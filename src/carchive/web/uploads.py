"""Streams one multipart file upload to disk under a hard, enforced size limit.

`fastapi`/`starlette`'s own `Request.form()` is not used for this: its multipart parser
caps individual non-file fields but writes file parts straight into a `SpooledTemporaryFile`
with no overall size limit at all, which is exactly the unbounded-upload risk this module
exists to close. `python-multipart`'s own `MultipartParser(max_size=...)` is not used
either: on reaching it, `write()` silently truncates the chunk it is fed instead of
raising, which would make an oversized upload look like a shorter, successfully parsed
one. Everything here is built directly on `python-multipart` (MIT; the same library
`Request.form()` uses internally), feeding it from `Request.stream()` chunk by chunk,
enforcing the size limit with this module's own running counter, and writing the one file
field this application expects straight to an already owner-only temp file, never into
memory.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from python_multipart.exceptions import FormParserError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import Request


class UploadError(ValueError):
    """Raised for a malformed multipart body or a missing required file field."""


class UploadTooLargeError(UploadError):
    """Raised when the request body exceeds the configured size limit."""


@dataclass(slots=True)
class _CurrentPart:
    field_name: str = ""
    filename: str | None = None
    header_name: bytearray = field(default_factory=bytearray)
    header_value: bytearray = field(default_factory=bytearray)
    content_disposition: bytes = b""
    text_value: bytearray = field(default_factory=bytearray)


@dataclass(slots=True)
class UploadedFile:
    """The result of `read_multipart_upload`."""

    path: Path
    original_filename: str
    fields: dict[str, str]


async def read_multipart_upload(
    request: Request,
    *,
    file_field: str,
    max_body_bytes: int,
    dest_dir: Path,
) -> UploadedFile:
    """Stream `request`'s multipart body, writing `file_field`'s content to a temp file.

    The temp file is created with mode 0600 in `dest_dir` (via `tempfile.mkstemp`, which
    always creates owner-only regardless of umask) before any byte of the upload is
    written, and the request body is never buffered as a whole: `max_body_bytes` is
    enforced by the underlying parser while bytes are still streaming in, so an oversized
    upload is aborted (and its partial temp file removed) before it ever fully lands on
    disk.

    Args:
        request: the incoming request; its body is read as a stream, once.
        file_field: the form field name expected to carry the uploaded file.
        max_body_bytes: the maximum number of bytes the whole multipart body may contain.
        dest_dir: the directory to create the temp file in; must already exist and be
            owner-only.

    Returns:
        The written temp file's path, the uploaded file's original (client-supplied)
        filename, and every other (non-file) form field's value.

    Raises:
        UploadError: if the body is not a well-formed multipart request, or `file_field`
            is missing from it.
        UploadTooLargeError: if the body exceeds `max_body_bytes`.
    """
    content_type = request.headers.get("content-type")
    if content_type is None:
        raise UploadError("missing Content-Type header")
    _, params = parse_options_header(content_type.encode("latin-1"))
    boundary = params.get(b"boundary")
    if not boundary:
        raise UploadError("missing multipart boundary")

    fd, tmp_name = tempfile.mkstemp(dir=dest_dir, prefix=".tmp-upload-", suffix=".pdf")
    tmp_path = Path(tmp_name)
    handle = os.fdopen(fd, "wb")
    fields: dict[str, str] = {}
    saw_file_field = False
    original_filename = ""
    current = _CurrentPart()
    total_bytes = 0

    def on_part_begin() -> None:
        nonlocal current
        current = _CurrentPart()

    def on_header_field(data: bytes, start: int, end: int) -> None:
        current.header_name.extend(data[start:end])

    def on_header_value(data: bytes, start: int, end: int) -> None:
        current.header_value.extend(data[start:end])

    def on_header_end() -> None:
        if current.header_name.lower() == b"content-disposition":
            current.content_disposition = bytes(current.header_value)
        current.header_name = bytearray()
        current.header_value = bytearray()

    def on_headers_finished() -> None:
        nonlocal saw_file_field, original_filename
        _, options = parse_options_header(current.content_disposition)
        name = options.get(b"name")
        if name is None:
            raise UploadError('a multipart part is missing its "name"')
        current.field_name = name.decode("latin-1")
        filename = options.get(b"filename")
        current.filename = filename.decode("latin-1") if filename is not None else None
        if current.field_name == file_field and current.filename is not None:
            saw_file_field = True
            original_filename = current.filename

    def on_part_data(data: bytes, start: int, end: int) -> None:
        nonlocal total_bytes
        chunk = data[start:end]
        total_bytes += len(chunk)
        if total_bytes > max_body_bytes:
            raise UploadTooLargeError(f"upload exceeds the {max_body_bytes} byte limit")
        if current.field_name == file_field and current.filename is not None:
            handle.write(chunk)
        else:
            current.text_value.extend(chunk)

    def on_part_end() -> None:
        if current.field_name != file_field or current.filename is None:
            fields[current.field_name] = bytes(current.text_value).decode("utf-8", errors="replace")

    parser = MultipartParser(
        boundary,
        {
            "on_part_begin": on_part_begin,
            "on_header_field": on_header_field,
            "on_header_value": on_header_value,
            "on_header_end": on_header_end,
            "on_headers_finished": on_headers_finished,
            "on_part_data": on_part_data,
            "on_part_end": on_part_end,
        },
    )

    try:
        async for chunk in request.stream():
            parser.write(chunk)
        parser.finalize()
    except UploadTooLargeError:
        handle.close()
        tmp_path.unlink(missing_ok=True)
        raise
    except FormParserError as exc:
        handle.close()
        tmp_path.unlink(missing_ok=True)
        raise UploadError(f"invalid multipart body: {exc}") from exc
    except Exception:
        handle.close()
        tmp_path.unlink(missing_ok=True)
        raise
    finally:
        if not handle.closed:
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()

    if not saw_file_field:
        tmp_path.unlink(missing_ok=True)
        raise UploadError(f"missing required file field {file_field!r}")

    return UploadedFile(path=tmp_path, original_filename=original_filename, fields=fields)
