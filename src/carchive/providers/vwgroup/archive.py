"""Unpacking of the ZIP archives the VW-group portal delivers.

Each delivery is a ZIP holding exactly one JSON document (or none, for a
`_no_content_found.zip` placeholder, which callers never pass here). The archive is
untrusted portal output, so it is bounded and validated the same way as
`eu_data_act_sampler.py`'s `_extract_json_payload`, plus a check against path-traversing
member names a hostile or corrupted archive could carry.
"""

from __future__ import annotations

import io
import zipfile

from carchive.core.errors import ProviderError

# The largest real file seen so far is a 17 MB JSON document; this leaves ample room while
# still bounding memory use against a broken or hostile response.
MAX_JSON_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100


def _is_safe_member_name(name: str) -> bool:
    """Reject member names that could escape an extraction directory.

    Nothing here is ever extracted to disk, but the same names are rejected on principle:
    an absolute path, a backslash (Windows-style separator) or a `..` path segment.
    """
    if name.startswith("/") or "\\" in name:
        return False
    return ".." not in name.split("/")


def extract_json(zip_bytes: bytes) -> bytes:
    """Extract the single JSON document from a downloaded delivery archive.

    Args:
        zip_bytes: the raw bytes of the downloaded ZIP archive.

    Returns:
        The JSON document's raw bytes, validated to be well-formed UTF-8.

    Raises:
        ProviderError: if the archive is not a valid ZIP, has suspicious member names, has
            too many members, has no JSON member, or that member exceeds the size limit or
            is not valid UTF-8.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise ProviderError(f"downloaded archive has too many members ({len(infos)})")
            unsafe = [info.filename for info in infos if not _is_safe_member_name(info.filename)]
            if unsafe:
                raise ProviderError("downloaded archive contains an unsafe member name")
            json_infos = [i for i in infos if i.filename.lower().endswith(".json")]
            if not json_infos:
                raise ProviderError("downloaded archive contains no JSON document")
            # The declared size can lie, so the read itself is bounded too.
            with archive.open(json_infos[0]) as member:
                data = member.read(MAX_JSON_BYTES + 1)
    except zipfile.BadZipFile as exc:
        raise ProviderError("downloaded file is not a valid ZIP archive") from exc

    if len(data) > MAX_JSON_BYTES:
        raise ProviderError("JSON document in the archive exceeds the size limit")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderError("JSON document in the archive is not valid UTF-8") from exc
    return data
