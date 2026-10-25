"""`GET /lang/{code}`: switch the UI language and redirect back where the user came from."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from starlette.responses import RedirectResponse

from carchive.web.i18n import LANG_COOKIE_NAME, SUPPORTED_LANGUAGES

router = APIRouter()


def _is_local_path(path: str) -> bool:
    # "//host" and "/\\host" are read by browsers as a scheme-relative URL to another site.
    return path.startswith("/") and not path.startswith(("//", "/\\")) and path.isprintable()


@router.get("/lang/{code}")
async def set_language(request: Request, code: str) -> RedirectResponse:
    """Set the `lang` cookie to `code` and redirect back to the referring page.

    Args:
        request: the incoming request; its `Referer` header, if present and pointing at
            this host and a plain local path, is used as the redirect target, else `/`.
        code: the language code to switch to.

    Returns:
        A redirect response with the `lang` cookie set.

    Raises:
        HTTPException: 404 if `code` is not a supported language.
    """
    if code not in SUPPORTED_LANGUAGES:
        raise HTTPException(status_code=404, detail="unsupported language")

    target = "/"
    referer = request.headers.get("referer")
    if referer:
        parts = urlsplit(referer)
        if parts.hostname == request.url.hostname and _is_local_path(parts.path):
            target = parts.path

    response = RedirectResponse(url=target, status_code=303)
    response.set_cookie(
        LANG_COOKIE_NAME,
        code,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return response
