"""OIDC login flow against the VW-group EU Data Act portal.

The portal has no documented public API. The request shapes and the login flow below were
worked out by reading evcc's MIT-licensed `eudataact` client
(https://github.com/evcc-io/evcc/tree/master/vehicle/vw/eudataact) and reimplemented
independently; nothing here is copied from it. The flow is: an OIDC authorize request lands
on an `emailPasswordForm`, which posts the e-mail address and receives a loosely-quoted
`window._IDK = {...}` template for the password step, whose POST either lands on the
portal's user page, on a marketing-consent page that needs one more GET, or on an error page.
"""

from __future__ import annotations

import json
import re
import secrets
from html.parser import HTMLParser
from typing import Any
from urllib.parse import ParseResult, parse_qs, urljoin, urlparse

import httpx

from carchive.core.errors import AuthenticationError, NeedsAttentionError, TransientError
from carchive.providers.vwgroup.brands import brand_identity

PORTAL_BASE_URL = "https://eu-data-act.drivesomethinggreater.com"
IDENTITY_BASE_URL = "https://identity.vwgroup.io"
AUTHORIZE_URL = f"{IDENTITY_BASE_URL}/oidc/v1/authorize"
REDIRECT_URI = f"{PORTAL_BASE_URL}/login"
OIDC_SCOPE = "openid cars profile"

PORTAL_HOST = urlparse(PORTAL_BASE_URL).hostname
IDENTITY_HOST = urlparse(IDENTITY_BASE_URL).hostname

MAX_LOGIN_REDIRECTS = 10


class _FormParser(HTMLParser):
    """Extracts a `<form id=...>` element's action and its `<input>` fields."""

    def __init__(self, form_id: str) -> None:
        super().__init__()
        self._target_id = form_id
        self._depth = 0
        self.action: str | None = None
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "form":
            if self._depth == 0 and attrs_dict.get("id") == self._target_id:
                self._depth = 1
                self.action = attrs_dict.get("action")
            elif self._depth:
                self._depth += 1
        elif tag == "input" and self._depth:
            name = attrs_dict.get("name")
            if name:
                self.inputs[name] = attrs_dict.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._depth:
            self._depth -= 1


def _parse_form(html: str, form_id: str) -> tuple[str, dict[str, str]]:
    """Extract a form's action URL and hidden input values from an HTML page.

    Args:
        html: the page's HTML.
        form_id: the `id` attribute of the form to extract.

    Returns:
        The form's `action` and a mapping of its input names to values.

    Raises:
        NeedsAttentionError: if no form with that id is present.
    """
    parser = _FormParser(form_id)
    parser.feed(html)
    if parser.action is None:
        raise NeedsAttentionError(
            f"login form #{form_id} not found (portal layout may have changed)"
        )
    return parser.action, parser.inputs


_IDK_BLOCK = re.compile(r"window\._IDK\s*=\s*(.*?)[;<]", re.DOTALL)


def _parse_credentials_page(html: str) -> dict[str, Any]:
    """Decode the inline `window._IDK = {...}` template model the identity service embeds.

    The block is loosely-quoted JS (single-quoted strings, unquoted keys, a trailing comma),
    not valid JSON, so it needs light normalization before `json.loads`.

    Args:
        html: the page's HTML.

    Returns:
        The decoded template object.

    Raises:
        NeedsAttentionError: if the template block is missing or not decodable.
    """
    match = _IDK_BLOCK.search(html)
    if not match:
        raise NeedsAttentionError(
            "credentials page template not found (portal layout may have changed)"
        )
    text = match.group(1).replace("'", '"')
    text = re.sub(r"(\s)(\w+)(\s*):", r'\1"\2"\3:', text)
    text = re.sub(r",\s*}", "}", text, flags=re.DOTALL)
    try:
        decoded: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NeedsAttentionError(f"could not decode credentials page template: {exc}") from exc
    return decoded


def _is_user_page(url: ParseResult, portal_host: str | None) -> bool:
    return (
        url.scheme == "https"
        and url.hostname == portal_host
        and url.path.startswith("/content/euda/")
        and url.path.endswith("user.html")
    )


def _is_marketing_consent_page(url: ParseResult, identity_host: str | None) -> bool:
    return url.hostname == identity_host and "/consent/marketing/" in url.path


async def _send(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    """Send one request with redirects disabled, mapping network failures to `TransientError`.

    Raises:
        TransientError: on a timeout, connection failure or 5xx response.
    """
    try:
        resp = await client.request(method, url, follow_redirects=False, **kwargs)
    except httpx.TimeoutException as exc:
        raise TransientError(
            f"timeout contacting the identity service ({type(exc).__name__})"
        ) from exc
    except httpx.TransportError as exc:
        raise TransientError(
            f"network error contacting the identity service ({type(exc).__name__})"
        ) from exc
    if resp.status_code >= 500:
        raise TransientError(f"identity service returned {resp.status_code}")
    return resp


async def _follow_redirects(
    client: httpx.AsyncClient, resp: httpx.Response
) -> tuple[str, httpx.Response | None]:
    """Follow redirects like a real login would, within the identity/portal hosts.

    Stops *before* fetching a target that is the portal's user page or a marketing-consent
    page - the URL itself is all those steps need - and rejects any other host as an
    unexpected redirect target.

    Returns:
        The final URL and, if it was actually fetched, the response holding its body.

    Raises:
        NeedsAttentionError: if a redirect targets an unexpected host/scheme, or the chain
            is longer than `MAX_LOGIN_REDIRECTS`.
        TransientError: on a timeout, connection failure or 5xx response while following.
    """
    hops = 0
    while True:
        location = resp.headers.get("Location")
        if not (300 <= resp.status_code < 400) or location is None:
            return str(resp.url), resp
        target = urljoin(str(resp.url), location)
        parsed = urlparse(target)
        if parsed.scheme != "https":
            raise NeedsAttentionError(f"login redirected to a non-https URL: {parsed.scheme}://…")
        if _is_user_page(parsed, PORTAL_HOST) or _is_marketing_consent_page(parsed, IDENTITY_HOST):
            return target, None
        if parsed.hostname not in (IDENTITY_HOST, PORTAL_HOST):
            raise NeedsAttentionError(f"unexpected login redirect host: {parsed.hostname}")
        hops += 1
        if hops > MAX_LOGIN_REDIRECTS:
            raise NeedsAttentionError("too many login redirects")
        resp = await _send(client, "GET", target)


def _raise_if_template_error(html: str) -> None:
    """Raise `AuthenticationError` if `html` is a credentials-page template with an error.

    Used both after the identifier step (rejected e-mail) and after the password step
    (wrong password lands back on the same template with its `error` field set).
    """
    try:
        template = _parse_credentials_page(html)
    except NeedsAttentionError:
        return
    model = template.get("templateModel", {})
    error = model.get("error")
    if error:
        raise AuthenticationError(f"portal rejected the login: {error}")


async def perform_login(client: httpx.AsyncClient, brand: str, user: str, password: str) -> None:
    """Log in to the VW-group EU Data Act portal, leaving `client` with a valid session.

    Args:
        client: the HTTP client to perform the login on; its cookies carry the resulting
            session. Redirects are followed manually regardless of the client's own
            `follow_redirects` setting.
        brand: the VW-group brand to log in as (e.g. `"audi"`), matched case-insensitively.
        user: the portal login (e-mail address).
        password: the portal password.

    Raises:
        ValueError: if `brand` is not a known VW-group brand.
        AuthenticationError: if the portal rejects the e-mail address or password.
        NeedsAttentionError: if the login form or template is not where expected, a
            redirect targets an unexpected host, or the flow ends on a consent/error page.
        TransientError: on a timeout, connection failure or 5xx response from either host.
    """
    identity = brand_identity(brand)
    query = {
        "client_id": identity.client_id,
        "response_type": "code",
        "scope": OIDC_SCOPE,
        "state": f"de__en__{identity.state_suffix}",
        "redirect_uri": REDIRECT_URI,
        "prompt": "login",
        "nonce": secrets.token_urlsafe(32)[:43],
    }
    authorize_resp = await _send(client, "GET", AUTHORIZE_URL, params=query)
    _, login_form_resp = await _follow_redirects(client, authorize_resp)
    if login_form_resp is None:
        raise NeedsAttentionError("login form page was not reached")

    action, fields = _parse_form(login_form_resp.text, "emailPasswordForm")
    identifier_url = urljoin(IDENTITY_BASE_URL, action)
    identifier_resp = await _send(
        client,
        "POST",
        identifier_url,
        data={
            "_csrf": fields.get("_csrf", ""),
            "relayState": fields.get("relayState", ""),
            "hmac": fields.get("hmac", ""),
            "email": user,
        },
    )
    _, credentials_resp = await _follow_redirects(client, identifier_resp)
    if credentials_resp is None:
        raise NeedsAttentionError("credentials page was not reached after the identifier step")

    _raise_if_template_error(credentials_resp.text)
    template = _parse_credentials_page(credentials_resp.text)
    model = template.get("templateModel", {})

    password_url = identifier_url.replace(
        model.get("identifierUrl", ""), model.get("postAction", "")
    )
    password_resp = await _send(
        client,
        "POST",
        password_url,
        data={
            "_csrf": template.get("csrf_token", ""),
            "relayState": model.get("relayState", ""),
            "hmac": model.get("hmac", ""),
            "email": user,
            "password": password,
        },
    )
    final_url, landing_resp = await _follow_redirects(client, password_resp)
    final_parsed = urlparse(final_url)

    if _is_marketing_consent_page(final_parsed, IDENTITY_HOST):
        callback = parse_qs(final_parsed.query).get("callback", [None])[0]
        if not callback:
            raise NeedsAttentionError("marketing consent page is missing its callback url")
        callback_resp = await _send(client, "GET", callback)
        final_url, landing_resp = await _follow_redirects(client, callback_resp)
        final_parsed = urlparse(final_url)

    if _is_user_page(final_parsed, PORTAL_HOST):
        return

    if landing_resp is not None:
        _raise_if_template_error(landing_resp.text)
    raise NeedsAttentionError(
        f"login did not complete, unexpected landing page {final_parsed.path}"
    )
