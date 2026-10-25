# Vendored frontend assets

Carchive's web GUI loads no scripts, styles or fonts from a CDN; everything is vendored
here and served from `/static/vendor/...`.

## htmx

- Version: 2.0.4
- Source: https://raw.githubusercontent.com/bigskysoftware/htmx/v2.0.4/dist/htmx.min.js
- SHA-256: `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447`
- License: 0BSD (see `htmx/LICENSE`)

To update: download the new `dist/htmx.min.js` and `LICENSE` from the matching git tag of
https://github.com/bigskysoftware/htmx, verify the SHA-256 against the project's own release
assets, and update the version/hash recorded above.
