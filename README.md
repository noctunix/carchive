# Carchive

Carchive collects the vehicle data that manufacturers deliver under the EU Data Act
(starting with the VW-group portal), stores it locally and shows it in a small web GUI.

## Running Carchive

### Linux laptop/server

```sh
uv tool install .
carchive check
carchive service install
```

`service install` writes `~/.config/systemd/user/carchive.service` (it runs
`carchive serve` from the path of the program you called), registers and starts it, and
tries to enable lingering. Without lingering a user unit stops at logout, and the
collector with it; if enabling it needs root, the command warns and prints the exact
`sudo loginctl enable-linger "$USER"` to run. The unit passes no environment variables on,
so the service uses the default config, secrets and data locations. Running it again is
harmless; after moving or reinstalling carchive it rewrites the unit and restarts the
service.

```sh
carchive service status      # unit, enabled/active, linger, URL, last 15 journal lines
carchive service uninstall   # leaves lingering on (other user services may need it)
```

`service status` exits non-zero unless the service is running and lingering is on. By
hand, the equivalent of `service install` is copying `deploy/systemd/carchive.service`
(adjust `ExecStart`) to `~/.config/systemd/user/`, then `systemctl --user daemon-reload`,
`systemctl --user enable --now carchive.service` and `loginctl enable-linger "$USER"`.

### Podman

```sh
podman build --format docker -f deploy/Containerfile -t localhost/carchive:latest .
podman secret create carchive-secrets ~/.config/carchive/secrets.toml
podman secret create carchive-vault-key ~/.config/carchive/vault.key
podman volume create carchive-data
mkdir -p ~/.config/containers/systemd
cp deploy/podman/carchive.container ~/.config/containers/systemd/
loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user start carchive.service
```

The container binds `0.0.0.0` internally (`CARCHIVE_CONTAINER=1`, set by the image) and
serves HTTPS with a self-signed certificate by default, kept in `tls/` of the data volume
(see [HTTPS](#https)); browse to `https://127.0.0.1:8470` and accept the certificate once.
The Quadlet unit's `PublishPort=127.0.0.1:8470:8470` limits reachability to the host's
loopback address; widen it only deliberately, the login password is then protected by TLS.

- **Own certificate:** add two more `Secret=` mounts to the unit and set
  `CARCHIVE_TLS_CERTFILE` / `CARCHIVE_TLS_KEYFILE` to the mounted paths (or put the files
  into the data volume). They take precedence over the generated one.
- **Behind a TLS-terminating proxy:** set `CARCHIVE_TLS_SELFSIGNED=false`. The container then
  serves plain HTTP and logs the warning `tls.container_plaintext` at every start; only the
  proxy may be able to reach the port.
- **Health:** the image's `HEALTHCHECK` runs `carchive healthcheck`, which asks `/healthz`
  on `127.0.0.1` (over HTTPS if enabled, without verifying the certificate) and exits 0 only
  on HTTP 200. It prints nothing.

`scripts/build-image.sh` wraps the build above: it builds `localhost/carchive:latest` from
the repository (wherever it is called from), restarts `carchive.service` if that unit is
active, and prunes the dangling images the build leaves behind.
`scripts/build-image.sh --install-timer` installs a weekly systemd user timer
(`carchive-image-build.timer`) that runs the same script, so the image picks up base-image
updates; `--uninstall-timer` removes it again. To rebuild on demand, run the script or
`systemctl --user start carchive-image-build.service`. Both need `podman` and `systemctl` in
`PATH`; a missing one ends the script with exit status 2.

The image is based on Debian 13 "trixie" (`python:3.12-slim-trixie`). The GitHub Actions
workflow `.github/workflows/ci.yml` runs `scripts/check.sh` and then builds the image on
every push to `main`, on `v*` tags, on pull requests against `main` and weekly (to pick up
base-image updates); only the push/tag/schedule/dispatch runs also build the image. It
pushes only if the secrets `REGISTRY_USER` and `REGISTRY_TOKEN` and the variable
`REGISTRY` (full image path, e.g. `registry.example.org/team/carchive`) are set;
otherwise it just builds.

### FreeBSD jail

Target is FreeBSD 15.1; the jail needs Python 3.12 or newer and `uv`, both packaged:
`pkg install python3 uv` (FreeBSD ports default to Python 3.13 as of 2026; `python312` is
also still packaged directly if you want that exact version instead).

```sh
uv tool install .
install -m 0555 deploy/freebsd/carchive /usr/local/etc/rc.d/carchive
sysrc carchive_enable=YES
service carchive start
```

Data lives in `/var/db/carchive` (owner-only), logs in `/var/log/carchive/carchive.log`.
`carchive_user`, `carchive_data_dir` and `carchive_env` (for further `CARCHIVE_*`
variables) are overridable in `/etc/rc.conf.d/carchive`.

### Taking over from the sampler

`import-sampler` reads the sampler's existing config and captured data without
touching either; run it as a dry run first, then apply:

```sh
carchive import-sampler
carchive import-sampler --apply
```

To check that nothing was lost, `carchive import-sampler --verify` (not combinable with
`--apply`) compares the sampler's databases with Carchive, read-only. Per account and
data-request kind (`all`/`partial`) it prints how many files the sampler holds, how many
of them Carchive stores, how many are missing and how many have different content; it
exits 0 only if nothing is missing or differs and every account could be read, else 1.
Files are matched by vehicle, kind and file name as the import does; content is compared
by the checksum of the JSON document itself, since the import repacks it into a new ZIP.
The output contains counts only, no file names, VINs or contents.

Once the import looks right, stop the sampler's own schedule so it does not keep
writing data the new install already collects on its own:

```sh
uv run python eu_data_act_sampler.py schedule remove
```

### HTTPS

On loopback Carchive speaks plain HTTP, which is fine for a browser on the same machine.
As soon as it listens on another address (`CARCHIVE_BIND_HOST`) or runs in a container, it
serves HTTPS with a certificate it creates itself; there is nothing to set up. Add the
names you reach it by to `allowed_hosts` in `~/.config/carchive/carchive.toml`:

```toml
bind_host = "0.0.0.0"
allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "carchive.home.lan"]
```

The certificate and key (ECDSA P-256) live in `tls/` of the data directory (owner-only).
The certificate is self-signed, valid for three years and lists every `allowed_hosts` entry,
the machine's host name and `localhost`; it is not tied to an IP address unless you list
one. It is reused across restarts. A new one is created when the files are missing or
damaged, when `allowed_hosts` changes, or 30 days before expiry; a running server checks
every 12 hours and switches to the new certificate without a restart.

Because nobody vouches for a self-signed certificate, each browser or device shows a warning
the first time (and once more after a new certificate was created). Compare the SHA-256
fingerprint in the browser's dialog with the one `carchive serve` logs at startup and
`carchive check` prints, then accept the exception. Carchive sends no
`Strict-Transport-Security` header with this certificate: browsers allow no exception for an
untrusted certificate once HSTS is set, which would lock you out.

`tls_selfsigned` (`CARCHIVE_TLS_SELFSIGNED`) overrides the automatic choice: `true` also
enables it on loopback, `false` turns it off (a non-loopback bind outside a container is then
refused, since it needs TLS; inside a container it is allowed with a startup warning). It cannot be combined with certificate files.

**If you want no warning at all**, bring a certificate and key as PEM files; they always take
precedence over the generated one. Carchive fetches no certificates and speaks no ACME or DNS
APIs, so use the tool of your choice:

- **Your own domain name plus Let's Encrypt via DNS-01.** Works for purely internal host
  names, no access from the internet needed: the ACME client proves control of the domain
  through a DNS record. Use an ACME client such as lego, acme.sh or certbot with the DNS
  plugin of your DNS provider. Host names end up in the public Certificate Transparency
  logs; a wildcard certificate (`*.home.example.org`) keeps the concrete name out of them.
- **A local CA** such as mkcert, or the internal CA of a reverse proxy. There is no
  certificate error only on devices that have the CA's root certificate installed.

```toml
tls_certfile = "~/.config/carchive/tls/fullchain.pem"
tls_keyfile = "~/.config/carchive/tls/privkey.pem"
allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "carchive.home.example.org"]
```

(or `CARCHIVE_TLS_CERTFILE` / `CARCHIVE_TLS_KEYFILE`). Both settings or neither. The key file
must be readable by you only (`chmod 600`); `serve` refuses to start with a key that group or
others can read, with an unreadable file, or with a certificate that does not match the key.
`carchive check` reports the same problems plus the days left until expiry and the names in
the certificate. An expired or soon-expiring certificate, or an `allowed_hosts` entry the
certificate does not cover, is logged as a warning or error but does not stop the collector.
With your own certificate Carchive sends `Strict-Transport-Security` (six months).

Your own certificate files are read once at startup. After every renewal, restart the
service, for example from your ACME client's renew hook:
`systemctl --user restart carchive`.

Either way TLS 1.2 or newer is required. Binding to a non-loopback address is only allowed
with TLS (`carchive serve` exits with status 2 otherwise); a container may opt out with
`CARCHIVE_TLS_SELFSIGNED=false` when something else terminates TLS. Every page is behind the operator login
described next.

## Portal credentials

Portal logins live in `secrets.toml` (default `~/.config/carchive/`), owner-only; Carchive
refuses to start if the file is group- or world-readable. Only the `password` of each
`[credentials.*]` entry is stored AES-256-GCM encrypted (`enc:v2:...`, bound to the account
and field) with the 32-byte key in `vault.key` next to `secrets.toml` (also owner-only;
created on the first write). The `user` and any other field stay readable, and so does the
operator's password hash in `[operator]`, which is already a hash.

This protects against `secrets.toml` leaking on its own: in a backup, a support paste, a
dotfile repository. It does not protect against code running as the same user, which can
read the key too. Keep `vault.key` out of wherever `secrets.toml` is copied, and back it up
separately or only inside an encrypted Carchive backup (see [Backups](#backups)): without it
the stored portal passwords cannot be recovered, and `carchive` refuses to load them (it
never creates a replacement key while encrypted values exist).

After a changed portal password, `carchive account set-password <label>` replaces just
that password (prompted, never an argument), tests it against the portal first and keeps the
account and its data; the web UI has the same form on each account's page under `/accounts`.
A running service
re-reads `secrets.toml` whenever it changes, so the next collection pass uses the new
password; no restart is needed.

**Lost `vault.key`:** all stored passwords are then unreadable, and a new key is only created
once none are left. Run `carchive account set-password` *without* a label: it asks for a
new password for each affected account in turn (each is tested against the portal) and
writes them and the new key in one step. If you abort or the portal rejects one, the secrets
file stays untouched. With a label and other unreadable accounts it refuses and names them.
`carchive account remove` works without the key.

Plaintext passwords still load and are encrypted by the next credential write; passwords in
the retired `enc:v1:` format are refused. `carchive check` shows how many passwords are
stored each way. The database holds no credentials, and backups only when you ask for them.

## Login

The web interface requires a password. On the first start nothing is set yet, and every page
redirects to `/login`, which asks you to choose one (at least 16 characters). **Whoever
submits that form first becomes the operator**; there is no setup token. On a loopback bind
only the local machine can do that. If the server is reachable from the network (a bind
beyond loopback, or a container), anyone who can connect can claim it, so set the password
right after starting: `carchive serve` logs the warning `operator.setup_open_to_network`
until you do.

`carchive check` shows whether a password is set. To change it, use the form under Settings
(every other session ends, this browser stays signed in), or run `carchive operator
set-password` from the terminal, which is also the reset if you forgot it and revokes every
session. This also works while `carchive serve` is still running, as long as the database is
already on its latest schema revision; otherwise stop the server first and run `carchive db
upgrade`.

Sessions are stored on the server and expire after 12 hours without use or 14 days at the
latest; "Sign out" ends one at once. The cookie is HttpOnly, SameSite=Strict and, over HTTPS,
Secure. Wrong passwords are throttled: after five failures from one address further attempts
are locked out for 30 seconds, doubling up to 15 minutes, and a much higher number of
failures from all addresses together locks the login for everyone for a while. The address
is the socket peer; `X-Forwarded-For` is ignored, so behind a reverse proxy all visitors
share the proxy's address and its throttle. Setting `trusted_proxies` to the proxy's
address (or network) lifts that only for peers listed there, using the left-most
`X-Forwarded-For` address as the throttle key instead; it is empty by default, so nothing
changes until a reverse proxy is actually in place.

## CLI reference

Every subcommand loads `~/.config/carchive/carchive.toml` and takes the data directory lock
while it writes anything, so it never races a running `carchive serve`. Run `carchive
<command> --help` for the exact flags; this is the short version, grouped by command family.

- `carchive version` - print the version and exit.
- `carchive check` - verify the secrets file, vault, data directory, bind host, operator
  login and TLS configuration; one `ok`/`error`/`warning` line each, no secrets or full VINs.
- `carchive serve` - run the collector and web GUI until stopped; migrates the database
  first (see [HTTPS](#https) for the certificate it picks).
- `carchive healthcheck` - probe the local server's `/healthz` over loopback; exit 0 only on
  HTTP 200, prints nothing (used by the container `HEALTHCHECK`, see [Podman](#podman)).
- `carchive parse-pending` - re-parse deliveries stuck at `parse_state = 'pending'`.
- `carchive fetch [--account LABEL] [--now]` - run one collection pass outside the
  scheduler: by default only accounts with work currently due, `--now` runs every account,
  `--account` restricts to one label.

**Database**

- `carchive db upgrade` - migrate to the latest schema, backing up first if the database
  already holds data.
- `carchive db status` - print the current and latest revision; exits 1 if behind.

**Accounts and vehicles** (see [Portal credentials](#portal-credentials) for how passwords
are stored)

- `carchive account add` - interactively add a portal account (choose the brand from a
  numbered list, then label, login, password), test the login, then offer the vehicles it
  reports.
- `carchive account list` - list configured accounts with their state and last run.
- `carchive account remove <label> [--yes]` - remove an account, its vehicles and all their
  data; without `--yes` only previews what would be deleted.
- `carchive account set-password [<label>]` - replace one account's stored portal password,
  or every unreadable one at once after losing `vault.key`; prompted, never an argument.
- `carchive vehicle sync <label>` - add vehicles an account newly reports that are not
  tracked yet.
- `carchive vehicle list` - list configured vehicles with their state and last run.
- `carchive vehicle remove <id-prefix> [--yes]` - remove one vehicle (matched by a unique
  prefix of its id) and all its data; without `--yes` only previews.

**Operator login** (see [Login](#login))

- `carchive operator set-password` - set or replace the web login password from the
  terminal; ends every session. Also works while `serve` is running, provided the database
  is already on its latest schema revision.

**Backups** (see [Backups](#backups) for the archive format, retention and encryption)

- `carchive backup create [--[no-]include-credentials] [--[no-]encrypt] [--allow-plaintext-credentials]`
- `carchive backup list`
- `carchive backup verify <file>`
- `carchive backup prune`
- `carchive backup restore <file> [--restore-credentials] [--overwrite-credentials]`

**Catalog**

`carchive serve` seeds the VW-group dictionary bundled with this version on its first
start; `catalog import` below is only needed for a different provider or a newer
dictionary version than the bundled one.

- `carchive catalog import <pdf> [--catalog-version VERSION] [--provider PROVIDER]` - parse a
  manufacturer Data Dictionary PDF into the local `catalog_entries` table (default provider
  `vwgroup-euda`; the version is derived from the file name if not given).
- `carchive catalog list` - list imported catalog versions with their entry counts.

**Service** (see [Linux laptop/server](#linux-laptopserver))

- `carchive service install [--no-start]` - install, enable and start the systemd user
  service, and enable lingering.
- `carchive service uninstall` - stop and remove the user service (lingering stays on).
- `carchive service status` - show unit state, lingering, URL and recent log lines; exits
  non-zero unless the service is running and lingering is on.

**Taking over from the sampler** (see
[Taking over from the sampler](#taking-over-from-the-sampler))

- `carchive import-sampler [--config PATH] [--sampler-data-dir PATH] [--apply | --verify] [--no-parse]`

## Backups

A backup runs daily at `backup_time` (default `03:30`) and before every schema migration;
`carchive backup create|list|verify|prune|restore` does the same by hand. Retention is
`backup_keep_daily/weekly/monthly` (7/4/6). By default a backup is the database only,
gzip-compressed (`carchive-<time>.sqlite3.gz`) with a SHA-256 sidecar, unencrypted.

| Option (setting / `backup create` flag) | Effect |
| --- | --- |
| `backup_include_credentials` / `--[no-]include-credentials` | also store `secrets.toml` and `vault.key` (`.tar.gz`); both files must exist and be owner-only |
| `backup_encrypt` / `--[no-]encrypt` | encrypt the archive (extra `.enc` suffix) |
| `backup_passphrase_file` | owner-only file with the passphrase, for scheduled backups |
| `backup_allow_plaintext_credentials` / `--allow-plaintext-credentials` | permit credentials without encryption |

**Credentials belong in a backup only encrypted.** The stored portal passwords are protected
by `vault.key`; in one readable archive next to `secrets.toml` the key is worthless.
Carchive therefore refuses (the manual command exits 1, the scheduler logs an error and
creates nothing) unless you allow it explicitly, which logs a warning every time.

The passphrase is read from `backup_passphrase_file`, else asked on the terminal (twice when
creating, no echo, at least 16 characters). It is never taken from an argument or an
environment variable. Without a passphrase file, scheduled backups of an encrypted setup fail,
and so does `backup prune` without a terminal, because pruning first verifies the newest
backup. A lost passphrase cannot be recovered.

`backup verify` and `backup restore` recognise every variant by content. `backup list`
shows per archive whether it is encrypted and whether it holds credentials (`unknown` for
encrypted ones: the name is not authenticated) and checks encrypted archives by checksum only
unless a passphrase file is set. `restore` refuses while the server runs (data lock), keeps the old
database aside as `*.before-restore-<time>` and restores credentials only with
`--restore-credentials`; existing `secrets.toml` or `vault.key` are replaced only with an
additional `--overwrite-credentials` (and kept aside the same way). Restored files are
owner-only.

The web interface has a **Backups** page: it lists the archives (size, encrypted, credentials,
checksum state), creates a backup with the same two options (pre-filled from the settings;
credentials are accepted only together with encryption, unless a third, always initially
unchecked box explicitly allows storing them unencrypted), checks one (an encrypted archive
needs its passphrase) and downloads it. The
passphrase is entered twice when creating, unless `backup_passphrase_file` is set; it is never
shown, logged or put into a redirect. Restoring is not offered there: it needs the server
stopped, so it stays `carchive backup restore`.

Format of `.enc` files: `CARCHIVEBK`, version byte `1`, 16-byte salt, Argon2id time, memory
(KiB) and parallelism as three 32-bit integers (defaults of argon2-cffi), a 7-byte nonce
prefix; then AES-256-GCM blocks of 64 KiB plaintext (+16-byte tag) under the 32-byte
Argon2id key. The nonce is prefix, 32-bit block counter and a last-block flag, and the whole
header is authenticated with every block, so truncation, reordering and header changes are
detected. A wrong passphrase and damaged data give the same error.

## Raw payload retention

Every delivery is parsed into typed data points, and the raw document as the portal sent
it (the ZIP) is kept alongside for a while, in case a future mapping fix needs to reparse
it. `raw_payload_retention_days` (default `30`) controls how long: `0` clears it as soon as
a delivery parses successfully, unset/empty keeps it forever. A delivery still waiting to
be parsed, or one that failed parsing, always keeps its raw payload regardless of age — it
is cleared only after a successful parse. The scheduler checks this on every pass; nothing
to run by hand.

## Sampler (current tool)

A small cron-friendly sampler for the VW-group "EU Data Act" data-delivery
portal (`eu-data-act.drivesomethinggreater.com`) that VW/Audi/Skoda/Seat/Cupra
point to from their EU Data Act notices. The portal does not stream live
telemetry; it deposits a new dataset for your vehicle roughly every 15
minutes once you've enabled a data request for it in the browser. This tool
logs in, checks whether a newer dataset has appeared, and if so downloads it,
unzips the JSON document inside, and stores it both as a plain file and as a
row in a local SQLite database.

No field-level decoding happens here on purpose: nobody has published what
the delivered JSON actually contains for a given vehicle, model and dataset
type, so this tool just archives the raw documents for later inspection
instead of guessing a schema.

### Status

The login flow and endpoint shapes below were worked out by reading evcc's
MIT-licensed [`eudataact` client](https://github.com/evcc-io/evcc/tree/master/vehicle/vw/eudataact)
and reimplemented independently here - nothing is copied from it, credit
where it's due for the protocol research.

Confirmed against a real account (2026-10-22): the login flow (`login-test`)
completes the full OIDC redirect chain to a landed portal session. Still
open:

- Listing and download accept exactly the dataset types `all` and `partial`
  (the portal's own 400 response says so), and each type is its own data
  request with its own identifier from `/metadata/<type>`. On the test
  account `all` held the one-off historical export and `partial` the
  continuous 15-minute deliveries; whether that holds generally is not
  confirmed. `fetch` therefore polls both and treats any 4xx as "this type
  is not set up".
- The portal lists at most the newest 30 files per request, and a request
  whose files are not downloaded within 7 days is cancelled. Empty cycles
  produce `..._no_content_found.zip` placeholders that count towards both,
  so `fetch` downloads (and records) those too, and warns when many files
  are still waiting or the oldest waiting one is getting old.
- The login flow targets the "legacy" `emailPasswordForm` variant of VW
  group's identity service. If your account instead gets the newer login UI,
  this will fail with a clear error rather than silently doing the wrong
  thing - please report back what you see instead of guessing a fix.

### Setup

Requires [`uv`](https://docs.astral.sh/uv/). `uv sync` creates `.venv` and
installs everything pinned in `uv.lock`:

```sh
uv sync
```

The config file lives at `~/.config/carchive/config.ini` (override with
`--config`). **Never commit this file anywhere** - it holds portal passwords.
The easiest way to create it, or to add another account later, is

```sh
uv run python eu_data_act_sampler.py init
```

which asks for brand, login and password (not echoed), tests the login,
lets you pick the vehicles and writes the file readable only by you. It
never overwrites: an existing file gets a new `[account:<name>]` section.
Written by hand, the file looks like this:

```ini
[portal]
brand = Audi
user = you@example.com
password = your-portal-password
# vin = leave unset until you've run list-vehicles once

[storage]
# optional, defaults to ~/.local/share/carchive
data_dir = ~/.local/share/carchive

[request]
# optional, defaults to polling both all and partial
dataset_type = partial
```

`brand` is one of `Volkswagen`, `Audi`, `Skoda`, `Seat`, `Cupra`.

Several portal accounts (e.g. a partner's or friends' cars, each under the
owner's own portal login) go into `[account:<name>]` sections instead of, or
next to, `[portal]`. Each account keeps its data in `<data_dir>/<name>/`, so
removing someone's data is removing that directory:

```ini
[storage]
data_dir = ~/.local/share/carchive

[account:a6]
brand = Audi
user = you@example.com
password = your-portal-password
vins = WAUZZZ...

[account:kodiaq]
brand = Skoda
user = friend@example.com
password = their-portal-password
# several vehicles of one account: separated by commas or spaces
vins = TMB...
# optional, defaults to polling both all and partial
# dataset_type = partial
```

Accounts run one after another in a single invocation, never in parallel
(the portal rate-limits even a single client); a failing account does not
stop the others. `--account <name>` (repeatable) restricts a run to some of
them.

```sh
# verify the login works at all
uv run python eu_data_act_sampler.py login-test

# find the VINs of the vehicles you want to sample, then add them to the config
uv run python eu_data_act_sampler.py list-vehicles

# download every file not captured yet, oldest first (max 50 per type and run)
uv run python eu_data_act_sampler.py fetch
```

### Looking at what arrived

```sh
uv run python eu_data_act_sampler.py tail -n 30                         # last fetched files
uv run python eu_data_act_sampler.py tail --records -n 50               # newest data records
uv run python eu_data_act_sampler.py tail --records --field mileage     # only matching fields
uv run python eu_data_act_sampler.py fields                             # which fields exist
uv run python eu_data_act_sampler.py status                             # is it running, what came
uv run python eu_data_act_sampler.py tail --account a6                  # one account only
```

`status` first says whether scheduled runs happen (the newest recorded run
is flagged if it is older than twice `--expect-every`, default 15 minutes)
and which schedule is installed; then, per account, vehicle and dataset
type, the outcome of the last run (`ok` with listed/empty/new/waiting counts,
or `unavailable`, `rate_limited`, `error`, and failed logins), when the last
file with content was created and fetched, and how many empty files have
followed it. Runs are recorded by `fetch` from this version on.

`fields` lists every field seen so far with its record count and newest
record time; array indices are collapsed to `[*]`
(`powerCurve.[*].timeCurve.[*].soc`), the spelling of the manufacturer's
data dictionary, and `--field` accepts either form.

The file view shows fetch and creation time, account, dataset type, size
and whether a file had content (and how many records) or was an empty
placeholder. The record view reads the `{"Data": [...]}` layout and sorts by
each record's own timestamp; documents in another layout are counted, not
shown. Both only read the databases. Record values are your vehicle data -
they are printed for you, not meant for sharing.

### Scheduling

```sh
uv run python eu_data_act_sampler.py schedule install   # every 15 minutes
uv run python eu_data_act_sampler.py schedule status
uv run python eu_data_act_sampler.py schedule remove
```

`install` picks the backend that keeps running after you log out:

- a **systemd user timer** (`carchive-fetch.timer`) when a systemd user
  manager is reachable *and* lingering is enabled for your user - without
  lingering the user manager, and the timer with it, stops at logout, so
  the timer is refused then (`sudo loginctl enable-linger $USER` enables
  it). Output goes to the journal: `journalctl --user -u carchive-fetch`.
  Missed runs (machine off) are caught up once on start.
- otherwise a block in **your crontab**, marked `# BEGIN carchive-fetch` /
  `# END carchive-fetch` and replaced as a whole on reinstall; the rest of
  your crontab is left alone. This is also the variant for FreeBSD
  (`periodic` only knows daily/weekly/monthly). Output goes to
  `~/.local/state/carchive/fetch.log`, rotated at 1 MB.

`--backend systemd|cron` forces one, `--interval` takes 5, 10, 15, 20, 30
or 60 minutes. Runs start at a random offset within the interval rather than
on the hour, and a run that is still busy (rate limit, catch-up) makes the
next one skip instead of overlapping. `install` warns if your crontab still
holds a hand-written entry for the sampler - remove that, or every run
happens twice.

### Storage layout

```
<data_dir>/captures.sqlite3   # one row per dataset with content (raw JSON included)
                              # and one per downloaded no-content placeholder
<data_dir>/captures/*.json    # the same raw JSON documents as plain files
```

Nothing here is pruned automatically; datasets are small JSON documents, so
this is left for you to manage once you know how much history you actually
want to keep.

### Inventory

`inventory.py` learns the *structure* of captured JSON documents (or a
directory/ZIP of them) without ever printing a value - no VINs, positions,
timestamps, odometer readings. The only exceptions are short enum-like
strings (e.g. `unit: "km"`) and, with `--known-keys`, UUIDs that are already
public vocabulary from the manufacturer's data dictionary; both are off with
`--no-enums`.

```sh
uv run python inventory.py <data_dir>/captures
uv run python inventory.py <data_dir>/captures --known-keys data/vwgroup/known_keys_v6.txt --compact --out inventory.md
```

`--compact` prints one line per path, which keeps large reports reviewable.

**Review the report before sharing it anywhere** - the header says so, but
check anyway; a structure-only report is the only thing that may leave this
machine, never a raw capture.

### Tests and checks

```sh
uv run pytest
uv run ruff check .
uv run mypy .
```

Tests are network-free: everything that talks to the portal (login flow, API
calls) is exercised against fixtures, not the real service.

## Development

`scripts/check.sh` runs the full check suite (ruff, mypy, pytest) for the whole repo,
including the `carchive` package under `src/` and the sampler above.
