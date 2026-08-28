# CLAUDE.md

Operational notes for Claude sessions working on this repo — dense, for an
agent, not prose for an external reader (that's what README.md is for).
Do not put server names, ISP/provider names, individual people's names,
or unpublished/draft project names here — same public-repo constraint as
README.md. `Server A`/`Server B`/etc. and `Provider A`/`Provider B`/etc.
below are anonymized codenames, not real hostnames or ISPs — a consistent
codename per real server/provider, same convention as z2r_autobench's own
CLAUDE.md (2026-08-26: retroactively scrubbed a real hostname that had
crept in here to this codename).

## Android MTProto investigation (started 2026-08-22)

**Status: mitigated via `mtproxy_relay.py`, deployed and confirmed working
on Server A** — real MTProto sessions on multiple DCs (DC1/DC2/DC2m/DC4m/
DC203) closing normally with substantial two-way data (one session moved
1.2MB down), verified live in `journalctl -u tg-mtproxy-relay`. Root
cause of *why* `transparent_relay.py`'s no-secret path fails on Android
is still UNRESOLVED (see the trail below, kept intact for context) —
**actively being re-opened as of 2026-08-28** (user wants the transparent,
zero-config WS path itself fixed for Android/Windows, not just the
secret-based mitigation). **Leading hypothesis as of the latest test round:
NOT a client-side TLS-wrapping quirk (a control test through a plain,
non-parsing exit — "FI VDS" — worked on Android/Windows too, ruling that
out) — now pointing at incomplete destination-IP coverage in
`setup_redirect.sh`'s cached CIDR list.** See "follow-up control test —
supersedes the VPN-heuristic hypothesis" for the full reasoning and the
two concrete next steps (refresh CIDR list; tcpdump the real destination
IPs), neither yet run on a live server.

**2026-08-28, confirmed test matrix — narrows the trigger to "via VLESS
specifically", not "Android/Windows in general":**

```
via VLESS:    ios/mac app -> VLESS -> 3x-ui (Server A) -> transparent_relay.py -> TG DC   [OK]
              android/win app -> VLESS -> 3x-ui (Server A) -> transparent_relay.py -> TG DC [FAILS]

via MTProxy:  ios/mac app -> mtproxy_relay.py (Server A) -> TG DC   [OK]
              android/win app -> mtproxy_relay.py (Server A) -> TG DC [OK]
```

Android/Windows Telegram DOES speak correct secret-based MTProto
perfectly fine when connecting directly to `mtproxy_relay.py` (no VLESS
involved at all) — so this is **not** "Android/Windows can't do
obfuscated2/MTProto," full stop, as the earlier framing implied. The
failure is specific to the combination of (Android or Windows) **+**
routed through VLESS. Sharpens the leading hypothesis from "Android
auto-wraps in Fake-TLS" to something more specific: Telegram's
Android/Windows clients most likely have a network heuristic that
detects "this looks like a VPN/proxy tunnel" (something iOS/macOS's
Telegram either lacks or doesn't trigger the same way) and voluntarily
switches to a TLS-camouflaged transport when it fires — worth checking
whether this correlates with any client-side "proxy detection" or "use
proxy for calls" style setting exposed in Telegram's own settings, in
parallel with the SNI capture below (that still doesn't need a new test —
already deployed, just needs someone to reopen Telegram on Android/
Windows through the VLESS path with `journalctl -u tg-transparent-relay -f`
open and paste back what shows up).

**2026-08-28, follow-up control test — supersedes the VPN-heuristic
hypothesis above:**

```
ios/mac app     -> VLESS -> 3x-ui (Server A) -> FI VDS (plain exit) -> TG DC   [OK]
android/win app -> VLESS -> 3x-ui (Server A) -> FI VDS (plain exit) -> TG DC   [OK]
```

Same VLESS tunnel, same "does this look like a VPN" client-side vantage
point — only the exit changed (a plain VDS in Finland doing ordinary IP
forwarding, no protocol parsing at all, instead of
`transparent_relay.py`). Both platforms now work. This rules out a
client-side "detects VPN, switches to Fake-TLS" heuristic — if that were
real, routing through *any* proxy exit (VLESS is still VLESS either way)
should trigger it identically regardless of what sits at the far end.
The fault is therefore isolated to `transparent_relay.py`/its REDIRECT
setup on Server A specifically, not to the Telegram client.

**New leading hypothesis: incomplete destination-IP coverage in
`setup_redirect.sh`'s REDIRECT rule, not a decode/parsing bug.**
`cidr/telegram_ipv4.txt` is a *cached* snapshot (`2026-08-17`, 9
subnets) of `core.telegram.org/resources/cidr.txt`, and REDIRECT only
catches outbound `:443` to those specific subnets (see
`relay/setup_redirect.sh`). If Android/Windows's real MTProto attempt
picks a destination IP outside that cached list — a different backup
DC, a range added/changed since the snapshot, anything not in those 9
subnets — it is NEVER caught by REDIRECT at all and goes straight out
from Server A's own uncensored-relay-less network path, where it hits
the exact ISP-level DPI block this whole project exists to route
around, and silently dies. iOS/Mac's attempts apparently land inside
the covered ranges by luck/platform-specific candidate ordering, so
they get relayed successfully; Android/Windows's don't. This would
explain BOTH results at once without needing any client-side protocol
theory: through FI VDS, it doesn't matter which IP is targeted, because
*everything* routes out through an uncensored network regardless of
destination — only `transparent_relay.py`'s narrow, IP-scoped REDIRECT
cares which specific subnet the connection is headed to.

**Earlier "confirmed real TLS ClientHello" finding does NOT contradict
this** — that capture only proves what showed up *inside* the redirected
CIDR range (background HTTPS/CDN traffic sharing the same subnets, per
the already-documented web.telegram.org-passthrough case); it says
nothing about connections that never got redirected in the first place,
since those are invisible to `transparent_relay.py`'s own logs by
construction. Both mechanisms could coexist; this one is now the
higher-priority lead specifically because the FI-VDS control test rules
out the client-heuristic theory outright, while nothing has yet ruled
this one out.

**Two concrete next steps, neither requiring more guessing:**
1. Refresh the cached CIDR list — `cd /opt/Zenith-TG/cidr &&
   ./fetch_telegram_cidr.sh` (earlier attempt on 2026-08-22 failed
   because `core.telegram.org` didn't respond over TLS from Server A at
   that moment — worth retrying now) — then `setup_redirect.sh remove`
   + `apply` to pick up any changed/added subnets, and re-test
   Android/Windows through the normal VLESS path.
2. **Decisive test, no code change needed:** a non-invasive `tcpdump` on
   Server A's outbound interface during a fresh Android/Windows test —
   `tcpdump -i any -n 'tcp dst port 443'` (or scope to the VLESS/3x-ui
   process's own traffic) while reopening Telegram — to see the actual
   destination IP(s) attempted, then diff those against
   `cidr/telegram_ipv4.txt`. If even one target IP falls outside all 9
   subnets, this hypothesis is confirmed and the fix is just widening
   REDIRECT coverage (either a fresher CIDR list, or matching Telegram's
   full published range instead of the cached subset).

**One open caveat, NOT independently verified:** all confirmed-working
sessions were captured with the Android device on the same home Wi-Fi as
Server A (source IP `192.168.0.24`, a LAN peer address — NOT `192.168.0.40`,
which is what Server A's own tunnel-terminated traffic shows elsewhere in
this doc). `tg://proxy?server=192.168.0.40&...` points at a **private**
RFC1918 address, unreachable from outside that LAN by definition. Whether
Happ (the Android VLESS client) actually tunnels traffic to a private
destination IP through VLESS, or has a hardcoded "bypass VPN for LAN
addresses" default (common in VPN clients, separate from the app's own
user-facing "routing" toggle which is currently OFF) determines whether
this same link keeps working once the phone leaves that Wi-Fi network —
untested; the user judged it likely fine given their client is in
full-tunnel mode, but flagged and not proven. **If it turns out NOT to
work away from home:** the fix is port-forwarding `9443` on the home
router (Keenetic) to Server A and pointing the `tg://proxy` link's `server=`
at the router's public IP/DDNS instead of `192.168.0.40` — same principle
already used for whatever address the VLESS inbound itself is reachable
on from outside. Not done as of this writing; only prepare it if the
cross-network case actually fails in practice.

**Symptom:** `relay/transparent_relay.py` (transparent, no-secret MTProto
relay) works fine on iPhone, but Telegram never gets past "Connecting..."
on two separate Android devices on the same network/VLESS tunnel. This
section is the full trail so a future session (or a fresh one after this
one ran out of context) doesn't have to re-derive any of it.

### Ruled out, in the order investigated

1. **DHCP/DNS was not the cause.** A parallel, unrelated incident that
   day (z2r_autobench side, see that repo's own CLAUDE.md) had already
   broken and then fixed system DNS on Server A — checked and ruled out as
   a factor here; this relay resolves fine.
2. **Dead CF-fallback fronting domains** (`vendor/config.py`,
   `Flowseal/tg-ws-proxy`'s published domain list) — all 20 resolved to
   `gaierror(-5, 'No address associated with hostname')` (domain exists,
   no A/AAAA record — upstream domains are just dead, not a censorship
   or DNS-provider issue). **Fixed** in commit `ada2100`: expanded
   `DEFAULT_DC_IP` in `transparent_relay.py` from `{2, 4}` to all 5 real
   DCs (`1..5`), all pointed at the same `149.154.167.220` WebSocket
   gateway — `ws_domains()` already builds a per-DC Host domain
   generically, so this was a pure config gap, not a design limitation.
   This closes the need for the fallback path entirely for any
   legitimately-decoded connection.
3. **False-positive MTProto detection.** Before the `dc_id` range check
   existed, a large stream of unrelated non-MTProto TCP traffic sharing
   Telegram's CIDR (caught by the same iptables REDIRECT) would
   occasionally have its 4-byte `proto_tag` field coincidentally match
   one of the 3 known tags after AES-CTR decode — producing absurd
   `DC16712`-style hits (Telegram DC ids are ONLY ever 1-5, or +10000 for
   test). Confirmed this was happening in volume specifically right
   after reopening Telegram on Android (dozens of hits/second). **Fixed**
   in commit `a44c1f8`: `_decode_direct_client_init()` now rejects any
   decoded `dc_id` outside `_REAL_DC_IDS = {1..5} ∪ {10001..10005}`
   before ever treating a connection as a genuine client.
4. **Happ (Android VPN client) "preferred API type" was `Auto`, iOS's
   Happ defaults to `IPv4` explicitly** — a real, confirmed client-side
   difference (found live, not guessed) that looked like a strong
   suspect (IPv6 leak bypassing the VLESS tunnel entirely — YouTube/
   Instagram working while Telegram didn't fit that pattern, since IPv6
   leak would only affect whichever specific connections resolve/route
   over IPv6 at that moment). **Set to IPv4 on Android to match iOS —
   did NOT fix the issue.** Ruled out as sole cause, though leaving it on
   IPv4 is still correct hygiene regardless.

### The actual finding (raw bytes, not a guess)

Added a temporary diagnostic (`-v`/`--verbose`, commit `14135fc`) that
logs the first 16 bytes of any handshake `_decode_direct_client_init()`
rejects. Captured live from Android reopening Telegram:

```
16030106e6010006e20303f72e066e64
160301072601000722030349e56acafc
16030106e4010006e00303688e64716d
1603010726010007220303ea291996e5
16030107240100072003035e8cebd0c3
16030106e6010006e2030365c3bff436
1603010706010007020303e93964fb8d
16030106c6010006c20303db8291ef55
```

Every single one starts `16 03 01`/`16 03 03` (TLS record: Handshake,
TLS1.0/1.2) followed by `01 00 XX XX` (Handshake type ClientHello +
length) then `03 03` again (ClientHello's own `client_version` = TLS1.2)
then `client_random`. **This is a genuine, real TLS ClientHello** — not
obfuscated2 MTProto's random-looking 64-byte prefix, which is what
`_decode_direct_client_init()` is built to parse (raw key derived
straight from the packet, no secret — see that function's docstring and
`prober/proto.py`).

All destination IPs for these connections were real Telegram DC
addresses (`149.154.167.99`, `149.154.170.200`, `149.154.174.200`,
`149.154.167.51`, `149.154.167.41`, `149.154.167.222`, `149.154.175.54`)
— and every one of them, once passed through as plain TCP passthrough
(since `_decode_direct_client_init()` correctly refuses to touch real
TLS), timed out / failed to connect.

**Correction (this whole paragraph originally said something wrong —
kept below with the fix so the mistake and the reason it was wrong are
both on record):** a `curl -v --connect-timeout 4 https://<ip>:443/`
for `.51`/`.41`/`.222`/`175.54`, run as **root**, appeared to show TCP
connecting and a real ClientHello going out before silently timing out —
read at the time as a DPI blackhole *after* the handshake starts, not a
SYN-level block like the already-documented `.99` case. **That test was
invalid.** `iptables -t nat OUTPUT` REDIRECTs *any* locally-originated
connection to Telegram's CIDR to the relay's own port — the self-loop
exclusion (`c173450`, see below) only exempts traffic from the `tgrelay`
user. `curl` run as root has no such exemption, so it was hitting the
relay's own listening socket on Server A, not the real internet — the
"ClientHello sent, then silence" was really the relay receiving curl's
ClientHello locally, correctly classifying it as non-MTProto, and its
*own* (correctly `tgrelay`-exempted) passthrough re-connect attempt
timing out in the background while curl sat on its side of the loop
waiting.

**Redone correctly** (`sudo -u tgrelay curl -sv --connect-timeout 4
https://149.154.167.51:443/`, genuinely bypassing REDIRECT this time):
plain `Connection timed out` at the TCP layer — no ClientHello is even
reached. This **is** the same SYN-null-route class as `149.154.167.99`/
web.telegram.org, just confirmed now for a wider set of "well-known"
default DC IPs too — matches this project's own earlier finding, from
before this relay existed, that the block is "a curated IP blacklist of
specific well-known Telegram DC addresses," not a DPI signature. The
`--lua-desync=`/ClientHello-fragmentation idea floated earlier for
`transparent_relay.py`'s passthrough path was therefore never viable —
correctly abandoned, just for the right reason now instead of the wrong
one.

One real puzzle this surfaces: `149.154.167.220` (the WS-bridge gateway
`mtproxy_relay.py`'s confirmed-working sessions actually connect to) is
in the *same* `149.154.160.0/20` block, yet is reachable — the blacklist
is evidently curated by specific IP, not by the whole announced CIDR
range, and `.220` (obscure, only meaningful to tg-ws-proxy-style relays,
not something an ordinary direct client would ever try on its own)
simply never made that list. Doesn't change what happens to be reachable
from Server A for MTProto (via `mtproxy_relay.py`'s WS-bridge path, always
fine) — but it does mean `transparent_relay.py`'s plain-TCP passthrough
for "not MTProto" traffic is structurally dead for most of Telegram's
real IP space, not just `.99`, independent of any DPI trickery.

**Important: none of this touches why Android sends TLS instead of
obfuscated2 in the first place.** REDIRECT rewrites the destination in
netfilter before a packet ever leaves Server A, so whether that
destination would ultimately have been reachable is irrelevant to what
bytes the relay actually receives from the client — the format mystery
is unaffected by this finding either way. Recorded here purely to fix
the earlier wrong conclusion and stop it from misleading a future
session, not because it resolves the open question.

### What this means, and what's still open

- `verify_client_hello()` in `relay/vendor/fake_tls.py` (real Fake-TLS,
  the MTProxy masking transport) requires a pre-shared secret via HMAC
  over `client_random` — that's for clients with a manually-configured
  `tg://proxy?...` link. A **direct, unconfigured** client (the whole
  premise this relay is built on) has no secret to use for that, so this
  traffic is very unlikely to be classic Fake-TLS in the MTProxy sense.
- Leading hypothesis, NOT yet confirmed: recent Telegram Android builds
  may have a built-in "detect restrictive network, wrap in TLS" fallback
  transport that activates automatically (no user proxy config needed),
  separate from both plain obfuscated2 and manually-configured Fake-TLS.
  If true, decoding/relaying it would require reverse-engineering
  whatever scheme that transport actually uses — not yet attempted.
- **CONFIRMED, not just the startup burst:** checked a settled window (app
  left open ~90s, not immediately after reopening) and the *steady-state*
  traffic was still 100% TLS-shaped, zero `прямой клиент` hits, ever.
  Android does not send obfuscated2 to this relay at any point observed —
  not just during the initial multi-DC probe burst. Rules out "wait for
  the burst to settle" as an explanation.
- Still not checked: does Telegram actually send/receive messages despite
  the perpetual "Connecting..." UI state. Moot for the moment given the
  pivot below, but relevant if `mtproxy_relay.py` doesn't fully resolve
  it either.

### Also ruled out (checked directly on Server A, both clean)

- **IPv6 bypassing REDIRECT entirely.** `setup_redirect.sh` only ever
  touches `iptables` (IPv4) — `cidr/fetch_telegram_cidr.sh` fetches an
  IPv6 list too but nothing applies it (`ip6tables`), and neither relay
  listens on an IPv6 address. Real concern: if Android's real MTProto
  attempt went out over IPv6, it would never reach either relay and we'd
  never see it. Checked: `ip -6 route show default` is **empty** and
  `curl -6` to a known-good global IPv6 address fails immediately
  ("Сеть недоступна" / network unreachable) — Server A's only IPv6 address
  is a ULA (`fd3f:...`, RFC4193, not internet-routable, likely
  auto-assigned by the home router). No real IPv6 path exists at all, in
  or out — this can't be the gap, on either side.
- **Stale/incomplete Telegram CIDR list.** `cidr/telegram_ipv4.txt`
  (cached 2026-08-17) covers `149.154.160.0/20`, which includes every
  single destination IP observed in the TLS-shaped captures (`.51`,
  `.41`, `.99`, `.167.222`, `.170.200`, `.174.200`, `.175.54` — all fall
  in `160.0–175.255`). REDIRECT is not missing these destinations; they
  were always being caught and delivered to the relay correctly, which
  is exactly what the logs already showed. (Side finding, unrelated:
  re-running `fetch_telegram_cidr.sh` to check for a fresher upstream
  list failed outright — `core.telegram.org` itself doesn't respond over
  TLS from Server A right now. Not investigated further, the cached list
  was already sufficient for this question.)

Both of these were real, testable hypotheses about the iptables/REDIRECT
layer specifically (the user's explicit suggestion for where to look
next) — both came back clean. The gap is not in what gets captured or
delivered to `transparent_relay.py`; it's that Android's real client
genuinely sends TLS instead of obfuscated2 over this network path, for a
reason still not identified.

**Also checked (user's memory, correctly recalled): did the earlier
"get web.telegram.org working" commit chain (`ea1ec87` →
`37cbe19` → `0410f48` → `51b5cd7` → `c173450` → `3dd56ae`, all from
2026-08-17, before this repo's history was made a shallow clone — needed
`git fetch --unshallow` to see them) introduce a regression that broke
Android specifically, only caught for iPhone at the time?** Read every
diff in that chain: none of them ever touch `_decode_direct_client_init()`
(the MTProto/TLS classification function itself) — they only add/refine
what happens *after* that function already says "not MTProto"
(passthrough, its concurrency cap, CF-Worker fallback). The detection
logic is identical from the very first commit (`9625513`) to today. So
this specific chain is not where a decoder regression could hide — ruled
out as the mechanism, though see the SYN-block correction above, which
*was* found by re-reading `c173450` (the self-loop fix in that same
chain) and is a real, useful outcome of chasing this lead even though
the regression theory itself didn't pan out.

### Path taken: `mtproxy_relay.py` (explicit MTProxy, not more reverse-engineering)

The user supplied the key piece of context that ended the guessing: **the
original upstream project, unmodified, with the standard secret-based
MTProxy protocol and a client explicitly configured via a `tg://proxy?...`
link, already worked correctly on both iPhone and Android before this
project adapted it into the transparent no-secret connector.** The
transparent mode was a usability nice-to-have (no client config needed),
not a requirement — and it's the thing that broke on Android, not the
underlying relay machinery.

Rather than continuing to reverse-engineer whatever TLS-shaped transport
unconfigured Android is actually using, added `relay/mtproxy_relay.py` +
vendored `relay/vendor/tg_ws_proxy.py` (the ORIGINAL upstream entry point,
completely unmodified — just imported as a module, same MIT vendoring
convention as the rest of `vendor/`) as a second, independent service.
Runs the real secret-based protocol on a public port; `transparent_relay.py`
is untouched and keeps running for iPhone (or anything else the no-secret
path works for). See README.md "Альтернатива: mtproxy_relay.py" for setup,
`tg-mtproxy-relay.service` for the systemd unit (requires
`ZTG_MTPROXY_SECRET`/`ZTG_MTPROXY_PORT` in `/etc/z2r_autobench/tgrelay.env`
— generate the secret once with `python3 -c "import os; print(os.urandom(16).hex())"`,
never let the service auto-generate one on every restart or every
configured client breaks).

**Deployed and verified on Server A** (2026-08-22): port `9443`, secret
fixed via `ZTG_MTPROXY_SECRET`/`ZTG_MTPROXY_PORT` in
`/etc/z2r_autobench/tgrelay.env`, `tg-mtproxy-relay.service` enabled.
Link configured on the Android device, real MTProto traffic confirmed
flowing (see status note at the top of this section for the one
remaining unverified caveat — cross-network reachability of the
currently-advertised private LAN address). Root cause of *why*
`transparent_relay.py` fails on Android is still open (see above) — this
is a working mitigation, not a fix for the transparent mode itself.

### How to reproduce the diagnostic capture

```bash
cd /opt/Zenith-TG
git pull origin main
systemctl stop tg-transparent-relay
cd relay
/opt/Zenith-TG/.venv/bin/python -u transparent_relay.py --host 127.0.0.1 --port 8447 -v
```
(Manual foreground run hits the shell's default `ulimit -n` under load —
saw `[Errno 24] Too many open files` during a flood of connections. The
systemd unit has its own higher limit and doesn't hit this; only matters
for manual `-v` debug runs like this one. Raise with `ulimit -n 65536`
in the same shell before running if it recurs.)

### 2026-08-28: SNI/ALPN diagnostic added — next concrete lead, not yet run

The hex-dump above only captured the first 16 bytes of each rejected
handshake — nowhere near far enough into a real ClientHello to reach the
`server_name` extension (SNI usually sits 60-200+ bytes in, past
`client_random`/session_id/cipher_suites/compression). Added
`_parse_tls_client_hello()` + `_read_more_for_tls_sniff()` in
`relay/transparent_relay.py`: whenever `_decode_direct_client_init()`
rejects a handshake that starts with `0x16` (TLS), the relay now reads
the rest of that TLS record (using the record's own declared length,
already read to be sure — `already_read` fed to `_passthrough_plain_tcp`
is the FULL buffer including these extra bytes, so passthrough is
unaffected either way) and logs the decoded SNI/ALPN **at INFO level**
(no `-v` needed — this is the actual missing signal, not routine debug
noise). Unit-tested against a hand-built synthetic ClientHello
(`tests/test_tls_sni_parser.py`, no network needed) — confirms the parser
correctly extracts SNI+ALPN from a full ClientHello, returns `None`
(never raises) on a truncated one (e.g. only the first 64 bytes, which is
exactly the old blind spot) or outright garbage.

**Why this is the right next step, not a guess:** `relay/vendor/
tg_ws_proxy.py` (the *original*, unmodified upstream MTProxy code this
project vendors) has an entire branch for exactly this shape of traffic —
`_read_client_init()`'s `if first_byte[0] == TLS_RECORD_HANDSHAKE and
masking:` path unwraps a Fake-TLS-wrapped MTProto handshake via
`fake_tls.py::verify_client_hello()`, which needs to know the *masking
domain* the client thinks it's talking to (it's baked into how the
server-side HMAC-over-`client_random` check works). `transparent_relay.py`
never implemented that branch at all — it only handles the plain
`obfuscated2` case (no secret, no masking) — so if Android/Windows really
are auto-wrapping their connection attempt in Fake-TLS (leading
hypothesis, see above — still unconfirmed), the SNI/ALPN captured here is
exactly the piece of information needed to go implement that branch
correctly. Reproduce the same way as the hex-dump above (`git pull` +
reopen Telegram on Android/Windows), except **the systemd unit's normal
logs already show this now** (`journalctl -u tg-transparent-relay -f`) —
no need for the manual foreground `-v` run just for this signal
specifically (still useful for the raw hex dump if the SNI parse itself
comes back `None`/unexpected). Next step once this is captured: compare
the reported SNI against known masking-domain lists (e.g. what
`fake_tls.py`/`cfproxy_worker_domains` already expect) and decide whether
implementing the Fake-TLS unwrap branch is warranted.

Reopen Telegram on the Android device while this is running, watch for
`non-MTProto handshake head: ...` lines. `Ctrl+C` when done, then
`systemctl start tg-transparent-relay` to restore normal operation —
don't leave the manual foreground run as the only thing serving this
port.

### Environment facts (for context, not secret)

- Android client app: Happ (Xray/VLESS-based). iOS: also Happ, same
  provider config, "preferred API type" defaults differ (IPv4 on iOS,
  was Auto on Android — now set to IPv4 on both).
  Confirmed YouTube/Instagram work fine over the same VLESS tunnel on
  Android — rules out a fully broken tunnel, base connectivity is fine.
- Server-side proxy panel: 3x-ui (`x-ui.service`).
- `_REAL_DC_IDS`, `DEFAULT_DC_IP`, and the `-v` hex-dump diagnostic are
  all in `relay/transparent_relay.py` as of commit `14135fc` (main
  branch, pushed directly — this repo doesn't currently use a designated
  feature branch the way z2r_autobench does).

## REDIRECT rules can be silently wiped by an unrelated service (since 2026-08-23)

- Live incident on Server A: `zapret2.service` (separate repo,
  `z2r_autobench`) crash-looped three times in ~20s overnight (its own
  bug, see that repo's `CLAUDE.md` — a `/opt/zapret2/lua` symlink hid the
  real core lua library files). Each stop/start cycle ran that project's
  own `init.d` iptables clear/apply logic — and despite being a formally
  unrelated table/chain from Zenith-TG's own `nat OUTPUT` REDIRECT rules,
  it wiped them out too. `relay/transparent_relay.py` kept running the
  whole time without any indication of a problem (it only listens on
  `127.0.0.1:8447` — whether traffic actually gets redirected there is
  invisible to it), so Telegram on iOS over VLESS silently broke
  overnight and nobody noticed until morning, well after the YouTube
  outage from the same root cause had already been found and fixed.
- Mitigated (not root-caused, since the other service isn't ours to fix)
  via `relay/redirect_watchdog.sh` + `tg-redirect-watchdog.timer` — runs
  every 5 minutes, checks `iptables -t nat -S OUTPUT` for any `-j
  REDIRECT` rule, and if there are truly zero (not partial corruption —
  that class hasn't been observed) runs `setup_redirect.sh remove` then
  `apply` to restore. Deliberately `remove` before `apply`, never a bare
  re-`apply` — `setup_redirect.sh apply` uses `iptables -A` with no
  existence check, so calling it on top of already-present rules
  duplicates every REDIRECT entry instead of being a no-op.
- Not yet installed on Server A as of this commit — `cp
  relay/tg-redirect-watchdog.{service,timer} /etc/systemd/system/ &&
  systemctl daemon-reload && systemctl enable --now
  tg-redirect-watchdog.timer`, see README.md "Развёртывание на сервере".
