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

**Status: ROOT CAUSE FOUND 2026-08-28, fix shipped, NOT YET LIVE-VERIFIED.**
`_decode_direct_client_init()` was hard-rejecting genuine client
`obfuscated2` packets from Android/Windows because their `dc_id` field
didn't fall in Telegram's real `1-5` numbering — proven, not guessed
(all 8 captured samples decode to a valid `proto_tag`, `(3/2^32)^8≈6e-74`
odds of that being chance). Fixed: out-of-range `dc_id` no longer
rejects the packet, just uses a fallback DC for the WS `Host:` header
(routing doesn't depend on it — every DC goes through the same
`149.154.167.220` gateway). See "THE ARTIFACT CAME BACK" below for the
full reasoning. **Next action: pull + restart on Server A, re-test
Android/Windows through the normal VLESS path, confirm real two-way
data flows instead of another instant-close or new failure mode.**

`mtproxy_relay.py` (secret-based, separate service, deployed and
confirmed working on Server A — real MTProto sessions on multiple DCs
DC1/DC2/DC2m/DC4m/DC203 closing normally with substantial two-way data,
one session moved 1.2MB down, verified live in `journalctl -u
tg-mtproxy-relay`) remains available as a fallback mitigation regardless
of how the fix above verifies. Rest of this section is the historical
trail, kept intact for context — **superseded by the finding above, but
the earlier disproven hypotheses are worth reading** so they don't get
re-investigated from scratch: NOT a client-side TLS-wrapping quirk (a
control test through a plain, non-parsing exit — "FI VDS" — worked on
Android/Windows too, ruling that out) — the follow-up "incomplete CIDR
coverage" hypothesis was then RULED OUT too (a fresh fetch of Telegram's
official list matched the cached one byte-for-byte — nothing missing).
What the actual live re-test surfaced instead: the rejected handshakes
in that particular run were NOT
TLS-shaped at all (no accompanying SNI log), a third category distinct
from both `obfuscated2` and the original TLS-ClientHello finding — but
the old diagnostic only hex-dumped 16 bytes at `DEBUG` for exactly this
case, so nothing was visible. Fixed: both non-MTProto branches now log
the first 64 bytes at `INFO`.** See "both steps run" near the bottom of
this section for the full blow-by-blow and the one remaining missing
artifact (the actual 64-byte hex dump, not yet captured).

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

**2026-08-28, both steps run — step 1 ruled OUT, step 2's own tcpdump
filter was flawed, but the live capture from step 1's re-test surfaced
the real next artifact needed:**

1. **CIDR refresh: no functional change.** Fetched `cidr.txt` directly
   from outside Server A (this session's own network access isn't
   subject to Server A's ISP block) since `fetch_telegram_cidr.sh`
   itself still fails from Server A (`core.telegram.org` TLS
   unreachable, same as 2026-08-22). Result: **byte-for-byte the same 9
   IPv4 subnets** already in `cidr/telegram_ipv4.txt` (2026-08-17
   snapshot), just reordered — Telegram's officially published range
   hasn't changed. Ruled out: this isn't a case of a stale/incomplete
   *official* list. (IPv6 ranges exist in the upstream list but were not
   added — Server A has no real outbound IPv6 path at all, per "Also
   ruled out" below, so they're moot here regardless.)

2. **The `tcpdump -i any -n 'tcp dst port 443'` filter was wrong** —
   `iptables -t nat OUTPUT REDIRECT` rewrites the destination *before*
   the packet reaches a physical interface, so a client's real MTProto
   attempt (redirected to `127.0.0.1:8447`) never appears there at all;
   only traffic *exempt* from REDIRECT (the relay's own `tgrelay`-user
   passthrough attempts) or traffic *outside* the CIDR match shows up.
   The actual capture (two runs, ~10:10 and ~10:16) confirmed exactly
   that: a lot of unrelated `142.251.0.0/16` (Google/QUIC) and
   `8.8.4.4` (DNS-over-HTTPS) traffic — nothing to do with Telegram —
   plus the relay's own passthrough SYNs to `149.154.166.111:443` and
   `149.154.167.50:443`, retransmitted with the same sequence number and
   growing backoff, no reply ever — i.e. **two more Telegram IPs
   confirmed SYN-blackholed from Server A**, same class as the
   already-documented `.99`/`.51`/`.41`/`.222`/`175.54`. Useful
   confirmation that the passthrough fallback is even more
   comprehensively doomed than previously catalogued, but doesn't touch
   the actual open question (why the client's original handshake didn't
   decode as `obfuscated2` in the first place) — those SYNs are the
   relay's own second-hop attempt, not the client's original packet.

3. **What the live `journalctl` capture during the SAME re-test DID
   show, and why it's the real next lead:** the burst of `[label] не
   MTProto -- прозрачный TCP passthrough к <ip>:443` lines around
   10:16:09–10:17:09 had **no accompanying `TLS ClientHello` log line**
   — meaning, unlike the original 2026-08-22 hex-dump capture (which was
   unambiguously `0x16 0x03...` real TLS), **these particular rejected
   handshakes are NOT TLS-shaped at all.** Whatever they are, they're a
   third category, distinct from both `obfuscated2` and Fake-TLS. The
   old diagnostic only hex-dumped 16 bytes at `DEBUG` level for this
   non-TLS case, invisible in a normal `journalctl` view — **fixed in
   the same commit as this note**: both non-MTProto branches in
   `_handle_client()` now log the first 64 bytes (all of what's already
   read for the `obfuscated2` check, no extra cost) at `INFO`, not
   `DEBUG`. This is now the single missing artifact: reproduce once more
   (`journalctl -u tg-transparent-relay -f`, reopen Telegram on
   Android/Windows through the normal VLESS path) and paste back the
   `non-MTProto handshake (не TLS), первые 64 байта: ...` lines — those
   64 bytes, compared against what `prober/proto.py::build_obfuscated_init`
   expects, will show exactly which field (if any) is mismatched, or
   reveal a completely different packet shape (worth checking against
   plain/non-obfuscated MTProto's `abridged`/`intermediate` framing,
   which `_decode_direct_client_init()` was never built to recognize at
   all — see its docstring, it only implements the obfuscated2 scheme).

**2026-08-28, THE ARTIFACT CAME BACK — root cause found and fixed
(pending live re-verification):** the re-test produced 8 fresh 64-byte
hex dumps. Ran all 8 through `_decode_direct_client_init()`'s own
formula by hand: **all 8 out of 8 decode to a valid, recognized
`proto_tag`** (`ef ef ef ef` = ABRIDGED, every single time). The odds of
that happening by pure chance on genuinely random bytes are `(3/2^32)^8
≈ 6e-74` — not "unlikely," mathematically impossible for independent
random data. These are real client `obfuscated2` packets. The ONLY
thing that made `_decode_direct_client_init()` reject them was the
`dc_id` field (bytes 60-62 of the decrypted tail): across all 8 samples
it came out as an apparently-uniform-random 16-bit value (12965, 17956,
11312, 3455, 24624, 18029, 19685, and one negative/media-flagged
-31114) — nothing resembling Telegram's real `1-5` DC numbering that
`prober/proto.py`'s own reference encoder assumes. **This is NOT the
same false-positive mechanism as the 2026-08-22 incident** (that one
involved genuine, *structured* TLS ClientHello bytes, where repeated/
patterned input could plausibly bias a self-referential AES-CTR decode
far more than true randomness would — these 8 samples show no visible
structure at all, consistent with intentionally-random `obfuscated2`
padding, not TLS). Conclusion: Android/Windows's real client embeds
*something* other than a `1-5` DC index in that field — semantics not
identified, but irrelevant to fixing this, because **the relay already
knows the real destination DC via `_get_original_dst()`/REDIRECT
regardless of what the client's own field says**, and literally every
`dc` 1-5 routes to the identical `149.154.167.220` WS gateway anyway
(see `DEFAULT_DC_IP`) — the field only ever picked which `Host:` domain
string to present during the WS upgrade.

**Fix shipped in this commit:** `_decode_direct_client_init()` no
longer hard-rejects on an out-of-range `dc_id` — only an unrecognized
`proto_tag` is still a real rejection (kept, since that check alone is
already a ~1-in-1.4-billion-per-packet filter, plenty reliable on its
own). An out-of-range `dc_id` now returns `dc_reliable=False` and a
substitute `_FALLBACK_DC=2` for the WS `Host:` domain, and the
connection is relayed normally instead of falling into
`_passthrough_plain_tcp` (which was *structurally* doomed anyway — see
the SYN-blackhole findings throughout this file). Covered by
`tests/test_decode_direct_client_init.py` (valid dc still marked
reliable; a Telegram-out-of-range dc — reproducing the exact live
symptom via `build_obfuscated_init(12965, ...)` — now relays with the
fallback instead of returning `None`; genuinely unrecognized `proto_tag`
still correctly rejected) plus the existing `test_transparent_relay_e2e.py`
(real network round-trip against `149.154.167.220`, confirms the
already-reliable path is untouched).

**Not yet verified live:** this has NOT been confirmed to fix the
actual Android/Windows "stuck on Connecting" symptom end-to-end — only
that it should stop misrouting these specific packets into a doomed
fallback. Next step: `git pull` + restart `tg-transparent-relay` on
Server A, re-test Android/Windows through the normal VLESS path, and
check for `[label] прямой клиент: proto=... dc_id клиента вне диапазона
-- релею с DC2 по умолчанию` lines followed by either a normal WS
session (ideally with substantial two-way byte counts, not another
instant close) or a new, different failure mode worth capturing.

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

## `cf_worker/worker.js` deployed and confirmed working for web.telegram.org (2026-09-01)

- This closes the open question `cf_worker/README.md` had been carrying
  since it was written ("не проверено на реальном трафике, нужен деплой в
  реальный Cloudflare-аккаунт, к которому у этой сессии Claude нет
  доступа") — a human did the actual deploy (Cloudflare account access is
  inherently outside what any Claude session can do), Claude walked
  through the steps live. **Confirmed on Server A**: `web.telegram.org`
  loads fully through the VLESS tunnel now, including the real
  message-data WS endpoints (`zws2.web.telegram.org`,
  `kws2.web.telegram.org`, `venus.web.telegram.org` all seen going through
  the same passthrough → CF-Worker-fallback path in `journalctl -u
  tg-transparent-relay`) — not just the static page shell.
- Direct TCP to `149.154.167.99` still times out exactly as documented
  elsewhere in this file (SYN null-route, unaffected by any of this) —
  the Worker fallback is what actually carries the traffic, with zero
  `Cloudflare Worker fallback ... тоже не удался` lines in the log,
  confirming Cloudflare's own network path to that IP is clean.
- **Deploy hit one real snag, not an architecture problem**: `wrangler`
  (npm) requires Node ≥22; Debian's own `apt install nodejs` on Server A
  only provides v20 — installed via `nvm install 22` instead of fighting
  apt/NodeSource. Also, `wrangler login`'s OAuth callback listens on
  `localhost` **on the machine running wrangler** (the server), which is
  useless if the human opens the printed link in a browser on their own
  laptop — either `ssh -L 8976:localhost:8976` from the laptop first, or
  skip OAuth entirely and use a Cloudflare API token
  (`export CLOUDFLARE_API_TOKEN=...`, "Edit Cloudflare Workers" template
  scope is sufficient) — the latter is simpler for a headless remote
  server and is what actually got used here.
- **First `wrangler deploy` + `wrangler secret put RELAY_SECRET` attempt
  did NOT work end-to-end on the first try — pure human copy-paste error,
  not a bug**: the instructions handed over said to put "the same secret
  you just set via `wrangler secret put`" into
  `ZTG_CF_WORKER_SECRET=` in `/etc/z2r_autobench/tgrelay.env`, and the
  literal placeholder text (including the angle brackets) got pasted in
  verbatim instead of the actual generated value. Symptom was subtle:
  `Cloudflare Worker fallback включён: ...` DID print at startup (both
  `CF_WORKER_HOST`/`CF_WORKER_SECRET` were non-empty strings, which is
  all that log line checks), so the feature LOOKED configured — the real
  giveaway was every single passthrough attempt still failing with no
  working fallback until the placeholder was replaced with the real
  secret and the service restarted again. Worth remembering next time
  someone hands over a "paste the same value from step N" instruction —
  the software can't tell a placeholder from a real secret if both are
  just non-empty strings.
- Cloudflare account's own workers.dev subdomain is tied to the
  deploying human's account (not reproduced here — publishing hygiene,
  same as not committing real server/provider names) — whoever redeploys
  this Worker gets their own `<something>.workers.dev` address and needs
  to update `ZTG_CF_WORKER_HOST` accordingly; it is not a fixed, shared
  value across deployments.

## Same fallback extended to WhatsApp (2026-09-01)

- Same failure class, confirmed the same way: `curl` from Server A to
  `web.whatsapp.com`/`static.whatsapp.net` times out at the TCP layer
  (SYN null-route), not a DPI/SNI block — the existing passthrough → CF
  Worker fallback in `transparent_relay.py` needed zero code changes,
  since it already classifies traffic generically (any non-MTProto TLS
  goes to passthrough regardless of which REDIRECT rule delivered it).
- Added `cidr/whatsapp_ipv4.txt` — deliberately just the two prefixes
  (`157.240.0.0/17`, `31.13.64.0/18`) containing the confirmed-blocked
  test endpoints, sourced from AS32934's own published RIR records, NOT
  the full Meta ASN (35 CIDR blocks, 500k+ addresses spanning Facebook/
  Instagram/Messenger too — unnecessary blast radius through a relay
  meant for two specific domains). `setup_redirect.sh` gained
  `--cidr-file` so it can be invoked a second time for this list
  alongside the existing Telegram call; the self-loop exclusion insert
  (`-m owner --uid-owner tgrelay -j RETURN`) is now idempotent (checked
  via `iptables -C` before `-I`) so calling `apply` twice doesn't
  duplicate it. `worker.js`'s `ALLOWED_CIDRS` extended with the same two
  prefixes and redeployed (`RELAY_SECRET` untouched by a redeploy — it's
  a separate Worker secret, not part of the script content).
- Confirmed working live the same session: `web.whatsapp.com` opened
  through the VLESS tunnel after `setup_redirect.sh apply --cidr-file
  ../cidr/whatsapp_ipv4.txt` + `wrangler deploy` + relay restart.

## `cf_worker/deploy.sh` — one-command deploy for a fresh server (2026-09-01)

- Direct ask, worth recording the reasoning: "давай ключи зашьём чтобы
  нельзя было достать но и работало из коробки" (bake in the keys so
  they can't be extracted but it works out of the box) — and the
  follow-up "tg-ws-proxy же как-то смог закоммитить с ключами" (well
  tg-ws-proxy managed to commit with keys somehow). Both explained and
  declined as asked, for a reason that doesn't go away with more
  engineering effort: `cfproxy_worker_domains` are OTHER PEOPLE's
  deliberately-open, volunteer-run Workers — a shared public pool with
  nothing to protect. Our `worker.js` runs on the deploying human's OWN
  Cloudflare account; `RELAY_SECRET` exists specifically to stop a
  stranger who finds the `*.workers.dev` URL from riding that account's
  quota for free (and running an open relay is a Cloudflare ToS
  violation — real account-ban risk). A secret baked into code that the
  running process must read to function can always be extracted by
  anyone with the same access the process has — obfuscation adds friction,
  not a real barrier — and this repo is PUBLIC, so committing a real
  secret wouldn't even be "hard to extract," it would be instantly
  published to everyone. Conclusion given to the user: can't ship a
  shared baked-in secret, CAN automate away every manual step except the
  one that's inherently irreducible (a Cloudflare API token — no account,
  nowhere to deploy the Worker at all).
- `deploy.sh` (new, `cf_worker/`): takes `CLOUDFLARE_API_TOKEN` from the
  environment (never written to disk by this script), runs `wrangler
  deploy`, greps the resulting `*.workers.dev` URL out of its output,
  generates a FRESH `openssl rand -hex 32` secret every run (never
  reused across servers or across re-runs — regenerating is cheap and
  each server should have its own), pipes it non-interactively into
  `wrangler secret put RELAY_SECRET`, idempotently writes/updates
  `ZTG_CF_WORKER_HOST`/`ZTG_CF_WORKER_SECRET` in `tgrelay.env` (same
  sed-if-exists-else-append idiom z2r_autobench's `z0r` already uses for
  `ZENITH_PROFILES` — doesn't clobber `ZTG_MTPROXY_SECRET` or anything
  else already in that file), then applies both `setup_redirect.sh`
  calls (Telegram + WhatsApp) and restarts `tg-transparent-relay` if
  it's installed. `--skip-redirect` for a box where the relay service
  isn't installed yet or REDIRECT is managed separately; `--env-file`
  to target something other than the default path.
- This directly fixes the exact bug from the WhatsApp/Telegram deploy
  session immediately before it existed: a human manually copying "the
  same secret you just set" into `tgrelay.env` typed the literal
  placeholder text instead, and nothing caught it until live traffic was
  tested — `deploy.sh` never round-trips the secret through a human's
  clipboard at all, it goes straight from `openssl rand` into both
  `wrangler secret put`'s stdin and the env file programmatically.

## `CLOUDFLARE_API_TOKEN` caching, and why not Google Drive (2026-09-01)

- Direct follow-up ask: "почему апи токен не можем зашить в код деплоя
  мб пусть он в тхт лежит в гугл диске" (why can't we bake the API token
  into the deploy code, maybe keep it as a .txt on Google Drive) —
  wanting to get rid of typing it in even the first time per server.
  Declined the Drive idea specifically (not just "secrets in general"):
  for `deploy.sh` to read it from there automatically, `deploy.sh`
  itself would need ITS OWN credential to access Drive — that doesn't
  remove a secret from the picture, it adds a second one on top and
  moves the trust boundary to whatever sharing setting that Drive file
  has. A shareable link readable by anything with the URL has strictly
  worse guarantees than Cloudflare's own token panel (no access log, no
  revocation UI tied to actual usage, easy to mis-share broader than
  intended) — this is the same class of mistake as committing a secret
  to the repo, just moved one hop away.
- What actually ships: `deploy.sh` now caches `CLOUDFLARE_API_TOKEN`
  itself into `tgrelay.env` (`chmod 600`) right after a deploy actually
  succeeds (inside the `set -e` path — a failed deploy never caches a
  token that might be bad/wrong-scoped). Every subsequent run on THAT
  SAME server — reading env-var first, falling back to
  `grep '^CLOUDFLARE_API_TOKEN=' "$ENV_FILE"` (deliberately not `source`-ing
  the whole file — it can carry other vars not meant to be executed) —
  picks it up with zero prompts. `z0r`'s `tgrelay_setup_cf_worker()`
  mirrors the same cache check before it even decides whether to prompt,
  so the interactive question genuinely only ever appears once per
  server, not once per `deploy.sh` invocation. A genuinely new/different
  server still needs the human to type it in that one time — inherent to
  needing a Cloudflare account at all, no software fix removes that.

## `setup_redirect.sh apply` fully idempotent, `deploy.sh` disables wrangler telemetry prompt (2026-09-01, found on Server B)

- Live audit before a fresh deploy on Server B, prompted by a direct ask
  to check the whole flow up front instead of hitting one missing piece
  at a time (that server had already surfaced the wrangler-not-installed
  and git-dubious-ownership issues in quick succession). Server B's
  Zenith-TG install already had Telegram REDIRECT applied from its
  original `tgrelay_enable()` install — `cf_worker/deploy.sh` calls
  `setup_redirect.sh apply` (Telegram) and `apply --cidr-file
  .../whatsapp_ipv4.txt` (WhatsApp) unconditionally on every run, but only
  the self-loop exclusion insert had the `-C` existence check before
  `-I`/`-A` — the per-CIDR REDIRECT rules themselves had none. Every
  re-run of `deploy.sh` (including this first one, against an
  already-REDIRECTed Telegram list) would have duplicated all 9 Telegram
  rules. Not a routing bug (iptables matches the first hit either way),
  but an unbounded NAT-table bloat that would repeat on every future
  redeploy/secret-rotation. Fixed: the REDIRECT loop in `apply` now does
  the same `-C`-before-`-A` check as the exclusion already did.
- Separately, `deploy.sh` reads `wrangler deploy`'s output via `$(...)`
  — on a genuinely first-ever `wrangler` invocation on a box (exactly
  Server B's situation, `wrangler`/Node were just installed minutes
  earlier), some versions ask an interactive anonymous-telemetry consent
  question. Captured via command substitution, that prompt's text would
  vanish into the captured string instead of reaching the terminal, while
  stdin stays connected — from the outside this looks exactly like
  `deploy.sh` hanging for no visible reason. Fixed defensively (not yet
  needed to reproduce this live to justify it — a well-known, documented
  wrangler env var): `export WRANGLER_SEND_METRICS=false` near the top of
  `deploy.sh`, before the first `wrangler` call.
