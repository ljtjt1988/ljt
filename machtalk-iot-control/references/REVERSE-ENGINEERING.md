# How to do this yourself, on your own device

The end goal: control the device from your own code, with no phone app running.

This is the route that actually worked, in the order that works. It also flags
the two blind alleys that cost the most time, so you can skip them.

**Only do this against hardware and accounts you own.**

---

## Step 0 — What you need

* The vendor's Android app, and an account that already controls the device
* A rooted phone, or an Android emulator, or just a PC that can capture the
  phone's traffic
* Python 3 with `pycryptodome`
* Optional: `jadx` for APK inspection (large download; you may not need it)

---

## Step 1 — Read the app's own log files first

**Do this before anything else.** Machtalk's SDK writes verbose logs to the
device, and they give away most of the protocol for free.

```bash
adb shell ls /sdcard/Android/data/<package>/files/
adb pull /sdcard/Android/data/<package>/files/ ./device_logs/
```

Then grep them:

```bash
grep -a "loginAddr"  device_logs/machtalkLog*CloudService.txt   # login host+port
grep -a "pwd:"       device_logs/machtalkLog*CloudService.txt   # the 32-char password
grep -a "UID\|APIKey" device_logs/machtalkLog*CloudService.txt  # account identifiers
grep -a '"as"'       device_logs/log*.txt                       # attribute snapshots
```

What you are looking for:

| Log line                                     | Gives you                        |
|----------------------------------------------|----------------------------------|
| `loginAddr,loginPort,loginType:<host>,<port>,NORMAL` | the login server         |
| `data user type,pwd:1,<32 characters>`       | **the AES key material**         |
| `UID:<32 hex>  APIKey:<32 hex>`              | account identifiers              |
| `"as":{"101":1,"104":45,...}`                | attribute snapshots with timestamps |

That `pwd:` line is the whole ballgame: `key = pwd[:16]`, `iv = pwd[16:]`.
Every encrypted frame in your capture becomes readable from that one string.

---

## Step 2 — Capture traffic

Any method that yields a `.pcap` works. Options in rough order of convenience:

* `tcpdump` on a rooted phone
* PC as hotspot + Wireshark
* Router-side mirror

You do **not** need mitmproxy or certificate pinning bypass. This is not TLS —
it is a custom binary protocol on a plain TCP socket, so a passive capture is
enough. (Time spent on cert unpinning is wasted here.)

Capture at least one full app cold start so you get the login exchange.

---

## Step 3 — Extract your credentials

```bash
python scripts/extract_credentials.py \
    --password <the 32-char string from step 1> \
    --pcap your_capture.pcap \
    --write-config
```

This locates every `AA BB` frame, decrypts them, and prints:

* `phone`, `auth_cred` — from the AUTH (0x09) frame
* `device_id` — from the `to` field of any DATA (0x11) frame
* `session_uid`, `user_uid`, `api_key`, broker address — from AUTH_RESP (0x0b)

`--write-config` drops a ready-to-use `scripts/config.json`.

### Blind alley #1 — "`auth_cred` must be an expiring token"

It looks like a session token, so the natural assumption is that it expires and
must be re-captured live (Frida, emulator, hooking `SocketOutputStream.write`).
That assumption cost the most time of anything in this project.

**Test it before you believe it.** Decrypt AUTH frames from captures taken hours
apart and compare:

```
capture A (seq 1465)  ->  auth_cred = <value>
capture B (seq 2064)  ->  auth_cred = <same value>
capture C (seq 3624)  ->  auth_cred = <same value>
```

Identical across a 7-hour span — it is a **stable credential**, not a token.
`extract_credentials.py` prints `auth_cred is STABLE` when it sees several AUTH
frames agree. Once it is stable, the entire emulator + Frida route is
unnecessary; a single old capture is enough forever.

(Also worth knowing: brute-forcing ~140 combinations of MD5/SHA/HMAC over the
password, phone, uid and api_key produced no match, so `auth_cred` is not
locally derivable either. It is issued once, server-side, and then reused.)

---

## Step 4 — Rebuild the frames and verify against your capture

Validate your frame construction with `self_test()`, which checks the frame
structure and checksum and then compares the **meaningful payload** of a
captured frame to what your builder produces.

```python
import machtalk_client as M
M.self_test(expected_auth_hex="aabb09...", seq=1465)   # printed by step 3
```

`OK  meaningful payload matches your capture` means your understanding of the
layout, the checksum and the encryption is all correct simultaneously. One
caveat: the official app prepends an undocumented per-frame header to the
encrypted body, whereas this builder prepends the sequence number; the server
accepts both, and `self_test` strips that header before comparing (see
PROTOCOL.md "Sequence numbers & the encryption prefix"). Any other result means
the layout, checksum or encryption is wrong, and debugging that against a live
server — which just closes the connection — is far harder.

If the checksum is off, re-read PROTOCOL.md §1: sum the **unpadded
pre-encryption** payload.

---

## Step 5 — Connect for real

```bash
python scripts/machtalk_ctl.py status
```

Sequence: AUTH → read broker from AUTH_RESP → connect broker → SESSION →
DATA query.

### Blind alley #2 — inventing a status byte

The first byte of AUTH_RESP is *not* a result code. Successful logins have
returned `0x00`, `0x01`, `0x02` and `0x03`. A guard like
`if dec[0] != 0: return False` therefore rejects working sessions, and the
symptom — "authentication rejected" — sends you back to step 3 hunting for a
credential problem that does not exist.

Judge success structurally: does the tail of the response parse into a
plausible uid / api_key / broker? See PROTOCOL.md §4.

Also parse AUTH_RESP **from the end**. The prefix length varies, so
`dec[4:36]`-style forward offsets slide by one byte and produce garbage that
looks almost right.

### If the broker times out

Normal. Brokers are load-balanced and some nodes are unreachable from any given
network. Re-authenticate to get a different one — `machtalk_ctl.py` retries up
to 6 times automatically.

---

## Step 6 — Work out what the attributes mean

Attributes arrive as opaque numeric ids: `{"as":{"101":1,"102":44,"104":45}}`.

Rather than guessing, build a **time series** and correlate it with physical
reality. The app logs from step 1 already contain hours of snapshots:

```bash
grep -ao '"as":{[^}]*}' device_logs/log*.txt
```

| dpid | 07:05 | 21:00 | Inference                                   |
|------|-------|-------|---------------------------------------------|
| 101  | 0     | 1     | changes when you toggle power → **power**   |
| 102  | 44    | 44    | constant, matches the app's setpoint → **target temp** |
| 104  | 28    | 45    | drifts continuously → **current temp**      |

Three rules that make this fast:

1. **Constant values** are settings; **drifting values** are sensors.
2. **Toggle one thing in the app** and diff the snapshot before and after.
3. **Look for correlations** — a "heating" flag should be 1 exactly when
   current temp < target temp. That is a free cross-check, and it is how dpid
   106 was confirmed rather than guessed.

Write the result into `config.json` under `attributes`; the CLI renders names
and units straight from there, so no code changes are needed for a new device.

### Verify writes properly

Send the value, then **query again**. Do not trust the ACK: a device will echo
`{"as":{"102":45}}` and still ignore the write (a water heater rejects
temperature changes while powered off). And a query fired immediately after a
write often returns the pre-write value because the device has not refreshed.

---

## What to skip

| Approach | Why it was a waste |
|---|---|
| mitmproxy / certificate unpinning | Not TLS. Plain TCP; passive capture is enough. |
| Frida + emulator to re-capture credentials | `auth_cred` is stable. Verify that first. |
| Brute-forcing hashes to derive `auth_cred` | ~140 combinations, no match. Server-issued. |
| Deep APK decompilation as the first move | The app's own log files gave up more, faster. Reach for `jadx` only when the logs run out. |

---

## Reusing this on a non-machtalk device

The specific frame layout will differ, but the method transfers:

1. Read the app's own logs before touching a decompiler — SDK authors log a lot.
2. Look for a logged password/key string; symmetric keys are routinely derived
   from something already in plaintext on disk.
3. Passive-capture first; assume plain TCP until proven otherwise.
4. Reproduce one captured frame's payload (via `self_test`) before going live.
5. Validate assumptions across *multiple* captures before declaring a value
   "dynamic" or "expiring" — that single check would have saved the most time here.
