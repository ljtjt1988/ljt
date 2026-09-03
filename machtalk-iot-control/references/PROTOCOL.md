# Machtalk cloud IoT — TCP protocol specification

Recovered by reverse-engineering an Android app + packet captures.
Verified against real hardware: the reference implementation in this skill
authenticates, attaches to the broker, and queries/controls a real device.
(One place where it differs from the official app on the wire — and why that is
harmless — is explained under "Sequence numbers & the encryption prefix".)

No credentials appear in this document.

---

## 1. Frame format

```
+------+------+-----------+----------+---------------+-----------+---------+
| AA   | BB   | type      | plain_len| checksum      | enc_len   | ...     |
| 0    | 1    | 2         | 3        | 4             | 5..6 (BE) |         |
+------+------+-----------+----------+---------------+-----------+---------+
| plain_data : plain_len bytes (cleartext)                                 |
| enc_data   : enc_len bytes   (AES-128-CBC, always a multiple of 16)      |
+--------------------------------------------------------------------------+
```

Total frame length = `7 + plain_len + enc_len`.

### Checksum

```
checksum = ( enc_len_hi
           + enc_len_lo
           + sum(plain_data)
           + sum(pre_encryption_payload)      ) & 0xFF
```

`pre_encryption_payload` = the 2-byte sequence prefix + the real payload,
**before** PKCS5 padding is applied.

> **The single most common mistake.** If you decrypt a captured frame and sum
> the result, you include the PKCS5 padding bytes and the checksum will not
> match — but only for AUTH/SESSION frames, because DATA payloads often happen
> to land on a block boundary. That inconsistency sends people hunting for a
> per-frame-type formula that does not exist. Strip the padding first; one
> formula covers every frame type.

### Encryption

* **AES-128-CBC**, PKCS5 padding
* `key = password[:16]` (ASCII bytes)
* `iv  = password[16:]` (ASCII bytes)

The password is a 32-character string the app logs in plaintext, so the whole
protocol is readable once you have that one line. There is no key exchange.

### Sequence numbers & the encryption prefix

This reference implementation prepends a 2-byte big-endian **sequence number**
to the payload **before encryption** (it is therefore part of
`pre_encryption_payload` for the checksum).

* The first frame of a connection is accepted with any value.
* Every subsequent frame must be `+1` or `+2` relative to the previous one.

> **Note on the official app.** The commercial app does *not* use the sequence
> number as the encryption prefix. Instead it prepends a small type-specific
> 2-byte header to the encrypted body — observed values:
> AUTH `08 10`, SESSION `12 88`, and DATA frames carry an incrementing value
> (e.g. `01 b6`, `01 b7`, ...). **The server accepts both forms identically**, so
> the device works whether you send the seq prefix (this skill) or the app's
> headers. The meaningful payload (phone / auth_cred / app_id / JSON) is
> byte-for-byte the same in both cases. `scripts/machtalk_client.py:self_test()`
> verifies the payload with the 2-byte header stripped for exactly this reason.

---

## 2. Frame types

| Type   | Name              | Direction | Purpose                       |
|--------|-------------------|-----------|-------------------------------|
| `0x01` | HEARTBEAT         | →         | keepalive                     |
| `0x02` | HEARTBEAT_RESP    | ←         | keepalive ack                 |
| `0x09` | AUTH              | →         | login                         |
| `0x0a` | SESSION           | →         | attach to broker              |
| `0x0b` | AUTH/SESSION_RESP | ←         | response to both `09` and `0a`|
| `0x11` | DATA              | ↔         | JSON query / control / push   |

---

## 3. Two-stage handshake

```
        ┌─ stage 1: login server (default nls.machtalk.net:6779) ─┐
        │  AUTH (0x09)   ──────────────────────────────────────►  │
        │  AUTH_RESP (0x0b) ◄────  session_uid, user_uid,         │
        │                          api_key, BROKER ADDRESS        │
        └──────────────────────────────────────────────────────────┘
                                  │
                                  ▼   connect to that broker
        ┌─ stage 2: broker (address & port vary per login) ───────┐
        │  SESSION (0x0a)  ────────────────────────────────────►  │
        │  SESSION_RESP (0x0b) ◄──── heartbeat interval (40 s)    │
        │  DATA (0x11)  ◄───────────────────────────────────────► │
        └──────────────────────────────────────────────────────────┘
```

The login server host is printed in the app log as:

```
loginAddr,loginPort,loginType:<host>,<port>,NORMAL
```

Use the **hostname**, not a resolved IP — the IP rotates.

---

## 4. Payload layouts

### AUTH (0x09)

`plain_data`:

```
[0x01] [0x00] [0x02] [phone ASCII]
```

`payload` (encrypted, after the 2-byte seq prefix):

```
[phone_len:1] [phone ASCII]
[LE int32 = 1]                 login type
[0x01] [0x01]                  flags
[cred_len:1]  [auth_cred ASCII]
[BE int32 = app_id]            observed value 5
[0x01]
```

### AUTH_RESP (0x0b)

**Parse from the END.** The prefix length is not constant across responses, so
fixed forward offsets slip by a byte and silently corrupt every field.

```
[ ...variable-length prefix... ]
[session_uid : 32 ASCII]
[user_uid    : 32 ASCII]
[api_key     : 32 ASCII]
[broker_ip   :  4 bytes]
[broker_port :  2 bytes BE]
```

```python
broker_port = (dec[-2] << 8) | dec[-1]
broker_ip   = ".".join(str(b) for b in dec[-6:-2])
api_key     = dec[-38:-6].decode()
user_uid    = dec[-70:-38].decode()
session_uid = dec[-102:-70].decode()
```

> **`dec[0]` is NOT a status code.** Values `0x00`, `0x01`, `0x02` and `0x03`
> have all been observed on *successful* logins. Writing
> `if dec[0] != 0: fail` aborts perfectly good sessions and looks exactly like
> an authentication rejection. Judge success by whether the trailing structure
> parses into a sane uid / api_key / broker instead.

### SESSION (0x0a)

```
plain_data = session_uid            (32 ASCII bytes, from AUTH_RESP)
payload    = BE int32 heartbeat_interval    (observed 40 seconds)
```

### DATA (0x11)

`plain_data` is empty; the payload is compact JSON (no spaces).

Query:

```json
{"to":"<device_id>","cmd":"query","mid":"<random>"}
```

Control:

```json
{"to":"<device_id>","cmd":"opt","mid":"<random>","as":{"<dpid>":<value>}}
```

Responses:

| `cmd`   | Meaning                                            |
|---------|----------------------------------------------------|
| `resp`  | **full** attribute snapshot                        |
| `post`  | incremental push — only the attributes that changed |

Polling code that accepts the first reply will frequently get a `post` with two
fields in it. Keep reading until a `resp` arrives.

---

## 5. Operational notes

**Brokers are load-balanced and some are unreachable.** Every login returns a
different broker address (ports `3009`, `3011`, `3012`, `3013`, `6778` have all
been seen). From any given network a fraction of the nodes simply time out.
The correct retry strategy is to **re-authenticate to obtain a different
broker**, not to retry the same address. Two or three attempts is typically
enough.

**The ACK does not prove the write took effect.** A device may acknowledge an
attribute write with an echo (`{"as":{"102":45}}`) and then ignore it — a water
heater ignores temperature changes while powered off, for instance. Always
re-query to confirm, and expect the value immediately after a write to still be
stale for a second or two.
