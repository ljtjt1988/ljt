---
name: machtalk-iot-control
description: Control machtalk-cloud IoT devices (water heaters and similar) directly over their native TCP protocol from Python, with no vendor app running - query state, power on/off, change setpoints. Also a complete field guide for reverse-engineering the protocol on your own device. Use when someone wants to script/automate a machtalk or Yunho device, integrate one into home automation, or reverse-engineer a similar Android-app-controlled IoT device. Bring your own credentials; none are bundled.
agent_created: true
---

# Machtalk IoT — direct protocol control

A working Python client for the machtalk cloud platform's native TCP protocol,
plus the method used to recover it. Verified against real hardware: it
authenticates, attaches to the broker, and queries/controls a real device.

**No credentials are bundled.** Everything comes from your `config.json`.
See `references/REVERSE-ENGINEERING.md` for how to obtain the values from
your own device.

---

## Setup (once)

```bash
pip install pycryptodome

cd scripts/
cp config.example.json config.json      # then fill in your own values
```

Four required fields. If any is missing the tool prints exactly where to find it:

| Field | Where it comes from |
|---|---|
| `password` | app log line `pwd:1,<32 chars>` — also derives the AES key/IV |
| `auth_cred` | decrypt one AUTH (0x09) frame from your own capture |
| `phone` | your login account |
| `device_id` | the `to` field of any DATA (0x11) JSON payload |

Have a capture already? Skip the manual work:

```bash
python extract_credentials.py --password <32-char> --pcap yours.pcap --write-config
```

Credentials can also be supplied via `MACHTALK_PHONE` / `MACHTALK_PASSWORD` /
`MACHTALK_AUTH_CRED` / `MACHTALK_DEVICE_ID`, or a config elsewhere via
`MACHTALK_CONFIG=/path/to/config.json` (env wins over the file).

---

## Daily use

```bash
cd scripts/
python machtalk_ctl.py status        # full state snapshot
python machtalk_ctl.py on            # power on   (dpid 101 = 1)
python machtalk_ctl.py off           # power off  (dpid 101 = 0)
python machtalk_ctl.py temp 45       # target temperature (dpid 102)
python machtalk_ctl.py raw 108 2     # write any attribute
python machtalk_ctl.py watch 5       # poll 5 times, 10 s apart
```

```
OK  connected to broker 117.50.9.5:6778 (attempt 1)

  -- device state ----------------------------------
    Power         : off
    Water temp    : 30°C
    Target temp   : 44°C
    Heating       : idle
    WiFi RSSI     : -63dBm
  --------------------------------------------------
```

Output includes handshake diagnostics; filter with
`| grep -E "device state|Power|temp|Heating|WiFi|--"` if you only want the state.

### As a library

```python
import machtalk_client as M

c = M.MachtalkClient()
c.authenticate()        # -> fills c.broker_ip / c.broker_port from AUTH_RESP
c.connect_broker()
print(c.query_status())
c.send_control('101', 1)
c.close()
```

---

## Attribute table

Attribute ids (`dpid`) are device-specific and live in `config.json`, so no code
changes are needed for a different device. Defaults shipped in
`config.example.json` describe a **water heater**:

| dpid | Meaning | Writable |
|---|---|---|
| 101 | power (0/1) | yes |
| 102 | target temperature °C | yes |
| 104 | current water temperature °C | no |
| 106 | heating (0 idle / 1 heating) | no |
| 254 | WiFi RSSI dBm | no |

To derive the table for another device, see
`references/REVERSE-ENGINEERING.md` step 6 (time-series correlation).

---

## Three things that will bite you

**1. A broker timeout is normal, not a failure.** Brokers are load-balanced and
every login hands out a different address; some nodes are unreachable from any
given network. The fix is to *re-authenticate for a different broker*, not to
retry the same one. `machtalk_ctl.py` does this automatically, up to 6 times.

**2. The ACK lies.** A device will echo `{"as":{"102":45}}` and still ignore the
write — a water heater rejects temperature changes while powered off. Always
re-query to confirm. Also, a query fired straight after a write often returns
the stale value.

**3. Partial state snapshots.** `cmd == "post"` is an incremental push
containing only what changed; `cmd == "resp"` is the full snapshot. Code that
accepts the first reply will intermittently see two fields instead of ten.
Use `full_status()`, not a bare `query_status()`.

---

## Protocol summary

```
[AA BB][type:1][plain_len:1][checksum:1][enc_len:2 BE][plain][enc]

checksum = (enc_len_hi + enc_len_lo + sum(plain) + sum(unpadded payload)) & 0xFF
AES-128-CBC, key = password[:16], iv = password[16:], PKCS5
2-byte BE sequence number prepended BEFORE encryption

login server (0x09 AUTH) -> AUTH_RESP carries the broker address
   -> connect broker (0x0a SESSION) -> 40 s heartbeat -> 0x11 DATA (JSON)
```

Two traps worth stating up front, because each one imitates a credential
failure:

* **`dec[0]` of AUTH_RESP is not a status byte.** `0x00`/`0x01`/`0x02`/`0x03`
  have all been seen on successful logins.
* **Parse AUTH_RESP from the end.** The prefix length varies; forward offsets
  slip a byte and silently corrupt every field.

Full details: `references/PROTOCOL.md`.

---

## Files

```
scripts/
  machtalk_client.py       protocol library (frames, crypto, session)
  machtalk_ctl.py          CLI
  extract_credentials.py   pull your own credentials out of your own pcap
  config.example.json      template - copy to config.json
references/
  PROTOCOL.md              wire format specification
  REVERSE-ENGINEERING.md   step-by-step guide for a new device, incl. dead ends
```

`config.json` holds live account secrets. Keep it out of version control.

---

## Reverse-engineering a different device

`references/REVERSE-ENGINEERING.md` is the full field guide. The short version:

1. **Read the app's own log files before anything else** — machtalk's SDK logs
   the login host, the 32-char password, account uids and attribute snapshots.
   That alone yields most of the protocol.
2. **Passive-capture the traffic.** It is not TLS; certificate unpinning is
   wasted effort.
3. **Check whether a suspicious-looking credential actually changes** across
   captures taken hours apart before concluding it expires. Assuming otherwise
   was the single biggest time sink here — it triggered an entirely unnecessary
   emulator + Frida detour for a value that turned out to be constant.
4. **Reproduce one captured frame's payload** before going live. The
   `self_test(expected_auth_hex=...)` helper verifies your frame construction
   against your own capture (see note there about the encryption-prefix
   header). Debugging layout, checksum and crypto simultaneously against a
   server that just drops the connection is far harder.
5. **Derive attribute meanings from time series**, not guesswork — constants are
   settings, drifting values are sensors, and cross-correlations (heating flag
   vs. temp gap) confirm the reading.

**Legal note:** intended for interoperating with hardware and accounts you own.
