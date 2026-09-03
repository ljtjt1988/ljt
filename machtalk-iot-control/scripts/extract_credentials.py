#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract YOUR machtalk credentials from YOUR OWN packet capture.

The only thing you must supply by hand is the 32-character password, which the
app prints to its own log:

    grep -a "pwd:" machtalkLog*CloudService.txt
    ...  data user type,pwd:1,<32 characters>   <- this

That password is also the AES key material (key = pwd[:16], IV = pwd[16:]),
so with it every frame in the capture becomes readable.

Usage
-----
  # from a capture file (.pcap or .pcapng)
  python extract_credentials.py --password <32-char> --pcap capture.pcap

  # from a single frame you copied as hex (e.g. from Wireshark "copy as hex")
  python extract_credentials.py --password <32-char> --hex aabb09...

  # also write scripts/config.json straight away
  python extract_credentials.py --password <32-char> --pcap capture.pcap --write-config

What it pulls out
-----------------
  AUTH (0x09)      -> phone, auth_cred          (the two login secrets)
  DATA (0x11)      -> device_id                 (the "to" field)
  AUTH_RESP (0x0b) -> session_uid, user_uid, api_key, broker ip:port

Nothing is uploaded anywhere; everything runs locally.
"""
import argparse
import json
import os
import re
import struct
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("pycryptodome is required:  pip install pycryptodome")


# ------------------------------------------------------------------
# crypto
# ------------------------------------------------------------------
def make_cipher(password):
    if len(password) != 32:
        sys.exit(f"password must be exactly 32 characters, got {len(password)}")
    return password[:16].encode('ascii'), password[16:].encode('ascii')


def decrypt(blob, key, iv):
    if not blob or len(blob) % 16:
        return None
    try:
        data = AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
    except Exception:
        return None
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        data = data[:-pad]
    return data


# ------------------------------------------------------------------
# capture readers
# ------------------------------------------------------------------
def read_pcap(path):
    """Classic libpcap. Returns concatenated raw packet bytes."""
    raw = open(path, 'rb').read()
    magic = raw[:4]
    if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return None
    endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
    off, out = 24, []
    while off + 16 <= len(raw):
        _, _, incl, _ = struct.unpack(endian + 'IIII', raw[off:off + 16])
        off += 16
        out.append(raw[off:off + incl])
        off += incl
    return b''.join(out)


def read_pcapng(path):
    """pcapng - we only care about Enhanced Packet Blocks (type 0x06)."""
    raw = open(path, 'rb').read()
    if raw[:4] != b'\x0a\x0d\x0d\x0a':
        return None
    endian = '<' if raw[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
    off, out = 0, []
    while off + 12 <= len(raw):
        btype, blen = struct.unpack(endian + 'II', raw[off:off + 8])
        if blen < 12 or off + blen > len(raw):
            break
        if btype == 0x06:                       # Enhanced Packet Block
            cap_len = struct.unpack(endian + 'I', raw[off + 20:off + 24])[0]
            out.append(raw[off + 28:off + 28 + cap_len])
        off += blen
    return b''.join(out)


def load_capture(path):
    for reader in (read_pcap, read_pcapng):
        data = reader(path)
        if data:
            return data
    sys.exit(f"unrecognised capture format: {path} (expected .pcap or .pcapng)")


# ------------------------------------------------------------------
# frame scanning
# ------------------------------------------------------------------
def scan_frames(buf):
    """Find every [AA BB ...] frame in a byte blob.

    We scan the raw bytes rather than reassembling TCP streams - crude, but
    the AA BB magic plus the self-consistent length fields make false
    positives very unlikely, and it needs no dependencies.
    """
    frames, i = [], 0
    while i < len(buf) - 9:
        if buf[i] == 0xAA and buf[i + 1] == 0xBB:
            ftype, plain_len = buf[i + 2], buf[i + 3]
            enc_len = (buf[i + 5] << 8) | buf[i + 6]
            total = 7 + plain_len + enc_len
            if i + total <= len(buf) and enc_len % 16 == 0 and enc_len <= 4096:
                frames.append((ftype, buf[i:i + total]))
                i += total
                continue
        i += 1
    return frames


def parse_auth(frame, key, iv):
    """AUTH 0x09 -> (seq, phone, auth_cred).

    Decrypted layout after the 2-byte BE sequence prefix:
      [phone_len][phone][LE int32 =1][0x01 0x01][cred_len][auth_cred]
      [BE int32 app_id][0x01]
    """
    plain_len = frame[3]
    enc_len = (frame[5] << 8) | frame[6]
    data = decrypt(frame[7 + plain_len:7 + plain_len + enc_len], key, iv)
    if not data or len(data) < 8:
        return None
    seq = (data[0] << 8) | data[1]
    body = data[2:]
    try:
        n = body[0]
        phone = body[1:1 + n].decode('ascii')
        pos = 1 + n + 4 + 2
        clen = body[pos]
        cred = body[pos + 1:pos + 1 + clen].decode('ascii')
        app_id = struct.unpack('>I', body[pos + 1 + clen:pos + 5 + clen])[0]
    except Exception:
        return None
    return seq, phone, cred, app_id


def parse_auth_resp(frame, key, iv):
    """AUTH_RESP 0x0b -> dict.

    IMPORTANT: parse from the END. The prefix length varies between responses,
    so fixed forward offsets slip by a byte. Trailing layout is stable:
      [...variable prefix...][session_uid:32][user_uid:32][api_key:32]
      [broker_ip:4][broker_port:2 BE]
    Also note the first byte is NOT a status code - 0x00/0x01/0x02/0x03 have
    all been observed on successful logins.
    """
    plain_len = frame[3]
    enc_len = (frame[5] << 8) | frame[6]
    data = decrypt(frame[7 + plain_len:7 + plain_len + enc_len], key, iv)
    if not data or len(data) < 102:
        return None
    try:
        return {
            'session_uid': data[-102:-70].decode('ascii'),
            'user_uid': data[-70:-38].decode('ascii'),
            'api_key': data[-38:-6].decode('ascii'),
            'broker': f"{'.'.join(str(b) for b in data[-6:-2])}:"
                      f"{(data[-2] << 8) | data[-1]}",
        }
    except Exception:
        return None


def parse_data(frame, key, iv):
    """DATA 0x11 -> the JSON payload (contains the device id in 'to')."""
    plain_len = frame[3]
    enc_len = (frame[5] << 8) | frame[6]
    data = decrypt(frame[7 + plain_len:7 + plain_len + enc_len], key, iv)
    if not data or len(data) < 3:
        return None
    try:
        return json.loads(data[2:].decode('utf-8'))
    except Exception:
        return None


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Extract machtalk credentials from your own capture.")
    ap.add_argument('--password', required=True,
                    help='32-char password from the app log ("pwd:1,<...>")')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--pcap', help='.pcap / .pcapng capture file')
    src.add_argument('--hex', help='a single frame as a hex string')
    ap.add_argument('--write-config', action='store_true',
                    help='write config.json next to this script')
    args = ap.parse_args()

    key, iv = make_cipher(args.password)

    if args.hex:
        blob = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', args.hex))
    else:
        blob = load_capture(args.pcap)

    frames = scan_frames(blob)
    print(f"scanned {len(blob)} bytes, found {len(frames)} protocol frames")
    counts = {}
    for ftype, _ in frames:
        counts[ftype] = counts.get(ftype, 0) + 1
    print("  by type: " + ", ".join(f"0x{t:02x} x{n}"
                                    for t, n in sorted(counts.items())))

    found = {}
    auth_hexes = []
    devices = set()

    for ftype, frame in frames:
        if ftype == 0x09:
            parsed = parse_auth(frame, key, iv)
            if parsed:
                seq, phone, cred, app_id = parsed
                found.setdefault('phone', phone)
                found.setdefault('auth_cred', cred)
                found.setdefault('app_id', app_id)
                auth_hexes.append((seq, frame.hex()))
        elif ftype == 0x0B:
            resp = parse_auth_resp(frame, key, iv)
            if resp:
                for k, v in resp.items():
                    found.setdefault(k, v)
        elif ftype == 0x11:
            payload = parse_data(frame, key, iv)
            if isinstance(payload, dict) and payload.get('to'):
                devices.add(payload['to'])

    if not found and not devices:
        sys.exit("\nNothing decrypted. Wrong password, or this capture holds no "
                 "machtalk traffic.")

    print("\n" + "=" * 58)
    print("EXTRACTED (these are YOUR secrets - do not share them)")
    print("=" * 58)
    for k in ('phone', 'auth_cred', 'app_id', 'session_uid',
              'user_uid', 'api_key', 'broker'):
        if k in found:
            print(f"  {k:<12}= {found[k]}")
    if devices:
        print(f"  {'device_id':<12}= {', '.join(sorted(devices))}")

    # Multiple AUTH frames let us prove auth_cred is stable, not an expiring token.
    if len(auth_hexes) > 1:
        creds = {found.get('auth_cred')}
        print(f"\n  {len(auth_hexes)} AUTH frames seen "
              f"(seq {', '.join(str(s) for s, _ in auth_hexes[:5])}) "
              f"-> auth_cred is {'STABLE' if len(creds) == 1 else 'VARYING'}")

    if auth_hexes:
        seq, hx = auth_hexes[0]
        print("\n  To byte-verify your frame builder against this capture:")
        print(f"    import machtalk_client as M")
        print(f"    M.self_test(expected_auth_hex=\"{hx}\", seq={seq})")

    if args.write_config:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'config.json')
        if os.path.exists(out):
            print(f"\n  {out} already exists - not overwriting.")
        else:
            cfg = {
                'phone': found.get('phone', ''),
                'password': args.password,
                'auth_cred': found.get('auth_cred', ''),
                'device_id': sorted(devices)[0] if devices else '',
                'app_id': found.get('app_id', 5),
                'auth_host': 'nls.machtalk.net',
                'auth_port': 6779,
            }
            example = os.path.join(os.path.dirname(out), 'config.example.json')
            if os.path.exists(example):
                base = json.load(open(example, encoding='utf-8'))
                for k in ('primary', 'attributes'):
                    if k in base:
                        cfg[k] = base[k]
            with open(out, 'w', encoding='utf-8') as fh:
                json.dump(cfg, fh, indent=2, ensure_ascii=False)
            print(f"\n  wrote {out}")
            missing = [k for k in ('phone', 'auth_cred', 'device_id')
                       if not cfg[k]]
            if missing:
                print(f"  still blank, fill in by hand: {', '.join(missing)}")

    print("=" * 58)
    return 0


if __name__ == '__main__':
    sys.exit(main())
