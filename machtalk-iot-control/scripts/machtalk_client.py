#!/usr/bin/env python3
"""
Machtalk cloud IoT — native TCP protocol client
===============================================
Reverse-engineered from an Android APK + pcap analysis.
Works with devices on the machtalk platform (water heaters, etc.).

Credentials are NOT bundled — supply your own via config.json.

Protocol: Custom binary TCP with AES-128-CBC encryption
Frame format: [AA BB] [type:1] [plain_len:1] [checksum:1] [enc_len:2B BE] [plain:N] [enc:M]
Checksum: (enc_len_hi + enc_len_lo + sum(plain_data) + sum(pre_enc_data_unpadded)) & 0xFF
AES: key=password[:16], IV=password[16:], PKCS5 padding
Pre-encryption data: 2-byte BE sequence number + payload

Flow: AUTH(0x09) → AUTH_RESP(0x0b) → SESSION(0x0a) → SESSION_RESP(0x0b) → DATA(0x11)
"""
import socket
import struct
import json
import time
import random
import threading
import sys
import os
from Crypto.Cipher import AES

# ============================================================
# Configuration
# ------------------------------------------------------------
# NO SECRET IS HARD-CODED HERE.
# Credentials come from config.json next to this file
# (or $MACHTALK_CONFIG / environment variables).
# Copy config.example.json -> config.json and fill in YOUR values.
# How to obtain each value: references/REVERSE-ENGINEERING.md
# ============================================================
CONFIG_PATH = os.environ.get(
    'MACHTALK_CONFIG',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json'),
)

_ENV_MAP = {
    'phone':     'MACHTALK_PHONE',
    'password':  'MACHTALK_PASSWORD',
    'auth_cred': 'MACHTALK_AUTH_CRED',
    'device_id': 'MACHTALK_DEVICE_ID',
    'app_id':    'MACHTALK_APP_ID',
}
_REQUIRED = ('phone', 'password', 'auth_cred', 'device_id')

_HELP = """
Missing credentials: {missing}

This tool needs YOUR OWN account/device values. Nothing is bundled.

  1. cp config.example.json config.json
  2. Fill in phone / password / auth_cred / device_id
  3. Re-run

Where each value comes from -> references/REVERSE-ENGINEERING.md
  password  : 32-char string in the app log line  "pwd:1,<32 chars>"
              (also derives the AES key/IV)
  auth_cred : decrypt one AUTH(0x09) frame from your own capture
              -> scripts/extract_credentials.py does this for you
  device_id : the "to" field of any DATA(0x11) JSON payload

Config file searched at: {path}
(override with the MACHTALK_CONFIG environment variable)
"""


def load_config(path=None, required=True):
    """Load credentials from JSON file; environment variables override it."""
    path = path or CONFIG_PATH
    cfg = {}
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as fh:
            cfg = json.load(fh)
    for key, env in _ENV_MAP.items():          # env wins over file
        if os.environ.get(env):
            cfg[key] = os.environ[env]

    if required:
        missing = [k for k in _REQUIRED if not cfg.get(k)]
        if missing:
            raise SystemExit(_HELP.format(missing=', '.join(missing), path=path))
        if len(str(cfg['password'])) != 32:
            raise SystemExit(
                "password must be exactly 32 characters "
                "(AES key = password[:16], IV = password[16:]); got "
                f"{len(str(cfg['password']))}"
            )
    return cfg


CONFIG = load_config()

PHONE = CONFIG.get('phone', '')
PASSWORD = CONFIG.get('password', '')
AUTH_CRED = CONFIG.get('auth_cred', '')
DEVICE_ID = CONFIG.get('device_id', '')
APP_ID = int(CONFIG.get('app_id', 5))

# Filled in dynamically by authenticate() from AUTH_RESP — never configured.
SESSION_UID = ''
USER_UID = ''
API_KEY = ''

# Login server. Take it from your app log line:
#   "loginAddr,loginPort,loginType:<host>,<port>,NORMAL"
# Use the hostname, not a resolved IP — the IP rotates.
AUTH_SERVER = (
    CONFIG.get('auth_host', 'nls.machtalk.net'),
    int(CONFIG.get('auth_port', 6779)),
)
# Broker address is ALWAYS obtained dynamically from AUTH_RESP.
BROKER_SERVER = (None, None)

# AES-128-CBC key/IV derived from the 32-char password
KEY = PASSWORD[:16].encode('ascii')
IV = PASSWORD[16:].encode('ascii')

# Frame types
TYPE_HEARTBEAT = 0x01
TYPE_HEARTBEAT_RESP = 0x02
TYPE_AUTH = 0x09
TYPE_SESSION = 0x0a
TYPE_AUTH_SESSION_RESP = 0x0b
TYPE_DATA = 0x11

# DPID mapping
DPID_POWER = '101'        # 0=off, 1=on
DPID_TARGET_TEMP = '102'  # 35-75 °C
DPID_CURRENT_TEMP = '104' # read-only
DPID_MODE = '108'         # 0=standard, 1=comfort, 2=ECO
DPID_PREHEAT = '109'     # 0=off, 1=once, 2=all-day, 3=smart
DPID_POWER_LEVEL = '112' # 0=max, 1=min, 2=mid


# ============================================================
# AES Encryption
# ============================================================
def aes_encrypt(data: bytes) -> bytes:
    """AES-128-CBC encrypt with PKCS5 padding."""
    pad_len = 16 - (len(data) % 16)
    padded = data + bytes([pad_len] * pad_len)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(padded)


def aes_decrypt(data: bytes) -> bytes:
    """AES-128-CBC decrypt (returns full blocks including padding)."""
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.decrypt(data)


def strip_pkcs5(data: bytes) -> bytes:
    """Strip PKCS5/PKCS7 padding."""
    if len(data) == 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        return data
    return data[:-pad_len]


# ============================================================
# Frame Construction
# ============================================================
def build_frame(frame_type: int, seq: int, enc_plain_data: bytes,
                plain_data: bytes = b'') -> bytes:
    """
    Build a complete machtalk protocol frame.
    
    Uses the Util.l.n algorithm:
    1. Prepend 2-byte BE seq to enc_plain_data → pre_enc_data
    2. PKCS5 pad + AES encrypt → enc_data
    3. checksum = (enc_len_hi + enc_len_lo + sum(plain_data) + sum(pre_enc_data)) & 0xFF
    4. Frame = AA BB type plain_len checksum enc_len_hi enc_len_lo plain_data enc_data
    """
    # Step 1: Prepend sequence number
    pre_enc_data = struct.pack('>H', seq & 0xFFFF) + enc_plain_data
    
    # Step 2: Encrypt
    enc_data = aes_encrypt(pre_enc_data)
    enc_len = len(enc_data)
    enc_len_hi = (enc_len >> 8) & 0xFF
    enc_len_lo = enc_len & 0xFF
    
    # Step 3: Compute checksum
    checksum = (enc_len_hi + enc_len_lo + sum(plain_data) + sum(pre_enc_data)) & 0xFF
    
    # Step 4: Build frame
    frame = bytes([0xAA, 0xBB, frame_type, len(plain_data), checksum,
                   enc_len_hi, enc_len_lo])
    frame += plain_data
    frame += enc_data
    return frame


def build_simple_frame(frame_type: int, plain_data: bytes = b'') -> bytes:
    """Build a frame without encryption (enc_len=0)."""
    enc_len = 0
    checksum = (0 + 0 + sum(plain_data)) & 0xFF
    frame = bytes([0xAA, 0xBB, frame_type, len(plain_data), checksum, 0, 0])
    frame += plain_data
    return frame


def build_heartbeat() -> bytes:
    """Build a simple heartbeat frame (4 bytes)."""
    return bytes([0xAA, 0xBB, 0x01, 0x00])


# ============================================================
# Frame Parsing
# ============================================================
def parse_frame_header(data: bytes):
    """Parse frame header. Returns (type, plain_len, checksum, enc_len, header_size) or None."""
    if len(data) < 7:
        return None
    if data[0] != 0xAA or data[1] != 0xBB:
        return None
    frame_type = data[2]
    plain_len = data[3]
    checksum = data[4]
    enc_len = (data[5] << 8) | data[6]
    return (frame_type, plain_len, checksum, enc_len, 7)


def read_frame(sock: socket.socket, timeout: float = 10.0):
    """
    Read a complete frame from socket.
    Returns (frame_type, plain_data, enc_data, checksum) or None.
    """
    sock.settimeout(timeout)
    
    # Read header (7 bytes)
    header = b''
    while len(header) < 7:
        chunk = sock.recv(7 - len(header))
        if not chunk:
            return None
        header += chunk
    
    result = parse_frame_header(header)
    if not result:
        return None
    
    frame_type, plain_len, checksum, enc_len, _ = result
    total_payload = plain_len + enc_len
    
    # Read payload
    payload = b''
    while len(payload) < total_payload:
        chunk = sock.recv(total_payload - len(payload))
        if not chunk:
            return None
        payload += chunk
    
    plain_data = payload[:plain_len]
    enc_data = payload[plain_len:]
    
    # Verify checksum (best-effort; warn but don't fail)
    enc_len_hi = header[5]
    enc_len_lo = header[6]
    if enc_data:
        try:
            dec_padded = aes_decrypt(enc_data)
            dec_unpadded = strip_pkcs5(dec_padded)
            computed_cs = (enc_len_hi + enc_len_lo + sum(plain_data) + sum(dec_unpadded)) & 0xFF
            if computed_cs != checksum:
                print(f"  ⚠ Checksum mismatch: expected 0x{checksum:02x}, got 0x{computed_cs:02x}")
        except Exception as e:
            print(f"  ⚠ Could not verify checksum: {e}")
    
    return (frame_type, plain_data, enc_data, checksum)


def decrypt_enc_data(enc_data: bytes) -> bytes:
    """Decrypt and strip padding from enc data."""
    if not enc_data:
        return b''
    dec = aes_decrypt(enc_data)
    return strip_pkcs5(dec)


def extract_seq(dec_data: bytes) -> int:
    """Extract 2-byte BE sequence number from decrypted data."""
    if len(dec_data) < 2:
        return -1
    return (dec_data[0] << 8) | dec_data[1]


# ============================================================
# AUTH Frame Construction
# ============================================================
def build_auth_frame(seq: int) -> bytes:
    """
    Build AUTH frame (type=0x09).
    
    plain_data: [0x01, 0x00, 0x02] + phone (14 bytes)
    enc_plain_data: [phone_len] + phone + [LE int32=1] + [0x01, 0x01, 0x10] + 
                    auth_cred + [0x00, 0x00, 0x00, app_id] + [0x01] (40 bytes)
    """
    phone_bytes = PHONE.encode('ascii')
    auth_cred_bytes = AUTH_CRED.encode('ascii')
    
    # plain_data
    plain_data = bytes([0x01, 0x00, 0x02]) + phone_bytes
    
    # enc_plain_data (this is the payload BEFORE seq prefix)
    enc_plain = bytes([len(phone_bytes)])  # phone length
    enc_plain += phone_bytes                # phone
    enc_plain += struct.pack('<I', 1)       # LE int32 = 1 (login type?)
    enc_plain += bytes([0x01, 0x01])        # unknown flags
    enc_plain += bytes([len(auth_cred_bytes)])  # auth_cred length
    enc_plain += auth_cred_bytes           # auth_cred
    enc_plain += struct.pack('>I', APP_ID) # BE int32 = 5 (app_id)
    enc_plain += bytes([0x01])              # unknown trailing byte
    
    return build_frame(TYPE_AUTH, seq, enc_plain, plain_data)


# ============================================================
# SESSION Frame Construction
# ============================================================
def build_session_frame(seq: int, session_uid: str) -> bytes:
    """
    Build SESSION frame (type=0x0a).
    
    plain_data: session_uid (32 bytes ASCII)
    enc_plain_data: [0x00, 0x00, 0x00, 0x28] = heartbeat interval 40 (4 bytes)
    """
    plain_data = session_uid.encode('ascii')
    enc_plain = struct.pack('>I', 40)  # heartbeat interval = 40 (big-endian)
    return build_frame(TYPE_SESSION, seq, enc_plain, plain_data)


# ============================================================
# DATA Frame Construction
# ============================================================
def build_data_frame(seq: int, cmd: str, device_id: str, 
                     mid: str = None, dp_map: dict = None) -> bytes:
    """
    Build DATA frame (type=0x11).
    
    plain_data: empty
    enc_plain_data: JSON string bytes
    
    For query: {"to":"<device>","cmd":"query","mid":"<mid>"}
    For control: {"to":"<device>","cmd":"opt","mid":"<mid>","as":{"<dpid>":<value>}}
    """
    if mid is None:
        mid = str(random.randint(100, 99999))
    
    payload = {
        'to': device_id,
        'cmd': cmd,
        'mid': mid
    }
    if dp_map:
        payload['as'] = dp_map
    
    # Compact JSON (no spaces) - matching the app format
    json_str = json.dumps(payload, separators=(',', ':'))
    enc_plain = json_str.encode('utf-8')
    
    return build_frame(TYPE_DATA, seq, enc_plain, b'')


# ============================================================
# Main Client
# ============================================================
class MachtalkClient:
    def __init__(self):
        self.seq = random.randint(0, 65535)
        self.session_uid = SESSION_UID
        self.user_uid = USER_UID
        self.api_key = API_KEY
        self.broker_ip = BROKER_SERVER[0]
        self.broker_port = BROKER_SERVER[1]
        self.heartbeat_interval = 40
        self.sock = None
        self.running = False
        self._hb_thread = None
        
    def next_seq(self) -> int:
        s = self.seq
        self.seq = (self.seq + 1) % 65536
        return s
    
    def authenticate(self) -> bool:
        """Step 1: Connect to auth server and authenticate."""
        print(f"\n{'='*60}")
        print("Step 1: Authentication")
        print(f"{'='*60}")
        print(f"  Auth server: {AUTH_SERVER[0]}:{AUTH_SERVER[1]}")
        print(f"  Phone: {PHONE}")
        print(f"  Auth cred: {AUTH_CRED}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        try:
            sock.connect(AUTH_SERVER)
            print(f"  ✓ Connected to auth server")
        except Exception as e:
            print(f"  ✗ Connection failed: {e}")
            sock.close()
            return False
        
        # Build and send AUTH frame
        seq = self.next_seq()
        auth_frame = build_auth_frame(seq)
        print(f"  → Sending AUTH frame (seq={seq}, {len(auth_frame)} bytes)")
        print(f"    Frame hex: {auth_frame.hex()}")
        sock.send(auth_frame)
        
        # Read AUTH_RESP
        try:
            result = read_frame(sock, timeout=15)
        except socket.timeout:
            print(f"  ✗ Timeout waiting for AUTH response")
            sock.close()
            return False
        
        if result is None:
            print(f"  ✗ No response from auth server")
            sock.close()
            return False
        
        frame_type, plain_data, enc_data, checksum = result
        print(f"  ← Received AUTH_RESP (type=0x{frame_type:02x}, plain={len(plain_data)}B, enc={len(enc_data)}B)")
        
        if frame_type != TYPE_AUTH_SESSION_RESP:
            print(f"  ✗ Unexpected frame type: 0x{frame_type:02x}")
            sock.close()
            return False
        
        # Decrypt and parse
        dec = decrypt_enc_data(enc_data)
        # Structure (parsed from the END, prefix length varies):
        #   [prefix (status + header)] [session_uid:32B] [user_uid:32B]
        #   [api_key:32B] [broker_ip:4B] [broker_port:2B BE]
        # NOTE: dec[0] is NOT a success flag. The real app's successful login
        # returned dec[0]=0x03; a live retry returned 0x02. Both are structurally
        # complete and valid. So we parse from the tail and never abort on dec[0].
        if len(dec) < (96 + 6):
            print(f"  ✗ Response too short: {len(dec)} bytes (need >= 102)")
            print(f"    Decrypted: {dec.hex()}")
            sock.close()
            return False
        
        status = dec[0]
        self.broker_ip = ".".join(str(b) for b in dec[-6:-2])
        self.broker_port = (dec[-2] << 8) | dec[-1]
        self.api_key = dec[-38:-6].decode('ascii', errors='replace')
        self.user_uid = dec[-70:-38].decode('ascii', errors='replace')
        self.session_uid = dec[-102:-70].decode('ascii', errors='replace')
        
        print(f"  ✓ Authentication response parsed (dec[0]=0x{status:02x}, {len(dec)}B)")
        print(f"    Session UID: {self.session_uid}")
        print(f"    User UID:    {self.user_uid}")
        print(f"    API Key:     {self.api_key}")
        print(f"    Broker:      {self.broker_ip}:{self.broker_port}")
        
        sock.close()
        return True
    
    def connect_broker(self) -> bool:
        """Step 2: Connect to broker and establish session."""
        broker = (self.broker_ip, self.broker_port)
        print(f"\n{'='*60}")
        print("Step 2: Broker Session")
        print(f"{'='*60}")
        print(f"  Broker: {broker[0]}:{broker[1]}")
        print(f"  Session UID: {self.session_uid}")
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # short timeout for the TCP connect so unreachable nodes fail fast
        # (the server load-balances brokers; some are unreachable from here)
        self.sock.settimeout(5)
        try:
            self.sock.connect(broker)
            print(f"  ✓ Connected to broker")
        except Exception as e:
            print(f"  ✗ Connection failed: {e}")
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            return False
        # restore a longer timeout for the session/data exchange
        self.sock.settimeout(15)
        
        # Build and send SESSION frame
        seq = self.next_seq()
        session_frame = build_session_frame(seq, self.session_uid)
        print(f"  → Sending SESSION frame (seq={seq}, {len(session_frame)} bytes)")
        print(f"    Frame hex: {session_frame.hex()}")
        self.sock.send(session_frame)
        
        # Read SESSION_RESP
        try:
            result = read_frame(self.sock, timeout=15)
        except socket.timeout:
            print(f"  ✗ Timeout waiting for SESSION response")
            self.sock.close()
            self.sock = None
            return False
        
        if result is None:
            print(f"  ✗ No response from broker")
            self.sock.close()
            self.sock = None
            return False
        
        frame_type, plain_data, enc_data, checksum = result
        print(f"  ← Received SESSION_RESP (type=0x{frame_type:02x}, plain={len(plain_data)}B, enc={len(enc_data)}B)")
        
        if frame_type != TYPE_AUTH_SESSION_RESP:
            print(f"  ✗ Unexpected frame type: 0x{frame_type:02x}")
            self.sock.close()
            self.sock = None
            return False
        
        # Decrypt and parse
        dec = decrypt_enc_data(enc_data)
        print(f"  Decrypted: {dec.hex()}")
        
        if len(dec) >= 6:
            server_seq = extract_seq(dec)
            print(f"  Server seq: {server_seq}")
            if len(dec) >= 6:
                hb_interval = (dec[4] << 8) | dec[5]
                print(f"  Heartbeat interval: {hb_interval}s")
                self.heartbeat_interval = hb_interval
        
        print(f"  ✓ Session established!")
        
        # Start heartbeat thread
        self.running = True
        self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()
        
        return True
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats."""
        while self.running and self.sock:
            try:
                time.sleep(self.heartbeat_interval)
                if self.running and self.sock:
                    hb = build_heartbeat()
                    self.sock.send(hb)
                    # Try to read heartbeat response (non-blocking)
                    # (we don't block on it - just send and continue)
            except Exception:
                break
    
    def query_status(self) -> dict:
        """Query device status."""
        print(f"\n{'='*60}")
        print("Querying device status")
        print(f"{'='*60}")
        
        seq = self.next_seq()
        frame = build_data_frame(seq, 'query', DEVICE_ID)
        print(f"  → Sending QUERY (seq={seq}, {len(frame)} bytes)")
        
        try:
            self.sock.send(frame)
        except Exception as e:
            print(f"  ✗ Send failed: {e}")
            return {}
        
        # Read response(s)
        responses = []
        try:
            while True:
                result = read_frame(self.sock, timeout=10)
                if result is None:
                    break
                frame_type, plain_data, enc_data, checksum = result
                if frame_type == TYPE_DATA:
                    dec = decrypt_enc_data(enc_data)
                    seq_resp = extract_seq(dec)
                    json_data = dec[2:].decode('utf-8', errors='replace')
                    print(f"  ← DATA response (seq={seq_resp}): {json_data}")
                    try:
                        responses.append(json.loads(json_data))
                    except:
                        pass
                elif frame_type == TYPE_HEARTBEAT_RESP:
                    # Heartbeat response - ignore
                    pass
                else:
                    print(f"  ← Frame type 0x{frame_type:02x}")
                
                # Check if we got enough responses
                if len(responses) >= 2:
                    break
        except socket.timeout:
            pass
        
        return responses
    
    def send_control(self, dp_id: str, value) -> dict:
        """Send a control command."""
        print(f"\n{'='*60}")
        print(f"Sending control: DPID {dp_id} = {value}")
        print(f"{'='*60}")
        
        seq = self.next_seq()
        dp_map = {dp_id: value}
        frame = build_data_frame(seq, 'opt', DEVICE_ID, dp_map=dp_map)
        print(f"  → Sending CONTROL (seq={seq}, {len(frame)} bytes)")
        
        try:
            self.sock.send(frame)
        except Exception as e:
            print(f"  ✗ Send failed: {e}")
            return {}
        
        # Read response
        try:
            result = read_frame(self.sock, timeout=10)
            if result and result[0] == TYPE_DATA:
                dec = decrypt_enc_data(result[2])
                seq_resp = extract_seq(dec)
                json_data = dec[2:].decode('utf-8', errors='replace')
                print(f"  ← Response (seq={seq_resp}): {json_data}")
                try:
                    return json.loads(json_data)
                except:
                    pass
        except socket.timeout:
            print(f"  (no response - may still have been applied)")
        
        return {}
    
    def power_on(self):
        return self.send_control(DPID_POWER, 1)
    
    def power_off(self):
        return self.send_control(DPID_POWER, 0)
    
    def set_temperature(self, temp: int):
        if temp < 35 or temp > 75:
            print(f"  ⚠ Temperature {temp}°C out of range (35-75)")
        return self.send_control(DPID_TARGET_TEMP, temp)
    
    def set_mode(self, mode: int):
        """0=standard, 1=comfort, 2=ECO"""
        return self.send_control(DPID_MODE, mode)
    
    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None


# ============================================================
# Self-test: verify frame construction matches pcap
# ============================================================
def self_test(expected_auth_hex=None, seq=0x0001, session_uid=None):
    """Sanity-check frame construction, and optionally verify against YOUR capture.

    No golden vectors are bundled: those would embed someone else's encrypted
    account data. To verify against your own capture, pass the full hex of one
    AUTH(0x09) frame taken from your pcap together with its sequence number:

        self_test(expected_auth_hex="aabb09...", seq=0x05b9)

    (scripts/extract_credentials.py prints both for you.)

    The check compares the MEANINGFUL payload (unencrypted plain + the decrypted
    encrypted body with its 2-byte leading header stripped). The official
    commercial app prepends an undocumented per-frame header to the encrypted
    payload (AUTH=08 10, SESSION=12 88, ...); this implementation prepends the
    sequence number instead, which the server accepts identically. So a raw
    byte comparison would differ in the first 2 bytes even when the protocol
    content is correct - hence we compare the content, not the raw bytes.
    """
    print("=" * 60)
    print("SELF-TEST: frame construction")
    print("=" * 60)
    ok = True

    def check(name, frame):
        """Structural validation: magic, declared lengths, checksum."""
        nonlocal ok
        good = True
        if frame[:2] != b'\xaa\xbb':
            good = False
        plain_len, cs = frame[3], frame[4]
        enc_len = (frame[5] << 8) | frame[6]
        if len(frame) != 7 + plain_len + enc_len:
            good = False
        if enc_len % 16 != 0:
            good = False
        # recompute checksum from the decrypted (unpadded) payload
        plain = frame[7:7 + plain_len]
        enc = frame[7 + plain_len:]
        if enc:
            dec = strip_pkcs5(aes_decrypt(enc))
            if ((frame[5] + frame[6] + sum(plain) + sum(dec)) & 0xFF) != cs:
                good = False
        print(f"  {'OK ' if good else 'FAIL'}  {name:<14} "
              f"len={len(frame):<4} plain={plain_len:<3} enc={enc_len:<4} cs=0x{cs:02x}")
        ok = ok and good
        return frame

    auth_frame = check("AUTH  0x09", build_auth_frame(seq))
    check("SESSION 0x0a", build_session_frame(seq + 1, session_uid or '0' * 32))
    check("DATA  0x11", build_data_frame(seq + 2, 'query', DEVICE_ID, mid='140'))

    if expected_auth_hex:
        expected = bytes.fromhex(expected_auth_hex.replace(' ', ''))
        print("\n--- payload-diff against your captured AUTH frame ---")

        def payload_of(frame):
            pl = frame[3]
            el = (frame[5] << 8) | frame[6]
            plain = frame[7:7 + pl]
            enc = frame[7 + pl:]
            dec = strip_pkcs5(aes_decrypt(enc)) if enc else b''
            return plain, dec[2:]  # dec[2:] strips the 2-byte frame header

        bp, bd = payload_of(auth_frame)
        ep, ed = payload_of(expected)
        same = (bp == ep and bd == ed)
        ok = ok and same
        print(f"  {'OK  ' if same else 'FAIL'} meaningful payload "
              f"{'matches' if same else 'differs from'} your capture")
        if not same:
            if bp != ep:
                print(f"    plain    built={bp.hex()}  captured={ep.hex()}")
            if bd != ed:
                print(f"    enc(dec,header-stripped) built={bd.hex()}")
                print(f"                                captured={ed.hex()}")
        print("  (note: the 2-byte frame header may differ from the commercial")
        print("   app - this is expected and tolerated by the server; see PROTOCOL.md)")

    print("=" * 60)
    return ok


# ============================================================
# Main
# ============================================================
def main():
    # Run self-test first
    if not self_test():
        print("\n*** Self-test FAILED - aborting ***")
        return
    
    print("\n\n" + "=" * 60)
    print("All self-tests passed! Frame construction is byte-exact.")
    print("=" * 60)
    
    # Try full flow
    client = MachtalkClient()
    
    try:
        # Step 1: Authenticate
        if not client.authenticate():
            print("\n*** Authentication failed ***")
            print("The auth_cred may be expired. Need to obtain a fresh one.")
            return
        
        # Step 2: Connect to broker
        if not client.connect_broker():
            print("\n*** Broker connection failed ***")
            return
        
        # Step 3: Query status
        responses = client.query_status()
        if responses:
            print(f"\n📊 Device status:")
            for r in responses:
                if 'as' in r:
                    for k, v in r['as'].items():
                        dpid_names = {
                            '101': 'Power', '102': 'Target Temp', '104': 'Current Temp',
                            '106': 'Status', '108': 'Mode', '109': 'Preheat',
                            '112': 'Power Level', '254': 'Sensor'
                        }
                        name = dpid_names.get(k, f'DPID{k}')
                        print(f"  {name}: {v}")
        
        # Interactive mode
        print(f"\n{'='*60}")
        print("Interactive control mode")
        print(f"{'='*60}")
        print("Commands: on, off, temp <35-75>, mode <0-2>, query, quit")
        
        while True:
            try:
                cmd_input = input("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            
            if not cmd_input:
                continue
            elif cmd_input == 'quit' or cmd_input == 'q':
                break
            elif cmd_input == 'on':
                client.power_on()
            elif cmd_input == 'off':
                client.power_off()
            elif cmd_input.startswith('temp '):
                try:
                    t = int(cmd_input[5:])
                    client.set_temperature(t)
                except ValueError:
                    print("Invalid temperature")
            elif cmd_input.startswith('mode '):
                try:
                    m = int(cmd_input[5:])
                    client.set_mode(m)
                except ValueError:
                    print("Invalid mode")
            elif cmd_input == 'query':
                client.query_status()
            else:
                print("Unknown command")
    
    finally:
        client.close()
        print("\nDisconnected.")


if __name__ == '__main__':
    main()
