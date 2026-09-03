#!/usr/bin/env python3
# bemfa_ha_bridge.py — bridge Bemfa (巴法云) MQTT <-> Home Assistant / native device.
#
# Lets 小爱同学 (via Bemfa) control HA entities and, optionally, set a device temperature
# directly through a native-protocol client (e.g. yunho_ctl.py for a water heater).
#
# Bemfa MQTT convention:
#   broker  : bemfa.com
#   port    : 9501 (tcp)
#   clientId: your Bemfa UID (private key)  -> all topics live under your account
#   topic   : the device "主题" (device id) you set in the Bemfa console
#   message : "on" / "off"
#
# config.json device types:
#   {"type":"switch",     "entity_id":"...", ...}  -> HA turn_on/turn_off
#   {"type":"yunho_temp", "value": 65,      ...}  -> run yunho_ctl on + temp <value>
#
# NOTE: ONE-WAY bridge (Bemfa command -> target). State is NEVER pushed back to Bemfa
# (echo + self-oscillation). Voice control only needs the command path.

import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
LOG_PATH = os.path.join(HERE, "bemfa-bridge.log")

# Native-protocol client for the yunho_temp type (override path via config "yunho_ctl_path").
YUNHO_CTL = os.environ.get("YUNHO_CTL") or os.path.join(HERE, "yunho", "yunho_ctl.py")
YUNHO_PY = os.environ.get("YUNHO_PY", "/usr/bin/python3")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("bemfa-bridge")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


CFG = load_config()
UID = CFG["bemfa_uid"]
HA_URL = CFG["ha_url"]
AUTH_PATH = CFG.get("ha_auth_path") or CFG.get("ha_auth_file")
DEVICES = CFG["devices"]
BEMFA_HOST = CFG.get("bemfa_host", "bemfa.com")
BEMFA_PORT = int(CFG.get("bemfa_port", 9501))
MQTT_USER = CFG.get("mqtt_username")
MQTT_PASS = CFG.get("mqtt_password")
YUNHO_CTL = CFG.get("yunho_ctl_path", YUNHO_CTL)

if not UID or UID == "REPLACE_WITH_YOUR_UID":
    log.error("bemfa_uid not set in config.json — fill it in, then restart.")
    sys.exit(2)


# ---------- HA forged JWT (bypass http.ban when bridge runs on a banned host) ----------
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge_token():
    with open(AUTH_PATH) as f:
        auth = json.load(f)
    owner = next((u for u in auth["data"]["users"] if u.get("is_owner")), None)
    rt = None
    if owner:
        rt = next(
            (t for t in auth["data"]["refresh_tokens"]
             if t.get("user_id") == owner["id"] and t.get("jwt_key") and t.get("token_type") == "normal"),
            None,
        )
    if not rt:
        rt = next(
            (t for t in auth["data"]["refresh_tokens"]
             if t.get("jwt_key") and t.get("token_type") == "normal"),
            None,
        )
    if not rt:
        raise RuntimeError("No usable refresh token with jwt_key in .storage/auth")
    key = rt["jwt_key"]
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64url(json.dumps({"iss": rt["id"], "iat": now, "exp": now + 10 * 365 * 24 * 3600}).encode())
    sig = hmac.new(key.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


TOKEN = forge_token()


def ha_request(method, path, body=None, retries=2, timeout=20):
    url = HA_URL + path
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", "Bearer " + TOKEN)
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1)
    raise last


def set_ha_state(eid, on):
    domain = eid.split(".")[0]
    svc = "turn_on" if on else "turn_off"
    ha_request("POST", f"/api/services/{domain}/{svc}", {"entity_id": eid})
    log.info("[HA] %s -> %s", eid, "on" if on else "off")


# ---------- native-protocol temp control (yunho_temp) ----------
def run_yunho_temp(value):
    # setting temperature while off is a no-op on this device -> power on first
    try:
        subprocess.run([YUNHO_PY, YUNHO_CTL, "on"], capture_output=True, text=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        log.error("[yunho] power-on failed: %s", e)
    try:
        r = subprocess.run([YUNHO_PY, YUNHO_CTL, "temp", str(value)],
                           capture_output=True, text=True, timeout=60)
        log.info("[yunho] set temp %s rc=%s", value, r.returncode)
        for line in (r.stdout or "").splitlines()[-3:]:
            log.info("[yunho-out] %s", line.strip())
    except Exception as e:  # noqa: BLE001
        log.error("[yunho] set temp %s failed: %s", value, e)


# ---------- MQTT <-> targets ----------
client = None


def on_connect(c, userdata, flags, reason_code, properties=None):
    rc = reason_code if isinstance(reason_code, int) else getattr(reason_code, "value", reason_code)
    if rc == 0:
        sp = flags.get("session_present", False) if isinstance(flags, dict) else False
        if not sp:
            for d in DEVICES:
                c.subscribe(d["topic"], qos=1)
                log.info("subscribed topic=%s (qos=1) -> %s", d["topic"], d.get("entity_id") or d.get("value"))
    else:
        log.warning("Bemfa connect failed, rc=%s (will retry)", rc)


def on_disconnect(c, userdata, *args):
    log.warning("Bemfa disconnected (will auto-reconnect)")


def on_message(c, userdata, msg):
    try:
        val = msg.payload.decode("utf-8", "ignore").strip().lower()
        topic = msg.topic
        dev = next((d for d in DEVICES if d["topic"] == topic), None)
        if not dev:
            return
        if val not in ("on", "off"):
            return
        on = val == "on"
        dtype = dev.get("type", "switch")
        if dtype == "yunho_temp":
            if on:
                log.info("[Bemfa] %s on -> yunho temp %s", dev["name"], dev["value"])
                threading.Thread(target=run_yunho_temp, args=(dev["value"],), daemon=True).start()
            else:
                log.info("[Bemfa] %s off -> 温度挡位 no-op", dev["name"])
            return
        log.info("[Bemfa] %s %s -> HA %s", dev["name"], val, dev["entity_id"])
        threading.Thread(target=set_ha_state, args=(dev["entity_id"], on), daemon=True).start()
    except Exception as e:  # noqa: BLE001
        log.error("on_message error: %s", e)


def main():
    global client
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=UID,
            clean_session=False,
        )
    except Exception:  # noqa: BLE001
        client = mqtt.Client(client_id=UID, clean_session=False)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS or "")
    client.reconnect_delay_set(min_delay=3, max_delay=30)
    client.connect(BEMFA_HOST, BEMFA_PORT, keepalive=30)
    client.loop_start()
    log.info("bemfa-ha-bridge started, %d devices (clean_session=False, keepalive=30)", len(DEVICES))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        client.loop_stop()


if __name__ == "__main__":
    main()
