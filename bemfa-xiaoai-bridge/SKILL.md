---
name: bemfa-xiaoai-bridge
description: |
  Expose Home Assistant switches/lights/scenes (or any appliance reachable from a Linux/NAS box)
  to 小爱同学 (XiaoAI) voice control via 巴法云 (Bemfa) MQTT. Use this when a user wants to
  voice-control a third-party / non-Mi-Home device through 小爱音响, when Matter into 米家 is
  rejected, or when setting up the Bemfa MQTT <-> HA bridge, device naming, or the one-way
  echo-loop pitfall. This skill should be used when a user says things like "让小爱控制 HA 里的
  设备", "巴法云 接 小爱", "Bemfa MQTT 桥", "小爱 控制第三方电器", or asks about 米家 第三方平台设备.
---

# Bemfa (巴法云) → 小爱同学 Voice Bridge

## Purpose

Let 小爱同学 voice-control appliances that are **not** native Mi Home devices, by routing voice
through 巴法云 (Bemfa) MQTT to a small always-on bridge running on a Linux/NAS host, which then
drives Home Assistant (or any native device protocol reachable from that host). This is the
working path for mainland-China Mi Home, where Matter pairing of 3rd-party devices is rejected.

## When to use

- User wants 小爱 to control a device that lives in Home Assistant but has no Mi Home equivalent.
- User already added Bemfa under 米家 → 我的 → 其他平台设备, but devices show offline / unresponsive.
- Naming collisions: 小爱 picks the real Mi Home device over the virtual one, or asks "which device".
- Building / debugging the bridge process, or extending it with new device types (e.g. temperature presets).

## Architecture

```
小爱音响
  │  (Mi Home cloud, "其他平台设备 = 巴法云")
  ▼
巴法云 Bemfa MQTT  (broker bemfa.com:9501, clientId = your UID)
  │  topic = device "主题" (device id), payload "on"/"off"
  ▼
bridge (systemd service on Linux/NAS host)
  │  - type "switch"     -> HA REST API (forged JWT) turn_on/off
  │  - type "yunho_temp" -> external native-protocol client (e.g. water heater)
  ▼
Home Assistant  /  native appliance protocol
```

The bridge is **ONE-WAY**: Bemfa command → target. It never publishes state back to Bemfa.

## Why NOT Matter

Mainland Mi Home rejects third-party Matter commissions (QR shows "无法识别该二维码"). Do not pursue
Matter for 小爱 voice control — use Bemfa. (A Matter bridge may still be useful for Apple Home /
Google Home, but not for 小爱.)

## Prerequisites

- A 巴法云 account; the **private key / UID** is the MQTT `clientId` (find it in the Bemfa console).
- A Linux/NAS host always on, with Python 3 + `paho-mqtt` (v2) + outbound MQTT to `bemfa.com:9501`.
- Home Assistant reachable from that host. If HA blocks the host via `http.ban`, the bridge MUST run
  on the HA box itself (or a host not banned) and forge a JWT (see below).
- 米家 app: 我的 → 其他平台设备 → 添加 巴法云 (bind your Bemfa account).

## Bemfa concepts (critical)

- **Broker**: `bemfa.com`, port `9501` (tcp).
- **clientId** = your Bemfa UID (the private key). All your topics live under this account.
- **topic** = the device "主题" (a device-id string, e.g. `XXXXXXXX006`). The trailing `006` is the
  switch-device type code; keep it when creating new switch topics.
- **message**: plain text `on` / `off`.
- **nickname** (昵称) = the human name 小爱 matches on. It is **separate** from the topic.
- Bemfa **echoes every published message to all subscribers** (including the bridge itself).

## CRITICAL gotchas (hard-won)

1. **topic = device id, NOT the nickname.** Setting the Bemfa console "主题/昵称" to a friendly name
   while the bridge subscribes to a different string → device shows **offline** and never receives
   commands. Always subscribe to / create with the real device-id topic.
2. **Never name a Bemfa device the same as an existing Mi Home product.** 小爱 prioritizes the real
   Mi Home device, shadowing the virtual one (or prompting "which device?"). Pick a distinct name
   (e.g. if the real product is "热水器", name the virtual "冲凉水", not "热水器").
3. **Bridge MUST be ONE-WAY.** Do NOT poll HA state and publish it back to Bemfa. Bemfa echoes the
   message back to the bridge → the bridge re-triggers the action → **self-oscillation** that, combined
   with HA's 4–21 s cloud ack latency, flips the final state. Voice control needs only the command path.
4. **paho-mqtt v2 API**: use `mqtt.Client(CallbackAPIVersion.VERSION2, client_id=UID, clean_session=False)`,
   subscribe qos=1, `keepalive=30`. Persistent session avoids re-subscribe storms.
5. **HA calls from a banned host**: forge an HS256 JWT from `.storage/auth` (key=`jwt_key`, iss=`id` of
   a `normal` refresh token) to bypass `http.ban`. Prefer running the bridge on the HA host itself.
6. **HA switch latency**: `turn_on/off` can take 4–21 s (cloud/device ack). Set HTTP timeout ≥ 20 s and
   run the call in a thread so the MQTT loop is never blocked.

## Deployment

### 1. config.json (on the bridge host)

```json
{
  "bemfa_uid": "<BEMFA_UID>",
  "bemfa_host": "bemfa.com",
  "bemfa_port": 9501,
  "ha_url": "http://<HA_HOST>:8123",
  "ha_auth_path": "/path/to/home-assistant/.storage/auth",
  "devices": [
    {"name": "冲凉水", "topic": "<DEVICE_TOPIC_1>", "entity_id": "switch.re_shui_qi", "type": "switch"},
    {"name": "高温挡", "topic": "<DEVICE_TOPIC_2>", "value": 65, "type": "yunho_temp"}
  ]
}
```

`type` values:
- `switch` → HA `turn_on`/`turn_off` of `entity_id`.
- `yunho_temp` → run an external native client (`yunho_ctl.py on` then `temp <value>`). Used when HA
  cannot set the device (e.g. HA integration lacks `set_temperature`). See "Native device control" below.

### 2. bridge.py — see `references/bridge.py` (canonical, declassified). Deploy it next to config.json.

### 3. systemd unit (on the bridge host)

```ini
[Unit]
Description=Bemfa -> HA / device voice bridge
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/bemfa-bridge/bemfa_ha_bridge.py
WorkingDirectory=/opt/bemfa-bridge
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now bemfa-bridge.service
systemctl status bemfa-bridge.service
```

### 4. dependencies

```bash
pip install paho-mqtt            # v2
# for the yunho_temp type, also install the native client's deps on the bridge host,
# e.g. pycryptodome, and place yunho_ctl.py + its client next to the bridge (see below).
```

## Bemfa device lifecycle (HTTP API)

Full endpoint list + request samples: **`references/bemfa_api.md`**. Quick reference:

| Action | Method / URL |
|---|---|
| Create topic (no secret needed, v1) | `POST https://pro.bemfa.com/v1/createTopic` body `{uid, type:1, topic, name}` |
| Get nickname | `GET https://apis.bemfa.com/va/getName?uid=&topic=&type=1` |
| Set nickname | `POST https://apis.bemfa.com/va/modifyName` body `{uid, topic, type:1, name}` |
| Delete topic | `POST https://pro.bemfa.com/v1/deleteTopic` body `{uid, topic, type:1}` |
| Publish test msg | `GET https://apis.bemfa.com/va/sendMessage?uid=&topic=&type=1&msg=on` |

> New topics: generate an 8-char alphanumeric prefix and append `006` (switch type code). Rename to a
> Chinese nickname via `modifyName` so 小爱 matches the spoken phrase.

## Voice verification (end-to-end)

1. From any host, publish a test command via the Bemfa HTTP API (`sendMessage?msg=on`).
2. `tail -n 20 /opt/bemfa-bridge/bemfa-bridge.log` — confirm `[Bemfa] <name> on -> HA <entity>` and
   `[HA] -> on` appear.
3. On the HA host, read the entity state via the forged JWT to confirm it flipped.
4. In 米家 → 其他平台设备 → 巴法云, **pull to refresh** so new Chinese nicknames sync.
5. Say to 小爱: "打开 <昵称>" / "关闭 <昵称>".

If 小爱 says "没有这个设备" or asks "打开哪个": the nickname has not synced in 米家, or it collides
with a real Mi Home device name. Re-check gotcha #2 and refresh 米家.

## Native device control (optional `yunho_temp` type)

When HA cannot drive the appliance (e.g. the integration has no `set_temperature`, or the entity is
`unavailable`), control the device through its **native protocol** from the bridge host. For the
云合/Yunho water heater this is a Python client speaking the machtalk TCP protocol; see the separate
`yunho-water-heater` skill for that client. Wire it into the bridge as a `yunho_temp` device: the
bridge spawns `yunho_ctl.py on` then `yunho_ctl.py temp <value>` (power-on first because setting
temperature while off is a no-op on that device). Keep the proprietary client **out of this skill** —
reference the device-specific skill instead.

## Troubleshooting

- **Device offline in Bemfa console**: topic mismatch (gotcha #1). Verify the bridge subscribes to the
  exact device-id topic, not the nickname.
- **小爱 no response / "which device?"**: nickname not synced (refresh 米家) or collides with a real
  Mi Home product (gotcha #2). Never reuse a real product's name.
- **State flips / oscillates**: you added a state-sync loop that publishes back to Bemfa (gotcha #3).
  Remove it; keep the bridge one-way.
- **HA call times out**: raise timeout to ≥20 s and run in a thread (gotcha #6). If `http.ban`, run the
  bridge on the HA host and forge the JWT (gotcha #5).
- **HA entity won't change at all** (`set_value` returns `[]`, `last_changed` stale): the HA entity is
  broken/unavailable — drive the device via its native protocol instead (see above).
