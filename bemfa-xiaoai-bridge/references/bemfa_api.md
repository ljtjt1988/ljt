# 巴法云 (Bemfa) HTTP API reference

All calls need your `uid` (= the Bemfa private key / MQTT clientId). `type=1` is the MQTT device type.
Replace `<UID>` and `<TOPIC>` with real values. These are used for create/rename/delete/verify and to
push a test command during bridge verification (the bridge itself uses the MQTT broker, not these).

## Base hosts
- REST/console-ish: `https://apis.bemfa.com`
- v1 management: `https://pro.bemfa.com`

## Endpoints

### Get a topic's nickname
```
GET https://apis.bemfa.com/va/getName?uid=<UID>&topic=<TOPIC>&type=1
```
Response: `{ "code": 0, "data": "<nickname or empty>", "message": "..." }`

### Publish a test message (simulates 小爱 / console "发送")
```
GET https://apis.bemfa.com/va/sendMessage?uid=<UID>&topic=<TOPIC>&type=1&msg=on
```
Use `msg=on` / `msg=off`. This is the quickest way to verify the bridge receives a command without
talking to 小爱. Tail the bridge log to confirm `[Bemfa] <name> on -> ...`.

### Set / update a topic's nickname
```
POST https://apis.bemfa.com/va/modifyName
Content-Type: application/json; charset=utf-8
{ "uid": "<UID>", "topic": "<TOPIC>", "type": 1, "name": "中文昵称" }
```
The nickname is what 小爱 matches on. Set it to the exact phrase the user will speak (e.g. "冲凉水").

### Create a new topic (v1, NO secret required)
```
POST https://pro.bemfa.com/v1/createTopic
Content-Type: application/json; charset=utf-8
{ "uid": "<UID>", "type": 1, "topic": "<NEW_TOPIC>", "name": "中文昵称" }
```
- Generate `<NEW_TOPIC>` = 8-char alphanumeric prefix + `006` (switch type code). Example prefix
  `kNEsilbo` → topic `kNEsilbo006`.
- After creation, call `getName` to confirm the nickname took effect.
- A "专业版" create endpoint exists (`/vs/web/v2/createTopic`) requiring an AppID/SecretKey pair; the
  v1 endpoint above works without those and is preferred for personal use.

### Delete a topic
```
POST https://pro.bemfa.com/v1/deleteTopic
Content-Type: application/json; charset=utf-8
{ "uid": "<UID>", "topic": "<TOPIC>", "type": 1 }
```
Use this to remove orphan/virtual devices that collide with real Mi Home products (see SKILL gotcha #2).
After deletion, refresh 米家 → 其他平台设备 → 巴法云 so the card disappears there too.

## Notes
- Bemfa echoes every published message to all subscribers (including the bridge). Never publish HA
  state back to Bemfa from the bridge — it self-oscillates.
- Topic = device id. Nickname = display name. They are different fields; the bridge must subscribe to
  the device-id topic, the user speaks the nickname.
