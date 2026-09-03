# 让小爱同学控制云合APP的热水器

巴法云 MQTT 桥接 + machtalk 私有云协议逆向 —— 一套完整可复现的折腾记录。

> 配套 B 站视频：_（发布后把链接补在这里）_

---

## 问题从哪来

一台云合电热水器，官方 App 走的是 machtalk 私有云 TCP 协议，跟小米生态**一点关系都没有**：

| 路线 | 结论 |
| --- | --- |
| 直接接米家 | APK 全文搜 `xiaomi` / `miot` / `mijia` / `xiaoai` —— **0 命中**，没有小米 SDK |
| Matter 配对 | 国行米家**拒绝**第三方设备 Matter 配对 |
| **巴法云 MQTT** | ✅ 米家「其他平台设备」隐藏入口，官方支持第三方接入 |

所以最终跑通的是这条链路：

```
小爱音响  「小爱同学，打开冲凉水」
   │   米家 App → 我的 → 其他平台设备 → 巴法云
   ▼
巴法云 MQTT  broker bemfa.com:9501，clientId = 你的 UID
   │   topic = 设备主题，payload = on / off
   ▼
bridge  常驻进程，跑在 NAS / Linux 主机上
   │   ├─ type "switch"      → Home Assistant REST API
   │   └─ type "yunho_temp"  → machtalk 原生 TCP 协议直连设备
   ▼
云合热水器
```

---

## 仓库里有什么

| 目录 | 作用 | 能单独用吗 |
| --- | --- | --- |
| [`bemfa-xiaoai-bridge/`](bemfa-xiaoai-bridge/) | 巴法云 MQTT ↔ Home Assistant / 设备 的桥接服务 | ✅ 任何 HA 设备都能用，**不绑定热水器** |
| [`machtalk-iot-control/`](machtalk-iot-control/) | machtalk 私有云协议的 Python 客户端 + 完整逆向方法论 | ✅ 任何 machtalk 系设备 |

两个 Skill 各自独立，可以只取其中一个。

### `bemfa-xiaoai-bridge/`

把 HA 里的 `switch` / `light` / `scene`（或任何从 Linux 主机能摸到的电器）暴露给小爱同学。

- `SKILL.md` — 架构、配置、systemd 部署、6 条 CRITICAL gotchas
- `references/bridge.py` — 桥接主程序（含 HA JWT 伪造、单向回显抑制）
- `references/bemfa_api.md` — 巴法云 HTTP API（建主题 / 改昵称 / 发消息）
- `scripts/bemfa_publish.py` — 主题与昵称批量管理

### `machtalk-iot-control/`

不跑官方 App，直接用 Python 走原生 TCP 协议查水温、开关机、设温度。

- `SKILL.md` — 快速上手
- `references/PROTOCOL.md` — 帧结构 / AES 参数 / dpid 属性表
- `references/REVERSE-ENGINEERING.md` — **五步逆向法**，换台设备也能照做
- `scripts/machtalk_client.py` / `machtalk_ctl.py` / `extract_credentials.py`

---

## 想直接用？从这边开始

只要让小爱控制 Home Assistant 里的设备 —— 只看 `bemfa-xiaoai-bridge/`：

```bash
pip install paho-mqtt

cd bemfa-xiaoai-bridge/
cp references/config_example.json config.json   # 填你自己的 UID / HA 地址
python references/bridge.py
```

然后把巴法云加进米家：**米家 App → 我的 → 其他平台设备 → 巴法云 → 绑定 → 下拉刷新同步**。

要控制的是 machtalk 系设备 —— 再看 `machtalk-iot-control/`：

```bash
pip install pycryptodome

cd machtalk-iot-control/scripts/
cp config.example.json config.json              # 填你自己的四个字段
python machtalk_ctl.py status
```

---

## 五个真正会卡住你的坑

踩坑记录比代码值钱，这几条都是实测出来的。完整说明在各 Skill 的 `SKILL.md` 里。

1. **topic ≠ nickname。** 小爱同学匹配的是**昵称**，不是主题名，这是两个字段。
2. **昵称撞车。** 别叫「热水器」—— 小爱会优先命中米家里的真实设备，或者反问你"哪个热水器"。改名「冲凉水」这类唯一词。
3. **桥接必须单向。** 巴法云会把你发出去的消息回显回来，双向桥接 = 自激振荡。
4. **HA 调用有 4~21 秒延迟。** `timeout` 要给到 20 秒以上，并且放到线程里跑，别阻塞 MQTT 循环。
5. **HA 的 `http.ban`。** 从非信任主机调 REST API 会被封，需要在桥接机伪造 JWT（读 `.storage/auth`）。

machtalk 协议侧还有三个坑（都在 `PROTOCOL.md`）：

- `AUTH_RESP` 首字节**不是**状态位 —— `0x00` / `0x01` / `0x02` / `0x03` 全都表示登录成功
- `AUTH_RESP` 得**倒着解析** —— 前缀长度可变
- `auth_cred` 是**稳定凭证** —— 跨 7 小时抓包完全一致，不需要 Frida，也不需要模拟器

---

## 安全声明

仓库内**不含任何真实凭证**。所有敏感值都是占位符：

`<BEMFA_UID>` · `<DEVICE_TOPIC_...>` · `YOUR_AUTH_CRED_HEX` · `YOUR_LOGIN_PHONE_NUMBER` · `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

`config.json` 已被 `.gitignore` 排除。请不要把真实凭证提交到公开仓库。

两个 Skill 都是纯本地脚本，不向任何第三方上传数据（巴法云是你自己选择接入的桥接目标）。

---

## 前置要求

- 一台常驻 Linux 主机（NAS / 软路由 / 树莓派都行），用来跑 bridge
- 巴法云账号（免费）
- 已装 Home Assistant（若走 HA 路线）
- 目标设备与抓包条件（若走协议逆向路线）

---

## License

MIT — 见 [LICENSE](LICENSE)。
