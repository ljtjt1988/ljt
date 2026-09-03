#!/usr/bin/env python3
# bemfa_publish.py — manage & test Bemfa topics from the CLI (declassified).
#
# Env / args:
#   UID          Bemfa private key (MQTT clientId).  Required.
#   --topic T    device "主题" (device id)
#   --name N     nickname (for create/rename)
#   --msg on|off publish a test command (simulates 小爱)
#
# Subcommands:
#   publish  --topic T --msg on|off     publish a test message
#   name     --topic T                  print current nickname
#   rename   --topic T --name N         set nickname
#   create   --topic T --name N         create a new topic (v1, no secret)
#   delete   --topic T                  delete a topic
#
# Examples:
#   UID=xxxx python bemfa_publish.py publish --topic AbCd1234006 --msg on
#   UID=xxxx python bemfa_publish.py create  --topic AbCd1234006 --name 冲凉水
#   UID=xxxx python bemfa_publish.py delete  --topic AbCd1234006

import json
import os
import sys
import urllib.request

UID = os.environ.get("UID")
REST = "https://apis.bemfa.com"
MGR = "https://pro.bemfa.com"


def _req(url, data=None, method="GET"):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.data = json.dumps(data).encode()
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except Exception as e:  # noqa: BLE001
        return {"_err": str(e)}


def main():
    if not UID:
        print("ERROR: set env UID to your Bemfa private key", file=sys.stderr)
        return 1
    cmd = sys.argv[1] if len(sys.argv) > 1 else "publish"
    args = sys.argv[2:]
    kv = {}
    i = 0
    while i < len(args):
        if args[i] in ("--topic", "--name", "--msg"):
            kv[args[i].lstrip("-")] = args[i + 1]
            i += 2
        else:
            i += 1

    t = kv.get("topic")
    if not t:
        print("ERROR: --topic required", file=sys.stderr)
        return 1

    if cmd == "publish":
        m = kv.get("msg", "on")
        r = _req(f"{REST}/va/sendMessage?uid={UID}&topic={t}&type=1&msg={m}")
        print("publish", m, "->", r)
    elif cmd == "name":
        print("nickname:", _req(f"{REST}/va/getName?uid={UID}&topic={t}&type=1").get("data"))
    elif cmd == "rename":
        body = {"uid": UID, "topic": t, "type": 1, "name": kv["name"]}
        print("rename ->", _req(f"{REST}/va/modifyName", body, "POST"))
    elif cmd == "create":
        body = {"uid": UID, "type": 1, "topic": t, "name": kv.get("name", "")}
        print("create ->", _req(f"{MGR}/v1/createTopic", body, "POST"))
        print("nickname now:", _req(f"{REST}/va/getName?uid={UID}&topic={t}&type=1").get("data"))
    elif cmd == "delete":
        body = {"uid": UID, "topic": t, "type": 1}
        print("delete ->", _req(f"{MGR}/v1/deleteTopic", body, "POST"))
    else:
        print("unknown subcommand:", cmd, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
