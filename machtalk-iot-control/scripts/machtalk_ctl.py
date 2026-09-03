#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""machtalk IoT device - command line control

Usage:
    python machtalk_ctl.py status           # query full state snapshot
    python machtalk_ctl.py on               # power on   (dpid 101 = 1)
    python machtalk_ctl.py off              # power off  (dpid 101 = 0)
    python machtalk_ctl.py temp 45          # target temperature (dpid 102)
    python machtalk_ctl.py raw <dpid> <val> # write any attribute
    python machtalk_ctl.py watch 5          # poll 5 times, 10s apart

Credentials come from config.json (see config.example.json).
Attribute names/units are also read from config.json, so this tool works for
any machtalk device once you have filled in its dpid table.
"""
import sys
import time

import machtalk_client as M

CFG = M.CONFIG
ATTR = CFG.get('attributes', {})
PRIMARY = CFG.get('primary', sorted(ATTR.keys()))

# dpid used by the on/off and temp shortcuts; override in config.json if your
# device numbers them differently.
DP_POWER = str(CFG.get('dp_power', '101'))
DP_TARGET_TEMP = str(CFG.get('dp_target_temp', '102'))


def fmt(dpid, value):
    """Render a raw dpid value using the metadata from config.json."""
    meta = ATTR.get(str(dpid))
    if not meta:
        return str(value)
    vmap = meta.get('map')
    if vmap and str(value) in vmap:
        return vmap[str(value)]
    unit = meta.get('unit', '')
    return f"{value}{unit}" if unit else str(value)


def label(dpid):
    meta = ATTR.get(str(dpid))
    return meta.get('name', f'dpid {dpid}') if meta else f'dpid {dpid}'


def merge_attrs(responses):
    """Merge the 'as' maps of several responses into one snapshot."""
    state = {}
    for r in responses or []:
        if isinstance(r, dict) and isinstance(r.get('as'), dict):
            state.update(r['as'])
    return state


def full_status(client, tries=3):
    """Query until a FULL snapshot arrives.

    cmd == "post" is an incremental push (changed attributes only);
    cmd == "resp" is the complete snapshot. Waiting for "resp" avoids
    reporting a half-empty state.
    """
    state = {}
    for _ in range(tries):
        responses = client.query_status() or []
        state.update(merge_attrs(responses))
        if any(isinstance(r, dict) and r.get('cmd') == 'resp' for r in responses):
            break
        time.sleep(1)
    return state


def show(state):
    if not state:
        print("  (no attributes received)")
        return
    print("\n  -- device state " + "-" * 34)
    for k in PRIMARY:
        if k in state:
            print(f"    {label(k):<14}: {fmt(k, state[k])}")
    others = [k for k in state if k not in PRIMARY]
    if others:
        try:
            others.sort(key=lambda x: int(x))
        except ValueError:
            others.sort()
        print("    " + f"{'other':<14}: " +
              "  ".join(f"{k}={state[k]}" for k in others))
    print("  " + "-" * 50)


def connect(max_tries=6):
    """Authenticate, then connect to the broker returned by AUTH_RESP.

    The server load-balances brokers and hands out a different address every
    login; some nodes are unreachable from a given network. So on failure we
    re-authenticate to get a different broker rather than retrying the same one.
    """
    tried = []
    for attempt in range(1, max_tries + 1):
        c = M.MachtalkClient()
        if not c.authenticate():
            print(f"  [{attempt}/{max_tries}] auth failed, retrying...")
            time.sleep(1)
            continue
        broker = f"{c.broker_ip}:{c.broker_port}"
        tried.append(broker)
        if c.connect_broker():
            print(f"\nOK  connected to broker {broker} (attempt {attempt})")
            return c
        print(f"  [{attempt}/{max_tries}] broker {broker} unreachable, "
              f"re-auth for another node...")
        time.sleep(1)
    print(f"\nFAIL after {max_tries} attempts. Brokers tried: {', '.join(tried)}")
    return None


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else 'status'

    if cmd in ('-h', '--help', 'help'):
        print(__doc__)
        return 0

    client = connect()
    if not client:
        return 1

    try:
        if cmd == 'status':
            show(full_status(client))

        elif cmd in ('on', 'off'):
            value = 1 if cmd == 'on' else 0
            print(f"\n>>> set {label(DP_POWER)} = {fmt(DP_POWER, value)}")
            client.send_control(DP_POWER, value)
            time.sleep(2)
            show(full_status(client))

        elif cmd == 'temp':
            if len(args) < 2:
                print("usage: machtalk_ctl.py temp <celsius>")
                return 1
            t = int(args[1])
            print(f"\n>>> set {label(DP_TARGET_TEMP)} = {t}")
            print("    NOTE: on a water heater this is IGNORED while powered "
                  "off, even though the device still ACKs it. Run 'on' first.")
            client.send_control(DP_TARGET_TEMP, t)
            time.sleep(2)
            show(full_status(client))

        elif cmd == 'raw':
            if len(args) < 3:
                print("usage: machtalk_ctl.py raw <dpid> <value>")
                return 1
            dpid, val = args[1], int(args[2])
            print(f"\n>>> set dpid {dpid} = {val}")
            client.send_control(dpid, val)
            time.sleep(2)
            show(full_status(client))

        elif cmd == 'watch':
            n = int(args[1]) if len(args) > 1 else 5
            for i in range(n):
                print(f"\n===== round {i + 1}/{n} =====")
                show(full_status(client))
                if i < n - 1:
                    time.sleep(10)

        else:
            print(__doc__)
            return 1
    finally:
        client.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
