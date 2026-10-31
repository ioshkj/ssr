#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 QX 配置行转成 clash proxy，逐个测：Google / YouTube / 下载"""
import base64, json, os, re, sys, time
import verify

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_line(line):
    m = re.match(r"^([a-z0-9]+)=([^,]+),\s*(.*)$", line.strip())
    if not m:
        return None
    typ, hostport, rest = m.group(1), m.group(2), m.group(3)
    kv = {}
    tag = ""
    for part in re.split(r",\s*(?=[a-z0-9_-]+=)", rest):
        if "=" in part:
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "tag":
                tag = v
            else:
                kv[k] = v
    host, _, port = hostport.rpartition(":")
    if not host or not port.isdigit():
        return None
    q = {"name": tag or host, "server": host, "port": int(port), "skip-cert-verify": True}
    if typ in ("shadowsocks", "ss"):
        q.update(type="ss", cipher=kv.get("method", "aes-256-gcm"), password=kv.get("password", ""))
    elif typ == "trojan":
        q.update(type="trojan", password=kv.get("password", ""), sni=kv.get("tls-host", host), udp=True)
        if kv.get("obfs") in ("wss", "ws"):
            q["network"] = "ws"
            q["ws-opts"] = {"path": kv.get("obfs-uri", "/"),
                            "headers": {"Host": kv.get("obfs-host") or kv.get("tls-host", host)}}
        if kv.get("over-tls", "true") == "true":
            q["tls"] = True
    elif typ == "vless":
        q.update(type="vless", uuid=kv.get("password", ""), udp=True, tls=True,
                 servername=kv.get("obfs-host") or kv.get("tls-host") or host)
        if kv.get("vless-flow"):
            q["flow"] = kv["vless-flow"]
        if kv.get("reality-base64-pubkey"):
            q["reality-opts"] = {"public-key": kv["reality-base64-pubkey"],
                                 "short-id": kv.get("reality-hex-shortid", "")}
        obfs = kv.get("obfs", "")
        if obfs in ("wss", "ws"):
            q["network"] = "ws"
            q["ws-opts"] = {"path": kv.get("obfs-uri", "/"),
                            "headers": {"Host": kv.get("obfs-host", host)}}
    elif typ == "anytls":
        q.update(type="anytls", password=kv.get("password", ""), sni=kv.get("tls-host", host))
    elif typ == "http":
        q.update(type="http", tls=kv.get("over-tls") == "true")
        if kv.get("username") and kv["username"] != "null":
            q["username"] = kv["username"]
            q["password"] = kv.get("password", "")
    else:
        return None
    return q


def main():
    lines = [l for l in open(os.path.join(HERE, "probe_nodes.txt"), encoding="utf-8").read().splitlines() if l.strip()]
    proxies = [p for p in (parse_line(l) for l in lines) if p]
    print("解析 %d 条" % len(proxies), flush=True)

    results = {}
    for label, url in [("Google", "https://www.gstatic.com/generate_204"),
                       ("YouTube", "https://i.ytimg.com/generate_204")]:
        r = verify.verify([dict(p) for p in proxies], workers=16, timeout=10000, url=url, log=lambda m: None)
        for p, d in r:
            results.setdefault(p["name"], {})[label] = d
        print("%s 通过 %d" % (label, len(r)), flush=True)

    dl = verify.verify([dict(p) for p in proxies if p["name"] in results],
                       workers=8, timeout=20000,
                       url="https://speed.cloudflare.com/__down?bytes=300000", log=lambda m: None)
    for p, d in dl:
        results.setdefault(p["name"], {})["下载KB/s"] = round(300.0 / max(d, 1) * 1000, 0)

    rows = []
    for p in proxies:
        r = results.get(p["name"], {})
        rows.append("%-14s %-8s %-8s %-8s %s" % (
            p["name"][:14], p["type"],
            ("%dms" % r["Google"]) if "Google" in r else "✗",
            ("%dms" % r["YouTube"]) if "YouTube" in r else "✗",
            ("%.0fKB/s" % r["下载KB/s"]) if "下载KB/s" in r else "✗"))
    out = "名称           协议     Google   YouTube  下载\n" + "\n".join(rows)
    print(out)
    open(os.path.join(HERE, "sub", "probe.txt"), "w", encoding="utf-8").write(out + "\n")


if __name__ == "__main__":
    main()
