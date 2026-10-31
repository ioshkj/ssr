#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对指定节点做多维度测试：TCP / 五个目标 / 抖动 / 下载 / UDP"""
import base64, json, os, re, socket, statistics, time
import verify
import sub_build as sb

HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS = [
    ("Google", "https://www.gstatic.com/generate_204"),
    ("YouTube", "https://i.ytimg.com/generate_204"),
    ("Cloudflare", "https://cp.cloudflare.com/generate_204"),
    ("Twitter", "https://abs.twimg.com/favicon.ico"),
    ("Telegram", "https://telegram.org/favicon.ico"),
]


def parse_line(line):
    m = re.match(r"^([a-z0-9]+)=([^,]+),\s*(.*)$", line.strip())
    if not m:
        return None
    typ, hostport, rest = m.group(1), m.group(2), m.group(3)
    kv, tag = {}, ""
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
        q["tls"] = True
    elif typ == "vless":
        q.update(type="vless", uuid=kv.get("password", ""), udp=True, tls=True,
                 servername=kv.get("obfs-host") or kv.get("tls-host") or host)
        if kv.get("vless-flow"):
            q["flow"] = kv["vless-flow"]
        if kv.get("reality-base64-pubkey"):
            q["reality-opts"] = {"public-key": kv["reality-base64-pubkey"],
                                 "short-id": kv.get("reality-hex-shortid", "")}
        if kv.get("obfs") in ("wss", "ws"):
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



def ip_api(q, timeout=12):
    """通过节点访问 ip-api，返回 (ip, 国家码) 或 (None, None)"""
    import json as _j, socket as _sk, subprocess as _sp, tempfile as _tf, time as _t
    import urllib.request as _ur
    wd = _tf.mkdtemp(prefix="geo-")
    a, b = _sk.socket(), _sk.socket()
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    api_p, mix_p = a.getsockname()[1], b.getsockname()[1]
    a.close(); b.close()
    cfg = {"mixed-port": mix_p, "external-controller": "127.0.0.1:%d" % api_p,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = wd + "/c.yaml"
    open(path, "w").write(_j.dumps(cfg, ensure_ascii=False))
    p = _sp.Popen([verify.BIN, "-d", wd, "-f", path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        for _ in range(40):
            _t.sleep(0.2)
            try:
                _ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None, None
        r = _sp.run(["curl", "-s", "--max-time", str(timeout),
                     "-x", "http://127.0.0.1:%d" % mix_p,
                     "http://ip-api.com/json/?fields=query,countryCode"],
                    capture_output=True, text=True)
        d = _j.loads(r.stdout or "{}")
        return d.get("query"), (d.get("countryCode") or "").upper() or None
    except Exception:
        return None, None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def tcp_ms(host, port, n=3):
    best = None
    for _ in range(n):
        t0 = time.time()
        try:
            socket.create_connection((host, port), timeout=2).close()
            v = int((time.time() - t0) * 1000)
            best = v if best is None else min(best, v)
        except Exception:
            pass
    return best


def main():
    lines = [l for l in open(os.path.join(HERE, "probe_nodes.txt"), encoding="utf-8").read().splitlines() if l.strip()]
    proxies = [p for p in (parse_line(l) for l in lines) if p]
    print("解析 %d 条" % len(proxies), flush=True)
    res = {i: {} for i in range(len(proxies))}

    for i, p in enumerate(proxies):
        res[i]["tcp"] = tcp_ms(p["server"], p["port"])
    print("TCP 完成", flush=True)

    for label, url in TARGETS:
        r = verify.verify([dict(p) for p in proxies], workers=16, timeout=10000, url=url, log=lambda m: None)
        key = {(p["server"], int(p["port"])) for p, _ in r}
        for i, p in enumerate(proxies):
            if (p["server"], int(p["port"])) in key:
                res[i][label] = 1
        print("%s 通过 %d" % (label, len(r)), flush=True)

    # 抖动：Google 打三次
    for _ in range(3):
        r = verify.verify([dict(p) for p in proxies], workers=16, timeout=10000,
                          url=TARGETS[0][1], log=lambda m: None)
        for p, d in r:
            k = (p["server"], int(p["port"]))
            for i, q in enumerate(proxies):
                if (q["server"], int(q["port"])) == k:
                    res[i].setdefault("samples", []).append(d)
    print("延迟采样完成", flush=True)

    dl = verify.verify([dict(p) for p in proxies], workers=8, timeout=25000,
                       url="https://speed.cloudflare.com/__down?bytes=300000", log=lambda m: None)
    for p, d in dl:
        k = (p["server"], int(p["port"]))
        for i, q in enumerate(proxies):
            if (q["server"], int(q["port"])) == k:
                res[i]["kbps"] = round(300.0 / max(d, 1) * 1000)
    print("下载完成", flush=True)

    for i, p in enumerate(proxies):
        ip, cc = ip_api(p)
        res[i]["ip"] = ip
        res[i]["cc"] = cc
    print("IP 查询完成", flush=True)
    print("UDP 完成", flush=True)

    rows = ["名称          协议      TCP    Google YT  CF  TW  TG   导出IP           国家  下载KB/s"]
    for i, p in enumerate(proxies):
        r = res[i]
        sm = sorted(r.get("samples", []))
        jit = int(statistics.pstdev(sm)) if len(sm) > 1 else 0
        rows.append("%-12s %-8s %-6s %-5s %-3s %-3s %-3s %-3s %-16s %-5s %-8s" % (
            p["name"][:12], p["type"],
            ("%dms" % r["tcp"]) if r.get("tcp") else "✗",
            "✓" if r.get("Google") else "✗",
            "✓" if r.get("YouTube") else "✗",
            "✓" if r.get("Cloudflare") else "✗",
            "✓" if r.get("Twitter") else "✗",
            "✓" if r.get("Telegram") else "✗",
            r.get("ip") or "✗",
            r.get("cc") or "-",
            str(r.get("kbps", "✗"))))
    out = "\n".join(rows)
    print(out)
    open(os.path.join(HERE, "sub", "probe.txt"), "w", encoding="utf-8").write(out + "\n")


if __name__ == "__main__":
    main()
