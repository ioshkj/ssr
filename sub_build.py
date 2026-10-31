#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原样合并订阅源 -> 测速 -> 只改名字 -> 生成唯一订阅 sub/sub.txt
   规则：节点链接一个字都不改，只替换 # 后面的名称"""
import base64, os, re, subprocess, time
import verify, nodeconv, geo
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "sub")
SRC = [
    "Pawdroid/Free-servers/main/sub",
    "mfuu/FreeProxies/master/sub",
    "zhuhaiuk/free-nodes/main/nodes.txt",
    "Barabama/FreeNodes/main/nodes/cfmem.txt",
    "shaoyouvip/free/main/base64.txt",
    "ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",
    "snakem982/proxypool/main/source/v2ray-2.txt",
    "ssrsub/ssr/master/v2ray",
    "mfuu/FreeProxies/master/sub.yaml",
    "shaoyouvip/free/main/mihomo.yaml",
    "shaoyouvip/free/main/all.yaml",
    "zhulinghuanyu/BestSub/main/clash.yaml",
]
NAME = "%s-%02d 0070077.xyz"   # 名字里不要出现冒号和全角符号，QX 会整行丢弃


def log(m):
    print(m, flush=True)


def fetch(path):
    url = "https://gh-proxy.org/https://raw.githubusercontent.com/" + path
    out = subprocess.run(["curl", "-sL", "-m", "20", url], capture_output=True).stdout
    return out


def lines_of(body):
    t = body.decode("utf-8", "ignore")
    if "proxies:" in t[:400]:
        import yaml
        try:
            d = yaml.safe_load(t)
        except Exception:
            return []
        out = []
        for p in (d.get("proxies") or []):
            if isinstance(p, dict) and p.get("type") in ("vmess", "vless", "trojan", "ss", "anytls", "http"):
                u = nodeconv.to_uri(p)
                if u:
                    out.append(u)
        return out
    try:
        t = base64.b64decode(re.sub(rb"\s", b"", body) + b"=" * (-len(body) % 4)).decode("utf-8", "ignore")
    except Exception:
        pass
    return [l.strip() for l in t.splitlines()
            if re.match(r"^(vmess|vless|trojan|ss|anytls|https?)://\S", l.strip(), re.I)]


def discovered():
    import json
    p = os.path.join(HERE, "sources.json")
    if not os.path.exists(p):
        return []
    try:
        items = json.load(open(p, encoding="utf-8"))
    except Exception:
        return []
    import datetime
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=36)
    out = []
    for x in items:
        try:
            t = datetime.datetime.fromisoformat(x["pushed"].replace("Z", "+00:00"))
        except Exception:
            continue
        if t >= cutoff:
            out.append("%s/%s/%s" % (x["repo"], x.get("branch", "main"), x["path"]))
    return out


def tcp_ok(host, port, timeout=1.5):
    import socket
    try:
        socket.create_connection((host, int(port)), timeout=timeout).close()
        return True
    except Exception:
        return False


def main():
    os.makedirs(OUT, exist_ok=True)
    seen, lines = set(), []
    for p in SRC + discovered():
        n = 0
        for u in lines_of(fetch(p)):
            k = u.split("#")[0]
            if k in seen:
                continue
            seen.add(k)
            lines.append(u)
            n += 1
        log("  %-46s +%d" % (p.split("/")[-1][:44], n))
    log("合并 %d 条（原样，未改）" % len(lines))

    # 第一步：按 server:port 去重（同一入口只留一条）
    items, seen_ep = [], set()
    for u in lines:
        q = nodeconv.to_clash(u, "x")
        if not q:
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_ep:
            continue
        seen_ep.add(ep)
        items.append((u, q))
    log("去重后唯一入口 %d 个" % len(items))
    ps = [q for _, q in items]

    def tcp_ms(q):
        import socket, time as _t
        best = None
        for _ in range(2):
            t0 = _t.time()
            try:
                socket.create_connection((q["server"], int(q["port"])), timeout=2).close()
                v = int((_t.time() - t0) * 1000)
                best = v if best is None else min(best, v)
            except Exception:
                pass
        return best

    # ① TCP 初筛：3 次取最小，>500ms 淘汰（只做粗筛）
    def tcp_ms(q):
        import socket, time as _t
        best = None
        for _ in range(3):
            t0 = _t.time()
            try:
                socket.create_connection((q["server"], int(q["port"])), timeout=2).close()
                v = int((_t.time() - t0) * 1000)
                best = v if best is None else min(best, v)
            except Exception:
                pass
        return best

    with ThreadPoolExecutor(max_workers=256) as ex:
        lat = list(ex.map(tcp_ms, ps))
    pairs = [(l, q) for q, l in zip(ps, lat) if l is not None and l <= 500]
    pairs.sort(key=lambda x: x[0])
    ps = [q for _, q in pairs][:400]
    log("TCP ≤500ms 的 %d 条，进入端到端测试" % len(ps))

    # ② 端到端延迟 + 抖动：3 次请求 Google，至少 2 次成功
    samples = {}
    for rnd in range(3):
        r = verify.verify([dict(p) for p in ps], workers=192, timeout=8000,
                          url=verify.URL_GOOGLE, log=lambda m: None)
        for p, d in r:
            samples.setdefault((p["server"], int(p["port"])), []).append(d)
        log("  第 %d 次延迟采样成功 %d" % (rnd + 1, len(r)))

    import statistics
    stats = {}
    for k, ds in samples.items():
        if len(ds) < 2:
            continue
        med = sorted(ds)[len(ds) // 2]
        jit = statistics.pstdev(ds) if len(ds) > 1 else 0
        if med > 600 or jit > 200:
            continue
        stats[k] = (med, jit)
    log("端到端达标（≤600ms，抖动≤200ms）%d 条" % len(stats))

    # ③ 下载 1MB 测真实速度
    ps2 = [p for p in ps if (p["server"], int(p["port"])) in stats]
    sp = verify.verify([dict(p) for p in ps2], workers=48, timeout=20000,
                       url="https://speed.cloudflare.com/__down?bytes=1000000", log=lambda m: None)
    speed = {(p["server"], int(p["port"])): 1000.0 / max(d, 1) for p, d in sp}  # KB/s
    log("下载 1MB 成功 %d 条" % len(speed))

    # ④ 加权评分 0-100：速度 50% + 延迟 35% + 抖动 15%
    keep = []
    for u, q in items:
        k = (q["server"], int(q["port"]))
        if k not in speed or k not in stats:
            continue
        med, jit = stats[k]
        sp_kb = speed[k]
        if sp_kb < 300:
            continue
        score = 100.0 * (0.50 * min(sp_kb / 2000.0, 1.0)
                         + 0.35 * (1 - min(med / 1000.0, 1.0))
                         + 0.15 * (1 - min(jit / 300.0, 1.0)))
        keep.append(((-score, med), u, q))
    keep.sort(key=lambda x: x[0])
    log("评分达标 %d 条" % len(keep))

    # 同网段最多 12 个，避免整份都是同一家的机器
    lim, seen_net, dedup = 12, {}, []
    import ipaddress
    for d, u, q in keep:
        try:
            net = str(ipaddress.ip_network(q["server"] + "/24", strict=False))
        except Exception:
            net = q["server"]
        if seen_net.get(net, 0) >= lim:
            continue
        seen_net[net] = seen_net.get(net, 0) + 1
        dedup.append((d, u, q))
    keep = dedup
    log("同网段去重后 %d" % len(keep))

    regs = geo.regions([q for _, _, q in keep])
    cnt, out = {}, []
    for (d, u, q), r in zip(keep, regs):
        cnt[r] = cnt.get(r, 0) + 1
        out.append(u.split("#")[0] + "#" + (NAME % (r, cnt[r])).replace(" ", "%20"))
    out = out[:50]

    old_n = 0
    fp = os.path.join(OUT, "final2.txt")
    if os.path.exists(fp):
        try:
            old_n = len(base64.b64decode(open(fp).read()).decode().splitlines())
        except Exception:
            old_n = 0
    if not out or (old_n >= 40 and len(out) < old_n * 0.5):
        log("  !! 本轮结果 %d 条，明显少于上一版 %d 条，保留上一版" % (len(out), old_n))
        return
    with open(os.path.join(OUT, "final2.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(out).encode()).decode())
    with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
        f.write("更新 %s\n合并 %d / 通过 %d / 收录 %d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), len(lines), len(ok_keys), len(out)))
    log("写入 sub.txt：%d 条" % len(out))


if __name__ == "__main__":
    main()
