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




def real_speed(q, bytes_=300000, timeout=25):
    """单节点：起一个只含它的内核，用 curl 走本地代理下载，返回 KB/s"""
    import json as _json, socket as _sock, subprocess as _sp, tempfile as _tf, time as _t, urllib.request as _ur

    wd = _tf.mkdtemp(prefix="sp-")
    s1, s2 = _sock.socket(), _sock.socket()
    s1.bind(("127.0.0.1", 0)); s2.bind(("127.0.0.1", 0))
    api_p, mix_p = s1.getsockname()[1], s2.getsockname()[1]
    s1.close(); s2.close()
    cfg = {"mixed-port": mix_p, "external-controller": "127.0.0.1:%d" % api_p,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = wd + "/c.yaml"
    open(path, "w").write(_json.dumps(cfg, ensure_ascii=False))
    p = _sp.Popen([verify.BIN, "-d", wd, "-f", path],
                  stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        for _ in range(40):
            _t.sleep(0.2)
            try:
                _ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None
        r = _sp.run(["curl", "-s", "-o", "/dev/null", "-x", "http://127.0.0.1:%d" % mix_p,
                     "--max-time", str(timeout), "-w", "%{speed_download}",
                     "https://speed.cloudflare.com/__down?bytes=%d" % bytes_],
                    capture_output=True, text=True)
        speed = float(r.stdout.strip() or 0) / 1024.0
        return speed if speed > 1 else None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()

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
    pairs = [(l, q) for q, l in zip(ps, lat) if l is not None and l <= 600]
    tcp_of = {(q["server"], int(q["port"])): l for l, q in pairs}
    pairs.sort(key=lambda x: x[0])
    ps = [q for _, q in pairs]
    log("TCP ≤500ms 的 %d 条，进入端到端测试" % len(ps))

    # ② 端到端延迟：并发 32，测 2 次取最小值；抖动 = 两次差值
    samples = {}
    for rnd in range(2):
        r = verify.verify([dict(p) for p in ps], workers=32, timeout=8000,
                          url="http://www.gstatic.com/generate_204", log=lambda m: None)
        for p, d in r:
            samples.setdefault((p["server"], int(p["port"])), []).append(d)
        log("  第 %d 次采样成功 %d" % (rnd + 1, len(r)))

    stats = {}
    for k, ds in samples.items():
        if not ds:
            continue
        med = min(ds)
        jit = (max(ds) - min(ds)) if len(ds) > 1 else 0
        if med > 1000 or jit > 400:
            continue
        stats[k] = (med, jit)
    log("端到端达标（≤1000ms，抖动≤400ms）%d 条" % len(stats))

    # ③ 真实带宽：全部达标节点，6 路并行，每路单独内核 + curl 下载 300KB
    speed = {}
    top_keys = [k for k, _ in sorted(stats.items(), key=lambda kv: kv[1][0])][:200]

    def _one(k):
        q = next((x for _, x in items if (x["server"], int(x["port"])) == k), None)
        return k, (real_speed(q) if q else None)

    from concurrent.futures import ThreadPoolExecutor as _TPE
    with _TPE(max_workers=6) as _ex:
        for k, v in _ex.map(_one, top_keys):
            if v:
                speed[k] = v
    log("真实带宽达标 %d 条" % len(speed))

    # ④ 加权评分 0-100：速度 50% + 延迟 35% + 抖动 15%
    keep = []
    for u, q in items:
        k = (q["server"], int(q["port"]))
        if k not in speed or k not in stats:
            continue
        med, jit = stats[k]
        sp_kb = speed[k]
        if sp_kb < 30:
            continue
        score = 100.0 * (0.50 * min(sp_kb / 2000.0, 1.0)
                         + 0.35 * (1 - min(med / 1000.0, 1.0))
                         + 0.15 * (1 - min(jit / 300.0, 1.0)))
        keep.append((tcp_of.get(k, 9999), -score, u, q))
    keep.sort(key=lambda x: (x[0], x[1]))
    log("评分达标 %d 条" % len(keep))

    # 同网段最多 12 个，避免整份都是同一家的机器
    lim, seen_net, dedup = 12, {}, []
    import ipaddress
    for tcp, sc, u, q in keep:
        try:
            net = str(ipaddress.ip_network(q["server"] + "/24", strict=False))
        except Exception:
            net = q["server"]
        if seen_net.get(net, 0) >= lim:
            continue
        seen_net[net] = seen_net.get(net, 0) + 1
        dedup.append((tcp, sc, u, q))
    keep = dedup
    log("同网段去重后 %d" % len(keep))

    # 稳定性：连续多轮通过才收录（known.json 记录每轮结果）
    import json as _j, time as _tm
    kp = os.path.join(HERE, "known.json")
    try:
        known = _j.load(open(kp, encoding="utf-8"))
    except Exception:
        known = {}
    now = _tm.time()
    cur = {"%s:%d" % (q["server"], int(q["port"])) for *_, q in keep}
    for k in list(known):
        if k not in cur:
            known[k]["s"] = known[k].get("s", 0) - 1
            if known[k]["s"] <= 0:
                del known[k]
    for *_, u, q in keep:
        k = "%s:%d" % (q["server"], int(q["port"]))
        rec = known.get(k, {"s": 0})
        rec["s"] = rec.get("s", 0) + 1
        rec["t"] = now
        rec["u"] = u
        known[k] = rec
    known = dict(sorted(known.items(), key=lambda kv: -kv[1].get("t", 0))[:800])
    try:
        _j.dump(known, open(kp, "w", encoding="utf-8"), ensure_ascii=False)
    except Exception:
        pass
    stable = [x for x in keep
              if known.get("%s:%d" % (x[3]["server"], int(x[3]["port"])), {}).get("s", 0) >= 3]
    log("连续 3 轮通过 %d 条，本轮通过 %d 条" % (len(stable), len(keep)))
    keep = stable or keep[:30]
    # 最终按 TCP 延迟从低到高排（客户端显示的延迟更接近这个值）
    keep = sorted(keep, key=lambda x: (x[0], x[1]))

    regs = geo.regions([q for *_, q in keep])
    cnt, out = {}, []
    for (tcp, sc, u, q), r in zip(keep, regs):
        cnt[r] = cnt.get(r, 0) + 1
        out.append(u.split("#")[0] + "#" + (NAME % (r, cnt[r])).replace(" ", "%20"))
    out = out[:200]

    old_n = 0
    fp = os.path.join(OUT, "final2.txt")
    if os.path.exists(fp):
        try:
            old_n = len(base64.b64decode(open(fp).read()).decode().splitlines())
        except Exception:
            old_n = 0
    if not out:
        log("  !! 本轮结果 %d 条，明显少于上一版 %d 条，保留上一版" % (len(out), old_n))
        return
    with open(os.path.join(OUT, "final2.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(out).encode()).decode())
    with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
        f.write("更新 %s\n合并 %d / 通过 %d / 收录 %d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), len(lines), len(speed), len(out)))
    log("写入 sub.txt：%d 条" % len(out))


if __name__ == "__main__":
    import traceback
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
