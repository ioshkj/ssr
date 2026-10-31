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


def repo_pushed(repo, cache={}):
    """返回仓库最近一次 push 时间（datetime），失败返回 None"""
    if repo in cache:
        return cache[repo]
    import json as _json, os as _os, urllib.request as _ur
    h = {"Accept": "application/vnd.github+json", "User-Agent": "curl/8"}
    tok = _os.environ.get("GITHUB_TOKEN", "")
    if tok:
        h["Authorization"] = "Bearer " + tok
    try:
        req = _ur.Request("https://api.github.com/repos/%s" % repo, headers=h)
        d = _json.loads(_ur.urlopen(req, timeout=20).read().decode())
        import datetime as _dt
        t = _dt.datetime.fromisoformat(d["pushed_at"].replace("Z", "+00:00"))
    except Exception:
        t = None
    cache[repo] = t
    return t


def is_fresh(path, hours=48):
    import datetime as _dt
    repo = "/".join(path.split("/")[:2])
    t = repo_pushed(repo)
    if t is None:
        return True          # 查不到就放行，避免误杀
    age = (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() / 3600.0
    return age <= hours


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
    if not isinstance(items, list):
        return []
    out = []
    for x in items:
        if isinstance(x, str):
            out.append(x)
            continue
        if x.get("fails", 0) >= 3:
            continue
        repo = x.get("repo")
        path = x.get("path")
        if not repo or not path:
            continue
        out.append("%s/%s/%s" % (repo, x.get("branch", "main"), path))
    return out


def tcp_ok(host, port, timeout=1.5):
    import socket
    try:
        socket.create_connection((host, int(port)), timeout=timeout).close()
        return True
    except Exception:
        return False





def exit_cc(q, timeout=12):
    """通过节点查询真实出口国家码：起单节点内核 + curl 走本地代理问 ip-api"""
    import json as _json, socket as _sock, subprocess as _sp, tempfile as _tf, time as _t, urllib.request as _ur

    wd = _tf.mkdtemp(prefix="geo-")
    a, b = _sock.socket(), _sock.socket()
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    api_p, mix_p = a.getsockname()[1], b.getsockname()[1]
    a.close(); b.close()
    cfg = {"mixed-port": mix_p, "external-controller": "127.0.0.1:%d" % api_p,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = wd + "/c.yaml"
    open(path, "w").write(_json.dumps(cfg, ensure_ascii=False))
    p = _sp.Popen([verify.BIN, "-d", wd, "-f", path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        for _ in range(40):
            _t.sleep(0.2)
            try:
                _ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None
        r = _sp.run(["curl", "-s", "--max-time", str(timeout),
                     "-x", "http://127.0.0.1:%d" % mix_p,
                     "http://ip-api.com/json/?fields=countryCode"],
                    capture_output=True, text=True)
        d = _json.loads(r.stdout or "{}")
        cc = (d.get("countryCode") or "").upper()
        return cc or None
    except Exception:
        return None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


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
    stale = 0
    for p in SRC + discovered():
        if not is_fresh(p, 48):
            stale += 1
            log("  [跳过] %s 超过 48 小时未更新" % p)
            continue
        n = 0
        for u in lines_of(fetch(p)):
            k = u.split("#")[0]
            if k in seen:
                continue
            seen.add(k)
            lines.append(u)
            n += 1
        log("  %-46s +%d" % (p.split("/")[-1][:44], n))
    log("合并 %d 条（原样，未改），跳过过期源 %d 个" % (len(lines), stale))

    # 第一步：按 server:port 去重（同一入口只留一条）
    items, seen_ep, us_skip = [], set(), 0
    for u in lines:
        q = nodeconv.to_clash(u, "x")
        if not q:
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_ep:
            continue
        # 去重阶段就剔除美国节点（测速在境外，美国节点会天然占优）
        if geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", ""))) in ("US", "CA"):
            us_skip += 1
            continue
        seen_ep.add(ep)
        items.append((u, q))
    log("去重后唯一入口 %d 个（提前剔除疑似美国/加拿大 %d 个）" % (len(items), us_skip))
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
    pairs = [(l, q) for q, l in zip(ps, lat) if l is not None and l <= 1500]
    tcp_of = {(q["server"], int(q["port"])): l for l, q in pairs}
    pairs.sort(key=lambda x: x[0])
    ps = [q for _, q in pairs]
    log("TCP ≤1500ms 的 %d 条，进入端到端测试" % len(ps))

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
        if med > 2500 or jit > 600:
            continue
        stats[k] = (med, jit)
    log("端到端达标（≤2500ms，抖动≤600ms）%d 条" % len(stats))

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

    # ④ 记录两条延迟指标
    keep = []
    for u, q in items:
        k = (q["server"], int(q["port"]))
        if k not in speed or k not in stats:
            continue
        med, jit = stats[k]
        if speed[k] < 30:
            continue
        sc = 100.0 * (0.50 * min(speed[k] / 2000.0, 1.0)
                      + 0.35 * (1 - min(med / 1000.0, 1.0))
                      + 0.15 * (1 - min(jit / 300.0, 1.0)))
        keep.append((tcp_of.get(k, 9999), med, jit, speed[k], sc, u, q))
    keep.sort(key=lambda x: x[0])
    log("通过全部测试 %d 条" % len(keep))

    # 同网段最多 12 个
    lim, seen_net, dedup = 12, {}, []
    import ipaddress
    for tcp, med, jit, sp, sc, u, q in keep:
        try:
            net = str(ipaddress.ip_network(q["server"] + "/24", strict=False))
        except Exception:
            net = q["server"]
        if seen_net.get(net, 0) >= lim:
            continue
        seen_net[net] = seen_net.get(net, 0) + 1
        dedup.append((tcp, med, jit, sp, sc, u, q))
    keep = dedup
    log("同网段去重后 %d" % len(keep))

    # 稳定性（known.json）
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
    known = dict(sorted(known.items(), key=lambda kv: -kv[1].get("t", 0))[:1200])
    try:
        _j.dump(known, open(kp, "w", encoding="utf-8"), ensure_ascii=False)
    except Exception:
        pass
    stable = [x for x in keep
              if known.get("%s:%d" % (x[6]["server"], int(x[6]["port"])), {}).get("s", 0) >= 3]
    log("连续 3 轮通过 %d 条，本轮通过 %d 条" % (len(stable), len(keep)))
    keep = stable if len(stable) >= 10 else keep[:60]

    # 只按「节点名 / 域名」判断地区（不做 IP 反查，避免 CF 节点被误判成加拿大）
    keep2, regs = [], []
    for row in keep:
        q = row[6]
        cc = geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", "")))
        if cc in ("US", "CA"):
            continue
        keep2.append(row)
        regs.append(geo.CC_NAME.get(cc, "其他"))
    log("按名称剔除美加后：%d 条" % len(keep2))
    keep = keep2

    def emit(filename, order):
        PER_REGION = 5
        cnt, out = {}, []
        KEYS = {0: lambda t: t[0], 1: lambda t: t[1], 2: lambda t: -t[3], 3: lambda t: -t[4]}
        for row, r in sorted(zip(keep, regs), key=lambda z: KEYS[order](z[0])):
            tcp, med, jit, sp, sc, u, q = row
            if cnt.get(r, 0) >= PER_REGION:
                continue
            cnt[r] = cnt.get(r, 0) + 1
            out.append(u.split("#")[0] + "#" + (NAME % (r, cnt[r])).replace(" ", "%20"))
            if len(out) >= 200:
                break
        if not out:
            log("  !! %s 本轮无结果，保留上一版" % filename)
            return 0
        with open(os.path.join(OUT, filename), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out).encode()).decode())
        log("  %s：%d 条（%d 个地区）" % (filename, len(out), len(cnt)))
        return len(out)

    n_tcp = emit("final2.txt", 0)    # 按 TCP 延迟
    n_http = emit("final3.txt", 1)   # 按 HTTP 延迟
    n_speed = emit("final4.txt", 2)  # 按下载速度
    n_score = emit("final5.txt", 3)  # 综合评分

    # ⑤ 第五份：与上面同一批节点，但按真实地区重新编号输出（方便单独对比）
    if keep:
        cnt_r, out_r = {}, []
        for (tcp, med, jit, sp, sc, u, q), r in zip(keep, regs):
            if cnt_r.get(r, 0) >= 5:
                continue
            cnt_r[r] = cnt_r.get(r, 0) + 1
            out_r.append(u.split("#")[0] + "#" + (NAME % (r, cnt_r[r])).replace(" ", "%20"))
            if len(out_r) >= 200:
                break
        if out_r:
            with open(os.path.join(OUT, "final6.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_r).encode()).decode())
            log("  final6.txt：%d 条（真实出口）" % len(out_r))

    with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
        f.write("更新 %s\n合并 %d / 通过 %d / 稳定 %d / TCP版 %d / HTTP版 %d / 速度版 %d / 综合版 %d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), len(lines), len(keep),
                   len(stable), n_tcp, n_http, n_speed, n_score))


if __name__ == "__main__":
    import traceback
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
