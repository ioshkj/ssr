#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原样合并订阅源 -> 测速 -> 只改名字 -> 生成唯一订阅 sub/sub.txt
   规则：节点链接一个字都不改，只替换 # 后面的名称"""
import base64, os, re, subprocess, time
import urllib.parse as up
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


def is_fresh(path, hours=30):
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






def udp_ok(q, timeout=8):
    """通过 SOCKS5 UDP ASSOCIATE 发一次 DNS 查询，能收到回包说明节点支持 UDP"""
    import json as _json, socket as _sk, struct as _st, subprocess as _sp
    import tempfile as _tf, time as _t, urllib.request as _ur
    wd = _tf.mkdtemp(prefix="udp-")
    a, b = _sk.socket(), _sk.socket()
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    api_p, mix_p = a.getsockname()[1], b.getsockname()[1]
    a.close(); b.close()
    cfg = {"mixed-port": mix_p, "external-controller": "127.0.0.1:%d" % api_p,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = wd + "/c.yaml"
    open(path, "w").write(_json.dumps(cfg, ensure_ascii=False))
    p = _sp.Popen([verify.BIN, "-d", wd, "-f", path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    s = None
    try:
        for _ in range(40):
            _t.sleep(0.2)
            try:
                _ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return False
        s = _sk.create_connection(("127.0.0.1", mix_p), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False
        s.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        rep = s.recv(32)
        if len(rep) < 10 or rep[1] != 0:
            return False
        u = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
        u.settimeout(timeout)
        relay = (_sk.inet_ntoa(rep[4:8]) if rep[3] == 1 else "127.0.0.1",
                 _st.unpack(">H", rep[8:10])[0])
        if relay[0] == "0.0.0.0":
            relay = ("127.0.0.1", relay[1])
        tid = 0x1234
        header = _st.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qn = b"".join(bytes([len(x)]) + x.encode() for x in "example.com".split(".")) + b"\x00"
        dns = header + qn + _st.pack(">HH", 1, 1)
        pkt = b"\x00\x00\x00\x01" + _sk.inet_aton("8.8.8.8") + _st.pack(">H", 53) + dns
        u.sendto(pkt, relay)
        data, _ = u.recvfrom(2048)
        return len(data) > 10
    except Exception:
        return False
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def exit_cc(q, timeout=12):
    """通过节点查询真实出口国家码：先 2 秒 TCP 探测，再起单节点内核问 ip-api"""
    try:
        import socket as _s0
        _s0.create_connection((q["server"], int(q["port"])), timeout=2).close()
    except Exception:
        return None
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
        if not is_fresh(p, 30):
            stale += 1
            log("  [跳过] %s 超过 30 小时未更新" % p)
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
    raw_types = {}
    raw_total = 0
    for u in lines:
        _name = up.unquote(u.split("#")[-1]) if "#" in u else ""
        q = nodeconv.to_clash(u, _name)
        if not q:
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_ep:
            continue
        raw_total += 1
        _t0 = q.get("type", "?")
        raw_types[_t0] = raw_types.get(_t0, 0) + 1
        # 去重阶段就剔除美国节点（测速在境外，美国节点会天然占优）
        _cc0 = geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", "")))
        if _cc0 in ("US", "CA") and q.get("type") not in ("anytls", "http"):
            us_skip += 1
            continue
        seen_ep.add(ep)
        items.append((u, q))
    import collections as _col
    _types = _col.Counter(q.get("type", "?") for _, q in items)
    log("去重后唯一入口 %d 个（提前剔除疑似美国/加拿大 %d 个）" % (len(items), us_skip))
    log("  去重后总量 %d，类型分布：" % raw_total)
    for _k, _v in sorted(raw_types.items(), key=lambda kv: -kv[1]):
        log("    %-10s %d" % (_k, _v))
    anytls_pool = [(u, q) for u, q in items if q.get("type") == "anytls"]
    http_pool = [(u, q) for u, q in items if q.get("type") in ("http", "anytls")]
    log("  AnyTLS 原始 %d 条" % len(anytls_pool))
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

    # ④ 地区检测（先于测速）：逐个查真实出口 IP
    from concurrent.futures import ThreadPoolExecutor as _TPE_G

    def _geo(uq):
        u, q = uq
        return exit_cc(q)

    with _TPE_G(max_workers=32) as _exg:
        _all_cc = list(_exg.map(_geo, items))
    log("地区检测完成，共 %d 个" % len(_all_cc))

    # ⑤ 剔除真实出口在美加的（anytls / http 两类特殊订阅除外）
    keep_geo, regs_geo = [], []
    unverified_raw = []
    for (u, q), cc in zip(items, _all_cc):
        if not cc:
            unverified_raw.append((u, q))
            continue
        if cc in ("US", "CA") and q.get("type") not in ("anytls", "http"):
            continue
        keep_geo.append((u, q))
        regs_geo.append(geo.CC_NAME.get(cc, "其他"))
    log("剔除美加后 %d 条，未查到出口 %d 条" % (len(keep_geo), len(unverified_raw)))

    # ⑥ 改名：地区-序号 0070077.xyz
    cnt_name = {}
    renamed = []
    for (u, q), r in zip(keep_geo, regs_geo):
        cnt_name[r] = cnt_name.get(r, 0) + 1
        nm = NAME % (r, cnt_name[r])
        uri = u.split("#")[0] + "#" + nm.replace(" ", "%20")
        renamed.append((uri, dict(q, name=nm), r))
    log("改名完成，示例：%s" % (renamed[0][1]["name"] if renamed else "无"))

    # ⑦ 测速：TCP（全部）
    ps = [q for _, q, _ in renamed]
    lat = []
    from concurrent.futures import ThreadPoolExecutor as _TPE_T
    with _TPE_T(max_workers=32) as _ext:
        lat = list(_ext.map(lambda q: tcp_ms(q), ps))
    tcp_of = {}
    alive = []
    for (uri, q, r), l in zip(renamed, lat):
        if l is not None:
            tcp_of[(q["server"], int(q["port"]))] = l
            alive.append((uri, q, r))
    log("TCP 连通 %d / %d" % (len(alive), len(renamed)))

    # ⑦ 测速：HTTP（全部连通节点，两轮取最小）
    samples = {}
    for rnd in range(2):
        r_ = verify.verify([dict(q) for _, q, _ in alive], workers=32, timeout=8000,
                           url="http://www.gstatic.com/generate_204", log=lambda m: None)
        for p, d in r_:
            samples.setdefault((p["server"], int(p["port"])), []).append(d)
        log("  HTTP 第 %d 次成功 %d" % (rnd + 1, len(r_)))
    stats = {}
    for k, ds in samples.items():
        med = min(ds)
        jit = (max(ds) - min(ds)) if len(ds) > 1 else 0
        stats[k] = (med, jit)
    log("HTTP 通 %d 条" % len(stats))

    # ⑦ 测速：下载（全部 HTTP 通过节点，10 路并行）
    http_alive = [(uri, q, r) for uri, q, r in alive if (q["server"], int(q["port"])) in stats]
    from concurrent.futures import ThreadPoolExecutor as _TPE_D

    def _dl(item):
        uri, q, r = item
        return (q["server"], int(q["port"])), real_speed(q)

    speed = {}
    with _TPE_D(max_workers=16) as _exd:
        for k, v in _exd.map(_dl, http_alive):
            if v:
                speed[k] = v
    log("下载成功 %d 条" % len(speed))

    # ⑧ 组装 keep（tcp, http, jitter, 速度, 综合分, uri, proxy）
    keep, regs = [], []
    for uri, q, r in http_alive:
        k = (q["server"], int(q["port"]))
        if k not in speed:
            continue
        med, jit = stats[k]
        sp_kb = speed[k]
        sc = 100.0 * (0.50 * min(sp_kb / 2000.0, 1.0)
                      + 0.35 * (1 - min(med / 1000.0, 1.0))
                      + 0.15 * (1 - min(jit / 300.0, 1.0)))
        keep.append((tcp_of[k], med, jit, sp_kb, sc, uri, q))
        regs.append(r)
    log("通过全部测试 %d 条" % len(keep))
    _rows = [(t, m, j, s, sc, u, q) for (t, m, j, s, sc, u, q) in keep]
    _ccs = [None] * len(keep)
    unverified_rows = [((0, 0, 0, 0.0, 0.0, u, q),
                        geo.CC_NAME.get(geo.guess_cc(q.get("name", "")), "其他"))
                       for u, q in unverified_raw]

    def emit(filename, order):
        PER_REGION = 7
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

    # ⑤ 真实出口地区（复用前面查好的结果）
    if keep:
        cnt_e, out_e = {}, []
        for row, r in sorted(zip(keep, regs), key=lambda z: -z[0][4]):
            if cnt_e.get(r, 0) >= 7:
                continue
            cnt_e[r] = cnt_e.get(r, 0) + 1
            out_e.append(row[5].split("#")[0] + "#" + (NAME % (r, cnt_e[r])).replace(" ", "%20"))
            if len(out_e) >= 200:
                break
        if out_e:
            with open(os.path.join(OUT, "final6.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_e).encode()).decode())
        log("  final6.txt：%d 条（真实出口）" % len(out_e))

    # ⑥ 第六份：剔除美加后的全部节点（不限地区，最多 200）
    out_all, cnt_a = [], {}
    for (tcp, med, jit, sp, sc, u, q), r in sorted(zip(keep, regs), key=lambda z: -z[0][4]):
        cnt_a[r] = cnt_a.get(r, 0) + 1
        out_all.append(u.split("#")[0] + "#" + (NAME % (r, cnt_a[r])).replace(" ", "%20"))
        if len(out_all) >= 200:
            break
    if out_all:
        with open(os.path.join(OUT, "final7.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out_all).encode()).decode())
    log("  final7.txt：%d 条（全部通过，不限地区）" % len(out_all))

    # ⑦ 按协议类型分组，每种最多 7 条（按综合分排序）
    TYPE_CN = {"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan",
               "ss": "SS", "ssr": "SSR", "anytls": "AnyTLS",
               "http": "HTTP", "socks5": "Socks5", "hysteria2": "Hy2"}
    cnt_t, out_t = {}, []
    for (tcp, med, jit, sp, sc, u, q), r in sorted(zip(keep, regs), key=lambda z: -z[0][4]):
        t = q.get("type", "other")
        if cnt_t.get(t, 0) >= 7:
            continue
        cnt_t[t] = cnt_t.get(t, 0) + 1
        nm = "%s-%02d 0070077.xyz" % (TYPE_CN.get(t, t), cnt_t[t])
        out_t.append(u.split("#")[0] + "#" + nm.replace(" ", "%20"))
        if len(out_t) >= 200:
            break
    if out_t:
        with open(os.path.join(OUT, "final8.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out_t).encode()).decode())
    log("  final8.txt：%d 条（按协议类型，每种 7 条）" % len(out_t))

    # ⑧ 高延迟段：TCP 延迟 500~1000ms 的节点（其他规则不变）
    mid = [(row, r) for row, r in zip(keep, regs) if 500 <= row[0] <= 1000]
    cnt_m, out_m = {}, []
    for (tcp, med, jit, sp, sc, u, q), r in sorted(mid, key=lambda z: -z[0][4]):
        if cnt_m.get(r, 0) >= 7:
            continue
        cnt_m[r] = cnt_m.get(r, 0) + 1
        out_m.append(u.split("#")[0] + "#" + (NAME % (r, cnt_m[r])).replace(" ", "%20"))
        if len(out_m) >= 200:
            break
    if out_m:
        with open(os.path.join(OUT, "final9.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out_m).encode()).decode())
    log("  final9.txt：%d 条（TCP 500~1000ms）" % len(out_m))

    # ⑨ 回国方向：通过节点访问国内站点，按该延迟排序，每地区 7 条
    cn_rows = [(row, r) for row, r in zip(keep, regs)]
    if cn_rows:
        probes = [dict(row[6]) for row, _ in cn_rows]
        r_cn = verify.verify(probes, workers=16, timeout=10000,
                             url="http://www.baidu.com", log=lambda m: None)
        cn_map = {(p["server"], int(p["port"])): d for p, d in r_cn}
        log("回国方向可用 %d 条" % len(cn_map))
        picked = []
        for row, r in cn_rows:
            k = (row[6]["server"], int(row[6]["port"]))
            if k in cn_map:
                picked.append((cn_map[k], row, r))
        picked.sort(key=lambda z: z[0])
        cnt_c, out_c = {}, []
        for delay, row, r in picked:
            if cnt_c.get(r, 0) >= 7:
                continue
            cnt_c[r] = cnt_c.get(r, 0) + 1
            out_c.append(row[5].split("#")[0] + "#" + (NAME % (r, cnt_c[r])).replace(" ", "%20"))
            if len(out_c) >= 200:
                break
        if out_c:
            with open(os.path.join(OUT, "final10.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_c).encode()).decode())
        log("  final10.txt：%d 条（回国方向，每地区 7 条）" % len(out_c))

    # ⑩ 逐目标测试，记录每个节点在哪些目标上通过
    TARGETS = [
        ("YouTube", "https://i.ytimg.com/generate_204"),
        ("Cloudflare", "https://cp.cloudflare.com/generate_204"),
        ("Twitter", "https://abs.twimg.com/favicon.ico"),
        ("Telegram", "https://telegram.org/favicon.ico"),
    ]
    passed = {}          # key -> set(通过的 target)
    if keep:
        keys = [(row[6]["server"], int(row[6]["port"])) for row in keep]
        for tname, url in TARGETS:
            got = verify.verify([dict(row[6]) for row in keep],
                                workers=24, timeout=10000, url=url, log=lambda m: None)
            ok = {(p["server"], int(p["port"])) for p, _ in got}
            for k in keys:
                passed.setdefault(k, set())
                if k in ok:
                    passed[k].add(tname)
            log("  目标 %-10s 通过 %d / %d" % (tname, len(ok), len(keys)))

    def dump(filename, rows, cap=7):
        cnt, out = {}, []
        for row, r in sorted(rows, key=lambda z: -z[0][4]):
            if cnt.get(r, 0) >= cap:
                continue
            cnt[r] = cnt.get(r, 0) + 1
            out.append(row[5].split("#")[0] + "#" + (NAME % (r, cnt[r])).replace(" ", "%20"))
            if len(out) >= 200:
                break
        if out:
            with open(os.path.join(OUT, filename), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out).encode()).decode())
        log("  %s：%d 条" % (filename, len(out)))
        return out

    # ⑪ 五目标全通（Google 由前面的测试保证）
    full_ok = [(row, r) for row, r in zip(keep, regs)
               if len(passed.get((row[6]["server"], int(row[6]["port"])), set())) == len(TARGETS)]
    log("五目标全通：%d 条" % len(full_ok))
    dump("final11.txt", full_ok)

    # ⑫ SNI 敏感：Google 通，但其它目标里至少有一个不通
    sni_rows = [(row, r) for row, r in zip(keep, regs)
                if 0 < len(passed.get((row[6]["server"], int(row[6]["port"])), set())) < len(TARGETS)]
    log("SNI 敏感（部分目标被封）：%d 条" % len(sni_rows))
    dump("final12.txt", sni_rows)

    # ⑬ SNI 敏感 + 支持 UDP
    if sni_rows:
        from concurrent.futures import ThreadPoolExecutor as _TPE3
        with _TPE3(max_workers=4) as _ex3:
            udp_res = list(_ex3.map(lambda z: udp_ok(z[0][6]), sni_rows))
        combo = [z for z, ok in zip(sni_rows, udp_res) if ok]
        log("SNI 敏感且支持 UDP：%d 条" % len(combo))
        dump("final13.txt", combo)

    # ⑬ 单独一份：支持 UDP 的节点
    if keep:
        from concurrent.futures import ThreadPoolExecutor as _TPE4
        with _TPE4(max_workers=6) as _ex4:
            u_flags = list(_ex4.map(lambda row: udp_ok(row[6]), keep))
        u_rows = [(row, r) for row, r, ok in zip(keep, regs, u_flags) if ok]
        log("支持 UDP：%d 条" % len(u_rows))
        cnt_u, out_u = {}, []
        for row, r in sorted(u_rows, key=lambda z: -z[0][4]):
            if cnt_u.get(r, 0) >= 7:
                continue
            cnt_u[r] = cnt_u.get(r, 0) + 1
            out_u.append(row[5].split("#")[0] + "#" + (NAME % (r, cnt_u[r])).replace(" ", "%20"))
            if len(out_u) >= 200:
                break
        if out_u:
            with open(os.path.join(OUT, "final14.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_u).encode()).decode())
        log("  final14.txt：%d 条（支持 UDP）" % len(out_u))

    # ⑭ 拿不到出口地区的节点（可能仍能用，单独放）
    if unverified_rows:
        cnt_v, out_v = {}, []
        for row, r in sorted(unverified_rows, key=lambda z: -z[0][4]):
            if cnt_v.get(r, 0) >= 7:
                continue
            cnt_v[r] = cnt_v.get(r, 0) + 1
            out_v.append(row[5].split("#")[0] + "#" + (NAME % (r, cnt_v[r])).replace(" ", "%20"))
            if len(out_v) >= 200:
                break
        if out_v:
            with open(os.path.join(OUT, "final15.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_v).encode()).decode())
        log("  final15.txt：%d 条（未验证地区）" % len(out_v))

    # ⑮ 全部合并（final2~15 去重后重新编号，避免重名）
    merged, seen_ep2, cnt_m2 = [], set(), {}
    for i in range(2, 16):
        fn = os.path.join(OUT, "final%d.txt" % i)
        if not os.path.exists(fn):
            continue
        try:
            text = base64.b64decode(open(fn, "rb").read()).decode()
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            q = nodeconv.to_clash(line, "x")
            if not q:
                continue
            ep = (str(q["server"]).lower(), int(q["port"]))
            if ep in seen_ep2:
                continue
            seen_ep2.add(ep)
            cc = geo.guess_cc(q.get("name", ""))
            r = geo.CC_NAME.get(cc, "其他")
            cnt_m2[r] = cnt_m2.get(r, 0) + 1
            merged.append(line.split("#")[0] + "#" + (NAME % (r, cnt_m2[r])).replace(" ", "%20"))
    if merged:
        with open(os.path.join(OUT, "all.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(merged).encode()).decode())
    log("  all.txt：%d 条（合并去重）" % len(merged))

    # 测速明细表（剔除美加后，按延迟排序）
    if keep:
        lines_t = ["名称\t协议\t地区\tTCP(ms)\tHTTP(ms)\t抖动(ms)\t下载(KB/s)"]
        for (tcp, med, jit, sp, sc, u, q), r in sorted(zip(keep, regs), key=lambda z: z[0][0]):
            lines_t.append("%s\t%s\t%s\t%d\t%d\t%d\t%.0f" % (
                q.get("name", "")[:28], q.get("type", ""), r, tcp, med, jit, sp))
        with open(os.path.join(OUT, "table.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines_t) + "\n")
        log("  table.txt：%d 行（按延迟）" % (len(lines_t) - 1))

        lines_s = ["名称\t协议\t地区\t下载(KB/s)\tTCP(ms)\tHTTP(ms)\t抖动(ms)"]
        for (tcp, med, jit, sp, sc, u, q), r in sorted(zip(keep, regs), key=lambda z: -z[0][3]):
            lines_s.append("%s\t%s\t%s\t%.0f\t%d\t%d\t%d" % (
                q.get("name", "")[:28], q.get("type", ""), r, sp, tcp, med, jit))
        with open(os.path.join(OUT, "table_speed.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines_s) + "\n")
        log("  table_speed.txt：%d 行（按下载速度）" % (len(lines_s) - 1))

    # 网页版报表（可用浏览器直接看，支持点表头排序）
    if keep:
        import html as _html
        rows_html = []
        for (tcp, med, jit, sp, sc, u, q), r in sorted(zip(keep, regs), key=lambda z: -z[0][3]):
            sp_ = float(sp)
            cls = "fast" if sp_ >= 500 else ("mid" if sp_ >= 150 else "slow")
            rows_html.append(
                '<tr class="%s"><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%.0f</td></tr>'
                % (cls, _html.escape(q.get("name", "")[:40]), _html.escape(q.get("type", "")),
                   _html.escape(r), tcp, med, jit, sp_))
        stats_html = ""
        page = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>节点测速表</title>
<style>
body{font-family:-apple-system,"PingFang SC",sans-serif;background:#0f1115;color:#e6e6e6;margin:24px}
h1{font-size:18px;margin:0 0 4px}.sub{color:#8b93a1;font-size:12px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid #23262e;text-align:left;white-space:nowrap}
th{position:sticky;top:0;background:#161a21;cursor:pointer;user-select:none;color:#9aa4b2;font-weight:500}
tr.fast td:nth-child(7){color:#4ade80}tr.mid td:nth-child(7){color:#fbbf24}tr.slow td:nth-child(7){color:#f87171}
tr:hover{background:#171b22}
</style></head><body>
<h1>节点测速表</h1>
<div class="sub">共 @N@ 条 · 已剔除美国/加拿大 · 点击表头排序</div>
<table id="t"><thead><tr><th>名称</th><th>协议</th><th>地区</th><th>TCP(ms)</th><th>HTTP(ms)</th><th>抖动(ms)</th><th>下载(KB/s)</th></tr></thead>
<tbody>@ROWS@</tbody></table>
<script>
document.querySelectorAll('#t th').forEach(function(th,i){
  var asc=false;
  th.onclick=function(){
    asc=!asc;
    var tb=document.querySelector('#t tbody');
    var rows=Array.prototype.slice.call(tb.rows);
    rows.sort(function(a,b){
      var x=a.cells[i].innerText, y=b.cells[i].innerText;
      var nx=parseFloat(x), ny=parseFloat(y);
      if(!isNaN(nx)&&!isNaN(ny)) return asc?nx-ny:ny-nx;
      return asc? x.localeCompare(y) : y.localeCompare(x);
    });
    rows.forEach(function(r){tb.appendChild(r)});
  };
});
</script></body></html>""".replace("@N@", str(len(rows_html))).replace("@ROWS@", "\n".join(rows_html))
        with open(os.path.join(OUT, "report.html"), "w", encoding="utf-8") as f:
            f.write(page)
        log("  report.html：%d 行（网页版）" % len(rows_html))

    # 中速段：下载 100~300 KB/s
    mid_rows = [(row, r) for row, r in zip(keep, regs) if 100 <= row[3] <= 300]
    if mid_rows:
        cnt_d, out_d = {}, []
        for (tcp, med, jit, sp, sc, u, q), r in sorted(mid_rows, key=lambda z: -z[0][3]):
            if cnt_d.get(r, 0) >= 7:
                continue
            cnt_d[r] = cnt_d.get(r, 0) + 1
            out_d.append(u.split("#")[0] + "#" + (NAME % (r, cnt_d[r])).replace(" ", "%20"))
            if len(out_d) >= 200:
                break
        if out_d:
            with open(os.path.join(OUT, "final17.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_d).encode()).decode())
        log("  final17.txt：%d 条（下载 100~300KB/s）" % len(out_d))

    # HTTP + AnyTLS 合并（不测速，直接输出）
    if http_pool:
        cnt_h, out_h, seen_h = {}, [], set()
        for u, q in http_pool:
            ep_h = (str(q["server"]).lower(), int(q["port"]))
            if ep_h in seen_h:
                continue
            seen_h.add(ep_h)
            cc = geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", "")))
            r = geo.CC_NAME.get(cc, "其他")
            cnt_h[r] = cnt_h.get(r, 0) + 1
            out_h.append(u.split("#")[0] + "#" + (NAME % (r, cnt_h[r])).replace(" ", "%20"))
        with open(os.path.join(OUT, "final18.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out_h).encode()).decode())
        log("  final18.txt：%d 条（HTTP + AnyTLS，未测速）" % len(out_h))

    # ⑯ 全部 AnyTLS：只查真实出口 IP（不测速），查不到的不收
    if anytls_pool:
        from concurrent.futures import ThreadPoolExecutor as _TPE_Y
        with _TPE_Y(max_workers=6) as _exy:
            _ycc = list(_exy.map(lambda uq: exit_cc(uq[1]), anytls_pool))
        cnt_y, out_y, seen_y = {}, [], set()
        for (u, q), cc in zip(anytls_pool, _ycc):
            if not cc:
                continue
            ep_y = (str(q["server"]).lower(), int(q["port"]))
            if ep_y in seen_y:
                continue
            seen_y.add(ep_y)
            r = geo.CC_NAME.get(cc, "其他")
            cnt_y[r] = cnt_y.get(r, 0) + 1
            out_y.append(u.split("#")[0] + "#" + (NAME % (r, cnt_y[r])).replace(" ", "%20"))
        if out_y:
            with open(os.path.join(OUT, "final16.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(out_y).encode()).decode())
        log("  final16.txt：%d 条（AnyTLS，仅查 IP，共 %d）" % (len(out_y), len(anytls_pool)))

    with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
        f.write("更新 %s\n合并 %d / 通过 %d / 稳定 %d / TCP版 %d / HTTP版 %d / 速度版 %d / 综合版 %d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), len(lines), len(keep),
                   len(keep), n_tcp, n_http, n_speed, n_score))


if __name__ == "__main__":
    import traceback
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
