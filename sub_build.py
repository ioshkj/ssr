#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""原样合并订阅源 -> 测速 -> 只改名字 -> 生成唯一订阅 sub/sub.txt
   规则：节点链接一个字都不改，只替换 # 后面的名称"""
import base64, os, re, subprocess, time
import urllib.parse as up
import nodeconv, geo
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
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "mihomo")
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
    p = _sp.Popen([BIN, "-d", wd, "-f", path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
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
    p = _sp.Popen([BIN, "-d", wd, "-f", path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
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



def fix_http_auth(uri):
    """QX/小火箭 对没有 user:pass 的 http(s) 链接会解析失败，补上 null:null"""
    if not uri.startswith(("http://", "https://")):
        return uri
    head, _, tail = uri.partition("://")
    hostpart = tail.split("?")[0].split("/")[0]
    if "@" in hostpart:
        return uri
    return head + "://null:null@" + tail


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
    p = _sp.Popen([BIN, "-d", wd, "-f", path],
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
                     "--max-time", str(timeout),
                     "-w", "%{http_code} %{size_download} %{speed_download}",
                     "https://speed.cloudflare.com/__down?bytes=%d" % bytes_],
                    capture_output=True, text=True)
        parts = (r.stdout or "").split()
        if len(parts) < 3:
            return None
        code, size, sp = parts[0], float(parts[1] or 0), float(parts[2] or 0)
        # 必须真的下到 90% 以上，才算成功
        if code != "200" or size < bytes_ * 0.9:
            return None
        speed = sp / 1024.0
        return speed if speed > 1 else None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()

def main():
    os.makedirs(OUT, exist_ok=True)

    # ① 抓取全部源
    seen, lines, stale = set(), [], 0
    for p in SRC + discovered():
        if not is_fresh(p, 30):
            stale += 1
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
    log("合并 %d 条，跳过过期源 %d 个" % (len(lines), stale))

    # ② 只保留 http / https / anytls
    import urllib.parse as _up
    pool, seen_ep, types = [], set(), {}
    for u in lines:
        nm = _up.unquote(u.split("#")[-1]) if "#" in u else ""
        q = nodeconv.to_clash(u, nm)
        if not q:
            continue
        t = q.get("type")
        types[t] = types.get(t, 0) + 1
        if t not in ("http", "anytls"):
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_ep:
            continue
        seen_ep.add(ep)
        pool.append((u, q))
    log("全部节点类型：" + "  ".join("%s %d" % (k, v) for k, v in sorted(types.items(), key=lambda kv: -kv[1])[:8]))
    log("http/anytls 去重后 %d 条" % len(pool))

    # ③ 地区检测（只用于命名，不删减）
    from concurrent.futures import ThreadPoolExecutor as _TPE

    with _TPE(max_workers=16) as _ex:
        ccs = list(_ex.map(lambda uq: exit_cc(uq[1]), pool))
    got = sum(1 for c in ccs if c)
    log("查到出口地区 %d / %d" % (got, len(pool)))

    PREFER = ["香港", "台湾", "日本", "韩国", "新加坡", "马来西亚", "泰国",
              "菲律宾", "越南", "印度尼西亚", "印度", "澳大利亚", "美国", "加拿大"]

    def region_rank(r):
        return (PREFER.index(r) if r in PREFER else 99, r)

    def scheme_rank(u):
        if u.startswith("https://"): return 0
        if u.startswith("anytls://"): return 1
        if u.startswith("http://"): return 2
        return 3

    # 先剔除「查不到出口 IP」的节点（实测这类 100% 不可用）
    _with_cc = [((u, q), cc) for (u, q), cc in zip(pool, ccs) if cc]
    log("查到出口 IP 的节点：%d / %d" % (len(_with_cc), len(pool)))
    pool = [x for x, _ in _with_cc]
    ccs = [cc for _, cc in _with_cc]

    # ④ 下载测试（多次尝试，失败剔除）
    from concurrent.futures import ThreadPoolExecutor as _TPE_D

    def _dl_try(uq):
        u, q = uq
        best = None
        for _ in range(3):
            v = real_speed(q)
            if v and v > 1:
                best = max(best or 0, v)
        return uq, best

    with _TPE_D(max_workers=8) as _exd:
        _res = list(_exd.map(_dl_try, pool))
    kept, dropped = [], 0
    speed_of = {}
    for (u, q), v in _res:
        if v:
            kept.append((u, q))
            speed_of[(q["server"], int(q["port"]))] = v
        else:
            dropped += 1
    log("下载测试：通过 %d 条，剔除 %d 条" % (len(kept), dropped))

    # ⑤ 按 协议优先级 → 地区 排序后输出唯一订阅
    cc_map = {}
    for (u, q), cc in zip(pool, ccs):
        cc_map[(q["server"], int(q["port"]))] = cc
    rows = []
    cnt = {}
    ordered = sorted(kept, key=lambda uq: (scheme_rank(uq[0]), region_rank(
        geo.CC_NAME.get(cc_map.get((uq[1]["server"], int(uq[1]["port"]))), "其他")
        if cc_map.get((uq[1]["server"], int(uq[1]["port"]))) else
        geo.CC_NAME.get(geo.guess_cc("%s %s" % (uq[1].get("name", ""), uq[1]["server"])), "其他"))))
    out = []
    for u, q in ordered:
        cc = cc_map.get((q["server"], int(q["port"])))
        r = geo.CC_NAME.get(cc, "其他") if cc else geo.CC_NAME.get(
            geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", ""))), "其他")
        cnt[r] = cnt.get(r, 0) + 1
        out.append(fix_http_auth(u.split("#")[0]) + "#" + (NAME % (r, cnt[r])).replace(" ", "%20"))

    if out:
        with open(os.path.join(OUT, "0070077.xyz"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out).encode()).decode())
    log("写入 0070077.xyz：%d 条，%d 个地区" % (len(out), len(cnt)))

    # 亚太近距离地区单独一份
    ASIA = {"香港", "台湾", "日本", "韩国", "新加坡", "马来西亚", "泰国",
            "菲律宾", "越南", "印度尼西亚", "印度", "澳门", "柬埔寨", "澳大利亚"}
    cnt2, out2 = {}, []
    for u, q in ordered:
        cc = cc_map.get((q["server"], int(q["port"])))
        r = geo.CC_NAME.get(cc, "其他") if cc else geo.CC_NAME.get(
            geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", ""))), "其他")
        if r not in ASIA:
            continue
        cnt2[r] = cnt2.get(r, 0) + 1
        out2.append(fix_http_auth(u.split("#")[0]) + "#" + (NAME % (r, cnt2[r])).replace(" ", "%20"))
    if out2:
        with open(os.path.join(OUT, "asia.xyz"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(out2).encode()).decode())
    log("写入 asia.xyz：%d 条，%d 个地区" % (len(out2), len(cnt2)))

    with open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8") as f:
        f.write("更新 %s\n抓取 %d / 去重后 %d / 查到地区 %d / 下载通过 %d / 输出 %d\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), len(lines), len(pool), got, len(kept), len(out)))


if __name__ == "__main__":
    import traceback
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
