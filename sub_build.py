#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓源 → 去重 → 筛类型 → 测一遍 → 出表格 → 去 X → 命名排序 → 生成订阅"""
import base64, json, os, socket, subprocess, time
import urllib.parse as up
import nodeconv, geo

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "sub")
BIN = os.path.join(HERE, "bin", "mihomo")
NAME = "%s-%02d 0070077.xyz"
KEEP_TYPES = ("http", "anytls", "trojan")
CF = "http://cp.cloudflare.com/generate_204"
GOOGLE = "https://www.gstatic.com/generate_204"
YT = "https://i.ytimg.com/generate_204"
DL = "https://speed.cloudflare.com/__down?bytes=300000"

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

PREFER = ["香港", "台湾", "日本", "韩国", "新加坡", "马来西亚", "泰国",
          "菲律宾", "越南", "印度尼西亚", "印度", "澳门", "柬埔寨", "澳大利亚",
          "美国", "加拿大"]


def log(m):
    print(m, flush=True)


def fetch(path, tries=3):
    urls = ["https://gh-proxy.org/https://raw.githubusercontent.com/%s" % path,
            "https://raw.githubusercontent.com/%s" % path]
    for _ in range(tries):
        for u in urls:
            try:
                r = subprocess.run(["curl", "-sL", "--max-time", "25", u], capture_output=True)
                if r.returncode == 0 and len(r.stdout) > 50:
                    return r.stdout
            except Exception:
                pass
        time.sleep(2)
    return b""


def is_fresh(path, hours=30):
    import datetime as dt
    repo = "/".join(path.split("/")[:2])
    try:
        r = subprocess.run(["curl", "-s", "--max-time", "15",
                            "-H", "Accept: application/vnd.github+json",
                            "-H", "User-Agent: curl",
                            "https://api.github.com/repos/%s" % repo], capture_output=True)
        d = json.loads(r.stdout or b"{}")
        t = dt.datetime.fromisoformat(d["pushed_at"].replace("Z", "+00:00"))
        return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 3600 <= hours
    except Exception:
        return True


def lines_of(raw):
    if not raw:
        return []
    text = raw.decode("utf-8", "ignore")
    out = []
    if "proxies:" in text:
        try:
            import yaml
            d = yaml.safe_load(text) or {}
            for p in d.get("proxies") or []:
                u = nodeconv.to_uri(p)
                if u:
                    out.append(u)
            return out
        except Exception:
            pass
    if "://" in text:
        return [l.strip() for l in text.splitlines() if "://" in l]
    try:
        dec = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
        return [l.strip() for l in dec.splitlines() if "://" in l]
    except Exception:
        return []


def discovered():
    p = os.path.join(HERE, "sources.json")
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
        elif isinstance(x, dict) and x.get("repo") and x.get("path"):
            out.append("%s/%s/%s" % (x["repo"], x.get("branch", "main"), x["path"]))
    return out



ASIA_WORDS = ["香港", "台湾", "台北", "日本", "东京", "大阪", "韩国", "首尔",
              "新加坡", "狮城", "马来", "吉隆坡", "泰国", "曼谷", "越南",
              "印尼", "菲律宾", "马尼拉", "印度", "澳门", "柬埔寨"]
EN2CC = {"hk": "HK", "jp": "JP", "sg": "SG", "tw": "TW", "kr": "KR",
         "my": "MY", "th": "TH", "vn": "VN", "id": "ID", "ph": "PH",
         "mo": "MO", "kh": "KH"}


def asia_marker(name, server):
    """名字或域名里能不能看出是亚太"""
    import re as _re
    text = ("%s %s" % (name or "", server or "")).lower()
    for code in EN2CC:
        if _re.search(r"(^|[\s\-_|\[（(])%s(\d|[\s\-_|\]）)]|$)" % code, text):
            return True
    for w in ASIA_WORDS:
        if w in text:
            return True
    return False


def fix_http_auth(uri):
    if not uri.startswith(("http://", "https://")):
        return uri
    head, _, tail = uri.partition("://")
    host = tail.split("?")[0].split("/")[0]
    if "@" in host:
        return uri
    return head + "://null:null@" + tail


def tcp_ms(host, port, n=1, timeout=2.5):
    best = None
    for _ in range(n):
        t0 = time.time()
        try:
            socket.create_connection((host, int(port)), timeout=timeout).close()
            v = int((time.time() - t0) * 1000)
            best = v if best is None else min(best, v)
        except Exception:
            return None
    return best


def start_kernel(q):
    import tempfile as tf, urllib.request as ur
    wd = tf.mkdtemp(prefix="p-")
    a, b = socket.socket(), socket.socket()
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    api, mix = a.getsockname()[1], b.getsockname()[1]
    a.close(); b.close()
    cfg = {"mixed-port": mix, "external-controller": "127.0.0.1:%d" % api,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = os.path.join(wd, "c.yaml")
    open(path, "w").write(json.dumps(cfg, ensure_ascii=False))
    p = subprocess.Popen([BIN, "-d", wd, "-f", path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        time.sleep(0.2)
        try:
            ur.urlopen("http://127.0.0.1:%d/version" % api, timeout=1).read()
            return p, mix
        except Exception:
            if p.poll() is not None:
                return p, None
    return p, None


def curl_ms(port, url, timeout=15):
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                        "-x", "http://127.0.0.1:%d" % port, "-w", "%{time_total}", url],
                       capture_output=True, text=True)
    v = float(r.stdout.strip() or 0)
    return int(v * 1000) if v > 0 else None


def curl_dl(port, timeout=25, bytes_=300000):
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                        "-x", "http://127.0.0.1:%d" % port,
                        "-w", "%{http_code} %{size_download} %{speed_download}",
                        DL], capture_output=True, text=True)
    parts = (r.stdout or "").split()
    if len(parts) < 3 or parts[0] != "200" or float(parts[1] or 0) < bytes_ * 0.9:
        return None
    kb = float(parts[2] or 0) / 1024.0
    return round(kb) if kb > 1 else None


def curl_ip(port, timeout=12):
    r = subprocess.run(["curl", "-s", "--max-time", str(timeout),
                        "-x", "http://127.0.0.1:%d" % port,
                        "http://ip-api.com/json/?fields=query,countryCode"],
                       capture_output=True, text=True)
    try:
        d = json.loads(r.stdout or "{}")
        return d.get("query"), (d.get("countryCode") or "").upper() or None
    except Exception:
        return None, None



def exit_cc(q, timeout=12):
    """通过节点查真实出口国家码；先 2 秒 TCP 探测"""
    if not tcp_ms(q["server"], q["port"]):
        return None
    p, port = start_kernel(q)
    if port is None:
        try:
            p.terminate()
        except Exception:
            pass
        return None
    try:
        _, cc = curl_ip(port, timeout)
        return cc
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def udp_via(port, timeout=8):
    import struct
    s = None
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return False
        s.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        rep = s.recv(32)
        if len(rep) < 10 or rep[1] != 0:
            return False
        relay = (socket.inet_ntoa(rep[4:8]) if rep[3] == 1 else "127.0.0.1",
                 struct.unpack(">H", rep[8:10])[0])
        if relay[0] == "0.0.0.0":
            relay = ("127.0.0.1", relay[1])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qn = b"".join(bytes([len(x)]) + x.encode() for x in "example.com".split(".")) + b"\x00"
        dns = header + qn + struct.pack(">HH", 1, 1)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack(">H", 53) + dns
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


def profile(q):
    out = {"tcp": None, "cf": None, "jit": None, "gg": None, "yt": None,
           "dl": None, "ip": None, "cc": None, "udp": False}
    out["tcp"] = tcp_ms(q["server"], q["port"])
    if not out["tcp"]:
        return out
    p, port = start_kernel(q)
    if port is None:
        try:
            p.terminate()
        except Exception:
            pass
        return out
    try:
        samples = [v for v in (curl_ms(port, CF) for _ in range(3)) if v]
        if samples:
            out["cf"] = min(samples)
            out["jit"] = max(samples) - min(samples) if len(samples) > 1 else 0
            out["gg"] = curl_ms(port, GOOGLE)
            out["yt"] = curl_ms(port, YT)
            best = None
            for _ in range(3):
                v = curl_dl(port)
                if v:
                    best = max(best or 0, v)
            out["dl"] = best
            out["ip"], out["cc"] = curl_ip(port)
            out["udp"] = udp_via(port)
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()
    return out


def region_rank(r):
    return (PREFER.index(r) if r in PREFER else 99, r)


def scheme_rank(u):
    if u.startswith("https://"):
        return 0
    if u.startswith("anytls://"):
        return 1
    if u.startswith("trojan://"):
        return 2
    if u.startswith("http://"):
        return 3
    return 4


def main():
    os.makedirs(OUT, exist_ok=True)

    # ① 抓源
    seen, uris = set(), []
    for p in SRC + discovered():
        if not is_fresh(p):
            continue
        n = 0
        for u in lines_of(fetch(p)):
            k = u.split("#")[0]
            if k in seen:
                continue
            seen.add(k)
            uris.append(u)
            n += 1
        log("  %-46s +%d" % (p.split("/")[-1][:44], n))
    log("抓取 %d 条" % len(uris))

    # ② 去重 + 筛类型
    allpool_uris, seen_all = [], set()
    for u in uris:
        nm = up.unquote(u.split("#")[-1]) if "#" in u else ""
        q = nodeconv.to_clash(u, nm)
        if not q:
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_all:
            continue
        seen_all.add(ep)
        allpool_uris.append((u, q))

    pool, seen_ep = [], set()
    for u in uris:
        nm = up.unquote(u.split("#")[-1]) if "#" in u else ""
        q = nodeconv.to_clash(u, nm)
        if not q or q.get("type") not in KEEP_TYPES:
            continue
        ep = (str(q["server"]).lower(), int(q["port"]))
        if ep in seen_ep:
            continue
        if q.get("type") == "trojan" and not asia_marker(q.get("name", ""), q.get("server", "")):
            continue          # trojan 只收名字/域名能看出是亚太的
        seen_ep.add(ep)
        pool.append((u, q))
    log("去重后目标类型 %d 条" % len(pool))

    # ③ 先查 IP 地区 + 取名（地区+后戳）
    from concurrent.futures import ThreadPoolExecutor as _TPE_R
    log("查 IP 地区…")
    with _TPE_R(max_workers=16) as _exr:
        _ccs = list(_exr.map(lambda uq: exit_cc(uq[1]), pool))
    named, cnt_pre = [], {}
    for (u, q), cc in zip(pool, _ccs):
        rn = geo.CC_NAME.get(cc, "其他") if cc else geo.CC_NAME.get(
            geo.guess_cc("%s %s" % (q.get("name", ""), q.get("server", ""))), "其他")
        cnt_pre[rn] = cnt_pre.get(rn, 0) + 1
        nm = NAME % (rn, cnt_pre[rn])
        named.append((u, dict(q, name=nm), rn, cc))
    pool = [(u, q) for u, q, _, _ in named]
    regs = [rn for _, _, rn, _ in named]
    log("取好名字 %d 条" % len(pool))

    # ④ 测试（一次内核测全部指标）
    from concurrent.futures import ThreadPoolExecutor
    log("开始测试，6 并发…")
    results = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for idx, r in zip(range(len(pool)), ex.map(lambda uq: profile(uq[1]), pool)):
            results[idx] = r
            log("  %3d/%d %-20s %-7s cf=%-6s dl=%-6s %s" % (
                idx + 1, len(pool), (pool[idx][1].get("name") or "")[:20],
                pool[idx][1].get("type"), r["cf"] or "-", r["dl"] or "-",
                "OK" if r["dl"] else "X"))

    # ④ 表格
    rows = []
    for i, (u, q) in enumerate(pool):
        r = results[i]
        rows.append({
            "uri": u, "q": q, "r": r, "cc": r["cc"] or "-", "region": regs[i],
            "ok": bool(r["dl"]),
        })

    hdr = ["名称", "协议", "地区", "出口IP", "UDP", "TCP(ms)", "CF(ms)",
           "Google(ms)", "YouTube(ms)", "抖动(ms)", "下载(KB/s)", "可用"]
    lines = ["\t".join(hdr)]
    for row in rows:
        q, r = row["q"], row["r"]
        lines.append("\t".join([
            q.get("name", "")[:40], q.get("type", "-"), row["region"],
            r["ip"] or "-", "UDP" if r["udp"] else "-",
            str(r["tcp"] or "-"), str(r["cf"] or "-"), str(r["gg"] or "-"),
            str(r["yt"] or "-"), str(r["jit"] if r["jit"] is not None else "-"),
            str(r["dl"] or "-"), "OK" if row["ok"] else "X"]))
    open(os.path.join(OUT, "probe.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    log("写入 probe.txt")

    # ⑤ 网页表格
    trs = []
    for row in rows:
        q, r = row["q"], row["r"]
        cls = "ok" if row["ok"] else "bad"
        trs.append(
            '<tr class="%s"><td class="nm">%s</td><td><span class="tag t-%s">%s</span></td>'
            '<td>%s</td><td class="mono">%s</td><td>%s</td>'
            '<td class="num">%s</td><td class="num">%s</td><td class="num">%s</td>'
            '<td class="num">%s</td><td class="num">%s</td><td class="num dl">%s</td>'
            '<td class="res">%s</td></tr>' % (
                cls, (q.get("name", "") or "")[:40].replace("<", ""),
                q.get("type", ""), q.get("type", ""), row["region"],
                r["ip"] or "-", "UDP" if r["udp"] else "-",
                r["tcp"] or "-", r["cf"] or "-", r["gg"] or "-", r["yt"] or "-",
                r["jit"] if r["jit"] is not None else "-",
                r["dl"] or "-", "✔" if row["ok"] else "✘"))
    okn = sum(1 for row in rows if row["ok"])
    html = open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    html = html.replace("@N@", str(len(rows))).replace("@OK@", str(okn)).replace("@ROWS@", "\n".join(trs))
    open(os.path.join(OUT, "report.html"), "w", encoding="utf-8").write(html)
    log("写入 report.html（%d 条，可用 %d）" % (len(rows), okn))

    # ⑥ 去 X → 命名 → 排序 → 订阅
    keeps = [row for row in rows if row["ok"]]
    keeps.sort(key=lambda x: (region_rank(x["region"]), x["q"].get("name", "")))
    out = []
    for row in keeps:
        out.append(fix_http_auth(row["uri"].split("#")[0]) + "#" +
                   row["q"]["name"].replace(" ", "%20"))
    if out:
        open(os.path.join(OUT, "0070077.xyz"), "w", encoding="utf-8").write(
            base64.b64encode("\n".join(out).encode()).decode())
    log("写入 0070077.xyz：%d 条" % len(out))

    open(os.path.join(OUT, "report.txt"), "w", encoding="utf-8").write(
        "更新 %s\n抓取 %d / 去重后 %d / 可用 %d / 输出 %d\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"), len(uris), len(pool), okn, len(out)))


if __name__ == "__main__":
    main()
