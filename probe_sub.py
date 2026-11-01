#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对 sub/0070077.xyz 里的节点逐个测速，保留下单中的原始顺序，输出 sub/probe.txt"""
import base64, json, os, socket, statistics, time
import nodeconv
import geo
import sub_build

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "mihomo")
CF = "http://cp.cloudflare.com/generate_204"
GOOGLE = "https://www.gstatic.com/generate_204"
YT = "https://i.ytimg.com/generate_204"


def tcp_ms(host, port, n=2, timeout=2.5):
    best = None
    for _ in range(n):
        t0 = time.time()
        try:
            socket.create_connection((host, int(port)), timeout=timeout).close()
            v = int((time.time() - t0) * 1000)
            best = v if best is None else min(best, v)
        except Exception:
            pass
    return best


def start_kernel(q):
    """起一个只含该节点的内核，返回 (进程, 代理端口, API端口)"""
    import subprocess as sp, tempfile as tf, urllib.request as ur
    wd = tf.mkdtemp(prefix="p-")
    a, b = socket.socket(), socket.socket()
    a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
    api_p, mix_p = a.getsockname()[1], b.getsockname()[1]
    a.close(); b.close()
    cfg = {"mixed-port": mix_p, "external-controller": "127.0.0.1:%d" % api_p,
           "log-level": "warning", "mode": "rule",
           "proxies": [dict(q, name="p")], "rules": ["MATCH,p"]}
    path = os.path.join(wd, "c.yaml")
    open(path, "w").write(json.dumps(cfg, ensure_ascii=False))
    p = sp.Popen([BIN, "-d", wd, "-f", path], stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    for _ in range(30):
        time.sleep(0.2)
        try:
            ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
            return p, mix_p
        except Exception:
            if p.poll() is not None:
                return p, None
    return p, None


def curl_ms(proxy, url, timeout=15):
    import subprocess as sp
    r = sp.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                "-x", "http://127.0.0.1:%d" % proxy, "-w", "%{time_total}", url],
               capture_output=True, text=True)
    v = float(r.stdout.strip() or 0)
    return int(v * 1000) if v > 0 else None


def curl_dl(proxy, timeout=25, bytes_=300000):
    import subprocess as sp
    r = sp.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                "-x", "http://127.0.0.1:%d" % proxy,
                "-w", "%{http_code} %{size_download} %{speed_download}",
                "https://speed.cloudflare.com/__down?bytes=%d" % bytes_],
               capture_output=True, text=True)
    parts = (r.stdout or "").split()
    if len(parts) < 3 or parts[0] != "200" or float(parts[1] or 0) < bytes_ * 0.9:
        return None
    kb = float(parts[2] or 0) / 1024.0
    return round(kb) if kb > 1 else None


def curl_ip(proxy, timeout=12):
    import subprocess as sp
    r = sp.run(["curl", "-s", "--max-time", str(timeout),
                "-x", "http://127.0.0.1:%d" % proxy,
                "http://ip-api.com/json/?fields=query,countryCode"],
               capture_output=True, text=True)
    try:
        d = json.loads(r.stdout or "{}")
        return d.get("query"), (d.get("countryCode") or "").upper() or None
    except Exception:
        return None, None


def udp_via(proxy, timeout=8):
    """复用同一个代理端口做 SOCKS5 UDP 测试"""
    import struct
    s = None
    try:
        s = socket.create_connection(("127.0.0.1", proxy), timeout=timeout)
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
        tid = 0x1234
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
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
    """一次内核，测完全部指标"""
    tcp = tcp_ms(q["server"], q["port"])
    out = {"tcp": tcp, "cf": None, "jit": None, "gg": None, "yt": None,
           "dl": None, "ip": None, "cc": None, "udp": False}
    if not tcp:
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


def test_one(item):
    idx, u = item
    name = u.split("#")[-1].replace("%20", " ") if "#" in u else ""
    q = nodeconv.to_clash(u, name)
    if not q:
        return idx, [name, "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "X"]
    r = profile(q)
    cc = r["cc"] or geo.guess_cc(name) or "-"
    return idx, [name, q.get("type", "-"), cc, r["ip"] or "-",
                 "UDP" if r["udp"] else "-",
                 str(r["tcp"]) if r["tcp"] else "-",
                 str(r["cf"]) if r["cf"] else "-",
                 str(r["gg"]) if r["gg"] else "-",
                 str(r["yt"]) if r["yt"] else "-",
                 str(r["jit"]) if r["jit"] is not None else "-",
                 str(r["dl"]) if r["dl"] else "-",
                 "OK" if r["dl"] else "X"]


def main():
    uris = []
    for fn in ("0070077.xyz", "asia.xyz"):
        p = os.path.join(HERE, "sub", fn)
        if not os.path.exists(p):
            continue
        try:
            raw = base64.b64decode(open(p, "rb").read()).decode()
        except Exception:
            continue
        for l in raw.splitlines():
            l = l.strip()
            if l and l not in uris:
                uris.append(l)
    print("共 %d 条，并行测试（保持原顺序）" % len(uris), flush=True)
    from concurrent.futures import ThreadPoolExecutor
    res = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        for idx, row in ex.map(test_one, list(enumerate(uris))):
            res[idx] = row
            print("%3d/%d %-20s %-7s %-3s cf=%-6s dl=%-6s %s" % (
                idx + 1, len(uris), row[0][:20], row[1], row[2],
                row[6], row[10], row[11]), flush=True)
    rows = [res[i] for i in range(len(uris))]
    hdr = ["名称", "协议", "地区", "出口IP", "UDP", "TCP(ms)", "CF(ms)", "Google(ms)", "YouTube(ms)", "抖动(ms)", "下载(KB/s)", "可用"]
    out = ["\t".join(hdr)] + ["\t".join(map(str, r)) for r in rows]
    open(os.path.join(HERE, "sub", "probe.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")

    write_html(rows)

    # 回写两份订阅：只保留 OK 的（X 的全部剔除）
    keep_set = {u for u, r in zip(uris, rows) if r[11] == "OK"}
    for fn in ("0070077.xyz", "asia.xyz"):
        p = os.path.join(HERE, "sub", fn)
        if not os.path.exists(p):
            continue
        try:
            raw = base64.b64decode(open(p, "rb").read()).decode()
        except Exception:
            continue
        old = [l.strip() for l in raw.splitlines() if l.strip()]
        new = [l for l in old if l in keep_set]
        open(p, "w", encoding="utf-8").write(base64.b64encode("\n".join(new).encode()).decode())
        print("回写 %s：%d → %d 条（剔除 X）" % (fn, len(old), len(new)), flush=True)

def write_html(rows):
    # 网页版表格
    trs = []
    for r in rows:
        name, proto, region, ip, udp, tcp, cf, gg, yt, jit, dl, ok = r
        cls = "ok" if ok == "OK" else "bad"
        trs.append(
            '<tr class="' + cls + '"><td class="nm">' + name.replace(" 0070077.xyz", "") + '</td>'
            '<td><span class="tag t-' + proto + '">' + proto + '</span></td>'
            '<td>' + region + '</td><td class="mono">' + str(ip) + '</td>'
            '<td class="num">' + str(udp) + '</td><td class="num">' + str(tcp) + '</td><td class="num">' + str(cf) + '</td>'
            '<td class="num">' + str(gg) + '</td><td class="num">' + str(yt) + '</td>'
            '<td class="num">' + str(jit) + '</td><td class="num dl">' + str(dl) + '</td>'
            '<td class="res">' + ("✔" if ok == "OK" else "✘") + '</td></tr>')

    okn = sum(1 for r in rows if r[11] == "OK")
    html = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>节点测速表</title>
<style>
*{box-sizing:border-box}
body{margin:0;padding:28px 20px 60px;background:#0d1016;color:#e8ebf0;
 font:14px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
h1{font-size:20px;margin:0 0 6px;font-weight:600}
.meta{color:#7c8698;font-size:13px;margin-bottom:20px}
.meta b{color:#4ade80}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px;
 background:#12161f;border-radius:10px;overflow:hidden}
th{position:sticky;top:0;background:#1a2030;color:#94a3b8;font-weight:500;
 padding:11px 12px;text-align:left;cursor:pointer;user-select:none;white-space:nowrap;
 border-bottom:1px solid #222a3a}
th:hover{color:#e2e8f0}
td{padding:9px 12px;border-bottom:1px solid #1b2230;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr:hover td{background:#161d2b}
.nm{font-weight:500}
.mono{font-family:ui-monospace,Menlo,monospace;color:#94a3b8;font-size:12px}
.num{text-align:right;font-variant-numeric:tabular-nums;color:#cbd5e1}
.dl{color:#60a5fa;font-weight:600}
tr.bad td{opacity:.42}
tr.bad .res{color:#f87171;opacity:1}
tr.ok .res{color:#4ade80}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;background:#243044;color:#93b4d8}
.t-https{background:#1e3a5f;color:#7cc4ff}
.t-anytls{background:#3b2a52;color:#c4a5ff}
.t-http{background:#3d2d1a;color:#ffc078}
</style></head><body>
<h1>节点测速表</h1>
<div class="meta">共 @N@ 条 · 可用 <b>@OK@</b> 条 · 顺序与订阅一致 · 点击表头排序</div>
<table id="t"><thead><tr>
<th>名称</th><th>协议</th><th>地区</th><th>出口IP</th><th>UDP</th>
<th>TCP(ms)</th><th>CF(ms)</th><th>Google(ms)</th><th>YouTube(ms)</th><th>抖动(ms)</th><th>下载(KB/s)</th><th>可用</th>
</tr></thead><tbody>@ROWS@</tbody></table>
<script>
document.querySelectorAll('#t th').forEach(function(th,i){
 th.onclick=function(){
  var tb=document.querySelector('#t tbody');
  var rs=Array.prototype.slice.call(tb.rows);
  var asc=th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
  rs.sort(function(a,b){
   var x=a.cells[i].innerText.trim(), y=b.cells[i].innerText.trim();
   var nx=parseFloat(x), ny=parseFloat(y);
   if(!isNaN(nx)&&!isNaN(ny)) return asc?nx-ny:ny-nx;
   return asc?x.localeCompare(y):y.localeCompare(x);
  });
  rs.forEach(function(r){tb.appendChild(r)});
 };
});
</script></body></html>"""
    html = html.replace("@N@", str(len(rows))).replace("@OK@", str(okn)).replace("@ROWS@", "\n".join(trs))
    out = os.path.join(HERE, "sub", "report.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w", encoding="utf-8").write(html)
    print("写入 sub/report.html", flush=True)
    ok = sum(1 for r in rows if r[11] == "OK")
    print("完成：%d 条，可用 %d 条" % (len(rows), ok), flush=True)


if __name__ == "__main__":
    main()
# trigger 1793498939
