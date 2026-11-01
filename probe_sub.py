#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对 sub/ivapp.cn 里的节点逐个测速，保留下单中的原始顺序，输出 sub/probe.txt"""
import base64, json, os, socket, statistics, time
import nodeconv
import geo

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "mihomo")
CF = "http://cp.cloudflare.com/generate_204"


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


def via_node(q, url, timeout=15):
    """起单节点内核，curl 走代理访问 url，返回毫秒或 None"""
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
    try:
        for _ in range(30):
            time.sleep(0.2)
            try:
                ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None
        r = sp.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                    "-x", "http://127.0.0.1:%d" % mix_p,
                    "-w", "%{time_total}", url], capture_output=True, text=True)
        v = float(r.stdout.strip() or 0)
        return int(v * 1000) if v > 0 else None
    except Exception:
        return None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def download_kbps(q, bytes_=300000, timeout=25):
    import subprocess as sp, tempfile as tf, urllib.request as ur
    wd = tf.mkdtemp(prefix="d-")
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
    try:
        for _ in range(30):
            time.sleep(0.2)
            try:
                ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None
        r = sp.run(["curl", "-s", "-o", "/dev/null", "--max-time", str(timeout),
                    "-x", "http://127.0.0.1:%d" % mix_p,
                    "-w", "%{speed_download}",
                    "https://speed.cloudflare.com/__down?bytes=%d" % bytes_],
                   capture_output=True, text=True)
        v = float(r.stdout.strip() or 0) / 1024.0
        return round(v) if v > 1 else None
    except Exception:
        return None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def exit_country(q, timeout=12):
    import subprocess as sp, tempfile as tf, urllib.request as ur
    wd = tf.mkdtemp(prefix="g-")
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
    try:
        for _ in range(30):
            time.sleep(0.2)
            try:
                ur.urlopen("http://127.0.0.1:%d/version" % api_p, timeout=1).read()
                break
            except Exception:
                if p.poll() is not None:
                    return None, None
        r = sp.run(["curl", "-s", "--max-time", str(timeout),
                    "-x", "http://127.0.0.1:%d" % mix_p,
                    "http://ip-api.com/json/?fields=query,countryCode"],
                   capture_output=True, text=True)
        d = json.loads(r.stdout or "{}")
        return d.get("query"), (d.get("countryCode") or "").upper() or None
    except Exception:
        return None, None
    finally:
        p.terminate()
        try:
            p.wait(3)
        except Exception:
            p.kill()


def test_one(item):
    idx, u = item
    name = u.split("#")[-1].replace("%20", " ") if "#" in u else ""
    q = nodeconv.to_clash(u, name)
    if not q:
        return idx, [name, "-", "-", "-", "-", "-", "-", "-"]
    tcp = tcp_ms(q["server"], q["port"])
    cf = via_node(q, CF) if tcp else None
    dl = download_kbps(q) if cf else None
    ip, cc = exit_country(q) if tcp else (None, None)
    cc = cc or geo.guess_cc(name) or "-"
    return idx, [name, q.get("type", "-"), cc, ip or "-",
                 str(tcp) if tcp else "-", str(cf) if cf else "-",
                 str(dl) if dl else "-", "OK" if dl else "X"]


def main():
    uris = []
    for fn in ("ivapp.cn", "ivapp2.cn"):
        p = os.path.join(HERE, "sub", fn)
        if not os.path.exists(p):
            continue
        try:
            raw = base64.b64decode(open(p, "rb").read()).decode()
        except Exception:
            continue
        uris += [l.strip() for l in raw.splitlines() if l.strip()]
    print("共 %d 条，并行测试（保持原顺序）" % len(uris), flush=True)
    from concurrent.futures import ThreadPoolExecutor
    res = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for idx, row in ex.map(test_one, list(enumerate(uris))):
            res[idx] = row
            print("%3d/%d %-22s %-8s %s tcp=%s cf=%s dl=%s" % (
                idx + 1, len(uris), row[0][:22], row[1], row[2], row[4], row[5], row[6]), flush=True)
    rows = [res[i] for i in range(len(uris))]
    hdr = ["名称", "协议", "地区", "出口IP", "TCP(ms)", "CF(ms)", "下载(KB/s)", "可用"]
    out = ["\t".join(hdr)] + ["\t".join(map(str, r)) for r in rows]
    open(os.path.join(HERE, "sub", "probe.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    ok = sum(1 for r in rows if r[7] == "OK")
    print("完成：%d 条，可用 %d 条" % (len(rows), ok), flush=True)


if __name__ == "__main__":
    main()
# trigger 1793498939
