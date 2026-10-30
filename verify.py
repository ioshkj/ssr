#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 mihomo 内核做真实代理验证：通过本地内核请求指定 URL，成功返回 2xx/204 才算可用。"""
import json, os, socket, subprocess, tempfile, time, urllib.parse as up, urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bin", "mihomo")
URL_GOOGLE = "https://www.gstatic.com/generate_204"
URL_YOUTUBE = "https://i.ytimg.com/generate_204"
URL_HTTP = "http://cp.cloudflare.com/generate_204"
URL_SPEED = "https://speed.cloudflare.com/__down?bytes=1000000"
CHUNK = 1200


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Core:
    def __init__(self):
        self.api = None
        self.proc = None
        self.wd = None

    def start(self, proxies):
        self.api = "127.0.0.1:%d" % free_port()
        mixed = free_port()
        self.wd = tempfile.mkdtemp(prefix="mihomo-")
        cfg = {"mixed-port": mixed, "external-controller": self.api,
               "log-level": "warning", "mode": "direct",
               "proxies": proxies, "rules": ["MATCH,DIRECT"]}
        path = os.path.join(self.wd, "config.yaml")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False)
        self.log = open(os.path.join(self.wd, "core.log"), "w")
        self.proc = subprocess.Popen([BIN, "-d", self.wd, "-f", path],
                                     stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(160):
            time.sleep(0.2)
            try:
                urllib.request.urlopen("http://%s/version" % self.api, timeout=1).read()
                return True
            except Exception:
                if self.proc.poll() is not None:
                    return False
        return False

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        try:
            self.log.close()
        except Exception:
            pass

    def delay(self, name, url, timeout):
        u = "http://%s/proxies/%s/delay?timeout=%d&url=%s" % (
            self.api, up.quote(name, safe=""), timeout, up.quote(url, safe=""))
        try:
            with urllib.request.urlopen(u, timeout=timeout / 1000 + 4) as r:
                d = json.loads(r.read().decode()).get("delay")
            return d if isinstance(d, int) and d > 0 else None
        except Exception:
            return None


def _run_deep(part, workers, timeout, url, out):
    r = _run(part, workers, timeout, url)
    if r is not None:
        out.extend(r)
        return
    if len(part) <= 1:
        return
    mid = len(part) // 2
    _run_deep(part[:mid], workers, timeout, url, out)
    _run_deep(part[mid:], workers, timeout, url, out)


def _run(part, workers, timeout, url):
    core = Core()
    if not core.start(part):
        core.stop()
        return None
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            res = list(ex.map(lambda p: core.delay(p["name"], url, timeout), part))
        return [(p, d) for p, d in zip(part, res) if d]
    finally:
        core.stop()


def verify(proxies, workers=128, timeout=5000, url=URL_GOOGLE, chunk=CHUNK, log=print):
    for i, p in enumerate(proxies):
        p["name"] = "n%05d" % i
    out = []
    for s in range(0, len(proxies), chunk):
        part = proxies[s:s + chunk]
        r = None
        if True:
            tmp = []
            _run_deep(part, workers, timeout, url, tmp)
            r = tmp
        if r is None:
            half = len(part) // 2
            log("    批次 %d-%d 启动失败，拆分重试" % (s, s + len(part)))
            for sub in (part[:half], part[half:]):
                if sub:
                    r2 = _run(sub, workers, timeout, url)
                    if r2:
                        out += r2
        else:
            out += r
        log("    进度 %d/%d，累计可用 %d" % (min(s + chunk, len(proxies)), len(proxies), len(out)))
    out.sort(key=lambda x: x[1])
    return out
