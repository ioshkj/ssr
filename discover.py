#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""扫描 GitHub 上最近更新过的订阅仓库，探测可用订阅文件，写入 sources.json"""
import datetime, json, os, re, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "sources.json")
RAW = "https://raw.githubusercontent.com/"
UA = {"User-Agent": "curl/8"}
TOKEN = os.environ.get("GITHUB_TOKEN", "")

QUERIES = [
    "v2ray+free+nodes", "clash+subscription", "free+proxy+subscription",
    "v2ray+subscription", "free+nodes+vless", "clash+free+nodes",
    "proxy+sub+clash", "免费节点", "机场订阅", "free+vless+nodes",
    "vmess+free+sub", "trojan+free+sub", "clash+yaml+proxy", "代理+订阅",
    "v2ray+configs", "shadowrocket+sub", "singbox+subscription", "proxy+pool",
]
COMMON = ["sub", "sub.txt", "sub.yaml", "base64.txt", "clash.yaml", "all.yaml",
          "nodes.txt", "list.yml", "list.txt", "output/clash.yaml"]


def log(m):
    print(m, flush=True)


def api(url):
    h = {**UA, "Accept": "application/vnd.github+json"}
    if TOKEN:
        h["Authorization"] = "Bearer " + TOKEN
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        log("  api 失败 %s" % repr(e)[:60])
        return None


def fetch(url, timeout=12):
    try:
        r = subprocess.run(["curl", "-sL", "-m", str(timeout), url], capture_output=True)
        return r.stdout
    except Exception:
        return b""


def main():
    since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=36))
    q_since = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    repos = {}
    for q in QUERIES:
        d = api("https://api.github.com/search/repositories?q=%s+pushed:>=%s"
                "&sort=stars&order=desc&per_page=50" % (q, q_since))
        if d and d.get("items"):
            for it in d["items"]:
                repos[it["full_name"]] = {"stars": it["stargazers_count"],
                                          "pushed": it["pushed_at"],
                                          "branch": it["default_branch"]}
        log("  %-26s 累计 %d" % (q, len(repos)))
        time.sleep(6.5)

    found = []
    for repo, meta in sorted(repos.items(), key=lambda kv: -kv[1]["stars"])[:120]:
        branch = meta["branch"]
        paths = []
        body = fetch(RAW + "%s/%s/README.md" % (repo, branch))
        if len(body) > 300:
            for m in re.findall(r"https://raw\.githubusercontent\.com/[^\s)\"'`<>]+",
                                body.decode("utf-8", "ignore")):
                if m.lower().startswith((RAW + repo).lower()):
                    p = m[len(RAW) + len(repo) + 1:]
                    p = re.sub(r"^refs/heads/", "", p)
                    if p.split("/")[0] in (branch, "main", "master"):
                        p = "/".join(p.split("/")[1:])
                    if p:
                        paths.append(p)
        for p in (paths or COMMON)[:5]:
            b = fetch(RAW + "%s/%s/%s" % (repo, branch, p))
            if len(b) > 400 and b"<html" not in b[:200].lower():
                found.append({"repo": repo, "branch": branch, "path": p,
                              "kind": "clash" if p.lower().endswith((".yaml", ".yml")) else "uri",
                              "pushed": meta["pushed"], "stars": meta["stars"]})
                break
    if not found:
        found = []
    json.dump(found, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    log("共 %d 个订阅源 -> sources.json" % len(found))


if __name__ == "__main__":
    main()
