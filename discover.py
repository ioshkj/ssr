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
    # 针对 http / anytls / trojan 这类少而精的节点
    "anytls", "anytls+sub", "anytls+nodes", "anytls+subscription",
    "trojan+subscription", "trojan+nodes", "trojan+clash",
    "http+proxy+list", "https+proxy+nodes", "http+proxy+sub",
]
COMMON = ["sub", "sub.txt", "sub.yaml", "base64.txt", "clash.yaml", "all.yaml",
          "nodes.txt", "list.yml", "list.txt", "output/clash.yaml"]


BLOCKED = ("TheCrowCreature/v2rayExtractor",)



NODE_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                "hysteria2://", "hy2://", "tuic://", "anytls://",
                "http://", "https://", "socks5://")


def looks_like_nodes(raw, min_nodes=3):
    """内容是不是真的节点订阅：base64 里或明文里含至少 N 条代理链接"""
    if not raw or len(raw) < 80:
        return False
    text = raw.decode("utf-8", "ignore")
    if "proxies:" in text:          # clash 配置
        return text.count("- name") >= min_nodes or text.count("server:") >= min_nodes
    if "://" in text:
        n = sum(1 for line in text.splitlines() if line.strip().startswith(NODE_SCHEMES))
        return n >= min_nodes
    try:
        import base64 as _b64
        dec = _b64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
        n = sum(1 for line in dec.splitlines() if line.strip().startswith(NODE_SCHEMES))
        return n >= min_nodes
    except Exception:
        return False


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
    since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=30))
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

    # 读旧的源清单（累积）
    old = []
    if os.path.exists(OUT):
        try:
            old = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            old = []
    oldmap = {"%s|%s" % (x["repo"], x["path"]): x for x in old}
    now = time.time()

    if not repos:
        # 搜索接口整体失败：不要动现有清单，避免把源清空
        try:
            old_n = len(json.load(open(OUT, encoding="utf-8")))
        except Exception:
            old_n = 0
        log("搜索接口无返回，保留原有 %d 个源" % old_n)
        return

    found = []
    for repo, meta in sorted(repos.items(), key=lambda kv: -kv[1]["stars"])[:120]:
        if repo in BLOCKED:
            continue
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
            if not looks_like_nodes(b):
                continue
            if len(b) > 400 and b"<html" not in b[:200].lower():
                found.append({"repo": repo, "branch": branch, "path": p,
                              "kind": "clash" if p.lower().endswith((".yaml", ".yml")) else "uri",
                              "pushed": meta["pushed"], "stars": meta["stars"],
                              "last_ok": now, "fails": 0})
                break
    if not found:
        found = []
    # 合并：本轮命中的更新，未命中的记失败，失败 3 次淘汰
    merged = {}
    for x in found:
        merged["%s|%s" % (x["repo"], x["path"])] = x
    for k, x in oldmap.items():
        if k in merged:
            continue
        x = dict(x)
        x["fails"] = x.get("fails", 0) + 1
        if x["fails"] >= 3:
            continue
        merged[k] = x
    # 独立的新鲜度检测：超过 30 小时没更新的源直接丢弃
    import datetime as _dt
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=30)
    keep, dropped = [], 0
    for x in merged.values():
        try:
            t = _dt.datetime.fromisoformat(x["pushed"].replace("Z", "+00:00"))
        except Exception:
            keep.append(x)
            continue
        if t >= cutoff:
            keep.append(x)
        else:
            dropped += 1
    log("新鲜度检测：丢弃 %d 个超过 30 小时未更新的源" % dropped)
    # 备份一份，防止意外清空
    try:
        import shutil as _sh
        if os.path.exists(OUT):
            _sh.copy(OUT, os.path.join(HERE, "sources.backup.json"))
    except Exception:
        pass

    if not keep and not found:
        # 本轮什么都没找到：保留旧清单，避免把历史积累清空
        try:
            old_list = json.load(open(OUT, encoding="utf-8"))
        except Exception:
            old_list = []
        if old_list:
            log("本轮未发现新源，保留原有 %d 个" % len(old_list))
            return
    final = keep
    json.dump(final, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    log("本轮命中 %d，累积保留 %d 个订阅源" % (len(found), len(final)))


if __name__ == "__main__":
    main()
