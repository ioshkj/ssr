#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 vmess/vless/trojan/ss/hysteria2/tuic 分享链接转成 mihomo/clash 的 proxy 字典"""
import base64, json, re
import urllib.parse as up


def _b64(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def _q(u):
    q = up.urlparse(u)
    return dict(up.parse_qsl(q.query)), q


def _truthy(v):
    return str(v).lower() in ("1", "true", "tls", "reality")


def vmess(uri, name):
    j = json.loads(_b64(uri[8:].split("#")[0]))
    d = {"name": name, "type": "vmess", "server": str(j.get("add", "")).strip(),
         "port": int(j.get("port") or 0), "uuid": j.get("id", ""),
         "alterId": int(j.get("aid") or 0), "cipher": j.get("scy") or "auto", "udp": True}
    net = (j.get("net") or "tcp").lower()
    tls = _truthy(j.get("tls"))
    if tls:
        d["tls"] = True
        d["servername"] = j.get("sni") or j.get("host") or ""
    if net == "ws":
        d["network"] = "ws"
        d["ws-opts"] = {"path": j.get("path") or "/",
                        "headers": {"Host": j.get("host") or d.get("servername") or ""}}
    elif net == "grpc":
        d["network"] = "grpc"
        d["grpc-opts"] = {"grpc-service-name": j.get("path") or ""}
    elif net in ("h2", "http"):
        d["network"] = "h2"
        d["h2-opts"] = {"path": [j.get("path") or "/"], "host": [j.get("host") or ""]}
    d["skip-cert-verify"] = True
    return d


def vless(uri, name):
    p, q = _q(uri)
    m = re.match(r"^vless://([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)", uri)
    if not m:
        return None
    uuid, host, port = m.group(1), m.group(2).strip("[]"), int(m.group(3))
    net = (p.get("type") or "tcp").lower()
    sec = (p.get("security") or "").lower()
    d = {"name": name, "type": "vless", "server": host, "port": port, "uuid": uuid,
         "udp": True, "skip-cert-verify": True, "client-fingerprint": p.get("fp") or "chrome"}
    if sec in ("tls", "reality"):
        d["tls"] = True
        d["servername"] = p.get("sni") or p.get("host") or host
    if sec == "reality":
        d["reality-opts"] = {"public-key": p.get("pbk", ""), "short-id": p.get("sid", "")}
    if p.get("flow"):
        d["flow"] = p["flow"]
    if net == "ws":
        d["network"] = "ws"
        d["ws-opts"] = {"path": up.unquote(p.get("path") or "/"),
                        "headers": {"Host": p.get("host") or d.get("servername") or ""}}
    elif net == "grpc":
        d["network"] = "grpc"
        d["grpc-opts"] = {"grpc-service-name": p.get("serviceName") or p.get("path") or ""}
    elif net in ("h2", "http"):
        d["network"] = "h2"
        d["h2-opts"] = {"path": [up.unquote(p.get("path") or "/")], "host": [p.get("host") or ""]}
    return d


def trojan(uri, name):
    p, _ = _q(uri)
    m = re.match(r"^trojan://([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)", uri)
    if not m:
        return None
    d = {"name": name, "type": "trojan", "server": m.group(2).strip("[]"),
         "port": int(m.group(3)), "password": up.unquote(m.group(1)),
         "udp": True, "skip-cert-verify": True,
         "sni": p.get("sni") or p.get("peer") or m.group(2).strip("[]")}
    net = (p.get("type") or "tcp").lower()
    if net == "ws":
        d["network"] = "ws"
        d["ws-opts"] = {"path": up.unquote(p.get("path") or "/"),
                        "headers": {"Host": p.get("host") or d["sni"]}}
    elif net == "grpc":
        d["network"] = "grpc"
        d["grpc-opts"] = {"grpc-service-name": p.get("serviceName") or ""}
    return d


def ss(uri, name):
    body = uri[5:]
    body = body.split("#")[0]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            dec = _b64(userinfo) if ":" not in userinfo else up.unquote(userinfo)
        except Exception:
            dec = up.unquote(userinfo)
        if ":" not in dec:
            return None
        method, pwd = dec.split(":", 1)
    else:
        dec = _b64(body)
        m = re.match(r"(.+?):(.+)@(\[[^\]]+\]|[^:/]+):(\d+)$", dec)
        if not m:
            return None
        method, pwd, hostport = m.group(1), m.group(2), f"{m.group(3)}:{m.group(4)}"
        hostport = hostport.replace("[[", "[").replace("]]", "]")
    m = re.match(r"(\[[^\]]+\]|[^:/]+):(\d+)$", hostport)
    if not m:
        return None
    return {"name": name, "type": "ss", "server": m.group(1).strip("[]"),
            "port": int(m.group(2)), "cipher": method, "password": pwd, "udp": True}


def hysteria2(uri, name):
    p, _ = _q(uri)
    m = re.match(r"^hy(?:steria)?2://(?:([^@]+)@)?(\[[^\]]+\]|[^:/?#]+):(\d+)", uri)
    if not m:
        return None
    return {"name": name, "type": "hysteria2", "server": m.group(2).strip("[]"),
            "port": int(m.group(3)), "password": up.unquote(m.group(1) or ""),
            "sni": p.get("sni") or "", "skip-cert-verify": str(p.get("insecure", "1")) != "0"}


def tuic(uri, name):
    p, _ = _q(uri)
    m = re.match(r"^tuic://([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)", uri)
    if not m:
        return None
    cred = up.unquote(m.group(1))
    uid, _, pwd = cred.partition(":")
    return {"name": name, "type": "tuic", "server": m.group(2).strip("[]"),
            "port": int(m.group(3)), "uuid": uid, "password": pwd,
            "sni": p.get("sni") or "", "skip-cert-verify": True,
            "alpn": ["h3"], "udp-relay-mode": "native"}



def http_proxy(uri, name):
    p = up.urlparse(uri)
    if not p.hostname:
        return None
    d = {"name": name, "type": "http", "server": p.hostname,
         "port": int(p.port or (443 if p.scheme == "https" else 80)),
         "skip-cert-verify": True}
    if p.scheme == "https":
        d["tls"] = True
    if p.username:
        d["username"] = up.unquote(p.username)
        d["password"] = up.unquote(p.password or "")
    return d


def socks5(uri, name):
    p = up.urlparse(uri)
    if not p.hostname or not p.port:
        return None
    d = {"name": name, "type": "socks5", "server": p.hostname, "port": int(p.port),
         "udp": True, "skip-cert-verify": True}
    if p.username:
        d["username"] = up.unquote(p.username)
        d["password"] = up.unquote(p.password or "")
    return d


def anytls(uri, name):
    p, _ = _q(uri)
    m = re.match(r"^anytls://([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)", uri)
    if not m:
        return None
    d = {"name": name, "type": "anytls", "server": m.group(2).strip("[]"),
         "port": int(m.group(3)), "password": up.unquote(m.group(1)),
         "skip-cert-verify": str(p.get("insecure", "1")) != "0"}
    if p.get("sni"):
        d["sni"] = p["sni"]
    if p.get("alpn"):
        d["alpn"] = [x for x in p["alpn"].split(",") if x]
    if p.get("fp"):
        d["client-fingerprint"] = p["fp"]
    return d


def to_clash(uri, name):
    try:
        low = uri.lower()
        if low.startswith("vmess://"):
            d = vmess(uri, name)
        elif low.startswith("vless://"):
            d = vless(uri, name)
        elif low.startswith("trojan://"):
            d = trojan(uri, name)
        elif low.startswith("ss://"):
            d = ss(uri, name)
        elif low.startswith(("hysteria2://", "hy2://")):
            d = hysteria2(uri, name)
        elif low.startswith("tuic://"):
            d = tuic(uri, name)
        elif low.startswith("anytls://"):
            d = anytls(uri, name)
        elif low.startswith("socks5://"):
            d = socks5(uri, name)
        elif low.startswith(("http://", "https://")):
            d = http_proxy(uri, name)
        else:
            return None
    except Exception:
        return None
    if not d or not d.get("server") or not d.get("port"):
        return None
    return d


def _q_str(d):
    return "&".join("%s=%s" % (k, up.quote(str(v), safe="")) for k, v in d.items() if v not in (None, "", False))


def to_uri(p):
    """clash proxy dict -> 通用分享链接（用于生成通用订阅）"""
    try:
        t = p.get("type")
        name = up.quote(str(p.get("name", "")), safe="")
        srv, port = p["server"], int(p["port"])
        host = ("[%s]" % srv) if ":" in str(srv) and not str(srv).startswith("[") else srv
        net = p.get("network") or "tcp"
        ws = p.get("ws-opts") or {}
        wsh = (ws.get("headers") or {}).get("Host") or ""
        wsp = ws.get("path") or ""
        grpc = (p.get("grpc-opts") or {}).get("grpc-service-name", "")

        if t == "vmess":
            j = {"v": "2", "ps": p.get("name", ""), "add": srv, "port": str(port),
                 "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                 "scy": p.get("cipher", "auto"), "net": net, "type": "none",
                 "host": wsh, "path": wsp, "tls": "tls" if p.get("tls") else "",
                 "sni": p.get("servername") or p.get("sni") or ""}
            return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()

        if t == "vless":
            q = {"encryption": "none", "security": "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none"),
                 "type": net, "sni": p.get("servername") or p.get("sni") or "", "host": wsh,
                 "path": wsp, "fp": p.get("client-fingerprint", ""), "flow": p.get("flow", "")}
            if p.get("reality-opts"):
                q["pbk"] = p["reality-opts"].get("public-key", "")
                q["sid"] = p["reality-opts"].get("short-id", "")
            if net == "grpc":
                q["serviceName"] = grpc
            return "vless://%s@%s:%d?%s#%s" % (p.get("uuid", ""), host, port, _q_str(q), name)

        if t == "trojan":
            q = {"security": "tls", "type": net, "sni": p.get("sni") or p.get("servername") or "",
                 "host": wsh, "path": wsp}
            return "trojan://%s@%s:%d?%s#%s" % (up.quote(str(p.get("password", "")), safe=""),
                                                host, port, _q_str(q), name)

        if t == "ss":
            userinfo = base64.b64encode(("%s:%s" % (p.get("cipher", ""), p.get("password", ""))).encode()).decode().rstrip("=")
            return "ss://%s@%s:%d#%s" % (userinfo, host, port, name)

        if t == "anytls":
            q = {"sni": p.get("sni", ""), "insecure": "1" if p.get("skip-cert-verify") else "0"}
            return "anytls://%s@%s:%d?%s#%s" % (up.quote(str(p.get("password", "")), safe=""), host, port, _q_str(q), name)

        if t == "hysteria2":
            q = {"sni": p.get("sni", ""), "insecure": "1" if p.get("skip-cert-verify") else "0"}
            return "hysteria2://%s@%s:%d?%s#%s" % (up.quote(str(p.get("password", "")), safe=""), host, port, _q_str(q), name)

        if t == "tuic":
            q = {"sni": p.get("sni", ""), "alpn": "h3", "congestion_control": "bbr"}
            return "tuic://%s:%s@%s:%d?%s#%s" % (p.get("uuid", ""), up.quote(str(p.get("password", "")), safe=""),
                                                 host, port, _q_str(q), name)

        if t in ("http", "https"):
            scheme = "https" if p.get("tls") else "http"
            auth = ""
            if p.get("username"):
                auth = "%s:%s@" % (up.quote(p["username"], safe=""), up.quote(p.get("password", ""), safe=""))
            return "%s://%s%s:%d#%s" % (scheme, auth, host, port, name)

        if t == "socks5":
            auth = ""
            if p.get("username"):
                auth = "%s:%s@" % (up.quote(p["username"], safe=""), up.quote(p.get("password", ""), safe=""))
            return "socks5://%s%s:%d#%s" % (auth, host, port, name)
    except Exception:
        return None
    return None
