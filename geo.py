#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""节点地区判定：先看名字里的国旗/国名，再按 IP 反查国家码"""
import ipaddress, json, re, socket, urllib.request
from concurrent.futures import ThreadPoolExecutor

CCS = ["US","JP","HK","TW","SG","KR","DE","FR","GB","NL","CA","AU","RU","IN","TR","IR",
       "VN","TH","MY","ID","PH","BR","AR","UA","PL","SE","CH","FI","NO","DK","IE","IT",
       "ES","AT","CZ","RO","MD","LT","LV","EE","BG","RS","GR","IL","AE","SA","ZA","EG",
       "MX","CL","CO","PE","NZ","BE","PT","HU","SK","SI","HR","IS","LU","MT","CY","KZ",
       "PK","BD","LK","NP","MM","KH","LA","MN","GE","AM","AZ","BY","UZ","MO","PR","GU"]
FLAG_CC = {chr(0x1F1E6 + ord(c[0]) - 65) + chr(0x1F1E6 + ord(c[1]) - 65): c for c in CCS}

CC_NAME = {
 "US":"美国","JP":"日本","HK":"香港","TW":"台湾","SG":"新加坡","KR":"韩国","DE":"德国",
 "FR":"法国","GB":"英国","NL":"荷兰","CA":"加拿大","AU":"澳大利亚","RU":"俄罗斯","IN":"印度",
 "TR":"土耳其","IR":"伊朗","VN":"越南","TH":"泰国","MY":"马来西亚","ID":"印尼","PH":"菲律宾",
 "BR":"巴西","AR":"阿根廷","UA":"乌克兰","PL":"波兰","SE":"瑞典","CH":"瑞士","FI":"芬兰",
 "NO":"挪威","DK":"丹麦","IE":"爱尔兰","IT":"意大利","ES":"西班牙","AT":"奥地利","CZ":"捷克",
 "RO":"罗马尼亚","MD":"摩尔多瓦","LT":"立陶宛","LV":"拉脱维亚","EE":"爱沙尼亚","BG":"保加利亚",
 "RS":"塞尔维亚","GR":"希腊","IL":"以色列","AE":"阿联酋","SA":"沙特","ZA":"南非","EG":"埃及",
 "MX":"墨西哥","CL":"智利","CO":"哥伦比亚","PE":"秘鲁","NZ":"新西兰","BE":"比利时","PT":"葡萄牙",
 "HU":"匈牙利","SK":"斯洛伐克","SI":"斯洛文尼亚","HR":"克罗地亚","IS":"冰岛","LU":"卢森堡",
 "MT":"马耳他","CY":"塞浦路斯","KZ":"哈萨克","PK":"巴基斯坦","BD":"孟加拉","LK":"斯里兰卡",
 "NP":"尼泊尔","MM":"缅甸","KH":"柬埔寨","LA":"老挝","MN":"蒙古","GE":"格鲁吉亚","AM":"亚美尼亚",
 "AZ":"阿塞拜疆","BY":"白俄罗斯","UZ":"乌兹别克","MO":"澳门","PR":"波多黎各","GU":"关岛",
}

CC_NAME["CN"] = "中国"

HOST_CC = re.compile(r"(?:^|[.-])(jp|us|hk|tw|sg|kr|de|fr|uk|gb|nl|ca|au|ru|in|tr|ir|vn|th|my|id|ph|br|ar|ua|pl|se|ch|fi|no|dk|ie|it|es|at|cz|ro|md|lt|lv|ee|bg|rs|gr|il|ae|sa|za|eg|mx|cl|co|pe|nz|be|pt)\d*(?:[.-]|$)", re.I)

WORD_CC = [
 ("香港","HK"),("台湾","TW"),("澳門","MO"),("澳门","MO"),("新加坡","SG"),("日本","JP"),
 ("韩国","KR"),("韓國","KR"),("美国","US"),("美國","US"),("加拿大","CA"),("澳大利亚","AU"),
 ("澳洲","AU"),("德国","DE"),("法国","FR"),("英国","GB"),("荷兰","NL"),("俄罗斯","RU"),
 ("印度","IN"),("土耳其","TR"),("伊朗","IR"),("越南","VN"),("泰国","TH"),("马来西亚","MY"),
 ("印尼","ID"),("印度尼西亚","ID"),("菲律宾","PH"),("巴西","BR"),("阿根廷","AR"),("乌克兰","UA"),
 ("波兰","PL"),("瑞典","SE"),("瑞士","CH"),("芬兰","FI"),("挪威","NO"),("丹麦","DK"),
 ("爱尔兰","IE"),("意大利","IT"),("西班牙","ES"),("奥地利","AT"),("捷克","CZ"),
 ("罗马尼亚","RO"),("摩尔多瓦","MD"),("立陶宛","LT"),("拉脱维亚","LV"),("爱沙尼亚","EE"),
 ("保加利亚","BG"),("塞尔维亚","RS"),("希腊","GR"),("以色列","IL"),("阿联酋","AE"),
 ("沙特","SA"),("南非","ZA"),("埃及","EG"),("墨西哥","MX"),("智利","CL"),("哥伦比亚","CO"),
 ("秘鲁","PE"),("新西兰","NZ"),("比利时","BE"),("葡萄牙","PT"),("匈牙利","HU"),
 ("Hong Kong","HK"),("Taiwan","TW"),("Japan","JP"),("Korea","KR"),("Singapore","SG"),
 ("United States","US"),("America","US"),("Canada","CA"),("Australia","AU"),
 ("Germany","DE"),("France","FR"),("Britain","GB"),("Netherlands","NL"),("Russia","RU"),
 ("India","IN"),("Turkey","TR"),("Vietnam","VN"),("Thailand","TH"),("Malaysia","MY"),
 ("Indonesia","ID"),("Philippines","PH"),("Brazil","BR"),("Ukraine","UA"),("Poland","PL"),
 ("Sweden","SE"),("Switzerland","CH"),("Finland","FI"),("Norway","NO"),("Denmark","DK"),
 ("Ireland","IE"),("Italy","IT"),("Spain","ES"),("Austria","AT"),("Czech","CZ"),
 ("Romania","RO"),("Lithuania","LT"),("Latvia","LV"),("Estonia","EE"),("Bulgaria","BG"),
 ("Greece","GR"),("Israel","IL"),("Emirates","AE"),("Mexico","MX"),("Chile","CL"),
]

CC_RE = re.compile(r"(?<![A-Za-z])(US|JP|HK|TW|SG|KR|DE|FR|GB|UK|NL|CA|AU|RU|IN|TR|IR|VN|TH|MY|ID|PH|BR|AR|UA|PL|SE|CH|FI|NO|DK|IE|IT|ES|AT|CZ|RO|MD|LT|LV|EE|BG|RS|GR|IL|AE|SA|ZA|EG|MX|CL|CO|PE|NZ|BE|PT)(?![A-Za-z])")


def guess_cc(text):
    for f, cc in FLAG_CC.items():
        if f in text:
            return cc
    low = text.lower()
    for w, cc in WORD_CC:
        if w.lower() in low:
            return cc
    m = CC_RE.search(text)
    if m:
        cc = m.group(1)
        return "GB" if cc == "UK" else cc
    h = HOST_CC.search("." + text.replace(" ", ".") + ".")
    if h:
        cc = h.group(1).upper()
        return "GB" if cc == "UK" else cc
    return None


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False


def resolve(host):
    if is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def geo_ips(ips):
    out = {}
    ips = [i for i in ips if is_ip(i)]
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=query,countryCode",
                                         data=json.dumps(chunk).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=12) as r:
                for it in json.loads(r.read().decode()):
                    if it.get("countryCode"):
                        out[it["query"]] = it["countryCode"]
        except Exception:
            break
    return out


def regions(proxies):
    """返回与 proxies 等长的中文地区名列表"""
    res, need = [], []
    for p in proxies:
        cc = guess_cc("%s %s" % (p.get("name", ""), p.get("server", "")))
        res.append(cc)
        if not cc:
            need.append(len(res) - 1)
    if need:
        hosts = [proxies[i].get("server", "") for i in need]
        with ThreadPoolExecutor(max_workers=32) as ex:
            ips = list(ex.map(resolve, hosts))
        table = geo_ips(list({i for i in ips if i}))
        for i, ip in zip(need, ips):
            if ip and ip in table:
                res[i] = table[ip]
    return [CC_NAME.get(cc, "其他") if cc else "其他" for cc in res]
