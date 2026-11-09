"""同步大陆分流规则到 Cloudflare Zero Trust 全部设备策略。

与上游 cf-zt-cn-split 的差异：
1. 同时下发 IPv6 段（上游只处理 IPv4），解决国内 App 走隧道变慢的问题
2. 保留策略里已有的内网/保留段排除项，避免内网设备被劫持进隧道
3. 维护 Local Domain Fallback，让国内域名走国内 DNS 解析，返回国内 IP
4. 写入账户下全部设备策略（自定义策略优先级高于默认策略，只改默认会不生效）

环境变量：CF_API_TOKEN、CF_ACCOUNT_ID、MODE(默认 exclude)
"""
import ipaddress
import os
import sys
import time
import urllib.request

import requests

BASE = "https://api.cloudflare.com/client/v4"
V4_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"
V6_URL = "https://www.ipdeny.com/ipv6/ipaddresses/aggregated/cn-aggregated.zone"
BUDGET = 4000

CN_DOMAINS = [
    "baidu.com", "qq.com", "tencent.com", "taobao.com", "tmall.com", "alipay.com",
    "alibaba.com", "aliyun.com", "alicdn.com", "jd.com", "163.com", "126.net",
    "netease.com", "sohu.com", "sina.com.cn", "weibo.com", "sinaimg.cn",
    "bilibili.com", "hdslb.com", "douyin.com", "bytedance.com", "toutiao.com",
    "meituan.com", "dianping.com", "ele.me", "ctrip.com", "12306.cn", "iqiyi.com",
    "youku.com", "zhihu.com", "xiaohongshu.com", "kuaishou.com", "pinduoduo.com",
    "xiaomi.com", "mi.com", "huawei.com", "360.cn", "gov.cn", "edu.cn",
    "csdn.net", "gitee.com",
]
CN_DNS = ["223.5.5.5", "119.29.29.29"]


def env(name, default=""):
    v = os.getenv(name, default).strip()
    if not v:
        sys.exit(f"缺少环境变量 {name}")
    return v


def fetch(url, ver):
    txt = None
    for i in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as f:
                txt = f.read().decode()
            break
        except Exception as e:
            print(f"  抓取失败({i+1}/4) {type(e).__name__}，重试…")
            time.sleep(2)
    if txt is None:
        sys.exit(f"数据源不可达: {url}")
    out = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            n = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if n.version == ver:
            out.append(n)
    return out


def truncate(ns, pl):
    return list(ipaddress.collapse_addresses(
        [n.supernet(new_prefix=pl) if n.prefixlen > pl else n for n in ns]))


def policies(s, acct, mode):
    """返回 [(name, split_path, fallback_path, rules)]；默认策略走无 id 的路径"""
    out = []
    res = s.get(f"{BASE}/accounts/{acct}/devices/policies", timeout=30).json()
    for p in res.get("result") or []:
        pid = p["policy_id"]
        name = p.get("name") or "(未命名)"
        split = f"/accounts/{acct}/devices/policy/{pid}/{mode}"
        fallback = f"/accounts/{acct}/devices/policy/{pid}/fallback_domains"
        rr = s.get(BASE + split, timeout=60).json()
        fb = s.get(BASE + fallback, timeout=60).json()
        if not (rr.get("success") and rr.get("result") is not None):
            if not p.get("default"):
                print(f"  跳过 {name}：规则读取失败")
                continue
            split = f"/accounts/{acct}/devices/policy/{mode}"
            fallback = f"/accounts/{acct}/devices/policy/fallback_domains"
            rr = s.get(BASE + split, timeout=60).json()
            fb = s.get(BASE + fallback, timeout=60).json()
        out.append((name, split, fallback, rr.get("result") or [],
                    fb.get("result") if fb.get("success") else None))
    return out


def main():
    token, acct = env("CF_API_TOKEN"), env("CF_ACCOUNT_ID")
    mode = os.getenv("MODE", "exclude").strip() or "exclude"
    dry = "--dry-run" in sys.argv

    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

    tg = policies(s, acct, mode)
    if not tg:
        sys.exit("未找到可读的设备策略")
    print(f"模式 {mode}，目标策略 {len(tg)} 个")

    keep = [{"address": r["address"], "description": r.get("description") or "local"}
            for r in tg[0][3] if r.get("address")]
    kept = {r["address"] for r in keep}
    print(f"保留现有排除项 {len(keep)} 条（内网/保留段）")

    v4 = fetch(V4_URL, 4)
    print(f"IPv4 源 {len(v4)} 条")
    remain = BUDGET - len(keep) - len(v4)
    v6 = []
    if remain > 0:
        raw6 = fetch(V6_URL, 6)
        for pl in (32, 28, 24, 20, 16):
            cand = truncate(raw6, pl)
            if len(cand) <= remain:
                v6 = cand
                print(f"IPv6 源 {len(raw6)} 条 → /{pl} 粗化后 {len(cand)} 条")
                break
        if not v6:
            print("IPv6 无法放入余量，本次跳过")

    cn = [{"address": str(n), "description": "CN IPv4"} for n in v4]
    cn += [{"address": str(n), "description": "CN IPv6"} for n in v6]
    routes = keep + [r for r in cn if r["address"] not in kept]
    print(f"组装：保留 {len(keep)} + CN {len(cn)} = {len(routes)} 条（上限 {BUDGET}）")

    if dry:
        print("[干跑] 未写入")
        return

    ok = 0
    for name, split, fallback, cur, fb in tg:
        r = s.put(BASE + split, json=routes, timeout=180)
        body = r.json()
        if body.get("success"):
            ok += 1
            print(f"✅ {name}: {len(routes)} 条分流规则")
        else:
            msg = "; ".join(f"{e.get('code')}:{e.get('message')}" for e in body.get("errors") or [])
            print(f"❌ {name}: HTTP {r.status_code} {msg}")
            continue

        if fb is None:
            continue
        have = {c.get("suffix") for c in fb}
        new = list(fb) + [{"suffix": d, "description": "CN 直连解析", "dns_server": CN_DNS}
                          for d in CN_DOMAINS if d not in have]
        if len(new) == len(fb):
            print(f"   回退域名已是最新 {len(fb)} 条")
            continue
        rr = s.put(BASE + fallback, json=new, timeout=120).json()
        print(f"   回退域名 {len(fb)} → {len(new)} 条" + ("  ✅" if rr.get("success") else "  ❌"))

    print(f"\n完成 {ok}/{len(tg)} 个策略。服务端最长 10 分钟下发到设备。")


if __name__ == "__main__":
    main()
