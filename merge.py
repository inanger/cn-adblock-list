#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把多份中文区广告过滤清单合并去重，输出一份可直接订阅的 uBO / AdGuard 列表。

用法:
    python merge.py            # 合并（默认丢弃被父域规则覆盖的子域规则）
    python merge.py --no-subsume   # 保留所有子域规则

输出:
    merged/adblock-merged.txt   订阅文件
    merged/stats.md             统计报告
"""

import json
import re
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
CACHE = BASE / "data" / "merged"
OUT_DIR = BASE / "merged"
CACHE.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

BIZ = timezone(timedelta(hours=8))

SOURCES = [
    {
        "id": "awa",
        "name": "AWAvenue 秋风广告规则",
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "license": "GPL-3.0",
    },
    {
        "id": "adrules",
        "name": "Cats-Team AdRules",
        "url": "https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        "license": "见上游 Source.md（各上游原许可）",
    },
    {
        "id": "goodbye",
        "name": "GOODBYEADS",
        "url": "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/adblock.txt",
        "license": "MIT",
    },
    {
        "id": "antiad",
        "name": "anti-AD",
        "url": "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-adguard.txt",
        "license": "MIT",
    },
    {
        "id": "zhiyuan",
        "name": "zhiyuan1i/adblock_list",
        "url": "https://raw.githubusercontent.com/zhiyuan1i/adblock_list/master/adblock.txt",
        "license": "GPL-3.0",
    },
    {
        "id": "cjxlist",
        "name": "cjxlist",
        "url": "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjxlist.txt",
        "license": "LGPL-3.0",
    },
    {
        "id": "cjxannoy",
        "name": "cjx-annoyance",
        "url": "https://raw.githubusercontent.com/cjx82630/cjxlist/master/cjx-annoyance.txt",
        "license": "LGPL-3.0",
    },
    {
        "id": "cfrule",
        "name": "乘风广告过滤规则",
        "url": "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
        "license": "无 LICENSE（保留所有权利，仅个人使用）",
    },
    {
        "id": "cfmv",
        "name": "乘风视频广告过滤规则",
        "url": "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/mv.txt",
        "license": "无 LICENSE（保留所有权利，仅个人使用）",
    },
]

COSMETIC_SEPS = ("#@#", "#?#", "#$#", "#%#", "##")
HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+(\S+)")
BARE_NET_RE = re.compile(r"^\|\|([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*)\^$", re.I)
BARE_EXC_RE = re.compile(r"^@@\|\|([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*)\^$", re.I)


def fetch(src):
    dest = CACHE / (src["id"] + ".txt")
    if dest.exists() and dest.stat().st_size > 500:
        return dest
    req = urllib.request.Request(src["url"], headers={"User-Agent": "Mozilla/5.0 (list-merge)"})
    with urllib.request.urlopen(req, timeout=240) as resp:
        dest.write_bytes(resp.read())
    return dest


def decode(blob):
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return blob.decode(enc)
        except UnicodeDecodeError:
            continue
    return blob.decode("utf-8", errors="replace")


def classify(line):
    """返回 (类型, 去重键)。"""
    if line.startswith("!"):
        return "comment", None
    if line.startswith("@@"):
        m = BARE_EXC_RE.match(line)
        key = "exc:" + m.group(1).lower() if m else "exc:" + line[2:]
        return "exception", key
    m = HOSTS_RE.match(line)
    if m:
        return "hosts", "host:" + m.group(1).lower()
    for sep in COSMETIC_SEPS:
        i = line.find(sep)
        if i != -1:
            key = "cos:" + line[:i].lower() + sep + line[i + len(sep):]
            return "cosmetic", key
    if line.startswith("||") or line.startswith("|"):
        m = BARE_NET_RE.match(line)
        key = "net:" + m.group(1).lower() if m else "net:" + line
        return "network", key
    if line.startswith("/") and line.endswith("/") and len(line) > 2:
        return "regex", "re:" + line
    return "other", "oth:" + line


def ancestor_hosts(host):
    parts = host.split(".")
    for i in range(1, len(parts)):
        yield ".".join(parts[i:])


def wellformed(rule):
    """只保留语法明确的规则，丢弃上游被切碎的域名片段（如 *.i3z.、_ad2.、#189）。"""
    if rule.startswith("||") or rule.startswith("|") or rule.startswith("@@"):
        return True
    if rule.startswith("/") and rule.count("/") >= 2:
        return True
    if rule.startswith("*"):
        # 允许 *-ad.example.com* 这类通配模式，但要求含完整域名
        core = rule.strip("*")
        return bool(re.search(r"\.[a-z]{2,}(?:[/?]|$)", core, re.I))
    for sep in COSMETIC_SEPS:
        i = rule.find(sep)
        if i != -1:
            left = rule[:i]
            if left == "":
                return True
            return all(c.isalnum() or c in ".-_*,~" for c in left) and ("." in left or left.startswith("~"))
    return False


def main():
    subsume = "--no-subsume" not in sys.argv

    rules = {}          # key -> {"rule": str, "kind": str, "src": set()}
    per_source = {}
    dropped = Counter()

    for src in SOURCES:
        path = fetch(src)
        text = decode(path.read_bytes())
        stat = Counter()
        before = len(rules)
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            kind, key = classify(line)
            if kind == "comment":
                stat["comment"] += 1
                continue
            if kind == "hosts":
                # hosts 行语义（仅精确主机）与 ||domain^ （含子域）不同，不混入
                stat["hosts_skipped"] += 1
                continue
            stat["rule"] += 1
            stat[kind] += 1
            if key not in rules:
                rules[key] = {"rule": line, "kind": kind, "src": {src["id"]}}
            else:
                rules[key]["src"].add(src["id"])
                stat["dup"] += 1
        per_source[src["id"]] = {
            "name": src["name"],
            "bytes": path.stat().st_size,
            "added": len(rules) - before,
            **stat,
        }

    # 语法过滤：剔除上游碎片行与超长机器生成规则
    keep_loose = "--keep-loose" in sys.argv
    malformed = []
    too_long = []
    if not keep_loose:
        for key, item in list(rules.items()):
            if len(item["rule"]) > 2000:
                too_long.append(item["rule"])
                del rules[key]
                continue
            if not wellformed(item["rule"]):
                malformed.append(item["rule"])
                del rules[key]

    # 父子域收敛：纯 ||host^ 规则若其上级域已被纯 ||host^ 拦截，则本条冗余
    bare_net = {k[4:] for k, v in rules.items() if k.startswith("net:") and BARE_NET_RE.match(v["rule"])}
    subsume_dropped = []
    if subsume:
        for key, item in list(rules.items()):
            if not key.startswith("net:"):
                continue
            if not BARE_NET_RE.match(item["rule"]):
                continue
            host = key[4:]
            for anc in ancestor_hosts(host):
                if "." in anc and anc in bare_net:
                    subsume_dropped.append(item["rule"])
                    del rules[key]
                    break

    # 冲突检测：同一主机既被拦又被放行
    net_hosts = {k[4:] for k, v in rules.items() if k.startswith("net:") and BARE_NET_RE.match(v["rule"])}
    exc_hosts = {k[4:] for k, v in rules.items() if k.startswith("exc:") and BARE_EXC_RE.match(v["rule"])}
    conflicts = sorted(net_hosts & exc_hosts)

    order = [("network", "网络请求拦截"), ("cosmetic", "元素隐藏与页面清理"),
             ("exception", "例外规则（放行）"), ("regex", "正则规则"), ("other", "路径与关键词模式（无域名锚点）")]
    buckets = {k: [] for k, _ in order}
    for item in rules.values():
        buckets[item["kind"]].append(item["rule"])

    now = datetime.now(BIZ)
    header = [
        "! Title: 中文区广告拦截合并清单 (CN Ads Merged)",
        "! Description: 由 AWAvenue / AdRules / GOODBYEADS / anti-AD / zhiyuan1i / cjxlist / 乘风 合并去重生成，仅供个人使用",
        f"! Version: {now.strftime('%Y%m%d-%H%M')}",
        f"! TimeUpdated: {now.strftime('%Y-%m-%dT%H:%M:%S')}+08:00",
        "! Expires: 1 day",
        "! Homepage: local build",
        "! License: 各上游按其原始许可证授权，详见下列 Source 行；乘风规则无许可证，仅限个人使用",
        "! Note: 合并清单会继承上游的误拦风险，请在关键业务上自建白名单",
        "",
    ]
    for src in SOURCES:
        header.append(f"! Source: {src['name']} ({src['url']}) [{src['license']}]")
    header.append("")
    header.append("[Adblock Plus 2.0]")

    out = []
    out.extend(header)
    for kind, title in order:
        items = sorted(set(buckets[kind]), key=lambda s: (len(s), s))
        if not items:
            continue
        out.append("")
        out.append(f"! ===== {title}（{len(items)} 条）=====")
        out.extend(items)

    out_path = OUT_DIR / "adblock-merged.txt"
    out_path.write_text("\n".join(out) + "\n", encoding="utf-8")

    # 自校验
    check = Counter()
    seen = set()
    for line in out_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("!") or line.startswith("["):
            continue
        check["rule"] += 1
        if line in seen:
            check["dup"] += 1
        seen.add(line)
        if not (line.startswith("||") or line.startswith("|") or line.startswith("@@")
                or any(s in line for s in COSMETIC_SEPS) or line.startswith("/")
                or (line.startswith("*") and wellformed(line))):
            check["unknown_prefix"] += 1

    stats = {
        "generated_at": now.isoformat(),
        "output": str(out_path),
        "output_bytes": out_path.stat().st_size,
        "output_lines": len(out),
        "output_rules": check["rule"],
        "output_duplicates": check["dup"],
        "unknown_prefix": check["unknown_prefix"],
        "subsume": subsume,
        "subsume_dropped": len(subsume_dropped),
        "malformed_dropped": len(malformed),
        "malformed_examples": malformed[:12],
        "too_long_dropped": len(too_long),
        "by_kind": {k: len(buckets[k]) for k, _ in order},
        "unique_bare_network_hosts": len(net_hosts),
        "unique_exception_hosts": len(exc_hosts),
        "conflicts": len(conflicts),
        "conflict_examples": conflicts[:20],
        "sources": per_source,
        "feature_counts": {
            t: sum(1 for i in rules.values() if t in i["rule"])
            for t in ("$third-party", "$domain=", "$important", "$badfilter", "$redirect",
                      "$csp", "##+js(", "#?#", "#$#", ":has-text(")
        },
    }
    (OUT_DIR / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    md = ["# 合并结果", "",
          f"- 输出：`{out_path.name}`（{round(stats['output_bytes']/1024/1024, 2)} MB，{stats['output_rules']} 条规则，{stats['output_lines']} 行）",
          f"- 生成时间：{now.strftime('%Y-%m-%d %H:%M')} (UTC+8)",
          f"- 父域收敛：{'开启' if subsume else '关闭'}，移除冗余子域规则 {stats['subsume_dropped']} 条",
          f"- 语法过滤：丢弃上游碎片/非标准行 {stats['malformed_dropped']} 条（如 `*.i3z.`、`_ad2.`、`#189`）",
          f"- 超长规则：丢弃单行 >2000 字符的机器生成规则 {stats['too_long_dropped']} 条（最长 29519 字符，解析开销大）",
          f"- 唯一拦截主机名 {len(net_hosts)}，唯一例外主机名 {len(exc_hosts)}，冲突 {len(conflicts)}",
          f"- 自校验：重复 {check['dup']} 条，无法识别前缀 {check['unknown_prefix']} 条", "",
          "## 各来源贡献", "",
          "| 来源 | 体积 KB | 读入规则 | 新增 | 批内重复 | 许可 |",
          "|---|---:|---:|---:|---:|---|"]
    lic = {s["id"]: s["license"] for s in SOURCES}
    for sid, s in per_source.items():
        md.append(f"| {s['name']} | {round(s['bytes']/1024)} | {s.get('rule',0)} | {s['added']} | {s.get('dup',0)} | {lic[sid]} |")
    md += ["", "## 输出构成", "", "| 类型 | 条数 |", "|---|---:|"]
    for k, title in order:
        md.append(f"| {title} | {len(buckets[k])} |")
    md += ["", "## 语法特性计数", ""]
    for k, v in stats["feature_counts"].items():
        md.append(f"- `{k}`: {v}")

    (OUT_DIR / "stats.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
