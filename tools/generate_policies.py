#!/usr/bin/env python3
"""
从微软官方 MicrosoftEdgePolicyTemplates.zip 重建 EdgePolicyManager 的策略数据。

数据源（全部来自模板包，无任何手工录入）：
  windows/admx/msedge.admx            策略结构：名称/注册表路径/值类型/枚举项
  windows/admx/<lang>/*.adml          简中/繁中/英文文案与版本字符串
  html/<lang>/msedge*policylist.html  唯一包含 "Dynamic Policy Refresh" 的源
  VERSION                             策略版本号

用法：
  python tools/generate_policies.py --templates ../_templates
  python tools/generate_policies.py --templates ../_templates --verify-only
"""

import argparse
import html
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict

NS = "{http://www.microsoft.com/GroupPolicy/PolicyDefinitions}"

# 策略类型 -> (admx 文件名, html 文件名, 注册表根路径)
TYPES = OrderedDict([
    ("Edge",        ("msedge.admx",        "msedgepolicylist",        r"Software\Policies\Microsoft\Edge")),
    ("EdgeUpdate",  ("msedgeupdate.admx",  "msedgeupdatepolicylist",  r"Software\Policies\Microsoft\EdgeUpdate")),
    ("EdgeWebview", ("msedgewebview2.admx", "msedgewebview2policylist", r"Software\Policies\Microsoft\Edge\WebView2")),
])

LANGS = ("en-US", "zh-CN", "zh-TW")

# ADMX 根分类节点，本身不是可选分类
ROOT_CATEGORIES = {"microsoft_edge", "microsoft_edge_recommended"}

# 元素标签 -> (DataType, ValueKind)
# "boolean" 不是 ADMX 元素名，是 build_type_model 里对
# <policy> 直接带 <enabledValue>/<disabledValue> 情形的内部标记。
ELEMENT_TYPES = {
    "boolean": ("Boolean", "REG_DWORD"),
    "list":    ("Unknown", "N/A"),
    "text":    ("String",  "REG_SZ"),
    "decimal": ("Integer", "REG_DWORD"),
}

UNKNOWN_DYNAMIC_REFRESH = {
    "en-US": "Unknown",
    "zh-CN": "未知",
    "zh-TW": "未知",
}

# 根分类策略的兜底分类（沿用上游命名，保证旧配置可延续）
ADDITIONAL_CATEGORY_NAME = {
    "en-US": "Others",
    "zh-CN": "其他",
    "zh-TW": "其他",
}


def local(tag):
    """
    去掉 XML 命名空间前缀，返回裸标签名。

    msedgeupdate.adml省略了默认 xmlns（XML 合法），msedge.adml 带，
    所以不能假定所有节点都有同一前缀，必须按实际 tag 剥离。
    """
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def children(node, name):
    """按裸标签名取直接子节点，命名空间无关。"""
    return [c for c in node if local(c.tag) == name]


def child(node, name):
    found = children(node, name)
    return found[0] if found else None


def load_adml(adml_path):
    """读取 ADML，返回 id -> 文本 的字符串表。"""
    root = ET.parse(adml_path).getroot()
    resources = child(root, "resources")
    table = child(resources, "stringTable") if resources is not None else None
    strings = {}
    if table is None:
        return strings
    for node in children(table, "string"):
        strings[node.get("id")] = node.text or ""
    return strings


def load_admx(admx_path):
    return ET.parse(admx_path).getroot()


def ref_name(ref):
    """$(string.Foo) -> Foo；None -> None"""
    if not ref:
        return None
    m = re.fullmatch(r"\$\(string\.(.+)\)", ref.strip())
    return m.group(1) if m else None


def parse_dynamic_refresh(html_path):
    """
    从策略列表 HTML 抽取 {策略名: 动态刷新本地化文本}。

    这个字段只存在于 HTML 列表里，ADMX/ADML 都没有。
    结构：<h3><a name="X"></a>X</h3> ... <li>动态策略刷新:\n 是\n</li> ...
    """
    with open(html_path, encoding="utf-8", errors="replace") as f:
        doc = f.read()

    label = r"(?:Dynamic\s*Policy\s*Refresh|动态策略刷新|動態原則重新整理)"
    result = {}
    # 按 <h3><a name="X"></a> 切块，每块对应一条策略
    starts = [(m.start(), m.group(1))
              for m in re.finditer(r'<h3>\s*<a name="([^"]+)"></a>', doc)]
    for idx, (pos, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(doc)
        block = doc[pos:end]
        # 限定在"动态策略刷新"所在的那个 <li> 内，避免抓到后续段落
        m = re.search(label + r"\s*:(.*?)</li>", block, re.S)
        if not m or not m.group(1):
            continue
        text = re.sub(r"<[^>]+>", " ", m.group(1))
        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip().strip("·-— ")
        if text:
            result[name] = text
    return result


def build_type_model(admx_root):
    """
    解析单个 ADMX，返回:
      policies: OrderedDict[策略键名 -> 结构信息]
      categories: OrderedDict[分类名 -> 分类显示名 key]
    """
    policies = OrderedDict()

    # 第一遍：解析全部 policy，并记录哪些基名存在「强制级」形态。
    parsed = []
    mandatory_bases = set()

    for pol in admx_root.iter():
        if local(pol.tag) != "policy":
            continue
        pol_name = pol.get("name") or ""
        key = pol.get("key") or ""
        base_name = re.sub(r"_recommended$", "", pol_name)
        is_recommended = key.split("\\")[-1] == "Recommended"

        parent_cat = child(pol, "parentCategory")
        category = parent_cat.get("ref") if parent_cat is not None else None
        sup = child(pol, "supportedOn")
        supported_on = sup.get("ref") if sup is not None else None
        has_enabled = child(pol, "enabledValue") is not None
        value_name = pol.get("valueName")

        # ---- 枚举出该 policy 产出的注册表值名列表 ----
        if value_name and has_enabled:
            targets = [(value_name, "boolean", None)]
        else:
            targets = []
            elements = child(pol, "elements")
            for el in (list(elements) if elements is not None else []):
                tag = local(el.tag)
                if tag not in ("enum", "text", "list", "decimal"):
                    continue
                vn = el.get("valueName")
                if not vn and tag == "list":
                    lk = el.get("key")
                    vn = lk.split("\\")[-1] if lk else None
                if not vn:
                    vn = base_name
                targets.append((vn, tag, el))

        if not is_recommended:
            mandatory_bases.add(base_name)

        parsed.append((is_recommended, base_name, category, supported_on,
                       key, targets))

    recommended_bases = {b for (r, b, *_rest) in parsed if r}

    # 第二遍：建条目。
    # 推荐级 policy 只用于标记，不重复建条目 —— 但若某策略在 ADMX 里
    # 只有推荐级形态（无强制级版本），它仍需作为独立条目存在。
    for is_recommended, base_name, category, supported_on, key, targets in parsed:
        has_mandatory = base_name in mandatory_bases
        if is_recommended and has_mandatory:
            continue

        can_mandatory = has_mandatory and not is_recommended
        can_recommended = base_name in recommended_bases or is_recommended

        registry_root = key
        if is_recommended and registry_root.endswith("\\Recommended"):
            registry_root = registry_root[: -len("\\Recommended")]

        for vn, tag, el in targets:
            if vn in policies:
                continue

            data_type, value_kind = ELEMENT_TYPES.get(tag, ("Unknown", "N/A"))
            data_options = None

            if tag == "enum" and el is not None:
                opts = []
                for item in children(el, "item"):
                    label = ref_name(item.get("displayName"))
                    vnode = child(item, "value")
                    raw, raw_tag = None, None
                    if vnode is not None and len(vnode):
                        raw_tag = local(vnode[0].tag)
                        raw = vnode[0].get("value") or vnode[0].text
                    if raw is None:
                        continue
                    if raw_tag == "decimal":
                        try:
                            raw = int(raw)
                        except ValueError:
                            continue
                    elif raw_tag == "string":
                        raw = raw.strip()
                    else:
                        continue
                    opts.append({"Name": label, "Value": raw})
                if opts:
                    data_options = opts
                    if data_type == "Unknown":
                        # enum 按值类型定 DataType
                        if isinstance(opts[0]["Value"], str):
                            data_type, value_kind = "String", "REG_SZ"
                        else:
                            data_type, value_kind = "Integer", "REG_DWORD"

            policies[vn] = {
                "admx_name": base_name,
                "category": category,
                "supported_on": supported_on,
                "data_type": data_type,
                "value_kind": value_kind,
                "data_options": data_options,
                "label_key": base_name,
                "explain_key": f"{base_name}_Explain",
                "registry_root": registry_root,
                "can_mandatory": can_mandatory,
                "can_recommended": can_recommended,
            }

    # 分类表
    categories = OrderedDict()
    for cat in admx_root.iter():
        if local(cat.tag) != "category":
            continue
        cname = cat.get("name") or ""
        if cname in ROOT_CATEGORIES:
            continue
        disp = ref_name(cat.get("displayName")) or ""
        categories[cname] = disp

    return policies, categories


def normalize_text(text, policy_names):
    """
    ADML 的 _Explain 文本里，交叉引用写作裸 PolicyName（或 <PolicyName>），
    转成 App 内可点击的 markdown 链接 [Name](#Name)。
    """
    if not text:
        return text
    # 已经像链接的跳过
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)

    def repl(m):
        name = m.group(0)
        if name in policy_names:
            return f"[{name}](#{name})"
        return name

    # 策略名多为连续大驼峰，只匹配在 policy_names 里的
    pattern = re.compile(
        "|".join(re.escape(n) for n in sorted(policy_names, key=len, reverse=True))
    )
    return pattern.sub(repl, text)


def inherit_default_values(new_map, old_map):
    """旧 JSON 里人工推断过的 DefaultValue 原样继承。"""
    inherited = 0
    for name, detail in new_map.items():
        old = old_map.get(name)
        if old and old.get("Registry", {}).get("DefaultValue") is not None:
            detail["Registry"]["DefaultValue"] = old["Registry"]["DefaultValue"]
            inherited += 1
    return inherited


def generate_for_type(policy_type, templates_dir, old_defaults):
    admx_file, html_file, default_root = TYPES[policy_type]
    admx_path = os.path.join(templates_dir, "windows", "admx", admx_file)
    admx_root = load_admx(admx_path)
    policies, categories = build_type_model(admx_root)

    results = {}
    for lang in LANGS:
        adml_path = os.path.join(
            templates_dir, "windows", "admx", lang, admx_file.replace(".admx", ".adml")
        )
        html_path = os.path.join(templates_dir, "html", lang, html_file + ".html")

        strings = load_adml(adml_path)
        dyn_refresh = parse_dynamic_refresh(html_path) if os.path.exists(html_path) else {}

        detail_map = OrderedDict()
        for vn, info in policies.items():
            label = strings.get(info["label_key"], info["label_key"])
            explain = strings.get(info["explain_key"], "")
            explain = normalize_text(explain, set(policies.keys()))

            # registry_root 已在 build_type_model 里剥掉 \Recommended
            root = info["registry_root"]
            can_rec = info["can_recommended"]

            # 枚举项：把 ADML 字符串 key 换成本地化文案
            options = None
            if info["data_options"]:
                options = []
                for o in info["data_options"]:
                    opt_label = strings.get(o["Name"], o["Name"])
                    options.append({"Name": opt_label, "Value": o["Value"]})

            detail_map[vn] = {
                "Name": vn,
                "ShortDescription": label,
                "SupportVersion": strings.get(info["supported_on"] or "", ""),
                "Description": explain,
                "DataType": info["data_type"],
                "DataOptions": options,
                "DynamicRefresh": dyn_refresh.get(vn) or UNKNOWN_DYNAMIC_REFRESH[lang],
                "Registry": {
                    "CanMandatory": info["can_mandatory"],
                    "CanRecommended": can_rec,
                    "MandatoryPath": root if info["can_mandatory"] else "N/A",
                    "RecommendedPath": (root + "\\Recommended") if can_rec else "N/A",
                    "Name": vn,
                    "DefaultValue": None,
                    "ValueKind": info["value_kind"],
                },
            }

        old_detail = old_defaults.get(policy_type, {}).get(lang, {}).get("detail", {})
        if old_detail:
            inherit_default_values(detail_map, old_detail)

        # ---- 菜单 ----
        menu = []
        assigned = set()
        for cname, disp_key in categories.items():
            items = sorted(
                vn for vn, info in policies.items()
                if info["category"] == cname
            )
            if not items:
                continue
            assigned.update(items)
            menu.append({
                "Identifier": cname,
                "Icon": None,   # 稍后按旧映射填充
                "Name": strings.get(disp_key, disp_key or cname),
                "Items": items,
            })

        # ADMX 里大量策略的 parentCategory 直接是根节点 microsoft_edge，
        # 没有独立分类。上游用一个Additional 兜底分类收容它们，
        # 否则这些策略在App 里没有任何入口（只能靠搜索找到）。
        leftovers = sorted(set(detail_map) - assigned)
        if leftovers:
            menu.append({
                "Identifier": "Additional",
                "Icon": None,
                "Name": ADDITIONAL_CATEGORY_NAME[lang],
                "Items": leftovers,
            })

        results[lang] = {"detail": detail_map, "menu": menu}

    return results


def apply_icons(results_by_lang, old_menu_by_lang, iconmap):
    """沿用旧菜单的图标映射，新分类按关键词猜测。"""
    keyword_icons = [
        (("content", "内容"), "ExploitProtectionSettings"),
        (("certificate", "证书"), "Certificate"),
        (("extension", "扩展"), "Puzzle"),
        (("privacy", "隐私"), "Privacy"),
        (("security", "安全"), "Shield"),
        (("network", "网络", "proxy", "代理"), "Globe"),
        (("download", "下载"), "Download"),
        (("printing", "打印"), "Print"),
        (("search", "搜索"), "Search"),
        (("update", "更新"), "World"),
        (("application", "应用"), "AllApps"),
        (("cast",), "MiracastLogoSmall"),
        (("admin", "管理"), "Admin"),
        (("experimental", "实验"), "Flask"),
        (("password", "密码"), "Key"),
        (("copilot",), "Robot"),
        (("edgegames", "游戏"), "Game"),
        (("workspaces", "工作区"), "Processing"),
        (("crypto", "加密"), "Lock"),
        (("defaultsettings", "默认设置"), "Settings"),
    ]

    def guess(identifier, name):
        # 兜底分类固定用 More（与上游一致）
        if identifier == "Additional":
            return "More" if "More" in iconmap else None
        hay = (identifier + " " + name).lower()
        for keys, icon in keyword_icons:
            if any(k.lower() in hay for k in keys):
                if icon in iconmap:
                    return icon
        return "ViewAll" if "ViewAll" in iconmap else None

    for lang, data in results_by_lang.items():
        old_map = {}
        for item in old_menu_by_lang.get(lang, []):
            old_map[item.get("Identifier")] = item.get("Icon")
        for entry in data["menu"]:
            icon = old_map.get(entry["Identifier"])
            if not icon:
                icon = guess(entry["Identifier"], entry["Name"])
            entry["Icon"] = icon


def load_old(repo_root):
    """读取旧 JSON，用于 DefaultValue 继承与图标映射。"""
    old = {}
    menus = {}
    for ptype in TYPES:
        old[ptype] = {}
        menus[ptype] = {}
        for lang in LANGS:
            base = os.path.join(repo_root, "StaticModels", "Policy", ptype, lang)
            dp = os.path.join(base, "PolicyDetailMap.json")
            mp = os.path.join(base, "PolicyMenuList.json")
            detail = {}
            if os.path.exists(dp):
                with open(dp, encoding="utf-8") as f:
                    detail = json.load(f)
            menu = []
            if os.path.exists(mp):
                with open(mp, encoding="utf-8") as f:
                    menu = json.load(f)
            old[ptype][lang] = {"detail": detail}
            menus[ptype][lang] = menu
    return old, menus


def dump(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        f.write("\n")


def write_all(repo_root, all_data):
    changed = []
    for ptype, langs in all_data.items():
        for lang, data in langs.items():
            base = os.path.join(repo_root, "StaticModels", "Policy", ptype, lang)
            dp = os.path.join(base, "PolicyDetailMap.json")
            mp = os.path.join(base, "PolicyMenuList.json")
            dump(data["detail"], dp)
            dump(data["menu"], mp)
            changed += [dp, mp]

    version_file = os.path.join(repo_root, "StaticModels", "Policy", "SUPPORT_VERSION")
    md5_file = os.path.join(repo_root, "StaticModels", "Policy", "TEMPLATE_MD5")
    return changed, version_file, md5_file


def verify(repo_root, all_data, old_data, iconmap=None):
    """编译前校验，返回 (是否通过, 报告文本)。"""
    lines = []
    ok = True

    def log(s=""):
        lines.append(s)
        print(s)

    log("=" * 68)
    log("策略库校验报告")
    log("=" * 68)

    for ptype in TYPES:
        for lang in LANGS:
            new = all_data[ptype][lang]["detail"]
            menu = all_data[ptype][lang]["menu"]
            old = old_data[ptype][lang]["detail"]
            tag = f"{ptype}/{lang}"

            # 1) 菜单引用完整性（DetailPage.xaml.cs 硬索引，缺一个就崩）
            missing = set()
            for entry in menu:
                for item in entry["Items"]:
                    if item not in new:
                        missing.add(item)
            if missing:
                ok = False
                log(f"[FAIL] {tag} 菜单引用缺失 {len(missing)} 项: {sorted(missing)[:5]}")
            else:
                covered = set()
                for entry in menu:
                    covered.update(entry["Items"])
                uncovered = set(new) - covered
                if uncovered:
                    ok = False
                    log(f"[FAIL] {tag} {len(uncovered)} 条策略无菜单入口: "
                        f"{sorted(uncovered)[:5]}")
                else:
                    log(f"[ OK ] {tag} 菜单引用完整（{len(menu)} 个分类，"
                        f"覆盖全部 {len(new)} 条）")

            # 1b) 纯推荐级策略（CanMandatory=false）不得丢失
            rec_only_old = {
                k for k, v in old.items()
                if not v["Registry"].get("CanMandatory")
            }
            rec_only_new = {
                k for k, v in new.items()
                if not v["Registry"].get("CanMandatory")
            }
            lost_rec = rec_only_old - rec_only_new
            if lost_rec:
                ok = False
                log(f"[FAIL] {tag} 丢失纯推荐级策略 {len(lost_rec)} 条: "
                    f"{sorted(lost_rec)[:5]}")

            # 1c) 必填字段完整性（App 直接解引用，缺字段会崩）
            req = ("Name", "ShortDescription", "SupportVersion", "DataType",
                   "DynamicRefresh", "Registry")
            incomplete = [
                k for k, v in new.items()
                if any(not v.get(f) and v.get(f) != "" for f in req[:4])
                or not v.get("DynamicRefresh")
                or not v.get("Registry")
                or not v["Registry"].get("Name")
                or not v["Registry"].get("ValueKind")
            ]
            if incomplete:
                ok = False
                log(f"[FAIL] {tag} 字段缺失 {len(incomplete)} 条: "
                    f"{incomplete[:5]}")

            # 2) 枚举完整性
            bad_opts = []
            for name, d in new.items():
                opts = d["DataOptions"]
                if not opts:
                    continue
                seen = set()
                for o in opts:
                    sv = str(o["Value"])
                    if sv in seen:
                        bad_opts.append(f"{name}:值重复{sv}")
                    seen.add(sv)
                    if not o["Name"] or o["Name"].endswith(("_", "$(")):
                        #枚举文案没查表成功（残留 ADML key）
                        bad_opts.append(f"{name}:文案未本地化 {o['Name']}")
                dt = d["DataType"]
                if dt not in ("Integer", "String"):
                    bad_opts.append(f"{name}:类型{dt}却有枚举")
            if bad_opts:
                ok = False
                log(f"[FAIL] {tag} 枚举异常: {bad_opts[:5]}")
            else:
                log(f"[ OK ] {tag} 枚举完整")

            # 3) 与旧数据的回归比对
            common = set(new) & set(old)
            diffs = []
            for name in common:
                o = old[name]
                n = new[name]
                if (o["DataType"] != n["DataType"]
                        or o["Registry"]["ValueKind"] != n["Registry"]["ValueKind"]):
                    diffs.append(
                        f"{name}({o['DataType']}/{o['Registry']['ValueKind']}"
                        f"->{n['DataType']}/{n['Registry']['ValueKind']})")
            added = sorted(set(new) - set(old))
            removed = sorted(set(old) - set(new))

            # 允许的改进型变化：Unknown ->具体类型（上游把多部件策略误标为 Unknown）
            regressions = []
            for name in common:
                o = old[name]["DataType"]
                n = new[name]["DataType"]
                if o == n:
                    continue
                if o == "Unknown" and n in ("Integer", "String", "Boolean"):
                    continue  # 修正上游误标
                regressions.append(name)
            if regressions:
                ok = False
                log(f"[FAIL] {tag} {len(regressions)} 条类型退化/变化，"
                    f"例: {regressions[:5]}")

            if lang == "zh-CN" and ptype == "Edge":
                unknown = sum(
                    1 for v in new.values()
                    if v["DynamicRefresh"] == UNKNOWN_DYNAMIC_REFRESH[lang]
                )
                rate = 100.0 * unknown / max(len(new), 1)
                log(f"        动态刷新未知 {unknown}/{len(new)} ({rate:.1f}%)")
                if rate > 5:
                    ok = False
                    log(f"[FAIL] {tag} 动态刷新解析覆盖率过低")

            log(f"[ .. ] {tag} 旧 {len(old)} -> 新 {len(new)}"
                f" | 新增 {len(added)} 移除 {len(removed)}"
                f" 类型变化 {len(diffs)}（其中退化 {len(regressions)}）")
            if diffs:
                log(f"        类型变化: {diffs[:8]}")
            if added and lang == "zh-CN":
                log(f"        新增策略({len(added)}): {added}")
            if removed and lang == "zh-CN":
                log(f"        移除策略: {removed}")

    # 4) 三语言键集一致性
    log("-" * 68)
    for ptype in TYPES:
        sets = {lang: set(all_data[ptype][lang]["detail"]) for lang in LANGS}
        base = sets["zh-CN"]
        same = all(s == base for s in sets.values())
        if not same:
            ok = False
            log(f"[FAIL] {ptype} 三语言键集不一致")
            for lang, s in sets.items():
                log(f"        {lang}: {len(s)} 条, 与 zh-CN 差异 {len(s ^ base)}")
        else:
            log(f"[ OK ] {ptype} 三语言键集一致（各 {len(base)} 条）")

    # 5) 图标有效性（IconUtil 对未知名字会静默兜底，但分类标识会丢）
    log("-" * 68)
    for ptype in TYPES:
        for lang in LANGS:
            bad = [
                (e["Identifier"], e["Icon"])
                for e in all_data[ptype][lang]["menu"]
                if not e.get("Icon") or e["Icon"] not in iconmap
            ]
            if bad:
                ok = False
                log(f"[FAIL] {ptype}/{lang} 图标无效: {bad[:5]}")
            else:
                log(f"[ OK ] {ptype}/{lang} 图标全部有效")

    log("=" * 68)
    log("总体结果: " + ("通过" if ok else "存在问题，请勿编译"))
    log("=" * 68)
    return ok, "\n".join(lines)


def template_md5(templates_dir):
    """msedge.admx 的 MD5（大写十六进制），用于判断模板是否变化。"""
    import hashlib
    path = os.path.join(templates_dir, "windows", "admx", "msedge.admx")
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest().upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--templates", default="../_templates", help="模板解压目录")
    ap.add_argument("--repo", default=".", help="仓库根目录")
    ap.add_argument("--verify-only", action="store_true", help="只校验不写文件")
    ap.add_argument("--skip-version", action="store_true", help="不写 SUPPORT_VERSION")
    args = ap.parse_args()

    templates_dir = os.path.abspath(args.templates)
    repo_root = os.path.abspath(args.repo)

    version_file = os.path.join(templates_dir, "VERSION")
    if not os.path.exists(version_file):
        print(f"[FATAL] 找不到 {version_file}")
        return 2
    kv = {}
    for line in open(version_file, encoding="utf-8-sig"):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            kv[k] = v
    version = f"{kv['MAJOR']}.{kv['MINOR']}.{kv['BUILD']}.{kv['PATCH']}"
    print(f"模板策略版本: {version}")

    old_data, old_menus = load_old(repo_root)
    iconmap_path = os.path.join(repo_root, "StaticModels", "Icon", "IconMap.json")
    with open(iconmap_path, encoding="utf-8") as f:
        iconmap = json.load(f)

    all_data = {}
    for ptype in TYPES:
        all_data[ptype] = generate_for_type(ptype, templates_dir, old_data)
        apply_icons(all_data[ptype], old_menus[ptype], iconmap)

    ok, _ = verify(repo_root, all_data, old_data, iconmap)
    if not ok:
        print("\n校验未通过，已中止写入。")
        return 1

    if args.verify_only:
        print("\n--verify-only 模式，未写入任何文件。")
        return 0

    changed, sv_file, md5_file = write_all(repo_root, all_data)
    if not args.skip_version:
        with open(sv_file, "w", encoding="utf-8", newline="") as f:
            f.write(version + "\n")
        changed.append(sv_file)

        md5 = template_md5(templates_dir)
        with open(md5_file, "w", encoding="utf-8", newline="") as f:
            f.write(md5 + "\n")
        changed.append(md5_file)

    print(f"\n已写入 {len(changed)} 个文件：")
    for p in changed:
        print("  " + os.path.relpath(p, repo_root))
    return 0


if __name__ == "__main__":
    sys.exit(main())