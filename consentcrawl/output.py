# Output txt file from consentcrawl db schema
#!/usr/bin/env python3

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

TABLE = "crawl_results"
ID_COL = "id"
DOMAIN_COL = "domain_name"
URL_COL = "url"
PRE_COOKIES_COL = "pre_cookies"
POST_COOKIES_COL = "post_cookies"
PRE_EVIDENCE_COL = "pre_page_evidence"
POST_EVIDENCE_COL = "post_page_evidence"
CONSENT_ACTION_COL = "consent_action"  # e.g. 'accept' or 'reject'
CUSTOM_PREFS_COL = "custom_prefs_requested"
CUSTOM_TOGGLES_COL = "custom_toggles_changed"
CUSTOM_DEBUG_COL = "custom_flow_debug"

def action_label_for(action: str) -> str:
    action = (action or "").strip().lower()
    if action == "accept":
        return "Accept"
    if action == "reject":
        return "Reject"
    if action == "custom":
        return "Custom"
    return "Consent"

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Group pre/post cookies by consent action, then website, from an SQLite DB."
    )
    p.add_argument("db", help="Path to the SQLite .db file (must contain the 'crawl_results' table)")
    p.add_argument("--only-action", choices=["accept", "reject", "custom", "unknown"], help="Filter a single consent action type")
    p.add_argument("--max-sites", type=int, help="Limit how many sites (ids) to print per consent action")
    p.add_argument("--out", help="Write the report to this text file instead of stdout")
    p.add_argument("--include-values", action="store_true", help="Include cookie 'value' attribute in breakdown")
    return p.parse_args()

def to_iso(ts: Any) -> Optional[str]:
    try:
        t = float(ts)
        if t <= 0:
            return None
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    except Exception:
        return None

def load_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Select only columns that exist, defaulting missing ones to None."""
    desired = [
        ID_COL, DOMAIN_COL, URL_COL,
        PRE_COOKIES_COL, POST_COOKIES_COL,
        PRE_EVIDENCE_COL, POST_EVIDENCE_COL,
        CONSENT_ACTION_COL, CUSTOM_PREFS_COL, CUSTOM_TOGGLES_COL, CUSTOM_DEBUG_COL
    ]
    # Discover available columns
    cur = conn.execute(f'PRAGMA table_info("{TABLE}")')
    have = {row[1] for row in cur.fetchall()}  # set of column names
    cols = [c for c in desired if c in have]

    if ID_COL not in cols: cols.insert(0, ID_COL)
    sql = f'SELECT {", ".join([f"""\"{c}\"""" for c in cols])} FROM "{TABLE}"'
    cur = conn.execute(sql)
    rows = []
    for r in cur.fetchall():
        row = {c: r[i] for i, c in enumerate(cols)}
        # Ensure missing desired columns appear as None
        for d in desired:
            if d not in row:
                row[d] = None
        rows.append(row)
    return rows

def parse_json(raw: Optional[str]) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None

def parse_cookie_list(raw: Optional[str]) -> List[Dict[str, Any]]:
    j = parse_json(raw)
    return j if isinstance(j, list) else []

def parse_json_obj(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    j = parse_json(raw)
    return j if isinstance(j, dict) else None

def parse_evidence_list(raw: Optional[str]) -> List[Dict[str, Any]]:
    j = parse_json(raw)
    return j if isinstance(j, list) else []

def cookie_key(d: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    nm = d.get("name")
    if not nm:
        return None
    dom = (d.get("domain") or "").lstrip(".")
    path = d.get("path") or "/"
    return (str(nm), dom, path)

def build_pages_seen(evidence: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], List[str]]:
    """
    Build an ordered, de-duplicated list of URLs where each cookie (name,domain,path)
    was observed. Uses:
      - new_site_cookies (first seen here)
      - changed_site_cookies.after (value/expiry changed here)
      - browser_cookies (snapshot: present here)
    """
    seen: Dict[Tuple[str, str, str], List[str]] = {}
    order_cache: Dict[Tuple[str, str, str], set] = {}
    for ev in evidence or []:
        url = ev.get("url")
        if not url:
            continue

        # First-seen cookies at this page
        for c in (ev.get("new_site_cookies") or []):
            k = cookie_key(c)
            if not k: 
                continue
            lst = seen.setdefault(k, [])
            cache = order_cache.setdefault(k, set())
            if url not in cache:
                lst.append(url); cache.add(url)

        # Changed cookies: record that they were seen here too
        for ch in (ev.get("changed_site_cookies") or []):
            after = ch.get("after") or {}
            k = cookie_key(after)
            if not k:
                continue
            lst = seen.setdefault(k, [])
            cache = order_cache.setdefault(k, set())
            if url not in cache:
                lst.append(url); cache.add(url)

        # Snapshot presence: include the page if cookie exists in site-scoped browser_cookies
        for c in (ev.get("browser_cookies") or []):
            k = cookie_key(c)
            if not k:
                continue
            lst = seen.setdefault(k, [])
            cache = order_cache.setdefault(k, set())
            if url not in cache:
                lst.append(url); cache.add(url)

    return seen

def cookie_name_instances(cookies: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for d in cookies:
        nm = d.get("name")
        if nm is None:
            continue
        dom = (d.get("domain") or "").lstrip(".")
        path = d.get("path") or "/"
        if nm not in lines:
            lines.append(nm)
        else:
            lines.append(f"{nm} ({dom}{path})" if dom or path else str(nm))
    return lines

# def cookie_name_instances(cookies: List[Dict[str, Any]]) -> List[str]:
#     # De-duplicate by cookie *name* only (ignore differing paths)
#     names: List[str] = []
#     seen: set = set()
#     for d in cookies:
#         nm = d.get("name")
#         if not nm or nm in seen:
#             continue
#         names.append(str(nm))
#         seen.add(nm)
#     return names

ATTR_ORDER = [
    "domain", "path", "secure", "httpOnly", "sameSite", "expires", "expires_days", "session", "size", "priority"
]

def prefs_key(preferences: Optional[Dict[str, Any]]) -> str:
    if not preferences:
        return "<no-categories>"
    order = ("analytics", "advertising", "functional")
    parts = []
    for k in order:
        if k in preferences:
            v = preferences.get(k)
            parts.append(f"{k}={'on' if v else 'off'}")
    extras = sorted([k for k in preferences.keys() if k not in order])
    for k in extras:
        v = preferences.get(k)
        parts.append(f"{k}={'on' if bool(v) else 'off'}")
    return ", ".join(parts) if parts else "<no-categories>"

def fmt_seen_at(urls: List[str], limit: int = 12) -> List[str]:
    if not urls:
        return []
    if len(urls) <= limit:
        return [f"  - seen_at_urls:"] + [f"    • {u}" for u in urls]
    head = urls[:limit]
    rest = len(urls) - limit
    return [f"  - seen_at_urls:"] + [f"    • {u}" for u in head] + [f"    • … (+{rest} more)"]

def fmt_cookie_breakdown(d: Dict[str, Any], include_value: bool, seen_map: Dict[Tuple[str, str, str], List[str]]) -> List[str]:
    lines = []
    if include_value and "value" in d:
        val = d.get("value")
        if isinstance(val, str):
            preview = val if len(val) <= 120 else (val[:120] + "…")
            lines.append(f"  - value: {preview}")
        else:
            lines.append(f"  - value: {val}")
    for k in ATTR_ORDER:
        if k in d:
            v = d.get(k)
            if k == "expires":
                iso = to_iso(v)
                if iso:
                    lines.append(f"  - expires: {v} ({iso})")
                else:
                    lines.append(f"  - expires: {v}")
            else:
                lines.append(f"  - {k}: {v}")
    for k, v in d.items():
        if k in ATTR_ORDER or k == "value":
            continue
        if v is None or (isinstance(v, str) and v.strip() == ""):
            continue
        lines.append(f"  - {k}: {v}")
    # Append where it was seen
    k = cookie_key(d)
    if k and seen_map:
        lines.extend(fmt_seen_at(seen_map.get(k, [])))
    return lines

def build_report(rows: List[Dict[str, Any]], only_action: Optional[str], max_sites: Optional[int], include_value: bool) -> str:
    buckets: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for r in rows:
        act = (r.get(CONSENT_ACTION_COL) or "unknown").strip().lower()
        if only_action and act != only_action:
            continue
        site_id = str(r.get(ID_COL))
        domain = r.get(DOMAIN_COL) or ""
        url = r.get(URL_COL) or ""

        pre = parse_cookie_list(r.get(PRE_COOKIES_COL))
        post = parse_cookie_list(r.get(POST_COOKIES_COL))
        pre_ev = parse_evidence_list(r.get(PRE_EVIDENCE_COL))
        post_ev = parse_evidence_list(r.get(POST_EVIDENCE_COL))

        pre_seen_map = build_pages_seen(pre_ev)
        post_seen_map = build_pages_seen(post_ev)

        prefs = parse_json_obj(r.get(CUSTOM_PREFS_COL))
        toggles = r.get(CUSTOM_TOGGLES_COL)
        debug = parse_json_obj(r.get(CUSTOM_DEBUG_COL))

        group_key = prefs_key(prefs) if act == "custom" else "__all__"
        b = buckets.setdefault(act, {})
        b.setdefault(group_key, []).append({
            "id": site_id,
            "domain": domain,
            "url": url,
            "pre": pre,
            "post": post,
            "pre_seen": pre_seen_map,
            "post_seen": post_seen_map,
            "prefs": prefs,
            "toggles": toggles,
            "dbg": debug,
        })

    lines: List[str] = []
    for action in sorted(buckets.keys()):
        sites = buckets[action]
        lines.append(f"CONSENT ACTION: {action}")
        lines.append("")
        for group_key in sorted(sites.keys()):
            if action == "custom":
                lines.append(f"CATEGORIES: {group_key}")
                lines.append("")
            count = 0
            for info in sites[group_key]:
                if max_sites is not None and count >= max_sites:
                    lines.append(f"... (truncated after {max_sites} sites)")
                    break
                if info.get("domain"):
                    lines.append(f"domain_name: {info['domain']}")
                if info.get("url"):
                    lines.append(f"url: {info['url']}")
                if action == "custom":
                    if info.get("prefs"):
                        lines.append(f"custom_prefs_requested: {prefs_key(info['prefs'])}")
                    if info.get("toggles") is not None:
                        lines.append(f"custom_toggles_changed: {info['toggles']}")
                    if info.get("dbg"):
                        mo = info["dbg"].get("manage_opened")
                        sv = info["dbg"].get("saved")
                        lines.append(f"custom_flow_debug: manage_opened={mo}, saved={sv}")
                lines.append("")

                pre = info["pre"]; post = info["post"]
                pre_names = cookie_name_instances(pre)
                post_names = cookie_name_instances(post)

                lines.append("pre_cookies — names:")
                if pre_names:
                    for n in pre_names:
                        lines.append(f"- {n}")
                else:
                    lines.append("- <none>")
                lines.append("")

                lines.append("post_cookies — names:")
                if post_names:
                    for n in post_names:
                        lines.append(f"- {n}")
                else:
                    lines.append("- <none>")
                lines.append("")

                label = action_label_for(action)
                lines.append(f"Before {label} — cookie count: {len(pre)}")
                lines.append(f"After {label} — cookie count: {len(post)}")
                lines.append("")

                lines.append("pre_cookies — breakdown:")
                if pre:
                    for d in pre:
                        nm = d.get("name", "<unnamed>")
                        lines.append(f"* {nm}")
                        lines.extend(fmt_cookie_breakdown(d, include_value, info["pre_seen"]))
                        lines.append("")
                else:
                    lines.append("<none>")
                lines.append("")

                lines.append("post_cookies — breakdown:")
                if post:
                    for d in post:
                        nm = d.get("name", "<unnamed>")
                        lines.append(f"* {nm}")
                        lines.extend(fmt_cookie_breakdown(d, include_value, info["post_seen"]))
                        lines.append("")
                else:
                    lines.append("<none>")
                lines.append("")

                lines.append("----")
                lines.append("")
                count += 1

        lines.append("")
    return "\n".join(lines)

def main() -> int:
    args = parse_args()
    try:
        conn = sqlite3.connect(args.db)
    except sqlite3.Error as e:
        print(f"Error opening database: {e}", file=sys.stderr)
        return 2

    try:
        rows = load_rows(conn)
        report = build_report(
            rows=rows,
            only_action=args.only_action,
            max_sites=args.max_sites,
            include_value=args.include_values,
        )
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"Report written to {args.out}")
        else:
            print(report)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        conn.close()

if __name__ == "__main__":
    sys.exit(main())