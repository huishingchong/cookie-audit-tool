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
CONSENT_ACTION_COL = "consent_action"  # e.g., 'accept' or 'reject'
CUSTOM_PREFS_COL = "custom_prefs_requested"
CUSTOM_TOGGLES_COL = "custom_toggles_changed"
CUSTOM_DEBUG_COL = "custom_flow_debug"

def action_label_for(action: str) -> str:
    action = (action or "").strip().lower()
    if action == "accept":
        return "Accept"
    if action == "reject":
        return "Reject"
    if action =="custom":
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
    """Convert a unix timestamp to ISO-8601 (UTC) if plausible; return None for missing/invalid values."""
    try:
        t = float(ts)
        if t <= 0:
            return None
        return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()
    except Exception:
        return None


def load_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    cols = [ID_COL, DOMAIN_COL, URL_COL, PRE_COOKIES_COL, POST_COOKIES_COL, CONSENT_ACTION_COL, CUSTOM_PREFS_COL, CUSTOM_TOGGLES_COL, CUSTOM_DEBUG_COL]
    sql = f'SELECT {", ".join([f"""\"{c}\"""" for c in cols])} FROM "{TABLE}"'
    cur = conn.execute(sql)
    rows = []
    for r in cur.fetchall():
        rows.append({c: r[i] for i, c in enumerate(cols)})
    return rows


def parse_cookie_list(raw: Optional[str]) -> List[Dict[str, Any]]:
    if not raw:
        return []
    s = raw.strip()
    if not s:
        return []
    try:
        j = json.loads(s)
        if isinstance(j, list):
            # Ensure each cookie is a dict
            return [d for d in j if isinstance(d, dict)]
        # Unexpected format; fallback to empty
        return []
    except Exception:
        return []

def parse_json_obj(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        j = json.loads(raw)
        if isinstance(j, dict):
            return j
        return None
    except Exception:
        return None

def cookie_name_list(cookies: List[Dict[str, Any]]) -> List[str]:
    names = []
    for d in cookies:
        nm = d.get("name")
        if nm is None:
            continue
        names.append(str(nm))
    # keep original order but drop exact duplicates while retaining first occurrence
    seen = set()
    unique_ordered = []
    for n in names:
        if n not in seen:
            seen.add(n)
            unique_ordered.append(n)
    return unique_ordered


ATTR_ORDER = [
    "domain", "path", "secure", "httpOnly", "sameSite", "expires", "expires_days", "session", "size", "priority"
]

def prefs_key(preferences: Optional[Dict[str, Any]]) -> str:
    """
    Build a categories string to group custom flows.
    Only prints keys present; default order: analytics, advertising, functional.
    """
    if not preferences:
        return "<no-categories>"
    order = ("analytics", "advertising", "functional")
    parts = []
    for k in order:
        if k in preferences:
            v = preferences.get(k)
            parts.append(f"{k}={'on' if v else 'off'}")
    # Include any extra unexpected keys, deterministic order
    extras = sorted([k for k in preferences.keys() if k not in order])
    for k in extras:
        v = preferences.get(k)
        parts.append(f"{k}={'on' if bool(v) else 'off'}")
    return ", ".join(parts) if parts else "<no-categories>"

def fmt_cookie_breakdown(d: Dict[str, Any], include_value: bool) -> List[str]:
    """Return lines for the bullet-list of attributes (without the cookie name line)."""
    lines = []
    # Value is optional (can be long / sensitive); include on request
    if include_value and "value" in d:
        val = d.get("value")
        if isinstance(val, str):
            preview = val if len(val) <= 120 else (val[:120] + "…")
            lines.append(f"  - value: {preview}")
        else:
            lines.append(f"  - value: {val}")
    # Standard attributes in a consistent order
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
    # Print any remaining non-empty attributes that aren't in ATTR_ORDER or value
    for k, v in d.items():
        if k in ATTR_ORDER or k == "value":
            continue
        if v is None or (isinstance(v, str) and v.strip() == ""):
            continue
        lines.append(f"  - {k}: {v}")
    return lines


def build_report(rows: List[Dict[str, Any]], only_action: Optional[str], max_sites: Optional[int], include_value: bool) -> str:
    # Categorise by consent_action (accept, reject, or None->'unknown')
    buckets: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for r in rows:
        act = (r.get(CONSENT_ACTION_COL) or "unknown").strip().lower()
        if only_action and act != only_action:
            continue
        site_id = str(r.get(ID_COL))
        domain = r.get(DOMAIN_COL) or ""
        url = r.get(URL_COL) or ""

        pre = parse_cookie_list(r.get(PRE_COOKIES_COL))
        post = parse_cookie_list(r.get(POST_COOKIES_COL))

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
            "prefs": prefs,
            "toggles": toggles,
            "dbg": debug,
        })

    lines: List[str] = []
    for action in sorted(buckets.keys()):
        sites = buckets[action]
        lines.append(f"CONSENT ACTION: {action}")
        lines.append("")
        # Iterate groups (for custom it is each categories combo)
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
                # Optional minimal custom details (only printed for custom)
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
            

                # pre/post lists
                pre = info["pre"]
                post = info["post"]

                pre_names = cookie_name_list(pre)
                post_names = cookie_name_list(post)

                # Names lists (unchanged)
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

                # Action-specific counts before the breakdowns
                label = action_label_for(action)  # action is the consent bucket key
                lines.append(f"Before {label} — cookie count: {len(pre)}")
                lines.append(f"After {label} — cookie count: {len(post)}")
                lines.append("")

                # Breakdown (NAME as the heading, then indented bullets)
                lines.append("pre_cookies — breakdown:")
                if pre:
                    for d in pre:
                        nm = d.get("name", "<unnamed>")
                        lines.append(f"* {nm}")
                        lines.extend(fmt_cookie_breakdown(d, include_value))  # prints "  - domain: ...", etc.
                        lines.append("")  # spacer between cookies
                else:
                    lines.append("<none>")
                lines.append("")

                lines.append("post_cookies — breakdown:")
                if post:
                    for d in post:
                        nm = d.get("name", "<unnamed>")
                        lines.append(f"* {nm}")
                        lines.extend(fmt_cookie_breakdown(d, include_value))
                        lines.append("")
                else:
                    lines.append("<none>")
                lines.append("")

                lines.append("----")
                lines.append("")
                count += 1

        lines.append("")  # extra space between action buckets
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
            include_value=args.include_values if hasattr(args, "include_values") else args.include_values,
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
