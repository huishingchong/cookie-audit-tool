#!/usr/bin/env python3
"""
classification.py — deterministic cookie classifier and reporter
(accept/reject/custom compatible; single Excel workbook; expiry at crawl time)
"""

import os, re, io, json, argparse, sqlite3
import datetime as dt
from typing import Optional, List, Dict, Tuple, Any
import pandas as pd
import yaml
from consentcrawl.domain_utils import registrable_domain

# Utilities
def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

def _to_epoch_seconds(isoish: Optional[str]) -> Optional[int]:
    if not isoish:
        return None
    try:
        s = str(isoish).strip()
        if not s:
            return None
        s = s.replace("Z", "+00:00")
        t = dt.datetime.fromisoformat(s)
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return int(t.timestamp())
    except Exception:
        return None

def _safe_json_list(value: Any) -> List[dict]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return value.get("cookies", [])
    s = str(value).strip()
    if not s:
        return []
    for attempt in (s, s.replace("'", '"')):
        try:
            x = json.loads(attempt)
            if isinstance(x, list):
                return x
            if isinstance(x, dict) and "cookies" in x:
                return list(x["cookies"])
        except Exception:
            pass
    return []

def _parse_expires_ts(cookie_obj: dict) -> Optional[int]:
    exp = (cookie_obj.get("expires") or cookie_obj.get("Expires")
           or cookie_obj.get("expiry") or cookie_obj.get("Expiry"))
    if exp in (None, "", 0, "0"):
        return None
    try:
        if isinstance(exp, (int, float)):
            return int(exp)
        s = str(exp)
        for attempt in (s, s.replace("Z", "+00:00")):
            try:
                t = dt.datetime.fromisoformat(attempt)
                if t.tzinfo is None:
                    t = t.replace(tzinfo=dt.timezone.utc)
                return int(t.timestamp())
            except Exception:
                pass
        return None
    except Exception:
        return None

def _cookie_flags(cookie_obj: dict) -> Tuple[int, int, Optional[str]]:
    sec = 1 if bool(cookie_obj.get("secure") or cookie_obj.get("Secure")) else 0
    http = 1 if bool(cookie_obj.get("httpOnly") or cookie_obj.get("HttpOnly")) else 0
    samesite = cookie_obj.get("sameSite") or cookie_obj.get("SameSite")
    if samesite is not None:
        samesite = str(samesite)
    return sec, http, samesite

def _map_category(cat: Optional[str]) -> str:
    if not cat:
        return "uncategorised"
    c = str(cat).strip().lower()
    if c in ("necessary","strictly necessary","essential","strictly_necessary","required"):
        return "necessary"
    if c in ("functional","functionality","preferences","personalization","personalisation"):
        return "functional"
    if c in ("analytics","statistics","performance"):
        return "analytics"
    if c in ("advertising","marketing","ads","targeting"):
        return "advertising"
    return c

def _norm_header(h: str) -> str:
    h = (h or "").strip().lower()
    h = re.sub(r"[^a-z0-9]+", "_", h)
    h = re.sub(r"_+", "_", h).strip("_")
    return h

# rules & OCD loaders

def load_rules(rules_path: str) -> Tuple[dict, List[dict]]:
    with open(rules_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    meta = data.get("_meta", {})
    rules = data.get("rules", [])
    return meta, rules

def _compile_rule(rule: dict) -> dict:
    name = rule.get("name") or ""
    category = rule.get("category") or "uncategorised"
    vendor = rule.get("vendor") or None
    confidence = rule.get("confidence") or "medium"
    rule_id = rule.get("id") or name

    rx = rule.get("regex")
    wc = rule.get("wildcard")
    exact = rule.get("cookie")

    # support current rules file (name/domain)
    name_re = rule.get("name_re")
    domain_re = rule.get("domain_re")

    if rx:
        try:
            patt = re.compile(rx, flags=re.I)
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": confidence, "type": "regex", "compiled": patt,
                    "name": name}
        except re.error:
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": "low", "type": "bad_regex", "compiled": None,
                    "name": name}
    if wc:
        esc = re.escape(wc).replace("\\*", ".*")
        try:
            patt = re.compile(f"^{esc}$", flags=re.I)
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": confidence, "type": "wildcard", "compiled": patt,
                    "name": name}
        except re.error:
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": "low", "type": "bad_wildcard", "compiled": None,
                    "name": name}
    if exact is not None:
        val = str(exact).lower()
        return {"rule_id": rule_id, "category": category, "vendor": vendor,
                "confidence": confidence, "type": "exact", "value": val,
                "name": name}

    if name_re:
        try:
            name_patt = re.compile(str(name_re), flags=re.I)
            dom_patt = re.compile(str(domain_re), flags=re.I) if domain_re else None
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": confidence, "type": "name_domain",
                    "name_patt": name_patt, "domain_patt": dom_patt,
                    "name": name}
        except re.error:
            return {"rule_id": rule_id, "category": category, "vendor": vendor,
                    "confidence": "low", "type": "bad_name_domain",
                    "name_patt": None, "domain_patt": None, "name": name}

    return {"rule_id": rule_id, "category": "uncategorised", "vendor": vendor,
            "confidence": "low", "type": "none", "compiled": None, "name": name}

def load_ocd(ocd_path: Optional[str]) -> Tuple[Dict[str, dict], List[dict], pd.DataFrame]:
    """
    Load Open Cookie Database style CSV/JSON with flexible headers.
    Returns:
      - exact index: dict[name_lower] -> metadata
      - regex rules: list of {name_regex (compiled), meta}
      - raw DataFrame
    """
    if not ocd_path:
        return {}, [], pd.DataFrame()

    if ocd_path.lower().endswith(".csv"):
        df = pd.read_csv(ocd_path)
    else:
        with open(ocd_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if raw.startswith("["):
            df = pd.read_json(io.StringIO(raw))
        else:
            df = pd.read_csv(io.StringIO(raw))

    if df.empty:
        return {}, [], df

    cols = { _norm_header(c): c for c in df.columns }

    # cookie name column
    for candidate in ["name","cookie_name","cookie","cookie_data_key_name","cookie_data_key","cookie___data_key_name","cookie___data_key","cookie___data_key_name"]:
        if candidate in cols:
            name_col = cols[candidate]
            break
    else:
        name_col = next((c for c in df.columns if re.search(r'cookie.*name', c, re.I)), df.columns[0])

    # category/purpose
    for candidate in ["category","purpose"]:
        if candidate in cols:
            cat_col = cols[candidate]
            break
    else:
        cat_col = next((c for c in df.columns if re.search(r'category|purpose', c, re.I)), None)

    # vendor/provider/platform
    for candidate in ["vendor","provider","platform","data_controller"]:
        if candidate in cols:
            vendor_col = cols[candidate]
            break
    else:
        vendor_col = None

    wildcard_col = cols.get("wildcard_match") or next((c for c in df.columns if re.search(r'wildcard', c, re.I)), None)

    exact_idx : Dict[str, dict] = {}
    regex_rules : List[dict] = []

    for _, row in df.iterrows():
        nm_raw = row.get(name_col)
        if pd.isna(nm_raw):
            continue
        nm = str(nm_raw).strip()
        if not nm:
            continue
        cat_raw = row.get(cat_col) if cat_col else None
        mapped = _map_category(str(cat_raw)) if cat_raw is not None else "uncategorised"
        ven = str(row.get(vendor_col)).strip() if vendor_col else None
        meta = {
            "ocd_name": nm,
            "ocd_category": str(cat_raw) if cat_raw is not None else None,
            "ocd_category_mapped": mapped,
            "vendor": ven or None
        }
        wc_flag = row.get(wildcard_col) if wildcard_col in (df.columns) else None
        try:
            is_wc = (int(wc_flag) == 1) if wc_flag is not None and str(wc_flag).strip() != "" else False
        except Exception:
            is_wc = False

        if is_wc or ("*" in nm):
            esc = re.escape(nm).replace("\\*", ".*")
            try:
                patt = re.compile(f"^{esc}$", flags=re.I)
                regex_rules.append({"name_regex": patt, "meta": meta})
            except re.error:
                exact_idx[nm.lower()] = meta
        else:
            exact_idx[nm.lower()] = meta

    return exact_idx, regex_rules, df

# Schema
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cookie_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  crawl_id INTEGER,
  phase TEXT,
  domain_name TEXT,
  url TEXT,
  consent_action TEXT,
  consent_result TEXT,
  cookie_name TEXT,
  cookie_domain TEXT,
  etld1 TEXT,
  category TEXT,
  vendor TEXT,
  confidence TEXT,
  source TEXT,
  rule_id TEXT,
  ocd_name TEXT,
  ocd_category TEXT,
  ocd_category_mapped TEXT,
  disagreement TEXT,
  expires_ts INTEGER,
  expiry_days REAL,             -- days relative to crawl time if available, else relative to now
  secure INTEGER,
  http_only INTEGER,
  same_site TEXT,
  observed_at TEXT
);

CREATE TABLE IF NOT EXISTS pre_consent_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  crawl_id INTEGER,
  domain_name TEXT,
  url TEXT,
  phase TEXT,
  cookie_name TEXT,
  category TEXT,
  rule_code TEXT,
  severity TEXT,
  evidence TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS post_consent_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  crawl_id INTEGER,
  domain_name TEXT,
  url TEXT,
  phase TEXT,
  cookie_name TEXT,
  cookie_domain TEXT,
  etld1 TEXT,
  category TEXT,
  confidence TEXT,
  source TEXT,
  consent_action TEXT,
  consent_result TEXT,
  policy_json TEXT,
  issue_code TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS domain_category_summary (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_name TEXT,
  category TEXT,
  cookie_count INTEGER
);
"""

def migrate_schema(conn: sqlite3.Connection, fresh: bool = False) -> None:
    cur = conn.cursor
    cur = conn.cursor()
    if fresh:
        cur.executescript("""
        DROP TABLE IF EXISTS cookie_observations;
        DROP TABLE IF EXISTS pre_consent_issues;
        DROP TABLE IF EXISTS post_consent_issues;
        DROP TABLE IF EXISTS domain_category_summary;
        """)
    cur.executescript(SCHEMA_SQL)
    conn.commit()

## CLASSIFICATION
def _classify_one(name: str, domain: str, rules_idx: List[dict],
                  ocd_exact: Dict[str, dict], ocd_regex: List[dict]) -> Tuple[dict, str]:
    nm = (name or "").strip().lower()
    dm = (domain or "").strip().lower()

    r_hit = None
    for r in rules_idx:
        t = r.get("type")
        if t == "exact":
            if nm == r.get("value"):
                r_hit = r; break
        elif t in ("regex","wildcard"):
            patt = r.get("compiled")
            if patt and patt.search(nm):
                r_hit = r; break
        elif t == "name_domain":
            np, dp = r.get("name_patt"), r.get("domain_patt")
            if np and np.search(nm) and (dp.search(dm) if dp else True):
                r_hit = r; break

    o_hit = ocd_exact.get(nm)
    if not o_hit and ocd_regex:
        for rr in ocd_regex:
            patt = rr.get("name_regex")
            if patt and patt.search(nm):
                o_hit = rr.get("meta")
                break

    # precedence logic:
    # 1) If rules hit with a mapped category (!= uncategorised), use rules.
    #    If OCD also hit and disagrees, mark conflict but still keep rules category.
    # 2) Else if OCD hit with a mapped category, use OCD.
    # 3) Else uncategorised.
    ocat = (o_hit or {}).get("ocd_category_mapped")
    rcat = _map_category((r_hit or {}).get("category"))

    if r_hit and rcat and rcat != "uncategorised":
        disagree = (o_hit is not None) and (ocat is not None) and (rcat != ocat)
        return ({
            "category": rcat,
            "vendor": r_hit.get("vendor") or (o_hit.get("vendor") if o_hit else None),
            "rule_id": r_hit.get("rule_id"),
            "source": "conflict" if disagree else "rules",
            "ocd_name": (o_hit.get("ocd_name") if o_hit else None),
            "ocd_category": (o_hit.get("ocd_category") if o_hit else None),
            "ocd_category_mapped": (ocat if o_hit else None),
            "disagreement": "rules_vs_ocd" if disagree else None,
            "confidence": r_hit.get("confidence", "medium"),
        }, "medium")

    if o_hit and ocat:
        return ({
            "category": ocat,
            "vendor": o_hit.get("vendor"),
            "rule_id": None,
            "source": "ocd",
            "ocd_name": o_hit.get("ocd_name"),
            "ocd_category": o_hit.get("ocd_category"),
            "ocd_category_mapped": ocat,
            "disagreement": None,
            "confidence": "medium",
        }, "medium")

    # fallback: rules hit but no meaningful category → try to keep vendor at least
    if r_hit and (not rcat or rcat == "uncategorised"):
        return ({
            "category": "uncategorised",
            "vendor": r_hit.get("vendor"),
            "rule_id": r_hit.get("rule_id"),
            "source": "rules",
            "ocd_name": (o_hit.get("ocd_name") if o_hit else None),
            "ocd_category": (o_hit.get("ocd_category") if o_hit else None),
            "ocd_category_mapped": (ocat if o_hit else None),
            "disagreement": None,
            "confidence": r_hit.get("confidence", "medium"),
        }, "low")

    return ({
        "category": "uncategorised",
        "vendor": None,
        "rule_id": None,
        "source": "none",
        "ocd_name": None,
        "ocd_category": None,
        "ocd_category_mapped": None,
        "disagreement": None,
        "confidence": "low",
    }, "low")

def _policy_from_action(consent_action: str, custom_prefs_json: Optional[str]) -> dict:
    a = (consent_action or "").strip().lower()
    if a in ("accept","accept-all","allow","allow-all"):
        return {"analytics": True, "advertising": True, "functional": True}
    if a in ("reject","reject-all","deny","deny-all","refuse"):
        return {"analytics": False, "advertising": False, "functional": False}
    if a in ("custom","customise","customize","preferences"):
        try:
            p = json.loads(custom_prefs_json) if custom_prefs_json else {}
            return {
                "analytics": bool(p.get("analytics")) if p.get("analytics") is not None else False,
                "advertising": bool(p.get("advertising")) if p.get("advertising") is not None else False,
                "functional": bool(p.get("functional")) if p.get("functional") is not None else False,
            }
        except Exception:
            return {"analytics": False, "advertising": False, "functional": False}
    return {"analytics": False, "advertising": False, "functional": False}

def _post_issue_code(consent_action: str, category: str, policy: dict) -> str:
    a = (consent_action or "").strip().lower()
    cat = (category or "").strip().lower()
    if a in ("reject","reject-all","deny","deny-all","refuse"):
        return f"{cat}_set_after_reject"
    if a in ("custom","customise","customize","preferences"):
        allowed = bool(policy.get(cat, False))
        if not allowed:
            return f"{cat}_set_when_off"
    return "set-against-policy"

def _record_pre_issue(cur, crawl_id: int, domain_name: str, url: str, cookie_name: str, category: str) -> None:
    cur.execute("""
        INSERT INTO pre_consent_issues(crawl_id,domain_name,url,phase,cookie_name,category,rule_code,severity,evidence,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)
    """, (crawl_id, domain_name, url, "pre", cookie_name, category, "set-before-consent", "high", "pre-phase cookie observed", _now_iso()))

def _record_post_issue(cur, row: dict, policy: dict) -> None:
    issue = _post_issue_code(row.get("consent_action"), row.get("category"), policy)
    cur.execute("""
        INSERT INTO post_consent_issues(crawl_id,domain_name,url,phase,cookie_name,cookie_domain,etld1,category,confidence,source,consent_action,consent_result,policy_json,issue_code,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        row["crawl_id"], row["domain_name"], row["url"], row["phase"],
        row["cookie_name"], row["cookie_domain"], row["etld1"], row["category"],
        row["confidence"], row["source"], row["consent_action"], row["consent_result"],
        json.dumps(policy, ensure_ascii=False), issue, _now_iso()
    ))

def _insert_observation(cur, row: dict) -> None:
    cur.execute("""
        INSERT INTO cookie_observations(
            crawl_id, phase, domain_name, url, consent_action, consent_result,
            cookie_name, cookie_domain, etld1, category, vendor, confidence, source, rule_id,
            ocd_name, ocd_category, ocd_category_mapped, disagreement,
            expires_ts, expiry_days, secure, http_only, same_site, observed_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        row["crawl_id"], row["phase"], row["domain_name"], row["url"], row.get("consent_action"), row.get("consent_result"),
        row["cookie_name"], row["cookie_domain"], row["etld1"], row["category"], row.get("vendor"), row["confidence"], row["source"], row.get("rule_id"),
        row.get("ocd_name"), row.get("ocd_category"), row.get("ocd_category_mapped"), row.get("disagreement"),
        row.get("expires_ts"), row.get("expiry_days"), row.get("secure"), row.get("http_only"), row.get("same_site"),
        _now_iso()
    ))

def _observations_from_cookie_list(
    cookies: List[dict], page_etld1: str, crawl_id: int, phase: str,
    domain_name: str, url: str, consent_action: Optional[str], consent_result: Optional[str],
    rules_idx: List[dict], ocd_exact: Dict[str, dict], ocd_regex: List[dict],
    crawl_ts: Optional[int] = None
) -> List[dict]:
    out = []
    now_ts = int(dt.datetime.now(dt.timezone.utc).timestamp())
    for c in cookies:
        nm = str(c.get("name") or c.get("Name") or c.get("key") or "").strip()
        if not nm:
            continue
        cd = str(c.get("domain") or c.get("Domain") or "").strip() or domain_name
        etld1 = registrable_domain(cd) or registrable_domain(domain_name) or page_etld1
        cinfo, conf = _classify_one(nm, cd, rules_idx, ocd_exact, ocd_regex)
        exp_ts = _parse_expires_ts(c)
        base = crawl_ts if crawl_ts is not None else now_ts
        expiry_days = None
        if exp_ts is not None:
            expiry_days = (exp_ts - base) / 86400.0
        sec, httponly, samesite = _cookie_flags(c)
        out.append({
            "crawl_id": crawl_id,
            "phase": phase,
            "domain_name": domain_name,
            "url": url,
            "consent_action": consent_action,
            "consent_result": consent_result,
            "cookie_name": nm,
            "cookie_domain": cd,
            "etld1": etld1,
            "category": cinfo.get("category"),
            "vendor": cinfo.get("vendor"),
            "confidence": cinfo.get("confidence", conf),
            "source": cinfo.get("source"),
            "rule_id": cinfo.get("rule_id"),
            "ocd_name": cinfo.get("ocd_name"),
            "ocd_category": cinfo.get("ocd_category"),
            "ocd_category_mapped": cinfo.get("ocd_category_mapped"),
            "disagreement": cinfo.get("disagreement"),
            "expires_ts": exp_ts,
            "expiry_days": expiry_days,  # relative to crawl time if available
            "secure": sec,
            "http_only": httponly,
            "same_site": samesite,
        })
    return out

# ---------------------------- query builders for Excel/CSV ----------------------------

def _df_classifier_decisions(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("""
        SELECT crawl_id, domain_name, url, phase, cookie_name, cookie_domain, etld1,
               category, vendor, confidence, source, rule_id, ocd_name,
               ocd_category_mapped, ocd_category, disagreement, consent_action, consent_result,
               expires_ts, expiry_days, secure, http_only, same_site
        FROM cookie_observations
        ORDER BY domain_name, phase, cookie_name
    """, conn)

def _df_domain_category_summary(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("""
        SELECT domain_name, category, SUM(1) AS cookie_count
        FROM cookie_observations
        GROUP BY domain_name, category
        ORDER BY domain_name, category
    """, conn)

def _df_pre_consent_issues(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("""
        SELECT crawl_id, domain_name, url, phase, cookie_name, category, rule_code, severity, evidence, created_at
        FROM pre_consent_issues
        ORDER BY domain_name, phase, cookie_name
    """, conn)

def _df_conflicts_review(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("""
        SELECT domain_name, url, phase, cookie_name, cookie_domain, etld1,
               category AS final_category,
               category AS rules_category,
               ocd_category_mapped AS ocd_category,
               confidence, source
        FROM cookie_observations
        WHERE source='conflict'
        ORDER BY domain_name, phase, cookie_name
    """, conn)

def _df_unknowns_review(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql_query("""
        SELECT lower(cookie_name) AS cookie_name, etld1, phase
        FROM cookie_observations
        WHERE source='none' OR lower(category)='uncategorised'
    """, conn)
    if df.empty:
        return pd.DataFrame(columns=["cookie_name","total_count","example_domains","phases"])
    def top_domains(series, k=5):
        return ", ".join(series.value_counts().head(k).index.tolist())
    agg = df.groupby("cookie_name").agg(
        total_count=("cookie_name","size"),
        example_domains=("etld1", top_domains),
        phases=("phase", lambda s: ", ".join(sorted(set(s))))
    ).reset_index()
    agg.sort_values(by="total_count", ascending=False, inplace=True)
    return agg

def _df_post_consent_issues(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql_query("""
        SELECT crawl_id, domain_name, url, phase, cookie_name, cookie_domain, etld1,
               category, confidence, source, consent_action, consent_result, policy_json, issue_code, created_at
        FROM post_consent_issues
        ORDER BY domain_name, phase, cookie_name
    """, conn)
    if df.empty:
        return df
    def _pf(x):
        try:
            p = json.loads(x) if isinstance(x, str) else (x or {})
        except Exception:
            p = {}
        return pd.Series({
            "analytics_allowed": bool(p.get("analytics", False)),
            "advertising_allowed": bool(p.get("advertising", False)),
            "functional_allowed": bool(p.get("functional", False)),
        })
    flags = df["policy_json"].apply(_pf)
    df = pd.concat([df, flags], axis=1)
    def _fix_issue(row):
        if row.get("issue_code") and row["issue_code"] != "set-against-policy":
            return row["issue_code"]
        try:
            p = json.loads(row["policy_json"]) if isinstance(row["policy_json"], str) else (row["policy_json"] or {})
        except Exception:
            p = {}
        a = (row.get("consent_action") or "").strip().lower()
        cat = (row.get("category") or "").strip().lower()
        if a in ("reject","reject-all","deny","deny-all","refuse"):
            return f"{cat}_set_after_reject"
        if a in ("custom","customise","customize","preferences"):
            allowed = bool(p.get(cat, False))
            if not allowed:
                return f"{cat}_set_when_off"
        return "set-against-policy"
    df["issue_code"] = df.apply(_fix_issue, axis=1)
    return df

def _df_pre_issues_unique(conn: sqlite3.Connection) -> pd.DataFrame:
    pre = pd.read_sql_query("""
        SELECT pci.domain_name, pci.cookie_name, pci.category,
               co.consent_action, co.expires_ts, co.expiry_days
        FROM pre_consent_issues pci
        LEFT JOIN cookie_observations co
          ON co.domain_name=pci.domain_name
         AND co.cookie_name=pci.cookie_name
         AND co.phase='pre'
    """, conn)
    if pre.empty:
        return pd.DataFrame(columns=["domain_name","cookie_name","category","actions","occurrences","expiry_label"])
    def _expiry_label_from_group(expires_ts_series: pd.Series, expiry_days_series: pd.Series) -> str:
        if expires_ts_series.dropna().empty and expiry_days_series.dropna().empty:
            return ""
        if any(ts in (0, None) for ts in expires_ts_series.tolist()):
            return "session"
        try:
            days = float(expiry_days_series.dropna().min())
            return f"{max(0, int(round(days)))}d"
        except Exception:
            return ""
    rows = []
    for keys, df in pre.groupby(["domain_name","cookie_name","category"], dropna=False):
        domain_name, cookie_name, category = keys
        actions = sorted(set([a for a in df["consent_action"].dropna().astype(str).tolist() if a]))
        expiry_label = _expiry_label_from_group(df["expires_ts"], df["expiry_days"])
        rows.append({
            "domain_name": domain_name,
            "cookie_name": cookie_name,
            "category": category,
            "actions": ", ".join(actions) if actions else "",
            "occurrences": int(len(df)),
            "expiry_label": expiry_label,
        })
    return pd.DataFrame(rows).sort_values(["domain_name","cookie_name","category"])

def _df_post_issues_unique(conn: sqlite3.Connection) -> pd.DataFrame:
    post = pd.read_sql_query("""
        SELECT pci.domain_name, pci.cookie_name, pci.category, pci.consent_action,
               co.expires_ts, co.expiry_days
        FROM post_consent_issues pci
        LEFT JOIN cookie_observations co
          ON co.domain_name=pci.domain_name
         AND co.cookie_name=pci.cookie_name
         AND co.phase='post'
    """, conn)
    if post.empty:
        return pd.DataFrame(columns=["domain_name","cookie_name","category","actions","occurrences","expiry_label"])
    def _expiry_label_from_group(expires_ts_series: pd.Series, expiry_days_series: pd.Series) -> str:
        if expires_ts_series.dropna().empty and expiry_days_series.dropna().empty:
            return ""
        if any(ts in (0, None) for ts in expires_ts_series.tolist()):
            return "session"
        try:
            days = float(expiry_days_series.dropna().min())
            return f"{max(0, int(round(days)))}d"
        except Exception:
            return ""
    rows = []
    for keys, df in post.groupby(["domain_name","cookie_name","category"], dropna=False):
        domain_name, cookie_name, category = keys
        actions = sorted(set([a for a in df["consent_action"].dropna().astype(str).tolist() if a]))
        expiry_label = _expiry_label_from_group(df["expires_ts"], df["expiry_days"])
        rows.append({
            "domain_name": domain_name,
            "cookie_name": cookie_name,
            "category": category,
            "actions": ", ".join(actions) if actions else "",
            "occurrences": int(len(df)),
            "expiry_label": expiry_label,
        })
    return pd.DataFrame(rows).sort_values(["domain_name","cookie_name","category"])

def _df_cookie_summary(conn: sqlite3.Connection) -> pd.DataFrame:
    preu = _df_pre_issues_unique(conn)
    postu = _df_post_issues_unique(conn)
    unk = pd.read_sql_query("""
        SELECT cookie_name, etld1, phase
        FROM cookie_observations
        WHERE source='none' OR lower(category)='uncategorised'
    """, conn)
    rows = []
    if not preu.empty:
        for _, r in preu.iterrows():
            rows.append({"type": "pre_issue", **r.to_dict()})
    if not postu.empty:
        for _, r in postu.iterrows():
            rows.append({"type": "post_issue", **r.to_dict()})
    if not unk.empty:
        for cookie_key, g in unk.groupby("cookie_name", dropna=False):
            key = "" if pd.isna(cookie_key) else str(cookie_key)
            rows.append({
                "type": "unknown",
                "domain_name": "",
                "cookie_name": key,
                "category": "uncategorised",
                "actions": "",
                "occurrences": int(len(g)),
                "expiry_label": "",
            })
    cols = ["type","domain_name","cookie_name","category","actions","occurrences","expiry_label"]
    return pd.DataFrame(rows, columns=cols).sort_values(["type","domain_name","cookie_name"])

def _df_policy_matrix(conn: sqlite3.Connection) -> pd.DataFrame:
    cur = conn.cursor()
    cols = [c[1].lower() for c in cur.execute("PRAGMA table_info('crawl_results')").fetchall()]
    has_prefs = "custom_prefs_requested" in cols
    base_sql = """
        SELECT co.domain_name, co.cookie_name, co.category, co.phase,
               cr.consent_action {extra}
        FROM cookie_observations co
        JOIN crawl_results cr ON cr.id = co.crawl_id
    """
    extra = ", cr.custom_prefs_requested" if has_prefs else ""
    df = pd.read_sql_query(base_sql.format(extra=extra), conn)
    if df.empty:
        return pd.DataFrame(columns=[
            "domain_name","cookie_name","category",
            "pre_seen","post_accept_seen","post_reject_seen",
            "post_custom_analytics_off_seen","post_custom_advertising_off_seen","post_custom_functional_off_seen"
        ])
    def _norm_action(a: str) -> str:
        a = (a or "").lower()
        if "accept" in a or "allow" in a:
            return "accept"
        if "reject" in a or "deny" in a or "refuse" in a:
            return "reject"
        return a
    df["consent_action_norm"] = df["consent_action"].astype(str).apply(_norm_action)
    if has_prefs:
        def prefs_flags(js):
            if js is None or js == "":
                return pd.Series({"custom_analytics_off": False, "custom_advertising_off": False, "custom_functional_off": False})
            try:
                p = json.loads(js) if not isinstance(js, dict) else js
            except Exception:
                p = {}
            return pd.Series({
                "custom_analytics_off": (p.get("analytics") is False),
                "custom_advertising_off": (p.get("advertising") is False),
                "custom_functional_off": (p.get("functional") is False),
            })
        flags = df["custom_prefs_requested"].apply(prefs_flags)
        df = pd.concat([df, flags], axis=1)
    else:
        df["custom_analytics_off"] = False
        df["custom_advertising_off"] = False
        df["custom_functional_off"] = False
    rows = []
    for (dn, cn, cat), grp in df.groupby(["domain_name","cookie_name","category"], dropna=False):
        rows.append({
            "domain_name": dn, "cookie_name": cn, "category": cat,
            "pre_seen": bool((grp["phase"]=="pre").any()),
            "post_accept_seen": bool(((grp["phase"]=="post") & (grp["consent_action_norm"]=="accept")).any()),
            "post_reject_seen": bool(((grp["phase"]=="post") & (grp["consent_action_norm"]=="reject")).any()),
            "post_custom_analytics_off_seen": bool(((grp["phase"]=="post") & grp["custom_analytics_off"]).any()),
            "post_custom_advertising_off_seen": bool(((grp["phase"]=="post") & grp["custom_advertising_off"]).any()),
            "post_custom_functional_off_seen": bool(((grp["phase"]=="post") & grp["custom_functional_off"]).any()),
        })
    return pd.DataFrame(rows).sort_values(["domain_name","cookie_name","category"])

def _df_cookie_inventory(conn: sqlite3.Connection) -> pd.DataFrame:
    df = pd.read_sql_query("""
        SELECT co.domain_name, co.url, co.phase,
               co.cookie_name, co.cookie_domain, co.etld1,
               co.category, co.vendor, co.confidence, co.source,
               co.expires_ts, co.expiry_days, co.secure, co.http_only, co.same_site,
               cr.consent_action, cr.custom_prefs_requested
        FROM cookie_observations co
        JOIN crawl_results cr ON cr.id = co.crawl_id
    """, conn)
    if df.empty:
        return pd.DataFrame(columns=[
            "domain_name","cookie_name","category","vendor","source","confidence",
            "cookie_domain","etld1","first_seen_url","min_expiry_days","secure","http_only","same_site",
            "pre_seen","post_accept_seen","post_reject_seen",
            "post_custom_analytics_off_seen","post_custom_advertising_off_seen","post_custom_functional_off_seen"
        ])
    def _norm_action(a: str) -> str:
        a = (a or "").lower()
        if "accept" in a or "allow" in a:
            return "accept"
        if "reject" in a or "deny" in a or "refuse" in a:
            return "reject"
        return a
    df["consent_action_norm"] = df["consent_action"].astype(str).apply(_norm_action)
    def _flags(js):
        try:
            p = json.loads(js) if isinstance(js, str) else (js or {})
        except Exception:
            p = {}
        return pd.Series({
            "custom_analytics_off": (p.get("analytics") is False),
            "custom_advertising_off": (p.get("advertising") is False),
            "custom_functional_off": (p.get("functional") is False),
        })
    flags = df["custom_prefs_requested"].apply(_flags)
    df = pd.concat([df, flags], axis=1)
    rows = []
    for (dn, cn, cat), grp in df.groupby(["domain_name","cookie_name","category"], dropna=False):
        rows.append({
            "domain_name": dn,
            "cookie_name": cn,
            "category": cat,
            "vendor": grp["vendor"].dropna().iloc[0] if not grp["vendor"].dropna().empty else None,
            "source": grp["source"].dropna().iloc[0] if not grp["source"].dropna().empty else None,
            "confidence": grp["confidence"].dropna().iloc[0] if not grp["confidence"].dropna().empty else None,
            "cookie_domain": grp["cookie_domain"].dropna().iloc[0] if not grp["cookie_domain"].dropna().empty else None,
            "etld1": grp["etld1"].dropna().iloc[0] if not grp["etld1"].dropna().empty else None,
            "first_seen_url": grp["url"].dropna().iloc[0] if not grp["url"].dropna().empty else None,
            "min_expiry_days": float(grp["expiry_days"].dropna().min()) if not grp["expiry_days"].dropna().empty else None,
            "secure": int(grp["secure"].max()) if not grp["secure"].dropna().empty else None,
            "http_only": int(grp["http_only"].max()) if not grp["http_only"].dropna().empty else None,
            "same_site": grp["same_site"].dropna().iloc[0] if not grp["same_site"].dropna().empty else None,
            "pre_seen": bool((grp["phase"]=="pre").any()),
            "post_accept_seen": bool(((grp["phase"]=="post") & (grp["consent_action_norm"]=="accept")).any()),
            "post_reject_seen": bool(((grp["phase"]=="post") & (grp["consent_action_norm"]=="reject")).any()),
            "post_custom_analytics_off_seen": bool(((grp["phase"]=="post") & grp["custom_analytics_off"]).any()),
            "post_custom_advertising_off_seen": bool(((grp["phase"]=="post") & grp["custom_advertising_off"]).any()),
            "post_custom_functional_off_seen": bool(((grp["phase"]=="post") & grp["custom_functional_off"]).any()),
        })
    return pd.DataFrame(rows).sort_values(["domain_name","category","cookie_name"])

def _df_cookies_per_url_grid(conn: sqlite3.Connection) -> pd.DataFrame:
    """
    One row per (domain_name, url) with unique cookie name lists and counts per axis:
      - pre
      - post_accept
      - post_reject
      - post_analytics_off (custom runs where analytics=False)
      - post_advertising_off (custom runs where advertising=False)
      - post_functional_off (custom runs where functional=False)
    Reject is kept separate (not merged into the OFF axes).
    """
    q = """
        SELECT co.domain_name, co.url, co.phase, co.cookie_name,
               cr.consent_action, cr.custom_prefs_requested
        FROM cookie_observations co
        JOIN crawl_results cr ON cr.id = co.crawl_id
        ORDER BY co.domain_name, cr.consent_action, co.url, co.phase, co.cookie_name
    """
    df = pd.read_sql_query(q, conn)
    if df.empty:
        cols = [
            "domain_name", "url",
            "pre_cookie_names", "pre_count",
            "post_accept_cookie_names", "post_accept_count",
            "post_reject_cookie_names", "post_reject_count",
            "post_analytics_off_cookie_names", "post_analytics_off_count",
            "post_advertising_off_cookie_names", "post_advertising_off_count",
            "post_functional_off_cookie_names", "post_functional_off_count",
        ]
        return pd.DataFrame(columns=cols)

    # normalise name for dedupe
    df["cookie_name"] = df["cookie_name"].fillna("").astype(str).str.strip()
    df = df[df["cookie_name"] != ""]
    df["cookie_key"] = df["cookie_name"].str.lower()

    def is_accept(a: str) -> bool:
        a = (a or "").lower()
        return ("accept" in a) or ("allow" in a)

    def is_reject(a: str) -> bool:
        a = (a or "").lower()
        return ("reject" in a) or ("deny" in a) or ("refuse" in a)

    def prefs(js):
        try:
            p = json.loads(js) if isinstance(js, str) else (js or {})
        except Exception:
            p = {}
        return {
            "analytics_off": (p.get("analytics") is False),
            "advertising_off": (p.get("advertising") is False),
            "functional_off": (p.get("functional") is False),
        }

    # helper: unique names list + unique count for a filtered subset
    def uniq(sub: pd.DataFrame) -> tuple[str, int]:
        if sub.empty:
            return "", 0
        first = {}
        for _, r in sub.iterrows():
            k = r["cookie_key"]
            if k and k not in first:
                first[k] = r["cookie_name"]  # preserve original case of first seen
        names = [first[k] for k in sorted(first)]
        return ";".join(names), len(names)

    rows = []
    for (dn, url), g in df.groupby(["domain_name", "url"], dropna=False):
        # pre (all actions collapse)
        pre_list, pre_count = uniq(g[g["phase"] == "pre"])

        # post after accept
        post_accept = g[(g["phase"] == "post") & (g["consent_action"].apply(is_accept))]
        pa_list, pa_count = uniq(post_accept)

        # post after reject
        post_reject = g[(g["phase"] == "post") & (g["consent_action"].apply(is_reject))]
        pr_list, pr_count = uniq(post_reject)

        # custom OFF axes (exclude accept/reject explicitly)
        custom = g[(g["phase"] == "post") & ~(g["consent_action"].apply(is_accept) | g["consent_action"].apply(is_reject))].copy()
        if not custom.empty:
            flags = custom["custom_prefs_requested"].apply(prefs).apply(pd.Series)
            custom = pd.concat([custom, flags], axis=1)
        else:
            custom = custom.assign(analytics_off=False, advertising_off=False, functional_off=False)

        ana_list, ana_count = uniq(custom[custom["analytics_off"]])
        adv_list, adv_count = uniq(custom[custom["advertising_off"]])
        fun_list, fun_count = uniq(custom[custom["functional_off"]])

        rows.append({
            "domain_name": dn,
            "url": url,
            "pre_cookie_names": pre_list,
            "pre_count": pre_count,
            "post_accept_cookie_names": pa_list,
            "post_accept_count": pa_count,
            "post_reject_cookie_names": pr_list,
            "post_reject_count": pr_count,
            "post_analytics_off_cookie_names": ana_list,
            "post_analytics_off_count": ana_count,
            "post_advertising_off_cookie_names": adv_list,
            "post_advertising_off_count": adv_count,
            "post_functional_off_cookie_names": fun_list,
            "post_functional_off_count": fun_count,
        })

    out = pd.DataFrame(rows)
    return out.sort_values(["domain_name","url"])


# CSV exports
def _export_csvs(conn: sqlite3.Connection, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    _df_classifier_decisions(conn).to_csv(os.path.join(out_dir, "classifier_decisions.csv"), index=False)
    _df_domain_category_summary(conn).to_csv(os.path.join(out_dir, "domain_category_summary.csv"), index=False)
    _df_pre_consent_issues(conn).to_csv(os.path.join(out_dir, "pre_consent_issues.csv"), index=False)
    _df_conflicts_review(conn).to_csv(os.path.join(out_dir, "conflicts_review.csv"), index=False)
    _df_unknowns_review(conn).to_csv(os.path.join(out_dir, "unknowns_review.csv"), index=False)
    _df_post_consent_issues(conn).to_csv(os.path.join(out_dir, "post_consent_issues.csv"), index=False)
    _df_pre_issues_unique(conn).to_csv(os.path.join(out_dir, "pre_consent_issues_unique.csv"), index=False)
    _df_post_issues_unique(conn).to_csv(os.path.join(out_dir, "post_consent_issues_unique.csv"), index=False)
    _df_cookie_summary(conn).to_csv(os.path.join(out_dir, "cookie_summary.csv"), index=False)
    _df_policy_matrix(conn).to_csv(os.path.join(out_dir, "policy_matrix.csv"), index=False)
    _df_cookie_inventory(conn).to_csv(os.path.join(out_dir, "cookie_inventory.csv"), index=False)
    _df_cookies_per_url_grid(conn).to_csv(os.path.join(out_dir, "cookies_per_url_grid.csv"), index=False)


# Excel
def _pick_excel_engine() -> Optional[str]:
    try:
        import openpyxl  # noqa
        return "openpyxl"
    except Exception:
        try:
            import xlsxwriter  # noqa
            return "xlsxwriter"
        except Exception:
            return None

def export_excel_workbook(conn: sqlite3.Connection, out_dir: str, filename: str = "classification_report.xlsx") -> None:
    os.makedirs(out_dir, exist_ok=True)
    xlsx_path = os.path.join(out_dir, filename)

    engine = _pick_excel_engine()
    if engine is None:
        return

    with pd.ExcelWriter(xlsx_path, engine=engine) as xl:
        _df_classifier_decisions(conn).to_excel(xl, sheet_name="Classifier decisions", index=False)
        _df_pre_consent_issues(conn).to_excel(xl, sheet_name="Pre-consent issues", index=False)
        _df_post_consent_issues(conn).to_excel(xl, sheet_name="Post-consent issues", index=False)
        _df_pre_issues_unique(conn).to_excel(xl, sheet_name="Pre-consent issues (uniq)", index=False)
        _df_post_issues_unique(conn).to_excel(xl, sheet_name="Post-consent issues (uniq)", index=False)
        _df_conflicts_review(conn).to_excel(xl, sheet_name="Conflicts review", index=False)
        _df_unknowns_review(conn).to_excel(xl, sheet_name="Unknowns review", index=False)
        _df_domain_category_summary(conn).to_excel(xl, sheet_name="Domain × Category", index=False)
        _df_policy_matrix(conn).to_excel(xl, sheet_name="Policy matrix", index=False)
        _df_cookie_inventory(conn).to_excel(xl, sheet_name="Cookie inventory", index=False)
        _df_cookies_per_url_grid(conn).to_excel(xl, sheet_name="Cookies per URL (grid)", index=False)
        _df_cookie_summary(conn).to_excel(xl, sheet_name="Cookie summary", index=False)

# Runner
def export_all(conn: sqlite3.Connection, out_dir: str, excel_only: bool) -> None:
    if not excel_only:
        _export_csvs(conn, out_dir)
    export_excel_workbook(conn, out_dir)

def run(db_file: str, rules_path: str, ocd_path: Optional[str], out_dir: str, reset: bool, excel_only: bool):
    conn = sqlite3.connect(db_file)
    migrate_schema(conn, fresh=reset)

    cur = conn.cursor()
    cols = [c[1].lower() for c in cur.execute("PRAGMA table_info('crawl_results')").fetchall()]
    required = {"id","domain_name","url","consent_action","pre_cookies","post_cookies"}
    missing = required - set(cols)
    if missing:
        raise RuntimeError(f"crawl_results missing columns: {', '.join(sorted(missing))}")
    has_prefs = "custom_prefs_requested" in cols
    has_extraction = "extraction_datetime" in cols

    _, rules = load_rules(rules_path)
    rules_idx = [_compile_rule(r) for r in rules]
    ocd_exact, ocd_regex, _ = load_ocd(ocd_path)

    if reset:
        cur.execute("DELETE FROM cookie_observations")
        cur.execute("DELETE FROM pre_consent_issues")
        cur.execute("DELETE FROM domain_category_summary")
        cur.execute("DELETE FROM post_consent_issues")
        conn.commit()

    if has_extraction and has_prefs:
        rows = cur.execute("""
            SELECT id, domain_name, url, consent_action, consent_result, custom_prefs_requested, pre_cookies, post_cookies, extraction_datetime
            FROM crawl_results
        """).fetchall()
    elif has_extraction:
        rows = cur.execute("""
            SELECT id, domain_name, url, consent_action, consent_result, NULL as custom_prefs_requested, pre_cookies, post_cookies, extraction_datetime
            FROM crawl_results
        """).fetchall()
    elif has_prefs:
        rows = cur.execute("""
            SELECT id, domain_name, url, consent_action, consent_result, custom_prefs_requested, pre_cookies, post_cookies
            FROM crawl_results
        """).fetchall()
    else:
        rows = cur.execute("""
            SELECT id, domain_name, url, consent_action, consent_result, NULL as custom_prefs_requested, pre_cookies, post_cookies
            FROM crawl_results
        """).fetchall()

    for row in rows:
        if has_extraction:
            (crawl_id, domain_name, url, consent_action, consent_result, custom_prefs_json, pre_c, post_c, extraction_dt) = row
            crawl_ts = _to_epoch_seconds(extraction_dt)
        else:
            (crawl_id, domain_name, url, consent_action, consent_result, custom_prefs_json, pre_c, post_c) = row
            crawl_ts = None

        page_etld1 = registrable_domain(domain_name) or domain_name
        policy = _policy_from_action(consent_action, custom_prefs_json)

        pre_list = _safe_json_list(pre_c)
        post_list = _safe_json_list(post_c)

        pre_obs = _observations_from_cookie_list(pre_list, page_etld1, crawl_id, "pre", domain_name, url,
                                                 consent_action, consent_result, rules_idx, ocd_exact, ocd_regex, crawl_ts)
        post_obs = _observations_from_cookie_list(post_list, page_etld1, crawl_id, "post", domain_name, url,
                                                  consent_action, consent_result, rules_idx, ocd_exact, ocd_regex, crawl_ts)

        for r in pre_obs:
            _insert_observation(cur, r)
            if r["category"] in ("functional","analytics","advertising"):
                _record_pre_issue(cur, crawl_id, domain_name, url, r["cookie_name"], r["category"])

        for r in post_obs:
            _insert_observation(cur, r)
            if r["category"] in ("functional","analytics","advertising"):
                allowed = policy.get(r["category"], False)
                if not allowed:
                    _record_post_issue(cur, r, policy)

        conn.commit()

    cur.execute("DELETE FROM domain_category_summary")
    conn.commit()
    cur.execute("""
        INSERT INTO domain_category_summary(domain_name, category, cookie_count)
        SELECT domain_name, category, COUNT(1)
        FROM cookie_observations
        GROUP BY domain_name, category
    """)
    conn.commit()

    export_all(conn, out_dir, excel_only)
    conn.close()

def cli():
    parser = argparse.ArgumentParser(description="Cookie classification (rules + OCD) with single Excel workbook; expiry at crawl time.")
    parser.add_argument("--db", required=True, help="Path to crawl results SQLite DB")
    parser.add_argument("--rules", required=True, help="Path to cookie_rules.yml")
    parser.add_argument("--ocd", help="Path to Open Cookie Database CSV/JSON (local file)")
    parser.add_argument("--out", default="./reports", help="Directory to write outputs")
    parser.add_argument("--reset", action="store_true", help="Drop & recreate classifier tables before running")
    parser.add_argument("--excel-only", action="store_true", help="Write only the Excel workbook (no CSVs)")
    args = parser.parse_args()
    run(args.db, args.rules, args.ocd, args.out, args.reset, args.excel_only)

if __name__ == "__main__":
    cli()
