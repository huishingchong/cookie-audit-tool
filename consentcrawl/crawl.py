import os
import json
import logging
import re
import base64
import random
import yaml
import asyncio
import sqlite3
from datetime import date, datetime
from pathlib import Path
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright
from consentcrawl import utils
from consentcrawl.domain_utils import registrable_domain, is_third_party, host_from_url, is_blocklisted_host
from .custom_flow import customise as _flow_customise

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
CONSENT_MANAGERS_FILE = f"{MODULE_DIR}/assets/consent_managers.yml"

DEFAULT_UA_STRINGS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.92 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.92 Safari/537.36"
]
BROWSER_TYPE = "chrome"

# flags avoid background throttling issues when scanning in parallel
common_args = [
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
    "--disable-backgrounding-occluded-windows",
]

ACCEPT_TEXT = re.compile(
    r"\b("
    r"accept|agree|allow|consent|ok|got it|"
    r"akzeptieren|zustimmen|alle akzeptieren|alle zulassen|"
    r"accepter|tout accepter|"
    r"aceptar|acepto|aceptar todo|aceptar todas|"
    r"accetta|accetto|accetta tutto|"
    r"aceitar|aceito|aceitar tudo|"
    r"aanvaarden|alles accepteren|"
    r"godkänna|acceptera alla|"
    r"同意|接受|許可|承諾|同意する|"
    r"허용|동의"
    r")\b",
    re.IGNORECASE
)

REJECT_TEXT = re.compile(
    r"\b("
    r"reject|deny|decline|disagree|continue without|"
    r"alles ablehnen|ich lehne ab|alle ablehnen"
    r"tout refuser|refuser|"
    r"rechazar|"
    r"rifiuto|"
    r"recusar|"
    r"weigeren|"
    r"拒否|不同意|拒绝|拒否する|"
    r"거부|동의하지 않음"
    r")\b",
    re.IGNORECASE
)

MANAGE_TEXT = re.compile(
    r"\b(manage|preferences|settings|more options|customis(e|z)e|"
    r"cookie settings|manage options|mehr optionen|einstellungen|"
    r"paramètres|opciones|opties)\b",
    re.IGNORECASE
)

def get_extract_schema():
    return {
        "id": "STRING",
        "url": "STRING",
        "domain_name": "STRING",
        "extraction_datetime": "STRING",

        "pre_cookies": "STRING",
        "pre_third_party_domains": "STRING",
        "pre_tracking_domains": "STRING",

        "post_cookies": "STRING",
        "post_third_party_domains": "STRING",
        "post_tracking_domains": "STRING",

        "pre_page_evidence": "STRING",         # list[ { ts, url, note, document_cookie, browser_cookies[] } ]
        "pre_set_cookie_events": "STRING",     # list[ { ts, response_url, set_cookie_header } ]
        "pre_nav_log": "STRING",

        "post_page_evidence": "STRING",         # list[ { ts, url, note, document_cookie, browser_cookies[] } ]
        "post_set_cookie_events": "STRING",     # list[ { ts, response_url, set_cookie_header } ]
        "post_nav_log": "STRING",

        "pre_cookie_index": "STRING",
        "post_cookie_index": "STRING",

        "consent_action": "STRING",
        "consent_result": "STRING",
        "custom_prefs_requested": "STRING",
        "custom_toggles_changed": "STRING",
        "custom_flow_debug": "STRING",

        "consent_manager": "STRING",
        "screenshot_files": "STRING",
        "meta_tags": "STRING",
        "json_ld": "STRING",
        "status": "STRING",
        "status_msg": "STRING",
        "landed_url": "STRING",
    }


def get_consent_managers():
    with open(CONSENT_MANAGERS_FILE, "r") as f:
        return yaml.safe_load(f)

async def _try_click(locator):
    try:
        await locator.scroll_into_view_if_needed(timeout=2000)
    except Exception:
        pass
    try:
        await locator.click(timeout=3000, trial=True)
        await locator.click(timeout=3000)
        return True
    except Exception:
        pass
    try:
        await locator.click(timeout=3000, force=True)
        return True
    except Exception:
        pass
    try:
        await locator.evaluate("(el) => el.click()")
        return True
    except Exception:
        return False

async def click_consent_manager(page, action: str = "accept"):
    """
    action: 'accept' | 'reject'
    Try known CMPs for given action. If not found, fall back to text search.
    Returns a dict with 'status' when click likely happened.
    """
    consent_managers = get_consent_managers()
    text_pattern = ACCEPT_TEXT if action == "accept" else REJECT_TEXT

    for cmp in consent_managers:
        parent = page
        target = None
        flows = cmp.get("flows", {})
        steps = flows.get(action) or (cmp.get("actions", []) if action == "accept" else [])

        if action == "reject" and not steps and flows.get("manage"):
            opened = False
            for act in flows["manage"]:
                t = act.get("type"); v = act.get("value")
                if t == "iframe":
                    try:
                        await parent.locator(v).first.wait_for(state="attached", timeout=3000)
                        parent = parent.frame_locator(v).first
                    except Exception:
                        parent = None
                        break
                elif t in ("css-selector", "css-selector-list"):
                    sel_list = [v] if t == "css-selector" else v
                    for sel in sel_list:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _try_click(loc):
                            opened = True
                            try:
                                await page.wait_for_load_state("networkidle", timeout=2000)
                            except Exception:
                                pass
                            break
                if opened:
                    break
            if opened:
                btn = page.get_by_role("button", name=REJECT_TEXT).first
                if await btn.count() > 0 and await _try_click(btn):
                    return {"id":"managed-reject","name":"Manage then Reject (inline)","status":"clicked","clicked_action":"reject"}
                for sel in ("#onetrust-reject-all-handler",):
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await _try_click(loc):
                        return {"id":"managed-reject","name":"Manage then Reject (selector)","status":"clicked","clicked_action":"reject"}

        for act in steps:
            t = act.get("type"); v = act.get("value")
            if t == "iframe":
                try:
                    await parent.locator(v).first.wait_for(state="attached", timeout=3000)
                    parent = parent.frame_locator(v).first
                except Exception:
                    parent = None
                    break
            elif t == "css-selector":
                loc = parent.locator(v).first
                if await loc.count() > 0 and await loc.is_visible():
                    preferred = loc.locator("button, a, [role='button']").filter(has_text=text_pattern).first
                    if await preferred.count() > 0:
                        target = preferred
                    elif action == "accept":
                        target = loc
                if target is not None:
                    break
            elif t == "css-selector-list":
                for selector in v:
                    loc = parent.locator(selector).first
                    if await loc.count() > 0 and await loc.is_visible():
                        preferred = loc.locator("button, a, [role='button']").filter(has_text=text_pattern).first
                        if await preferred.count() > 0:
                            target = preferred
                            cmp["selector-list-item"] = selector
                            break
                        elif action == "accept":
                            target = loc
                            cmp["selector-list-item"] = selector
                            break

        if parent is None:
            continue

        if target is not None:
            ok = await _try_click(target)
            if not ok:
                cmp["status"] = "error"
                cmp["error"] = f"{action} click failed"
                return cmp
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except PlaywrightTimeoutError:
                pass
            try:
                still_visible = await target.is_visible()
            except Exception:
                still_visible = False
            cmp["status"] = "clicked" if not still_visible else "clicked-uncertain"
            cmp["clicked_action"] = action
            return cmp

    if action == "accept":
        for sel in ("#onetrust-accept-btn-handler", "#accept-recommended-btn-handler"):
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await _try_click(loc):
                    try:
                        await page.wait_for_load_state("networkidle", timeout=3000)
                    except PlaywrightTimeoutError:
                        pass
                    try:
                        still_visible = await loc.is_visible()
                    except Exception:
                        still_visible = False
                    return {
                        "id": "ot-accept",
                        "name": "OneTrust Accept",
                        "status": "clicked" if not still_visible else "clicked-uncertain",
                        "clicked_action": "accept",
                        "selector": sel,
                    }
            except Exception:
                pass

    btn = page.get_by_role("button", name=text_pattern).first
    if await btn.count() > 0 and await btn.is_visible():
        if await _try_click(btn):
            return {"id":"fallback-text","name":"Text search","status":"clicked","clicked_action":action}

    for frame in page.frames:
        try:
            btn = frame.get_by_role("button", name=text_pattern).first
            if await btn.count() > 0 and await btn.is_visible():
                if await _try_click(btn):
                    return {"id":"fallback-text-in-frame","name":"Text search (frame)","status":"clicked","clicked_action":action}
        except Exception:
            continue

    if action == "reject":
        try:
            manage_steps = []
            for cmp in consent_managers:
                if cmp.get("flows", {}).get("manage"):
                    manage_steps = cmp["flows"]["manage"]
                    break

            opened = False
            for act in manage_steps or []:
                parent = page
                t = act.get("type"); v = act.get("value")
                if t == "iframe":
                    try:
                        await parent.locator(v).first.wait_for(state="attached", timeout=3000)
                        parent = parent.frame_locator(v).first
                    except Exception:
                        continue
                elif t in ("css-selector", "css-selector-list"):
                    sel_list = [v] if t == "css-selector" else v
                    for sel in sel_list:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _try_click(loc):
                            opened = True
                            break
                if opened:
                    break

            for sel in ["#onetrust-pc-btn-handler"]:
                if opened:
                    break
                loc = page.locator(sel).first
                if await loc.count() > 0 and await _try_click(loc):
                    opened = True
                    break

            if not opened:
                btn = page.get_by_role("button", name=MANAGE_TEXT).first
                if await btn.count() > 0:
                    opened = await _try_click(btn)

            if opened:
                try:
                    await page.wait_for_load_state("networkidle", timeout=2000)
                except Exception:
                    pass
                btn = page.get_by_role("button", name=REJECT_TEXT).first
                if await btn.count() > 0 and await _try_click(btn):
                    return {"id":"fallback-manage-text","name":"Manage then Reject (text)","status":"clicked","clicked_action":"reject"}
                for sel in ["#onetrust-reject-all-handler"]:
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await _try_click(loc):
                        return {"id":"fallback-reject-handler","name":"Manage then Reject (selector)","status":"clicked","clicked_action":"reject"}
        except Exception:
            pass

    logging.debug(f"Unable to {action} cookies on: {page.url}")
    return {}

async def get_jsonld(page):
    json_ld = []
    for item in await page.locator('script[type="application/ld+json"]').all():
        contents = await item.inner_text()
        try:
            m = re.search(r"//<!\[CDATA\[\s*(.*?)\s*//\]\]>", contents.strip(), re.DOTALL)
            json_ld.append(json.loads(m.group(1), strict=False) if m else json.loads(contents.strip(), strict=False))
        except Exception as e:
            logging.debug(f"Unable to parse JSON-LD: {e}")
            json_ld.append({"raw": str(contents), "error": str(e)})
    return json_ld

async def get_meta_tags(page):
    meta_tags = {}
    for tag in await page.locator("meta[name]").all():
        try:
            meta_tags[await tag.get_attribute("name")] = await tag.get_attribute("content")
        except Exception as e:
            logging.debug(f"Unable to get meta tag: {e}")
    return meta_tags

# Cookie helpers
async def _site_cookies(context, site_etld1: str):
    all_cookies = await context.cookies()
    return [
        {
            "name": c["name"],
            "value": c.get("value"),
            "domain": c["domain"],
            "path": c.get("path"),
            "secure": bool(c.get("secure")),
            "httpOnly": bool(c.get("httpOnly")),
            "sameSite": c.get("sameSite"),
            "expires": int(c.get("expires") or 0),
            "session": int(c.get("expires") or 0) <= 0,
            "expires_days": (
                (date.fromtimestamp(int(c.get("expires") or 0)) - date.today()).days
                if int(c.get("expires") or 0) > 0 else None
            ),
        }
        for c in all_cookies
        if registrable_domain(c.get("domain", "").lstrip(".")) == site_etld1
    ]

async def _wait_cookie(context, site_etld1: str, min_ms=800, max_ms=6000, poll_ms=400):
    elapsed = 0
    last = await _site_cookies(context, site_etld1)
    last_len = len(last)
    stable_iters = 0

    if min_ms > 0:
        await asyncio.sleep(min_ms / 1000.0)
        elapsed += min_ms

    while elapsed < max_ms:
        cur = await _site_cookies(context, site_etld1)
        cur_len = len(cur)
        if cur_len == last_len:
            stable_iters += 1
            if stable_iters >= 2:
                return cur
        else:
            stable_iters = 0
        last = cur
        last_len = cur_len
        await asyncio.sleep(poll_ms / 1000.0)
        elapsed += poll_ms
    return last



## Extend crawler
# --- PRE-CONSENT EXPLORATION HELPERS ---

from urllib.parse import urljoin, urlparse

def _same_origin(u1: str, u2: str) -> bool:
    try:
        a, b = urlparse(u1), urlparse(u2)
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except Exception:
        return False

def _is_safe_href(href: str) -> bool:
    if not href:
        return False
    href = href.strip()
    if href.startswith(("javascript:", "mailto:", "tel:", "sms:")):
        return False
    # skip obvious logout/delete endpoints
    if re.search(r"(logout|signout|delete|unsubscribe|remove-account)", href, re.I):
        return False
    return True

def _diff_site_cookies(prev, cur):
    prev_map = {(c["name"], c.get("domain"), c.get("path")): c for c in prev or []}
    cur_map  = {(c["name"], c.get("domain"), c.get("path")): c for c in cur or []}
    added = [cur_map[k] for k in cur_map.keys() - prev_map.keys()]
    changed = []
    for k in cur_map.keys() & prev_map.keys():
        if cur_map[k].get("expires") != prev_map[k].get("expires") or cur_map[k].get("value") != prev_map[k].get("value"):
            changed.append({"before": prev_map[k], "after": cur_map[k]})
    return added, changed


async def _scroll_and_settle(page, short=False):
    try:
        # small scrolls to trigger lazy observers
        for dy in (200, 600, 1200, 0, -200):
            await page.mouse.wheel(0, dy)
            await page.wait_for_timeout(250 if short else 400)
        try:
            await page.wait_for_load_state("networkidle", timeout=2000 if short else 4000)
        except PlaywrightTimeoutError:
            pass
    except Exception:
        pass

async def _click_non_destructive(page, max_clicks=8):
    """
    Click 'safe' UI elements on the current page that often expand content:
    - buttons/links that look like menus, tabs, 'load more', accordions
    """
    clicks = 0
    candidates = await page.locator(
        "button, [role='button'], a[role='button'], summary, .accordion button, .accordion [role='button']"
    ).all()

    for el in candidates:
        if clicks >= max_clicks:
            break
        try:
            if not await el.is_visible():
                continue
            # Cache inner text once; it can be slow
            try:
                txt = (await el.inner_text() or "").lower()
            except Exception:
                txt = ""
            outer = (await el.evaluate("el => el.outerHTML") or "").lower()

            if any(s in outer or s in txt for s in ["menu", "more", "expand", "open", "tab", "accordion", "details", "filter"]):
                await el.scroll_into_view_if_needed()
                await el.click(timeout=1500)
                clicks += 1
                await page.wait_for_timeout(400)
        except Exception:
            continue

    await _scroll_and_settle(page, short=True)


async def _collect_same_origin_links(page, max_links=25):
    origin = page.url
    urls = set()
    anchors = await page.locator("a[href]").all()

    for a in anchors:
        try:
            href = await a.get_attribute("href")
            if not _is_safe_href(href):
                continue
            absu = urljoin(origin, href)
            if not _same_origin(absu, origin):
                continue
            u = urlparse(absu)
            norm = f"{u.scheme}://{u.netloc}{u.path}" + (f"?{u.query}" if u.query else "")
            urls.add(norm)
            if len(urls) >= max_links:
                break
        except Exception:
            continue
    return list(urls)


async def _pre_consent_explore(page, max_pages=10, max_depth=1, max_clicks_per_page=6, evidence_cb=None, context=None, label="pre"):
    """
    Shallow BFS over same-origin links, without consent interaction.
    """
    start = page.url
    visited = set([start])
    queue = [(start, 0)]
    frontier_cache = []

    # collect a frontier from landing page first
    try:
        frontier_cache = await _collect_same_origin_links(page, max_links=max_pages)
    except Exception:
        frontier_cache = []
    for u in frontier_cache:
        if u not in visited:
            queue.append((u, 1))

    # On the landing page, do some safe clicks too
    await _click_non_destructive(page, max_clicks=max_clicks_per_page)

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            logging.info(f"[{label}] visiting depth={depth}: {url}")
            await page.goto(url, wait_until="load", timeout=30000)
        except Exception:
            continue
        await _scroll_and_settle(page)
        await _click_non_destructive(page, max_clicks=max_clicks_per_page)
        if evidence_cb:
            await evidence_cb(context, page, note=f"visit depth={depth}")

        if depth < max_depth:
            try:
                more = await _collect_same_origin_links(page, max_links=max_pages)
                for v in more:
                    if v not in visited:
                        queue.append((v, depth + 1))
            except Exception:
                pass

    # return to the start if still same-origin (not required, but nice)
    try:
        if _same_origin(start, page.url):
            await page.goto(start, wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass

async def _record_page_evidence(output_evidence_list, context, page, site_etld1, state, note=None):
    try:
        ts = int(datetime.utcnow().timestamp() * 1000)
        visited = page.url

        # site-scoped browser cookies (includes HttpOnly)
        site_cookies = await _site_cookies(context, site_etld1)
        added, changed = _diff_site_cookies(state.get("last_site_cookies"), site_cookies)
        state["last_site_cookies"] = site_cookies  # update baseline

        try:
            document_cookie = await page.evaluate("() => document.cookie")
        except Exception:
            document_cookie = None

        output_evidence_list.append({
            "ts": ts,
            "url": visited,
            "note": note,
            "document_cookie": document_cookie,
            "browser_cookies": site_cookies,     # full snapshot (site-scoped)
            "new_site_cookies": added,           # ← cookies first seen at/after this page
            "changed_site_cookies": changed,     # ← value/expiry changed at/after this page
        })
    except Exception as e:
        logging.debug(f"record_page_evidence failed: {e}")

def _build_cookie_index(page_evidence):
    idx = {}
    for ev in page_evidence or []:
        url = ev.get("url")
        # mark presence on every page
        for c in (ev.get("browser_cookies") or []):
            key = (c.get("name"), c.get("domain"), c.get("path"))
            entry = idx.setdefault(key, {"first_seen_url": url, "pages_seen": []})
            if "first_seen_url" not in entry or not entry["first_seen_url"]:
                entry["first_seen_url"] = url
            if url not in entry["pages_seen"]:
                entry["pages_seen"].append(url)
        # might still want to track event pages separately
        # use new_site_cookies/changed_site_cookies if useful?
    return idx

def cookie_index_to_list(idx):
    out = []
    for (name, domain, path), val in (idx or {}).items():
        rec = {"name": name, "domain": domain, "path": path}
        rec.update(val or {})
        out.append(rec)
    return out


async def crawl_url(
    url,
    browser,
    tracking_domains_list=None,
    screenshot=True,
    device=None,
    wait_for_timeout=5000,
    consent_action: str = "accept",
    custom_prefs=None,
    critical_sem=None,
    **kwargs,
):
    output = {k: None for k in get_extract_schema().keys()}
    output["screenshot_files"] = []
    browser_context = None

    try:
        raw_input = url.strip()
        added_scheme = False
        if not re.match(r"^https?://", raw_input, re.I):
            url = "https://" + raw_input
            added_scheme = True
        else:
            url = raw_input

        output["url"] = url
        output["extraction_datetime"] = str(datetime.now())

        if device is None:
            device = {}
        if tracking_domains_list is None:
            tracking_domains_list = []

        if "user_agent" not in device:
            device["user_agent"] = DEFAULT_UA_STRINGS[0 if BROWSER_TYPE == "msedge" else 1]
        logging.info("UA=%s", device.get("user_agent"))

        if "viewport" not in device:
            device["viewport"] = {"width": 1366, "height": 768}
        if "locale" not in device:
            device["locale"] = "en-GB"
        if "timezone_id" not in device:
            device["timezone_id"] = "Europe/London"
        if "color_scheme" not in device:
            device["color_scheme"] = "light"
        if "is_mobile" not in device:
            device["is_mobile"] = False

        browser_context = await browser.new_context(**device)
        await browser_context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        req_urls_pre = []
        req_urls_post = []
        consent_boundary_reached = False

        def request_handler(req):
            try:
                if consent_boundary_reached:
                    req_urls_post.append(req.url)
                else:
                    req_urls_pre.append(req.url)
            except Exception:
                pass

        page = await browser_context.new_page()
        page.on("request", request_handler)

        # capture network-level Set-Cookie events (list) + activity counters
        set_cookie_events = []                     # [{ ts, response_url, set_cookie_header }]
        set_cookie_activity = {"total": 0, "recent": 0}

        def _on_response(resp):
            try:
                hdr = resp.headers.get("set-cookie")
                if hdr:
                    set_cookie_events.append({
                        "ts": int(datetime.utcnow().timestamp() * 1000),
                        "response_url": resp.url,
                        "set_cookie_header": hdr,
                    })
                    set_cookie_activity["total"] += 1
                    set_cookie_activity["recent"] += 1
            except Exception:
                pass
        page.on("response", _on_response)


        try:
            await page.goto(url, wait_until="load", timeout=90000)
        except Exception:
            if added_scheme and url.startswith("https://"):
                alt = "http://" + raw_input
                await page.goto(alt, wait_until="load", timeout=90000)
                url = alt
            else:
                raise

        output["landed_url"] = page.url
        landed_host = host_from_url(page.url) or host_from_url(url) or raw_input
        output["domain_name"] = landed_host
        site_etld1 = registrable_domain(landed_host) or landed_host

        run_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        id_source = f"{landed_host}|{run_tag}|{consent_action}".encode("idna").decode("ascii")
        output["id"] = base64.urlsafe_b64encode(id_source.encode("ascii")).decode("ascii")

        logging.info(f"Extracting data from domain {output['domain_name']}")

        await page.wait_for_timeout(10000)
        await page.mouse.move(543, 123)
        await page.mouse.wheel(0, -123)
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
        except PlaywrightTimeoutError:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except PlaywrightTimeoutError:
            pass
        await page.wait_for_timeout(wait_for_timeout)

        Path("screenshots").mkdir(parents=True, exist_ok=True)
        if screenshot:
            try:
                path_pre = f'./screenshots/screenshot_{output["id"]}_{run_tag}.png'
                await page.locator("body").screenshot(path=path_pre, timeout=15000)
                output["screenshot_files"] = [path_pre]
            except Exception as e:
                logging.debug(f"Pre-consent screenshot failed: {e}")
                output["screenshot_files"] = []

        logging.debug(f"Retrieving JSON-LD and meta tags on {output['domain_name']}")
        output["json_ld"] = await get_jsonld(page)
        output["meta_tags"] = await get_meta_tags(page)

        tracking_set = {h.lower() for h in (tracking_domains_list or [])}

        # --- PRE-CONSENT EXPLORATION ---
        # Prepare evidence collection
        # inside crawl_url, after site_etld1 computed and initial waits:
        state = {"last_site_cookies": await _site_cookies(browser_context, site_etld1)}
        nav_log = []
        pre_page_evidence = []
        async def _evidence_cb(cxt, pg, note=None):
            nav_log.append({"ts": int(datetime.utcnow().timestamp()*1000), "url": pg.url, "note": note})
            await _record_page_evidence(pre_page_evidence, cxt, pg, site_etld1, state, note=note)


        # record landing page BEFORE exploring
        await _evidence_cb(browser_context, page, note="landing")


        try:
            await _pre_consent_explore(
                page,
                max_pages=kwargs.get("max_pages", 12) if kwargs else 12,
                max_depth=kwargs.get("depth", 1) if kwargs else 1,
                max_clicks_per_page=kwargs.get("clicks", 6) if kwargs else 6,
                evidence_cb=_evidence_cb,
                context=browser_context,
                label="pre"
            )
        except Exception as e:
            logging.debug(f"Pre-consent exploration failed: {e}")

        output["pre_nav_log"] = nav_log

        # Save evidence gathered during exploration
        output["pre_page_evidence"] = pre_page_evidence

        # Small settle so last async tracker calls finish
        await page.wait_for_timeout(1000)

        landing_url_for_context = output["landed_url"] or page.url

        thirdparty_requests_pre = [r for r in req_urls_pre if is_third_party(r, landing_url_for_context)]
        output["pre_third_party_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_pre
            if registrable_domain(host_from_url(r))
        })
        output["pre_tracking_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_pre
            if is_blocklisted_host(host_from_url(r), tracking_set)
        })


        output["pre_cookies"] = await _wait_cookie(browser_context, site_etld1, min_ms=800, max_ms=5000, poll_ms=300)
        output["pre_cookies"].sort(key=lambda c: c.get("name") or "")

        output["consent_action"] = consent_action
        logging.debug(f"Trying to {consent_action} on {output['domain_name']}")
        try:
            await page.bring_to_front()
        except Exception:
            pass

        # Persist all network Set-Cookie events seen so far as "pre"
        output["pre_set_cookie_events"] = list(set_cookie_events)
        pre_events_len = len(set_cookie_events)

        consent_boundary_reached = True

        # critical window guarded by a small semaphore (reduces contention)
        if critical_sem:
            async with critical_sem:
                if consent_action in ("accept", "reject"):
                    cmp = await click_consent_manager(page, action=consent_action)
                elif consent_action == "custom":
                    output["custom_prefs_requested"] = custom_prefs or {}
                    cmp = await _flow_customise(page, custom_prefs or {}, managers=get_consent_managers())
                    output["custom_toggles_changed"] = str(cmp.get("changes"))
                    output["custom_flow_debug"] = {
                        "manage_opened": cmp.get("manage_opened"),
                        "manage_via": cmp.get("manage_via"),
                        "manage_role": cmp.get("manage_role"),
                        "manage_frame": cmp.get("manage_frame"),
                        "save_via": cmp.get("save_via"),
                        "save_role": cmp.get("save_role"),
                        "save_frame": cmp.get("save_frame"),
                        "saved": cmp.get("saved"),
                        "applied_prefs": cmp.get("applied_prefs"),
                        "category_hits": cmp.get("category_hits"),
                    }
                else:
                    cmp = await click_consent_manager(page, action="accept")

                output["consent_manager"] = cmp
                output["consent_result"] = cmp.get("status", "")

                if screenshot and output.get("consent_result") in ("clicked", "clicked-uncertain"):
                    try:
                        path_post = f'./screenshots/screenshot_{output["id"]}_{run_tag}_after_{consent_action}.png'
                        await page.locator("body").screenshot(path=path_post, timeout=15000)
                        output["screenshot_files"].append(path_post)
                    except Exception as e:
                        logging.debug(f"Post-consent screenshot failed: {e}")

                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except PlaywrightTimeoutError:
                    pass
                await page.wait_for_timeout(wait_for_timeout)
        else:
            if consent_action in ("accept", "reject"):
                cmp = await click_consent_manager(page, action=consent_action)
            elif consent_action == "custom":
                output["custom_prefs_requested"] = custom_prefs or {}
                cmp = await _flow_customise(page, custom_prefs or {}, managers=get_consent_managers())
                output["custom_toggles_changed"] = str(cmp.get("changes"))
                output["custom_flow_debug"] = {
                    "manage_opened": cmp.get("manage_opened"),
                    "manage_via": cmp.get("manage_via"),
                    "manage_role": cmp.get("manage_role"),
                    "manage_frame": cmp.get("manage_frame"),
                    "save_via": cmp.get("save_via"),
                    "save_role": cmp.get("save_role"),
                    "save_frame": cmp.get("save_frame"),
                    "saved": cmp.get("saved"),
                    "applied_prefs": cmp.get("applied_prefs"),
                    "category_hits": cmp.get("category_hits"),
                }
            else:
                cmp = await click_consent_manager(page, action="accept")

            output["consent_manager"] = cmp
            output["consent_result"] = cmp.get("status", "")

            if screenshot and output.get("consent_result") in ("clicked", "clicked-uncertain"):
                try:
                    path_post = f'./screenshots/screenshot_{output["id"]}_{run_tag}_after_{consent_action}.png'
                    await page.locator("body").screenshot(path=path_post, timeout=15000)
                    output["screenshot_files"].append(path_post)
                except Exception as e:
                    logging.debug(f"Post-consent screenshot failed: {e}")

            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except PlaywrightTimeoutError:
                pass
            await page.wait_for_timeout(wait_for_timeout)

        # small adaptive extension if Set-Cookie headers are still arriving
        if set_cookie_activity["total"] > 0:
            for _ in range(3):
                if set_cookie_activity["recent"] == 0:
                    break
                set_cookie_activity["recent"] = 0
                await page.wait_for_timeout(1000)


        thirdparty_requests_post = [r for r in req_urls_post if is_third_party(r, page.url)]

        # right after your post-consent waits and adaptive extension,
        # BEFORE computing post_third_party_domains / post_cookies:

        post_state = {"last_site_cookies": await _site_cookies(browser_context, site_etld1)}
        post_nav_log = []
        post_page_evidence = []

        async def _post_evidence_cb(cxt, pg, note=None):
            post_nav_log.append({"ts": int(datetime.utcnow().timestamp()*1000), "url": pg.url, "note": note})
            await _record_page_evidence(post_page_evidence, cxt, pg, site_etld1, post_state, note=note)

        # record current page first
        await _post_evidence_cb(browser_context, page, note="post-landing")

        try:
            await _pre_consent_explore(
                page,
                max_pages=kwargs.get("post_max_pages", kwargs.get("max_pages", 12)),
                max_depth=kwargs.get("post_depth", kwargs.get("depth", 1)),
                max_clicks_per_page=kwargs.get("post_clicks", kwargs.get("clicks", 6)),
                evidence_cb=_post_evidence_cb,
                context=browser_context,
                label="pro"
            )
        except Exception as e:
            logging.debug(f"Post-consent exploration failed: {e}")

        output["post_nav_log"] = post_nav_log
        output["post_page_evidence"] = post_page_evidence

        try:
            output["pre_cookie_index"]  = cookie_index_to_list(_build_cookie_index(output["pre_page_evidence"]))
            output["post_cookie_index"] = cookie_index_to_list(_build_cookie_index(output.get("post_page_evidence") or []))
        except Exception as e:
            logging.debug(f"cookie index build failed: {e}")


        output["post_third_party_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_post
            if registrable_domain(host_from_url(r))
        })
        output["post_tracking_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_post
            if is_blocklisted_host(host_from_url(r), tracking_set)
        })

        output["post_cookies"] = await _wait_cookie(browser_context, site_etld1, min_ms=2000, max_ms=15000, poll_ms=400)
        output["post_cookies"].sort(key=lambda c: c.get("name") or "")
        output["post_set_cookie_events"] = set_cookie_events[pre_events_len:]

        output["status"] = "success"
        output["status_msg"] = f"Successfully extracted data from {url}"
        return output

    except Exception as e:
        error_msg = f"Error extracting data from {url}: {e}"
        logging.debug(error_msg)
        output["status"] = "error"
        output["status_msg"] = error_msg
        return output
    finally:
        try:
            if browser_context is not None:
                await browser_context.close()
        except Exception as cleanup_error:
            logging.warning(f"Error closing browser context: {cleanup_error}")

async def crawl_batch(
    urls,
    results_function,
    batch_size=10,
    tracking_domains_list=None,
    browser_config=None,
    screenshot=False,
    flow="accept-all",
    custom_prefs=None,
    per_url_browser: bool = False,
    **kwargs,
):
    """
    Run the crawler for multiple URLs in batches and apply a (async) function
    to the results. Additional arguments can be passed to the results function.
    """
    if tracking_domains_list is None:
        tracking_domains_list = []

    # Ensure anti-throttling flags always applied, even if CLI provided a config
    if not browser_config:
        browser_config = {"headless": True, "channel": "chrome", "args": list(common_args)}
    else:
        cfg = dict(browser_config)
        existing = set(cfg.get("args", []))
        cfg["args"] = list(existing.union(common_args))
        browser_config = cfg

    def _map_flow_to_action(f):
        return "accept" if f == "accept-all" else "reject" if f == "reject-all" else "custom" if f == "custom" else "reject"

    async with async_playwright() as p:
        logging.debug("Starting browser")

        # Single semaphore for both modes
        critical_sem = asyncio.Semaphore(2)

        # Per-URL browser mode (optional)
        if per_url_browser:
            all_results = []
            for urls_batch in utils.batch(urls, batch_size):
                browsers = []
                tasks = []
                for url in urls_batch:
                    try:
                        b = await p.chromium.launch(**browser_config)
                        browsers.append(b)
                        tasks.append(
                            crawl_url(
                                url=url,
                                browser=b,
                                tracking_domains_list=tracking_domains_list,
                                screenshot=screenshot,
                                consent_action=_map_flow_to_action(flow),
                                custom_prefs=custom_prefs,
                                critical_sem=critical_sem,
                                **kwargs,
                            )
                        )
                    except Exception as e:
                        logging.error(f"Failed to launch browser for {url}: {e}")
                if tasks:
                    batch_results = [r for r in await asyncio.gather(*tasks)]
                    all_results.extend(batch_results)
                    logging.debug(f"Retrieved batch of {len(tasks)} URLs")
                    rf_kwargs = {}
                    for k in ("file", "results_db_file", "table_name"):
                        if k in kwargs and kwargs[k] is not None:
                            rf_kwargs[k] = kwargs[k]
                    await results_function(batch_results, **rf_kwargs)


                for b in browsers:
                    try:
                        await b.close()
                    except Exception as e:
                        logging.warning(f"Error closing browser: {e}")
            return all_results

        # Shared browser (default)
        try:
            browser = await p.chromium.launch(**browser_config)
            logging.info("Launched browser via channel=%s", browser_config.get("channel"))
        except Exception as e:
            if browser_config.get("channel"):
                logging.warning("Failed to launch channel=%s (%s). Falling back to bundled Chromium.",
                                browser_config.get("channel"), e)
                fallback_cfg = dict(browser_config)
                fallback_cfg.pop("channel", None)
                browser = await p.chromium.launch(**fallback_cfg)
            else:
                raise

        all_results = []
        for urls_batch in utils.batch(urls, batch_size):
            tasks = [
                crawl_url(
                    url=url,
                    browser=browser,
                    tracking_domains_list=tracking_domains_list,
                    screenshot=screenshot,
                    consent_action=_map_flow_to_action(flow),
                    custom_prefs=custom_prefs,
                    critical_sem=critical_sem,
                    **kwargs,
                )
                for url in urls_batch
            ]
            batch_results = [r for r in await asyncio.gather(*tasks)]
            all_results.extend(batch_results)
            logging.debug(f"Retrieved batch of {len(tasks)} URLs")
            rf_kwargs = {}
            for k in ("file", "results_db_file", "table_name"):
                if k in kwargs and kwargs[k] is not None:
                    rf_kwargs[k] = kwargs[k]
            await results_function(batch_results, **rf_kwargs)

        await browser.close()
    return all_results

async def crawl_single(url, tracking_domains_list=None, browser_config=None):
    if tracking_domains_list is None:
        tracking_domains_list = []
    if not browser_config:
        browser_config = {"headless": True, "channel": "chrome", "args": list(common_args)}

    async with async_playwright() as p:
        logging.debug("Starting browser")
        browser = await p.chromium.launch(**browser_config)
        return await crawl_url(url=url, browser=browser, tracking_domains_list=tracking_domains_list)

async def store_crawl_results(
    data, table_name="crawl_results", file=None, results_db_file="crawl_results.db"
):
    if file is not None:
        Path.mkdir(Path(file).parent, exist_ok=True)
        with open(file, "a") as f:
            f.writelines([json.dumps(item) + "\n" for item in data])

    if results_db_file is not None:
        Path.mkdir(Path(results_db_file).parent, exist_ok=True)

        conn = sqlite3.connect(results_db_file)
        c = conn.cursor()
        c.execute(
            f"CREATE TABLE IF NOT EXISTS {table_name} ({','.join([f'{k} TEXT' for k in get_extract_schema().keys()])})"
        )
        conn.commit()

        logging.info(f"Storing {len(data)} records in database")
        c = conn.cursor()
        for d in data:
            logging.info(f"Storing {d['url']}")
            d = {k: json.dumps(v) if type(v) in [dict, list, tuple] else v for k, v in d.items()}
            cols = list(get_extract_schema().keys())
            placeholders = ",".join(["?"] * len(cols))
            vals = [d.get(k) for k in cols]
            c.execute(
                f"INSERT INTO {table_name} ({','.join(cols)}) VALUES ({placeholders})",
                vals,
            )
            conn.commit()
        conn.close()
