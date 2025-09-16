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
# from consentcrawl.consent.flows import reject_all as _flow_reject_all, customise as _flow_customise
from .custom_flow import customise as _flow_customise

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
CONSENT_MANAGERS_FILE = f"{MODULE_DIR}/assets/consent_managers.yml"

DEFAULT_UA_STRINGS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/116.0.1938.81",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.92 Safari/537.36"
]
BROWSER_TYPE = "chrome"
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

        "consent_action": "STRING",   # 'accept' or 'reject' or 'custom'
        "consent_result": "STRING",   # 'clicked', 'clicked-uncertain', 'error', ''
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
        data = yaml.safe_load(f)
        return data

async def _try_click(locator):
    # Always try to bring into view first
    try:
        await locator.scroll_into_view_if_needed(timeout=2000)
    except Exception:
        pass

    # 1) Trial + normal click
    try:
        await locator.click(timeout=3000, trial=True)
        await locator.click(timeout=3000)
        return True
    except Exception:
        pass

    # 2) Force click
    try:
        await locator.click(timeout=3000, force=True)
        return True
    except Exception:
        pass

    # 3) JS click (last resort)
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
        # Prefer flow-specific steps. fallback to "actions" for accept
        steps = flows.get(action) or (cmp.get("actions", []) if action =="accept" else [])

        if action == "reject" and not steps and flows.get("manage"):
            opened = False
            for act in flows["manage"]:
                t = act.get("type")
                v = act.get("value")
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
                            except Exception: pass
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
            t = act.get("type")
            v = act.get("value")

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
                        # For accept we allow falling back to the provided selector (often the Accept CTA)
                        target = loc
                    # Need text match for reject, keep searching otherwise
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
                            # For accept we can still use the provided selector
                            target = loc
                            cmp["selector-list-item"] = selector
                            break
                        # For reject: no text match, keep iterating selectors

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

    # OneTrust fast path for ACCEPT
    if action == "accept":
        for sel in ("#onetrust-accept-btn-handler", "#accept-recommended-btn-handler"):
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0 and await _try_click(loc):
                    try:
                        await page.wait_for_load_state("networkidle", timeout=3000)
                    except PlaywrightTimeoutError:
                        pass
                    # If the button is gone, we’re confident
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

    # FALLBACK: text search on page, then frames
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
    
    # Fallback: open "Manage/Preferences", then try Reject again
    if action == "reject":
        try:
            manage_steps = []
            for cmp in consent_managers:
                if cmp.get("flows", {}).get("manage"):
                    manage_steps = cmp["flows"]["manage"]
                    break
            # Or esle try common selectors
            opened = False
            for act in manage_steps or []:
                parent = page
                t = act.get("type")
                v = act.get("value")
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
            
            # Try common OneTrust fast path
            open_candidates = ["#onetrust-pc-btn-handler"]
            
            for sel in open_candidates:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    if await _try_click(loc):
                        opened = True
                        break

            # If still not opened yet, try generic text-based manage button
            if not opened:
                btn = page.get_by_role("button", name=MANAGE_TEXT).first
                if await btn.count() > 0:
                    opened = await _try_click(btn)

            if opened:
                try:
                    await page.wait_for_load_state("networkidle", timeout=2000)
                except Exception:
                    pass

                # Try Reject again
                reject_locators = [
                    "#onetrust-reject-all-handler",
                ]
                btn = page.get_by_role("button", name=REJECT_TEXT).first
                if await btn.count() > 0 and await _try_click(btn):
                    return {"id":"fallback-manage-text","name":"Manage then Reject (text)","status":"clicked","clicked_action":"reject"}

                for sel in reject_locators:
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
            # remove potential CDATA tags
            match = re.search(
                r"//<!\[CDATA\[\s*(.*?)\s*//\]\]>", contents.strip(), re.DOTALL
            )
            if match:
                json_ld.append(json.loads(match.group(1), strict=False))
            else:
                json_ld.append(json.loads(contents.strip(), strict=False))
        except Exception as e:
            logging.debug(f"Unable to parse JSON-LD: {e}")
            json_ld.append({"raw": str(contents), "error": str(e)})

    return json_ld


async def get_meta_tags(page):
    meta_tags = {}
    for tag in await page.locator("meta[name]").all():
        try:
            meta_tags[await tag.get_attribute("name")] = await tag.get_attribute(
                "content"
            )
        except Exception as e:
            logging.debug(f"Unable to get meta tag: {e}")
    return meta_tags


async def crawl_url(
    url,
    browser,
    tracking_domains_list=None,
    screenshot=True,
    device=None,
    wait_for_timeout=5000,
    consent_action: str = "accept-all",
    custom_prefs = None,
):
    """
    Open a new browser context with a URL and extract data about cookies and
    tracking domains before and after consent.
    Returns:
    - All third party domains requested
    - Third party domains requested before consent
    - All tracking domains (based on blocklist)
    - Tracking domains before consent
    - All cookies (name, domain, expiration in days)
    - Cookies set before consent
    - Consent manager that was used on the site
    - Screenshot of the site before consenting
    """
    output = {k: None for k in get_extract_schema().keys()}
    output["screenshot_files"] = []
    
    try:
        raw_input = url.strip()
        added_scheme = False
        if not re.match(r"^https?://", raw_input, re.I):
            url = "https://" + raw_input
            added_scheme = True
        else:
            url = raw_input
        # if not url.startswith("http"):
        #     url = "https://" + url

        output["url"] = url
        output["extraction_datetime"] = str(datetime.now())

        if device is None:
            device = {}
        if tracking_domains_list is None:
            tracking_domains_list = []

        if "user_agent" not in device:
            # device["user_agent"] = random.choice(DEFAULT_UA_STRINGS)
            if BROWSER_TYPE == "msedge":
                device["user_agent"] = DEFAULT_UA_STRINGS[0]
            else:
                device["user_agent"] = DEFAULT_UA_STRINGS[1]
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

        browser_context = await browser.new_context(
            **device,
        )
        await browser_context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        req_urls = []
        page = await browser_context.new_page()
        page.on("request", lambda req: req_urls.append(req.url))

        try:
            await page.goto(url, wait_until="load", timeout=90000)
        except Exception:
            if added_scheme and url.startswith("https://"):
                alt = "http://" + raw_input
                await page.goto(alt, wait_until="load", timeout=90000)
                url = alt
            else:
                raise
        
                # output["domain_name"] = re.search("(?:https?://)?(?:www.)?([^/]+)", url).group(
        #     1
        # )
        output["landed_url"] = page.url
        landed_host = host_from_url(page.url) or host_from_url(url) or raw_input
        output["domain_name"] = landed_host
        site_etld1 = registrable_domain(landed_host) or landed_host
        # base64_url = base64.urlsafe_b64encode(
        #     output["domain_name"].encode("ascii")
        # ).decode("ascii")
        # id_source = landed_host.encode("idna").decode("ascii")

        # output["id"] = base64.urlsafe_b64encode(id_source.encode("ascii")).decode("ascii")
        # run_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        run_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        id_source = f"{landed_host}|{run_tag}|{consent_action}".encode("idna").decode("ascii")
        output["id"] = base64.urlsafe_b64encode(id_source.encode("ascii")).decode("ascii")

        logging.info(f"Extracting data from domain {output['domain_name']}")

        await page.wait_for_timeout(10000)
        await page.mouse.move(543, 123)
        await page.mouse.wheel(0, -123)
        await page.wait_for_timeout(
            wait_for_timeout
        )  # additional wait time just to be sure as consent managers can sometimes take a while to load
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

        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
        except PlaywrightTimeoutError:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except PlaywrightTimeoutError:
            pass
        
        thirdparty_requests_pre = [r for r in req_urls if is_third_party(r, page.url)]

        output["pre_third_party_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_pre
            if registrable_domain(host_from_url(r))
        })
        tracking_set = {h.lower() for h in (tracking_domains_list or [])}
        output["pre_tracking_domains"] = sorted({
            registrable_domain(host_from_url(r))
            for r in thirdparty_requests_pre
            if is_blocklisted_host(host_from_url(r), tracking_set)
        })


        # Collect all cookies, then keep only those for this site (by registrable domain)
        current_host = host_from_url(page.url) or host_from_url(url)
        site_etld1 = registrable_domain(current_host)
        all_cookies = await browser_context.cookies()
        cookies = [c for c in all_cookies if registrable_domain(c.get("domain", "").lstrip(".")) == site_etld1]

        output["pre_cookies"] = [
            {
                "name": c["name"],
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
            for c in cookies
        ]
        # output["pre_cookies"].sort(key=lambda c: ((c.get("name") or ""), (c.get("domain") or "")))
        output["pre_cookies"].sort(key=lambda c: c.get("name") or "")

        pre_len = len(req_urls)
        output["consent_action"] = consent_action
        logging.debug(f"Trying to {consent_action} on {output['domain_name']}")

        # Map action to flow
        if consent_action in ("accept", "reject"):
            cmp = await click_consent_manager(page, action=consent_action)
        elif consent_action =="custom":
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

        thirdparty_requests_post = [r for r in req_urls[pre_len:] if is_third_party(r, page.url)]
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


        all_cookies = await browser_context.cookies()
        current_host = host_from_url(page.url) or host_from_url(url)
        site_etld1 = registrable_domain(current_host)
        cookies = [c for c in all_cookies if registrable_domain(c.get("domain", "").lstrip(".")) == site_etld1]
        output["post_cookies"] = [
            {
                "name": c["name"],
                "domain": c["domain"],
                "path": c.get("path"),
                "secure": bool(c.get("secure")),
                "httpOnly": bool(c.get("httpOnly")),
                "sameSite": c.get("sameSite"),
                "expires": int(c.get("expires") or 0),
                "session": int(c.get("expires") or 0) <= 0,
                "expires_days": (
                    (date.fromtimestamp(int(c.get("expires") or 0)) - date.today()).days
                    if int(c.get("expires", 0) or 0) > 0 else None
                ),
            }
            for c in cookies
        ]
        # output["post_cookies"].sort(key=lambda c: ((c.get("name") or ""), (c.get("domain") or "")))
        output["post_cookies"].sort(key=lambda c: c.get("name") or "")

        await browser_context.close()

        output["status"] = "success"
        output["status_msg"] = f"Successfully extracted data from {url}"

        return output

    except Exception as e:
        error_msg = f"Error extracting data from {url}: {e}"
        logging.debug(error_msg)

        output["status"] = "error"
        output["status_msg"] = error_msg

        return output


async def crawl_batch(
    urls,
    results_function,
    batch_size=10,
    tracking_domains_list=None,
    browser_config=None,
    screenshot=False,
    flow="accept-all",
    custom_prefs=None,
    **kwargs,
):
    """
    Run the crawler for multiple URLs in batches and apply a (async) function
    to the results. Additional arguments can be passed to the results function.
    """
    browser = 'chrome'
    if tracking_domains_list is None:
        tracking_domains_list = []
    
    if not browser_config:
        if BROWSER_TYPE == 'msedge':
            browser_config = {"headless": True, "channel": "msedge", "args": common_args}
        else:
            browser_config = {"headless": True, "channel": "chrome", "args": common_args}

    async with async_playwright() as p:
        logging.debug("Starting browser")
        # browser = await p.chromium.launch(**browser_config)
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

        for urls_batch in utils.batch(urls, batch_size):
            def _map_flow_to_action(f):
                if f == "accept-all":
                    return "accept"
                if f == "reject-all":
                    return "reject"
                if f == "custom":
                    return "custom"
                return "reject"
            data = [
                crawl_url(
                    url=url,
                    browser=browser,
                    tracking_domains_list=tracking_domains_list,
                    screenshot=screenshot,
                    consent_action=_map_flow_to_action(flow),
                    custom_prefs=custom_prefs,
                )
                for url in urls_batch
            ]
            results = [
                r for r in await asyncio.gather(*data)
            ]  # run all urls in parallel
            logging.debug(f"Retrieved batch of {len(data)} URLs")

            await results_function(results, **kwargs)

        await browser.close()

        # return the last batch for convenience
    return results


async def crawl_single(url, tracking_domains_list=None, browser_config=None):
    """Crawl a single URL asynchronously."""
    if tracking_domains_list is None:
        tracking_domains_list = []
    if not browser_config:
        if BROWSER_TYPE == 'msedge':
            browser_config = {"headless": True, "channel": "msedge", "args": common_args}
        else:
            browser_config = {"headless": True, "channel": "chrome", "args": common_args}


    async with async_playwright() as p:
        logging.debug("Starting browser")
        browser = await p.chromium.launch(**browser_config)

        return await crawl_url(
            url=url, browser=browser, tracking_domains_list=tracking_domains_list
        )


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
            d = {
                k: json.dumps(v) if type(v) in [dict, list, tuple] else v
                for k, v in d.items()
            }
            cols = list(get_extract_schema().keys())
            placeholders = ",".join(["?"] * len(cols))
            vals = [d.get(k) for k in cols]
            c.execute(
                f"INSERT INTO {table_name} ({','.join(cols)}) VALUES ({placeholders})",
                vals,
            )
            conn.commit()

        conn.close()
