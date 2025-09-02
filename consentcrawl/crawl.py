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

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
CONSENT_MANAGERS_FILE = f"{MODULE_DIR}/assets/consent_managers.yml"

DEFAULT_UA_STRINGS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/116.0.1938.81"
]

ACCEPT_TEXT = re.compile(
    r"\b("
    r"accept|agree|allow|consent|ok|got it|"
    r"akzeptieren|zustimmen|alle akzeptieren|"
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

def get_extract_schema():
    return {
        "id": "STRING",
        "url": "STRING",
        "domain_name": "STRING",
        "extraction_datetime": "STRING",
        "cookies_all": "STRING",
        "cookies_no_consent": "STRING",
        "third_party_domains_all": "STRING",
        "third_party_domains_no_consent": "STRING",
        "tracking_domains_all": "STRING",
        "tracking_domains_no_consent": "STRING",
        "consent_manager": "STRING",
        "screenshot_files": "STRING",
        "meta_tags": "STRING",
        "json_ld": "STRING",
        "status": "STRING",
        "status_msg": "STRING",
    }


def get_consent_managers():
    with open(CONSENT_MANAGERS_FILE, "r") as f:
        data = yaml.safe_load(f)
        return data

async def _try_click(locator):
    # Try a safe click first; if it fails, force it.
    await locator.scroll_into_view_if_needed()
    try:
        await locator.click(timeout=3000, trial=True)
        await locator.click(timeout=3000)
        return True
    except PlaywrightTimeoutError:
        await locator.click(timeout=3000, force=True)
        return True
    except Exception:
        return False
    
async def click_consent_manager(page):
    """
    Try known CMPs; if we find a container but not a clear CTA, fall back to text-based Accept/Agree hits.
    Mark status 'clicked' only if the banner actually disappears or requests spike after the click.
    """
    consent_managers = get_consent_managers()
    for cmp in consent_managers:
        parent = page
        target = None

        for action in cmp["actions"]:
            t = action["type"]
            v = action["value"]

            if t == "iframe":
                # Narrow into CMP iframe if present
                try:
                    # Wait for the iframe to be attached, then restrict all further lookups to it
                    await parent.locator(v).first.wait_for(state="attached", timeout=3000)
                    parent = parent.frame_locator(v).first
                except Exception:
                    # Iframe not present => this CMP likely isn't here; try next CMP
                    parent = None
                    break

            elif t == "css-selector":
                loc = parent.locator(v).first
                if await loc.count() > 0 and await loc.is_visible():
                    # Prefer visible button-like descendants with Accept text
                    preferred = loc.locator("button, a, [role='button']").filter(has_text=ACCEPT_TEXT).first
                    target = preferred if await preferred.count() > 0 else loc
                    break

            elif t == "css-selector-list":
                for selector in v:
                    loc = parent.locator(selector).first
                    if await loc.count() > 0 and await loc.is_visible():
                        preferred = loc.locator("button, a, [role='button']").filter(has_text=ACCEPT_TEXT).first
                        if await preferred.count() > 0:
                            target = preferred
                            cmp["selector-list-item"] = selector
                            break
                        target = loc
                        cmp["selector-list-item"] = selector
                        break

            elif t == "xpath":
                # Not implemented; skip
                continue

        if parent is None:
            # CMP not on page; move to next
            continue

        if target is not None:
            try:
                # Snapshot pre-click request count to detect any network activity after the click
                pre_req_count = len((await page.context.storage_state())["origins"])  # cheap op; not perfect
            except Exception:
                pre_req_count = 0

            ok = await _try_click(target)
            if not ok:
                cmp["status"] = "error"
                cmp["error"] = "click failed"
                return cmp

            # Give the page a brief chance to load/settle; banners often self-remove
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except PlaywrightTimeoutError:
                pass

            # Heuristic: banner gone or accept CTA no longer visible?
            try:
                still_visible = await target.is_visible()
            except Exception:
                still_visible = False
            cmp["status"] = "clicked" if not still_visible else "clicked-uncertain"
            return cmp
    
    # FALLBACK
    # 1) page-wide
    btn = page.get_by_role("button", name=ACCEPT_TEXT).first
    if await btn.count() > 0 and await btn.is_visible():
        if await _try_click(btn):
            return {"id":"fallback-text","name":"Text search","status":"clicked"}

    # 2) all iframes
    for frame in page.frames:
        btn = frame.get_by_role("button", name=ACCEPT_TEXT).first
        if await btn.count() > 0 and await btn.is_visible():
            if await _try_click(btn):
                return {"id":"fallback-text-in-frame","name":"Text search (frame)","status":"clicked"}

    logging.debug(f"Unable to accept cookies on: {page.url}")
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
        if not url.startswith("http"):
            url = "https://" + url

        output["url"] = url
        output["extraction_datetime"] = str(datetime.now())
        if device is None:
            device = {}
        if tracking_domains_list is None:
            tracking_domains_list = []

        if "user_agent" not in device:
            device["user_agent"] = random.choice(DEFAULT_UA_STRINGS)

        if "viewport" not in device:
            device["viewport"] = {"width": 1366, "height": 768}

        browser_context = await browser.new_context(
            **device,
        )
        await browser_context.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        # output["domain_name"] = re.search("(?:https?://)?(?:www.)?([^/]+)", url).group(
        #     1
        # )
        output["domain_name"] = host_from_url(url) or url

        base64_url = base64.urlsafe_b64encode(
            output["domain_name"].encode("ascii")
        ).decode("ascii")

        output["id"] = base64_url
        run_tag = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        logging.info(f"Start extracting data from domain {output['domain_name']}")

        req_urls = []

        page = await browser_context.new_page()
        page.on("request", lambda req: req_urls.append(req.url))

        await page.goto(url, wait_until="load", timeout=90000)

        await page.wait_for_timeout(2000)
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

        # # Capture data pre-consent
        # thirdparty_requests = list(
        #     filter(lambda req_url: not output["domain_name"] in req_url, req_urls)
        # )
        # output["third_party_domains_no_consent"] = list(
        #     set(
        #         map(
        #             lambda r: re.search("https?://(?:www.)?([^\/]+\.[^\/]+)", r).group(
        #                 1
        #             ),
        #             thirdparty_requests,
        #         )
        #     )
        # )
        # output["tracking_domains_no_consent"] = list(
        #     set(
        #         [
        #             re.search("[^\.]+\.[a-z]+$", d).group(0)
        #             for d in output["third_party_domains_no_consent"]
        #             if d in tracking_domains_list
        #         ]
        #     )
        # )
        # cookies = await browser_context.cookies()
        
        pre_len = len(req_urls)
        # page_host = host_from_url(url)
        # page_reg = registrable_domain(page_host)
        
        thirdparty_requests_pre = [r for r in req_urls if is_third_party(r, url)]

        output["third_party_domains_no_consent"] = sorted({
            registrable_domain(r) for r in thirdparty_requests_pre
            if registrable_domain(r)
        })

        tracking_set = set(tracking_domains_list)

        output["tracking_domains_no_consent"] = sorted({
            registrable_domain(r)
            for r in thirdparty_requests_pre
            if is_blocklisted_host(host_from_url(r), tracking_set)
        })

        # cookies = await browser_context.cookies([url])

        # Collect all cookies, then keep only those for this site (by registrable domain)
        current_host = host_from_url(page.url) or host_from_url(url)
        site_etld1 = registrable_domain(current_host)
        all_cookies = await browser_context.cookies()
        cookies = [c for c in all_cookies if registrable_domain(c.get("domain", "").lstrip(".")) == site_etld1]

        output["cookies_no_consent"] = [
            {
                "name": c["name"],
                "domain": c["domain"],
                "path": c.get("path"),
                "secure": bool(c.get("secure")),
                "httpOnly": bool(c.get("httpOnly")),
                "sameSite": c.get("sameSite"),
                "expires": int(c.get("expires", 0)),
                "session": int(c.get("expires", 0) or 0) <= 0,
                "expires_days": (
                    (date.fromtimestamp(int(c["expires"])) - date.today()).days
                    if int(c.get("expires", 0)) > 0 else None
                ),
            }
            for c in cookies
        ]

        output["cookies_no_consent"].sort(key=lambda c: ((c.get("name") or ""), (c.get("domain") or "")))

        # try to accept full marketing consent
        logging.debug(
            f"Trying to accept full marketing consent on {output['domain_name']}"
        )
        output["consent_manager"] = await click_consent_manager(page)

        # if screenshot and output["consent_manager"].get("status", "") not in [
        #     "error",
        #     "",
        # ]:
        if screenshot and output["consent_manager"].get("status")  in ("clicked", "clicked-uncertain"):
            try:
                path_post = f'./screenshots/screenshot_{output["id"]}_{run_tag}_afterconsent.png'
                await page.locator("body").screenshot(path=path_post, timeout=15000)
                output["screenshot_files"].append(path_post)
            except Exception as e:
                logging.debug(f"Post-consent screenshot failed: {e}")

        # thirdparty_requests = list(
        #     filter(lambda req_url: not output["domain_name"] in req_url, req_urls)
        # )
        # output["third_party_domains_all"] = list(
        #     set(
        #         map(
        #             lambda r: re.search("https?://(?:www.)?([^\/]+\.[^\/]+)", r).group(
        #                 1
        #             ),
        #             thirdparty_requests,
        #         )
        #     )
        # )
        # output["tracking_domains_all"] = list(
        #     set(
        #         [
        #             re.search("[^\.]+\.[a-z]+$", d).group(0)
        #             for d in output["third_party_domains_all"]
        #             if d in tracking_domains_list
        #         ]
        #     )
        # )

        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except PlaywrightTimeoutError:
            pass
        await page.wait_for_timeout(wait_for_timeout)
        # thirdparty_requests_all = [
        #     r for r in req_urls if is_third_party(r, url)
        # ]

        thirdparty_requests_post = [
            r for r in req_urls[pre_len:] if is_third_party(r, url)
        ]
        output["third_party_domains_all"] = sorted({
            registrable_domain(r) for r in thirdparty_requests_post
            if registrable_domain(r)
        })
        output["tracking_domains_all"] = sorted({
            registrable_domain(r)
            for r in thirdparty_requests_post
            if is_blocklisted_host(host_from_url(r), tracking_set)
        })

        all_cookies = await browser_context.cookies()
        current_host = host_from_url(page.url) or host_from_url(url)
        site_etld1 = registrable_domain(current_host)
        cookies = [c for c in all_cookies if registrable_domain(c.get("domain", "").lstrip(".")) == site_etld1]

        output["cookies_all"] = [
            {
                "name": c["name"],
                "domain": c["domain"],
                "path": c.get("path"),
                "secure": bool(c.get("secure")),
                "httpOnly": bool(c.get("httpOnly")),
                "sameSite": c.get("sameSite"),
                "expires": int(c.get("expires", 0)),
                "session": int(c.get("expires", 0) or 0) <= 0,
                "expires_days": (
                    (date.fromtimestamp(int(c["expires"])) - date.today()).days
                    if int(c.get("expires", 0) or 0) > 0 else None
                ),
            }
            for c in cookies
        ]

        output["cookies_all"].sort(key=lambda c: ((c.get("name") or ""), (c.get("domain") or "")))

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
    **kwargs,
):
    """
    Run the crawler for multiple URLs in batches and apply a (async) function
    to the results. Additional arguments can be passed to the results function.
    """
    if tracking_domains_list is None:
        tracking_domains_list = []
    if not browser_config:
        browser_config = {"headless": True, "channel": "msedge"}

    async with async_playwright() as p:
        logging.debug("Starting browser")
        browser = await p.chromium.launch(**browser_config)

        for urls_batch in utils.batch(urls, batch_size):
            data = [
                crawl_url(
                    url=url,
                    browser=browser,
                    tracking_domains_list=tracking_domains_list,
                    screenshot=screenshot,
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
        browser_config = {"headless": True, "channel": "msedge"}

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
