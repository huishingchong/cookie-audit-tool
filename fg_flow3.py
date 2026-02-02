# fg_flow.py
import argparse
import asyncio
import json
import os
import re
import csv

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlparse

from openpyxl import Workbook
from openpyxl.utils import get_column_letter

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError, Page

from consentcrawl.crawl import click_consent_manager, _site_cookies
from consentcrawl.custom_flow import customise as customise_cmp


STEPS = ["home", "consent", "search", "pdp", "add", "bag", "login_page", "login_submit", "post_auth_search", "post_auth_pdp", "post_auth_add", "post_auth_checkout"]

def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def _looks_like_auth(url: str) -> bool:
    u = (url or "").lower()
    return any(k in u for k in ["login", "signin", "sign-in", "account", "auth", "identity", "oauth"])

async def _already_on_login_form(page: Page) -> bool:
    email = page.locator("input[type='email'], input[name*='email' i], input[id*='email' i]").first
    pwd = page.locator("input[type='password']").first
    try:
        return (
            await email.count() > 0 and await email.is_visible()
            and await pwd.count() > 0 and await pwd.is_visible()
        )
    except Exception:
        return False

def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def _safe_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_")

def _parse_bool(s: str) -> bool:
    if isinstance(s, bool):
        return s
    v = (s or "").strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("Expected yes/no, true/false, 1/0, on/off")

def _parse_categories(s: Optional[str]) -> Optional[Dict[str, bool]]:
    if not s:
        return None
    allowed = {"analytics", "functional", "advertising"}
    aliases = {"marketing": "advertising", "ads": "advertising", "advertisement": "advertising"}
    truthy = {"1", "true", "on", "yes"}
    falsy = {"0", "false", "off", "no"}

    out: Dict[str, bool] = {}
    for raw in s.split(","):
        raw = raw.strip()
        if not raw:
            continue
        if "=" not in raw:
            raise argparse.ArgumentTypeError(f"Invalid pair '{raw}'. Use key=value.")
        k, v = raw.split("=", 1)
        key = aliases.get(k.strip().lower(), k.strip().lower())
        val = v.strip().lower()
        if key not in allowed:
            raise argparse.ArgumentTypeError(f"Unknown category '{key}'. Allowed: {sorted(allowed)}")
        if val in truthy:
            out[key] = True
        elif val in falsy:
            out[key] = False
        else:
            raise argparse.ArgumentTypeError(f"Invalid value '{val}' for {key}. Use on/off/true/false/yes/no/1/0")
    return out

OBS_HEADERS = [
    "run_id", "base_url", "site_etld1",
    "flow", "flow_params",
    "step", "step_index",
    "ts_utc", "page_url",
    "cookie_key",
    "name", "domain", "path",
    "secure", "httpOnly", "sameSite",
    "session", "expires", "expires_days",
]

def _cookie_key(name: str, domain: str, path: str) -> str:
    return f"{(name or '').strip()}|{(domain or '').strip()}|{(path or '').strip()}"

class ObservationsCsvSink:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh)

        if self.path.stat().st_size == 0:
            self._writer.writerow(OBS_HEADERS)
            self._fh.flush()

    def write_row(self, row: list) -> None:
        self._writer.writerow(row)
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

def _autosize(ws, min_w: int = 10, max_w: int = 60) -> None:
    for col in range(1, ws.max_column + 1):
        letter = get_column_letter(col)
        max_len = 0
        for cell in ws[letter]:
            v = "" if cell.value is None else str(cell.value)
            max_len = max(max_len, len(v))
        ws.column_dimensions[letter].width = max(min_w, min(max_w, max_len + 2))

def csv_to_xlsx(csv_path: Path, xlsx_path: Path, sheet_name: str = "observations") -> None:
    xlsx_path.parent.mkdir(parents=True, exist_ok=True)

    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name

    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            ws.append(row)

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    _autosize(ws)

    wb.save(xlsx_path)

async def _dump_snapshot(
    *,
    context,
    page: Page,
    site_etld1: str,
    out_dir: Path,
    prefix: str,
    note: str,
    obs_sink: Optional[ObservationsCsvSink] = None,
    run_id: str = "",
    base_url: str = "",
    flow: str = "",
    flow_params: str = "",
    step: str = "",
    step_index: int = 0,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = _now_stamp()
    base = f"{prefix}_{ts}_{_safe_filename(note)}"

    cookies = await _site_cookies(context, site_etld1)

    if obs_sink is not None:
        for c in cookies or []:
            name = c.get("name", "")
            domain = c.get("domain", "")
            path = c.get("path", "") or ""
            obs_sink.write_row([
                run_id, base_url, site_etld1,
                flow, flow_params,
                step, step_index,
                ts, page.url,
                _cookie_key(name, domain, path),
                name, domain, path,
                bool(c.get("secure")),
                bool(c.get("httpOnly")),
                c.get("sameSite") or "",
                bool(c.get("session")) if "session" in c else (int(c.get("expires") or 0) <= 0),
                int(c.get("expires") or 0),
                c.get("expires_days"),
            ])

    cookies_path = out_dir / f"{base}.cookies.json"
    meta_path = out_dir / f"{base}.meta.json"
    shot_path = out_dir / f"{base}.png"

    with cookies_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "ts_utc": ts,
                "url": page.url,
                "note": note,
                "site_etld1": site_etld1,
                "count": len(cookies),
                "cookies": cookies,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(
            {"ts_utc": ts, "url": page.url, "note": note, "site_etld1": site_etld1},
            f,
            ensure_ascii=False,
            indent=2,
        )

    try:
        await page.screenshot(path=str(shot_path), full_page=True)
    except Exception:
        pass

async def _perform_consent(
    page: Page,
    flow: str,
    categories: Optional[Dict[str, bool]],
) -> Dict[str, Any]:
    if flow == "accept-all":
        return await click_consent_manager(page, action="accept")
    if flow == "reject-all":
        return await click_consent_manager(page, action="reject")
    if flow == "custom":
        if not categories:
            raise ValueError("custom flow requires --categories (e.g. analytics=off,advertising=off,functional=on)")
        return await customise_cmp(page, categories, managers=None)
    raise ValueError(f"Unknown flow: {flow}")

async def _search_product(page: Page, search_term: str) -> None:
    candidates = [
        page.get_by_role("searchbox").first,
        page.locator("input[type='search']").first,
        page.locator("input[placeholder*='search' i]").first,
        page.locator("input[name*='search' i]").first,
    ]

    for loc in candidates:
        try:
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=3000)
                await loc.fill(search_term)
                await loc.press("Enter")
                await page.wait_for_load_state("domcontentloaded")
                await page.wait_for_timeout(1200)
                return
        except Exception:
            continue

    await page.goto(urljoin(page.url, f"/searchresults?descriptionfilter={search_term.replace(' ', '+')}"),
                    wait_until="domcontentloaded")
    await page.wait_for_timeout(1200)

async def _open_first_product(page: Page) -> None:
    locators = [
        page.locator("a.ProductImageList[href*='colcode=']").first,
        page.locator("a[href*='colcode=']").first,
        page.locator("a[href*='/product/']").first,
        page.locator("a[href*='product']").first,
        page.locator("a").filter(has_text=re.compile(r"€|£", re.I)).first,
    ]
    for loc in locators:
        try:
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=8000)
                await page.wait_for_load_state("domcontentloaded")
                await page.wait_for_timeout(1200)
                return
        except Exception:
            continue
    raise RuntimeError("Could not find a clickable product link on the results page.")

async def _select_in_stock_size_if_needed(page: Page) -> bool:
    """
    Selects an in-stock size when required.
    Returns True if a size was selected and CTA appears actionable.
    """
    
    def _add_cta():
        return page.locator(
            "#aAddToBag, "
            "a.addToBag, "
            "button[data-testid='purchase-button'], "
            "button:has-text('Add to bag'), "
            "button:has-text('Add To Bag')"
        ).first
    
    async def _cta_is_ready() -> bool:
        """Check if add-to-bag button is visible and actionable."""
        cta = _add_cta()
        try:
            if await cta.count() == 0:
                return False
            
            if not await cta.is_visible():
                return False
            
            text = await cta.inner_text()
            if "select" in text.lower() and "size" in text.lower():
                return False
            
            if hasattr(cta, "is_enabled"):
                if not await cta.is_enabled():
                    return False
            
            aria_disabled = await cta.get_attribute("aria-disabled")
            if aria_disabled and aria_disabled.lower() == "true":
                return False
            
            if await cta.get_attribute("disabled") is not None:
                return False
            
            overlay = page.locator("#NonBuyableOverlay").first
            if await overlay.count() > 0 and await overlay.is_visible():
                box = await overlay.bounding_box()
                if box and box.get("width", 0) >= 50:
                    return False
            
            return True
            
        except Exception:
            return False
    
    if await _cta_is_ready():
        return True
    
    # Try IE swatches (also handles design/color swatches)
    enabled_swatches = page.locator("[data-testid='swatch-button-enabled']")
    swatch_count = await enabled_swatches.count()
    
    if swatch_count > 0:
        for i in range(min(swatch_count, 30)):
            swatch = enabled_swatches.nth(i)
            try:
                if not await swatch.is_visible():
                    continue
                
                await swatch.scroll_into_view_if_needed(timeout=2000)
                await swatch.click(timeout=3000)
                await page.wait_for_timeout(800)
                
                if await _cta_is_ready():
                    return True
                    
            except Exception:
                continue
        
        return await _cta_is_ready()
    
    # Try WWW legacy list
    legacy_items = page.locator(
        "#ulSizes li.sizeButtonli, "
        "#ulSizes li.tooltip.sizeButtonli, "
        "ul#ulSizes li[role='radio']"
    )
    legacy_count = await legacy_items.count()
    
    if legacy_count == 0:
        return await _cta_is_ready()
    
    for i in range(min(legacy_count, 40)):
        li = legacy_items.nth(i)
        try:
            if not await li.is_visible():
                continue
            
            cls = (await li.get_attribute("class")) or ""
            if "greyOut" in cls or "disabled" in cls:
                continue
            
            stock_raw = await li.get_attribute("data-stock-qty")
            if stock_raw is not None:
                try:
                    if int(stock_raw) <= 0:
                        continue
                except Exception:
                    pass
            
            await li.scroll_into_view_if_needed(timeout=2000)
            
            clicked = False
            for target in (li, li.locator("a, button").first):
                try:
                    await target.click(timeout=3000)
                    clicked = True
                    break
                except Exception:
                    try:
                        await target.click(timeout=3000, force=True)
                        clicked = True
                        break
                    except Exception:
                        continue
            
            if not clicked:
                continue
            
            await page.wait_for_timeout(800)
            
            if await _cta_is_ready():
                return True
                
        except Exception:
            continue
    
    return await _cta_is_ready()

async def _add_to_bag(page: Page) -> None:
    """
    Add item to bag. Handles both IE (button) and WWW (anchor) variants.
    """
    
    size_selected = await _select_in_stock_size_if_needed(page)
    
    if not size_selected:
        out_of_stock = page.get_by_role("button", name=re.compile(r"\bout of stock\b", re.I)).first
        if await out_of_stock.count() > 0 and await out_of_stock.is_visible():
            raise RuntimeError("Cannot add to bag: Product is out of stock")
        raise RuntimeError("Cannot add to bag: Could not select an in-stock size")
    
    cta_locators = [
        page.locator("#aAddToBag").first,
        page.locator("a.addToBag").first,
        page.locator("button[data-testid='purchase-button']").first,
        page.get_by_role("button", name=re.compile(r"\badd to bag\b", re.I)).first,
    ]
    
    async def _get_button_text(loc) -> str:
        try:
            inner = loc.locator(".addToBagInner").first
            if await inner.count() > 0:
                return (await inner.inner_text()).strip().lower()
            return (await loc.inner_text()).strip().lower()
        except Exception:
            return ""
    
    active_loc = None
    for loc in cta_locators:
        try:
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            
            text = await _get_button_text(loc)
            if "select" in text and "size" in text:
                continue
            
            active_loc = loc
            break
        except Exception:
            continue
    
    if not active_loc:
        raise RuntimeError("Could not find add-to-bag button")
    
    await active_loc.scroll_into_view_if_needed(timeout=2000)
    await page.wait_for_timeout(500)
    
    pre_click_text = await _get_button_text(active_loc)
    
    clicked = False
    
    try:
        await active_loc.click(timeout=10000)
        clicked = True
    except Exception:
        pass
    
    if not clicked:
        try:
            await active_loc.click(timeout=10000, force=True)
            clicked = True
        except Exception:
            pass
    
    if not clicked:
        try:
            await active_loc.evaluate("(el) => el.click()")
            clicked = True
        except Exception:
            pass
    
    if not clicked:
        raise RuntimeError("All click strategies failed")
    
    text_changed = False
    for _ in range(40):
        current_text = await _get_button_text(active_loc)
        
        if "added" in current_text or "added to bag" in current_text:
            text_changed = True
            break
        
        if "adding" in current_text:
            await page.wait_for_timeout(500)
            continue
        
        if current_text != pre_click_text and current_text:
            await page.wait_for_timeout(500)
            continue
        
        await page.wait_for_timeout(500)
    
    if not text_changed:
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            await page.wait_for_timeout(3000)
    
    cart_badge_selectors = [
        "[data-testid='basket'] .itemCount",
        ".basket .itemCount", 
        "#lblItemsInBasket",
        ".basketCount",
        ".basketlink .itemCount",
    ]
    
    await page.wait_for_timeout(1000)
    
    for badge_sel in cart_badge_selectors:
        try:
            badge = page.locator(badge_sel).first
            if await badge.count() > 0 and await badge.is_visible():
                count_text = await badge.inner_text()
                count_match = re.search(r'\d+', count_text)
                if count_match and int(count_match.group()) > 0:
                    return
        except Exception:
            continue
    
    final_text = await _get_button_text(active_loc)
    
    if "adding" in final_text:
        raise RuntimeError(
            "Add to bag appears stuck at 'Adding...'. "
            "This may indicate a failed AJAX request or network issue."
        )
    
    await page.wait_for_timeout(1000)

async def _go_to_bag(page: Page, base_url: str) -> None:
    """Navigate to cart/bag page."""
    
    cart_link_locators = [
        page.locator("a[href='/cart']").first,
        page.locator("a[href*='/cart']").first,
        page.locator("a[data-testid='basket']").first,
        page.get_by_role("link", name=re.compile(r"\b(bag|basket|cart)\b", re.I)).first,
    ]
    
    for loc in cart_link_locators:
        try:
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=8000)
                await page.wait_for_load_state("domcontentloaded")
                await page.wait_for_timeout(1000)
                
                if "/cart" in page.url or "/basket" in page.url or "/bag" in page.url:
                    return
        except Exception:
            continue
    
    try:
        await page.goto(urljoin(base_url, "/cart"), wait_until="domcontentloaded", timeout=20000)
        await page.wait_for_timeout(1000)
        return
    except Exception:
        pass
    
    for path in ("/basket", "/bag", "/checkout/cart"):
        try:
            await page.goto(urljoin(base_url, path), wait_until="domcontentloaded", timeout=20000)
            await page.wait_for_timeout(1000)
            if not ("404" in page.url or "not-found" in page.url.lower()):
                return
        except Exception:
            continue
    
    raise RuntimeError("Could not navigate to cart page")

async def _go_to_checkout_from_cart(page: Page) -> None:
    """
    Click checkout CTA on cart page.
    This should redirect to login if not authenticated.
    """
    
    checkout_locators = [
        page.locator("button[data-action='checkout'].ContinueOn").first,
        page.locator("#divContinueSecurely button").first,
        page.locator("button[data-testid='continue-to-payment']").first,
        page.get_by_role("button", name=re.compile(r"\b(continue securely|continue to checkout|checkout)\b", re.I)).first,
        page.locator("button").filter(has_text=re.compile(r"\b(continue|checkout)\b", re.I)).first,
    ]
    
    for loc in checkout_locators:
        try:
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            
            if hasattr(loc, "is_enabled"):
                try:
                    if not await loc.is_enabled():
                        continue
                except Exception:
                    pass
            
            await loc.scroll_into_view_if_needed(timeout=2000)
            await loc.click(timeout=10000)
            
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=15000)
            except PlaywrightTimeoutError:
                pass
            
            await page.wait_for_timeout(1500)
            return
            
        except Exception:
            continue
    
    raise RuntimeError("Could not find or click checkout button on cart page")

async def _go_to_login_page(page: Page, base_url: str) -> None:
    rx = re.compile(r"\b(sign in|log in|login|account)\b", re.I)
    locators = [
        page.get_by_role("link", name=rx).first,
        page.get_by_role("button", name=rx).first,
        page.locator("a").filter(has_text=rx).first,
        page.locator("button").filter(has_text=rx).first,
    ]
    for loc in locators:
        try:
            if await loc.count() > 0 and await loc.is_visible():
                await loc.click(timeout=8000)
                await page.wait_for_load_state("domcontentloaded")
                await page.wait_for_timeout(1200)
                return
        except Exception:
            continue

    await page.goto(urljoin(base_url, "/login"), wait_until="domcontentloaded", timeout=20000)
    await page.wait_for_timeout(1200)

async def _captcha_present(page: Page) -> bool:
    """
    Check if CAPTCHA is currently visible on the page.
    Checks multiple CAPTCHA providers and patterns.
    """
    selectors = [
        # reCAPTCHA v2
        "iframe[src*='recaptcha' i]",
        "iframe[title*='recaptcha' i]",
        ".g-recaptcha",
        "#g-recaptcha",
        "iframe[src*='anchor' i][src*='recaptcha' i]",
        
        # hCaptcha
        "iframe[src*='hcaptcha' i]",
        "iframe[title*='hcaptcha' i]",
        ".h-captcha",
        "#h-captcha",
        
        # Generic CAPTCHA patterns
        "iframe[src*='captcha' i]",
        "[class*='captcha' i][class*='container' i]",
        "[id*='captcha' i][id*='container' i]",
        
        # Cloudflare Turnstile
        "iframe[src*='turnstile' i]",
        ".cf-turnstile",
        
        # FunCaptcha
        "iframe[src*='funcaptcha' i]",
        "#FunCaptcha",
    ]
    
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            count = await loc.count()
            if count == 0:
                continue
            
            is_visible = await loc.is_visible(timeout=500)
            if not is_visible:
                continue
            
            # For iframes, check size (some hidden iframes exist)
            if "iframe" in sel:
                box = await loc.bounding_box()
                if box:
                    if box["width"] >= 250 and box["height"] >= 60:
                        return True
            else:
                return True
                
        except Exception:
            continue
    
    # Additional check: look for CAPTCHA-related text
    try:
        captcha_text = page.get_by_text(re.compile(r"verify (you're|you are|youre) (not )?(a )?human|complete (the )?captcha|security check", re.I)).first
        if await captcha_text.count() > 0 and await captcha_text.is_visible(timeout=500):
            return True
    except Exception:
        pass
    
    return False

async def _post_submit_captcha_pause(page: Page, manual_captcha: bool) -> None:
    """
    Wait for CAPTCHA and post-login navigation.
    In manual mode, always pauses. In auto mode, only pauses if CAPTCHA detected.
    """
    await page.wait_for_timeout(1000)
    
    captcha_visible = await _captcha_present(page)
    
    if captcha_visible:
        print("CAPTCHA detected - waiting for you to solve it")
        await _wait_for_user(
            "\n============================================================\n"
            "CAPTCHA DETECTED\n"
            "- Solve the CAPTCHA in the browser window\n"
            "- Wait for the page to fully load after solving\n"
            "- Then press ENTER here to continue\n"
            "============================================================\n"
        )
    elif manual_captcha:
        print("Manual CAPTCHA mode - pausing for manual intervention")
        await _wait_for_user(
            "\n============================================================\n"
            "MANUAL CAPTCHA CHECKPOINT\n"
            "- If you see a CAPTCHA, solve it now\n"
            "- Wait for login to complete and page to load\n"
            "- Press ENTER when you see you're logged in\n"
            "============================================================\n"
        )
    
    await page.wait_for_timeout(2000)
    print("Post-login navigation completed")

async def _submit_login(page: Page, username: str, password: str, manual_captcha: bool) -> None:
    async def first_visible(selectors, timeout_ms=2000):
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if await loc.count() > 0:
                    await loc.wait_for(state="visible", timeout=timeout_ms)
                    return loc
            except Exception:
                continue
        return None

    email = await first_visible(
        [
            "input[type='email']",
            "input[name*='email' i]",
            "input[id*='email' i]",
            "input[name*='user' i]",
            "input[id*='user' i]",
            "input[autocomplete='username']",
        ],
        timeout_ms=6000,
    )
    if not email:
        raise RuntimeError("Could not locate username/email field.")

    await email.fill(username)

    pwd = await first_visible(
        [
            "input[type='password']",
            "input[name*='pass' i]",
            "input[id*='pass' i]",
            "input[autocomplete='current-password']",
        ],
        timeout_ms=1500,
    )

    btn = await first_visible(
        [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Continue')",
            "button:has-text('Next')",
            "button:has-text('Sign in')",
            "button:has-text('Log in')",
            "button:has-text('Login')",
        ],
        timeout_ms=4000,
    )
    if not btn:
        rx = re.compile(r"\b(sign in|log in|login|continue|next)\b", re.I)
        loc = page.get_by_role("button", name=rx).first
        try:
            if await loc.count() > 0 and await loc.is_visible():
                btn = loc
        except Exception:
            pass
    if not btn:
        raise RuntimeError("Could not locate a login submit/continue button.")

    # 1-step login
    if pwd:
        await pwd.fill(password)
        await btn.click(timeout=10000)
        print(f"Login form submitted for {username}")
        await _post_submit_captcha_pause(page, manual_captcha=manual_captcha)
        return

    # 2-step login
    await btn.click(timeout=10000)
    await page.wait_for_timeout(800)

    pwd = await first_visible(
        [
            "input[type='password']",
            "input[name*='pass' i]",
            "input[id*='pass' i]",
            "input[autocomplete='current-password']",
        ],
        timeout_ms=8000,
    )

    if not pwd and (manual_captcha or await _captcha_present(page)):
        await _wait_for_user(
            "\nIf a CAPTCHA appears before the password step, solve it.\n"
            "Continue until the password field is visible, then press ENTER.\n"
        )
        pwd = await first_visible(
            [
                "input[type='password']",
                "input[name*='pass' i]",
                "input[id*='pass' i]",
                "input[autocomplete='current-password']",
            ],
            timeout_ms=15000,
        )

    if not pwd:
        raise RuntimeError("Password field did not appear after email step (2-step login).")

    await pwd.fill(password)

    btn2 = await first_visible(
        [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Sign in')",
            "button:has-text('Log in')",
            "button:has-text('Login')",
        ],
        timeout_ms=4000,
    )
    if not btn2:
        rx = re.compile(r"\b(sign in|log in|login)\b", re.I)
        loc = page.get_by_role("button", name=rx).first
        try:
            if await loc.count() > 0 and await loc.is_visible():
                btn2 = loc
        except Exception:
            pass
    if not btn2:
        raise RuntimeError("Could not locate submit button on password step (2-step login).")

    await btn2.click(timeout=10000)
    print(f"Login form submitted for {username}")
    await _post_submit_captcha_pause(page, manual_captcha=manual_captcha)

async def run_flow(
    *,
    base_url: str,
    out_dir: Path,
    headless: bool,
    slow_mo_ms: int,
    flow: str,
    categories: Optional[Dict[str, bool]],
    stop_after: str,
    search_term: str,
    username: Optional[str],
    password: Optional[str],
    delay_ms: int,
    manual_captcha: bool,
    keep_open: bool,
    run_id: str,
    obs_sink: Optional[ObservationsCsvSink],
    flow_params: str = "",
    post_auth_journey: bool = False,
) -> None:
    stop_after = stop_after.lower()
    if stop_after not in STEPS:
        raise ValueError(f"--stop-after must be one of: {STEPS}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=headless,
            slow_mo=slow_mo_ms,
            args=[
                '--disable-blink-features=AutomationControlled',
            ]
        )
        
        context = await browser.new_context(
            locale="en-GB",
            timezone_id="Europe/London",
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        )
        
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-GB', 'en-US', 'en'],
            });
            
            window.chrome = {
                runtime: {},
            };
            
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: 'prompt' }) :
                    originalQuery(parameters)
            );
        """)

        page = await context.new_page()
        await page.goto(base_url, wait_until="domcontentloaded", timeout=90000)
        await page.wait_for_timeout(1500)

        host = re.sub(r"^https?://", "", page.url).split("/")[0].lower()
        try:
            from consentcrawl.domain_utils import registrable_domain
            site_etld1 = registrable_domain(host)
        except Exception:
            site_etld1 = host

        # STEP: home
        print(f"[Step 1/8] Home page loaded")
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="01", note="home_loaded",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="home", step_index=1
        )
        if stop_after == "home":
            await context.close()
            await browser.close()
            return

        # STEP: consent
        print(f"[Step 2/8] Processing consent flow: {flow}")
        cmp_res = await _perform_consent(page, flow=flow, categories=categories)
        try:
            await page.wait_for_load_state("networkidle", timeout=7000)
        except PlaywrightTimeoutError:
            pass
        await page.wait_for_timeout(1500)

        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="02", note="consent_selected",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="consent", step_index=2
        )
        (out_dir / "consent_result.json").write_text(json.dumps(cmp_res, ensure_ascii=False, indent=2), encoding="utf-8")

        if stop_after == "consent":
            await context.close()
            await browser.close()
            return

        # STEP: search
        print(f"[Step 3/8] Searching for: {search_term}")
        await _search_product(page, search_term)
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="03", note="after_search_results",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="search", step_index=3
        )
        if stop_after == "search":
            await context.close()
            await browser.close()
            return

        # STEP: pdp
        print(f"[Step 4/8] Opening product page")
        await _open_first_product(page)
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="04", note="product_page_loaded",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="pdp", step_index=4
        )
        if stop_after == "pdp":
            await context.close()
            await browser.close()
            return

        # STEP: add
        print(f"[Step 5/8] Adding item to bag")
        await _add_to_bag(page)
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="05", note="add_to_bag",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="add", step_index=5
        )
        if stop_after == "add":
            await context.close()
            await browser.close()
            return

        # STEP: bag
        print(f"[Step 6/8] Navigating to cart")
        await _go_to_bag(page, base_url=base_url)
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="06", note="cart",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="bag", step_index=6
        )
        if stop_after == "bag":
            await context.close()
            await browser.close()
            return

        # STEP: login_page
        print(f"[Step 7/8] Navigating to login page")
        base_host = _host(base_url)

        try:
            await _go_to_checkout_from_cart(page)
        except Exception:
            await _go_to_login_page(page, base_url=base_url)

        if not (_host(page.url) != base_host or _looks_like_auth(page.url) or await _already_on_login_form(page)):
            await _go_to_login_page(page, base_url=base_url)

        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="07", note="login_page",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="login_page", step_index=7
        )

        if stop_after == "login_page":
            await context.close()
            await browser.close()
            return

        # STEP: login_submit
        print(f"[Step 8/8] Submitting login")
        if not username or not password:
            raise ValueError("Login steps require credentials: use FG_USER / FG_PASS env vars, or pass --username/--password.")
        
        await _submit_login(page, username=username, password=password, manual_captcha=manual_captcha)
        
        await page.wait_for_timeout(delay_ms)
        await _dump_snapshot(
            context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
            prefix="08", note="after_login_submit",
            obs_sink=obs_sink, run_id=run_id, base_url=base_url,
            flow=flow, flow_params=flow_params,
            step="login_submit", step_index=8
        )

        if keep_open and not post_auth_journey:
            await _wait_for_user("\nFlow finished. Press ENTER to close the browser\n")

        # POST-AUTH JOURNEY (optional)
        if post_auth_journey:
            print("\n" + "="*60)
            print("STARTING POST-AUTHENTICATION JOURNEY")
            print("="*60 + "\n")

            # STEP: post_auth_search
            print(f"[Step 9/12] Navigating to home page (post-auth)")
            await page.goto(base_url, wait_until="domcontentloaded", timeout=90000)
            await page.wait_for_timeout(delay_ms)
            
            print(f"[Step 9/12] Searching for: {search_term} (post-auth)")
            await _search_product(page, search_term)
            await page.wait_for_timeout(delay_ms)
            await _dump_snapshot(
                context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
                prefix="09", note="post_auth_search_results",
                obs_sink=obs_sink, run_id=run_id, base_url=base_url,
                flow=flow, flow_params=flow_params,
                step="post_auth_search", step_index=9
            )
            if stop_after == "post_auth_search":
                await context.close()
                await browser.close()
                return

            # STEP: post_auth_pdp
            print(f"[Step 10/12] Opening product page (post-auth)")
            await _open_first_product(page)
            await page.wait_for_timeout(delay_ms)
            await _dump_snapshot(
                context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
                prefix="10", note="post_auth_product_page",
                obs_sink=obs_sink, run_id=run_id, base_url=base_url,
                flow=flow, flow_params=flow_params,
                step="post_auth_pdp", step_index=10
            )
            if stop_after == "post_auth_pdp":
                await context.close()
                await browser.close()
                return

            # STEP: post_auth_add
            print(f"[Step 11/12] Adding item to bag (post-auth)")
            await _add_to_bag(page)
            await page.wait_for_timeout(delay_ms)
            await _dump_snapshot(
                context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
                prefix="11", note="post_auth_add_to_bag",
                obs_sink=obs_sink, run_id=run_id, base_url=base_url,
                flow=flow, flow_params=flow_params,
                step="post_auth_add", step_index=11
            )
            if stop_after == "post_auth_add":
                await context.close()
                await browser.close()
                return

            # STEP: post_auth_checkout
            print(f"[Step 12/12] Navigating to checkout (post-auth)")
            await _go_to_bag(page, base_url=base_url)
            await page.wait_for_timeout(delay_ms)
            
            try:
                await _go_to_checkout_from_cart(page)
                await page.wait_for_timeout(delay_ms)
            except Exception as e:
                print(f"Warning: Could not proceed to checkout: {e}")
            
            await _dump_snapshot(
                context=context, page=page, site_etld1=site_etld1, out_dir=out_dir,
                prefix="12", note="post_auth_checkout",
                obs_sink=obs_sink, run_id=run_id, base_url=base_url,
                flow=flow, flow_params=flow_params,
                step="post_auth_checkout", step_index=12
            )

            print("\n" + "="*60)
            print("POST-AUTHENTICATION JOURNEY COMPLETE")
            print("="*60 + "\n")

            if keep_open:
                await _wait_for_user("\nPost-auth journey finished. Press ENTER to close the browser\n")

        await context.close()
        await browser.close()

async def _wait_for_user(prompt: str) -> None:
    await asyncio.to_thread(input, prompt)

def _generate_custom_combos(exclude_all_off: bool = True, exclude_all_on: bool = True):
    keys = ["analytics", "advertising", "functional"]
    combos = []
    for a in (False, True):
        for ad in (False, True):
            for f in (False, True):
                cats = {"analytics": a, "advertising": ad, "functional": f}
                if exclude_all_off and (not a and not ad and not f):
                    continue
                if exclude_all_on and (a and ad and f):
                    continue
                combos.append(cats)
    return combos

def _flow_params_str(categories: dict) -> str:
    return ",".join([f"{k}={'on' if categories[k] else 'off'}" for k in ["analytics", "advertising", "functional"]])

async def run_one_or_all(
    *,
    base_url: str,
    out_root: Path,
    headless: bool,
    slow_mo_ms: int,
    stop_after: str,
    search_term: str,
    username: Optional[str],
    password: Optional[str],
    delay_ms: int,
    manual_captcha: bool,
    keep_open: bool,
    flow: str,
    categories: Optional[Dict[str, bool]],
    run_all_flows: bool,
    post_auth_journey: bool,
) -> Path:
    run_tag = "ALLFLOWS" if run_all_flows else flow
    run_id = f"{_safe_filename(base_url)}_{_now_stamp()}_{run_tag}"
    out_dir = out_root / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    obs_csv = out_dir / "observations.csv"
    obs_sink = ObservationsCsvSink(obs_csv)

    try:
        if not run_all_flows:
            await run_flow(
                base_url=base_url,
                out_dir=out_dir,
                headless=headless,
                slow_mo_ms=slow_mo_ms,
                flow=flow,
                categories=categories,
                stop_after=stop_after,
                search_term=search_term,
                username=username,
                password=password,
                delay_ms=delay_ms,
                manual_captcha=manual_captcha,
                keep_open=keep_open,
                run_id=run_id,
                obs_sink=obs_sink,
                flow_params="" if flow != "custom" else _flow_params_str(categories or {}),
                post_auth_journey=post_auth_journey,
            )
        else:
            flow_specs = [("accept-all", None), ("reject-all", None)]
            for cats in _generate_custom_combos(exclude_all_off=True, exclude_all_on=True):
                flow_specs.append(("custom", cats))

            for idx, (f, cats) in enumerate(flow_specs, 1):
                flow_params = "" if f != "custom" else _flow_params_str(cats)
                subname = f if f != "custom" else f"custom_{_safe_filename(flow_params)}"
                sub_dir = out_dir / subname
                sub_dir.mkdir(parents=True, exist_ok=True)

                print(f"\n{'='*60}")
                print(f"Running flow {idx}/{len(flow_specs)}: {subname}")
                print(f"{'='*60}\n")

                await run_flow(
                    base_url=base_url,
                    out_dir=sub_dir,
                    headless=headless,
                    slow_mo_ms=slow_mo_ms,
                    flow=f,
                    categories=cats,
                    stop_after=stop_after,
                    search_term=search_term,
                    username=username,
                    password=password,
                    delay_ms=delay_ms,
                    manual_captcha=manual_captcha,
                    keep_open=False,
                    run_id=run_id,
                    obs_sink=obs_sink,
                    flow_params=flow_params,
                    post_auth_journey=post_auth_journey,
                )
                
                print(f"\nCompleted flow {idx}/{len(flow_specs)}: {subname}\n")
    finally:
        obs_sink.close()

    xlsx_path = out_dir / "cookie_findings.xlsx"
    csv_to_xlsx(obs_csv, xlsx_path, sheet_name="observations")
    return xlsx_path

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FG retail flow runner with cookie snapshots.")
    p.add_argument("--base-url", default="https://ie.sportsdirect.com/", help="Start URL (e.g. https://ie.sportsdirect.com/)")
    p.add_argument("--out-dir", default="fg_runs", help="Directory to write snapshots")
    p.add_argument("--headless", type=_parse_bool, default=True, help="Run headless: yes/no (default: yes)")
    p.add_argument("--slowmo-ms", type=int, default=0, help="Playwright slow motion in ms (debugging)")
    p.add_argument("--flow", choices=["accept-all", "reject-all", "custom"], default="reject-all", help="Consent path")
    p.add_argument("--categories", default=None, help="For --flow custom: analytics=off,advertising=off,functional=on")
    p.add_argument("--stop-after", choices=STEPS, default="consent", help=f"Stop after step (default: consent). Options: {STEPS}")
    p.add_argument("--search-term", default="nike trainers", help="Search term used for product discovery")
    p.add_argument("--username", default=None, help="Login username (prefer env FG_USER)")
    p.add_argument("--password", default=None, help="Login password (prefer env FG_PASS)")
    p.add_argument("--delay-ms", type=int, default=1500, help="Wait this many ms before each cookie snapshot (default: 1500)")
    p.add_argument("--manual-captcha", type=_parse_bool, default=False,
               help="If yes, pause when CAPTCHA is detected so you can solve it manually (default: no)")
    p.add_argument("--keep-open", type=_parse_bool, default=True,
                help="If yes, keep the browser open at the end until you press ENTER (default: yes)")
    p.add_argument(
        "--run-all-flows",
        type=_parse_bool,
        default=False,
        help="Run accept-all, reject-all, and all custom combinations into one workbook (default: no)"
    )
    p.add_argument(
        "--post-auth-journey",
        type=_parse_bool,
        default=False,
        help="After login, repeat the shopping journey (search -> add -> checkout) to capture post-auth cookies (default: no)"
    )

    return p

if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    categories = _parse_categories(args.categories)
    if args.flow == "custom" and not categories and not args.run_all_flows:
        raise SystemExit("ERROR: --flow custom requires --categories (e.g. analytics=off,advertising=off,functional=on)")

    username = os.environ.get("FG_USER") or args.username
    password = os.environ.get("FG_PASS") or args.password

    xlsx_path = asyncio.run(
        run_one_or_all(
            base_url=args.base_url,
            out_root=Path(args.out_dir),
            headless=args.headless,
            slow_mo_ms=args.slowmo_ms,
            stop_after=args.stop_after,
            search_term=args.search_term,
            username=username,
            password=password,
            delay_ms=args.delay_ms,
            manual_captcha=args.manual_captcha,
            keep_open=args.keep_open,
            flow=args.flow,
            categories=categories,
            run_all_flows=args.run_all_flows,
            post_auth_journey=args.post_auth_journey,
        )
    )
    
    print(f"\nWrote: {xlsx_path}")