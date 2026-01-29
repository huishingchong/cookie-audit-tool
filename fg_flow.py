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

# Reuse existing CMP + cookie collection logic (do not re-implement)
from consentcrawl.crawl import click_consent_manager, _site_cookies  # cookie attrs included :contentReference[oaicite:1]{index=1}
from consentcrawl.custom_flow import customise as customise_cmp        # your "custom categories" flow :contentReference[oaicite:2]{index=2}


# --- Flow steps (stop points) ---
STEPS = ["home", "consent", "search", "pdp", "add", "bag", "login_page", "login_submit"]

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
    """
    analytics=off,advertising=off,functional=on
    """
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

# ---
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

        # write header only if file is empty
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

# ---

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

    """
    Writes:
      - cookies JSON (site-scoped, includes Secure/HttpOnly/SameSite/expiry etc.)
      - screenshot PNG
      - small metadata JSON (url + timestamp + note)
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = _now_stamp()
    base = f"{prefix}_{ts}_{_safe_filename(note)}"

    cookies = await _site_cookies(context, site_etld1)  # already normalised :contentReference[oaicite:3]{index=3}

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
        # not fatal
        pass


async def _perform_consent(
    page: Page,
    flow: str,
    categories: Optional[Dict[str, bool]],
) -> Dict[str, Any]:
    """
    Uses your existing CMP implementations.
    - accept/reject: click_consent_manager :contentReference[oaicite:4]{index=4}
    - custom: customise() from custom_flow.py :contentReference[oaicite:5]{index=5}
    """
    if flow == "accept-all":
        return await click_consent_manager(page, action="accept")
    if flow == "reject-all":
        return await click_consent_manager(page, action="reject")
    if flow == "custom":
        if not categories:
            raise ValueError("custom flow requires --categories (e.g. analytics=off,advertising=off,functional=on)")
        # pass managers=None: customise() has OneTrust fast path + generic text/YAML logic already :contentReference[oaicite:6]{index=6}
        return await customise_cmp(page, categories, managers=None)
    raise ValueError(f"Unknown flow: {flow}")


async def _search_product(page: Page, search_term: str) -> None:
    # Prefer ARIA role; fall back to common search input patterns.
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

    # Last resort: try a query-style URL; harmless if it 404s.
    await page.goto(urljoin(page.url, f"/searchresults?descriptionfilter={search_term.replace(' ', '+')}"),
                    wait_until="domcontentloaded")
    await page.wait_for_timeout(1200)


async def _open_first_product(page: Page) -> None:
    # Try product-ish links first; then fall back to a visible link in product list.
    locators = [
        # www.sportsdirect.com commonly uses colcode= in PDP links
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
    
    # Define the add-to-bag CTA locators (in priority order)
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
            
            # Check for "Select a size" text (indicates not ready)
            text = await cta.inner_text()
            if "select" in text.lower() and "size" in text.lower():
                return False
            
            # Check if disabled
            if hasattr(cta, "is_enabled"):
                if not await cta.is_enabled():
                    return False
            
            # Check aria-disabled
            aria_disabled = await cta.get_attribute("aria-disabled")
            if aria_disabled and aria_disabled.lower() == "true":
                return False
            
            # Check disabled attribute
            if await cta.get_attribute("disabled") is not None:
                return False
            
            # Check for blocking overlay
            overlay = page.locator("#NonBuyableOverlay").first
            if await overlay.count() > 0 and await overlay.is_visible():
                box = await overlay.bounding_box()
                if box and box.get("width", 0) >= 50:
                    return False
            
            return True
            
        except Exception:
            return False
    
    # If CTA is already ready, no size selection needed
    if await _cta_is_ready():
        return True
    
    # --- Path A: IE swatches (also handles design/color swatches) ---
    enabled_swatches = page.locator("[data-testid='swatch-button-enabled']")
    swatch_count = await enabled_swatches.count()
    
    if swatch_count > 0:
        # Try each enabled swatch (could be color or size)
        for i in range(min(swatch_count, 30)):
            swatch = enabled_swatches.nth(i)
            try:
                if not await swatch.is_visible():
                    continue
                
                await swatch.scroll_into_view_if_needed(timeout=2000)
                await swatch.click(timeout=3000)
                await page.wait_for_timeout(800)  # Wait for UI to update
                
                # Check if this made the CTA ready
                if await _cta_is_ready():
                    return True
                    
            except Exception:
                continue
        
        # After trying all swatches, check final state
        return await _cta_is_ready()
    
    # --- Path B: WWW legacy list ---
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
            
            # Skip disabled/out-of-stock sizes
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
            
            # Try clicking the li or its child button/anchor
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
            
            # Check if CTA is ready now
            if await _cta_is_ready():
                return True
                
        except Exception:
            continue
    
    return await _cta_is_ready()

async def _add_to_bag(page: Page) -> None:
    """
    Add item to bag. Assumes product page is loaded.
    """
    
    # First, ensure a size is selected
    size_selected = await _select_in_stock_size_if_needed(page)
    
    if not size_selected:
        # Check if product is out of stock
        out_of_stock = page.get_by_role("button", name=re.compile(r"\bout of stock\b", re.I)).first
        if await out_of_stock.count() > 0 and await out_of_stock.is_visible():
            raise RuntimeError("Cannot add to bag: Product is out of stock")
        
        raise RuntimeError("Cannot add to bag: Could not select an in-stock size")
    
    # Define CTA locators
    cta_locators = [
        page.locator("#aAddToBag").first,
        page.locator("a.addToBag").first,
        page.locator("button[data-testid='purchase-button']").first,
        page.get_by_role("button", name=re.compile(r"\badd to bag\b", re.I)).first,
        page.get_by_role("button", name=re.compile(r"\badd to basket\b", re.I)).first,
    ]
    
    # Try clicking the CTA
    for loc in cta_locators:
        try:
            if await loc.count() == 0:
                continue
            
            if not await loc.is_visible():
                continue
            
            await loc.scroll_into_view_if_needed(timeout=2000)
            
            # Get button text before clicking
            try:
                pre_text = (await loc.inner_text()).strip().lower()
                if "select" in pre_text and "size" in pre_text:
                    continue  # Still showing "Select a size"
            except Exception:
                pass
            
            # Try clicking
            try:
                await loc.click(timeout=10000)
            except Exception:
                try:
                    await loc.click(timeout=10000, force=True)
                except Exception:
                    await loc.evaluate("(el) => el.click()")
            
            # Wait for action to complete
            await page.wait_for_timeout(1500)
            
            # Verify success by checking button text changed
            try:
                post_text = (await loc.inner_text()).strip().lower()
                if "added" in post_text:
                    return  # Success!
            except Exception:
                pass
            
            # Alternative: check if mini-bag popup appeared
            mini_bag_indicators = [
                page.locator("[data-testid='mini-bag']").first,
                page.locator(".miniBag").first,
                page.get_by_text(re.compile(r"added to (bag|basket)", re.I)).first,
            ]
            
            for indicator in mini_bag_indicators:
                try:
                    if await indicator.count() > 0 and await indicator.is_visible():
                        return  # Success!
                except Exception:
                    continue
            
            # If we got here, assume success (no error means it worked)
            return
            
        except Exception as e:
            continue
    
    raise RuntimeError("Could not add to bag: All CTA click attempts failed")

async def _go_to_bag(page: Page, base_url: str) -> None:
    """
    Navigate to cart/bag page. Simplified to go directly to /cart.
    """
    
    # Strategy 1: Look for cart/bag link in header (most reliable)
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
                
                # Verify we're on cart page
                if "/cart" in page.url or "/basket" in page.url or "/bag" in page.url:
                    return
        except Exception:
            continue
    
    # Strategy 2: Direct navigation to /cart
    try:
        await page.goto(urljoin(base_url, "/cart"), wait_until="domcontentloaded", timeout=20000)
        await page.wait_for_timeout(1000)
        return
    except Exception:
        pass
    
    # Strategy 3: Try alternative cart URLs
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
        # www.sportsdirect.com specific
        page.locator("button[data-action='checkout'].ContinueOn").first,
        page.locator("#divContinueSecurely button").first,
        
        # ie.sportsdirect.com specific
        page.locator("button[data-testid='continue-to-payment']").first,
        
        # Generic fallbacks
        page.get_by_role("button", name=re.compile(r"\b(continue securely|continue to checkout|checkout)\b", re.I)).first,
        page.locator("button").filter(has_text=re.compile(r"\b(continue|checkout)\b", re.I)).first,
    ]
    
    for loc in checkout_locators:
        try:
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            
            # Check if button is enabled
            if hasattr(loc, "is_enabled"):
                try:
                    if not await loc.is_enabled():
                        continue
                except Exception:
                    pass
            
            await loc.scroll_into_view_if_needed(timeout=2000)
            await loc.click(timeout=10000)
            
            # Wait for navigation (usually to login or checkout page)
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=15000)
            except PlaywrightTimeoutError:
                pass
            
            await page.wait_for_timeout(1500)
            return
            
        except Exception:
            continue
    
    raise RuntimeError("Could not find or click checkout button on cart page")


async def _add_to_bag(page: Page) -> None:
    """
    Add item to bag. Handles both IE (button) and WWW (anchor) variants.
    """
    
    # Ensure a size is selected
    size_selected = await _select_in_stock_size_if_needed(page)
    
    if not size_selected:
        out_of_stock = page.get_by_role("button", name=re.compile(r"\bout of stock\b", re.I)).first
        if await out_of_stock.count() > 0 and await out_of_stock.is_visible():
            raise RuntimeError("Cannot add to bag: Product is out of stock")
        raise RuntimeError("Cannot add to bag: Could not select an in-stock size")
    
    # Define CTA locators (order matters - try most specific first)
    cta_locators = [
        page.locator("#aAddToBag").first,                                           # WWW anchor
        page.locator("a.addToBag").first,                                          # WWW anchor fallback
        page.locator("button[data-testid='purchase-button']").first,               # IE button
        page.get_by_role("button", name=re.compile(r"\badd to bag\b", re.I)).first, # Generic button
    ]
    
    # Helper to get button text (handles .addToBagInner span)
    async def _get_button_text(loc) -> str:
        try:
            inner = loc.locator(".addToBagInner").first
            if await inner.count() > 0:
                return (await inner.inner_text()).strip().lower()
            return (await loc.inner_text()).strip().lower()
        except Exception:
            return ""
    
    # Find the active CTA
    active_loc = None
    for loc in cta_locators:
        try:
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            
            # Check text isn't "Select a size"
            text = await _get_button_text(loc)
            if "select" in text and "size" in text:
                continue
            
            active_loc = loc
            break
        except Exception:
            continue
    
    if not active_loc:
        raise RuntimeError("Could not find add-to-bag button")
    
    # Scroll into view and wait for any animations
    await active_loc.scroll_into_view_if_needed(timeout=2000)
    await page.wait_for_timeout(500)  # Let any animations settle
    
    # Get text before clicking
    pre_click_text = await _get_button_text(active_loc)
    print(f"Add-to-bag button text before click: '{pre_click_text}'")
    
    # Try multiple click strategies (important for anchor tags with JS handlers)
    clicked = False
    
    # Strategy 1: Normal click
    try:
        await active_loc.click(timeout=10000)
        clicked = True
        print("Clicked via normal click")
    except Exception as e:
        print(f"Normal click failed: {e}")
    
    # Strategy 2: Force click (if normal failed)
    if not clicked:
        try:
            await active_loc.click(timeout=10000, force=True)
            clicked = True
            print("Clicked via force click")
        except Exception as e:
            print(f"Force click failed: {e}")
    
    # Strategy 3: JavaScript click (most reliable for anchor tags)
    if not clicked:
        try:
            await active_loc.evaluate("(el) => el.click()")
            clicked = True
            print("Clicked via JavaScript")
        except Exception as e:
            print(f"JS click failed: {e}")
    
    if not clicked:
        raise RuntimeError("All click strategies failed")
    
    # Wait for the button text to change (indicates AJAX started)
    print("Waiting for add-to-bag operation...")
    
    text_changed = False
    for _ in range(40):  # 20 seconds max (40 * 500ms)
        current_text = await _get_button_text(active_loc)
        
        # Success states
        if "added" in current_text or "added to bag" in current_text:
            print(f"Button shows: '{current_text}'")
            text_changed = True
            break
        
        # Still processing
        if "adding" in current_text:
            # Still in progress, keep waiting
            await page.wait_for_timeout(500)
            continue
        
        # Text changed from original (even if not "added")
        if current_text != pre_click_text and current_text:
            await page.wait_for_timeout(500)
            continue
        
        await page.wait_for_timeout(500)
    
    # Alternative success indicators if button text doesn't change
    if not text_changed:
        print("Button text didn't change to 'Added', checking other indicators...")
        
        # Wait for network to settle
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
            print("Network settled")
        except Exception:
            await page.wait_for_timeout(3000)
    
    # Verify via cart badge (best verification)
    cart_badge_selectors = [
        "[data-testid='basket'] .itemCount",
        ".basket .itemCount", 
        "#lblItemsInBasket",
        ".basketCount",
        ".basketlink .itemCount",  # Additional WWW selector
    ]
    
    await page.wait_for_timeout(1000)  # Give badge time to update
    
    for badge_sel in cart_badge_selectors:
        try:
            badge = page.locator(badge_sel).first
            if await badge.count() > 0 and await badge.is_visible():
                count_text = await badge.inner_text()
                count_match = re.search(r'\d+', count_text)
                if count_match and int(count_match.group()) > 0:
                    count = int(count_match.group())
                    print(f"Cart badge shows {count} item(s) - add successful")
                    return
        except Exception:
            continue
    
    # If we get here, we clicked but couldn't verify
    # Check final button state
    final_text = await _get_button_text(active_loc)
    print(f"Final button text: '{final_text}'")
    
    if "adding" in final_text:
        raise RuntimeError(
            "Add to bag appears stuck at 'Adding...'. "
            "This may indicate a failed AJAX request or network issue."
        )
    
    # Assume success if no errors (cart page will show if it failed)
    print("Add to bag clicked, cart verification will happen on cart page")
    await page.wait_for_timeout(1000)

async def _go_to_checkout_from_cart(page: Page) -> None:
    """
    Click checkout CTA on cart page.
    This should redirect to login if not authenticated.
    """
    
    checkout_locators = [
        # www.sportsdirect.com specific
        page.locator("button[data-action='checkout'].ContinueOn").first,
        page.locator("#divContinueSecurely button").first,
        
        # ie.sportsdirect.com specific
        page.locator("button[data-testid='continue-to-payment']").first,
        
        # Generic fallbacks
        page.get_by_role("button", name=re.compile(r"\b(continue securely|continue to checkout|checkout)\b", re.I)).first,
        page.locator("button").filter(has_text=re.compile(r"\b(continue|checkout)\b", re.I)).first,
    ]
    
    for loc in checkout_locators:
        try:
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            
            # Check if button is enabled
            if hasattr(loc, "is_enabled"):
                try:
                    if not await loc.is_enabled():
                        continue
                except Exception:
                    pass
            
            await loc.scroll_into_view_if_needed(timeout=2000)
            await loc.click(timeout=10000)
            
            # Wait for navigation (usually to login or checkout page)
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
    selectors = [
        "iframe[src*='recaptcha' i]",
        "iframe[src*='hcaptcha' i]",
        "iframe[src*='captcha' i]",
        "div.g-recaptcha",
        "div.h-captcha",
        "[class*='hcaptcha' i]",
        "[class*='recaptcha' i]",
        "[id*='hcaptcha' i]",
        "[id*='recaptcha' i]",
    ]
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.count() == 0 or not await loc.is_visible():
                continue
            box = await loc.bounding_box()
            if box and box["width"] >= 80 and box["height"] >= 80:
                return True
        except Exception:
            continue
    return False


async def _post_submit_captcha_pause(page: Page, manual_captcha: bool) -> None:
    await page.wait_for_timeout(600)

    appeared = False
    for _ in range(12):
        if await _captcha_present(page):
            appeared = True
            break
        await page.wait_for_timeout(500)

    if manual_captcha or appeared:
        await _wait_for_user(
            "\nIf a CAPTCHA appears, solve it in the browser and click ENTER.\n"
            "If no CAPTCHA appears, just press ENTER to continue.\n"
        )

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=20000)
    except PlaywrightTimeoutError:
        pass
    await page.wait_for_timeout(800)


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
        await _post_submit_captcha_pause(page, manual_captcha=manual_captcha)
        return

    # 2-step login: submit email
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

    # If CAPTCHA blocks password step, let user solve it (only if enabled or detected)
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
) -> None:
    stop_after = stop_after.lower()
    if stop_after not in STEPS:
        raise ValueError(f"--stop-after must be one of: {STEPS}")

    async with async_playwright() as p:
        # Launch with anti-detection args
        browser = await p.chromium.launch(
            headless=headless,
            slow_mo=slow_mo_ms,
            args=[
                '--disable-blink-features=AutomationControlled',
            ]
        )
        
        # Create context with realistic settings
        context = await browser.new_context(
            locale="en-GB",
            timezone_id="Europe/London",
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        )
        
        # Add stealth scripts
        await context.add_init_script("""
            // Overwrite the `navigator.webdriver` property to return undefined
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
            });
            
            // Overwrite the `plugins` property to use a custom getter
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            
            // Overwrite the `languages` property to use a custom getter
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-GB', 'en-US', 'en'],
            });
            
            // Pass the Chrome Test
            window.chrome = {
                runtime: {},
            };
            
            // Pass the Permissions Test
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

        # Determine site scope for cookie snapshots
        # Use registrable domain like your crawler does would be ideal, but _site_cookies expects site_etld1 already.
        # Easiest: derive from the loaded URL hostname using a simple split; you can swap to registrable_domain(...) if you prefer.
        host = re.sub(r"^https?://", "", page.url).split("/")[0].lower()
        # Best: match your crawler’s logic by importing registrable_domain; keep it minimal here:
        try:
            from consentcrawl.domain_utils import registrable_domain
            site_etld1 = registrable_domain(host)
        except Exception:
            site_etld1 = host

        # STEP: home
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
        cmp_res = await _perform_consent(page, flow=flow, categories=categories)
        # small settle to allow cookies to be set post-choice
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
        # Now: try checkout from cart (this often redirects to auth automatically).
        base_host = _host(base_url)

        try:
            await _go_to_checkout_from_cart(page)
        except Exception:
            # If checkout CTA not found, fall back to login/account discovery
            await _go_to_login_page(page, base_url=base_url)

        # If we aren't on auth/login, try login/account links as a final fallback
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

        if keep_open:
            await _wait_for_user("\nFlow finished. Press ENTER to close the browser...\n")

        await context.close()
        await browser.close()


async def _wait_for_user(prompt: str) -> None:
    # non-blocking for asyncio loop
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
    # stable ordering
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
) -> Path:
    run_tag = "ALLFLOWS" if run_all_flows else flow
    run_id = f"{_safe_filename(base_url)}_{_now_stamp()}_{run_tag}"
    out_dir = out_root / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    obs_csv = out_dir / "observations.csv"
    obs_sink = ObservationsCsvSink(obs_csv)

    try:
        if not run_all_flows:
            # single flow: evidence in the main folder
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
            )
        else:
            # all flows: store evidence per-flow in subfolders
            flow_specs = [("accept-all", None), ("reject-all", None)]
            for cats in _generate_custom_combos(exclude_all_off=True, exclude_all_on=True):
                flow_specs.append(("custom", cats))

            for (f, cats) in flow_specs:
                flow_params = "" if f != "custom" else _flow_params_str(cats)
                subname = f if f != "custom" else f"custom_{_safe_filename(flow_params)}"
                sub_dir = out_dir / subname
                sub_dir.mkdir(parents=True, exist_ok=True)

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
                    keep_open=False,  # don’t block mid-matrix
                    run_id=run_id,
                    obs_sink=obs_sink,  # shared sink = single workbook later
                    flow_params=flow_params,
                )
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
    p.add_argument("--delay-ms", type=int, default=1500, help="Wait this many ms before each cookie snapshot (default: 2000)")
    p.add_argument("--manual-captcha", type=_parse_bool, default=False,
               help="If yes, pause at login steps so you can solve CAPTCHA manually (default: no)")
    p.add_argument("--keep-open", type=_parse_bool, default=True,
                help="If yes, keep the browser open at the end until you press ENTER (default: yes)")
    
    p.add_argument(
        "--run-all-flows",
        type=_parse_bool,
        default=False,
        help="Run accept-all, reject-all, and all custom combinations into one workbook (default: no)"
    )

    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    categories = _parse_categories(args.categories)
    if args.flow == "custom" and not categories:
        raise SystemExit("ERROR: --flow custom requires --categories (e.g. analytics=off,advertising=off,functional=on)")

    # Prefer env vars (safer than shell history)
    username = os.environ.get("FG_USER") or args.username
    password = os.environ.get("FG_PASS") or args.password

    run_id = f"{_safe_filename(args.base_url)}_{_now_stamp()}_{args.flow}"
    out_dir = Path(args.out_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    obs_csv = out_dir / "observations.csv"
    obs_sink = ObservationsCsvSink(obs_csv)

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
        )
    )
    
    print(f"\nWrote: {xlsx_path}")

    # Write a single-sheet workbook (your “1st view”)
    csv_to_xlsx(obs_csv, out_dir / "cookie_findings.xlsx", sheet_name="observations")
    print(f"Wrote: {out_dir / 'cookie_findings.xlsx'}")

