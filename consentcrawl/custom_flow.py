import re
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from consentcrawl.domain_utils import host_from_url
# from consentcrawl.crawl import get_consent_managers

_MANAGE_TEXT = re.compile(r"(manage|preferences|settings|more options|customis(e|z)e|cookie settings)", re.I)
_SAVE_TEXT = re.compile(r"(save|confirm (my )?choices|allow selection|apply|agree to selection)", re.I)

_CATEGORY_SYNONYMS = {
    "analytics": [r"analytics", r"statistics", r"measurement"],
    "advertising": [r"marketing", r"advertis(?:ing|e?ments?)", r"ads?", r"profil(ing|e)", r"target(?:ed|ing)", r"personal(?:iz|is)ation",r"remarket(?:ing)?", r"retarget(?:ing)?",],
    "functional": [r"functional", r"preferences", r"performance", r"experience"],
}

async def _safe_click(target):
    try:
        await target.scroll_into_view_if_needed(timeout=1500)
    except Exception:
        pass
    try:
        await target.click(timeout=2500, trial=True)
        await target.click(timeout=2500)
        return True
    except Exception:
        try:
            await target.click(timeout=2500, force=True)
            return True
        except Exception:
            try:
                await target.evaluate("(el)=>el.click()")
                return True
            except Exception:
                return False

async def _open_manage(page, managers=None):
    managers = managers or []
    for cmp in managers:
        for act in cmp.get("flows", {}).get("manage", []):
            parent = page
            t = act.get("type"); v = act.get("value")
            try:
                if t == "iframe":
                    await parent.locator(v).first.wait_for(state="attached", timeout=2000)
                    parent = parent.frame_locator(v).first
                elif t == "css-selector":
                    loc = parent.locator(v).first
                    if await loc.count() > 0 and await _safe_click(loc):
                        return True
                elif t == "css-selector-list":
                    for sel in v:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _safe_click(loc):
                            return True
            except Exception:
                continue
    # Fallback: text search
    btn = page.get_by_role("button", name=_MANAGE_TEXT).first
    if await btn.count() > 0 and await _safe_click(btn):
        return True
    return False

async def _save_choices(page, managers = None):
    # Try YAML save flows
    managers = managers or []
    for cmp in managers:
        for act in cmp.get("flows", {}).get("save", []):
            parent = page
            t = act.get("type"); v = act.get("value")
            try:
                if t == "iframe":
                    await parent.locator(v).first.wait_for(state="attached", timeout=2000)
                    parent = parent.frame_locator(v).first
                elif t == "css-selector":
                    loc = parent.locator(v).first
                    if await loc.count() > 0 and await _safe_click(loc):
                        return True
                elif t == "css-selector-list":
                    for sel in v:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _safe_click(loc):
                            return True
            except Exception:
                continue

    cand = page.get_by_role("button", name=_SAVE_TEXT).first
    if await cand.count() > 0 and await _safe_click(cand):
        return True
    return False

def _want_on(category: str, prefs: dict) -> bool | None:
    if category not in prefs: return None
    return bool(prefs[category])

async def _set_category(page, label_regexes, want_on: bool):
    """
    Generic approach: find a 'switch' or 'checkbox' whose accessible name matches label_regexes.
    Toggle only if current state differs from want_on.
    """
    for patt in label_regexes:
        # Try role=switch
        sw = page.get_by_role("switch", name=re.compile(patt, re.I)).first
        if await sw.count() > 0:
            try:
                state = await sw.get_attribute("aria-checked")
                is_on = (state == "true")
            except Exception:
                is_on = None
            if is_on is None or is_on != want_on:
                if await _safe_click(sw):
                    return True
        # Try role=checkbox
        cb = page.get_by_role("checkbox", name=re.compile(patt, re.I)).first
        if await cb.count() > 0:
            try:
                checked = await cb.is_checked()
            except Exception:
                checked = None
            if checked is None or checked != want_on:
                if await _safe_click(cb):
                    return True
    return False

async def customise(page, prefs: dict, managers=None):
    """
    prefs example: {"analytics": False, "advertising": False, "functional": True}
    Returns a dict with status and clicked_action='custom'
    """
    opened = await _open_manage(page, managers=managers)
    if not opened:
        return {"id":"customise","name":"Customise","status":"error",
                "clicked_action":"custom",
                "error":"manage-not-opened",
                "manage_opened": False,
                "saved": False,
                "changes": 0,
                "applied_prefs": prefs}
    try:
        await page.wait_for_load_state("networkidle", timeout=3000)
    except PlaywrightTimeoutError:
        pass

    changes = 0
    for cat, synonyms in _CATEGORY_SYNONYMS.items():
        want = _want_on(cat, prefs)
        if want is None:
            continue
        flipped = await _set_category(page, synonyms, want)
        if flipped:
            changes += 1

    saved = await _save_choices(page, managers=managers)
    status = "clicked" if saved else ("clicked-uncertain" if changes > 0 else "error")
    return {"id":"customise",
            "name":"Customise",
            "status":status,
            "clicked_action":"custom",
            "manage_opened": True,
            "saved": bool(saved),
            "changes": int(changes),
            "applied_prefs": prefs}
