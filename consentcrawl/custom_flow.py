# consentcrawl/custom_flow.py
import re
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

# Multilingual terms (Manage / Save)
_MANAGE_TERMS = [
    "manage","preferences","settings","more options","customise","customize","cookie settings","manage options",
    # DE
    "mehr optionen","weitere optionen","einstellungen","verwalten",
    # FR
    "paramètres","gérer","plus d’options","plus d'options","personnaliser","préférences","gestion",
    # ES
    "configuración","más opciones","preferencias","administrar","personalizar",
    # IT
    "impostazioni","altre opzioni","preferenze","gestisci","personalizza",
    # PT
    "configurações","mais opções","preferências","gerenciar","personalizar",
    # NL
    "instellingen","meer opties","voorkeuren","beheer","aanpassen",
    # DA / SV / NO
    "indstillinger","flere indstillinger","præferencer","tilpas",
    "inställningar","fler alternativ","preferenser","anpassa",
    "innstillinger","flere alternativer","preferanser","tilpass",
    # FI
    "asetukset","lisää vaihtoehtoja","hallinnoi","mukauta",
    # PL
    "ustawienia","więcej opcji","preferencje","zarządzaj","dostosuj",
    # CS / SK
    "nastavení","další možnosti","předvolby","spravovat","přizpůsobit",
    "nastavenia","ďalšie možnosti","predvoľby","spravovať","prispôsobiť",
    # HU
    "beállítások","további lehetőségek","preferenciák","testreszabás",
    # RO
    "setări","mai multe opțiuni","preferințe","gestionați","personalizați",
    # EL
    "ρυθμίσεις","περισσότερες επιλογές","προτιμήσεις","διαχείριση","προσαρμογή",
    # TR
    "ayarlar","daha fazla seçenek","tercihler","yönet","özelleştir",
    # RU / UK
    "настройки","дополнительные параметры","предпочтения","управление","настроить",
    "налаштування","більше параметрів","параметри","керувати","налаштувати",
    # HR (Croatian)
    "postavke","više opcija","preferencije","upravljanje","prilagodi","postavke kolačića",
    # de-AT (Austrian German)
    "optionen verwalten","auswahl anpassen",
]
_SAVE_TERMS = [
    "save","confirm","confirm choices","save and exit","confirm and continue","apply","allow selection",
    # DE
    "speichern","bestätigen","anwenden","auswahl bestätigen",
    # FR
    "enregistrer","confirmer","appliquer","valider",
    # ES
    "guardar","confirmar","aplicar",
    # IT
    "salva","conferma","applica",
    # PT
    "guardar","salvar","confirmar","aplicar","permitir seleção","permitir selecao",
    # NL
    "opslaan","bevestigen","toepassen","keuze bevestigen",
    # DA / SV / NO
    "gem","bekræft","anvend",
    "spara","bekräfta","använd",
    "lagre","bekreft","bruk",
    # FI
    "tallenna","vahvista","käytä",
    # PL
    "zapisz","potwierdź","zastosuj",
    # CS / SK
    "uložit","potvrdit","použít","pouzit","uložiť","potvrdiť","použiť",
    # HU
    "mentés","megerősítés","alkalmaz",
    # RO
    "salvează","confirmă","aplică",
    # EL
    "αποθήκευση","επιβεβαίωση","εφαρμογή",
    # TR
    "kaydet","onayla","uygula",
    # RU / UK
    "сохранить","подтвердить","применить",
    "зберегти","підтвердити","застосувати",
    # HR (Croatian)
    "spremi","sačuvaj","potvrdi","primijeni","spremi i izađi","potvrdi i nastavi",
    # de-AT (Austrian German)
    "auswahl speichern","auswahl bestätigen","speichern & schließen","speichern und schließen","bestätigen und fortfahren",
]
_MANAGE_TEXT = re.compile(r"(?:" + "|".join(map(re.escape, _MANAGE_TERMS)) + r")", re.I)
_SAVE_TEXT   = re.compile(r"(?:" + "|".join(map(re.escape, _SAVE_TERMS))   + r")", re.I)

# Multilingual category labels (broad just to be safe)
_CATEGORY_SYNONYMS = {
    "analytics": [
        r"analytics", r"statistics", r"measurement",
        r"analyse", r"analytique", r"statistiques",              # FR
        r"analyse|statisti(?:k|ken)",                            # DE/NL
        r"analítica|estadístic",                                 # ES
        r"analitic|statistic",                                   # IT/RO
        r"estatístic",                                           # PT
        r"statistik", r"tilasto",                                # DA/SV/NO/FI
        r"statystyk", r"statistiky|štatistik",                   # PL/CS/SK
        r"аналит|статист", r"аналіт|статист",                    # RU/UK
        r"analitik", r"statistik", r"mjerenj",                   # HR
    ],
    "advertising": [
        r"advertis(?:ing|e?ments?)", r"ads?", r"marketing",
        r"personal(?:iz|is)ation", r"profil(?:ing|e)", r"target(?:ed|ing)",
        r"remarket(?:ing)?", r"retarget(?:ing)?",
        r"publicit", r"ciblage",                                  # FR
        r"werb(?:ung)?|anzeigen|personalisier|zielgrupp",          # DE
        r"publicidad|anuncios|personalizaci(?:ó|o)n|segmentaci",   # ES
        r"pubblicit|annunci|personalizzaz|target",                 # IT
        r"publicidade|anúnc|personaliza",                          # PT
        r"reclame|advertentie|personalis",                         # NL
        r"reklam|annon", r"personali(?:s|z)er", r"målrett",        # DA/SV/NO
        r"mainon|personoin|kohdenn",                               # FI
        r"reklam|marketing|personaliza|targetow",                  # PL
        r"reklam|personalizac|cílen",                              # CS/SK
        r"hirdet|személyre\s*szab|célz",                           # HU
        r"προσωποπ|διαφήμ",                                        # EL
        r"reklam|pazarlama|kişisell|hedefle",                      # TR
        r"реклам|маркетинг|персонализ|таргет",                      # RU
        r"реклам|маркетинг|персоналіз|таргет",                      # UK
        r"oglašav", r"oglasi", r"personalizac", r"ciljan", r"retarget", r"remarket",  # HR
    ],
    "functional": [
        r"functional", r"preferences", r"performance", r"experience",
        r"fonctionnel|préférences|perform",                        # FR
        r"funktion|präferenz|leistung|erfahr",                     # DE
        r"funcional|preferenc|rendim|experien",                    # ES/PT/RO
        r"funzional|preferen|prestaz|esperien",                    # IT
        r"functioneel|voorkeur|prestat|ervaring",                  # NL
        r"funktion(?:el)?|præferenc|ydels|erfar",                  # DA
        r"funktionell|preferens|prestanda|erfaren",                # SV
        r"funksjonell|preferans|ytels|erfar",                      # NO
        r"toiminn|asetuk|suoritus|kokem",                          # FI
        r"funkcj(?:onal)|preferenc|wydajno|doświadc",              # PL
        r"funkč|předvolb|výkon|zkuše",                             # CS
        r"funkčn|predvoľb|výkon|skúsen",                           # SK
        r"funkcion|beállít|teljesít|élmény",                       # HU
        r"λειτουργ|προτιμ|απόδοσ|εμπειρ",                          # EL
        r"işlevsel|tercih|performans|deneyim",                     # TR
        r"функцион|предпочтен|производит|опыт",                    # RU
        r"функціон|уподобан|продуктив|досвід",                     # UK
        r"funkcionaln", r"preferenc", r"performans", r"iskustv",   # HR stems
    ],
}

# Helper functions
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

# ONETRUST FAST PATH
_OT_CATEGORY_IDS = {
    "analytics":   "ot-group-id-C0002",
    "functional":  "ot-group-id-C0003",
    "advertising": "ot-group-id-C0004",
}

async def _ot_detect(page) -> bool:
    """
    Heuristic for OneTrust: banner/prefs button/second layer/save button.
    """
    try:
        return (await page.locator(
            "#onetrust-pc-btn-handler, #onetrust-banner-sdk, "
            "button#onetrust-accept-btn-handler, #ot-pc-content, "
            ".save-preference-btn-handler"
        ).count()) > 0
    except Exception:
        return False

async def _ot_open_manage(page):
    # If second layer is already present, consider manage open
    pc = page.locator("#ot-pc-content").first
    try:
        if await pc.count() > 0 and await pc.is_visible():
            return {"ok": True, "via": "ot-hardcoded", "role": "panel", "frame": False}
    except Exception:
        pass

    btn = page.locator("#onetrust-pc-btn-handler").first
    if await btn.count() > 0 and await _safe_click(btn):
        try:
            await page.locator("#ot-pc-content").first.wait_for(state="visible", timeout=5000)
        except Exception:
            # Some skins don’t use #ot-pc-content; accept the click anyway
            pass
        return {"ok": True, "via": "ot-hardcoded", "role": "button", "frame": False}
    return {"ok": False}

async def _ot_toggle_input(page, input_id: str, want_on: bool):
    inp = page.locator(f"input#{input_id}").first
    if (await inp.count()) == 0:
        return False, {"pattern": input_id, "role": "checkbox", "state_before": None}
    state = None
    try:
        state = await inp.is_checked()
    except Exception:
        try:
            attr = await inp.get_attribute("aria-checked")
            state = True if attr == "true" else False if attr == "false" else None
        except Exception:
            state = None
    if state is None or state != want_on:
        lab = page.locator(f"label[for='{input_id}']").first
        target = lab if (await lab.count()) > 0 else inp
        if await _safe_click(target):
            return True, {"pattern": input_id, "role": "checkbox", "state_before": state}
    return False, {"pattern": input_id, "role": "checkbox", "state_before": state}

async def _ot_save(page):
    btn = page.locator(".save-preference-btn-handler").first
    if (await btn.count()) > 0 and await _safe_click(btn):
        return {"ok": True, "via": "ot-hardcoded", "role": "button", "frame": False}
    cand = page.get_by_role("button", name=re.compile(r"confirm(\s+(my )?choices)?", re.I)).first
    if (await cand.count()) > 0 and await _safe_click(cand):
        return {"ok": True, "via": "ot-hardcoded", "role": "button", "frame": False}
    return {"ok": False}

# Generic flows (YAML rules and text)
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
                        return {"ok": True, "via":"yaml", "role":"selector", "frame": False, "selector": v, "cmp_id": cmp.get("id") or cmp.get("name")}
                elif t == "css-selector-list":
                    for sel in v:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _safe_click(loc):
                            return {"ok": True, "via":"yaml", "role":"selector", "frame": False, "selector": sel, "cmp_id": cmp.get("id") or cmp.get("name")}
            except Exception:
                continue
    
    # Fallback by accessible name: button or link
    for role in ("button","link"):
        cand = page.get_by_role(role, name=_MANAGE_TEXT).first
        if await cand.count() > 0 and await _safe_click(cand):
            return {"ok": True, "via":"text", "role": role, "frame": False}
    # Try inside iframes (some CMPs render second layer in an iframe)
    for frame in page.frames:
        for role in ("button","link"):
            try:
                cand = frame.get_by_role(role, name=_MANAGE_TEXT).first
                if await cand.count() > 0 and await _safe_click(cand):
                    return {"ok": True, "via":"text", "role": role, "frame": True}
            except Exception:
                continue
    return {"ok": False}

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
                        return {"ok": True, "via":"yaml", "role":"selector", "frame": False, "selector": v, "cmp_id": cmp.get("id") or cmp.get("name")}
                elif t == "css-selector-list":
                    for sel in v:
                        loc = parent.locator(sel).first
                        if await loc.count() > 0 and await _safe_click(loc):
                            return {"ok": True, "via":"yaml", "role":"selector", "frame": False, "selector": sel, "cmp_id": cmp.get("id") or cmp.get("name")}
            except Exception:
                continue

    # Button or link on the current page
    for role in ("button","link"):
        cand = page.get_by_role(role, name=_SAVE_TEXT).first
        if await cand.count() > 0 and await _safe_click(cand):
            return {"ok": True, "via":"text", "role": role, "frame": False}
    # Try inside frames as well
    for frame in page.frames:
        for role in ("button","link"):
            try:
                cand = frame.get_by_role(role, name=_SAVE_TEXT).first
                if await cand.count() > 0 and await _safe_click(cand):
                    return {"ok": True, "via":"text", "role": role, "frame": True}
            except Exception:
                continue
    return {"ok": False}

def _want_on(category: str, prefs: dict) -> bool | None:
    if category not in prefs:
        return None
    return bool(prefs[category])

async def _set_category(page, label_regexes, want_on: bool):
    """
    Try switch, checkbox and button (with ARIA state).
    Return (clicked: bool, hit_info: dict).
    """
    last_info = None
    for patt in label_regexes:
        rx = re.compile(patt, re.I)
        # 1) role=switch
        sw = page.get_by_role("switch", name=rx).first
        if await sw.count() > 0:
            try:
                state = await sw.get_attribute("aria-checked")
                is_on = True if state == "true" else False if state == "false" else None
            except Exception:
                is_on = None
            if is_on is None or is_on != want_on:
                if await _safe_click(sw):
                    return True, {"pattern": patt, "role": "switch", "state_before": is_on}
            last_info = {"pattern": patt, "role": "switch", "state_before": is_on}
        # 2) role=checkbox
        cb = page.get_by_role("checkbox", name=rx).first
        if await cb.count() > 0:
            try:
                checked = await cb.is_checked()
            except Exception:
                checked = None
            if checked is None or checked != want_on:
                if await _safe_click(cb):
                    return True, {"pattern": patt, "role": "checkbox", "state_before": checked}
            last_info = {"pattern": patt, "role": "checkbox", "state_before": checked}
        # 3) role=button with aria-pressed / aria-checked
        btn = page.get_by_role("button", name=rx).first
        if await btn.count() > 0:
            try:
                attr = await btn.get_attribute("aria-pressed") or await btn.get_attribute("aria-checked")
                pressed = True if attr == "true" else False if attr == "false" else None
            except Exception:
                pressed = None
            if pressed is None or pressed != want_on:
                if await _safe_click(btn):
                    return True, {"pattern": patt, "role": "button", "state_before": pressed}
            last_info = {"pattern": patt, "role": "button", "state_before": pressed}
    return False, (last_info or {"pattern": None, "role": None, "state_before": None})


# Public API
async def customise(page, prefs: dict, managers=None):
    """
    prefs example: {"analytics": False, "advertising": False, "functional": True}
    Returns a dict with status and clicked_action='custom'
    """
    # 0) OneTrust fast path first
    if await _ot_detect(page):
        open_info = await _ot_open_manage(page)
        if not open_info.get("ok"):
            return {
                "id":"customise","name":"Customise","status":"error",
                "clicked_action":"custom","error":"manage-not-opened",
                "manage_opened": False,"saved": False,"changes": 0,
                "applied_prefs": prefs
            }
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except PlaywrightTimeoutError:
            pass

        changes = 0
        category_hits = []
        for cat, input_id in _OT_CATEGORY_IDS.items():
            want = _want_on(cat, prefs)
            if want is None:
                continue
            flipped, hit = await _ot_toggle_input(page, input_id, want)
            hit.update({"category": cat, "want_on": bool(want), "clicked": bool(flipped)})
            category_hits.append(hit)
            if flipped:
                changes += 1

        save_info = await _ot_save(page)
        saved = bool(save_info.get("ok"))
        status = "clicked" if saved else ("clicked-uncertain" if changes > 0 else "error")
        return {
            "id":"customise","name":"Customise","status":status,"clicked_action":"custom",
            "manage_opened": True,
            "manage_via": open_info.get("via"), "manage_role": open_info.get("role"), "manage_frame": open_info.get("frame"),
            "saved": saved,
            "save_via": save_info.get("via"), "save_role": save_info.get("role"), "save_frame": save_info.get("frame"),
            "changes": int(changes), "applied_prefs": prefs, "category_hits": category_hits
        }

    # Generic (YAML and text search) path
    open_info = await _open_manage(page, managers=managers)
    if not open_info.get("ok"):
        return {
            "id":"customise","name":"Customise","status":"error",
            "clicked_action":"custom","error":"manage-not-opened",
            "manage_opened": False,"saved": False,"changes": 0,
            "applied_prefs": prefs
        }

    try:
        await page.wait_for_load_state("networkidle", timeout=3000)
    except PlaywrightTimeoutError:
        pass

    changes = 0
    category_hits = []
    for cat, synonyms in _CATEGORY_SYNONYMS.items():
        want = _want_on(cat, prefs)
        if want is None:
            continue
        flipped, hit = await _set_category(page, synonyms, want)
        hit.update({"category": cat, "want_on": bool(want), "clicked": bool(flipped)})
        category_hits.append(hit)
        if flipped:
            changes += 1

    save_info = await _save_choices(page, managers=managers)
    saved = bool(save_info.get("ok"))
    status = "clicked" if saved else ("clicked-uncertain" if changes > 0 else "error")
    return {
        "id":"customise","name":"Customise","status":status,"clicked_action":"custom",
        "manage_opened": True,
        "manage_via": open_info.get("via"), "manage_role": open_info.get("role"), "manage_frame": open_info.get("frame"),
        "saved": bool(saved),
        "save_via": save_info.get("via"), "save_role": save_info.get("role"), "save_frame": save_info.get("frame"),
        "changes": int(changes), "applied_prefs": prefs, "category_hits": category_hits
    }
