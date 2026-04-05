"""
Microsoft Update Catalog driver scraper.

Scrapes all pages of test.catalog.update.microsoft.com for driver updates,
downloads .cab packages, extracts .sys files, deletes the .cab, and produces
a single self-contained catalog.html with all driver metadata.

Run from this directory (microsoft_parsing/):
    python scrape.py                    # scrape everything
    python scrape.py --max-pages 2      # first 2 pages only
    python scrape.py --resume           # continue where you left off
    python scrape.py --no-download      # metadata + HTML only, no .sys

Output (everything stays in this directory):
    *.sys           - extracted driver binaries
    catalog.html    - browsable viewer with full metadata + direct download links
"""

import argparse
import hashlib
import html as html_mod
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from typing import Dict, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
BASE_URL = "https://test.catalog.update.microsoft.com"
SEARCH_URL = f"{BASE_URL}/search.aspx"
DOWNLOAD_DIALOG_URL = f"{BASE_URL}/DownloadDialog.aspx"
DETAIL_URL = f"{BASE_URL}/ScopedViewInline.aspx"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = SCRIPT_DIR
STATE_FILE = os.path.join(SCRIPT_DIR, ".scrape_state.json")

MAX_RETRIES = 5
RETRY_BACKOFF = 2
REQUEST_TIMEOUT = 30
PAGE_DELAY = 1.0
DETAIL_DELAY = 0.4
DOWNLOAD_CHUNK = 1 << 20

LOG_FMT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("catalog")

# ---------------------------------------------------------------------------
# State (tiny JSON file for resume support, replaces SQLite)
# ---------------------------------------------------------------------------
def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"last_page": 0, "updates": {}}


def save_state(state: dict):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    return s


def fetch(session, url, method="GET", data=None):
    delay = RETRY_BACKOFF
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if method == "POST":
                r = session.post(url, data=data, timeout=REQUEST_TIMEOUT)
            else:
                r = session.get(url, params=data, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            log.warning("[HTTP] %d/%d %s: %s", attempt, MAX_RETRIES, url[:80], exc)
            if attempt == MAX_RETRIES:
                raise
            time.sleep(delay)
            delay *= 2


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def parse_search_page(html: str) -> Tuple[list, int]:
    soup = BeautifulSoup(html, "lxml")
    total_pages = 1
    span = soup.find("span", id="ctl00_catalogBody_searchDuration")
    if span:
        m = re.search(r"page\s+\d+\s+of\s+(\d+)", span.get_text(), re.I)
        if m:
            total_pages = int(m.group(1))

    updates = []
    seen = set()
    for tr in soup.find_all("tr"):
        m = re.match(r"([0-9a-f\-]{36})_R\d+", tr.get("id", ""), re.I)
        if not m:
            continue
        uid = m.group(1)
        if uid in seen:
            continue
        seen.add(uid)
        tds = tr.find_all("td")
        def td(i):
            return tds[i].get_text(strip=True) if i < len(tds) else ""
        title = ""
        if len(tds) > 1:
            a = tds[1].find("a")
            title = a.get_text(strip=True) if a else td(1)
        size_bytes = 0
        if len(tds) > 6:
            orig = tds[6].find("span", id=re.compile(r"_originalSize$"))
            if orig:
                try: size_bytes = int(orig.get_text(strip=True))
                except ValueError: pass
        updates.append({
            "update_id": uid, "title": title, "products": td(2),
            "classification": td(3), "last_updated": td(4),
            "version": td(5), "size": td(6), "size_bytes": size_bytes,
        })
    return updates, total_pages


DIRECT = {
    "description": "ScopedViewHandler_desc",
    "reboot_behavior": "ScopedViewHandler_rebootBehavior",
    "user_input": "ScopedViewHandler_userInput",
    "install_exclusively": "ScopedViewHandler_installationImpact",
    "requires_network": "ScopedViewHandler_connectivity",
    "company": "ScopedViewHandler_company",
    "driver_model": "ScopedViewHandler_driverModel",
    "driver_provider": "ScopedViewHandler_driverProvider",
    "driver_version": "ScopedViewHandler_version",
    "driver_date": "ScopedViewHandler_versionDate",
    "driver_class": "ScopedViewHandler_driverClass",
    "driver_manufacturer": "ScopedViewHandler_manufacturer",
}
PARENT_DIV = {
    "architecture": "ScopedViewHandler_labelArchitecture_Separator",
    "supported_products": "ScopedViewHandler_labelSupportedProducts_Separator",
    "supported_languages": "ScopedViewHandler_labelSupportedLanguages_Separator",
    "uninstall_notes": "ScopedViewHandler_labelUninstallNotes_Separator",
}
URL_FIELDS = {
    "more_info_url": "ScopedViewHandler_labelMoreInfo_Separator",
    "support_url": "ScopedViewHandler_labelSupportUrl_Separator",
}


def parse_detail(html: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    info = {}
    for col, eid in DIRECT.items():
        el = soup.find(id=eid)
        if el:
            info[col] = el.get_text(separator="\n", strip=True)
    for col, eid in PARENT_DIV.items():
        el = soup.find(id=eid)
        if el and el.parent:
            full = el.parent.get_text(separator=" ", strip=True)
            label = el.get_text(strip=True)
            val = full.replace(label, "", 1).strip()
            if val:
                info[col] = val
    for col, eid in URL_FIELDS.items():
        el = soup.find(id=eid)
        if el and el.parent:
            a = el.parent.find("a")
            if a and a.get("href"):
                info[col] = a["href"]
    hw = soup.find(id="driverhwIDs")
    if hw:
        ids = [d.get_text(strip=True) for d in hw.find_all("div") if d.get_text(strip=True)]
        if ids:
            info["hardware_ids"] = "\n".join(ids)
    return info


def get_download_url(session, uid) -> Optional[str]:
    payload = {
        "updateIDs": json.dumps([{"size": 0, "languages": "", "uidInfo": uid, "updateID": uid}]),
        "updateIDsBlockedForImport": "", "wsusApiRecipient": "", "contentImport": "",
    }
    try:
        r = fetch(session, DOWNLOAD_DIALOG_URL, method="POST", data=payload)
        urls = re.findall(r"https?://[a-zA-Z0-9./_\-]+\.(?:cab|msu|exe)", r.text, re.I)
        return urls[0] if urls else None
    except Exception as exc:
        log.warning("[DL_URL] %s: %s", uid[:8], exc)
        return None


# ---------------------------------------------------------------------------
# Download + extract .sys + delete cab
# ---------------------------------------------------------------------------
def download_and_extract(session, url, uid, out_dir, seen_hashes) -> List[str]:
    """Download cab, extract .sys, delete cab. Deduplicates by SHA-256."""
    log.info("[DL] %s %s", uid[:8], url.split("/")[-1][:60])
    tmpdir = tempfile.mkdtemp(prefix="cat_")
    cab_path = os.path.join(tmpdir, "driver.cab")
    extracted = []
    try:
        r = session.get(url, stream=True, timeout=300)
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        written = 0
        with open(cab_path, "wb") as f:
            for chunk in r.iter_content(DOWNLOAD_CHUNK):
                f.write(chunk)
                written += len(chunk)
                if total:
                    print(f"\r  [{uid[:8]}] {written*100//total}%", end="", flush=True)
        if total:
            print()
        log.info("[DL] %s done (%s bytes)", uid[:8], f"{written:,}")

        # Expand cab
        _expand(cab_path, tmpdir)
        # Expand nested cabs
        for root, _, files in os.walk(tmpdir):
            for fn in files:
                if fn.lower().endswith(".cab") and fn != "driver.cab":
                    nested_out = os.path.join(root, fn + "_x")
                    os.makedirs(nested_out, exist_ok=True)
                    _expand(os.path.join(root, fn), nested_out)

        # Collect .sys — deduplicate by SHA-256
        for root, _, files in os.walk(tmpdir):
            for fn in files:
                if fn.lower().endswith(".sys"):
                    src = os.path.join(root, fn)
                    h = hashlib.sha256(open(src, "rb").read()).hexdigest()
                    if h in seen_hashes:
                        log.info("[SYS] SKIP (dup hash) %s = %s", fn, seen_hashes[h])
                        continue
                    out_name = f"{uid[:8]}_{fn}"
                    dst = os.path.join(out_dir, out_name)
                    if not os.path.exists(dst):
                        shutil.copy2(src, dst)
                    seen_hashes[h] = out_name
                    extracted.append(out_name)
                    log.info("[SYS] %s", out_name)
    except Exception as exc:
        log.error("[DL] FAIL %s: %s", uid[:8], exc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return extracted


def _expand(cab, dest):
    try:
        res = subprocess.run(["expand", cab, "-F:*", dest],
                             capture_output=True, timeout=120, check=False)
        if res.returncode != 0:
            raise OSError()
    except (OSError, FileNotFoundError):
        try:
            with zipfile.ZipFile(cab) as z:
                z.extractall(dest)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTML generator — .sys-focused, click row for source driver detail
# ---------------------------------------------------------------------------
def generate_html(state, out_path):
    all_updates = list(state["updates"].values())
    updates = [u for u in all_updates if u.get("sys_files")]
    total_updates = len(updates)
    total_sys = sum(len(u.get("sys_files", [])) for u in updates)
    total_scraped = len(all_updates)

    def e(v):
        return html_mod.escape(str(v)) if v else ""

    data_json = json.dumps(updates, default=str, ensure_ascii=False)

    # Build one row per .sys file
    rows = ""
    for u in updates:
        uid = u["update_id"]
        for fn in u.get("sys_files", []):
            dl = u.get("download_url") or ""
            dl_link = f'<a class="lk" href="{e(dl)}" target="_blank" onclick="event.stopPropagation()">.cab</a>' if dl else "-"
            search = " ".join(filter(None, [
                fn, u.get("title"), u.get("driver_provider"), u.get("driver_manufacturer"),
                u.get("driver_model"), u.get("company"), u.get("hardware_ids"),
                u.get("driver_class"), u.get("architecture"),
            ])).lower()
            rows += (
                f'<tr class="ck" onclick=\'S("{e(uid)}")\' data-s="{e(search)}">'
                f'<td class="mn">{e(fn)}</td>'
                f'<td title="{e(u.get("title",""))}">{e((u.get("title",""))[:65])}</td>'
                f'<td>{e(u.get("driver_provider",""))}</td>'
                f'<td><span class="cc">{e(u.get("driver_class",""))}</span></td>'
                f'<td>{e(u.get("driver_version",""))}</td>'
                f'<td><span class="ca">{e(u.get("architecture",""))}</span></td>'
                f'<td>{e(u.get("last_updated",""))}</td>'
                f'<td>{dl_link}</td></tr>\n'
            )

    # Use string.Template to avoid {{}} escaping hell with JS
    from string import Template
    tpl = Template(open(os.devnull).read() if False else _HTML_TEMPLATE)
    page = tpl.safe_substitute(
        total_sys=total_sys, total_updates=total_updates,
        total_scraped=total_scraped, rows=rows, data_json=data_json,
    )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    log.info("[HTML] %s (%d .sys from %d drivers)", os.path.abspath(out_path), total_sys, total_updates)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MS Update Catalog - .sys Files</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f0f2f5;color:#1a1a1a}
.hd{background:#0078d4;color:#fff;padding:14px 20px}
.hd h1{font-size:18px} .hd .st{font-size:12px;opacity:.9;margin-top:3px}
.ct{background:#fff;padding:10px 20px;border-bottom:1px solid #ddd;display:flex;gap:10px;flex-wrap:wrap;align-items:center;position:sticky;top:0;z-index:100}
.ct input[type=text]{padding:5px 10px;border:1px solid #ccc;border-radius:4px;font-size:13px;width:320px}
.ct select{padding:5px;border:1px solid #ccc;border-radius:4px;font-size:12px}
.ct label{font-size:12px;color:#555} .ct .n{font-size:12px;color:#666;margin-left:auto}
table{width:100%;border-collapse:collapse;font-size:12px}
thead{background:#fafafa;position:sticky;top:46px;z-index:50}
th{padding:7px 8px;text-align:left;border-bottom:2px solid #ddd;cursor:pointer;white-space:nowrap;user-select:none}
th:hover{background:#eee}
td{padding:5px 8px;border-bottom:1px solid #eee;vertical-align:top}
tr:hover{background:#f0f7ff} .ck{cursor:pointer}
.lk{color:#0078d4;text-decoration:none;font-size:11px} .lk:hover{text-decoration:underline}
.ca,.cc{display:inline-block;padding:1px 7px;border-radius:9px;font-size:10px}
.ca{background:#e3f2fd;color:#1565c0} .cc{background:#f3e5f5;color:#7b1fa2}
.mn{font-family:monospace;font-weight:600}
.mo{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:1000}
.mo.sh{display:flex;align-items:center;justify-content:center}
.md{background:#fff;border-radius:8px;max-width:780px;width:95%;max-height:85vh;overflow-y:auto;padding:20px;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.md h2{font-size:15px;margin-bottom:14px;padding-bottom:7px;border-bottom:1px solid #eee}
.md .f{display:flex;margin-bottom:6px} .md .fl{font-weight:600;min-width:150px;color:#555;font-size:12px} .md .fv{font-size:12px;word-break:break-word}
.md .x{float:right;cursor:pointer;font-size:18px;color:#999;border:none;background:none} .md .x:hover{color:#333}
.md .sc{margin-top:14px;font-weight:600;font-size:13px;color:#0078d4;border-bottom:1px solid #eee;padding-bottom:3px;margin-bottom:7px}
</style></head><body>
<div class="hd"><h1>MS Update Catalog - Extracted .sys Files</h1>
<div class="st">$total_sys .sys files from $total_updates driver updates ($total_scraped scraped) &mdash; click any row for full source driver info</div></div>
<div class="ct">
<input type="text" id="q" placeholder="Search filename, provider, model, HW ID..." oninput="F()">
<label>Arch:</label><select id="fa" onchange="F()"><option value="">All</option></select>
<label>Class:</label><select id="fc" onchange="F()"><option value="">All</option></select>
<label>Provider:</label><select id="fp" onchange="F()"><option value="">All</option></select>
<span class="n" id="rc"></span>
</div>
<table><thead><tr>
<th onclick="R(0)">.sys File</th><th onclick="R(1)">Source Driver</th>
<th onclick="R(2)">Provider</th><th onclick="R(3)">Class</th>
<th onclick="R(4)">Version</th><th onclick="R(5)">Arch</th>
<th onclick="R(6)">Date</th><th>Cab</th>
</tr></thead>
<tbody id="tb">$rows</tbody></table>
<div class="mo" id="mo" onclick="if(event.target===this)C()"><div class="md"><button class="x" onclick="C()">&times;</button><div id="mb"></div></div></div>
<script>
const D=$data_json;
const M={};D.forEach(u=>M[u.update_id]=u);
const ar=new Set(),cl=new Set(),pr=new Set();
D.forEach(u=>{if(u.architecture)ar.add(u.architecture);if(u.driver_class)cl.add(u.driver_class);if(u.driver_provider)pr.add(u.driver_provider)});
function O(id,vs){const s=document.getElementById(id);[...vs].sort().forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;s.appendChild(o)})}
O('fa',ar);O('fc',cl);O('fp',pr);
function F(){const q=document.getElementById('q').value.toLowerCase(),a=document.getElementById('fa').value.toLowerCase(),c=document.getElementById('fc').value.toLowerCase(),p=document.getElementById('fp').value.toLowerCase();let v=0;
document.querySelectorAll('#tb tr').forEach(t=>{const x=t.dataset.s||'';let s=true;if(q&&!x.includes(q))s=false;if(a&&!x.includes(a))s=false;if(c&&!x.includes(c))s=false;if(p&&!x.includes(p))s=false;t.style.display=s?'':'none';if(s)v++});
document.getElementById('rc').textContent=v+'/$total_sys'}
let sc=-1,sa=true;
function R(c){if(sc===c)sa=!sa;else{sc=c;sa=true};const b=document.getElementById('tb'),r=Array.from(b.rows);r.sort((a,b)=>{let x=a.cells[c].textContent.trim(),y=b.cells[c].textContent.trim();return sa?x.localeCompare(y):y.localeCompare(x)});r.forEach(x=>b.appendChild(x))}
function S(id){const u=M[id];if(!u)return;const f=[['Title',u.title],['Description',u.description],['_','Driver Info'],['Company',u.company],['Provider',u.driver_provider],['Manufacturer',u.driver_manufacturer],['Model',u.driver_model],['Class',u.driver_class],['Version',u.driver_version],['Date',u.driver_date],['Architecture',u.architecture],['_','Compatibility'],['Supported Products',u.supported_products],['Supported Languages',u.supported_languages],['Hardware IDs',u.hardware_ids],['_','Install'],['Reboot',u.reboot_behavior],['User Input',u.user_input],['Exclusive Install',u.install_exclusively],['Network Required',u.requires_network],['Uninstall Notes',u.uninstall_notes],['_','Links'],['Cab Download',u.download_url?'<a href="'+u.download_url+'" target="_blank" style="word-break:break-all">'+u.download_url+'</a>':'-'],['More Info',u.more_info_url?'<a href="'+u.more_info_url+'" target="_blank">Link</a>':'-'],['Support',u.support_url?'<a href="'+u.support_url+'" target="_blank">Link</a>':'-'],['Update ID',u.update_id],['Last Updated',u.last_updated],['Size',u.size],['All .sys from this driver',(u.sys_files||[]).join(', ')||'-']];
let h='<h2>'+(u.title||'Detail')+'</h2>';f.forEach(([l,v])=>{if(l==='_')h+='<div class="sc">'+v+'</div>';else{const isA=typeof v==='string'&&v.startsWith('<a ');const d=isA?v:(v?String(v).replace(/\\n/g,'<br>'):'<span style="color:#aaa">-</span>');h+='<div class="f"><span class="fl">'+l+'</span><span class="fv">'+d+'</span></div>'}});
document.getElementById('mb').innerHTML=h;document.getElementById('mo').classList.add('sh')}
function C(){document.getElementById('mo').classList.remove('sh')}
document.addEventListener('keydown',e=>{if(e.key==='Escape')C()});F();
</script></body></html>"""


# ---------------------------------------------------------------------------
# Cross-directory dedup — remove .sys files duplicated across scrapers
# ---------------------------------------------------------------------------
SIBLING_DIRS = [
    SCRIPT_DIR,
    os.path.join(SCRIPT_DIR, "..", "driverscape_parsing"),
]


def dedup_across_dirs():
    """Remove duplicate .sys files across all scraper output directories.

    Walks directories in priority order (this scraper first, then driverscape).
    Keeps the first occurrence of each SHA-256 hash, deletes the rest.
    """
    seen = {}
    deleted = 0
    total = 0
    for d in SIBLING_DIRS:
        d = os.path.normpath(d)
        if not os.path.isdir(d):
            continue
        files = sorted(f for f in os.listdir(d) if f.lower().endswith(".sys"))
        for fn in files:
            fp = os.path.join(d, fn)
            total += 1
            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
            if h in seen:
                os.remove(fp)
                deleted += 1
                log.info("[DEDUP] Removed %s (dup of %s)", fn, os.path.basename(seen[h]))
            else:
                seen[h] = fp
    if deleted:
        log.info("[DEDUP] Removed %d duplicates, %d unique .sys remain", deleted, total - deleted)
    else:
        log.info("[DEDUP] %d .sys files, no cross-directory duplicates", total)
    return seen


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def run(query="driver", resume=False, no_download=False, max_pages=0):
    os.makedirs(OUT_DIR, exist_ok=True)

    # Cross-directory dedup before starting
    dedup_across_dirs()

    session = make_session()
    state = load_state() if resume else {"last_page": 0, "updates": {}, "seen_hashes": {}}
    if "seen_hashes" not in state:
        state["seen_hashes"] = {}
    seen_hashes = state["seen_hashes"]

    start_page = state["last_page"] + 1 if resume and state["last_page"] else 1

    log.info("[START] query=%r  output=%s", query, os.path.abspath(OUT_DIR))

    # Page 1
    resp = fetch(session, SEARCH_URL, data={"q": query})
    page_updates, total_pages = parse_search_page(resp.text)
    log.info("[SEARCH] %d pages, %d updates on page 1", total_pages, len(page_updates))

    if max_pages > 0:
        total_pages = min(total_pages, max_pages)

    def process_page(updates, page_num):
        log.info("[PAGE %d/%d] %d updates", page_num, total_pages, len(updates))
        for i, u in enumerate(updates, 1):
            uid = u["update_id"]
            if uid in state["updates"] and state["updates"][uid].get("done"):
                continue

            # Merge basic info
            rec = state["updates"].get(uid, {})
            rec.update(u)

            # Detail page
            if not rec.get("scraped"):
                time.sleep(DETAIL_DELAY)
                try:
                    r = fetch(session, f"{DETAIL_URL}?updateid={uid}")
                    detail = parse_detail(r.text)
                    rec.update(detail)
                    rec["scraped"] = True
                    log.info("  [%d/%d] %s | %s | %s",
                             i, len(updates), u["title"][:50],
                             detail.get("driver_provider", "?"),
                             detail.get("architecture", "?"))
                except Exception as exc:
                    log.warning("  [%d/%d] detail fail: %s", i, len(updates), exc)

            # Download URL
            if not rec.get("download_url"):
                time.sleep(0.2)
                rec["download_url"] = get_download_url(session, uid)

            # Download + extract .sys
            if not no_download and not rec.get("done") and rec.get("download_url"):
                sys_files = download_and_extract(session, rec["download_url"], uid, OUT_DIR, seen_hashes)
                rec["sys_files"] = sys_files
                rec["done"] = True
            elif no_download:
                rec["done"] = True

            state["updates"][uid] = rec

        state["last_page"] = page_num
        save_state(state)

    if start_page <= 1:
        process_page(page_updates, 1)

    for page in range(max(2, start_page), total_pages + 1):
        time.sleep(PAGE_DELAY)
        try:
            resp = fetch(session, SEARCH_URL, data={"q": query, "p": page - 1})
            updates, _ = parse_search_page(resp.text)
            process_page(updates, page)
        except Exception as exc:
            log.error("[PAGE %d] FAIL: %s", page, exc)
            state["last_page"] = page
            save_state(state)

    # Generate HTML
    html_path = os.path.join(OUT_DIR, "catalog.html")
    generate_html(state, html_path)

    # Clean up state file
    total_sys = sum(len(u.get("sys_files", [])) for u in state["updates"].values())
    log.info("[DONE] %d updates, %d .sys files", len(state["updates"]), total_sys)


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Scrape MS Update Catalog drivers")
    ap.add_argument("--query", "-q", default="driver")
    ap.add_argument("--resume", action="store_true", help="Continue from last run")
    ap.add_argument("--no-download", action="store_true", help="Metadata + HTML only")
    ap.add_argument("--max-pages", type=int, default=0, help="0 = all pages")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    run(query=args.query, resume=args.resume, no_download=args.no_download, max_pages=args.max_pages)


if __name__ == "__main__":
    main()
