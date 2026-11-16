#!/usr/bin/env python3
"""Automated Target Fetcher — WordPress.org Plugin API.

Query api.wordpress.org/plugins/info/1.2/ for recently updated plugins,
filter by active installs, download the zips with Range-resume, verify the
real version inside the zip (the API ``version`` field is known to lie —
see README.md), and unzip each plugin into a staging folder.

Universally usable by any agent / human / CI job:
  * Python 3.9+ standard library ONLY — no pip installs, no API keys.
  * One file: copy ``wp_target_fetcher.py`` anywhere and run it.
  * Works as a CLI *and* as an importable library (``fetch_targets()``).
  * No hardcoded paths, users, lanes, or platforms. Everything is a
    flag, a config file, or an environment variable.
  * Deterministic, resumable, idempotent: a re-run skips already-fetched
    targets (manifest + sha256 marker) unless ``--force`` is given.
  * Safe extraction: Zip-Slip / absolute-path / symlink entries rejected,
    uncompressed-size cap, ``testzip`` verification before extraction.
  * Machine-readable output: ``manifest.json`` + ``manifest.csv`` in the
    staging dir, plus ``--json`` summary on stdout.

Platform presets (install bars — overridable with ``--min-installs``):
  * ``--platform patchstack`` (default): active_installs >= 1,000
  * ``--platform wordfence``:                active_installs >= 50,000
  * ``--platform custom``:                   use ``--min-installs`` as-is

Typical uses::

    # Recently updated, Patchstack bar (>= 1,000 installs), 20 targets
    python3 wp_target_fetcher.py --limit 20 --staging ./staging

    # Wordfence bar (>= 50,000 installs)
    python3 wp_target_fetcher.py --platform wordfence --limit 20 --staging ./staging

    # Just list what *would* be fetched — no downloads
    python3 wp_target_fetcher.py --limit 20 --dry-run

    # Explicit slugs, regardless of recency
    python3 wp_target_fetcher.py --slugs contact-form-7,akismet --staging ./staging

    # Library use
    from wp_target_fetcher import fetch_targets, FetcherConfig
    results = fetch_targets(FetcherConfig(limit=5, platform="wordfence"))

Exit codes: 0 = all requested targets fetched (or dry-run OK),
1 = partial failure (some targets failed, see manifest ``status``),
2 = usage / config error, 3 = API failure, no usable results.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import logging
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "1.0.0"
API_BASE = "https://api.wordpress.org/plugins/info/1.2/"
USER_AGENT = f"wp-target-fetcher/{__version__} (automated-target-fetcher; +https://wordpress.org/plugins/)"

# Install bars. Kept here so the presets are visible in one place; the
# CLI/config/env can override them at runtime — never edit this file to
# change a bar for one run.
PLATFORM_MIN_INSTALLS: Dict[str, int] = {
    "patchstack": 1_000,
    "wordfence": 50_000,
    "custom": 1_000,
}

# WP.org `last_updated` looks like "2026-11-08 4:39pm GMT".
_LAST_UPDATED_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{1,2}):(\d{2})(am|pm)\s+GMT$", re.IGNORECASE
)
_VERSION_IN_ZIP_NAME = re.compile(r"\.(\d[\w.\-]*)\.zip$", re.IGNORECASE)
_STABLE_TAG_RE = re.compile(r"^Stable tag:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_PLUGIN_HEADER_VERSION_RE = re.compile(r"^Version:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_PLUGIN_HEADER_NAME_RE = re.compile(r"^Plugin Name:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)

log = logging.getLogger("wp_target_fetcher")


class FetcherPolicyError(RuntimeError):
    """The archive violated a configured size or extraction safety policy."""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class FetcherConfig:
    """All inputs to a fetch run. No globals, no hardcoded user state."""

    staging: Path = Path("output/fetcher")
    platform: str = "patchstack"          # patchstack | wordfence | custom
    min_installs: Optional[int] = None    # overrides platform preset
    limit: int = 20                       # max targets to fetch
    max_pages: int = 50                   # API pages to scan (per_page=100)
    per_page: int = 100
    browse: str = "updated"               # updated | popular | new | top-rated
    search: Optional[str] = None          # query_plugins search term
    slugs: List[str] = field(default_factory=list)  # explicit slugs (bypass browse)
    updated_since: Optional[str] = None   # ISO date YYYY-MM-DD; skip older
    max_age_days: Optional[int] = None    # skip plugins updated > N days ago
    exclude: List[str] = field(default_factory=list)
    keep_zips: bool = True
    unzip: bool = True
    force: bool = False                   # re-download even if already staged
    dry_run: bool = False
    delay_secs: float = 0.3               # pause between API calls
    download_delay_secs: float = 0.2      # pause between downloads
    retries: int = 14
    timeout_secs: int = 60
    max_download_mb: int = 100         # compressed archive cap
    max_uncompressed_mb: int = 500        # zip-bomb guard per plugin
    user_agent: str = USER_AGENT

    def effective_min_installs(self) -> int:
        if self.min_installs is not None:
            return self.min_installs
        return PLATFORM_MIN_INSTALLS.get(self.platform, 1_000)

    def updated_since_dt(self) -> Optional[datetime]:
        if self.updated_since:
            return datetime.strptime(self.updated_since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if self.max_age_days is not None:
            return datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        return None


def config_from_dict(d: Dict[str, Any]) -> FetcherConfig:
    """Build a config from a JSON config file (unknown keys are rejected)."""
    known = {f.name for f in FetcherConfig.__dataclass_fields__.values()}
    unknown = set(d) - known
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    cfg = FetcherConfig()
    for k, v in d.items():
        if k == "staging":
            v = Path(v)
        setattr(cfg, k, v)
    return cfg


def config_from_env(prefix: str = "WP_FETCHER_") -> Dict[str, Any]:
    """Optional env overrides, e.g. WP_FETCHER_MIN_INSTALLS=50000."""
    out: Dict[str, Any] = {}
    mapping = {
        "STAGING": "staging", "PLATFORM": "platform", "MIN_INSTALLS": "min_installs",
        "LIMIT": "limit", "BROWSE": "browse", "SEARCH": "search",
        "UPDATED_SINCE": "updated_since", "MAX_AGE_DAYS": "max_age_days",
        "MAX_DOWNLOAD_MB": "max_download_mb", "MAX_UNCOMPRESSED_MB": "max_uncompressed_mb",
        "KEEP_ZIPS": "keep_zips", "UNZIP": "unzip", "DRY_RUN": "dry_run",
    }
    for env_key, cfg_key in mapping.items():
        raw = os.environ.get(prefix + env_key)
        if raw is None or raw == "":
            continue
        if cfg_key in ("min_installs", "limit", "max_age_days",
                       "max_download_mb", "max_uncompressed_mb"):
            out[cfg_key] = int(raw)
        elif cfg_key in ("keep_zips", "unzip", "dry_run"):
            out[cfg_key] = raw.strip().lower() in ("1", "true", "yes", "y")
        else:
            out[cfg_key] = raw
    return out


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def strip_html(text: Optional[str]) -> str:
    """' <a href=...>Foo</a> ' -> 'Foo'. API author fields are HTML."""
    if not text:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


def parse_last_updated(value: Optional[str]) -> Optional[datetime]:
    """Parse WP.org '2026-11-08 4:39pm GMT' -> aware UTC datetime, else None."""
    if not value:
        return None
    m = _LAST_UPDATED_RE.match(value.strip())
    if not m:
        # Fallback: ISO-ish dates the API sometimes returns for `added`.
        try:
            return datetime.strptime(value.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    year, month, day, hour, minute, ampm = m.groups()
    hour = int(hour)
    if ampm.lower() == "pm" and hour != 12:
        hour += 12
    if ampm.lower() == "am" and hour == 12:
        hour = 0
    return datetime(int(year), int(month), int(day), hour, int(minute), tzinfo=timezone.utc)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def version_from_download_link(link: Optional[str]) -> Optional[str]:
    """'.../plugin/contact-form-7.6.2.4.1.zip' -> '6.2.4.1'."""
    if not link:
        return None
    m = _VERSION_IN_ZIP_NAME.search(link.rstrip("/"))
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# WP.org API
# ---------------------------------------------------------------------------

def _api_get(params: Dict[str, str], cfg: FetcherConfig) -> Dict[str, Any]:
    """One GET against the Plugins API. Raises on HTTP/network failure."""
    # urlencode handles the bracketed request[...] keys correctly; do NOT
    # build these URLs by hand (curl needs -g for the same reason).
    url = API_BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout_secs) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"WP.org API HTTP {e.code} for {url}: {e.read()[:300]!r}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"WP.org API request failed for {url}: {e}") from e


def fetch_plugin_info(slug: str, cfg: FetcherConfig) -> Optional[Dict[str, Any]]:
    """plugin_information for one slug; None if the slug is not a plugin.

    Note: themes are NOT plugins — a theme slug returns an error object
    here, which is the correct signal (fetch the Themes API instead).
    """
    data = _api_get({
        "action": "plugin_information",
        "request[slug]": slug,
        "request[fields][active_installs]": "true",
        "request[fields][download_link]": "true",
        "request[fields][last_updated]": "true",
    }, cfg)
    if isinstance(data, dict) and data.get("error"):
        log.info("slug %s: not a plugin (%s)", slug, data.get("error"))
        return None
    return data if isinstance(data, dict) else None


def query_plugins(cfg: FetcherConfig) -> List[Dict[str, Any]]:
    """Walk query_plugins (browse=updated by default) until `limit` matches.

    The API has NO server-side min-installs filter, so filtering is
    client-side: every page is scanned, plugins below the bar are dropped,
    and paging stops once `limit` qualifying plugins are found, the
    `updated_since` cutoff is passed (browse=updated is newest-first, so
    once a page's newest entry is older than the cutoff, later pages can
    only be older), or `max_pages` is hit.
    """
    min_installs = cfg.effective_min_installs()
    cutoff = cfg.updated_since_dt()
    seen: Dict[str, Dict[str, Any]] = {}
    page = 1
    while page <= cfg.max_pages and len(seen) < cfg.limit:
        params: Dict[str, str] = {
            "action": "query_plugins",
            "request[page]": str(page),
            "request[per_page]": str(cfg.per_page),
            "request[fields][active_installs]": "true",
            "request[fields][download_link]": "true",
            "request[fields][last_updated]": "true",
            "request[fields][versions]": "false",
        }
        if cfg.search:
            params["request[search]"] = cfg.search
        else:
            params["request[browse]"] = cfg.browse
        data = _api_get(params, cfg)
        plugins = data.get("plugins") or []
        info = data.get("info") or {}
        log.info("API page %s/%s: %d plugins, %d qualifying so far",
                 page, info.get("pages"), len(plugins), len(seen))
        if not plugins:
            break
        page_newest: Optional[datetime] = None
        for p in plugins:
            slug = p.get("slug")
            if not slug or slug in seen or slug in cfg.exclude:
                continue
            installs = p.get("active_installs")
            if installs is None or int(installs) < min_installs:
                continue
            updated = parse_last_updated(p.get("last_updated"))
            if updated and (page_newest is None or updated > page_newest):
                page_newest = updated
            if cutoff and updated and updated < cutoff:
                continue
            seen[slug] = p
            if len(seen) >= cfg.limit:
                break
        # browse=updated is newest-first: if this page's newest entry is
        # already older than the cutoff, no later page can qualify.
        if cutoff and cfg.browse == "updated" and page_newest and page_newest < cutoff:
            log.info("cutoff reached on page %s (newest %s < %s); stopping",
                     page, page_newest.date(), cutoff.date())
            break
        if info.get("pages") and page >= int(info["pages"]):
            break
        page += 1
        if cfg.delay_secs:
            time.sleep(cfg.delay_secs)
    return list(seen.values())[: cfg.limit]


# ---------------------------------------------------------------------------
# Download (Range-resume, testzip-verified)
# ---------------------------------------------------------------------------

def download_plugin(url: str, dest: Path, cfg: FetcherConfig) -> Tuple[Path, int]:
    """Download with HTTP Range resume; returns (dest, bytes).

    Behaviour learned the hard way on this VM's egress (see README):
      * downloads stall mid-transfer — resume with Range, retry, back off;
      * a server may ignore Range and restart from 0 (HTTP 200) — detect
        that and overwrite instead of appending garbage;
      * a 1-byte probe returning 416 means the file is complete — but a
        416 on a truncated file is NOT proof, so a testzip check decides.
    Raises RuntimeError if the file cannot be completed + verified.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    max_bytes = cfg.max_download_mb * 1024 * 1024
    if max_bytes <= 0:
        raise ValueError("max_download_mb must be positive")
    last_err: Optional[Exception] = None
    for attempt in range(cfg.retries + 1):
        have = dest.stat().st_size if dest.exists() else 0
        if have > max_bytes:
            dest.unlink(missing_ok=True)
            raise FetcherPolicyError(
                f"zip exceeds compressed cap ({cfg.max_download_mb} MB): {dest.name}")
        req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
        if have:
            req.add_header("Range", f"bytes={have}-")
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout_secs) as resp:
                code = resp.getcode()
                # Server ignored Range: restart cleanly, don't append.
                mode = "ab" if (have and code == 206) else "wb"
                if mode == "wb" and have:
                    log.warning("%s: server restarted transfer from 0; overwriting %d bytes",
                                dest.name, have)
                with open(dest, mode) as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        if f.tell() + len(chunk) > max_bytes:
                            raise FetcherPolicyError(
                                f"zip exceeds compressed cap ({cfg.max_download_mb} MB): {dest.name}")
                        f.write(chunk)
            if _download_complete(url, dest, cfg):
                return dest, dest.stat().st_size
            log.warning("%s: incomplete after attempt %d%s", dest.name, attempt,
                        "; retrying" if attempt < cfg.retries else " — no retries left")
        except FetcherPolicyError:
            dest.unlink(missing_ok=True)
            raise
        except Exception as e:  # noqa: BLE001 — retried below, surfaced after
            last_err = e
            if "416" in str(e):
                # 416 on the probe / request means "nothing beyond `have`".
                # Only trust it if the zip actually verifies.
                if _zip_ok(dest):
                    log.info("%s: complete (416, zip OK)", dest.name)
                    return dest, dest.stat().st_size
                log.warning("%s: 416 but zip invalid — restarting from 0", dest.name)
                dest.unlink(missing_ok=True)
            else:
                log.warning("%s: attempt %d failed: %s", dest.name, attempt, e)
        if attempt < cfg.retries:
            time.sleep(min(30.0, 5.0 * (attempt + 1)))
    raise RuntimeError(f"download failed after {cfg.retries + 1} attempts: {url} ({last_err})")


def _download_complete(url: str, dest: Path, cfg: FetcherConfig) -> bool:
    """1-byte probe past EOF: empty body / 416 => complete; else more data."""
    size = dest.stat().st_size
    if size == 0:
        return False
    if not _zip_ok(dest):
        return False
    req = urllib.request.Request(url, headers={"User-Agent": cfg.user_agent})
    req.add_header("Range", f"bytes={size}-{size}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            if r.getcode() == 416:
                return True
            return r.getcode() == 206 and not r.read(1)
    except urllib.error.HTTPError as e:
        return e.code == 416
    except (urllib.error.URLError, TimeoutError):
        return False


def _zip_ok(path: Path) -> bool:
    try:
        return zipfile.ZipFile(path).testzip() is None
    except (zipfile.BadZipFile, OSError):
        return False


# ---------------------------------------------------------------------------
# Version verification — never trust the API `version` field alone
# ---------------------------------------------------------------------------

def verify_plugin_version(zip_path: Path, api_version: Optional[str]) -> Dict[str, Any]:
    """Read the real version out of the zip and compare with the API.

    Sources, in trust order: readme.txt ``Stable tag`` (the shipped
    version), then the main plugin file's ``Version:`` header, then the
    version embedded in ``download_link``'s filename. Returns a dict with
    ``version_verified``, ``version_source``, ``drift`` (bool) and the
    individual readings, so callers can decide — a drift is a flag, not
    a silent overwrite: the staged tree is what the zip actually is.
    """
    result: Dict[str, Any] = {
        "version_api": api_version,
        "version_verified": api_version,
        "version_source": "api",
        "stable_tag": None,
        "header_version": None,
        "download_link_version": None,
        "drift": False,
    }
    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            # readme.txt — usually <slug>/readme.txt at the top level.
            readme = next((n for n in names if n.rsplit("/", 1)[-1].lower() == "readme.txt"), None)
            if readme:
                text = zf.read(readme).decode("utf-8", errors="replace")
                m = _STABLE_TAG_RE.search(text)
                if m and m.group(1).strip().lower() != "trunk":
                    result["stable_tag"] = m.group(1).strip()
            # Main plugin file: a .php one level down (<slug>/<slug>.php)
            # whose header has Plugin Name. (Depth 0 also allowed.)
            for name in names:
                if name.count("/") > 1 or not name.lower().endswith(".php"):
                    continue
                try:
                    head = zf.read(name).decode("utf-8", errors="replace")[:4096]
                except KeyError:
                    continue
                if _PLUGIN_HEADER_NAME_RE.search(head):
                    m = _PLUGIN_HEADER_VERSION_RE.search(head)
                    if m:
                        result["header_version"] = m.group(1).strip()
                    break
    except zipfile.BadZipFile as e:
        result["error"] = f"bad zip: {e}"
        return result

    verified = result["stable_tag"] or result["header_version"]
    if verified:
        result["version_verified"] = verified
        result["version_source"] = "stable_tag" if result["stable_tag"] else "header"
    if api_version and verified and verified != api_version:
        result["drift"] = True
        log.warning("%s: VERSION DRIFT api=%s zip=%s (using zip version)",
                    zip_path.name, api_version, verified)
    return result


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------

def extract_plugin_zip(zip_path: Path, dest_dir: Path, cfg: FetcherConfig) -> int:
    """Extract with Zip-Slip / symlink / zip-bomb guards. Returns file count."""
    max_bytes = cfg.max_uncompressed_mb * 1024 * 1024
    if max_bytes <= 0:
        raise ValueError("max_uncompressed_mb must be positive")
    root = dest_dir.resolve()
    total = 0
    count = 0
    entries = []
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > 100_000:
            raise FetcherPolicyError(f"zip contains too many entries: {zip_path.name}")
        for info in infos:
            target = (root / info.filename).resolve()
            if target != root and root not in target.parents:
                raise FetcherPolicyError(f"unsafe zip entry (path escape): {info.filename!r}")
            if target == root and not info.is_dir():
                raise FetcherPolicyError(f"unsafe zip entry (file targets extraction root): {info.filename!r}")
            # Unix symlink entries: external_attr high bits = file type.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise FetcherPolicyError(f"unsafe zip entry (symlink): {info.filename!r}")
            total += info.file_size
            if total > max_bytes:
                raise FetcherPolicyError(
                    f"zip exceeds uncompressed cap ({cfg.max_uncompressed_mb} MB): {zip_path.name}")
            entries.append((info, target))
        dest_dir.mkdir(parents=True, exist_ok=True)
        written_total = 0
        for info, target in entries:
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        written_total += len(chunk)
                        if written_total > max_bytes:
                            raise FetcherPolicyError(
                                f"zip exceeds uncompressed cap ({cfg.max_uncompressed_mb} MB): {zip_path.name}")
                        dst.write(chunk)
                count += 1
    return count


def run_self_tests() -> bool:
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "demo.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
                zipped.writestr("demo/readme.txt", "Stable tag: 1.2.3\n")
                zipped.writestr(
                    "demo/demo.php",
                    "<?php\nPlugin Name: Demo\nVersion: 1.2.3\n",
                )
            if not _zip_ok(archive):
                raise AssertionError("generated self-test archive did not validate")
            verified = verify_plugin_version(archive, "1.2.3")
            if verified.get("version_verified") != "1.2.3" or verified.get("drift"):
                raise AssertionError("archive version verification failed")
            extracted = root / "extracted"
            count = extract_plugin_zip(
                archive, extracted, FetcherConfig(max_uncompressed_mb=1))
            if count != 2 or not (extracted / "demo" / "demo.php").is_file():
                raise AssertionError("safe extraction failed")
        return True
    except Exception:
        log.exception("fetcher self-test failed")
        return False


# ---------------------------------------------------------------------------
# Manifest / resume
# ---------------------------------------------------------------------------

def load_manifest(staging: Path) -> List[Dict[str, Any]]:
    path = staging / "manifest.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        log.warning("manifest %s unreadable; starting fresh", path)
        return []


def save_manifest(staging: Path, entries: List[Dict[str, Any]]) -> None:
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.json").write_text(
        json.dumps(entries, indent=2, sort_keys=True), encoding="utf-8")
    fieldnames = ["slug", "name", "version_api", "version_verified", "version_source",
                  "drift", "active_installs", "last_updated", "download_link",
                  "zip_sha256", "zip_bytes", "extract_path", "files_count",
                  "status", "reason", "fetched_at"]
    with open(staging / "manifest.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for e in entries:
            w.writerow(e)


def _already_staged(entry: Dict[str, Any], cfg: FetcherConfig) -> bool:
    """Resume check: manifest says fetched + dir exists + marker sha matches."""
    if cfg.force or entry.get("status") != "fetched":
        return False
    extract_path = Path(entry.get("extract_path") or "")
    marker = extract_path / ".fetcher.json"
    if not extract_path.is_dir() or not marker.exists():
        return False
    try:
        saved = json.loads(marker.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    zip_path = Path(entry.get("zip_path") or "")
    if cfg.keep_zips and zip_path.exists():
        return saved.get("zip_sha256") == entry.get("zip_sha256") == sha256_file(zip_path)
    return saved.get("zip_sha256") == entry.get("zip_sha256")


# ---------------------------------------------------------------------------
# Main fetch
# ---------------------------------------------------------------------------

def build_entry(plugin: Dict[str, Any], cfg: FetcherConfig) -> Dict[str, Any]:
    """Manifest entry skeleton from one API record (before download)."""
    return {
        "slug": plugin.get("slug"),
        "name": strip_html(plugin.get("name")),
        "version_api": plugin.get("version"),
        "version_verified": plugin.get("version"),
        "version_source": "api",
        "stable_tag": None,
        "header_version": None,
        "download_link_version": version_from_download_link(plugin.get("download_link")),
        "drift": False,
        "active_installs": plugin.get("active_installs"),
        "last_updated": plugin.get("last_updated"),
        "added": plugin.get("added"),
        "author": strip_html(plugin.get("author")),
        "author_profile": plugin.get("author_profile"),
        "homepage": plugin.get("homepage"),
        "requires": plugin.get("requires"),
        "tested": plugin.get("tested"),
        "requires_php": plugin.get("requires_php"),
        "download_link": plugin.get("download_link"),
        "zip_path": "",
        "zip_sha256": "",
        "zip_bytes": 0,
        "extract_path": "",
        "files_count": 0,
        "status": "pending",
        "reason": "",
        "fetched_at": "",
    }


def fetch_targets(cfg: FetcherConfig) -> List[Dict[str, Any]]:
    """Fetch one run. Returns the manifest entries for THIS run.

    Library contract: pass a FetcherConfig, get back a list of dicts with
    the schema in README.md. ``status`` is one of fetched / skipped /
    drift-fetched / failed / dry-run. A drift is NOT a failure — the entry
    is staged under its *verified* version and flagged ``drift: true``.
    Raises RuntimeError only when the API yields nothing usable at all.
    """
    if cfg.platform not in PLATFORM_MIN_INSTALLS and cfg.min_installs is None:
        raise ValueError(f"unknown platform {cfg.platform!r}; use patchstack|wordfence|custom")
    cfg.staging.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(cfg.staging)
    by_slug = {e["slug"]: e for e in manifest}

    # --- 1. Discover candidates -------------------------------------------
    if cfg.slugs:
        plugins: List[Dict[str, Any]] = []
        for slug in dict.fromkeys(cfg.slugs):  # dedupe, keep order
            if slug in cfg.exclude:
                continue
            info = fetch_plugin_info(slug, cfg)
            if info is None:
                manifest.append({**build_entry({"slug": slug}, cfg),
                                 "status": "failed", "reason": "not a plugin (or not found)"})
                continue
            if int(info.get("active_installs") or 0) < cfg.effective_min_installs():
                manifest.append({**build_entry(info, cfg), "status": "skipped",
                                 "reason": f"active_installs {info.get('active_installs')} "
                                           f"< {cfg.effective_min_installs()}"})
                continue
            plugins.append(info)
            if cfg.delay_secs:
                time.sleep(cfg.delay_secs)
    else:
        plugins = query_plugins(cfg)

    if not plugins and not any(e["status"] in ("failed", "skipped") for e in manifest):
        raise RuntimeError("WP.org API returned no usable plugins for this query")

    # --- 2. Fetch each candidate -------------------------------------------
    run_entries: List[Dict[str, Any]] = []
    for plugin in plugins[: cfg.limit]:
        entry = build_entry(plugin, cfg)
        slug, api_version = entry["slug"], entry["version_api"]
        prev = by_slug.get(slug)

        if prev and _already_staged(prev, cfg) and not cfg.dry_run:
            prev = dict(prev, status="skipped", reason="already staged (use --force to re-fetch)")
            run_entries.append(prev)
            log.info("%s: already staged, skipping", slug)
            continue

        if cfg.dry_run:
            entry.update(status="dry-run", reason="dry run — no download")
            run_entries.append(entry)
            log.info("%s %s (%s installs) — dry run", slug, api_version, entry["active_installs"])
            continue

        download_link = plugin.get("download_link")
        if not download_link:
            entry.update(status="failed", reason="API returned no download_link")
            run_entries.append(entry)
            continue
        try:
            zip_dir = cfg.staging / "zips"
            zip_path = zip_dir / f"{slug}-{api_version}.zip"
            download_plugin(download_link, zip_path, cfg)
            verified = verify_plugin_version(zip_path, api_version)
            entry.update({
                "version_verified": verified["version_verified"],
                "version_source": verified["version_source"],
                "stable_tag": verified.get("stable_tag"),
                "header_version": verified.get("header_version"),
                "drift": verified["drift"],
            })
            if verified.get("error"):
                entry.update(status="failed", reason=verified["error"])
                run_entries.append(entry)
                continue
            ver = entry["version_verified"]
            # Re-name the zip under the verified version if drifted.
            if verified["drift"]:
                fixed = zip_dir / f"{slug}-{ver}.zip"
                if fixed != zip_path:
                    zip_path.rename(fixed)
                    zip_path = fixed
            entry.update({
                "zip_path": str(zip_path),
                "zip_sha256": sha256_file(zip_path),
                "zip_bytes": zip_path.stat().st_size,
            })
            if cfg.unzip:
                extract_path = cfg.staging / f"{slug}-{ver}"
                count = extract_plugin_zip(zip_path, extract_path, cfg)
                entry.update(extract_path=str(extract_path), files_count=count)
                (extract_path / ".fetcher.json").write_text(json.dumps({
                    "slug": slug, "version_verified": ver,
                    "zip_sha256": entry["zip_sha256"],
                    "download_link": download_link,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }, indent=2), encoding="utf-8")
                if not cfg.keep_zips:
                    zip_path.unlink(missing_ok=True)
                    entry["zip_path"] = ""
            entry.update({
                "status": "drift-fetched" if verified["drift"] else "fetched",
                "reason": (f"API version {api_version} != zip version {ver}"
                           if verified["drift"] else ""),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            })
            log.info("%s %s (%s installs) -> %s [%s]",
                     slug, ver, entry["active_installs"], entry["status"], entry["extract_path"])
        except Exception as e:  # noqa: BLE001 — one bad plugin must not kill the run
            entry.update(status="failed", reason=str(e)[:500])
            log.error("%s: failed: %s", slug, e)
            run_entries.append(entry)
            continue
        run_entries.append(entry)
        if cfg.download_delay_secs:
            time.sleep(cfg.download_delay_secs)

    # --- 3. Merge + persist manifest (newest run wins per slug) ------------
    merged = {e["slug"]: e for e in manifest}
    for e in run_entries:
        merged[e["slug"]] = e
    # Keep failed/skipped rows appended in the discovery step too.
    for e in manifest:
        merged.setdefault(e["slug"], e)
    final = sorted(merged.values(), key=lambda e: (e.get("fetched_at") or "", e["slug"]))
    # Preserve discovery-step failures that were appended to `manifest` above.
    save_manifest(cfg.staging, final)
    return run_entries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wp_target_fetcher",
        description="Fetch recently updated WordPress.org plugins into a staging folder.",
        epilog="Config file: JSON with the same keys as FetcherConfig "
               "(e.g. {\"platform\": \"wordfence\", \"limit\": 20}). "
               "Env overrides: WP_FETCHER_PLATFORM, WP_FETCHER_MIN_INSTALLS, "
               "WP_FETCHER_LIMIT, WP_FETCHER_STAGING, WP_FETCHER_DRY_RUN, ...",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    # Defaults are None here on purpose: a value given on the CLI wins, else
    # the env var / config file value stands, else the FetcherConfig default.
    # (argparse defaults would clobber config-file values.)
    p.add_argument("--staging", default=None,
                   help="staging folder (default output/fetcher)")
    p.add_argument("--platform", choices=["patchstack", "wordfence", "custom"],
                   default=None, help="install bar preset (default patchstack >=1000)")
    p.add_argument("--min-installs", type=int, default=None,
                   help="override the platform install bar")
    p.add_argument("--limit", type=int, default=None, help="max targets to fetch (default 20)")
    p.add_argument("--max-pages", type=int, default=None, help="API pages to scan (default 50)")
    p.add_argument("--per-page", type=int, default=None, help="results per API page (default 100)")
    p.add_argument("--browse", default=None,
                   choices=["updated", "popular", "new", "top-rated"],
                   help="query_plugins browse mode (default updated)")
    p.add_argument("--search", default=None, help="search term instead of browse mode")
    p.add_argument("--slugs", default=None,
                   help="comma-separated explicit slugs (bypasses browse/recency)")
    p.add_argument("--slugs-file", default=None,
                   help="file with one slug per line (bypasses browse/recency)")
    p.add_argument("--updated-since", default=None,
                   help="only plugins updated on/after YYYY-MM-DD")
    p.add_argument("--max-age-days", type=int, default=None,
                   help="only plugins updated within the last N days")
    p.add_argument("--exclude", default=None, help="comma-separated slugs to skip")
    p.add_argument("--exclude-file", default=None, help="file with one slug per line to skip")
    p.add_argument("--config", default=None, help="JSON config file")
    p.add_argument("--no-keep-zips", action="store_true", default=None,
                   help="delete zips after extraction")
    p.add_argument("--no-unzip", action="store_true", default=None,
                   help="download zips only, do not extract")
    p.add_argument("--force", action="store_true", default=None,
                   help="re-download already-staged targets")
    p.add_argument("--dry-run", action="store_true", default=None,
                   help="list candidates, download nothing")
    p.add_argument("--delay-secs", type=float, default=None)
    p.add_argument("--retries", type=int, default=None,
                   help="resume attempts per download (default 14: wp.org stalls mid-transfer)")
    p.add_argument("--timeout-secs", type=int, default=None)
    p.add_argument("--max-download-mb", type=int, default=None)
    p.add_argument("--max-uncompressed-mb", type=int, default=None)
    p.add_argument("--json", action="store_true", help="print run summary as JSON on stdout")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--self-test", action="store_true",
                   help="run offline unit checks (no network) and exit")
    return p.parse_args(argv)


def _read_slug_file(path: str) -> List[str]:
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    if args.self_test:
        return 0 if run_self_tests() else 1

    # Precedence: CLI > env > config file > defaults.
    cfg_dict: Dict[str, Any] = {}
    if args.config:
        cfg_dict.update(json.loads(Path(args.config).read_text(encoding="utf-8")))
    cfg_dict.update(config_from_env())
    try:
        cfg = config_from_dict(cfg_dict)
    except ValueError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    # CLI overrides — only when the flag was actually given (None = unset).
    if args.staging is not None:
        cfg.staging = Path(args.staging)
    if args.platform is not None:
        cfg.platform = args.platform
    if args.min_installs is not None:
        cfg.min_installs = args.min_installs
    if args.limit is not None:
        cfg.limit = args.limit
    if args.max_pages is not None:
        cfg.max_pages = args.max_pages
    if args.per_page is not None:
        cfg.per_page = args.per_page
    if args.browse is not None:
        cfg.browse = args.browse
    if args.search is not None:
        cfg.search = args.search
    if args.updated_since is not None:
        cfg.updated_since = args.updated_since
    if args.max_age_days is not None:
        cfg.max_age_days = args.max_age_days
    if args.no_keep_zips is not None:
        cfg.keep_zips = not args.no_keep_zips
    if args.no_unzip is not None:
        cfg.unzip = not args.no_unzip
    if args.force is not None:
        cfg.force = args.force
    if args.dry_run is not None:
        cfg.dry_run = args.dry_run
    if args.delay_secs is not None:
        cfg.delay_secs = args.delay_secs
    if args.retries is not None:
        cfg.retries = args.retries
    if args.timeout_secs is not None:
        cfg.timeout_secs = args.timeout_secs
    if args.max_download_mb is not None:
        cfg.max_download_mb = args.max_download_mb
    if args.max_uncompressed_mb is not None:
        cfg.max_uncompressed_mb = args.max_uncompressed_mb

    slugs: List[str] = []
    if args.slugs:
        slugs += [s.strip() for s in args.slugs.split(",") if s.strip()]
    if args.slugs_file:
        slugs += _read_slug_file(args.slugs_file)
    if slugs:
        cfg.slugs = slugs
    exclude: List[str] = []
    if args.exclude:
        exclude += [s.strip() for s in args.exclude.split(",") if s.strip()]
    if args.exclude_file:
        exclude += _read_slug_file(args.exclude_file)
    if exclude:
        cfg.exclude = exclude

    if cfg.limit < 1 or cfg.per_page < 1 or cfg.per_page > 250:
        print("error: --limit >= 1 and 1 <= --per-page <= 250", file=sys.stderr)
        return 2
    if cfg.max_download_mb < 1 or cfg.max_uncompressed_mb < 1:
        print("error: archive size limits must be positive", file=sys.stderr)
        return 2
    if cfg.updated_since:
        try:
            datetime.strptime(cfg.updated_since, "%Y-%m-%d")
        except ValueError:
            print("error: --updated-since must be YYYY-MM-DD", file=sys.stderr)
            return 2

    try:
        entries = fetch_targets(cfg)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    fetched = [e for e in entries if e["status"] in ("fetched", "drift-fetched")]
    failed = [e for e in entries if e["status"] == "failed"]
    skipped = [e for e in entries if e["status"] == "skipped"]
    drifted = [e for e in entries if e["status"] == "drift-fetched"]
    summary = {
        "staging": str(cfg.staging),
        "platform": cfg.platform,
        "min_installs": cfg.effective_min_installs(),
        "requested": len(entries),
        "fetched": len(fetched),
        "drift_fetched": len(drifted),
        "skipped": len(skipped),
        "failed": len(failed),
        "entries": entries,
    }
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"Fetched {len(fetched)} target(s) into {cfg.staging} "
              f"(min_installs={cfg.effective_min_installs()}, platform={cfg.platform})")
        if drifted:
            print(f"WARNING: {len(drifted)} version drift(s) — API version != zip version; "
                  f"staged under the verified zip version: "
                  + ", ".join(f"{e['slug']} api={e['version_api']} zip={e['version_verified']}"
                              for e in drifted))
        if failed:
            print(f"FAILED ({len(failed)}): " + ", ".join(
                f"{e['slug']} ({e['reason'][:120]})" for e in failed), file=sys.stderr)
        if skipped:
            print(f"Skipped ({len(skipped)}): " + ", ".join(e["slug"] for e in skipped))
        print(f"Manifest: {cfg.staging}/manifest.json  +  manifest.csv")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
