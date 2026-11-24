"""Download public labelled URL datasets into datasets/<name>/ and write datasets/MANIFEST.json.

Developer tool, standard library only (pyarrow is used when present, for the HuggingFace parquet sets:
only the URL + label columns are read, over HTTP range requests, so a 36 GB set costs a few MB).
Downloaded files are untrusted data: nothing in them is executed. Run it isolated:

  .venv-train/bin/python -I tools/fetch_datasets.py            # download everything + manifest
  .venv-train/bin/python -I tools/fetch_datasets.py --only tranco,openphish
  .venv/bin/python -I tools/fetch_datasets.py --manifest-only  # recount what is already on disk

A source that is unreachable is skipped and recorded in the manifest with its error.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import shutil
import sys
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import url_datasets  # noqa: E402

OUT = ROOT / "datasets"
UA = "Mozilla/5.0 (compatible; dataset-fetcher/1.0)"
TIMEOUT = 60
MAX_FILE_BYTES = 1_500_000_000
HF_API = "https://huggingface.co/api/datasets/{name}/parquet"
URL_COLUMN_NAMES = ("url", "text", "URL", "domain")
LABEL_COLUMN_NAMES = ("label", "status", "phishing", "type", "result")

# kind: file (saved as is) | zip / gz (unpacked, archive deleted) | hf (parquet -> urls.csv) | mendeley
SOURCES: list[dict] = [
    {"name": "tranco", "licence": "free to use, cite Le Pochat et al. NDSS 2019", "label": "legit (popularity list)",
     "files": [("zip", "https://tranco-list.eu/top-1m.csv.zip", "top-1m.csv")]},
    {"name": "phiusiil", "licence": "CC BY 4.0", "label": "column label: 1 = legit, 0 = phishing",
     "files": [("zip", "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
                "PhiUSIIL_Phishing_URL_Dataset.csv")]},
    {"name": "phishing_army", "licence": "CC BY-NC 4.0", "label": "phishing (hostnames)",
     "files": [("file", "https://phishing.army/download/phishing_army_blocklist.txt", "phishing_army_blocklist.txt"),
               ("file", "https://phishing.army/download/phishing_army_blocklist_extended.txt",
                "phishing_army_blocklist_extended.txt")]},
    {"name": "openphish", "licence": "community feed, non-commercial use", "label": "phishing",
     "files": [("file", "https://openphish.com/feed.txt", "feed.txt"),
               ("file", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
                "feed_github.txt")]},
    {"name": "urlhaus", "licence": "CC0", "label": "malware distribution URLs",
     "files": [("file", "https://urlhaus.abuse.ch/downloads/csv_online/", "csv_online.csv"),
               ("file", "https://urlhaus.abuse.ch/downloads/csv_recent/", "csv_recent.csv")]},
    {"name": "phishing_database", "licence": "MIT", "label": "phishing",
     "files": [("file", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                        "phishing-links-ACTIVE.txt", "phishing-links-ACTIVE.txt"),
               ("file", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                        "phishing-domains-ACTIVE.txt", "phishing-domains-ACTIVE.txt"),
               ("file", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                        "phishing-links-NEW-today.txt", "phishing-links-NEW-today.txt")]},
    {"name": "phishtank", "licence": "CC BY-SA 2.5", "label": "phishing (verified, online)",
     "files": [("gz", "http://data.phishtank.com/data/online-valid.csv.gz", "online-valid.csv")]},
    {"name": "jpcert", "licence": "see github.com/JPCERTCC/phishurl-list", "label": "phishing (confirmed by JPCERT/CC)",
     "files": [("file", f"https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/{y}/{y}{m:02d}.csv",
                f"{y}{m:02d}.csv") for y, m in [(2025, m) for m in range(1, 13)] + [(2026, m) for m in range(1, 11)]]},
    {"name": "hannousse", "licence": "CC BY 4.0", "label": "column status: phishing / legitimate",
     "files": [("mendeley", "https://data.mendeley.com/public-api/datasets/c2gw7fy2j4/files?folder_id=root&version=3",
                "dataset_B_05_2020.csv")]},
    {"name": "hf_ealvaradob", "licence": "Apache-2.0", "label": "column label: 1 = phishing",
     "files": [("file", "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json",
                "urls.json")]},
    {"name": "hf_kmack", "licence": "unknown (HuggingFace kmack/Phishing_urls)", "label": "column label: 1 = phishing",
     "files": [("hf", "kmack/Phishing_urls", "urls.csv")]},
    {"name": "hf_pirocheto", "licence": "CC BY 4.0 (re-host of Hannousse & Yahiouche)", "label": "column status",
     "files": [("hf", "pirocheto/phishing-url", "urls.csv")]},
    {"name": "hf_phreshphish", "licence": "CC BY 4.0", "label": "column label: phish / benign",
     "files": [("hf", "phreshphish/phreshphish", "urls.csv")]},
]


def _open(url: str, headers: dict | None = None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*", **(headers or {})})
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def download(url: str, dest: Path) -> None:
    tmp = dest.with_name(dest.name + ".part")
    with _open(url) as resp, open(tmp, "wb") as out:
        total = 0
        while chunk := resp.read(1 << 20):
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise ValueError(f"larger than {MAX_FILE_BYTES} bytes")
            out.write(chunk)
    if total == 0:
        tmp.unlink()
        raise ValueError("empty response")
    tmp.replace(dest)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def unpack_zip(archive: Path, wanted: str, dest: Path) -> None:
    """Extract one member by name; member paths from the archive are never used as file paths."""
    with zipfile.ZipFile(archive) as z:
        members = [m for m in z.infolist() if not m.is_dir() and Path(m.filename).name == wanted]
        if not members:
            members = [m for m in z.infolist() if not m.is_dir() and m.filename.lower().endswith(".csv")]
        if not members:
            raise ValueError(f"{wanted} not in archive")
        with z.open(members[0]) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)


class RangeFile(io.RawIOBase):
    """Seekable read-only view of a remote file over HTTP range requests (for pyarrow column reads)."""

    def __init__(self, url: str):
        with _open(url, {"Range": "bytes=0-0"}) as resp:
            self.url = resp.geturl()
            self.size = int(resp.headers["Content-Range"].rsplit("/", 1)[1])
        self.pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = 0) -> int:
        self.pos = offset if whence == 0 else self.pos + offset if whence == 1 else self.size + offset
        return self.pos

    def read(self, n: int = -1) -> bytes:
        end = self.size if n is None or n < 0 else min(self.size, self.pos + n)
        if end <= self.pos:
            return b""
        with _open(self.url, {"Range": f"bytes={self.pos}-{end - 1}"}) as resp:
            data = resp.read()
        self.pos += len(data)
        return data

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)


def _hf_shard(url: str) -> list[tuple[str, str, str]]:
    import pyarrow.parquet as pq

    split = url.rsplit("/", 2)[-2]
    pf = pq.ParquetFile(RangeFile(url))
    names = pf.schema_arrow.names
    url_col = next(c for c in URL_COLUMN_NAMES if c in names)
    label_col = next(c for c in LABEL_COLUMN_NAMES if c in names)
    table = pf.read(columns=[url_col, label_col])
    return [(str(u), str(v), split) for u, v in zip(table[url_col].to_pylist(), table[label_col].to_pylist())
            if u is not None]


def fetch_hf(name: str, dest: Path) -> str:
    """URL + label columns of every parquet shard -> one CSV (url,label,split). Returns a note."""
    try:
        import pyarrow.parquet  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("pyarrow is needed for HuggingFace parquet sets (use .venv-train)") from exc
    with _open(HF_API.format(name=name)) as resp:
        listing = json.load(resp)
    shards = [u for splits in listing.values() for urls in splits.values() for u in urls
              if isinstance(u, str) and u.startswith("https://huggingface.co/")]
    failed = 0
    tmp = dest.with_name(dest.name + ".part")
    with open(tmp, "w", newline="", encoding="utf-8") as out, ThreadPoolExecutor(max_workers=8) as pool:
        writer = csv.writer(out)
        writer.writerow(["url", "label", "split"])

        def safe(u: str) -> list[tuple[str, str, str]] | None:
            for _ in range(3):
                try:
                    return _hf_shard(u)
                except (OSError, ValueError, KeyError, StopIteration):
                    continue
            return None

        for rows in pool.map(safe, shards):
            if rows is None:
                failed += 1
            else:
                writer.writerows(rows)
    tmp.replace(dest)
    return f"{len(shards) - failed}/{len(shards)} parquet shards read (URL + label columns only)"


def fetch_one(source: dict) -> dict:
    folder = OUT / source["name"]
    folder.mkdir(parents=True, exist_ok=True)
    entry = {"name": source["name"], "licence": source["licence"], "label_meaning": source["label"],
             "downloaded": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "files": []}
    for kind, url, filename in source["files"]:
        dest = folder / filename
        rec = {"file": f"{source['name']}/{filename}", "source_url": url if kind != "hf" else
               f"https://huggingface.co/datasets/{url}"}
        try:
            if kind == "file":
                download(url, dest)
            elif kind == "zip":
                archive = folder / "download.zip"
                download(url, archive)
                unpack_zip(archive, filename, dest)
                archive.unlink()
            elif kind == "gz":
                archive = folder / "download.gz"
                download(url, archive)
                with gzip.open(archive, "rb") as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
                archive.unlink()
            elif kind == "mendeley":
                with _open(url) as resp:
                    listing = json.load(resp)
                link = next(f["content_details"]["download_url"] for f in listing if f["filename"] == filename)
                if not link.startswith("https://data.mendeley.com/"):
                    raise ValueError("unexpected download host")
                download(link, dest)
            elif kind == "hf":
                rec["note"] = fetch_hf(url, dest)
            rec["ok"] = True
        except (OSError, ValueError, KeyError, StopIteration, RuntimeError, zipfile.BadZipFile) as exc:
            rec["ok"] = False
            rec["error"] = f"{type(exc).__name__}: {exc}"[:300]
            for leftover in folder.glob("*.part"):
                leftover.unlink()
        entry["files"].append(rec)
        print(f"  {'ok  ' if rec['ok'] else 'FAIL'} {rec['file']}  {rec.get('error', rec.get('note', ''))}", flush=True)
    return entry


def describe(entry: dict) -> dict:
    """Add sha256, size and label / path statistics for every file that is on disk."""
    for rec in entry["files"]:
        path = OUT / rec["file"]
        if not path.exists():
            rec["ok"] = False
            continue
        rec["ok"] = True
        rec["bytes"] = path.stat().st_size
        rec["sha256"] = sha256(path)
        if entry["name"] == "tranco":
            with open(path, encoding="utf-8") as f:
                rec["rows"] = sum(1 for _ in f)
            continue
        try:
            rows = url_datasets.load_labelled(path, source=entry["name"], quiet=True)
        except (ValueError, OSError, ImportError) as exc:
            rec["load_error"] = str(exc)[:300]
            continue
        rec.update(url_datasets.summarise(rows))
    return entry


def write_manifest(entries: list[dict]) -> None:
    manifest = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "label_convention": "1 = phishing / malicious, 0 = legitimate (after tools/url_datasets.py)",
                "datasets": entries}
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", default="", help="comma-separated dataset names")
    ap.add_argument("--manifest-only", action="store_true", help="do not download, recount files on disk")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    only = {n for n in args.only.split(",") if n}
    previous = {}
    if (OUT / "MANIFEST.json").exists():
        previous = {e["name"]: e for e in json.loads((OUT / "MANIFEST.json").read_text(encoding="utf-8"))["datasets"]}
    entries = []
    for source in SOURCES:
        if only and source["name"] not in only or args.manifest_only:
            entry = previous.get(source["name"]) or {
                "name": source["name"], "licence": source["licence"], "label_meaning": source["label"],
                "downloaded": None, "files": [{"file": f"{source['name']}/{f}", "source_url": u}
                                              for _, u, f in source["files"]]}
        else:
            print(source["name"], flush=True)
            entry = fetch_one(source)
        entries.append(describe(entry))
        write_manifest(entries + [previous[n] for n in previous if n not in {e["name"] for e in entries}])
    write_manifest(entries)
    for e in entries:
        for rec in e["files"]:
            print(f"{rec['file']:60} {'ok' if rec.get('ok') else 'MISSING':8} phishing={rec.get('phishing', '-')} "
                  f"legit={rec.get('legit', '-')} legit_with_path={rec.get('legit_with_path_share', '-')}")


if __name__ == "__main__":
    main()
