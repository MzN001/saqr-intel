"""One loader for any labelled URL dataset -> [(url, label, source)], label 1 = phishing, 0 = legitimate.

    from url_datasets import load_labelled
    rows = load_labelled("datasets/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv")
    rows = load_labelled("feed.txt", label=1)                       # plain list, label given by flag
    rows = load_labelled("x.csv", url_col="link", label_col="verdict", positive={"bad"})

Formats: CSV / TSV / TXT / JSON / JSONL (standard library only, also .gz) and parquet (needs pyarrow).
The URL column, the label column and the label vocabulary are detected. Numeric labels are ambiguous
(PhiUSIIL uses 1 = legitimate): known datasets are in KNOWN, everything else is checked against the
popular-site list ("which class holds more hosts that are a top-10k site") and a loud AmbiguousLabelWarning is raised
when that check cannot decide.

CLI:  python tools/url_datasets.py <file> [--label 0|1] [--url-col c] [--label-col c] [--positive v,v]
"""
from __future__ import annotations

import csv
import gzip
import json
import re
import sys
import warnings
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POPULAR_PATH = ROOT / "saqr" / "intel" / "data" / "popular_domains.txt.gz"

Row = tuple[str, int, str]

POSITIVE_WORDS = frozenset({
    "phishing", "phish", "phising", "malicious", "bad", "spam", "defacement", "malware", "fraud", "scam",
    "suspicious", "unsafe", "dangerous", "attack", "illegitimate", "malicious_url", "phishing_url", "yes",
})
NEGATIVE_WORDS = frozenset({
    "benign", "legit", "legitimate", "good", "safe", "clean", "normal", "ham", "trusted", "harmless", "no",
    "legitimate_url", "non-phishing", "not phishing", "nonphishing",
})
NUMERIC_POSITIVE = frozenset({"1", "true"})
NUMERIC_NEGATIVE = frozenset({"0", "false", "-1"})
URL_NAMES = ("url", "urls", "link", "links", "uri", "website", "address", "text", "domain", "domains", "host",
             "hostname", "fqdn")
LABEL_NAMES = ("label", "labels", "status", "class", "classlabel", "class_label", "result", "verdict", "type",
               "category", "phishing", "is_phishing", "isphishing", "malicious", "is_malicious", "target", "y")
URL_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^\s/@]+@)?(?:[^\s/:?#]+\.)+(?:[^\s/:?#.]{2,}|\d{1,3})\.?(?::\d+)?(?:[/?#]\S*)?$",
                    re.IGNORECASE)
SAMPLE = 5000
HEURISTIC_SAMPLE = 20000


class AmbiguousLabelWarning(UserWarning):
    """The meaning of the label values could not be confirmed: check the dataset by hand."""


# Known quirks, matched on the lower-cased path. "positive" = raw label values that mean phishing,
# "label" = every row has this label (the file has no label column).
KNOWN: tuple[dict, ...] = (
    {"match": "phiusiil", "source": "phiusiil", "url_col": "URL", "label_col": "label", "positive": {"0"}},
    {"match": "tranco", "source": "tranco", "label": 0},
    {"match": "top-1m", "source": "tranco", "label": 0},
    {"match": "phishing_army", "source": "phishing_army", "label": 1},
    {"match": "openphish", "source": "openphish", "label": 1},
    {"match": "urlhaus", "source": "urlhaus", "url_col": "url", "label": 1},
    {"match": "phishing_database", "source": "phishing_database", "label": 1},
    {"match": "phishing-links", "source": "phishing_database", "label": 1},
    {"match": "phishing-domains", "source": "phishing_database", "label": 1},
    {"match": "phishtank", "source": "phishtank", "url_col": "url", "label": 1},
    {"match": "online-valid", "source": "phishtank", "url_col": "url", "label": 1},
    {"match": "jpcert", "source": "jpcert", "url_col": "URL", "label": 1},
    {"match": "hannousse", "source": "hannousse", "url_col": "url", "label_col": "status", "positive": {"phishing"}},
    {"match": "dataset_b_05_2020", "source": "hannousse", "url_col": "url", "label_col": "status",
     "positive": {"phishing"}},
    {"match": "pirocheto", "source": "hf_pirocheto", "url_col": "url", "positive": {"phishing"}},
    {"match": "phreshphish", "source": "hf_phreshphish", "url_col": "url", "label_col": "label",
     "positive": {"phish", "phishing"}},
    {"match": "/augmented/", "url_col": "url", "label_col": "label", "positive": {"1"}},
)


def known_quirk(path: str | Path) -> dict | None:
    text = str(path).lower().replace("\\", "/")
    for quirk in KNOWN:
        if quirk["match"] in text:
            return quirk
    return None


def normalise_url(raw: object) -> str:
    """Trimmed URL with a scheme ("http://" is added to bare hosts); "" when it is not a URL."""
    if raw is None:
        return ""
    text = str(raw).strip().strip('"\'').strip()
    if not text or text[0] in "#!" or any(c in text for c in " \t\r\n"):
        return ""
    if "://" not in text[:12]:
        text = "http://" + text
    return text if URL_RE.match(text) else ""


def host_of(url: str) -> str:
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        return ""
    host = host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def has_path(url: str) -> bool:
    """True when the URL is more than a bare homepage (a path, query or fragment)."""
    try:
        parts = urlsplit(url if "://" in url else "http://" + url)
    except ValueError:
        return False
    return bool(parts.path.strip("/") or parts.query or parts.fragment)


_popular: dict[int, frozenset[str]] = {}


def load_popular(top: int = 10_000) -> frozenset[str]:
    """The first 'top' registered domains of the bundled popularity list (empty if the file is missing)."""
    if top not in _popular:
        names: list[str] = []
        if POPULAR_PATH.exists():
            with gzip.open(POPULAR_PATH, "rt", encoding="utf-8") as f:
                for line in f:
                    names.append(line.strip())
                    if len(names) >= top:
                        break
        _popular[top] = frozenset(n for n in names if n)
    return _popular[top]


def is_popular(host: str, popular: frozenset[str]) -> bool:
    labels = host.split(".")
    return any(".".join(labels[i:]) in popular for i in range(max(len(labels) - 1, 1)))


def _open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, encoding="utf-8-sig", errors="replace", newline="")


def _kind(path: Path) -> str:
    suffixes = [s.lower().lstrip(".") for s in path.suffixes if s.lower() != ".gz"]
    ext = suffixes[-1] if suffixes else ""
    if ext in ("csv", "tsv", "json", "parquet"):
        return ext
    if ext in ("jsonl", "ndjson"):
        return "jsonl"
    return "txt"


def _looks_like_data(cells: list[str]) -> bool:
    return any(normalise_url(c) or c.strip().lstrip("-").isdigit() for c in cells)


def _delimited(path: Path, delimiter: str) -> Iterator[dict]:
    csv.field_size_limit(1 << 27)
    with _open_text(path) as f:
        header: list[str] | None = None
        comment_header: list[str] | None = None

        def lines() -> Iterator[str]:
            nonlocal comment_header
            for line in f:
                if line.startswith("#"):
                    cells = next(csv.reader([line.lstrip("# ").strip()], delimiter=delimiter), [])
                    if len(cells) > 1:
                        comment_header = [c.strip() for c in cells]
                    continue
                if line.strip():
                    yield line

        for cells in csv.reader(lines(), delimiter=delimiter):
            if header is None:
                if not _looks_like_data(cells):
                    header = [c.strip() for c in cells]
                    continue
                header = comment_header if comment_header and len(comment_header) == len(cells) else \
                    [f"c{i}" for i in range(len(cells))]
            yield dict(zip(header, cells))


def _text_lines(path: Path) -> Iterator[dict]:
    with _open_text(path) as f:
        for line in f:
            line = line.strip()
            if not line or line[0] in "#!;":
                continue
            tokens = line.split()
            if len(tokens) == 2 and tokens[0] in ("0.0.0.0", "127.0.0.1"):
                line = tokens[1]
            yield {"url": line}


def _json_records(path: Path) -> Iterator[dict]:
    with _open_text(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list)]
        data = max(lists, key=len) if lists else [data]
    for item in data:
        yield item if isinstance(item, dict) else {"url": item}


def _jsonl_records(path: Path) -> Iterator[dict]:
    with _open_text(path) as f:
        for line in f:
            line = line.strip()
            if line:
                item = json.loads(line)
                yield item if isinstance(item, dict) else {"url": item}


def _parquet_records(path: Path, columns: list[str] | None = None) -> Iterator[dict]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise ImportError("reading parquet needs pyarrow (use the training venv); CSV/TXT/JSON work without it") from exc
    pf = pq.ParquetFile(path)
    if columns is None:
        columns = [f.name for f in pf.schema_arrow if str(f.type) in
                   ("string", "large_string", "bool", "int8", "int16", "int32", "int64", "double", "float")]
    for batch in pf.iter_batches(batch_size=50_000, columns=columns):
        yield from batch.to_pylist()


def _records(path: Path, columns: list[str] | None = None) -> Iterator[dict]:
    kind = _kind(path)
    if kind == "csv":
        return _delimited(path, ",")
    if kind == "tsv":
        return _delimited(path, "\t")
    if kind == "json":
        return _json_records(path)
    if kind == "jsonl":
        return _jsonl_records(path)
    if kind == "parquet":
        return _parquet_records(path, columns)
    return _text_lines(path)


def _raw_label(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    text = str(value).strip().lower()
    return text[:-2] if text.endswith(".0") and text[:-2].lstrip("-").isdigit() else text


def _pick(columns: list[str], wanted: str | None, names: tuple[str, ...]) -> str | None:
    lowered = {c.lower().strip(): c for c in columns}
    if wanted is not None:
        if wanted in columns:
            return wanted
        return lowered.get(wanted.lower())
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def detect_columns(sample: list[dict], url_col: str | None = None, label_col: str | None = None,
                   want_label: bool = True) -> tuple[str, str | None]:
    """(URL column, label column or None) from a sample of records."""
    columns = list(dict.fromkeys(k for rec in sample for k in rec))
    if url_col is not None and _pick(columns, url_col, ()) is None:
        raise ValueError(f"URL column {url_col!r} not found; columns: {columns[:30]}")
    if label_col is not None and _pick(columns, label_col, ()) is None:
        raise ValueError(f"label column {label_col!r} not found; columns: {columns[:30]}")

    def url_share(col: str) -> float:
        values = [rec.get(col) for rec in sample if rec.get(col) not in (None, "")]
        return sum(1 for v in values if isinstance(v, str) and normalise_url(v)) / len(values) if values else 0.0

    url = _pick(columns, url_col, URL_NAMES)
    if url is None or (url_col is None and url_share(url) < 0.5):
        scored = sorted(((url_share(c), c) for c in columns), reverse=True)
        if not scored or scored[0][0] < 0.5:
            raise ValueError(f"no URL column found; columns: {columns[:30]}")
        url = scored[0][1]

    label = _pick(columns, label_col, LABEL_NAMES) if want_label else None
    if want_label and label is None:
        vocabulary = POSITIVE_WORDS | NEGATIVE_WORDS | NUMERIC_POSITIVE | NUMERIC_NEGATIVE
        for col in columns:
            values = {_raw_label(rec[col]) for rec in sample if rec.get(col) not in (None, "")}
            if col != url and 1 <= len(values) <= 6 and values <= vocabulary:
                label = col
                break
    return url, label


def _class_profile(pairs: list[tuple[str, str]], popular: frozenset[str]) -> dict[str, tuple[int, float, float]]:
    """raw label -> (rows sampled, share of hosts that ARE a popular site, share of bare homepages).

    Exact host match on purpose: phishing on popular platforms (x.blogspot.com, sites.google.com) would
    otherwise make the phishing class look popular (measured on PhiUSIIL: 6.6% vs 2.5% for legit).
    """
    seen: Counter[str] = Counter()
    pop: Counter[str] = Counter()
    bare: Counter[str] = Counter()
    for url, raw in pairs:
        if seen[raw] >= HEURISTIC_SAMPLE:
            continue
        seen[raw] += 1
        pop[raw] += host_of(url) in popular
        bare[raw] += not has_path(url)
    return {raw: (n, pop[raw] / n, bare[raw] / n) for raw, n in seen.items()}


def resolve_vocabulary(pairs: list[tuple[str, str]], positive: Iterable | None = None,
                       popular: frozenset[str] | None = None, name: str = "dataset") -> dict[str, int]:
    """Map every raw label value to 1 (phishing) / 0 (legit). Unknown values are left out (rows dropped)."""
    values = Counter(raw for _, raw in pairs)
    if positive is not None:
        chosen = {_raw_label(v) for v in ([positive] if isinstance(positive, (str, int, bool)) else positive)}
        if not chosen & set(values) and not set(values) <= NEGATIVE_WORDS | NUMERIC_NEGATIVE:
            warnings.warn(f"{name}: none of the positive values {sorted(chosen)} occur; values seen: "
                          f"{dict(values.most_common(8))}", AmbiguousLabelWarning, stacklevel=3)
        return {v: int(v in chosen) for v in values}

    popular = load_popular() if popular is None else popular
    profile = _class_profile(pairs, popular)
    mapping: dict[str, int] = {}
    for v in values:
        if v in POSITIVE_WORDS:
            mapping[v] = 1
        elif v in NEGATIVE_WORDS:
            mapping[v] = 0
    numeric = [v for v in values if v in NUMERIC_POSITIVE | NUMERIC_NEGATIVE]
    unknown = [v for v in values if v not in mapping and v not in numeric]

    if numeric:
        ones = [v for v in numeric if v in NUMERIC_POSITIVE]
        zeros = [v for v in numeric if v in NUMERIC_NEGATIVE]
        flipped = False
        if ones and zeros and popular:
            def share(group: list[str]) -> float:
                n = sum(profile[v][0] for v in group)
                return sum(profile[v][0] * profile[v][1] for v in group) / n if n else 0.0
            p1, p0 = share(ones), share(zeros)
            if p1 >= 0.02 and p1 >= 3 * p0:
                flipped = True
                warnings.warn(f"{name}: label 1 looks LEGITIMATE ({p1:.1%} of its hosts are top-10k sites, "
                              f"{p0:.1%} for label 0): treating 0 as phishing. Pass positive=... to override.",
                              AmbiguousLabelWarning, stacklevel=3)
            elif not (p0 >= 0.02 and p0 >= 3 * p1):
                warnings.warn(f"{name}: AMBIGUOUS numeric labels (top-10k share: label 1 = {p1:.1%}, label 0 = "
                              f"{p0:.1%}); assuming 1 = phishing. Check by hand and pass positive=...",
                              AmbiguousLabelWarning, stacklevel=3)
        elif len(set(mapping.values())) < 1 and len(numeric) < 2:
            warnings.warn(f"{name}: only one numeric label value {numeric}; assuming 1 = phishing",
                          AmbiguousLabelWarning, stacklevel=3)
        for v in ones:
            mapping[v] = 0 if flipped else 1
        for v in zeros:
            mapping[v] = 1 if flipped else 0
    elif popular and {0, 1} <= set(mapping.values()):
        def word_share(label: int) -> float:
            group = [v for v, lab in mapping.items() if lab == label]
            n = sum(profile[v][0] for v in group)
            return sum(profile[v][0] * profile[v][1] for v in group) / n if n else 0.0
        bad, good = word_share(1), word_share(0)
        if bad >= 0.05 and bad >= 5 * good:
            warnings.warn(f"{name}: the class named as phishing holds more top-10k hosts ({bad:.1%}) than the "
                          f"legitimate class ({good:.1%}); labels may be swapped", AmbiguousLabelWarning, stacklevel=3)

    if unknown:
        dropped = sum(values[v] for v in unknown)
        warnings.warn(f"{name}: {dropped} rows dropped, label values not understood: {unknown[:8]}. "
                      f"Pass positive=... to map them.", AmbiguousLabelWarning, stacklevel=3)
    return mapping


def load_labelled(path: str | Path, url_col: str | None = None, label_col: str | None = None,
                  positive: Iterable | None = None, *, label: int | None = None, source: str | None = None,
                  popular: frozenset[str] | None = None, limit: int | None = None, dedupe: bool = True,
                  quiet: bool = False) -> list[Row]:
    """Load any labelled URL file as [(url, label, source)] with label 1 = phishing, 0 = legitimate.

    url_col / label_col: column names (auto-detected when None). positive: the raw label value(s) meaning
    phishing. label: 0 or 1 for a file without a label column (plain lists). source: tag for every row
    (default: the file's own "source" column if it has one, else the known dataset name or the file name).
    limit: stop after this many rows.
    """
    path = Path(path)
    quirk = known_quirk(path) or {}
    explicit = url_col is not None or label_col is not None or positive is not None or label is not None
    if not explicit:
        url_col, label_col, positive, label = (quirk.get("url_col"), quirk.get("label_col"), quirk.get("positive"),
                                               quirk.get("label"))
    elif url_col is None:
        url_col = quirk.get("url_col")
    fixed_source = source or quirk.get("source")
    fallback_source = path.name.split(".")[0]
    if label is not None and label not in (0, 1):
        raise ValueError("label must be 0 or 1")

    sample = []
    for rec in _records(path):
        sample.append(rec)
        if len(sample) >= SAMPLE:
            break
    if not sample:
        return []
    try:
        url_key, label_key = detect_columns(sample, url_col, label_col, want_label=label is None)
    except ValueError:
        if not quirk or explicit:
            raise
        url_key, label_key = detect_columns(sample, None, None, want_label=label is None)
    if label is None and label_key is None:
        raise ValueError(f"{path.name}: no label column found; pass label=0/1 (plain list) or label_col=...")

    source_key = "source" if fixed_source is None and "source" in sample[0] and url_key != "source" else None
    pairs: list[tuple[str, str]] = []
    sources: list[str] = []
    seen: set[str] = set()
    columns = [url_key] + ([label_key] if label_key else []) + ([source_key] if source_key else [])
    for rec in _records(path, columns):
        url = normalise_url(rec.get(url_key))
        if not url or (dedupe and url in seen):
            continue
        if dedupe:
            seen.add(url)
        pairs.append((url, "" if label_key is None else _raw_label(rec.get(label_key))))
        sources.append(str(rec.get(source_key) or fallback_source) if source_key else fixed_source or fallback_source)
        if limit is not None and len(pairs) >= limit:
            break

    if label is not None:
        return [(url, label, src) for (url, _), src in zip(pairs, sources)]
    with warnings.catch_warnings():
        if quiet:
            warnings.simplefilter("ignore", AmbiguousLabelWarning)
        mapping = resolve_vocabulary(pairs, positive, popular, name=path.name)
    return [(url, mapping[raw], src) for (url, raw), src in zip(pairs, sources) if raw in mapping]


def summarise(rows: list[Row], popular: frozenset[str] | None = None) -> dict:
    """Counts and the path / scheme / popularity shares per class (the biases a trainer must know about)."""
    popular = load_popular() if popular is None else popular
    out: dict = {"rows": len(rows)}
    for name, lab in (("phishing", 1), ("legit", 0)):
        urls = [u for u, y, _ in rows if y == lab]
        out[name] = len(urls)
        if urls:
            n = len(urls)
            out[f"{name}_with_path_share"] = round(sum(map(has_path, urls)) / n, 4)
            out[f"{name}_https_share"] = round(sum(u.lower().startswith("https://") for u in urls) / n, 4)
            out[f"{name}_www_share"] = round(sum("://www." in u[:14].lower() for u in urls) / n, 4)
            out[f"{name}_top10k_host_share"] = round(sum(is_popular(host_of(u), popular) for u in urls) / n, 4)
            out[f"{name}_distinct_hosts"] = len({host_of(u) for u in urls})
    out["legit_rows_have_paths"] = out.get("legit_with_path_share", 0) > 0.05
    return out


def write_csv(rows: Iterable[Row], path: str | Path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "source"])
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Load a labelled URL dataset and print its summary.")
    ap.add_argument("path")
    ap.add_argument("--url-col")
    ap.add_argument("--label-col")
    ap.add_argument("--positive", help="comma-separated raw label values that mean phishing")
    ap.add_argument("--label", type=int, choices=(0, 1), help="label for a file without a label column")
    ap.add_argument("--out", help="write the normalised rows to this CSV")
    args = ap.parse_args()
    rows = load_labelled(args.path, args.url_col, args.label_col,
                         args.positive.split(",") if args.positive else None, label=args.label)
    print(json.dumps(summarise(rows), indent=1))
    for row in rows[:5]:
        print(row)
    if args.out:
        print(f"wrote {write_csv(rows, args.out)} rows to {args.out}")


if __name__ == "__main__":
    main()
