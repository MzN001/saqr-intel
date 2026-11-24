# SAQR phishing URL model v2 — model card

Generated from `saqr/intel/data/model_metrics.json` (trained 2026-11-24T08:43:07Z, seed 20261124). Every number below is copied from that file; reproduce with:

```
.venv/bin/python tools/train_url_model.py --build-holdout   # fixed holdout sets + exclude list
.venv-train/bin/py -I tools/train_url_model.py              # train, pick thresholds, write the model
.venv/bin/python tools/evaluate.py --suite                  # model + end-to-end system on the holdout sets
```

## What it is

- Shipped stage: **ensemble** (2.0-ensemble), 2.51 MB of model files, pure-Python inference (no numpy at runtime).
- Stage 1: logistic regression over hashed character n-grams / tokens with separate host, path and query namespaces (2^19 int16 weights, `saqr/intel/url_model.bin`).
- Stage 2: LightGBM, 499 trees over 50 named features (`saqr/intel/url_features.py`) + the stage-1 score, exported to `saqr/intel/url_model_trees.json` and walked in Python. Per-feature contributions along the tree paths (Saabas) give the top 2-3 plain-language reasons shown to citizens (EN + AR).
- Input: the FULL URL. Scheme, `www.` and default ports are dropped (collection artefacts in public datasets).
- Used by `ai_inspector.intel_flags`: AI_PHISHING_URL / AI_SUSPICIOUS_URL. Official / trusted sites and Tranco top-100k sites off free hosting are never judged by the model.

## Training data

663,454 rows after canonical de-duplication (347,432 phishing). Rows per source:

| source | rows |
|---|---:|
| hf_phreshphish | 180,000 |
| tranco | 100,000 |
| phishing_database | 95,000 |
| phiusiil | 90,000 |
| hf_kmack + hf_ealvaradob (50,000 + 30,000 cap) | 80,000 |
| jpcert | 41,966 |
| phishing_army | 40,000 |
| synthetic | 13,015 |
| harvest_tranco | 8,840 |
| hf_ealvaradob_free_hosting | 7,688 |
| phiusiil+evasion | 4,426 |
| hf_kmack+evasion | 3,999 |
| hf_ealvaradob+evasion | 3,926 |
| hf_phreshphish+evasion | 3,807 |
| hf_phreshphish_lure_host | 3,078 |
| synthetic+evasion | 2,423 |
| phishing_database+evasion | 2,154 |
| phishing_army+evasion | 2,046 |
| hf_ealvaradob_free_hosting+evasion | 1,930 |
| hf_phreshphish_lure_host+evasion | 1,877 |
| harvest_tranco+evasion | 1,866 |
| hf_kmack_free_hosting | 869 |
| tranco_lure_host | 697 |
| hf_kmack_free_hosting+evasion | 522 |
| tranco_lure_host+evasion | 438 |
| hf_phreshphish_free_hosting | 356 |
| hf_ealvaradob_lure_host | 297 |
| hf_kmack_lure_host | 293 |
| hf_phreshphish_free_hosting+evasion | 199 |
| hf_ealvaradob_lure_host+evasion | 194 |
| hf_kmack_lure_host+evasion | 181 |
| phiusiil_lure_host | 29 |
| phiusiil_lure_host+evasion | 12 |

Bias handling: PhiUSIIL, Tranco, Phishing Army and Phishing.Database *domains* are trained as bare hosts (their legit side has no paths), so path / query evidence is learnt only from sources where both classes carry paths (PhreshPhish, kmack, ealvaradob, harvested deep links, Phishing.Database links, JPCERT). Synthetic rows weigh 0.3, evasion variants 0.5; classes are re-weighted to balance. URLs with both labels are dropped.

## Evaluation protocol

- **Grouped validation**: 10% of *sites* (registered domain, or full host on a free-hosting platform) by hash; no site is on both sides. Used for early stopping and thresholds.
- **Source-disjoint holdout**: the whole Hannousse & Yahiouche 2021 dataset (and its re-host) is never trained on.
- **Fresh phishing** (recall only): JPCERT 2026-08 + 2026-09, OpenPhish (today), PhishTank online-valid (today).
- **False-positive suite** (legit only): UAE official / bank / telecom deep links, global-brand official deep links, 20% of harvested Tranco deep links and legit free-hosting pages (by site hash), 6,000 Tranco long-tail homepages (ranks 100k-1M), 52 hand-picked bank / payment / government login pages.
- **Robustness**: evasion variants of the holdout URLs (letter case, added/removed www, explicit port, trailing-dot FQDN, scheme swap, extra slashes, percent-encoding, userinfo '@' prefix).
- Every site in these sets ({'fp_suite': 13727, 'fresh_phishing': 49371, 'hannousse': 11426, 'robustness': 23891}) is listed in `tools/holdout_sites.txt.gz` and removed from training; the exact URLs are in `datasets/holdout/*.csv` (rebuilt deterministically).
- Thresholds: on the legitimate URLs the server would actually let the model judge (validation + FP suite, 29,403 rows): certain = 0.1% of them reach it, strong = 0.5%, suspect = 2%. Shipped: certain 0.9899, strong 0.9614, suspect 0.8423.

## Model-level results (probability >= threshold)

### linear (thresholds certain 0.9873 / strong 0.9447 / suspect 0.8125)

| set | rows | phishing | P@strong | R@strong | F1@strong | FPR@strong | R@suspect | FPR@suspect | R@certain | FPR@certain |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| validation | 64,980 | 35,249 | 0.9936 | 0.6223 | 0.7653 | 0.0048 | 0.7574 | 0.0179 | 0.4549 | 0.0010 |
| fp_suite | 13,727 | 0 | 0 | n/a | n/a | 0.0140 | n/a | 0.0453 | n/a | 0.0020 |
| fresh_phishing | 49,371 | 49,371 | 1 | 0.5185 | 0.6829 | n/a | 0.6729 | n/a | 0.3220 | n/a |
| hannousse | 11,426 | 5,711 | 0.9828 | 0.5202 | 0.6803 | 0.0091 | 0.6822 | 0.0264 | 0.3371 | 0.0035 |
| robustness | 23,891 | 16,035 | 0.9916 | 0.5717 | 0.7253 | 0.0099 | 0.7219 | 0.0286 | 0.3859 | 0.0041 |

### ensemble (thresholds certain 0.9899 / strong 0.9614 / suspect 0.8423)

| set | rows | phishing | P@strong | R@strong | F1@strong | FPR@strong | R@suspect | FPR@suspect | R@certain | FPR@certain |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| validation | 64,980 | 35,249 | 0.9956 | 0.6817 | 0.8093 | 0.0036 | 0.7987 | 0.0153 | 0.5502 | 0.0004 |
| fp_suite | 13,727 | 0 | 0 | n/a | n/a | 0.0036 | n/a | 0.0136 | n/a | 0.0012 |
| fresh_phishing | 49,371 | 49,371 | 1 | 0.4283 | 0.5997 | n/a | 0.5474 | n/a | 0.3348 | n/a |
| hannousse | 11,426 | 5,711 | 0.9839 | 0.5467 | 0.7028 | 0.0089 | 0.7158 | 0.0248 | 0.3579 | 0.0017 |
| robustness | 23,891 | 16,035 | 0.9919 | 0.6002 | 0.7479 | 0.0101 | 0.7322 | 0.0257 | 0.4618 | 0.0023 |

Shipped: **ensemble** (it is shipped only if its holdout F1 at the strong threshold beats the linear stage alone).

## End-to-end offline system, before vs after

`analyze_lexical` + `run_rules(lex, {}, None, None)` (no network, no LLM, no threat feeds): what a scan decides before any page is fetched. Block = HIGH-RISK (>= 65), warn = SUSPICIOUS or worse (>= 30). Before = the v1 host-only model at commit HEAD of this branch.

| set | cut | before P | before R | before FPR | after P | after R | after FPR |
|---|---|---:|---:|---:|---:|---:|---:|
| fp_suite | block_65 | 0 | n/a | 0.0030 | 0 | n/a | 0.0009 |
| fp_suite | warn_30 | 0 | n/a | 0.1652 | 0 | n/a | 0.0078 |
| fresh_phishing | block_65 | 1 | 0.1077 | n/a | 1 | 0.1933 | n/a |
| fresh_phishing | warn_30 | 1 | 0.3120 | n/a | 1 | 0.4138 | n/a |
| hannousse | block_65 | 0.9919 | 0.1719 | 0.0014 | 0.9966 | 0.3119 | 0.0010 |
| hannousse | warn_30 | 0.8783 | 0.3183 | 0.0441 | 0.9871 | 0.5341 | 0.0070 |
| robustness | block_65 | 0.9955 | 0.1640 | 0.0015 | 0.9988 | 0.3529 | 0.0009 |
| robustness | warn_30 | 0.9129 | 0.3295 | 0.0642 | 0.9934 | 0.5566 | 0.0075 |

False-positive suite, after (system), by source:

| source | rows | warn (>=30) | block (>=65) |
|---|---:|---:|---:|
| harvest_uae_official | 1,046 | 0 (before 0) | 0 (before 0) |
| harvest_brand_official | 2,081 | 0 (before 0) | 0 (before 0) |
| harvest_tranco | 2,242 | 0 (before 0) | 0 (before 0) |
| hf_ealvaradob_free_hosting | 1,977 | 12 (before 1884) | 1 (before 3) |
| hf_kmack_free_hosting | 220 | 9 (before 212) | 1 (before 2) |
| hf_phreshphish_free_hosting | 107 | 29 (before 102) | 0 (before 21) |
| tranco_longtail | 6,000 | 57 (before 69) | 11 (before 15) |
| fp_extra_bank_gov | 52 | 0 (before 0) | 0 (before 0) |
## Known weaknesses (measured, not fixed)

- Recall is limited by design: thresholds allow at most 0.5% (strong) / 2% (suspect) of judged legitimate URLs to be flagged, so about half of the holdout phishing URLs score below the strong threshold. Most misses are pages on big shared platforms (sites.google.com, blogspot, Google Forms, docs/file shares) and compromised old websites whose address looks ordinary; the page content checks (sandbox), DNS/WHOIS age and threat feeds have to catch those.
- On today's fresh feeds the linear stage alone recalls more than the ensemble at its own strong threshold (see the model-level tables): the ensemble was chosen on the source-disjoint holdout F1, not on fresh recall.
- Free-hosting legit pages remain the hardest legit group (the PhreshPhish free-hosting benign rows have the highest false-alarm share in the FP suite); dataset "legit" labels there are also noisy.
- Tranco long-tail sites on cheap TLDs (.top, .xyz, .cyou ...) account for most remaining system false alarms at the block level (the model's flag + SUSPICIOUS_TLD corroboration).
- Popular (Tranco top-100k) sites are never judged by the model off free hosting, so phishing on a compromised popular site is invisible to it.
- PhiUSIIL / ealvaradob / kmack are older crawls; the holdout (2020) is older than the fresh feeds (2026). Numbers on the judges' hidden set may differ.

## Tools

- `tools/evaluate.py <file> [--url-col --label-col --positive --label] [--mode model|system|live] [--threshold] [--out report.json]`: any dataset; precision / recall / F1 / FPR / accuracy, confusion matrix, PR points, 20 worst false positives / negatives with reasons. `live` runs the full pipeline against a throw-away database with NextDNS / push keys blanked and no graph ingestion.
- `tools/predict.py urls.txt|csv -o predictions.csv [--label-at warn|block]`: url, label, score, verdict, model_probability, reasons for an unlabelled list (default label cut: warn = score >= 30).
- `GET /api/model/metrics`: the stored metrics JSON (model, datasets, holdout, fresh phishing, FP suite, system before/after, thresholds).
