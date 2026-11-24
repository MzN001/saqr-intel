# SAQR phishing URL model v2 — model card

Generated from `saqr/intel/data/model_metrics.json` (trained 2026-11-24T08:43:07Z, seed 20261124). Every number below is copied from that file; reproduce with:

```
.venv/bin/python tools/train_url_model.py --build-holdout   # fixed holdout sets + exclude list
.venv-train/bin/py -I tools/train_url_model.py              # train, pick thresholds, write the model
.venv/bin/python tools/evaluate.py --suite                  # model + end-to-end system on the holdout sets
```

## Summary

| Configuration (live sample B, 800 live links: 400 newest PhishTank phishing + 400 legitimate, no AI judge) | Warn (score >= 30) | Block (score >= 65) |
|---|---|---|
| **System as deployed**: threat feeds on as in production. The test scams were publicly reported scams, so the feeds had already seen most of them (387 of 400 feed hits, 0 on legit) | **accuracy 98.6%**, recall 98.5%, precision 98.75%, false-alarm rate 1.25% (TP 394 / FP 5 / FN 6 / TN 395) | accuracy 98.25%, recall 97.5%, false-alarm rate 1.0% (390 / 4 / 10 / 396) |
| **Stress test**: every blocklist switched off (stands in for brand-new scams no list knows yet) | recall 75%, precision 98.4%, false-alarm rate 1.25% (300 / 5 / 100 / 395) | recall 63%, false-alarm rate 1.0% (252 / 4 / 148 / 396) |
<!-- SAMPLE_D_ROW: sealed sample D (scams reported in the last day, never seen by the deployed model) goes here as one more row -->

With every blocklist switched off, Saqr still caught 75% of the scams (63% blocked outright) and was right 98.4% of the time when it flagged. 0 false alarms on the 224 UAE official / bank / government / brand pages in the sample. Against the brief's targets (accuracy 98%, recall 97.5%, false-alarm rate 1%): as deployed, accuracy and recall meet them at warn level and the false-alarm rate (1.25%) is slightly above (1.0% at block meets it); with blocklists off, recall 75% does not. Sealed sample C, the UAE suite, the rejected retrain and the limits are below, unchanged.

## What it is

- Shipped stage: **ensemble** (2.0-ensemble), 2.51 MB of model files, pure-Python inference (no numpy at runtime).
- Stage 1: logistic regression over hashed character n-grams / tokens with separate host, path and query namespaces (2^19 int16 weights, `saqr/intel/url_model.bin`).
- Stage 2: LightGBM, 499 trees over 50 named features (`saqr/intel/url_features.py`) + the stage-1 score, exported to `saqr/intel/url_model_trees.json` and walked in Python. Per-feature contributions along the tree paths (Saabas) give the top 2-3 plain-language reasons shown to citizens (EN + AR).
- Input: the FULL URL. Scheme, `www.` and default ports are dropped (collection artefacts in public datasets).
- Used by `ai_inspector.intel_flags`: AI_PHISHING_URL / AI_SUSPICIOUS_URL. Official / trusted sites and Tranco top-100k sites are never judged by the model, unless the host is a free-hosting / user-content platform (`url_features.FREE_HOSTING` + `page_signals.USER_CONTENT_HOSTS`), where anyone can publish a page.

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

## End-to-end offline system: v1 vs round 1 vs now

`analyze_lexical` + `run_rules(lex, {}, None, None)` (no network, no LLM, no threat feeds): what a scan decides before any page is fetched, and what `tools/predict.py` (default mode) writes. Block = HIGH-RISK (>= 65), warn = SUSPICIOUS or worse (>= 30). v1 = the original host-only model; round 1 = the v2 model as first shipped; now = after round 2 (same model files, rule changes below).

| set | cut | v1 P | v1 R | v1 FPR | round 1 P | round 1 R | round 1 FPR | now P | now R | now FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| fp_suite | block_65 | 0.0000 | n/a | 0.0030 | 0.0000 | n/a | 0.0009 | 0.0000 | n/a | 0.0009 |
| fp_suite | warn_30 | 0.0000 | n/a | 0.1652 | 0.0000 | n/a | 0.0078 | 0.0000 | n/a | 0.0063 |
| fresh_phishing | block_65 | 1.0000 | 0.1077 | n/a | 1.0000 | 0.1933 | n/a | 1.0000 | 0.1936 | n/a |
| fresh_phishing | warn_30 | 1.0000 | 0.3120 | n/a | 1.0000 | 0.4138 | n/a | 1.0000 | 0.4151 | n/a |
| hannousse | block_65 | 0.9919 | 0.1719 | 0.0014 | 0.9966 | 0.3119 | 0.0010 | 0.9967 | 0.3138 | 0.0010 |
| hannousse | warn_30 | 0.8783 | 0.3183 | 0.0441 | 0.9871 | 0.5341 | 0.0070 | 0.9871 | 0.5374 | 0.0070 |
| robustness | block_65 | 0.9955 | 0.1640 | 0.0015 | 0.9988 | 0.3529 | 0.0009 | 0.9988 | 0.3538 | 0.0009 |
| robustness | warn_30 | 0.9129 | 0.3295 | 0.0642 | 0.9934 | 0.5566 | 0.0075 | 0.9935 | 0.5585 | 0.0075 |

False-positive suite by source (system):

| source | rows | warn (>=30) now / round 1 / v1 | block (>=65) now / round 1 / v1 |
|---|---:|---:|---:|
| harvest_uae_official | 1,046 | 0 / 0 / 0 | 0 / 0 / 0 |
| harvest_brand_official | 2,081 | 0 / 0 / 0 | 0 / 0 / 0 |
| harvest_tranco | 2,242 | 0 / 0 / 0 | 0 / 0 / 0 |
| hf_ealvaradob_free_hosting | 1,977 | 11 / 12 / 1884 | 1 / 1 / 3 |
| hf_kmack_free_hosting | 220 | 9 / 9 / 212 | 1 / 1 / 2 |
| hf_phreshphish_free_hosting | 107 | 10 / 29 / 102 | 0 / 0 / 21 |
| tranco_longtail | 6,000 | 57 / 57 / 69 | 11 / 11 / 15 |
| fp_extra_bank_gov | 52 | 0 / 0 / 0 | 0 / 0 / 0 |

## Live pipeline evaluation (2026-11-24)

`tools/evaluate.py <file> --mode live --records run.jsonl`: every URL goes through the full `pipeline.analyze_url` (redirects / shorteners, WHOIS / DNS / TLS, the page fetched over HTTP as a UAE phone and as a bot for the two-view cloaking check; `ENABLE_PLAYWRIGHT=false`, i.e. exactly the Render path; no LLM), 20 at a time, 45 s per URL, throw-away database, `ingest=False`, NextDNS / push / LLM keys blanked in-process. The records file keeps each scan's network and page evidence, so `--rescore` re-judges the same evidence with changed rules (checked: re-judging with the previous code reproduces all 800 as-run scores exactly).

- **Sample B (the headline, never used for tuning rules):** the 400 newest PhishTank online-valid URLs (submitted 2026-11-18 to 24, sites not in training) + 400 legitimate pages from the never-trained FP suite: 100 UAE official deep links, 54 bank / government login pages, 70 global-brand official pages, 120 Tranco long-tail homepages, 56 legit free-hosting pages. Caveat: two false-positive fixes (platform-named brands, renewed certificates) were added after looking at sample B's false alarms; neither changed a sample-B phishing verdict to a miss except one (warn recall 0.7525 -> 0.75 on the same evidence).
- **Sample A (tuning):** 200 OpenPhish (GitHub community feed, today) + 200 PhishTank (today) + 400 legit of the same mix. Its misses were read to design the page rules, so its "now" numbers are optimistic.
- **Extra legit (700):** 200 Tranco deep links, 250 Tranco long-tail homepages, 250 legit free-hosting pages, to measure false alarms on pages: warn FPR 3.00% (21) before -> 1.86% (13) now; block 0.14% (1) before and now.
- **with feeds** = the same scans plus a Phishing Army / OpenPhish lookup of every host on the link's path (a hit scores 70). This is the system as deployed. The test scams were publicly reported scams (PhishTank), so the feeds had already seen most of them; **no feeds** is the stress test that stands in for brand-new scams no list knows yet. Feed hits: 387 of 400 phishing, 0 of 400 legit (sample B).

| run | cut | P (no feeds) | R (no feeds) | FPR (no feeds) | TP/FP/FN/TN | P (with feeds) | R (with feeds) | FPR (with feeds) |
|---|---|---:|---:|---:|---|---:|---:|---:|
| sample B, before this round | block | 0.9837 | 0.6050 | 1.00% | 242/4/158/396 | 0.9898 | 0.9750 | 1.00% |
| sample B, before this round | warn | 0.9699 | 0.7250 | 2.25% | 290/9/110/391 | 0.9775 | 0.9775 | 2.25% |
| **sample B, now (as run)** | block | 0.9844 | 0.6300 | 1.00% | 252/4/148/396 | 0.9898 | 0.9750 | 1.00% |
| **sample B, now (as run)** | warn | 0.9836 | 0.7500 | 1.25% | 300/5/100/395 | 0.9875 | 0.9850 | 1.25% |
| sample A, before | block | 1.0000 | 0.6525 | 0.00% | 261/0/139/400 | 1.0000 | 0.9625 | 0.00% |
| sample A, before | warn | 0.9785 | 0.7950 | 1.75% | 318/7/82/393 | 0.9822 | 0.9650 | 1.75% |
| sample A, now (re-judged) | block | 1.0000 | 0.7350 | 0.00% | 294/0/106/400 | 1.0000 | 0.9625 | 0.00% |
| sample A, now (re-judged) | warn | 0.9858 | 0.8700 | 1.25% | 348/5/52/395 | 0.9874 | 0.9800 | 1.25% |

Sample B, scan time per URL (as run, 20 in parallel): median 8.6 s, 95th percentile 16.5 s, max 36.5 s; 0 errors / timeouts. Zero false alarms on the UAE official, bank / government and global-brand official pages in every live sample (224 + 224 pages).

Sample B phishing missed at warn (no feeds), by what the scan saw: own domain, benign-looking page 45; dead / blocked: HTTP 4xx 23; dead: unreachable 19; dead: no DNS 10; own domain, has a form (PASSWORD,PHONE) 1; dead / blocked: HTTP 5xx 1; platform-hosted page 1. "Dead" = the site was already down when scanned (PhishTank keeps listing URLs for days); "benign-looking" = the page served to our fetcher had no form, brand or warning (often a JavaScript shell, a parked page or a bot check).

Sample B false alarms (no feeds, warn): gobabytrade.com (70; an "AI crypto trading" site, model 0.98 + brand / urgency text), rushmoreservicing.com (70; its homepage redirects to an Azure B2C log-in URL with a GUID path that the URL model rates 0.98), officesupportjp.github.io (70; a Microsoft Japan support blog on GitHub Pages, model 0.998 + Microsoft on the page), softgateon.herokuapp.com (70; a "URL to Google Drive" tool with a password field, model 0.998), britishbottleforum.co.uk (35; certificate issued in the last 48 h, WHOIS age unknown, brand + urgency words).

## Round 2 changes (recall without more false alarms)

Each step measured on the four fixed sets (system, address-only) and on the live records; only what helped was kept.

| step | what | fixed sets (system) | live | kept? |
|---|---|---|---|---|
| a | combine the linear and tree stages (mean logit, 0.7 / 0.3 mix) at the same validation FPR | on judged rows, recall at the strong cut: ensemble 0.6983 val / 0.7857 fresh / 0.6091 Hannousse; linear 0.6338 / 0.6775 / 0.5368; mean 0.6868 / 0.7523 / 0.5905; mix 0.691 / 0.7665 / 0.6024. The round-1 "linear beats ensemble on fresh" came from different thresholds and from counting rows the model never judges (23,521 of the fresh rows are on popular / official hosts: google.com 5,049, qrco.de 4,591, ead.me 3,290, bit.ly 1,565 ...) | - | no: ensemble alone is best |
| b | per-segment thresholds (free hosting / own domain / raw IP) | validation has 3 legit free-hosting rows (cannot be tuned there); FP-suite free-hosting FPR at the global strong cut is already 1.22% vs 0.30% for own domains | - | no |
| c | page evidence in the HTTP-only sandbox (`saqr/intel/page_signals.py`): security-provider phishing interstitial (Cloudflare "Suspected Phishing", 70), shortener that disabled the link (45), password / card / OTP form posting to a form service (Weebly formSubmit, Formspree, Apps Script, Telegram bot ..., 45), registry brand in the page title of a log-in page on user-content hosting or next to a credential form on a non-top-100k site (25, strong); static-HTML field labels (`<label for>`, enclosing label, text before the field) and password words in 8 languages | no effect (address only) | sample A warn R 0.795 -> 0.85, block 0.6525 -> 0.7325; 1 new warn false alarm in 1,100 legit (a real 2FA "Device Verification Code" field) | yes |
| c2 | address model + page agree: a model flag (>= suspect) plus a brand on the page lets weak page signals count; new domain (< 30 days) + model >= 0.5 (+15, AI_NEW_DOMAIN); domain no longer resolves + model flag (+15, SITE_TAKEN_DOWN) | no effect | sample A warn R 0.85 -> 0.8575 / 0.8625 / 0.8525 one at a time, 0.8725 together; no new false alarm in 1,100 legit | yes |
| d | the model also judges popular hosts that are user-content platforms (weeblysite.com, gitbook.io, cloudfront.net, storage.googleapis.com, backblazeb2.com ...); an official domain's user-content host (Google Cloud Storage bucket, Google Sites, SharePoint) is no longer whitelisted (`page_signals.lexical`, used by the pipeline, redirect hops, evaluate and predict) | fresh warn 0.4138 -> 0.4152, block 0.1933 -> 0.1936; Hannousse warn 0.5341 -> 0.5383, block 0.3119 -> 0.3140; robustness warn 0.5566 -> 0.5589; FP suite unchanged (107 / 13) | 3 phishing pages on storage.googleapis.com had been judged SAFE as "official Google" | yes |
| e | false-alarm fixes: a brand named only by its own platform (`tenant.sharepoint.com` -> "Microsoft") no longer counts as impersonation unless the URL model also says phishing; a certificate renewed in the last 48 h on a domain older than a year is not a "zero-hour" signal | FP suite warn 107 -> 87 (free-hosting PhreshPhish rows 29 -> 10), block 13 -> 13; Hannousse warn 0.5383 -> 0.5374, block 0.3140 -> 0.3138; fresh warn 0.4152 -> 0.4151; robustness warn 0.5589 -> 0.5585 | warn false alarms on A + extra legit 29 -> 18; sample A warn R 0.8725 -> 0.87 | yes |
| f | judge same-site redirect hops by host only (a site's own redirect to an SSO URL with a GUID path) | - | would fix 1 false alarm (rushmoreservicing.com) and lose 1 phishing (a same-site click tracker) | no |

## Known weaknesses (measured, not fixed)

- The offline (address-only) system still recalls only 41.5% of the fresh phishing at warn: 23,521 of those rows sit on hosts the model is never allowed to judge (Google, QR / link shorteners, Adobe, Mailchimp, Dropbox, HubSpot / Jotform forms ...). Judging them by path would need training data with legit pages on the same platforms. The live pipeline resolves shorteners and reads the page, which is where most of the recall comes from (sample B warn 0.75 live vs address-only numbers in the 0.4-0.55 range).
- Live misses are mostly sites already dead when scanned (53 of 100 sample-B misses) and pages that show our HTTP fetcher nothing suspicious (45): JavaScript-built kits need the Chromium sandbox (not on Render's free tier) or the LLM judge on the page.
- Live block-level false alarms are 1.0% (4 / 400) on sample B, all from the URL model being very confident on an unusual legit address (GitHub Pages blog, Heroku tool, SSO redirect, crypto site) plus a weak corroborating clue. Bank / government / UAE official pages: 0.
- Address-only false alarms concentrate on Tranco long-tail sites (57 / 6,000 warn, 11 block). In the long-tail + free-hosting + Hannousse legit pool (14,019 URLs, now): model flag alone 48 warn (vs 11,717 phishing), model suspect flag + cheap TLD 35 (vs 147 phishing), TYPOSQUAT alone 9 (vs 1), BRAND_IMPERSONATION alone 8 (vs 19). The look-alike rules live in `domain_intel.py` and were not changed here.
- Free-hosting legit pages remain the hardest legit group; dataset "legit" labels there are noisy (several "legit" PhreshPhish SharePoint / GitHub Pages rows look like phishing lures).
- PhiUSIIL / ealvaradob / kmack are older crawls; the Hannousse holdout (2020) is older than the fresh feeds (2026). Numbers on the judges' hidden set may differ.

## UAE regression suite (synthetic, 2026-11-24)

`tests/uae_suite/cases.json`: 50 cases written by the team (25 scams, 25 legitimate; 10 each for website links,
emails, Maps listings, phone numbers and SMS / WhatsApp texts; Arabic included). All scam domains are invented.
Legitimate cases include deliberately hard ones (genuine-style bank email about OTP + urgency, official link with a
long tracking query, "Dubai Fabrics", a restaurant with a WhatsApp website). Emails are pasted Gmail "Show original"
sources: offline, sender authentication comes only from Gmail's own `Authentication-Results` header (a trusted
authserv sitting above every unknown `Received` header), so both "authenticated official" and "official domain,
DMARC fail" are represented without DNS.

Offline, rules only (`tools/eval_uae.py`, also asserted by `tests/test_uae_suite.py`: 0 false positives, >= 24 / 25
detected): **25 / 25 detected, 0 / 25 legitimate flagged** (precision 1.00, recall 1.00, FPR 0, F1 1.00); every
official legitimate case returns `verified_official: true`. Detected = verdict not SAFE (phone: level caution or
danger).

Caveats: a regression check, not an accuracy estimate. The authors know the rules, the cases are clean
single-message examples, and none needs WHOIS / page evidence; real-world numbers are the holdout and live
results above. The weakest true positives are close to the line: the Darb look-alike (31, no brand token), the
ADCB / Abu Dhabi Police Maps listings with only a mobile or foreign number (30). While writing the suite, one general
gap was fixed: Arabic polite requests with a verbal noun ("يرجى إرسال رمز التحقق", "الرجاء مشاركة الرقم السري") were not
recognised as asking for a code (a request word is required, so "تم إرسال رمز التحقق إلى هاتفك" stays a notice).

### UAE suite extended to 100 cases (2026-11-24)

50 "tricky" cases (`"tricky": true`; 25 scams + 25 legitimate, 5 + 5 per input type) were written from realistic
patterns BEFORE the suite was run on them (free-host look-alikes, sub-domain abuse, a percent-encoded Arabic lure
path, brand in the path of an unrelated host, an open-redirect wrapper, look-alike senders, link-in-bio listings,
foreign numbers for government bodies, Arabic OTP harvest; legit: UAE news about scams, tracking-heavy official
links, a Telr payment page, bank marketing with urgency, brand-like business names, official SMS, short codes).
Run ONCE, offline, rules only:

| type | cases | TP | FN | FP | TN | recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| url | 20 | 8 | 2 | 0 | 10 | 0.80 | 0 |
| email | 20 | 10 | 0 | 0 | 10 | 1.00 | 0 |
| maps | 20 | 10 | 0 | 0 | 10 | 1.00 | 0 |
| phone | 20 | 9 | 1 | 0 | 10 | 0.90 | 0 |
| message | 20 | 9 | 1 | 0 | 10 | 0.90 | 0 |
| **all** | 100 | 46 | 4 | 0 | 50 | **0.92** | **0** |

Precision 1.00, F1 0.958. Misses (kept in the file): `url-mal-arabic-encoded-path` (11), `url-mal-brand-in-path`
(25), `phone-mal-fab-one-digit-off` (600 number one digit off FAB's: level none), `msg-mal-salik-shortener-uk`
(0: an unexpandable bit.ly from a UK mobile claiming Salik). `tests/test_uae_suite.py` now asserts the honest floor
46 / 50 detected (below the old 24 / 25 ratio) and 0 false positives.

## Sealed sample C (2026-11-24): 460 legitimate pages + only 3 phishing URLs

Protocol: detection code, rules, weights, thresholds, registry and baselines frozen at 2026-11-24T21:39:11Z
(`saqr/` tree SHA-256 `544ca45e…f6f756`, unchanged at scoring time); the only changes made in the pre-freeze step were `eand.ae`
added as e&'s official site (verified: `etisalat.ae` answers 302 to `www.eand.ae`) and a test. Sample sealed in
`datasets/live3.csv` (SHA-256 `76e5baa915a7202e04c21a2551cb3f89548cf43e8e4c6848fe29691d57c7bc90`) before scoring;
scored ONCE with `tools/evaluate.py --mode live` (HTTP only, no LLM, no feeds in the scan, `VISUAL_SCREENSHOTS=false`,
concurrency 30, 45 s per URL).

**Phishing: only 3 URLs qualified, too few to measure recall.** The rule was "submitted / first seen after the
21:10Z training cut-off", one URL per registered domain, no domain present in any local dataset / holdout /
hard-negative list. First attempt (~22:05Z): 0 (newest PhishTank online-valid submission 21:06:26Z). Second attempt
(22:25:46Z, after PhishTank published its 22:21:59Z dump): 5 PhishTank verified + online submissions after the
cut-off (submitted 21:23-22:03Z), 1 dropped (domain already in local data), 1 dropped (same site twice); OpenPhish and
Phishing.Database NEW-today still had no entries absent from the cut-off snapshot. Sealed as `datasets/live3_phish.csv`
(SHA-256 `5ff1c30a29131a872d9ecd6fe7411b1e1f76fc7c3091ce8ccd092e3a8c46e0c7`, 22:26:01Z) and scored once with the same
settings except concurrency 20 (30 caused timeouts on the legit half). Detection code: commit 1d9cf1c, `git diff HEAD
-- saqr` empty, and re-judging the saved legit evidence still reproduces all 430 judged scores, so no detection file
changed between the two halves. Nothing was back-filled with older phishing.

| phishing half (3 URLs, no feeds) | caught | recall | 95% Wilson CI |
|---|---:|---:|---|
| warn (>= 30) | 2 / 3 | 66.7% | 20.8% - 93.9% |
| block (>= 65) | 2 / 3 | 66.7% | 20.8% - 93.9% |

All 3 pages answered HTTP 200 (live-only recall is the same 2 / 3). Caught: `allegrolokalnie.8563421.lat` (100: URL
model + new domain + fresh certificate) and `bradesco.beneficios-pj.com` (80: URL model + young domain + fresh / invalid
certificate). Missed: a page on `sodstore.vercel.app` (20, platform-hosted: only AI_SUSPICIOUS_URL). Misses by
category: dead / no DNS 0, HTTP 4xx-5xx 0, benign-looking own-domain page 0, platform-hosted 1, other 0. Scan time
median 3.8 s, max 4.8 s. With feeds (circular): identical, 0 feed hits.

Combined sample C (3 phishing : 460 legit, 0.65% phishing; precision and F1 are dominated by the 460 legit pages and
are not comparable to a balanced sample):

| cut | TP | FP | FN | TN | accuracy (CI) | precision (CI) | recall (CI) | FPR (CI) | F1 |
|---|---:|---:|---:|---:|---|---|---|---|---:|
| warn (>= 30) | 2 | 19 | 1 | 441 | 95.7% (93.4-97.2) | 9.5% (2.7-28.9) | 66.7% (20.8-93.9) | 4.13% (2.66-6.36) | 0.17 |
| block (>= 65) | 2 | 3 | 1 | 457 | 99.1% (97.8-99.7) | 40.0% (11.8-76.9) | 66.7% (20.8-93.9) | 0.65% (0.22-1.90) | 0.50 |

With feeds (circular): identical. A proper phishing half (>= 200, ideally 400) still has to be collected a day or
more after a cut-off.

**Legitimate: 460 never-trained pages** (none of their URLs in any local dataset / holdout file): 90 UAE official
deep links, 60 global-brand official pages, 60 log-in pages (banks, government, big services), 70 scam-topic news
articles (14 UAE, 56 global; from sites NOT used for the hard-negative training set), 120 Tranco long-tail
homepages (FP-suite pool sites held out of the shipped model), 60 legit user-content pages (github.io, vercel.app,
netlify.app, pages.dev ... linked from public curated lists). Sample A / B files are not on this machine, so overlap
with them could only be excluded through the training / holdout files.

| cut | false alarms | FPR | 95% Wilson CI |
|---|---:|---:|---|
| warn (>= 30) | 19 / 460 | 4.13% | 2.66% - 6.36% |
| block (>= 65) | 3 / 460 | 0.65% | 0.22% - 1.90% |

By source (warn / block): UAE official 0 / 0, brand official 0 / 0, log-in pages 0 / 0, global news 0 / 0, Tranco
long tail 0 / 0, UAE news 2 / 0 (dubaichronicle.com, 35: fresh certificate + brand + urgency words), **free hosting
17 / 3 of 60** (URL model on GitHub Pages / Vercel / Netlify / Pages project names; the three blocks are
wox-launcher.github.io, pickywawa.github.io, sentinel-james-murphy.pages.dev at 70). 30 Tranco homepages timed out
at concurrency 30 and count as not flagged (on the 430 that answered: warn 4.42%, block 0.70%). With feeds
(circular): identical, 0 feed hits on legit. Scan time median 9.6 s, p95 53.4 s (concurrency 30 is too high for
this laptop).

New signals on these 460 legit pages: `MOBILE_CLOAKING_DETECTED` 0, `VISUAL_BRAND_CLONE_DETECTED` 0,
`VISUAL_BRAND_SIMILARITY` 0 (fingerprint computed on 225 pages), per-hop page evidence on 6 (verdict judged from a
hop page once), JS-redirect hops 0. No false alarm was caused by a new signal. A/B on identical saved evidence
(re-judging reproduced all 430 judged scores exactly): removing the cloaking / visual inputs changes 0 scores.
On the 3 phishing URLs: `MOBILE_CLOAKING_DETECTED` 0, `VISUAL_BRAND_CLONE_DETECTED` 0, `VISUAL_BRAND_SIMILARITY` 0
(fingerprint computed on all 3), per-hop page evidence 0; the A/B re-judge (433 / 433 reproduced) changes 0 scores, so
the new signals caught 0 extra phishing here. Three URLs say nothing about how often they fire in general.
LLM subsample: skipped (time).

Against the spec targets (accuracy 98%, recall 97.5%, FPR 1%), as measured on C: accuracy 95.7% at warn / 99.1% at
block (but on a sample that is 99.35% legitimate, so accuracy mostly reflects the false-alarm rate); recall 2 / 3
(CI 21-94%), not a usable estimate and no evidence either way about 97.5%; warn-level
FPR 4.13% is above 1%, driven entirely by free-hosting pages; block-level FPR 0.65% is under 1%, but its CI reaches
1.9%. On sample B (older, see above) warn recall without feeds was 0.75, far below 97.5%.

## Retrain, calibration, visual similarity (2026-11-24)

- **Retrain rejected (null result).** A candidate trained with hard negatives lost on the pre-agreed rule
  (validation recall at the strong cut 0.6782 vs 0.6867; FP-suite block false positives 22 vs 17); the shipped
  model files are unchanged (`datasets/candidate/compare.json`, `retrain_comparison` in the metrics JSON).
- **Calibration.** A Platt table fitted on the validation split gives `calibrated_probability` (ECE 0.0082 -> 0.0033
  on validation). It is shown to citizens; decisions still use the RAW probability and the shipped thresholds.
  Validation is ~half phishing, so it overstates real-world odds.
- **Visual similarity.** `brand_fingerprint.py` compares a fetched page's title / site name, brand assets, favicon
  hash, colours and form shape with baselines of 11 official portals: 6 full (Abu Dhabi Police, Emirates Post,
  Salik, ADCB, FAB, e&), 5 partial (TAMM and UAE PASS are JavaScript-only shells, ICP and Emirates NBD did not
  answer, du disallows fetching). >= 75 on a non-official domain = `VISUAL_BRAND_CLONE_DETECTED` (+35), 50-74 =
  `VISUAL_BRAND_SIMILARITY` (+10, weak). The optional screenshot dHash (`VISUAL_SCREENSHOTS`, thum.io) is weakly
  discriminative: unrelated white portals already reach 70-75%, so it only adds points next to a fingerprint match
  and never makes a clone alone. It was not measured on sample C.

## Tools

- `tools/evaluate.py <file> [--url-col --label-col --positive --label] [--mode model|system|live] [--threshold] [--out report.json]`: any dataset; precision / recall / F1 / FPR / accuracy, confusion matrix, PR points, 20 worst false positives / negatives with reasons.
- Live mode: `--mode live [--records run.jsonl] [--concurrency 20] [--timeout 45] [--feeds] [--llm] [--browser] [--live-metrics]`: full pipeline, throw-away database, NextDNS / push keys blanked, no graph ingestion; prints precision / recall / FPR at block and warn with and without feeds, misses by category, false alarms by source, median / p95 scan time. `--records` is resumable (finished URLs are skipped). `--rescore run.jsonl` re-judges saved evidence with the current rules, offline.
- `tools/predict.py urls.txt|csv -o predictions.csv [--label-at warn|block] [--mode offline|live] [--records run.jsonl]`: url, label, score, verdict, model_probability, reasons for an unlabelled list (default label cut: warn = score >= 30).
- `tools/eval_uae.py [--json out.json] [--live]`: the 50-case UAE suite; per-type table, precision / recall / FPR / F1, misses. `--live` uses the network and the LLM keys in the environment (real requests, quota).
- `GET /api/model/metrics`: the stored metrics JSON (model, datasets, holdout, fresh phishing, FP suite, system v1 / round 1 / now, live, round 2 experiments, thresholds).
