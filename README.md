# AI Threat Detection Engine

Real-time web attack detection: Nginx-style access logs go in, scored alerts come out
on a live dashboard. Regex rules catch known patterns; an ML ensemble catches what the
rules miss (evasive payloads, scanner recon).

**Status:** working end to end (Day 6 of 7). Next: widen attack coverage, retest.

![Live dashboard](docs/dashboard.png)

## Pipeline

## Results (synthetic dataset, 6000 rows, 25% held-out)

| Model | Precision | Recall | F1 |
|---|---|---|---|
| Rules only | 1.000 | 0.365 | 0.535 |
| Random Forest | 1.000 | 1.000 | 1.000 |
| Isolation Forest | 0.891 | 0.795 | 0.840 |
| **Ensemble (0.7 RF + 0.3 IF)** | 1.000 | 0.999 | 0.999 |

Recall by attack family (rules -> ensemble): classic 100% -> 100%, **evasive 0% -> 99.7%**,
**recon 0% -> 100%**. False positives on benign traffic: 0%.

**Unseen-family test:** a Random Forest trained without any evasive samples still catches
**74%** of them, which is the more honest generalization figure.

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.gen_dataset && python -m app.train
python -m app.stub_server            # target, writes logs/access.log
uvicorn app.api:app --port 8000      # engine + dashboard at http://localhost:8000
python -m app.sim 60                 # demo traffic
```

## Holdout evaluation (hand-written, outside the training templates)

24 requests written by hand: 12 benign, 12 attacks (`app/holdout_eval.py`).

| | Rules only | Rules + ML |
|---|---|---|
| Attacks detected | 4/12 (33%) | 8/12 (67%) |
| False positives | 0/12 | 1/12 |

**What it showed**
- The layers complement each other: a Windows path traversal was caught by rules only
  (ML scored 0.20), while `DROP TABLE` and a PHP stream wrapper were caught by ML only.
- Misses: WordPress plugin recon, Solr admin recon, NoSQL operator injection, open redirect.
  None of these families exist in the training generator.
- The one false positive was a percent-encoded `next=` parameter (score 0.52 vs a 0.5
  threshold); the benign training data had no percent-encoded values.

Real-world accuracy is expected to be closer to this table than to the synthetic one above.

## Limitations

- The dataset is synthetic and templated (`app/gen_dataset.py`), so near-perfect scores
  describe this distribution, not real-world traffic. Expect lower numbers on live logs.
- Alert storage is SQLite and fan-out is in-process; the `Store` class isolates the swap to
  Postgres/Redis.
- ONNX export is planned; models are currently served with joblib.
