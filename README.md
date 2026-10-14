# AI Threat Detection Engine

Real-time web attack detection: Nginx-style access logs go in, scored alerts come out
on a live dashboard. Regex rules catch known patterns; an ML ensemble catches what the
rules miss (evasive payloads, scanner recon).

**Status:** working end to end (Day 5 of 7). Next: screenshots, Wazuh integration notes.

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

## Limitations

- The dataset is synthetic and templated (`app/gen_dataset.py`), so near-perfect scores
  describe this distribution, not real-world traffic. Expect lower numbers on live logs.
- Alert storage is SQLite and fan-out is in-process; the `Store` class isolates the swap to
  Postgres/Redis.
- ONNX export is planned; models are currently served with joblib.
