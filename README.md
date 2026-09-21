# 🛡️ Phishing URL Detection System

> **TCS-332** · An end-to-end machine learning system that classifies URLs as **Phishing** or **Legitimate** using a 60-feature lexical, structural, and network analysis pipeline powered by a tuned **LightGBM** classifier.

---

## 📊 Model Performance

| Metric | Score |
| :--- | :---: |
| **Accuracy** | 97.28% |
| **Precision** | 95.95% |
| **Recall** | 96.28% |
| **F1-Score** | 96.11% |
| **ROC-AUC** | 0.9959 |
| **PR-AUC** | 0.9928 |
| **Inference Time** | ~0.018 ms / URL |

---

## 📁 Project Structure

```text
TCS-332/
├── model/
│   └── url_phishing_bundle.joblib   # Serialized LightGBM model + StandardScaler + metadata
├── phishing_detector.py             # Core detection engine & 60-feature extractor
├── interact.py                      # Interactive terminal CLI & batch evaluator
├── example.py                       # Runnable Python API usage examples
├── train.ipynb                      # Model training & experimentation notebook
├── requirements.txt                 # Python package dependencies
└── .gitignore                       # Git ignore rules for venvs and caches
```

---

## ⚙️ Installation

### Prerequisites

- Python **3.9** or higher
- macOS users: LightGBM requires OpenMP — install it first:
  ```bash
  brew install libomp
  ```

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ravi9680/TCS-332.git
   cd TCS-332
   ```

2. **Create and activate a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate        # macOS / Linux
   # .venv\Scripts\activate         # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies

| Package | Version | Purpose |
| :--- | :--- | :--- |
| `lightgbm` | ≥ 4.0.0 | Gradient boosting classifier |
| `scikit-learn` | ≥ 1.3.0 | Preprocessing (StandardScaler) |
| `joblib` | ≥ 1.3.0 | Model bundle serialization |
| `tldextract` | ≥ 5.0.0 | Accurate domain/TLD parsing |
| `pandas` | ≥ 2.0.0 | Batch result DataFrames |
| `numpy` | ≥ 1.24.0 | Vectorized feature arrays |

---

## 🚀 Usage

### 1. Python API

```python
from phishing_detector import PhishingDetector

# Load the model (auto-discovers the bundle in the model/ directory)
detector = PhishingDetector()

# ── Single URL Prediction ──────────────────────────────────────────────────
result = detector.predict("http://paypal-verification-account-security-update.com/login.php?cmd=login")

print("Verdict:        ", result["prediction"])             # 'Phishing' or 'Legitimate'
print("Threat Level:   ", result["threat_level"])           # 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL'
print("Phishing Prob:  ", f"{result['phishing_probability']:.2%}")
print("Risk Score:     ", f"{result['risk_score']} / 100")
print("Key Indicators: ", result["key_indicators"])

# ── Batch Prediction ───────────────────────────────────────────────────────
urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "http://chase-security-login.servehttp.com/account",
]
df = detector.predict_batch(urls)
print(df)

# ── High-Performance Batch (single model call) ─────────────────────────────
df_fast = detector.predict_batch_fast(urls)
print(df_fast)

# ── Feature Inspection ─────────────────────────────────────────────────────
features = detector.extract_features("https://www.google.com")
print(features)   # dict of 60 numeric features

# ── Live DNS & Latency Analysis ────────────────────────────────────────────
result_live = detector.predict("https://example.com", live_lookup=True)
print(result_live["features"]["qty_ip_resolved"])
print(result_live["features"]["time_response"])
```

### 2. Interactive CLI

Launch an interactive REPL session — type any URL to analyze it in real-time:

```bash
python interact.py
```

In-session commands:

| Command | Action |
| :--- | :--- |
| `<any URL>` | Analyze URL and print security report |
| `info` | Show model specifications and benchmarks |
| `exit` / `quit` / `q` | Quit the session |

### 3. Command-Line Arguments

| Command | Description |
| :--- | :--- |
| `python interact.py "https://example.com"` | Scan a single URL |
| `python interact.py --live "https://example.com"` | Scan with live DNS & latency |
| `python interact.py --file urls.txt` | Batch scan from a file (one URL per line) |
| `python interact.py --file urls.txt --output results.csv` | Batch scan and save results to CSV |
| `python interact.py --info` | Display model specifications and metrics |

### 4. Run the Example Script

```bash
python example.py
```

This demonstrates: model loading, single-URL inference, batch prediction, and raw feature extraction.

---

## 🔍 Prediction Output Schema

The `predict()` method returns a dictionary with the following fields:

| Field | Type | Description |
| :--- | :--- | :--- |
| `url` | `str` | Original input URL |
| `prediction` | `str` | `"Phishing"` or `"Legitimate"` |
| `label` | `int` | `1` = Phishing, `0` = Legitimate |
| `is_phishing` | `bool` | Boolean verdict |
| `phishing_probability` | `float` | Model confidence for phishing class (0–1) |
| `legitimate_probability` | `float` | Model confidence for legitimate class (0–1) |
| `confidence` | `float` | Confidence in the final verdict |
| `risk_score` | `float` | Risk score scaled to 0–100 |
| `threat_level` | `str` | Categorical severity (see below) |
| `key_indicators` | `list[str]` | Human-readable explanations of the verdict |
| `features` | `dict` | All 60 extracted numeric features |

### Threat Levels

| Level | Phishing Probability | Meaning |
| :--- | :--- | :--- |
| `SAFE` | < 20% | Highly likely legitimate |
| `LOW_RISK` | 20% – 39% | Minor suspicious signals |
| `SUSPICIOUS` | 40% – 59% | Ambiguous — proceed with caution |
| `HIGH` | 60% – 84% | Strong phishing indicators |
| `CRITICAL` | ≥ 85% | Near-certain phishing attempt |

---

## 🧠 Feature Engineering

The detector extracts **60 numeric features** across 6 categories:

### URL-Level (18 features)
Character frequency counts for `.`, `-`, `_`, `/`, `?`, `=`, `@`, `&`, `!`, ` `, `~`, `,`, `+`, `*`, `#`, `$`, `%` in the full URL, plus overall URL length. Features are computed on the **scheme-less** representation to avoid protocol bias.

### Domain-Level (19 features)
Same 17 character counts for the domain component, plus vowel count and domain length.

### Directory-Level (18 features)
Character counts and length of the URL path directory component. Returns `-1` when no directory is present.

### File-Level (18 features)
Character counts and length of the filename component of the path. Returns `0` when no file component exists (e.g., trailing slash).

### Parameters-Level (20 features)
Query string length, number of `&`-separated parameters, TLD presence in query, and per-character counts. Returns `-1` when no query string is present.

### Network / External (8 features)
Live or cached DNS and network signals:

| Feature | Description |
| :--- | :--- |
| `qty_ip_resolved` | Number of IPs the domain resolves to |
| `time_response` | HTTP response latency (seconds) |
| `qty_nameservers` | Nameserver count |
| `qty_mx_servers` | MX record count |
| `ttl_hostname` | DNS TTL |
| `asn_ip` | Autonomous System Number |
| `time_domain_activation` | Domain registration age |
| `time_domain_expiration` | Days until domain expiry |

> **Note:** Network features default to `-1` when `live_lookup=False` (offline mode). Pass `live_lookup=True` to `predict()` or `extract_features()` to enable live DNS resolution and HTTP ping.

---

## 🏗️ Architecture

```
Raw URL Input
     │
     ▼
┌─────────────────────────────┐
│   PhishingDetector.predict() │
└─────────────────────────────┘
     │
     ▼
┌─────────────────────────────┐
│   extract_features()         │  → 60-dim feature vector
│   ├── URL-level analysis     │
│   ├── Domain parsing         │
│   │   (tldextract)           │
│   ├── Path decomposition     │
│   ├── Query string parsing   │
│   └── [Optional] Live DNS    │
└─────────────────────────────┘
     │
     ▼
┌─────────────────────────────┐
│   StandardScaler.transform() │  → Normalized feature matrix
└─────────────────────────────┘
     │
     ▼
┌─────────────────────────────┐
│   LightGBMClassifier.predict │  → Label + Probabilities
└─────────────────────────────┘
     │
     ▼
┌─────────────────────────────┐
│   Risk scoring & indicators  │  → Structured result dict
└─────────────────────────────┘
```

### Key Design Decisions

| Decision | Rationale |
| :--- | :--- |
| **Scheme-less feature extraction** | Prevents `http://` vs `https://` from skewing character-count features |
| **Module-level tldextract instance** | Eliminates repeated filesystem lookups; improves throughput significantly |
| **`predict_batch_fast()`** | Builds a NumPy matrix and runs a single `predict_proba()` call — reduces latency from ~1 ms to ~0.015 ms per URL for large batches |
| **`-1` sentinel for missing segments** | Matches training dataset convention for absent path/file/query components |
| **`0` for missing file length** | Distinguishes "trailing slash, no file" from "unavailable segment" |

---

## 📓 Training

The model was trained in [`train.ipynb`](train.ipynb) using the **Grega Vrbančič Phishing Dataset**. The training pipeline includes:

- Feature engineering (60 features as described above)
- Train/test split with stratification
- `StandardScaler` normalization
- `LightGBMClassifier` with hyperparameter tuning
- Evaluation using Accuracy, Precision, Recall, F1, ROC-AUC, and PR-AUC
- Export as a `.joblib` bundle containing: model, scaler, feature names list, and metrics dict

The serialized bundle is stored at `model/url_phishing_bundle.joblib`.

---

## 📋 API Reference

### `PhishingDetector(model_path=None)`
Loads the model bundle. Auto-discovers `model/url_phishing_bundle.joblib` relative to the script location if no path is provided.

### `.predict(url, live_lookup=False, timeout=2.0) → dict`
Full inference on a single URL. Returns the complete result schema described above.

### `.predict_batch(urls, live_lookup=False, return_df=True) → DataFrame | list`
Batch inference by calling `predict()` for each URL. Returns a summary DataFrame by default.

### `.predict_batch_fast(urls, live_lookup=False, return_df=True) → DataFrame | list`
High-performance batch inference. Runs a single `predict_proba()` call across all URLs. Recommended for large-scale evaluations.

### `.extract_features(url, live_lookup=False, timeout=2.0) → dict`
Extracts and returns all 60 features as a Python dictionary without running the classifier.

### `.get_model_info() → dict`
Returns bundle metadata: model name, architecture type, feature count, feature names, and validation metrics.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add: my feature description"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

Please ensure any new features include relevant tests and follow the existing code style.

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ravi Agarwal** — [github.com/ravi9680](https://github.com/ravi9680)

*TCS Project · TCS-332 · Phishing URL Detection System*
