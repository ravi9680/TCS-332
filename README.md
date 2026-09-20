# Phishing URL Detection System (TCS-332)

An intelligent machine learning system for classifying URLs as legitimate or phishing using lexical, domain, path, query, and network features.

---

## Overview

This repository provides an end-to-end inference engine and interactive CLI powered by a tuned **LightGBM Classifier** and **StandardScaler** trained on the Grega Vrbančič Phishing Dataset.

### Model Benchmarks

| Metric | Score |
| :--- | :--- |
| **Accuracy** | 97.28% |
| **Precision** | 95.95% |
| **Recall** | 96.28% |
| **F1-Score** | 96.11% |
| **ROC-AUC** | 0.9959 |
| **PR-AUC** | 0.9928 |
| **Inference Time** | ~0.018 ms / URL |

---

## Project Structure

```text
.
├── model/
│   └── url_phishing_bundle.joblib  # Serialized LightGBM model, scaler, and metadata
├── phishing_detector.py            # Core detection engine & 60-feature extractor
├── interact.py                     # Interactive terminal CLI & batch evaluator
├── example.py                      # Python API usage examples
├── trian.ipynb                     # Model training & experimentation notebook
├── requirements.txt                # Python package dependencies
└── .gitignore                      # Git ignore rules for virtualenvs and cache
```

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ravi9680/TCS-332.git
   cd TCS-332
   ```

2. **Set up a Python virtual environment** (Python 3.9+ recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

*(Note: On macOS, LightGBM may require OpenMP: `brew install libomp`)*

---

## Usage

### 1. Python Code Integration

```python
from phishing_detector import PhishingDetector

# Initialize the detector
detector = PhishingDetector()

# Analyze a single URL
result = detector.predict("http://paypal-verification-account-security-update.com/login.php?cmd=login")

print("Verdict:        ", result["prediction"])            # 'Phishing' or 'Legitimate'
print("Threat Level:   ", result["threat_level"])         # 'SAFE', 'LOW_RISK', 'CRITICAL', etc.
print("Phishing Prob:  ", f"{result['phishing_probability']:.2%}")
print("Risk Score:     ", f"{result['risk_score']} / 100")
print("Key Indicators: ", result["key_indicators"])

# Batch predictions
sample_urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "http://chase-security-login.servehttp.com/account"
]
df_results = detector.predict_batch(sample_urls)
print(df_results)
```

### 2. Interactive CLI

Launch an interactive terminal session:

```bash
python interact.py
```

### 3. Command Line Arguments

* **Scan a single URL**:
  ```bash
  python interact.py "https://example.com"
  ```

* **Scan with live DNS & latency analysis**:
  ```bash
  python interact.py --live "https://example.com"
  ```

* **Batch evaluation from a file**:
  ```bash
  python interact.py --file urls.txt --output results.csv
  ```

* **Display model specifications & metrics**:
  ```bash
  python interact.py --info
  ```

---

## Feature Extraction

The detector extracts 60 features categorized into:
* **URL-Level**: Length, suspicious character counts (`.`, `-`, `_`, `/`, `@`, `?`, `=`, etc.)
* **Domain-Level**: Length, vowel count, dot frequency, subdomain structure
* **Directory-Level**: Directory depth, length, special characters in path
* **File-Level**: Filename length, extensions, character counts
* **Parameters-Level**: Query length, number of parameters, TLD presence
* **Network / External**: DNS resolution, latency, nameservers, MX records
