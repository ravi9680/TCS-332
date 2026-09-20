"""
Phishing URL Detection Engine
Interacts with the trained LightGBM model and StandardScaler bundle.
"""

import os
import re
import socket
import time
import urllib.request
import warnings
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import tldextract

# Suppress sklearn/lightgbm version warnings if environments differ slightly
warnings.filterwarnings("ignore", category=UserWarning)
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass


class PhishingDetector:
    """
    Production-ready interface for the trained URL Phishing Detection Model.
    """

    SUSPICIOUS_CHARS = [
        '.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%'
    ]
    CHAR_NAMES = [
        'dot', 'hyphen', 'underline', 'slash', 'questionmark', 'equal', 'at', 'and',
        'exclamation', 'space', 'tilde', 'comma', 'plus', 'asterisk', 'hashtag', 'dollar', 'percent'
    ]

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the detector by locating and loading the model bundle.
        """
        self.model_path = self._resolve_model_path(model_path)
        self.bundle = joblib.load(self.model_path)

        self.model = self.bundle['model']
        self.scaler = self.bundle['scaler']
        self.feature_names = self.bundle.get('feature_names', [])
        self.model_name = self.bundle.get('model_name', 'LightGBM_Phishing_Detector')
        self.metrics = self.bundle.get('metrics', {})

    @staticmethod
    def _resolve_model_path(model_path: Optional[str]) -> str:
        """Find the bundle path across standard locations."""
        if model_path and os.path.exists(model_path):
            return model_path

        candidates = [
            model_path,
            "model/url_phishing_bundle.joblib",
            "model /url_phishing_bundle.joblib",
            "url_phishing_bundle.joblib",
            os.path.join(os.path.dirname(__file__), "model", "url_phishing_bundle.joblib"),
            os.path.join(os.path.dirname(__file__), "model ", "url_phishing_bundle.joblib"),
        ]

        for cand in candidates:
            if cand and os.path.exists(cand):
                return cand

        raise FileNotFoundError(
            "Could not locate 'url_phishing_bundle.joblib'. "
            "Please check that the model directory exists or pass model_path explicitly."
        )

    def extract_features(self, raw_url: str, live_lookup: bool = False, timeout: float = 2.0) -> Dict[str, Union[int, float]]:
        """
        Extract all lexical, domain, path, query, and network features from a raw URL.
        
        Args:
            raw_url: Target URL string (with or without http/https protocol).
            live_lookup: If True, queries DNS and performs HTTP ping to obtain live network features.
            timeout: Timeout in seconds for live network requests.
        """
        url = str(raw_url).strip()
        if not re.match(r'^[a-zA-Z]+://', url):
            url_full = 'http://' + url
        else:
            url_full = url

        parsed = urlparse(url_full)
        ext = tldextract.extract(url_full)
        domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')

        path = parsed.path
        query = parsed.query

        # Separate directory path and file component
        if not path or path == '/':
            directory = None
            file = None
        else:
            last_slash = path.rfind('/')
            if last_slash == -1:
                directory = None
                file = path
            else:
                directory = path[:last_slash + 1]
                file = path[last_slash + 1:]

        params = query if query else None

        feats: Dict[str, Union[int, float]] = {}

        # 1. URL-level character counts and length
        for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
            feats[f"qty_{name}_url"] = url.count(ch)
        feats["length_url"] = len(url)

        # 2. Domain-level features
        for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
            feats[f"qty_{name}_domain"] = domain.count(ch)
        feats["qty_vowels_domain"] = sum(domain.lower().count(v) for v in "aeiou")
        feats["domain_length"] = len(domain)

        # 3. Directory-level features (-1 if no directory present)
        if directory is not None:
            feats["directory_length"] = len(directory)
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_directory"] = directory.count(ch)
        else:
            feats["directory_length"] = -1
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_directory"] = -1

        # 4. File-level features (-1 if no file component present)
        if file is not None:
            feats["file_length"] = len(file)
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_file"] = file.count(ch)
        else:
            feats["file_length"] = -1
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_file"] = -1

        # 5. Parameters features (-1 if no query parameters present)
        if params is not None and len(params) > 0:
            feats["params_length"] = len(params)
            feats["tld_present_params"] = 1 if ext.suffix and ('.' + ext.suffix) in params else 0
            feats["qty_params"] = len(params.split('&'))
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_params"] = params.count(ch)
        else:
            feats["params_length"] = -1
            feats["tld_present_params"] = -1
            feats["qty_params"] = -1
            for ch, name in zip(self.SUSPICIOUS_CHARS, self.CHAR_NAMES):
                feats[f"qty_{name}_params"] = -1

        # 6. Network & External features
        if live_lookup:
            net_feats = self._fetch_live_network_features(domain, timeout=timeout)
            feats.update(net_feats)
        else:
            # Standard default values as represented in dataset when offline/unresolved
            feats["time_domain_activation"] = -1
            feats["time_domain_expiration"] = -1
            feats["ttl_hostname"] = -1
            feats["time_response"] = -1.0
            feats["asn_ip"] = -1
            feats["qty_ip_resolved"] = -1
            feats["qty_nameservers"] = -1
            feats["qty_mx_servers"] = -1

        return feats

    @staticmethod
    def _fetch_live_network_features(domain: str, timeout: float = 2.0) -> Dict[str, Union[int, float]]:
        """Fetch live DNS resolution count and HTTP response latency."""
        net: Dict[str, Union[int, float]] = {
            "time_domain_activation": -1,
            "time_domain_expiration": -1,
            "ttl_hostname": -1,
            "time_response": -1.0,
            "asn_ip": -1,
            "qty_ip_resolved": -1,
            "qty_nameservers": -1,
            "qty_mx_servers": -1,
        }
        if not domain:
            return net

        # DNS Resolution
        try:
            _, _, ips = socket.gethostbyname_ex(domain)
            net["qty_ip_resolved"] = len(ips)
        except Exception:
            net["qty_ip_resolved"] = 0

        # HTTP Ping / Latency
        try:
            start_time = time.time()
            req = urllib.request.Request(
                f"http://{domain}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                net["time_response"] = round(time.time() - start_time, 4)
        except Exception:
            pass

        return net

    def predict(self, url: str, live_lookup: bool = False, timeout: float = 2.0) -> Dict[str, Union[str, int, float, bool, List[str], Dict]]:
        """
        Run inference on a single URL string.

        Returns:
            Dictionary containing prediction verdict, probability, risk level, and indicators.
        """
        features_dict = self.extract_features(url, live_lookup=live_lookup, timeout=timeout)
        df_row = pd.DataFrame([features_dict])[self.feature_names]

        # Scale features and run inference
        X_scaled = self.scaler.transform(df_row)
        pred_label = int(self.model.predict(X_scaled)[0])
        probabilities = self.model.predict_proba(X_scaled)[0]

        phishing_prob = float(probabilities[1])
        legit_prob = float(probabilities[0])

        is_phishing = bool(pred_label == 1)
        verdict = "Phishing" if is_phishing else "Legitimate"
        confidence = phishing_prob if is_phishing else legit_prob

        # Categorize threat severity
        if phishing_prob >= 0.85:
            threat_level = "CRITICAL"
        elif phishing_prob >= 0.60:
            threat_level = "HIGH"
        elif phishing_prob >= 0.40:
            threat_level = "SUSPICIOUS"
        elif phishing_prob >= 0.20:
            threat_level = "LOW_RISK"
        else:
            threat_level = "SAFE"

        # Extract risk indicators
        key_indicators = self._analyze_risk_factors(url, features_dict, phishing_prob)

        return {
            "url": url,
            "prediction": verdict,
            "label": pred_label,
            "is_phishing": is_phishing,
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "confidence": round(confidence, 4),
            "risk_score": round(phishing_prob * 100, 2),
            "threat_level": threat_level,
            "key_indicators": key_indicators,
            "features": features_dict,
        }

    def predict_batch(self, urls: List[str], live_lookup: bool = False, return_df: bool = True) -> Union[pd.DataFrame, List[Dict]]:
        """
        Classify multiple URLs in batch.
        """
        results = [self.predict(u, live_lookup=live_lookup) for u in urls]
        if not return_df:
            return results

        summary_rows = []
        for r in results:
            summary_rows.append({
                "url": r["url"],
                "prediction": r["prediction"],
                "risk_score": r["risk_score"],
                "phishing_probability": r["phishing_probability"],
                "threat_level": r["threat_level"],
                "top_indicator": r["key_indicators"][0] if r["key_indicators"] else "Normal URL structure"
            })
        return pd.DataFrame(summary_rows)

    def get_model_info(self) -> Dict:
        """Return bundle metadata, accuracy metrics, and feature list."""
        return {
            "model_name": self.model_name,
            "model_type": type(self.model).__name__,
            "features_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "training_metrics": self.metrics,
        }

    @staticmethod
    def _analyze_risk_factors(url: str, feats: Dict[str, Union[int, float]], prob: float) -> List[str]:
        """Generate human-readable explanations based on extracted features."""
        indicators = []

        if feats.get("length_url", 0) > 75:
            indicators.append(f"Abnormally long URL ({feats['length_url']} characters)")

        if feats.get("qty_hyphen_url", 0) >= 3:
            indicators.append(f"High number of hyphens ({feats['qty_hyphen_url']} hyphens)")

        if feats.get("qty_dot_domain", 0) >= 3:
            indicators.append(f"Multiple subdomains detected ({feats['qty_dot_domain']} dots in domain)")

        if feats.get("qty_at_url", 0) > 0:
            indicators.append("Contains '@' symbol (often used to obscure destination)")

        url_lower = url.lower()
        suspicious_words = [
            "verify", "verification", "secure", "update", "account", "login",
            "signin", "banking", "confirm", "wallet", "password", "support"
        ]
        found_keywords = [w for w in suspicious_words if w in url_lower]
        if found_keywords:
            indicators.append(f"Contains security/credential keywords: {', '.join(found_keywords)}")

        if feats.get("qty_params", 0) >= 3:
            indicators.append(f"Heavy URL parameters payload ({feats['qty_params']} parameters)")

        if feats.get("qty_ip_resolved") == 0:
            indicators.append("Domain does not resolve to an active IP address")

        if not indicators:
            if prob > 0.5:
                indicators.append("Pattern of directory and structural features matches phishing profiles")
            else:
                indicators.append("Lexical structure and domain format resemble standard legitimate websites")

        return indicators
