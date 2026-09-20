"""
Example script demonstrating how to interact with the Phishing Detection Model.
"""

from phishing_detector import PhishingDetector


def main():
    # 1. Initialize the detector (loads model bundle automatically)
    print("Loading Phishing Detector model...")
    detector = PhishingDetector()

    # 2. View model metadata and validation benchmarks
    info = detector.get_model_info()
    metrics = info.get("training_metrics", {})
    print(f"\nModel: {info['model_name']} ({info['model_type']})")
    print(f"Features: {info['features_count']} features")
    print(f"Trained Accuracy: {metrics.get('accuracy', 0):.2%}, ROC-AUC: {metrics.get('roc_auc', 0):.4f}")

    # 3. Single URL Prediction
    test_url = "http://paypal-verification-account-security-update.com/login.php?cmd=login"
    print(f"\n--- Predicting Single URL: {test_url} ---")
    result = detector.predict(test_url)

    print(f"Verdict:              {result['prediction']}")
    print(f"Phishing Probability: {result['phishing_probability']:.2%}")
    print(f"Risk Score:           {result['risk_score']} / 100")
    print(f"Threat Level:         {result['threat_level']}")
    print("Key Indicators:")
    for indicator in result['key_indicators']:
        print(f"  - {indicator}")

    # 4. Batch Prediction
    sample_urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "http://chase-security-login-verification.servehttp.com/account",
        "http://appleid.apple.com-verify-account.info/login",
    ]
    print(f"\n--- Batch Prediction on {len(sample_urls)} URLs ---")
    df_results = detector.predict_batch(sample_urls)
    print(df_results.to_string(index=False))

    # 5. Feature Extraction (inspect the 60 extracted features)
    print("\n--- Extracted Feature Sample (First 10 features) ---")
    feats = detector.extract_features("https://www.google.com")
    for k in list(feats.keys())[:10]:
        print(f"  {k:28}: {feats[k]}")


if __name__ == "__main__":
    main()
