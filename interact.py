#!/usr/bin/env python3
"""
Interactive CLI for Phishing URL Detection Model
Run standalone to inspect URLs or test models in interactive mode.
"""

import argparse
import sys
from typing import List
from phishing_detector import PhishingDetector

# ANSI Color codes for clean terminal presentation
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def render_risk_meter(score: float, width: int = 30) -> str:
    """Render an ASCII/Unicode visual progress bar of risk."""
    filled = int((score / 100.0) * width)
    unfilled = width - filled
    if score >= 60:
        bar_color = RED
    elif score >= 40:
        bar_color = YELLOW
    else:
        bar_color = GREEN

    bar = f"{bar_color}{'█' * filled}{DIM}{'░' * unfilled}{RESET}"
    return f"[{bar}] {bar_color}{score:5.1f}%{RESET}"


def print_single_report(result: dict):
    """Print an attractive security report for a single URL."""
    verdict = result["prediction"]
    score = result["risk_score"]
    threat = result["threat_level"]
    url = result["url"]

    if verdict == "Phishing":
        status_badge = f"{RED}{BOLD}⚠️  PHISHING DETECTED{RESET}"
    else:
        status_badge = f"{GREEN}{BOLD}✅ LEGITIMATE (SAFE){RESET}"

    print(f"\n{BOLD}{'=' * 68}{RESET}")
    print(f" URL: {CYAN}{url}{RESET}")
    print(f"{'=' * 68}")
    print(f" Verdict:        {status_badge}")
    print(f" Threat Level:   {BOLD}{threat}{RESET}")
    print(f" Risk Meter:     {render_risk_meter(score)}")
    print(f" Phishing Prob:  {result['phishing_probability']:.2%}")
    print(f" Legitimate Prob:{result['legitimate_probability']:.2%}")

    print(f"\n{BOLD}Key Findings / Indicators:{RESET}")
    for idx, ind in enumerate(result["key_indicators"], 1):
        bullet = f"{RED}•{RESET}" if verdict == "Phishing" else f"{GREEN}•{RESET}"
        print(f"  {bullet} {ind}")
    print(f"{'=' * 68}\n")


def print_model_info(detector: PhishingDetector):
    """Display model metadata and evaluation benchmarks."""
    info = detector.get_model_info()
    metrics = info.get("training_metrics", {})

    print(f"\n{BOLD}{CYAN}=== MODEL SPECIFICATIONS ==={RESET}")
    print(f" Model Name:     {BOLD}{info['model_name']}{RESET}")
    print(f" Architecture:   {info['model_type']}")
    print(f" Total Features: {info['features_count']}")

    if metrics:
        print(f"\n{BOLD}{CYAN}=== VALIDATION BENCHMARKS ==={RESET}")
        print(f" Accuracy:       {metrics.get('accuracy', 0):.2%}")
        print(f" Precision:      {metrics.get('precision', 0):.2%}")
        print(f" Recall:         {metrics.get('recall', 0):.2%}")
        print(f" F1-Score:       {metrics.get('f1', 0):.2%}")
        print(f" ROC-AUC:        {metrics.get('roc_auc', 0):.4f}")
        print(f" PR-AUC:         {metrics.get('pr_auc', 0):.4f}")
        print(f" Inference Time: {metrics.get('infer_ms_per_sample', 0):.3f} ms / URL")
    print(f"{CYAN}{'=' * 28}{RESET}\n")


def interactive_loop(detector: PhishingDetector, live: bool = False):
    """Interactive loop to prompt user for URLs continuously."""
    print(f"\n{BOLD}{CYAN}🛡️  Phishing Detection System - Interactive Terminal{RESET}")
    print(f"{DIM}Type any URL to test it. Type 'exit' or 'quit' to close.{RESET}")
    if live:
        print(f"{YELLOW}[Live network analysis enabled]{RESET}")
    print("-" * 68)

    sample_suggestions = [
        "https://www.wikipedia.org",
        "http://secure-paypal-login.com/verification?session=123",
        "https://github.com/torvalds/linux",
        "http://appleid.apple.com-verify-account-security.net",
    ]
    print(f"{DIM}Suggestions to try:{RESET}")
    for s in sample_suggestions:
        print(f"  {DIM}→ {s}{RESET}")
    print("-" * 68)

    while True:
        try:
            user_input = input(f"{BOLD}Enter URL > {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{CYAN}Goodbye!{RESET}")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "q"):
            print(f"{CYAN}Exiting phishing detector. Goodbye!{RESET}")
            break

        if user_input.lower() == "info":
            print_model_info(detector)
            continue

        result = detector.predict(user_input, live_lookup=live)
        print_single_report(result)


def main():
    parser = argparse.ArgumentParser(description="Classify URLs using the trained Phishing Detection Model.")
    parser.add_argument("url", nargs="?", help="A single URL to analyze.")
    parser.add_argument("--live", action="store_true", help="Perform live DNS resolution and ping lookup.")
    parser.add_argument("--info", action="store_true", help="Show model metadata and training performance.")
    parser.add_argument("--file", "-f", help="Path to text file containing URLs to classify (one per line).")
    parser.add_argument("--output", "-o", help="Output CSV path for batch evaluation results.")
    args = parser.parse_args()

    detector = PhishingDetector()

    if args.info:
        print_model_info(detector)
        return

    if args.file:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"{CYAN}Classifying {len(urls)} URLs from '{args.file}'...{RESET}")
        df = detector.predict_batch(urls, live_lookup=args.live)
        if args.output:
            df.to_csv(args.output, index=False)
            print(f"{GREEN}✓ Results saved to {args.output}{RESET}")
        else:
            print(df.to_string(index=False))
        return

    if args.url:
        result = detector.predict(args.url, live_lookup=args.live)
        print_single_report(result)
        return

    # Default to interactive REPL
    interactive_loop(detector, live=args.live)


if __name__ == "__main__":
    main()
