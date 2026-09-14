
import argparse
import base64
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".msi",
}

SUSPICIOUS_KEYWORDS = [
    b"powershell",
    b"cmd.exe",
    b"wscript",
    b"cscript",
    b"rundll32",
    b"regsvr32",
    b"mshta",
    b"certutil",
    b"bitsadmin",
]

MAX_FILE_SIZE = 100 * 1024 * 1024


# ============================================================
# Hashing
# ============================================================

def calculate_hashes(data):
    """Calculate MD5, SHA-1 and SHA-256 hashes."""

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ============================================================
# Entropy
# ============================================================

def calculate_entropy(data):
    """Calculate Shannon entropy."""

    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    data_length = len(data)

    for count in frequency:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# File Indicators
# ============================================================

def detect_suspicious_extension(file_path):
    """Detect suspicious executable/script extensions."""

    return file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS


def detect_double_extension(file_path):
    """Detect names such as invoice.pdf.exe."""

    parts = file_path.name.lower().split(".")

    if len(parts) < 3:
        return False

    suspicious_names = {
        extension.replace(".", "")
        for extension in SUSPICIOUS_EXTENSIONS
    }

    return parts[-1] in suspicious_names


def detect_keywords(data):
    """Detect suspicious command/script indicators."""

    data_lower = data.lower()
    found = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in data_lower:
            found.append(
                keyword.decode("utf-8", errors="ignore")
            )

    return found


def detect_urls(data):
    """Extract HTTP and HTTPS URLs."""

    pattern = rb"https?://[^\s\"'<>]+"

    matches = re.findall(pattern, data)

    return [
        match.decode("utf-8", errors="ignore")
        for match in matches[:20]
    ]


def detect_ipv4(data):
    """Detect valid IPv4 addresses."""

    text = data.decode("latin-1", errors="ignore")

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(pattern, text)

    valid_ips = []

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)

            if candidate not in valid_ips:
                valid_ips.append(candidate)

        except ValueError:
            continue

    return valid_ips[:20]


def detect_base64_like(data):
    """Detect long Base64-like strings."""

    text = data.decode("latin-1", errors="ignore")

    pattern = (
        r"(?<![A-Za-z0-9+/])"
        r"[A-Za-z0-9+/]{80,}"
        r"={0,2}"
        r"(?![A-Za-z0-9+/])"
    )

    matches = re.findall(pattern, text)

    valid_matches = []

    for match in matches[:10]:
        try:
            base64.b64decode(
                match,
                validate=True
            )

            valid_matches.append(
                match[:60] + "..."
            )

        except Exception:
            continue

    return valid_matches


# ============================================================
# Risk Engine
# ============================================================

def calculate_risk(
    suspicious_extension,
    double_extension,
    keywords,
    urls,
    ips,
    base64_strings,
    entropy,
):
    """Calculate an explainable risk score."""

    score = 0
    findings = []

    if suspicious_extension:
        score += 15
        findings.append(
            "Suspicious executable/script extension"
        )

    if double_extension:
        score += 25
        findings.append(
            "Double file extension detected"
        )

    if keywords:
        score += min(len(keywords) * 10, 30)
        findings.append(
            "Suspicious command/script indicators detected"
        )

    if urls:
        score += 10
        findings.append(
            "URLs detected inside file"
        )

    if ips:
        score += 10
        findings.append(
            "IPv4 addresses detected inside file"
        )

    if base64_strings:
        score += 15
        findings.append(
            "Base64-like encoded data detected"
        )

    if entropy >= 7.0:
        score += 15
        findings.append(
            "High file entropy detected"
        )

    score = min(score, 100)

    if score >= 80:
        verdict = "CRITICAL"
    elif score >= 50:
        verdict = "HIGH"
    elif score >= 20:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return score, verdict, findings


# ============================================================
# File Analysis
# ============================================================

def analyze_file(file_path):
    """Analyze a file without executing it."""

    path = Path(file_path)

    if not path.exists():
        return None

    if not path.is_file():
        return None

    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            "File is larger than the configured 100 MB limit."
        )

    with path.open("rb") as file:
        data = file.read()

    hashes = calculate_hashes(data)

    entropy = calculate_entropy(data)

    suspicious_extension = (
        detect_suspicious_extension(path)
    )

    double_extension = (
        detect_double_extension(path)
    )

    keywords = detect_keywords(data)

    urls = detect_urls(data)

    ips = detect_ipv4(data)

    base64_strings = detect_base64_like(data)

    risk_score, verdict, findings = calculate_risk(
        suspicious_extension,
        double_extension,
        keywords,
        urls,
        ips,
        base64_strings,
        entropy,
    )

    return {
        "file": str(path),
        "size": file_size,
        "extension": path.suffix.lower(),

        "hashes": hashes,

        "entropy": round(
            entropy,
            3
        ),

        "suspicious_extension": (
            suspicious_extension
        ),

        "double_extension": (
            double_extension
        ),

        "keywords": keywords,

        "urls": urls,

        "ips": ips,

        "base64_indicators": (
            base64_strings
        ),

        "risk_score": risk_score,

        "verdict": verdict,

        "findings": findings,
    }


# ============================================================
# Console Report
# ============================================================

def print_report(result):
    """Print a readable security report."""

    print("\n" + "=" * 60)
    print("                 PyFileGuard")
    print("             STATIC MALWARE ANALYZER")
    print("=" * 60)

    print(f"File:       {result['file']}")
    print(f"Size:       {result['size']} bytes")
    print(f"Extension:  {result['extension']}")

    print("\n--- Hashes ---")

    print(
        f"MD5:        "
        f"{result['hashes']['md5']}"
    )

    print(
        f"SHA-1:      "
        f"{result['hashes']['sha1']}"
    )

    print(
        f"SHA-256:    "
        f"{result['hashes']['sha256']}"
    )

    print("\n--- Analysis ---")

    print(
        f"Entropy:    "
        f"{result['entropy']}"
    )

    print(
        "Suspicious extension:",
        result["suspicious_extension"]
    )

    print(
        "Double extension:",
        result["double_extension"]
    )

    print("\n--- Indicators ---")

    if result["keywords"]:
        print(
            "Keywords:",
            ", ".join(result["keywords"])
        )
    else:
        print("Keywords: None")

    if result["urls"]:
        print("URLs:")

        for url in result["urls"]:
            print(f"  - {url}")
    else:
        print("URLs: None")

    if result["ips"]:
        print("IPv4 addresses:")

        for ip in result["ips"]:
            print(f"  - {ip}")
    else:
        print("IPv4 addresses: None")

    if result["base64_indicators"]:
        print(
            "Base64-like data:",
            len(result["base64_indicators"])
        )
    else:
        print("Base64-like data: None")

    print("\n--- Verdict ---")

    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )

    print(
        f"Verdict:    "
        f"{result['verdict']}"
    )

    if result["findings"]:
        print("\nFindings:")

        for finding in result["findings"]:
            print(f"  [+] {finding}")

    else:
        print("\nFindings: None")

    print("\nNOTE:")

    print(
        "This tool performs static analysis only."
    )

    print(
        "It does NOT execute the analyzed file."
    )

    print(
        "A LOW score does not guarantee that a file is safe."
    )

    print("=" * 60)


# ============================================================
# JSON Report
# ============================================================

def save_json_report(result, output_file):
    """Save scan results as JSON."""

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# Command Line Interface
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "PyFileGuard - "
            "Static File Security Analyzer"
        )
    )

    parser.add_argument(
        "file",
        help=(
            "Path to the file "
            "you want to analyze"
        )
    )

    parser.add_argument(
        "--json",
        metavar="OUTPUT",
        help=(
            "Save the analysis "
            "report as JSON"
        )
    )

    args = parser.parse_args()

    try:
        result = analyze_file(
            args.file
        )

        if result is None:
            print(
                "Error: File not found "
                "or invalid path."
            )
            return

        print_report(result)

        if args.json:
            save_json_report(
                result,
                args.json
            )

            print(
                f"\nJSON report saved to: "
                f"{args.json}"
            )

    except PermissionError:
        print(
            "Error: Permission denied."
        )

    except ValueError as error:
        print(
            f"Error: {error}"
        )

    except OSError as error:
        print(
            f"Error accessing file: {error}"
        )


# ============================================================
# Program Entry Point
# ============================================================

if __name__ == "__main__":
    main()

