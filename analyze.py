import sys
import json
import hashlib
import zipfile
import shutil
import subprocess
import re
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

APK_NAME = "a.apk"

BASE_DIR = Path(__file__).resolve().parent
APK_PATH = BASE_DIR / APK_NAME

OUTPUT = BASE_DIR / "output"

FILES = OUTPUT / "files"
FLUTTER = OUTPUT / "flutter"
DART = OUTPUT / "dart_reconstruction"
CONFIG = OUTPUT / "configuration"
JAVA_SOURCE = OUTPUT / "java_source"
DECODED = OUTPUT / "decoded"
NATIVE = OUTPUT / "native"


# ONLY ANALYZE THIS FLUTTER ARCHITECTURE
TARGET_ARCH = "arm64-v8a"


# ============================================================
# SENSITIVE FILE / SECRET ANALYSIS CONSTANTS
# ============================================================

SENSITIVE_EXTENSIONS = {
    ".env",
    ".pem",
    ".key",
    ".crt",
    ".cer",
    ".der",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".mobileprovision",
    ".ovpn",
    ".conf",
    ".config",
    ".ini",
    ".properties",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".txt",
    ".db",
    ".sqlite",
    ".sqlite3",
}

SENSITIVE_FILENAME_WORDS = {
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwd",
    "token",
    "tokens",
    "apikey",
    "api_key",
    "api-key",
    "private",
    "privatekey",
    "private_key",
    "certificate",
    "cert",
    "keystore",
    "key",
    "firebase",
    "google-services",
    "service-account",
    "serviceaccount",
    ".env",
    "env.",
    "config",
    "configuration",
    "auth",
    "oauth",
    "jwt",
}

# Patterns are deliberately aimed at finding indicators,
# not automatically proving that a value is a valid secret.
SENSITIVE_PATTERNS = {
    "PRIVATE_KEY":
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",

    "JWT":
        r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b",

    "GOOGLE_API_KEY":
        r"\bAIza[0-9A-Za-z_-]{20,}\b",

    "AWS_ACCESS_KEY":
        r"\bAKIA[0-9A-Z]{16}\b",

    "GITHUB_TOKEN":
        r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",

    "SLACK_TOKEN":
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",

    "BEARER_TOKEN":
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}",

    "BASIC_AUTH":
        r"(?i)\bbasic\s+[A-Za-z0-9+/=]{16,}",

    "PASSWORD_ASSIGNMENT":
        r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^"' \r\n]{4,}""",

    "API_KEY_ASSIGNMENT":
        r"""(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*["']?[^"' \r\n]{8,}""",

    "SECRET_ASSIGNMENT":
        r"""(?i)\b(?:secret|client[_-]?secret)\s*[:=]\s*["']?[^"' \r\n]{8,}""",

    "ACCESS_TOKEN_ASSIGNMENT":
        r"""(?i)\b(?:access[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?[^"' \r\n]{8,}""",

    "DATABASE_URL":
        r"(?i)\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^ \r\n]+",

    "PRIVATE_IP":
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",

    "URL_WITH_CREDENTIALS":
        r"https?://[^/\s:@]+:[^@\s]+@[^/\s]+",

    "FIREBASE_PROJECT":
        r"(?i)(?:firebaseio\.com|firebaseapp\.com|googleapis\.com)",

    "GOOGLE_CLIENT_ID":
        r"\b\d{6,}-[a-z0-9]{20,}\.apps\.googleusercontent\.com\b",
}


# ============================================================
# HELPERS
# ============================================================

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def run_command(command, title):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)
    print(command)
    print()

    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace"
        )

        print(result.stdout[-8000:])

        if result.returncode == 0:
            print("[+] Command completed successfully.")
        else:
            print("[!] Command returned:", result.returncode)

        return result.returncode

    except Exception as e:
        print("[!] Command failed:", e)
        return 1


# ============================================================
# APK EXTRACTION
# ============================================================

def extract_apk():
    print("[+] Extracting APK...")

    FILES.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(APK_PATH, "r") as z:
        z.extractall(FILES)

    print("[+] Extraction complete.")


# ============================================================
# FIND ARM64 LIBAPP
# ============================================================

def find_arm64_libapp():
    target = FILES / "lib" / TARGET_ARCH / "libapp.so"
    if target.exists():
        return target
    return None


# ============================================================
# FLUTTER SETUP
# ============================================================

def prepare_flutter():
    libapp = find_arm64_libapp()

    if not libapp:
        print()
        print("[!] ARM64 libapp.so was not found.")
        return None

    destination = FLUTTER / TARGET_ARCH
    destination.mkdir(parents=True, exist_ok=True)

    shutil.copy2(libapp, destination / "libapp.so")

    # libflutter.so
    flutter_engine = FILES / "lib" / TARGET_ARCH / "libflutter.so"
    if flutter_engine.exists():
        shutil.copy2(flutter_engine, destination / "libflutter.so")

    print()
    print("[+] ARM64 Flutter binary:")
    print("    ", libapp)

    return libapp


# ============================================================
# FLUTTER ASSETS
# ============================================================

def copy_flutter_assets():
    assets = FILES / "assets" / "flutter_assets"

    if not assets.exists():
        print("[-] flutter_assets not found.")
        return

    destination = FLUTTER / "flutter_assets"

    if destination.exists():
        shutil.rmtree(destination)

    shutil.copytree(assets, destination)
    print("[+] Flutter assets copied.")


# ============================================================
# STRING EXTRACTION
# ============================================================

def extract_strings(binary):
    print()
    print("[+] Reading ARM64 libapp.so...")

    data = binary.read_bytes()
    strings = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= 4:
                try:
                    value = current.decode("ascii", errors="ignore")
                    strings.append(value)
                except Exception:
                    pass
            current.clear()

    if len(current) >= 4:
        try:
            strings.append(current.decode("ascii", errors="ignore"))
        except Exception:
            pass

    strings = sorted(set(strings))
    print(f"[+] Extracted {len(strings)} strings.")
    return strings


# ============================================================
# DART ANALYSIS
# ============================================================

def analyze_dart(strings):
    packages = set()
    dart_files = set()
    urls = set()
    indicators = set()
    candidates = set()

    framework_terms = [
        "StatelessWidget",
        "StatefulWidget",
        "BuildContext",
        "MaterialApp",
        "CupertinoApp",
        "Navigator",
        "MethodChannel",
        "EventChannel",
        "BasicMessageChannel",
        "ChangeNotifier",
        "Future",
        "Stream",
        "Firebase",
        "Provider",
        "Bloc",
        "GetMaterialApp"
    ]

    for value in strings:
        value = value.strip()
        if not value:
            continue

        # package:
        if value.startswith("package:"):
            if len(value) < 1000:
                packages.add(value)

        # Dart file references
        if ".dart" in value.lower():
            if len(value) < 1000:
                dart_files.add(value)

        # URLs
        if value.startswith("http://") or value.startswith("https://"):
            if len(value) < 2000:
                urls.add(value)

        # Flutter indicators
        for term in framework_terms:
            if term.lower() in value.lower():
                indicators.add(value)

        # Possible identifiers
        if (
            len(value) >= 3
            and len(value) <= 100
            and value[0].isupper()
            and value.replace("_", "").isalnum()
        ):
            candidates.add(value)

    return {
        "packages": sorted(packages),
        "dart_file_references": sorted(dart_files),
        "urls": sorted(urls),
        "flutter_framework_indicators": sorted(indicators),
        "possible_type_names": sorted(candidates)
    }


# ============================================================
# SAVE DART ANALYSIS
# ============================================================

def save_dart_analysis(strings, analysis):
    directory = DART / TARGET_ARCH
    directory.mkdir(parents=True, exist_ok=True)

    # Raw strings
    write_text(directory / "strings.txt", "\n".join(strings))

    # Packages
    write_text(directory / "packages.txt", "\n".join(analysis["packages"]))

    # Dart files
    write_text(
        directory / "dart_file_references.txt",
        "\n".join(analysis["dart_file_references"])
    )

    # URLs
    write_text(directory / "urls.txt", "\n".join(analysis["urls"]))

    # Framework indicators
    write_text(
        directory / "flutter_framework_indicators.txt",
        "\n".join(analysis["flutter_framework_indicators"])
    )

    # Possible types
    write_text(
        directory / "possible_type_names.txt",
        "\n".join(analysis["possible_type_names"])
    )

    # JSON
    with open(directory / "analysis.json", "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=4, ensure_ascii=False)


# ============================================================
# RECONSTRUCTED DART REPORT
# ============================================================

def create_reconstructed_dart(analysis):
    directory = DART / TARGET_ARCH
    output = []

    output.append("// ==================================================")
    output.append("// FLUTTER / DART BINARY RECONSTRUCTION")
    output.append("// ==================================================")
    output.append("")
    output.append("// Architecture: arm64-v8a")
    output.append("// Source: libapp.so")
    output.append("")
    output.append("// IMPORTANT:")
    output.append("// This is NOT the original Dart source.")
    output.append("// The APK contains compiled Dart AOT code.")
    output.append("// The following information was recovered")
    output.append("// from the binary and should be treated as")
    output.append("// reconstruction/analysis rather than source.")
    output.append("")
    output.append("// ==================================================")
    output.append("// DART FILE REFERENCES")
    output.append("// ==================================================")

    for item in analysis["dart_file_references"]:
        output.append("// " + item)

    output.append("")
    output.append("// ==================================================")
    output.append("// PACKAGE REFERENCES")
    output.append("// ==================================================")

    for item in analysis["packages"]:
        output.append("// " + item)

    output.append("")
    output.append("// ==================================================")
    output.append("// POSSIBLE TYPES")
    output.append("// ==================================================")

    for item in analysis["possible_type_names"]:
        output.append("// possible type: " + item)

    output.append("")
    output.append("// ==================================================")
    output.append("// URLS / ENDPOINTS")
    output.append("// ==================================================")

    for item in analysis["urls"]:
        output.append("// " + item)

    write_text(directory / "reconstructed.dart", "\n".join(output))


# ============================================================
# ENV / CONFIGURATION
# ============================================================

def find_configuration():
    print()
    print("=" * 70)
    print("CONFIGURATION / ENVIRONMENT FILES")
    print("=" * 70)

    CONFIG.mkdir(parents=True, exist_ok=True)
    found = []

    for path in FILES.rglob("*"):
        if not path.is_file():
            continue

        name = path.name.lower()

        if (
            name == ".env"
            or name.startswith(".env.")
            or name.endswith(".json")
            or name.endswith(".yaml")
            or name.endswith(".yml")
            or name.endswith(".properties")
            or name.endswith(".ini")
            or name.endswith(".conf")
        ):
            found.append(path)

    found.sort()
    report = []

    for path in found:
        relative = path.relative_to(FILES)
        report.append(str(relative))

        # Specifically copy .env files
        if path.name.lower() == ".env" or path.name.lower().startswith(".env."):
            destination = CONFIG / path.name
            try:
                shutil.copy2(path, destination)
            except Exception:
                pass

    write_text(CONFIG / "configuration_files.txt", "\n".join(report))
    print(f"[+] Found {len(found)} configuration-like files.")

    env_files = [
        x for x in found
        if x.name.lower() == ".env" or x.name.lower().startswith(".env.")
    ]

    if env_files:
        print()
        print("[+] ENVIRONMENT FILE(S) FOUND:")
        for path in env_files:
            print("    ", path.relative_to(FILES))
    else:
        print("[-] No .env file found.")


# ============================================================
# SENSITIVE FILE / SECRET ANALYSIS
# ============================================================

def mask_secret(value):
    """Never print an entire detected secret."""
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(20, len(value) - 8) + value[-4:]


def looks_sensitive_filename(path):
    name = path.name.lower()

    # Exact/compound sensitive names
    for word in SENSITIVE_FILENAME_WORDS:
        if word in name:
            return True

    # Dot-env variants
    if name.startswith(".env"):
        return True

    return False


def looks_like_text(data):
    if not data:
        return False

    sample = data[:8192]

    # NUL bytes strongly suggest binary data
    if b"\x00" in sample:
        return False

    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)
    ratio = printable / max(1, len(sample))
    return ratio >= 0.75


def scan_content(path):
    findings = []

    try:
        # Avoid loading enormous files into RAM.
        with open(path, "rb") as f:
            data = f.read(10 * 1024 * 1024)
    except Exception:
        return findings

    if not looks_like_text(data):
        return findings

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return findings

    for category, pattern in SENSITIVE_PATTERNS.items():
        try:
            matches = re.findall(pattern, text)
        except Exception:
            continue

        if not matches:
            continue

        # Deduplicate
        unique = []
        for match in matches:
            if isinstance(match, tuple):
                match = "".join(match)
            match = str(match).strip()
            if match and match not in unique:
                unique.append(match)

        for match in unique[:20]:
            findings.append({
                "type": category,
                "masked_match": mask_secret(match)
            })

    return findings


def find_sensitive_files():
    print()
    print("=" * 70)
    print("SENSITIVE FILE / SECRET SCAN")
    print("=" * 70)

    CONFIG.mkdir(parents=True, exist_ok=True)
    findings = []

    all_files = list(FILES.rglob("*"))
    all_files = [p for p in all_files if p.is_file()]

    print(f"[+] Scanning {len(all_files)} extracted files...")

    for path in all_files:
        relative = path.relative_to(FILES)
        reasons = []
        suffix = path.suffix.lower()

        if suffix in SENSITIVE_EXTENSIONS:
            reasons.append("sensitive_extension")

        if looks_sensitive_filename(path):
            reasons.append("sensitive_filename")

        content_findings = []

        # Don't attempt expensive content scanning on obvious large binaries.
        if path.stat().st_size <= 10 * 1024 * 1024:
            content_findings = scan_content(path)

        if content_findings:
            reasons.append("sensitive_content")

        if not reasons:
            continue

        item = {
            "file": str(relative),
            "size": path.stat().st_size,
            "reasons": reasons,
            "content_findings": content_findings
        }
        findings.append(item)

    # --------------------------------------------------------
    # Save JSON report
    # --------------------------------------------------------
    with open(CONFIG / "sensitive_files.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4, ensure_ascii=False)

    # --------------------------------------------------------
    # Save readable report
    # --------------------------------------------------------
    lines = []
    lines.append("SENSITIVE FILE / SECRET SCAN")
    lines.append("=" * 70)
    lines.append("")

    for item in findings:
        lines.append(f"FILE: {item['file']}")
        lines.append(f"SIZE: {item['size']:,} bytes")
        lines.append("REASONS: " + ", ".join(item["reasons"]))

        for finding in item["content_findings"]:
            lines.append(
                "  - " + finding["type"] + ": " + finding["masked_match"]
            )
        lines.append("")

    write_text(CONFIG / "sensitive_files.txt", "\n".join(lines))

    # --------------------------------------------------------
    # CMD SUMMARY
    # --------------------------------------------------------
    print()

    if not findings:
        print(
            "[-] No potentially sensitive files or"
            " recognizable secret patterns found."
        )
        return findings

    print(f"[!] Potentially sensitive files found: {len(findings)}")
    print()

    for item in findings:
        print("[KEY/CONFIG]", item["file"])
        print("    Reason:", ", ".join(item["reasons"]))

        for finding in item["content_findings"]:
            print(
                "    [SECRET INDICATOR]",
                finding["type"],
                "=>",
                finding["masked_match"]
            )

    print()
    print("[+] Full sensitive-file report:")
    print("    ", CONFIG / "sensitive_files.json")
    print("    ", CONFIG / "sensitive_files.txt")

    return findings


# ============================================================
# NATIVE LIBRARIES
# ============================================================

def analyze_native():
    NATIVE.mkdir(parents=True, exist_ok=True)
    results = []

    for path in FILES.rglob("*.so"):
        results.append({
            "path": str(path.relative_to(FILES)),
            "size": path.stat().st_size
        })

    with open(NATIVE / "native_libraries.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"[+] Native libraries found: {len(results)}")


# ============================================================
# JADX
# ============================================================

def run_jadx():
    JAVA_SOURCE.mkdir(parents=True, exist_ok=True)

    code = run_command(
        f'jadx -d "{JAVA_SOURCE}" "{APK_PATH}"',
        "JADX JAVA / KOTLIN ANALYSIS"
    )

    if code != 0:
        print("[!] JADX failed.")
    else:
        print("[+] JADX output:")
        print(JAVA_SOURCE)


# ============================================================
# APKTOOL
# ============================================================

def run_apktool():
    DECODED.mkdir(parents=True, exist_ok=True)

    code = run_command(
        f'apktool d -f -o "{DECODED}" "{APK_PATH}"',
        "APKTOOL RESOURCE ANALYSIS"
    )

    if code != 0:
        print()
        print("[!] Apktool is not available.")
        print("[!] Install it and add it to PATH.")


# ============================================================
# FILE INVENTORY
# ============================================================

def inventory():
    result = []

    for path in FILES.rglob("*"):
        if path.is_file():
            result.append({
                "path": str(path.relative_to(FILES)),
                "size": path.stat().st_size
            })

    result.sort(key=lambda x: x["path"].lower())

    with open(OUTPUT / "file_inventory.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print(f"[+] Files indexed: {len(result)}")


# ============================================================
# FINAL REPORT
# ============================================================

def create_report(analysis, libapp):
    report = {
        "apk": APK_NAME,
        "sha256": sha256(APK_PATH),
        "size_bytes": APK_PATH.stat().st_size,
        "flutter": {
            "detected": libapp is not None,
            "architecture": TARGET_ARCH,
            "libapp": str(libapp) if libapp else None
        },
        "dart_analysis": {
            "packages": len(analysis["packages"]),
            "dart_file_references": len(analysis["dart_file_references"]),
            "urls": len(analysis["urls"]),
            "possible_types": len(analysis["possible_type_names"])
        },
        "note": (
            "Dart reconstruction is binary analysis, "
            "not guaranteed original source."
        )
    }

    with open(OUTPUT / "report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("       FLUTTER / DART ARM64 APK ANALYZER")
    print("=" * 70)

    if not APK_PATH.exists():
        print("[!] a.apk not found:")
        print(APK_PATH)
        sys.exit(1)

    print()
    print("[+] APK:", APK_PATH)
    print("[+] Size:", f"{APK_PATH.stat().st_size:,}", "bytes")
    print("[+] SHA256:", sha256(APK_PATH))
    print()
    print("[+] Target architecture:", TARGET_ARCH)

    # --------------------------------------------------------
    # 1. Extract
    # --------------------------------------------------------
    extract_apk()

    # --------------------------------------------------------
    # 2. Inventory
    # --------------------------------------------------------
    inventory()

    # --------------------------------------------------------
    # 3. Flutter
    # --------------------------------------------------------
    libapp = prepare_flutter()
    copy_flutter_assets()

    # --------------------------------------------------------
    # 4. Dart analysis
    # --------------------------------------------------------
    analysis = {
        "packages": [],
        "dart_file_references": [],
        "urls": [],
        "flutter_framework_indicators": [],
        "possible_type_names": []
    }

    if libapp:
        strings = extract_strings(libapp)
        analysis = analyze_dart(strings)
        save_dart_analysis(strings, analysis)
        create_reconstructed_dart(analysis)

    # --------------------------------------------------------
    # 5. Configuration + Sensitive scan
    # --------------------------------------------------------
    find_configuration()
    sensitive_findings = find_sensitive_files()

    # --------------------------------------------------------
    # 6. Native
    # --------------------------------------------------------
    analyze_native()

    # --------------------------------------------------------
    # 7. JADX
    # --------------------------------------------------------
    run_jadx()

    # --------------------------------------------------------
    # 8. Apktool
    # --------------------------------------------------------
    run_apktool()

    # --------------------------------------------------------
    # 9. Report
    # --------------------------------------------------------
    create_report(analysis, libapp)

    # --------------------------------------------------------
    # DONE
    # --------------------------------------------------------
    print()
    print("=" * 70)
    print("                       COMPLETE")
    print("=" * 70)

    print()
    print("[+] Output:", OUTPUT)
    print()
    print("[+] ARM64 Dart analysis:")
    print("    ", DART / TARGET_ARCH)
    print()
    print("[+] JADX:")
    print("    ", JAVA_SOURCE)
    print()
    print("[+] Configuration:")
    print("    ", CONFIG)
    print()

    if libapp:
        print("[+] ARM64 libapp.so successfully analyzed.")
        print(
            "[+] Dart file references:",
            len(analysis["dart_file_references"])
        )
        print("[+] Packages:", len(analysis["packages"]))
        print("[+] URLs:", len(analysis["urls"]))
    else:
        print("[!] ARM64 libapp.so not found.")


if __name__ == "__main__":
    main()