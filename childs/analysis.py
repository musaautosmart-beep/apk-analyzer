import json
import re
import shutil
from pathlib import Path

from childs.helpers import (
    write_text,
    run_command,
)


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


# Patterns are indicators only.
# A match does NOT automatically prove a valid secret.
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
# FLUTTER / DART
# ============================================================

def find_arm64_libapp(files_dir, target_arch):
    """
    Search for libapp.so recursively.

    Do not assume that it is necessarily located at:

        lib/arm64-v8a/libapp.so
    """

    files_dir = Path(files_dir)

    candidates = []

    for path in files_dir.rglob("libapp.so"):

        if not path.is_file():
            continue

        candidates.append(path)

    if not candidates:
        return None

    # Prefer the requested ABI.
    preferred = [
        path
        for path in candidates
        if target_arch in str(path)
    ]

    if preferred:
        return preferred[0]

    return candidates[0]



def prepare_flutter(
    files_dir,
    flutter_dir,
    target_arch
):
    """
    Locate Flutter native libraries regardless of their
    exact extracted location.
    """

    files_dir = Path(files_dir)
    flutter_dir = Path(flutter_dir)

    destination = (
        flutter_dir
        / target_arch
    )

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    libapp = find_arm64_libapp(
        files_dir,
        target_arch
    )

    # --------------------------------------------------------
    # Search all Flutter native libraries
    # --------------------------------------------------------

    flutter_libs = []

    for path in files_dir.rglob("*.so"):

        if not path.is_file():
            continue

        name = path.name.lower()

        if (
            "flutter" in name
            or "app" in name
        ):
            flutter_libs.append(path)

    # --------------------------------------------------------
    # Copy libapp
    # --------------------------------------------------------

    if libapp:

        shutil.copy2(
            libapp,
            destination / "libapp.so"
        )

        print()
        print("[+] Flutter libapp.so found:")
        print("    ", libapp)

    else:

        print()
        print("[!] libapp.so was not found.")

    # --------------------------------------------------------
    # Copy libflutter
    # --------------------------------------------------------

    libflutter = None

    for path in files_dir.rglob("libflutter.so"):

        if path.is_file():

            if target_arch in str(path):
                libflutter = path
                break

            if libflutter is None:
                libflutter = path

    if libflutter:

        shutil.copy2(
            libflutter,
            destination / "libflutter.so"
        )

        print(
            "[+] libflutter.so found:"
        )

        print(
            "    ",
            libflutter
        )

    else:

        print(
            "[-] libflutter.so not found."
        )

    # --------------------------------------------------------
    # Native library inventory
    # --------------------------------------------------------

    native_inventory = []

    for path in files_dir.rglob("*.so"):

        if not path.is_file():
            continue

        native_inventory.append({
            "path": str(
                path.relative_to(files_dir)
            ),
            "name": path.name,
            "size": path.stat().st_size
        })

    native_inventory.sort(
        key=lambda x: x["path"].lower()
    )

    with open(
        flutter_dir / "native_inventory.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            native_inventory,
            f,
            indent=4
        )

    return libapp

def analyze_apk_structure(
    apk_path,
    output_dir
):
    """
    Analyze the APK itself instead of relying only on the
    extracted directory.
    """

    apk_path = Path(apk_path)
    output_dir = Path(output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    from childs.helpers import inspect_apk_archive

    result = inspect_apk_archive(
        apk_path
    )

    with open(
        output_dir / "apk_structure.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4,
            ensure_ascii=False
        )

    print()
    print("=" * 70)
    print("APK STRUCTURE")
    print("=" * 70)

    print(
        "[+] APK entries:",
        len(result["entries"])
    )

    print(
        "[+] DEX files:",
        len(result["dex_files"])
    )

    print(
        "[+] Native .so files:",
        len(result["native_libraries"])
    )

    print(
        "[+] Flutter assets:",
        len(result["flutter_assets"])
    )

    print(
        "[+] Nested APKs:",
        len(result["nested_apks"])
    )

    print(
        "[+] ABI directories:",
        ", ".join(
            result["abi_directories"]
        )
        if result["abi_directories"]
        else "NONE"
    )

    if result["split_indicators"]:

        print()
        print(
            "[!] Possible split/bundle indicators:"
        )

        for item in result[
            "split_indicators"
        ][:30]:

            print(
                "    ",
                item
            )

    if result["native_libraries"]:

        print()
        print(
            "[+] Native libraries:"
        )

        for item in result[
            "native_libraries"
        ]:

            print(
                "    ",
                item
            )

    return result

def analyze_dex(
    files_dir,
    output_dir
):
    """
    Inventory and perform lightweight textual analysis
    of DEX files.

    This does not decompile DEX. JADX does that later.
    """

    files_dir = Path(files_dir)
    output_dir = Path(output_dir)

    dex_dir = (
        output_dir / "dex_analysis"
    )

    dex_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    dex_files = sorted(
        files_dir.rglob("*.dex")
    )

    results = []

    interesting_terms = [
        "flutter",
        "firebase",
        "firestore",
        "firebaseauth",
        "methodchannel",
        "eventchannel",
        "flutteractivity",
        "flutterengine",
        "inappwebview",
        "ultralytics",
        "yolo",
        "camera",
        "location",
        "youtube",
        "sound",
        "record",
    ]

    for dex in dex_files:

        try:
            data = dex.read_bytes()
        except Exception:
            continue

        text = data.decode(
            "latin-1",
            errors="ignore"
        )

        matches = {}

        lower = text.lower()

        for term in interesting_terms:

            count = lower.count(
                term.lower()
            )

            if count:
                matches[term] = count

        results.append({
            "file": str(
                dex.relative_to(files_dir)
            ),
            "size": dex.stat().st_size,
            "interesting_terms": matches
        })

        # Save a limited printable extraction.
        strings = re.findall(
            r"[ -~]{5,}",
            text
        )

        strings = sorted(
            set(strings)
        )

        interesting_strings = []

        for value in strings:

            low = value.lower()

            if any(
                term in low
                for term in interesting_terms
            ):
                interesting_strings.append(
                    value
                )

        write_text(
            dex_dir
            / f"{dex.name}.strings.txt",
            "\n".join(
                interesting_strings[:10000]
            )
        )

    with open(
        dex_dir / "dex_analysis.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(
        "[+] DEX files analyzed:",
        len(dex_files)
    )

    return results

    
def analyze_manifest(
    files_dir,
    output_dir
):
    """
    Extract important Android manifest indicators.
    """

    files_dir = Path(files_dir)
    output_dir = Path(output_dir)

    manifest = (
        files_dir
        / "AndroidManifest.xml"
    )

    if not manifest.exists():
        return {}

    try:
        data = manifest.read_bytes()
    except Exception:
        return {}

    text = data.decode(
        "utf-8",
        errors="replace"
    )

    # Also search printable strings because the manifest
    # may be binary AXML.
    printable = "\n".join(
        re.findall(
            r"[ -~]{3,}",
            data.decode(
                "latin-1",
                errors="ignore"
            )
        )
    )

    combined = text + "\n" + printable

    patterns = {
        "flutter": r"(?i)flutter",
        "activities": r"(?i)activity",
        "services": r"(?i)service",
        "receivers": r"(?i)receiver",
        "providers": r"(?i)provider",
        "permissions": r"(?i)permission",
        "deep_links": r"(?i)http|https|intent-filter",
        "firebase": r"(?i)firebase",
        "google": r"(?i)google",
    }

    findings = {}

    for name, pattern in patterns.items():

        matches = re.findall(
            pattern,
            combined
        )

        findings[name] = len(matches)

    write_text(
        output_dir / "manifest_strings.txt",
        printable
    )

    with open(
        output_dir / "manifest_analysis.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            findings,
            f,
            indent=4
        )

    print()
    print(
        "[+] Manifest analysis created."
    )

    return findings

def copy_flutter_assets(
    files_dir,
    flutter_dir
):
    """
    Copy Flutter assets from the extracted APK.
    """

    assets = (
        Path(files_dir)
        / "assets"
        / "flutter_assets"
    )

    if not assets.exists():

        print(
            "[-] flutter_assets not found."
        )

        return

    destination = (
        Path(flutter_dir)
        / "flutter_assets"
    )

    if destination.exists():

        shutil.rmtree(
            destination
        )

    shutil.copytree(
        assets,
        destination
    )

    print(
        "[+] Flutter assets copied."
    )


# ============================================================
# STRING EXTRACTION
# ============================================================

def extract_strings(binary):
    """
    Extract printable ASCII strings from a binary.

    This is intentionally simple and does not attempt to
    decompile Dart AOT code.
    """

    binary = Path(binary)

    print()
    print(
        "[+] Reading ARM64 libapp.so..."
    )

    try:

        data = binary.read_bytes()

    except Exception as e:

        print(
            "[!] Unable to read binary:",
            e
        )

        return []

    strings = []
    current = bytearray()

    for byte in data:

        if 32 <= byte <= 126:

            current.append(
                byte
            )

        else:

            if len(current) >= 4:

                try:

                    value = current.decode(
                        "ascii",
                        errors="ignore"
                    )

                    if value:
                        strings.append(value)

                except Exception:
                    pass

            current.clear()

    # Handle final string.
    if len(current) >= 4:

        try:

            value = current.decode(
                "ascii",
                errors="ignore"
            )

            if value:
                strings.append(value)

        except Exception:
            pass

    strings = sorted(
        set(strings)
    )

    print(
        f"[+] Extracted {len(strings)} strings."
    )

    return strings


# ============================================================
# DART ANALYSIS
# ============================================================

def analyze_dart(strings):
    """
    Analyze extracted strings for Flutter/Dart indicators.
    """

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
        "GetMaterialApp",
    ]

    for value in strings:

        value = value.strip()

        if not value:
            continue

        # ----------------------------------------------------
        # package:
        # ----------------------------------------------------

        if value.startswith("package:"):

            if len(value) < 1000:
                packages.add(value)

        # ----------------------------------------------------
        # Dart file references
        # ----------------------------------------------------

        if ".dart" in value.lower():

            if len(value) < 1000:
                dart_files.add(value)

        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        if (
            value.startswith("http://")
            or value.startswith("https://")
        ):

            if len(value) < 2000:
                urls.add(value)

        # ----------------------------------------------------
        # Flutter framework indicators
        # ----------------------------------------------------

        for term in framework_terms:

            if term.lower() in value.lower():

                indicators.add(value)

        # ----------------------------------------------------
        # Possible type names
        # ----------------------------------------------------

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
        "possible_type_names": sorted(candidates),
    }


# ============================================================
# SAVE DART ANALYSIS
# ============================================================

def save_dart_analysis(
    strings,
    analysis,
    dart_dir,
    target_arch
):
    """
    Save all extracted Dart analysis artifacts.
    """

    directory = (
        Path(dart_dir)
        / target_arch
    )

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Raw strings
    # --------------------------------------------------------

    write_text(
        directory / "strings.txt",
        "\n".join(strings)
    )

    # --------------------------------------------------------
    # Packages
    # --------------------------------------------------------

    write_text(
        directory / "packages.txt",
        "\n".join(
            analysis["packages"]
        )
    )

    # --------------------------------------------------------
    # Dart file references
    # --------------------------------------------------------

    write_text(
        directory / "dart_file_references.txt",
        "\n".join(
            analysis["dart_file_references"]
        )
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    write_text(
        directory / "urls.txt",
        "\n".join(
            analysis["urls"]
        )
    )

    # --------------------------------------------------------
    # Flutter indicators
    # --------------------------------------------------------

    write_text(
        directory
        / "flutter_framework_indicators.txt",
        "\n".join(
            analysis[
                "flutter_framework_indicators"
            ]
        )
    )

    # --------------------------------------------------------
    # Possible type names
    # --------------------------------------------------------

    write_text(
        directory / "possible_type_names.txt",
        "\n".join(
            analysis[
                "possible_type_names"
            ]
        )
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    with open(
        directory / "analysis.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            analysis,
            f,
            indent=4,
            ensure_ascii=False
        )


# ============================================================
# RECONSTRUCTED DART REPORT
# ============================================================

def create_reconstructed_dart(
    analysis,
    dart_dir,
    target_arch
):
    """
    Create a readable reconstruction report.

    This does NOT recreate the original Dart source.
    """

    directory = (
        Path(dart_dir)
        / target_arch
    )

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    output = []

    output.append(
        "// =================================================="
    )
    output.append(
        "// FLUTTER / DART BINARY RECONSTRUCTION"
    )
    output.append(
        "// =================================================="
    )
    output.append("")
    output.append(
        f"// Architecture: {target_arch}"
    )
    output.append(
        "// Source: libapp.so"
    )
    output.append("")
    output.append(
        "// IMPORTANT:"
    )
    output.append(
        "// This is NOT the original Dart source."
    )
    output.append(
        "// The APK contains compiled Dart AOT code."
    )
    output.append(
        "// The following information was recovered"
    )
    output.append(
        "// from the binary and should be treated as"
    )
    output.append(
        "// reconstruction/analysis rather than source."
    )
    output.append("")

    # --------------------------------------------------------
    # Dart file references
    # --------------------------------------------------------

    output.append(
        "// =================================================="
    )
    output.append(
        "// DART FILE REFERENCES"
    )
    output.append(
        "// =================================================="
    )

    for item in analysis[
        "dart_file_references"
    ]:

        output.append(
            "// " + item
        )

    output.append("")

    # --------------------------------------------------------
    # Packages
    # --------------------------------------------------------

    output.append(
        "// =================================================="
    )
    output.append(
        "// PACKAGE REFERENCES"
    )
    output.append(
        "// =================================================="
    )

    for item in analysis[
        "packages"
    ]:

        output.append(
            "// " + item
        )

    output.append("")

    # --------------------------------------------------------
    # Possible types
    # --------------------------------------------------------

    output.append(
        "// =================================================="
    )
    output.append(
        "// POSSIBLE TYPES"
    )
    output.append(
        "// =================================================="
    )

    for item in analysis[
        "possible_type_names"
    ]:

        output.append(
            "// possible type: " + item
        )

    output.append("")

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    output.append(
        "// =================================================="
    )
    output.append(
        "// URLS / ENDPOINTS"
    )
    output.append(
        "// =================================================="
    )

    for item in analysis[
        "urls"
    ]:

        output.append(
            "// " + item
        )

    output.append("")

    # --------------------------------------------------------
    # Framework indicators
    # --------------------------------------------------------

    output.append(
        "// =================================================="
    )
    output.append(
        "// FLUTTER FRAMEWORK INDICATORS"
    )
    output.append(
        "// =================================================="
    )

    for item in analysis[
        "flutter_framework_indicators"
    ]:

        output.append(
            "// " + item
        )

    write_text(
        directory / "reconstructed.dart",
        "\n".join(output)
    )


# ============================================================
# CONFIGURATION / ENVIRONMENT
# ============================================================

def find_configuration(
    files_dir,
    config_dir
):
    """
    Locate configuration-like files inside the APK.
    """

    files_dir = Path(files_dir)
    config_dir = Path(config_dir)

    print()
    print("=" * 70)
    print(
        "CONFIGURATION / ENVIRONMENT FILES"
    )
    print("=" * 70)

    config_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    found = []

    for path in files_dir.rglob("*"):

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

        relative = path.relative_to(
            files_dir
        )

        report.append(
            str(relative)
        )

        # Copy .env files.
        if (
            path.name.lower() == ".env"
            or path.name.lower().startswith(".env.")
        ):

            destination = (
                config_dir / path.name
            )

            try:

                shutil.copy2(
                    path,
                    destination
                )

            except Exception:
                pass

    write_text(
        config_dir / "configuration_files.txt",
        "\n".join(report)
    )

    print(
        f"[+] Found {len(found)} "
        "configuration-like files."
    )

    env_files = [
        x
        for x in found
        if (
            x.name.lower() == ".env"
            or x.name.lower().startswith(".env.")
        )
    ]

    if env_files:

        print()
        print(
            "[+] ENVIRONMENT FILE(S) FOUND:"
        )

        for path in env_files:

            print(
                "    ",
                path.relative_to(files_dir)
            )

    else:

        print(
            "[-] No .env file found."
        )


# ============================================================
# SENSITIVE FILE / SECRET ANALYSIS
# ============================================================

def mask_secret(value):
    """
    Never print an entire detected secret.
    """

    value = value.strip()

    if len(value) <= 8:

        return "*" * len(value)

    visible_start = value[:4]
    visible_end = value[-4:]

    masked_length = min(
        20,
        max(
            1,
            len(value) - 8
        )
    )

    return (
        visible_start
        + ("*" * masked_length)
        + visible_end
    )


def looks_sensitive_filename(path):
    """
    Determine whether a filename looks sensitive.
    """

    name = path.name.lower()

    for word in SENSITIVE_FILENAME_WORDS:

        if word in name:
            return True

    if name.startswith(".env"):

        return True

    return False


def looks_like_text(data):
    """
    Basic binary/text detection.
    """

    if not data:
        return False

    sample = data[:8192]

    # NUL bytes strongly suggest binary data.
    if b"\x00" in sample:
        return False

    printable = sum(
        32 <= b <= 126
        or b in (9, 10, 13)
        for b in sample
    )

    ratio = (
        printable
        / max(1, len(sample))
    )

    return ratio >= 0.75


def scan_content(path):
    """
    Scan a file for recognizable secret indicators.

    Only masked values are returned.
    """

    findings = []

    try:

        with open(
            path,
            "rb"
        ) as f:

            data = f.read(
                10 * 1024 * 1024
            )

    except Exception:

        return findings

    if not looks_like_text(data):

        return findings

    try:

        text = data.decode(
            "utf-8",
            errors="replace"
        )

    except Exception:

        return findings

    for category, pattern in (
        SENSITIVE_PATTERNS.items()
    ):

        try:

            matches = re.findall(
                pattern,
                text
            )

        except Exception:

            continue

        if not matches:
            continue

        unique = []

        for match in matches:

            if isinstance(
                match,
                tuple
            ):

                match = "".join(
                    match
                )

            match = str(
                match
            ).strip()

            if (
                match
                and match not in unique
            ):

                unique.append(
                    match
                )

        for match in unique[:20]:

            findings.append(
                {
                    "type": category,
                    "masked_match": mask_secret(
                        match
                    )
                }
            )

    return findings


def find_sensitive_files(
    files_dir,
    config_dir
):
    """
    Scan extracted APK files for:

    - sensitive filenames
    - sensitive extensions
    - recognizable secret patterns
    """

    files_dir = Path(files_dir)
    config_dir = Path(config_dir)

    print()
    print("=" * 70)
    print(
        "SENSITIVE FILE / SECRET SCAN"
    )
    print("=" * 70)

    config_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    findings = []

    all_files = list(
        files_dir.rglob("*")
    )

    all_files = [
        path
        for path in all_files
        if path.is_file()
    ]

    print(
        f"[+] Scanning "
        f"{len(all_files)} "
        "extracted files..."
    )

    for path in all_files:

        relative = path.relative_to(
            files_dir
        )

        reasons = []

        suffix = path.suffix.lower()

        # ----------------------------------------------------
        # Sensitive extension
        # ----------------------------------------------------

        if suffix in SENSITIVE_EXTENSIONS:

            reasons.append(
                "sensitive_extension"
            )

        # ----------------------------------------------------
        # Sensitive filename
        # ----------------------------------------------------

        if looks_sensitive_filename(path):

            reasons.append(
                "sensitive_filename"
            )

        # ----------------------------------------------------
        # Content scan
        # ----------------------------------------------------

        content_findings = []

        try:

            file_size = path.stat().st_size

        except Exception:

            continue

        # Don't scan huge files.
        if file_size <= 10 * 1024 * 1024:

            content_findings = scan_content(
                path
            )

        if content_findings:

            reasons.append(
                "sensitive_content"
            )

        if not reasons:

            continue

        item = {
            "file": str(relative),
            "size": file_size,
            "reasons": reasons,
            "content_findings": content_findings
        }

        findings.append(
            item
        )

    # --------------------------------------------------------
    # Save JSON report
    # --------------------------------------------------------

    with open(
        config_dir / "sensitive_files.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            findings,
            f,
            indent=4,
            ensure_ascii=False
        )

    # --------------------------------------------------------
    # Save readable report
    # --------------------------------------------------------

    lines = []

    lines.append(
        "SENSITIVE FILE / SECRET SCAN"
    )
    lines.append(
        "=" * 70
    )
    lines.append("")

    for item in findings:

        lines.append(
            f"FILE: {item['file']}"
        )

        lines.append(
            f"SIZE: {item['size']:,} bytes"
        )

        lines.append(
            "REASONS: "
            + ", ".join(
                item["reasons"]
            )
        )

        for finding in item[
            "content_findings"
        ]:

            lines.append(
                "  - "
                + finding["type"]
                + ": "
                + finding["masked_match"]
            )

        lines.append("")

    write_text(
        config_dir / "sensitive_files.txt",
        "\n".join(lines)
    )

    # --------------------------------------------------------
    # Console summary
    # --------------------------------------------------------

    print()

    if not findings:

        print(
            "[-] No potentially sensitive "
            "files or recognizable secret "
            "patterns found."
        )

        return findings

    print(
        "[!] Potentially sensitive files found:",
        len(findings)
    )

    print()

    for item in findings:

        print(
            "[KEY/CONFIG]",
            item["file"]
        )

        print(
            "    Reason:",
            ", ".join(
                item["reasons"]
            )
        )

        for finding in item[
            "content_findings"
        ]:

            print(
                "    [SECRET INDICATOR]",
                finding["type"],
                "=>",
                finding["masked_match"]
            )

    print()

    print(
        "[+] Full sensitive-file report:"
    )

    print(
        "    ",
        config_dir / "sensitive_files.json"
    )

    print(
        "    ",
        config_dir / "sensitive_files.txt"
    )

    return findings


# ============================================================
# NATIVE LIBRARIES
# ============================================================

def analyze_native(
    files_dir,
    native_dir
):
    """
    Find all native .so libraries in the APK.
    """

    files_dir = Path(files_dir)
    native_dir = Path(native_dir)

    native_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    results = []

    for path in files_dir.rglob("*.so"):

        if not path.is_file():
            continue

        results.append(
            {
                "path": str(
                    path.relative_to(
                        files_dir
                    )
                ),
                "size": path.stat().st_size
            }
        )

    results.sort(
        key=lambda x: x["path"].lower()
    )

    with open(
        native_dir / "native_libraries.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"[+] Native libraries found: "
        f"{len(results)}"
    )

    return results


# ============================================================
# JADX
# ============================================================

def run_jadx(
    apk_path,
    java_source_dir
):
    """
    Run JADX against the APK.
    """

    java_source_dir = Path(
        java_source_dir
    )

    java_source_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    code = run_command(
        f'jadx -d "{java_source_dir}" "{apk_path}"',
        "JADX JAVA / KOTLIN ANALYSIS"
    )

    if code != 0:

        print(
            "[!] JADX failed."
        )

    else:

        print(
            "[+] JADX output:"
        )

        print(
            java_source_dir
        )

    return code


# ============================================================
# APKTOOL
# ============================================================

def run_apktool(
    apk_path,
    decoded_dir
):
    """
    Run Apktool against the APK.
    """

    decoded_dir = Path(
        decoded_dir
    )

    decoded_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    code = run_command(
        f'apktool d -f -o "{decoded_dir}" "{apk_path}"',
        "APKTOOL RESOURCE ANALYSIS"
    )

    if code != 0:

        print()
        print(
            "[!] Apktool failed or is not available."
        )

        print(
            "[!] Install Apktool and add it to PATH."
        )

    else:

        print(
            "[+] Apktool output:"
        )

        print(
            decoded_dir
        )

    return code


# ============================================================
# FILE INVENTORY
# ============================================================

def inventory(
    files_dir,
    output_dir
):
    """
    Create a JSON inventory of all extracted files.
    """

    files_dir = Path(files_dir)
    output_dir = Path(output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    result = []

    for path in files_dir.rglob("*"):

        if not path.is_file():
            continue

        try:

            size = path.stat().st_size

        except Exception:

            continue

        result.append(
            {
                "path": str(
                    path.relative_to(
                        files_dir
                    )
                ),
                "size": size
            }
        )

    result.sort(
        key=lambda x: x["path"].lower()
    )

    with open(
        output_dir / "file_inventory.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"[+] Files indexed: "
        f"{len(result)}"
    )

    return result


# ============================================================
# FINAL REPORT
# ============================================================

def create_report(
    apk_name,
    apk_path,
    output_dir,
    analysis,
    libapp,
    target_arch
):
    """
    Create the final analyzer report.
    """

    apk_path = Path(apk_path)
    output_dir = Path(output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    # Import here to keep helpers independent
    # from analysis.py.
    from childs.helpers import sha256

    report = {
        "apk": apk_name,

        "sha256": sha256(
            apk_path
        ),

        "size_bytes": apk_path.stat().st_size,

        "flutter": {
            "detected": libapp is not None,
            "architecture": target_arch,
            "libapp": (
                str(libapp)
                if libapp
                else None
            )
        },

        "dart_analysis": {
            "packages": len(
                analysis[
                    "packages"
                ]
            ),

            "dart_file_references": len(
                analysis[
                    "dart_file_references"
                ]
            ),

            "urls": len(
                analysis[
                    "urls"
                ]
            ),

            "flutter_framework_indicators": len(
                analysis[
                    "flutter_framework_indicators"
                ]
            ),

            "possible_types": len(
                analysis[
                    "possible_type_names"
                ]
            )
        },

        "note": (
            "Dart reconstruction is binary "
            "analysis, not guaranteed original source."
        )
    }

    with open(
        output_dir / "report.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(
        "[+] Final report created:"
    )

    print(
        "    ",
        output_dir / "report.json"
    )

    return report
