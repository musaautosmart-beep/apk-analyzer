import json
import re
import shutil
import subprocess
from pathlib import Path
from collections import defaultdict

from childs.helpers import (
    write_text,
    run_command,
    run_command_capture,
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

COMMON_ABI_ORDER = [
    "arm64-v8a",
    "armeabi-v7a",
    "x86_64",
    "x86",
]

COMMON_PUB_PACKAGES = {
    "bloc",
    "cached_network_image",
    "camera",
    "cloud_firestore",
    "connectivity_plus",
    "dio",
    "device_info_plus",
    "firebase_analytics",
    "firebase_auth",
    "firebase_core",
    "firebase_database",
    "firebase_messaging",
    "firebase_storage",
    "flutter_bloc",
    "flutter_local_notifications",
    "flutter_secure_storage",
    "geolocator",
    "get",
    "get_it",
    "google_sign_in",
    "hive",
    "hive_flutter",
    "http",
    "image_picker",
    "in_app_review",
    "intl",
    "just_audio",
    "package_info_plus",
    "path_provider",
    "permission_handler",
    "provider",
    "riverpod",
    "shared_preferences",
    "sqflite",
    "url_launcher",
    "video_player",
    "webview_flutter",
}


def _guess_abi_from_path(path):
    """
    Guess the ABI from a libapp.so path.
    """

    path = Path(path)
    lower = str(path).lower()

    for abi in COMMON_ABI_ORDER:

        if abi in lower:
            return abi

    for part in path.parts:

        if part.lower().startswith("arm") or part.lower().startswith("x86"):
            return part.lower()

    return None


def discover_libapp_candidates(files_dir, preferred_abi):
    """
    Find every libapp.so candidate and rank them by ABI.
    """

    files_dir = Path(files_dir)

    candidates = []

    for path in files_dir.rglob("libapp.so"):

        if not path.is_file():
            continue

        abi = _guess_abi_from_path(path)

        score = 100

        if abi == preferred_abi:
            score = 0
        elif abi in COMMON_ABI_ORDER:
            score = 10 + COMMON_ABI_ORDER.index(abi)

        candidates.append(
            {
                "path": path,
                "abi": abi or "unknown",
                "score": score,
            }
        )

    candidates.sort(
        key=lambda item: (
            item["score"],
            str(item["path"]).lower()
        )
    )

    return candidates


def find_arm64_libapp(files_dir, target_arch):
    """
    Search for libapp.so recursively.

    Do not assume that it is necessarily located at:

        lib/arm64-v8a/libapp.so
    """

    candidates = discover_libapp_candidates(
        files_dir,
        target_arch
    )

    if not candidates:
        return None

    return candidates[0]["path"]



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

    candidates = discover_libapp_candidates(
        files_dir,
        target_arch
    )

    selection = (
        candidates[0]
        if candidates
        else None
    )

    selected_abi = (
        selection["abi"]
        if selection
        else target_arch
    )

    destination = (
        flutter_dir
        / selected_abi
    )

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    libapp = (
        selection["path"]
        if selection
        else None
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
        print("[+] Selected ABI:")
        print("    ", selected_abi)

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

    selection_report = {
        "preferred_abi": target_arch,
        "selected_abi": (
            selected_abi
            if libapp
            else None
        ),
        "selected_libapp": (
            str(libapp)
            if libapp
            else None
        ),
        "candidates": [
            {
                "path": str(item["path"]),
                "abi": item["abi"],
                "score": item["score"],
            }
            for item in candidates
        ],
    }

    with open(
        flutter_dir / "selected_libapp.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            selection_report,
            f,
            indent=4,
            ensure_ascii=False
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


def _dedupe_ordered(values):
    seen = set()
    result = []

    for value in values:

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def _to_snake_case(value):
    value = re.sub(r"[^A-Za-z0-9]+", "_", str(value))
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_").lower()


def _to_pascal_case(value):
    parts = re.split(r"[^A-Za-z0-9]+", str(value))
    return "".join(part.capitalize() for part in parts if part)


def _read_text_safely(path, limit=2 * 1024 * 1024):
    path = Path(path)

    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _scan_text_evidence(root, suffixes):
    root = Path(root)

    evidence = {
        "class_names": set(),
        "method_channels": set(),
        "event_channels": set(),
        "basic_channels": set(),
        "urls": set(),
        "activity_names": set(),
        "package_names": set(),
        "firebase_signals": set(),
        "state_management_signals": set(),
    }

    if not root.exists():
        return evidence

    for path in root.rglob("*"):

        if not path.is_file():
            continue

        if path.suffix.lower() not in suffixes:
            continue

        text = _read_text_safely(path)

        if not text:
            continue

        evidence["class_names"].update(
            re.findall(
                r"\bclass\s+([A-Z][A-Za-z0-9_]+)",
                text
            )
        )
        evidence["method_channels"].update(
            re.findall(
                r"MethodChannel\(\s*['\"]([^'\"]+)['\"]",
                text
            )
        )
        evidence["event_channels"].update(
            re.findall(
                r"EventChannel\(\s*['\"]([^'\"]+)['\"]",
                text
            )
        )
        evidence["basic_channels"].update(
            re.findall(
                r"BasicMessageChannel\(\s*['\"]([^'\"]+)['\"]",
                text
            )
        )
        evidence["urls"].update(
            re.findall(
                r"https?://[^\s\"'<>]+",
                text
            )
        )
        evidence["activity_names"].update(
            re.findall(
                r"\b([A-Z][A-Za-z0-9_]*(?:Activity|Service|Receiver|Application))\b",
                text
            )
        )
        evidence["package_names"].update(
            re.findall(
                r"\bpackage\s+([a-zA-Z_][\w.]*)",
                text
            )
        )

        lower = text.lower()

        if "firebase" in lower:
            evidence["firebase_signals"].add(str(path))

        if any(term in lower for term in ("provider", "bloc", "getmaterialapp", "getx", "riverpod")):
            evidence["state_management_signals"].add(str(path))

    return evidence


def _infer_pub_dependencies(package_refs):
    dependencies = []
    evidence = []

    for ref in package_refs:

        match = re.match(
            r"package:([a-zA-Z0-9_]+)(?:/|$)",
            ref
        )

        if not match:
            continue

        package = match.group(1)

        if package in {"flutter", "cupertino_icons"}:
            continue

        if package not in COMMON_PUB_PACKAGES:
            continue

        if package in dependencies:
            continue

        dependencies.append(package)
        evidence.append(
            {
                "package": package,
                "source_reference": ref,
            }
        )

    return dependencies, evidence


def _classify_type_name(name):
    lowered = name.lower()

    screen_terms = (
        "screen",
        "page",
        "view",
        "route",
        "home",
        "login",
        "profile",
        "detail",
        "details",
        "dashboard",
        "settings",
    )
    widget_terms = (
        "widget",
        "card",
        "button",
        "dialog",
        "tile",
        "header",
        "footer",
        "item",
        "row",
        "panel",
    )
    model_terms = (
        "model",
        "entity",
        "dto",
        "request",
        "response",
        "payload",
        "user",
        "profile",
        "config",
        "setting",
    )
    service_terms = (
        "service",
        "api",
        "client",
        "repository",
        "repo",
        "bridge",
        "channel",
        "provider",
        "bloc",
        "cubit",
        "controller",
        "manager",
    )
    util_terms = (
        "util",
        "utils",
        "helper",
        "helpers",
        "constant",
        "constants",
        "formatter",
        "validator",
    )

    if any(term in lowered for term in screen_terms):
        return "screens"
    if any(term in lowered for term in widget_terms):
        return "widgets"
    if any(term in lowered for term in model_terms):
        return "models"
    if any(term in lowered for term in service_terms):
        return "services"
    if any(term in lowered for term in util_terms):
        return "utils"

    return None


def _build_type_candidates(analysis, java_source_dir, decoded_dir):
    candidates = []
    evidence = defaultdict(list)

    for value in analysis.get("possible_type_names", []):
        class_name = _to_pascal_case(value)
        if class_name and class_name[0].isalpha():
            candidates.append(class_name)
            evidence[class_name].append(
                {
                    "source": "analysis.possible_type_names",
                    "value": value,
                }
            )

    for ref in analysis.get("dart_file_references", []):
        stem = Path(ref).stem
        class_name = _to_pascal_case(stem)
        if class_name and class_name[0].isalpha():
            candidates.append(class_name)
            evidence[class_name].append(
                {
                    "source": "analysis.dart_file_references",
                    "value": ref,
                }
            )

    java_evidence = _scan_text_evidence(
        java_source_dir,
        {".java", ".kt", ".xml", ".txt"}
    )
    resource_evidence = _scan_text_evidence(
        decoded_dir,
        {".xml", ".txt", ".json", ".smali", ".java", ".kt"}
    )

    for name in sorted(java_evidence["class_names"] | resource_evidence["class_names"]):
        if name and name[0].isalpha():
            candidates.append(name)
            evidence[name].append(
                {
                    "source": "java_source/decoded source",
                    "value": name,
                }
            )

    candidates = _dedupe_ordered(
        [
            candidate
            for candidate in candidates
            if len(candidate) >= 3 and len(candidate) <= 80
        ]
    )

    ranked = []

    for candidate in candidates:
        category = _classify_type_name(candidate)
        if not category:
            continue
        score = 0
        lowered = candidate.lower()
        if any(lowered.endswith(term) for term in ("screen", "page", "view", "service", "model", "widget")):
            score += 2
        if candidate in analysis.get("possible_type_names", []):
            score += 1
        if candidate in [Path(ref).stem for ref in analysis.get("dart_file_references", [])]:
            score += 1
        ranked.append(
            {
                "class_name": candidate,
                "category": category,
                "score": score,
                "evidence": evidence.get(candidate, []),
            }
        )

    ranked.sort(
        key=lambda item: (
            -item["score"],
            item["class_name"].lower()
        )
    )

    return ranked[:12], java_evidence, resource_evidence


def _render_main_dart(app_title="Reconstructed App"):
    return "\n".join(
        [
            "// Reconstructed from APK evidence.",
            "// Original Dart source was not recovered.",
            "",
            "import 'package:flutter/material.dart';",
            "",
            "void main() {",
            "  runApp(const ReconstructedApp());",
            "}",
            "",
            "class ReconstructedApp extends StatelessWidget {",
            "  const ReconstructedApp({super.key});",
            "",
            "  @override",
            "  Widget build(BuildContext context) {",
            "    return MaterialApp(",
            f"      title: '{app_title}',",
            "      home: const ReconstructedHomePage(),",
            "    );",
            "  }",
            "}",
            "",
            "class ReconstructedHomePage extends StatelessWidget {",
            "  const ReconstructedHomePage({super.key});",
            "",
            "  @override",
            "  Widget build(BuildContext context) {",
            "    return Scaffold(",
            "      appBar: AppBar(",
            f"        title: const Text('{app_title}'),",
            "      ),",
            "      body: const Center(",
            "        child: Padding(",
            "          padding: EdgeInsets.all(24),",
            "          child: Text(",
            "            'Flutter project reconstructed from APK evidence',",
            "            textAlign: TextAlign.center,",
            "          ),",
            "        ),",
            "      ),",
            "    );",
            "  }",
            "}",
            "",
        ]
    )


def _render_screen_stub(class_name):
    return "\n".join(
        [
            "// Reconstructed from APK evidence.",
            "// Original Dart source was not recovered.",
            "",
            "import 'package:flutter/material.dart';",
            "",
            f"class {class_name} extends StatelessWidget {{",
            f"  const {class_name}({{super.key}});",
            "",
            "  @override",
            "  Widget build(BuildContext context) {",
            "    return Scaffold(",
            "      appBar: AppBar(",
            f"        title: const Text('{class_name}'),",
            "      ),",
            "      body: Center(",
            f"        child: Text('{class_name} reconstructed from APK evidence'),",
            "      ),",
            "    );",
            "  }",
            "}",
            "",
        ]
    )


def _render_widget_stub(class_name):
    return "\n".join(
        [
            "// Reconstructed from APK evidence.",
            "// Original Dart source was not recovered.",
            "",
            "import 'package:flutter/material.dart';",
            "",
            f"class {class_name} extends StatelessWidget {{",
            f"  const {class_name}({{super.key}});",
            "",
            "  @override",
            "  Widget build(BuildContext context) {",
            "    return const SizedBox.shrink();",
            "  }",
            "}",
            "",
        ]
    )


def _render_model_stub(class_name):
    return "\n".join(
        [
            "// Reconstructed from APK evidence.",
            "// Original Dart source was not recovered.",
            "",
            f"class {class_name} {{",
            f"  const {class_name}();",
            "",
            "  factory {0}.fromJson(Map<String, dynamic> json) {{".format(class_name),
            f"    return const {class_name}();",
            "  }",
            "",
            "  Map<String, dynamic> toJson() {",
            "    return const <String, dynamic>{};",
            "  }",
            "}",
            "",
        ]
    )


def _render_service_stub(class_name, urls=None, channels=None, packages=None):
    urls = urls or []
    channels = channels or []
    packages = packages or []

    lines = [
        "// Reconstructed from APK evidence.",
        "// Original Dart source was not recovered.",
        "",
        "import 'package:flutter/services.dart';",
        "",
        f"class {class_name} {{",
        f"  const {class_name}();",
        "",
    ]

    if urls:
        lines.append("  static const List<String> recoveredEndpoints = <String>[")
        for url in urls[:20]:
            lines.append(f"    '{url}',")
        lines.append("  ];")
        lines.append("")

    if channels:
        lines.append("  static const List<String> recoveredChannels = <String>[")
        for channel in channels[:20]:
            lines.append(f"    '{channel}',")
        lines.append("  ];")
        lines.append("")

    if packages:
        lines.append("  static const List<String> inferredDependencies = <String>[")
        for package in packages:
            lines.append(f"    '{package}',")
        lines.append("  ];")
        lines.append("")

    lines.extend(
        [
            "  Future<String?> invokeMethod(",
            "    String method, [",
            "    Object? arguments,",
            "  ]) async {",
            "    const channel = MethodChannel('reconstructed_flutter/platform');",
            "    final result = await channel.invokeMethod<String>(method, arguments);",
            "    return result;",
            "  }",
            "}",
            "",
        ]
    )

    return "\n".join(lines)


def _render_platform_bridge_stub(channel_names):
    lines = [
        "// Reconstructed from APK evidence.",
        "// Original Dart source was not recovered.",
        "",
        "import 'package:flutter/services.dart';",
        "",
        "class PlatformBridge {",
        "  PlatformBridge({MethodChannel? channel})",
        "      : _channel = channel ?? const MethodChannel('reconstructed_flutter/platform');",
        "",
        "  final MethodChannel _channel;",
        "",
        "  Future<T?> invoke<T>(String method, [Object? arguments]) async {",
        "    return _channel.invokeMethod<T>(method, arguments);",
        "  }",
        "",
    ]

    if channel_names:
        lines.append("  static const List<String> recoveredChannels = <String>[")
        for channel in channel_names[:20]:
            lines.append(f"    '{channel}',")
        lines.append("  ];")
        lines.append("")

    lines.extend(
        [
            "}",
            "",
        ]
    )

    return "\n".join(lines)


def _render_limitations(selected_abi, missing_packages):
    lines = [
        "# Limitations",
        "",
        "- Original Dart source is not guaranteed to be recoverable.",
        "- Release Flutter apps commonly contain compiled AOT Dart rather than readable source.",
        "- Generated Dart in this project is reconstructed and inferred from APK evidence.",
        "- Comments, original variable names, formatting, and project structure may be lost.",
        "- The generated code should be reviewed before production use.",
    ]

    if selected_abi:
        lines.append(
            f"- The reconstructed project was generated from the selected ABI: `{selected_abi}`."
        )

    if missing_packages:
        lines.append(
            "- Some recovered package references could not be mapped confidently to pub.dev dependencies:"
        )
        for package in missing_packages:
            lines.append(f"  - `{package}`")

    return "\n".join(lines) + "\n"


def _run_flutter_validation(project_dir):
    project_dir = Path(project_dir)

    validation_path = project_dir / "reconstruction" / "flutter_validation.txt"

    if not shutil.which("flutter"):
        write_text(
            validation_path,
            "Flutter was not installed or not available on PATH.\n"
            "Skipped: flutter pub get\n"
            "Skipped: flutter analyze\n"
        )
        return validation_path

    outputs = []

    for command in ("flutter pub get", "flutter analyze"):
        code, output = run_command_capture(command, cwd=project_dir)
        outputs.append(
            f"$ {command}\nreturncode: {code}\n{output}\n"
        )

    write_text(
        validation_path,
        "\n".join(outputs)
    )

    return validation_path


def generate_flutter_project(
    output_dir,
    analysis,
    flutter_dir,
    java_source_dir,
    decoded_dir,
    apk_path,
):
    """
    Generate a compilable Flutter project scaffold from APK evidence.
    """

    output_dir = Path(output_dir)
    flutter_dir = Path(flutter_dir)
    java_source_dir = Path(java_source_dir)
    decoded_dir = Path(decoded_dir)
    apk_path = Path(apk_path)

    print()
    print("[+] Flutter project reconstruction started")

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    reconstruction_dir = output_dir / "reconstruction"
    lib_dir = output_dir / "lib"
    assets_dir = output_dir / "assets"

    for path in (
        reconstruction_dir,
        lib_dir / "screens",
        lib_dir / "widgets",
        lib_dir / "models",
        lib_dir / "services",
        lib_dir / "utils",
        assets_dir / "flutter_assets",
    ):
        path.mkdir(
            parents=True,
            exist_ok=True
        )

    selected_info = {}
    selected_path = flutter_dir / "selected_libapp.json"

    if selected_path.exists():
        try:
            selected_info = json.loads(
                selected_path.read_text(
                    encoding="utf-8",
                    errors="replace"
                )
            )
        except Exception:
            selected_info = {}

    selected_abi = selected_info.get("selected_abi")

    flutter_assets_source = flutter_dir / "flutter_assets"
    copied_assets = 0

    if flutter_assets_source.exists():
        if (assets_dir / "flutter_assets").exists():
            shutil.rmtree(assets_dir / "flutter_assets")
        shutil.copytree(
            flutter_assets_source,
            assets_dir / "flutter_assets"
        )
        for path in (assets_dir / "flutter_assets").rglob("*"):
            if path.is_file():
                copied_assets += 1

    pub_packages, package_evidence = _infer_pub_dependencies(
        analysis.get("packages", [])
    )

    type_candidates, java_evidence, resource_evidence = _build_type_candidates(
        analysis,
        java_source_dir,
        decoded_dir
    )

    package_refs = analysis.get("packages", [])
    urls = analysis.get("urls", [])
    dart_refs = analysis.get("dart_file_references", [])
    framework_indicators = analysis.get("flutter_framework_indicators", [])
    possible_types = analysis.get("possible_type_names", [])

    reconstructed_files = {}

    def record_file(relative_path, evidence_items):
        reconstructed_files[relative_path] = evidence_items

    # pubspec.yaml
    pubspec_lines = [
        "name: reconstructed_flutter_app",
        "description: Reconstructed Flutter project generated from APK evidence.",
        "publish_to: 'none'",
        "version: 1.0.0+1",
        "",
        "environment:",
        "  sdk: '>=3.0.0 <4.0.0'",
        "",
        "dependencies:",
        "  flutter:",
        "    sdk: flutter",
    ]
    for package in pub_packages:
        pubspec_lines.append(f"  {package}: any")
    pubspec_lines.extend(
        [
            "",
            "dev_dependencies:",
            "  flutter_test:",
            "    sdk: flutter",
            "",
            "flutter:",
            "  uses-material-design: true",
            "  assets:",
            "    - assets/flutter_assets/",
            "",
        ]
    )
    write_text(output_dir / "pubspec.yaml", "\n".join(pubspec_lines))
    record_file(
        "pubspec.yaml",
        [
            {"source": "analysis.packages", "values": package_refs},
            {"source": "selected_libapp.json", "value": selected_abi},
            {"source": "analysis.flutter_framework_indicators", "values": framework_indicators},
        ]
    )

    app_title = "Reconstructed App"
    if selected_info.get("selected_abi"):
        app_title = f"Reconstructed App ({selected_info['selected_abi']})"

    write_text(output_dir / "lib" / "main.dart", _render_main_dart(app_title=app_title))
    record_file(
        "lib/main.dart",
        [
            {"source": "analysis.flutter_framework_indicators", "values": framework_indicators},
            {"source": "analysis.dart_file_references", "values": dart_refs},
            {"source": "analysis.possible_type_names", "values": possible_types},
            {"source": "manifest/jadx/apktool fallback template", "value": "MaterialApp fallback scaffold"},
        ]
    )

    readme_lines = [
        "# Reconstructed Flutter Project",
        "",
        "This project was generated from APK evidence and is intended as a compilable reconstruction scaffold.",
        "",
        "## Evidence sources",
        "",
        "- Flutter assets",
        "- libapp.so string analysis",
        "- Dart package and file references",
        "- JADX Java/Kotlin output",
        "- Apktool decoded resources",
        "- AndroidManifest.xml",
        "",
        f"- Selected ABI: `{selected_abi or 'unknown'}`",
        f"- Flutter assets copied: `{copied_assets}`",
        "",
        "## Notes",
        "",
        "- Original Dart source was not recovered.",
        "- Generated source is inferred and should be reviewed before use.",
        "",
    ]
    write_text(output_dir / "README.md", "\n".join(readme_lines))
    record_file(
        "README.md",
        [
            {"source": "analysis.*", "values": {
                "packages": package_refs,
                "dart_file_references": dart_refs,
                "urls": urls,
                "possible_type_names": possible_types,
            }},
            {"source": "flutter_assets", "value": str(flutter_assets_source)},
            {"source": "selected_libapp.json", "value": selected_abi},
        ]
    )

    # Targeted stubs from conservative evidence.
    generated_type_files = []
    for item in type_candidates:
        class_name = item["class_name"]
        category = item["category"]
        file_name = f"{_to_snake_case(class_name)}.dart"
        if category == "screens":
            path = lib_dir / "screens" / file_name
            contents = _render_screen_stub(class_name)
        elif category == "widgets":
            path = lib_dir / "widgets" / file_name
            contents = _render_widget_stub(class_name)
        elif category == "models":
            path = lib_dir / "models" / file_name
            contents = _render_model_stub(class_name)
        else:
            path = lib_dir / "services" / file_name
            contents = _render_service_stub(
                class_name,
                urls=urls,
                channels=list(java_evidence["method_channels"] | java_evidence["event_channels"] | java_evidence["basic_channels"]),
                packages=pub_packages,
            )

        if path.exists():
            continue

        write_text(path, contents)
        generated_type_files.append(str(path.relative_to(output_dir)))
        record_file(
            str(path.relative_to(output_dir)),
            item.get("evidence", [])
        )

    # Service / integration stubs.
    if urls:
        api_service = lib_dir / "services" / "api_service.dart"
        if not api_service.exists():
            write_text(
                api_service,
                _render_service_stub(
                    "ApiService",
                    urls=urls,
                    channels=list(java_evidence["method_channels"] | java_evidence["event_channels"] | java_evidence["basic_channels"]),
                    packages=pub_packages,
                )
            )
            record_file(
                "lib/services/api_service.dart",
                [
                    {"source": "analysis.urls", "values": urls},
                    {"source": "analysis.packages", "values": package_refs},
                ]
            )

    channel_names = list(
        _dedupe_ordered(
            list(java_evidence["method_channels"])
            + list(java_evidence["event_channels"])
            + list(java_evidence["basic_channels"])
        )
    )
    if channel_names:
        platform_bridge = lib_dir / "services" / "platform_bridge.dart"
        if not platform_bridge.exists():
            write_text(
                platform_bridge,
                _render_platform_bridge_stub(channel_names)
            )
            record_file(
                "lib/services/platform_bridge.dart",
                [
                    {"source": "java_source", "values": channel_names},
                    {"source": "decoded resources", "values": sorted(resource_evidence["urls"])} if resource_evidence["urls"] else {"source": "decoded resources", "values": []},
                ]
            )

    firebase_signals = _dedupe_ordered(
        sorted(java_evidence["firebase_signals"])
    )
    if any("firebase" in value.lower() for value in framework_indicators) or any("firebase" in ref.lower() for ref in package_refs) or firebase_signals:
        firebase_stub = lib_dir / "services" / "firebase_service.dart"
        if not firebase_stub.exists():
            write_text(
                firebase_stub,
                "\n".join(
                    [
                        "// Reconstructed from APK evidence.",
                        "// Original Dart source was not recovered.",
                        "",
                        "class FirebaseService {",
                        "  const FirebaseService();",
                        "",
                        "  Future<void> initialize() async {",
                        "    // Placeholder initialization stub.",
                        "  }",
                        "}",
                        "",
                    ]
                )
            )
            record_file(
                "lib/services/firebase_service.dart",
                [
                    {"source": "analysis.flutter_framework_indicators", "values": framework_indicators},
                    {"source": "analysis.packages", "values": package_refs},
                    {"source": "java_source/decoded", "values": firebase_signals},
                ]
            )

    if any(term in " ".join(framework_indicators).lower() for term in ("provider", "bloc", "getmaterialapp", "getx", "riverpod")):
        state_stub = lib_dir / "services" / "state_management.dart"
        if not state_stub.exists():
            write_text(
                state_stub,
                "\n".join(
                    [
                        "// Reconstructed from APK evidence.",
                        "// Original Dart source was not recovered.",
                        "",
                        "class StateManagementNotes {",
                        "  const StateManagementNotes();",
                        "}",
                        "",
                    ]
                )
            )
            record_file(
                "lib/services/state_management.dart",
                [
                    {"source": "analysis.flutter_framework_indicators", "values": framework_indicators},
                    {"source": "analysis.packages", "values": package_refs},
                ]
            )

    # Utility file with recovered URLs and package list.
    constants_path = lib_dir / "utils" / "reconstruction_constants.dart"
    if not constants_path.exists():
        write_text(
            constants_path,
            "\n".join(
                [
                    "// Reconstructed from APK evidence.",
                    "// Original Dart source was not recovered.",
                    "",
                    "class ReconstructionConstants {",
                    "  const ReconstructionConstants();",
                    "",
                    "  static const List<String> recoveredUrls = <String>[",
                ]
                + [f"    '{url}'," for url in urls[:50]]
                + [
                    "  ];",
                    "",
                    "  static const List<String> recoveredPackages = <String>[",
                ]
                + [f"    '{package}'," for package in pub_packages]
                + [
                    "  ];",
                    "}",
                    "",
                ]
            )
        )
        record_file(
            "lib/utils/reconstruction_constants.dart",
            [
                {"source": "analysis.urls", "values": urls},
                {"source": "analysis.packages", "values": package_refs},
            ]
        )

    limitations_path = reconstruction_dir / "limitations.md"
    missing_packages = []
    for package in package_refs:
        match = re.match(r"package:([a-zA-Z0-9_]+)", package)
        if not match:
            continue
        package_name = match.group(1)
        if package_name == "flutter":
            continue
        if package_name not in pub_packages:
            missing_packages.append(package_name)
    write_text(
        limitations_path,
        _render_limitations(selected_abi, _dedupe_ordered(missing_packages))
    )
    record_file(
        "reconstruction/limitations.md",
        [
            {"source": "analysis.packages", "values": package_refs},
            {"source": "selected_libapp.json", "value": selected_abi},
        ]
    )

    write_text(
        reconstruction_dir / "packages.txt",
        "\n".join(pub_packages)
    )
    write_text(
        reconstruction_dir / "urls.txt",
        "\n".join(urls)
    )
    write_text(
        reconstruction_dir / "dart_files.txt",
        "\n".join(dart_refs)
    )
    write_text(
        reconstruction_dir / "types.txt",
        "\n".join(
            item["class_name"]
            for item in type_candidates
        )
    )

    record_file(
        "reconstruction/packages.txt",
        [
            {"source": "analysis.packages", "values": package_refs},
        ]
    )
    record_file(
        "reconstruction/urls.txt",
        [
            {"source": "analysis.urls", "values": urls},
        ]
    )
    record_file(
        "reconstruction/dart_files.txt",
        [
            {"source": "analysis.dart_file_references", "values": dart_refs},
        ]
    )
    record_file(
        "reconstruction/types.txt",
        [
            {"source": "analysis.possible_type_names", "values": possible_types},
            {"source": "java_source/decoded", "values": [item["class_name"] for item in type_candidates]},
        ]
    )

    evidence = {
        "apk_path": str(apk_path),
        "selected_abi": selected_abi,
        "flutter_assets_source": str(flutter_assets_source) if flutter_assets_source.exists() else None,
        "copied_flutter_assets": copied_assets,
        "analysis": {
            "packages": package_refs,
            "dart_file_references": dart_refs,
            "urls": urls,
            "flutter_framework_indicators": framework_indicators,
            "possible_type_names": possible_types,
        },
        "source_scans": {
            "java_source": {
                "class_names": sorted(java_evidence["class_names"]),
                "method_channels": sorted(java_evidence["method_channels"]),
                "event_channels": sorted(java_evidence["event_channels"]),
                "basic_channels": sorted(java_evidence["basic_channels"]),
                "urls": sorted(java_evidence["urls"]),
                "activity_names": sorted(java_evidence["activity_names"]),
                "package_names": sorted(java_evidence["package_names"]),
                "firebase_signals": sorted(java_evidence["firebase_signals"]),
                "state_management_signals": sorted(java_evidence["state_management_signals"]),
            },
            "decoded_dir": {
                "class_names": sorted(resource_evidence["class_names"]),
                "method_channels": sorted(resource_evidence["method_channels"]),
                "event_channels": sorted(resource_evidence["event_channels"]),
                "basic_channels": sorted(resource_evidence["basic_channels"]),
                "urls": sorted(resource_evidence["urls"]),
                "activity_names": sorted(resource_evidence["activity_names"]),
                "package_names": sorted(resource_evidence["package_names"]),
                "firebase_signals": sorted(resource_evidence["firebase_signals"]),
                "state_management_signals": sorted(resource_evidence["state_management_signals"]),
            },
        },
        "generated_files": reconstructed_files,
    }

    write_text(
        reconstruction_dir / "evidence.json",
        json.dumps(
            evidence,
            indent=4,
            ensure_ascii=False
        )
    )

    validation_path = _run_flutter_validation(output_dir)

    print(
        "[+] Recovered packages:",
        len(pub_packages)
    )
    print(
        "[+] Recovered Dart references:",
        len(dart_refs)
    )
    print(
        "[+] Recovered URLs:",
        len(urls)
    )
    print(
        "[+] Recovered type candidates:",
        len(type_candidates)
    )
    print(
        "[+] Flutter assets copied:",
        copied_assets
    )
    print(
        "[+] Dart files generated:",
        len(generated_type_files) + 1
    )
    print("[+] Reconstruction project:")
    print("    ", output_dir)
    print("[+] Validation:")
    print("    ", validation_path)

    return {
        "project_dir": output_dir,
        "validation_path": validation_path,
        "selected_abi": selected_abi,
        "packages": pub_packages,
        "generated_files": reconstructed_files,
    }


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
