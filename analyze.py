import sys
from pathlib import Path

from childs.helpers import (
    sha256,
    extract_apk,
)

from childs.analysis import (
    inventory,
    prepare_flutter,
    copy_flutter_assets,
    extract_strings,
    analyze_dart,
    save_dart_analysis,
    create_reconstructed_dart,
    generate_flutter_project,
    find_configuration,
    find_sensitive_files,
    analyze_native,
    run_jadx,
    run_apktool,
    create_report,
    analyze_apk_structure,
    analyze_dex,
    analyze_manifest,
)


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

OUTPUT = BASE_DIR / "output"

FILES = OUTPUT / "files"
FLUTTER = OUTPUT / "flutter"
DART = OUTPUT / "dart_reconstruction"
RECONSTRUCTED = OUTPUT / "reconstructed_flutter"
CONFIG = OUTPUT / "configuration"
JAVA_SOURCE = OUTPUT / "java_source"
DECODED = OUTPUT / "decoded"
NATIVE = OUTPUT / "native"

# Preferred Flutter architecture.
#
# The analyzer will prefer ARM64, but the updated
# prepare_flutter() searches recursively rather than assuming
# lib/arm64-v8a/libapp.so exists.
TARGET_ARCH = "arm64-v8a"


# ============================================================
# APK ARGUMENT
# ============================================================

def get_apk_path():
    """
    Get APK path from command-line argument.

    Example:

        python analyze.py a.apk

    If no argument is provided, defaults to:

        a.apk
    """

    if len(sys.argv) >= 2:

        apk_argument = sys.argv[1]

        apk_path = Path(
            apk_argument
        )

        if not apk_path.is_absolute():

            apk_path = (
                Path.cwd()
                / apk_path
            )

        return apk_path.resolve()

    return (
        BASE_DIR / "a.apk"
    ).resolve()


# ============================================================
# PRINT SECTION
# ============================================================

def print_section(title):
    """
    Print a consistent console section header.
    """

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("       FLUTTER / DART APK RECONSTRUCTION ANALYZER")
    print("=" * 70)

    # --------------------------------------------------------
    # Get APK
    # --------------------------------------------------------

    apk_path = get_apk_path()

    apk_name = apk_path.name

    # --------------------------------------------------------
    # Check APK
    # --------------------------------------------------------

    if not apk_path.exists():

        print()
        print("[!] APK not found:")
        print("    ", apk_path)

        print()
        print("Usage:")
        print("    python analyze.py a.apk")

        sys.exit(1)

    if not apk_path.is_file():

        print()
        print("[!] APK path is not a file:")
        print("    ", apk_path)

        sys.exit(1)

    # --------------------------------------------------------
    # APK information
    # --------------------------------------------------------

    print()
    print("[+] APK:")
    print("    ", apk_path)

    print()
    print("[+] Size:")
    print(
        "    ",
        f"{apk_path.stat().st_size:,}",
        "bytes"
    )

    apk_hash = sha256(
        apk_path
    )

    print()
    print("[+] SHA256:")
    print("    ", apk_hash)

    print()
    print("[+] Preferred architecture:")
    print("    ", TARGET_ARCH)

    # ========================================================
    # 1. EXTRACT APK
    # ========================================================

    print_section(
        "1. APK EXTRACTION"
    )

    try:

        extract_apk(
            apk_path=apk_path,
            files_dir=FILES
        )

    except Exception as e:

        print()
        print(
            "[!] APK extraction failed:"
        )

        print(
            "    ",
            e
        )

        sys.exit(1)

    # ========================================================
    # 1B. DIRECT APK STRUCTURE
    # ========================================================

    print_section(
        "1B. DIRECT APK STRUCTURE ANALYSIS"
    )

    try:

        apk_structure = analyze_apk_structure(
            apk_path=apk_path,
            output_dir=OUTPUT
        )

    except Exception as e:

        apk_structure = {}

        print(
            "[!] APK structure analysis failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 1C. DEX ANALYSIS
    # ========================================================

    print_section(
        "1C. DEX ANALYSIS"
    )

    try:

        dex_analysis = analyze_dex(
            files_dir=FILES,
            output_dir=OUTPUT
        )

    except Exception as e:

        dex_analysis = []

        print(
            "[!] DEX analysis failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 1D. ANDROID MANIFEST
    # ========================================================

    print_section(
        "1D. ANDROID MANIFEST ANALYSIS"
    )

    try:

        manifest_analysis = analyze_manifest(
            files_dir=FILES,
            output_dir=OUTPUT
        )

    except Exception as e:

        manifest_analysis = {}

        print(
            "[!] Manifest analysis failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 2. FILE INVENTORY
    # ========================================================

    print_section(
        "2. FILE INVENTORY"
    )

    try:

        inventory_result = inventory(
            files_dir=FILES,
            output_dir=OUTPUT
        )

    except Exception as e:

        inventory_result = []

        print(
            "[!] File inventory failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 3. FLUTTER ANALYSIS
    # ========================================================

    print_section(
        "3. FLUTTER ANALYSIS"
    )

    try:

        libapp = prepare_flutter(
            files_dir=FILES,
            flutter_dir=FLUTTER,
            target_arch=TARGET_ARCH
        )

    except Exception as e:

        libapp = None

        print(
            "[!] Flutter binary analysis failed:"
        )

        print(
            "    ",
            e
        )

    def _selected_abi_from_libapp(path):
        if not path:
            return TARGET_ARCH
        path_str = str(path).lower()
        for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
            if abi in path_str:
                return abi
        return TARGET_ARCH

    selected_arch = _selected_abi_from_libapp(libapp)

    # --------------------------------------------------------
    # Flutter assets
    # --------------------------------------------------------

    try:

        copy_flutter_assets(
            files_dir=FILES,
            flutter_dir=FLUTTER
        )

    except Exception as e:

        print()
        print(
            "[!] Flutter asset extraction failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 4. DART ANALYSIS
    # ========================================================

    print_section(
        "4. DART / FLUTTER APPLICATION ANALYSIS"
    )

    analysis = {
        "packages": [],
        "dart_file_references": [],
        "urls": [],
        "flutter_framework_indicators": [],
        "possible_type_names": []
    }

    # --------------------------------------------------------
    # Full binary Dart analysis
    # --------------------------------------------------------

    if libapp:

        print()
        print(
            "[+] libapp.so is available."
        )

        print(
            "[+] Performing binary Dart string analysis..."
        )

        try:

            strings = extract_strings(
                binary=libapp
            )

            analysis = analyze_dart(
                strings=strings
            )

            save_dart_analysis(
                strings=strings,
                analysis=analysis,
                dart_dir=DART,
                target_arch=selected_arch
            )

            create_reconstructed_dart(
                analysis=analysis,
                dart_dir=DART,
                target_arch=selected_arch
            )

        except Exception as e:

            print()
            print(
                "[!] Dart binary analysis failed:"
            )

            print(
                "    ",
                e
            )

    # --------------------------------------------------------
    # IMPORTANT FALLBACK
    # --------------------------------------------------------

    else:

        print()
        print(
            "[!] libapp.so was not found."
        )

        print()
        print(
            "[+] This does NOT prove that the application "
            "was not Flutter."
        )

        print()
        print(
            "[+] Continuing reconstruction using:"
        )

        print(
            "    - Flutter assets"
        )

        print(
            "    - AndroidManifest.xml"
        )

        print(
            "    - DEX files"
        )

        print(
            "    - JADX"
        )

        print(
            "    - Apktool"
        )

        print(
            "    - APK ZIP structure"
        )

    # ========================================================
    # 5. CONFIGURATION
    # ========================================================

    print_section(
        "5. CONFIGURATION ANALYSIS"
    )

    try:

        find_configuration(
            files_dir=FILES,
            config_dir=CONFIG
        )

    except Exception as e:

        print(
            "[!] Configuration analysis failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 6. SENSITIVE FILE ANALYSIS
    # ========================================================

    print_section(
        "6. SENSITIVE FILE / SECRET INDICATOR ANALYSIS"
    )

    try:

        sensitive_findings = find_sensitive_files(
            files_dir=FILES,
            config_dir=CONFIG
        )

    except Exception as e:

        sensitive_findings = []

        print(
            "[!] Sensitive-file analysis failed:"
        )

        print(
            "    ",
            e
        )

    # Keep available for future extensions.
    _ = sensitive_findings

    # ========================================================
    # 7. NATIVE LIBRARIES
    # ========================================================

    print_section(
        "7. NATIVE LIBRARY ANALYSIS"
    )

    try:

        native_results = analyze_native(
            files_dir=FILES,
            native_dir=NATIVE
        )

    except Exception as e:

        native_results = []

        print(
            "[!] Native analysis failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 8. JADX
    # ========================================================

    print_section(
        "8. JADX JAVA / KOTLIN ANALYSIS"
    )

    try:

        jadx_result = run_jadx(
            apk_path=apk_path,
            java_source_dir=JAVA_SOURCE
        )

    except Exception as e:

        jadx_result = 1

        print(
            "[!] JADX execution failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 9. APKTOOL
    # ========================================================

    print_section(
        "9. APKTOOL RESOURCE ANALYSIS"
    )

    try:

        apktool_result = run_apktool(
            apk_path=apk_path,
            decoded_dir=DECODED
        )

    except Exception as e:

        apktool_result = 1

        print(
            "[!] Apktool execution failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # 10. FINAL REPORT
    # ========================================================

    print_section(
        "10. FINAL REPORT"
    )

    try:

        report = create_report(
            apk_name=apk_name,
            apk_path=apk_path,
            output_dir=OUTPUT,
            analysis=analysis,
            libapp=libapp,
            target_arch=selected_arch
        )

    except Exception as e:

        report = {}

        print(
            "[!] Final report creation failed:"
        )

        print(
            "    ",
            e
        )

    # Keep variables available for future extensions.
    _ = (
        apk_structure,
        dex_analysis,
        manifest_analysis,
        inventory_result,
        native_results,
        jadx_result,
        apktool_result,
        report,
    )

    # ========================================================
    # 11. FLUTTER PROJECT RECONSTRUCTION
    # ========================================================

    print_section(
        "11. FLUTTER PROJECT RECONSTRUCTION"
    )

    try:

        reconstruction = generate_flutter_project(
            output_dir=RECONSTRUCTED,
            analysis=analysis,
            flutter_dir=FLUTTER,
            java_source_dir=JAVA_SOURCE,
            decoded_dir=DECODED,
            apk_path=apk_path,
        )

    except Exception as e:

        reconstruction = {}

        print(
            "[!] Flutter project reconstruction failed:"
        )

        print(
            "    ",
            e
        )

    # ========================================================
    # COMPLETE
    # ========================================================

    print()
    print("=" * 70)
    print("                       ANALYSIS COMPLETE")
    print("=" * 70)

    print()
    print("[+] APK:")
    print("    ", apk_path)

    print()
    print("[+] Output:")
    print("    ", OUTPUT)

    print()
    print("[+] APK structure:")
    print("    ", OUTPUT / "apk_structure.json")

    print()
    print("[+] DEX analysis:")
    print("    ", OUTPUT / "dex_analysis")

    print()
    print("[+] Manifest analysis:")
    print("    ", OUTPUT / "manifest_analysis.json")

    print()
    print("[+] Flutter assets:")
    print("    ", FLUTTER)

    print()
    print("[+] Dart reconstruction:")
    print("    ", DART / selected_arch)

    print()
    print("[+] Reconstructed Flutter project:")
    print("    ", RECONSTRUCTED)

    print()
    print("[+] JADX:")
    print("    ", JAVA_SOURCE)

    print()
    print("[+] Apktool:")
    print("    ", DECODED)

    print()
    print("[+] Configuration:")
    print("    ", CONFIG)

    print()
    print("[+] Native libraries:")
    print("    ", NATIVE)

    # ========================================================
    # FLUTTER RESULT
    # ========================================================

    print()

    if libapp:

        print(
            "[+] libapp.so successfully analyzed."
        )

        print(
            "[+] Selected ABI:",
            selected_arch
        )

        print(
            "[+] Dart file references:",
            len(
                analysis[
                    "dart_file_references"
                ]
            )
        )

        print(
            "[+] Packages:",
            len(
                analysis[
                    "packages"
                ]
            )
        )

        print(
            "[+] URLs:",
            len(
                analysis[
                    "urls"
                ]
            )
        )

        print(
            "[+] Possible types:",
            len(
                analysis[
                    "possible_type_names"
                ]
            )
        )

    else:

        print(
            "[!] libapp.so was not found."
        )

        print()
        print(
            "[+] Flutter reconstruction will rely on "
            "the surviving APK evidence."
        )

        print(
            "[+] Check:"
        )

        print(
            "    ",
            OUTPUT / "apk_structure.json"
        )

        print(
            "    ",
            OUTPUT / "dex_analysis"
        )

        print(
            "    ",
            OUTPUT / "java_source"
        )

        print(
            "    ",
            OUTPUT / "decoded"
        )

        print(
            "    ",
            FLUTTER
        )

    print()
    print(
        "[+] SHA256:",
        apk_hash
    )

    print()
    print(
        "Next step: inspect the generated reconstruction reports."
    )

    _ = reconstruction


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
