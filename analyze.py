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
    find_configuration,
    find_sensitive_files,
    analyze_native,
    run_jadx,
    run_apktool,
    create_report,
)


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

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

        apk_path = Path(apk_argument)

        # If relative path was supplied, resolve it
        # relative to the current working directory.
        if not apk_path.is_absolute():
            apk_path = Path.cwd() / apk_path

        return apk_path.resolve()

    return (
        BASE_DIR / "a.apk"
    ).resolve()


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("       FLUTTER / DART ARM64 APK ANALYZER")
    print("=" * 70)

    # --------------------------------------------------------
    # Get APK
    # --------------------------------------------------------

    apk_path = get_apk_path()

    # APK name used in reports.
    apk_name = apk_path.name

    # --------------------------------------------------------
    # Check APK
    # --------------------------------------------------------

    if not apk_path.exists():

        print()
        print(
            "[!] APK not found:"
        )

        print(
            "    ",
            apk_path
        )

        print()
        print(
            "Usage:"
        )

        print(
            "    python analyze.py a.apk"
        )

        sys.exit(1)

    if not apk_path.is_file():

        print()
        print(
            "[!] APK path is not a file:"
        )

        print(
            "    ",
            apk_path
        )

        sys.exit(1)

    # --------------------------------------------------------
    # APK information
    # --------------------------------------------------------

    print()
    print(
        "[+] APK:",
        apk_path
    )

    print(
        "[+] Size:",
        f"{apk_path.stat().st_size:,}",
        "bytes"
    )

    print(
        "[+] SHA256:",
        sha256(apk_path)
    )

    print()
    print(
        "[+] Target architecture:",
        TARGET_ARCH
    )

    # --------------------------------------------------------
    # 1. Extract APK
    # --------------------------------------------------------

    extract_apk(
        apk_path=apk_path,
        files_dir=FILES
    )

    # --------------------------------------------------------
    # 2. File inventory
    # --------------------------------------------------------

    inventory(
        files_dir=FILES,
        output_dir=OUTPUT
    )

    # --------------------------------------------------------
    # 3. Flutter analysis
    # --------------------------------------------------------

    libapp = prepare_flutter(
        files_dir=FILES,
        flutter_dir=FLUTTER,
        target_arch=TARGET_ARCH
    )

    copy_flutter_assets(
        files_dir=FILES,
        flutter_dir=FLUTTER
    )

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
            target_arch=TARGET_ARCH
        )

        create_reconstructed_dart(
            analysis=analysis,
            dart_dir=DART,
            target_arch=TARGET_ARCH
        )

    # --------------------------------------------------------
    # 5. Configuration analysis
    # --------------------------------------------------------

    find_configuration(
        files_dir=FILES,
        config_dir=CONFIG
    )

    # --------------------------------------------------------
    # 6. Sensitive file / secret analysis
    # --------------------------------------------------------

    sensitive_findings = find_sensitive_files(
        files_dir=FILES,
        config_dir=CONFIG
    )

    # Keep available for future extensions.
    _ = sensitive_findings

    # --------------------------------------------------------
    # 7. Native libraries
    # --------------------------------------------------------

    analyze_native(
        files_dir=FILES,
        native_dir=NATIVE
    )

    # --------------------------------------------------------
    # 8. JADX
    # --------------------------------------------------------

    run_jadx(
        apk_path=apk_path,
        java_source_dir=JAVA_SOURCE
    )

    # --------------------------------------------------------
    # 9. Apktool
    # --------------------------------------------------------

    run_apktool(
        apk_path=apk_path,
        decoded_dir=DECODED
    )

    # --------------------------------------------------------
    # 10. Final report
    # --------------------------------------------------------

    create_report(
        apk_name=apk_name,
        apk_path=apk_path,
        output_dir=OUTPUT,
        analysis=analysis,
        libapp=libapp,
        target_arch=TARGET_ARCH
    )

    # --------------------------------------------------------
    # COMPLETE
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("                       COMPLETE")
    print("=" * 70)

    print()
    print(
        "[+] APK:"
    )

    print(
        "    ",
        apk_path
    )

    print()
    print(
        "[+] Output:"
    )

    print(
        "    ",
        OUTPUT
    )

    print()
    print(
        "[+] ARM64 Dart analysis:"
    )

    print(
        "    ",
        DART / TARGET_ARCH
    )

    print()
    print(
        "[+] JADX:"
    )

    print(
        "    ",
        JAVA_SOURCE
    )

    print()
    print(
        "[+] Configuration:"
    )

    print(
        "    ",
        CONFIG
    )

    print()

    if libapp:

        print(
            "[+] ARM64 libapp.so successfully analyzed."
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
            "[!] ARM64 libapp.so not found."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()