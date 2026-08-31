import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path


# ============================================================
# SHA256
# ============================================================

def sha256(path):
    path = Path(path)

    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


# ============================================================
# WRITE TEXT
# ============================================================

def write_text(path, text):
    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    path.write_text(
        text,
        encoding="utf-8",
        errors="replace"
    )


# ============================================================
# RUN COMMAND
# ============================================================

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

        output = result.stdout or ""

        if len(output) > 8000:
            print(output[-8000:])
        else:
            print(output)

        if result.returncode == 0:
            print("[+] Command completed successfully.")
        else:
            print("[!] Command returned:", result.returncode)

        return result.returncode

    except Exception as e:
        print("[!] Command failed:", e)
        return 1


# ============================================================
# RUN COMMAND AND CAPTURE OUTPUT
# ============================================================

def run_command_capture(command, cwd=None):
    """
    Run a command and return (returncode, combined_output).
    """

    try:

        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace"
        )

        return (
            result.returncode,
            result.stdout or ""
        )

    except Exception as e:

        return (
            1,
            str(e)
        )


# ============================================================
# APK EXTRACTION
# ============================================================

def extract_apk(apk_path, files_dir):
    """
    Extract APK ZIP archive.

    Existing extraction directory is removed first so that
    files from an older APK cannot contaminate the analysis.
    """

    apk_path = Path(apk_path)
    files_dir = Path(files_dir)

    print()
    print("[+] Extracting APK...")

    if not zipfile.is_zipfile(apk_path):
        raise ValueError(
            f"Not a valid ZIP/APK file: {apk_path}"
        )

    if files_dir.exists():
        import shutil
        shutil.rmtree(files_dir)

    files_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    with zipfile.ZipFile(
        apk_path,
        "r"
    ) as archive:

        archive.extractall(
            files_dir
        )

    print("[+] Extraction complete.")


# ============================================================
# APK ZIP INVENTORY
# ============================================================

def inspect_apk_archive(apk_path):
    """
    Inspect the APK directly without extracting it.

    This is important because the old analyzer only searched
    the extracted filesystem.
    """

    apk_path = Path(apk_path)

    result = {
        "entries": [],
        "native_libraries": [],
        "dex_files": [],
        "flutter_assets": [],
        "nested_apks": [],
        "split_indicators": [],
        "abi_directories": [],
    }

    with zipfile.ZipFile(
        apk_path,
        "r"
    ) as archive:

        for info in archive.infolist():

            name = info.filename

            result["entries"].append({
                "name": name,
                "size": info.file_size,
                "compressed_size": info.compress_size,
            })

            lower = name.lower()

            # Native libraries
            if lower.endswith(".so"):
                result["native_libraries"].append(name)

            # DEX
            if re.match(
                r"(^|/)classes\d*\.dex$",
                lower
            ):
                result["dex_files"].append(name)

            # Flutter assets
            if "assets/flutter_assets/" in lower:
                result["flutter_assets"].append(name)

            # Nested APK
            if lower.endswith(".apk"):
                result["nested_apks"].append(name)

            # Split APK / bundle indicators
            if (
                "split" in lower
                or "config." in lower
                or "base-master" in lower
                or "toc.pb" in lower
            ):
                result["split_indicators"].append(name)

            # ABI
            match = re.search(
                r"(?:^|/)lib/([^/]+)/",
                name
            )

            if match:
                abi = match.group(1)

                if abi not in result["abi_directories"]:
                    result["abi_directories"].append(
                        abi
                    )

    result["abi_directories"].sort()
    result["native_libraries"].sort()
    result["dex_files"].sort()
    result["flutter_assets"].sort()
    result["nested_apks"].sort()

    return result


# ============================================================
# EXTRACT NATIVE LIBRARIES DIRECTLY FROM APK
# ============================================================

def extract_native_from_apk(
    apk_path,
    destination
):
    """
    Extract every .so directly from the APK.

    This catches native libraries even if the normal
    filesystem assumptions are wrong.
    """

    apk_path = Path(apk_path)
    destination = Path(destination)

    destination.mkdir(
        parents=True,
        exist_ok=True
    )

    found = []

    with zipfile.ZipFile(
        apk_path,
        "r"
    ) as archive:

        for info in archive.infolist():

            name = info.filename

            if not name.lower().endswith(".so"):
                continue

            target = (
                destination
                / Path(name)
            )

            target.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with archive.open(info) as source:
                with open(target, "wb") as output:
                    output.write(
                        source.read()
                    )

            found.append(
                {
                    "archive_path": name,
                    "extracted_path": str(target),
                    "size": info.file_size,
                }
            )

    return found


# ============================================================
# READ TEXT FILE SAFELY
# ============================================================

def read_text_file(path):
    path = Path(path)

    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except Exception:
        return ""
