import hashlib
import subprocess
import zipfile
from pathlib import Path


# ============================================================
# SHA256
# ============================================================

def sha256(path):
    """
    Calculate SHA256 hash of a file.

    Args:
        path: Path to the file.

    Returns:
        SHA256 hexadecimal digest.
    """

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
# WRITE TEXT FILE
# ============================================================

def write_text(path, text):
    """
    Write text to a file.

    Parent directories are automatically created.

    Args:
        path: Destination path.
        text: Text content.
    """

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
# RUN EXTERNAL COMMAND
# ============================================================

def run_command(command, title):
    """
    Execute an external shell command and display its output.

    Args:
        command: Shell command to execute.
        title: Human-readable section title.

    Returns:
        Process return code.
    """

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

        # Avoid flooding the terminal with enormous output.
        if len(output) > 8000:
            print(
                output[-8000:]
            )
        else:
            print(output)

        if result.returncode == 0:

            print(
                "[+] Command completed successfully."
            )

        else:

            print(
                "[!] Command returned:",
                result.returncode
            )

        return result.returncode

    except FileNotFoundError as e:

        print(
            "[!] Command not found:",
            e
        )

        return 1

    except Exception as e:

        print(
            "[!] Command failed:",
            e
        )

        return 1


# ============================================================
# APK EXTRACTION
# ============================================================

def extract_apk(apk_path, files_dir):
    """
    Extract the APK ZIP archive.

    Args:
        apk_path: Path to APK.
        files_dir: Destination extraction directory.
    """

    apk_path = Path(apk_path)
    files_dir = Path(files_dir)

    print()
    print(
        "[+] Extracting APK..."
    )

    files_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    try:

        with zipfile.ZipFile(
            apk_path,
            "r"
        ) as archive:

            archive.extractall(
                files_dir
            )

        print(
            "[+] Extraction complete."
        )

    except zipfile.BadZipFile:

        print(
            "[!] APK is not a valid ZIP/APK archive."
        )

        raise

    except Exception as e:

        print(
            "[!] APK extraction failed:",
            e
        )

        raise
