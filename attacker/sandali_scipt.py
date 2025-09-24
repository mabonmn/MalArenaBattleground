from pathlib import Path
import shutil
import subprocess
import csv
import sys
import os

DIR = Path("./MLSec20/originais")
KEY = Path("mykey.pem")
CERT = Path("mycert.pem")
ERRDIR = Path("errlogs")
CSV_OUT = Path("signed_results.csv")


def run(cmd, stderr_path=None):
    """Run command. Return CompletedProcess."""
    if stderr_path:
        with open(stderr_path, "wb") as ef:
            return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=ef)
    else:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def compile_to_binary(script_path):
    cmd = ["pyinstaller", "--onefile", script_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Compilation failed: {result.stderr}", file=sys.stderr)
        return None
    binary_path = Path("dist") / Path(script_path).stem
    return str(binary_path)


def mutate_with_metame(input_binary, output_binary, mutation_level=5):
    cmd = [
        "metame",
        "-i", input_binary,
        "-o", output_binary,
        "-d"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Mutation failed: {result.stderr}", file=sys.stderr)
        return False
    print(f"Mutated binary created: {output_binary}")
    return True


def main():
    ERRDIR.mkdir(parents=True, exist_ok=True)
    if not shutil.which("openssl"):
        print("Error: openssl not found in PATH. Install OpenSSL and retry.", file=sys.stderr)
        sys.exit(1)

    # Create key if missing
    if not KEY.exists():
        print(f"[+] Generating RSA key -> {KEY}")
        p = run(["openssl", "genrsa", "-out", str(KEY), "2048"])
        if p.returncode != 0:
            print("Failed to generate key", file=sys.stderr)
            sys.exit(2)

    # Write CSV header
    with CSV_OUT.open("w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["path", "status", "error"])

        # iterate files in DIR
        if not DIR.exists() or not DIR.is_dir():
            print(f"Directory not found: {DIR}", file=sys.stderr)
            sys.exit(4)

        for f in sorted(DIR.iterdir()):
            if not f.is_file():
                continue
            sig = f.with_name(f.name + ".sig")
            errlog = ERRDIR / (f.name + ".err")
            # remove old errlog if present
            if errlog.exists():
                errlog.unlink()

            cmd = ["openssl", "dgst", "-sha256", "-sign", str(KEY), "-out", str(sig), str(f)]
            proc = run(cmd, stderr_path=str(errlog))
            if proc.returncode == 0:
                writer.writerow([str(f), "ok", ""])
                print(f"Signed: {f.name}")
            else:
                # read first line of errlog for CSV
                err_line = ""
                try:
                    with errlog.open("r", encoding="utf-8", errors="replace") as ef:
                        lines = ef.read().splitlines()
                        if lines:
                            err_line = lines[0].replace(",", ";")
                except Exception:
                    err_line = "error_writing_errlog"
                writer.writerow([str(f), "error", err_line])
                print(f"Failed signing: {f.name} (see {errlog})")

    print(f"Done. CSV: {CSV_OUT}  logs: {ERRDIR}/")

    # Metamorphic transformation
    script_path = __file__  # Current script
    binary_path = compile_to_binary(script_path)
    if binary_path:
        mutate_with_metame(binary_path, "mutated_signer")


if __name__ == "__main__":
    main()