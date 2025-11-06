import os
import hashlib
import csv
import json
import mimetypes
import math
import argparse
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)  # Enable colored output


# --- Step 1: calculate file hashes efficiently ---
def calculate_hashes(file_path, chunk_size=8192):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha256.update(chunk)
    except Exception as e:
        return None, None, f"Error reading file: {e}"
    return md5.hexdigest(), sha256.hexdigest(), None


# --- Step 2: calculate file entropy (measure randomness) ---
def calculate_entropy(file_path, chunk_size=8192):
    try:
        freq = [0] * 256
        total_bytes = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                total_bytes += len(chunk)
                for byte in chunk:
                    freq[byte] += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0
        for fcount in freq:
            if fcount:
                p = fcount / total_bytes
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return None


# --- Step 3: get file info ---
def get_file_info(file_path):
    try:
        stats = os.stat(file_path)
        size = stats.st_size
        ctime = datetime.fromtimestamp(stats.st_ctime)
        mtime = datetime.fromtimestamp(stats.st_mtime)
        file_type, _ = mimetypes.guess_type(file_path)
        return size, ctime, mtime, file_type or "Unknown"
    except Exception as e:
        return None, None, None, f"Error getting info: {e}"


# --- Step 4: human-readable file size ---
def human_readable_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0


# --- Step 5: analyze single file ---
def analyze_file(file_path):
    size, ctime, mtime, file_type = get_file_info(file_path)
    if size is None:
        return {"File Name": os.path.basename(file_path), "Error": file_type}

    md5, sha256, hash_error = calculate_hashes(file_path)
    if hash_error:
        return {"File Name": os.path.basename(file_path), "Error": hash_error}

    entropy = calculate_entropy(file_path)

    flag = ""
    if mtime < ctime:
        flag = "⚠ Modified before created (possible tampering)"
    elif entropy and entropy > 7.5:
        flag = "⚠ High entropy (possibly encrypted/compressed)"
    else:
        flag = "OK"

    return {
        "File Name": os.path.basename(file_path),
        "Path": file_path,
        "File Type": file_type,
        "Size": f"{size:,} bytes ({human_readable_size(size)})",
        "Entropy": entropy,
        "Created": ctime.strftime("%Y-%m-%d %H:%M:%S"),
        "Modified": mtime.strftime("%Y-%m-%d %H:%M:%S"),
        "MD5": md5,
        "SHA256": sha256,
        "Flag": flag
    }


# --- Step 6: analyze all files with progress bar ---
def analyze_folder(folder_path):
    results = []
    all_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            all_files.append(os.path.join(root, f))

    print(Fore.CYAN + f"🔍 Analyzing {len(all_files)} files...\n")
    for file_path in tqdm(all_files, desc="Processing files", unit="file"):
        result = analyze_file(file_path)
        results.append(result)

    print(Fore.GREEN + f"\n✅ Analysis complete. {len(results)} files processed.\n")
    return results


# --- Step 7: detect duplicate files based on hash ---
def find_duplicates(results):
    hash_map = {}
    duplicates = []
    for entry in results:
        file_hash = entry.get("SHA256")
        if not file_hash:
            continue
        if file_hash in hash_map:
            duplicates.append((hash_map[file_hash], entry["Path"]))
        else:
            hash_map[file_hash] = entry["Path"]

    if duplicates:
        print(Fore.YELLOW + "⚠ Duplicate files found:")
        for dup1, dup2 in duplicates:
            print(f"   - {dup1}\n     {dup2}")
    else:
        print(Fore.GREEN + "✅ No duplicates detected.")
    print()
    return duplicates


# --- Step 8: save reports ---
def save_to_csv(results, output_folder="reports"):
    os.makedirs(output_folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_folder, f"report_{timestamp}.csv")

    valid_results = [r for r in results if "Error" not in r]
    if not valid_results:
        print("⚠ No valid files to save.")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=valid_results[0].keys())
        writer.writeheader()
        writer.writerows(valid_results)

    print(Fore.BLUE + f"📊 CSV report saved: {output_path}")


def save_to_json(results, output_folder="reports"):
    os.makedirs(output_folder, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_folder, f"report_{timestamp}.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, default=str)

    print(Fore.BLUE + f"📘 JSON report saved: {output_path}")


# --- Step 9: CLI interface ---
def main():
    parser = argparse.ArgumentParser(
        description="📁 Metadata Analyzer — Analyze file metadata, hashes, entropy, and duplicates."
    )
    parser.add_argument("--folder", "-f", required=True, help="Folder to analyze")
    parser.add_argument("--json", action="store_true", help="Export results to JSON")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV")
    parser.add_argument("--duplicates", action="store_true", help="Check for duplicate files")
    args = parser.parse_args()

    if not os.path.exists(args.folder):
        print(Fore.RED + f"❌ Folder not found: {args.folder}")
        return

    results = analyze_folder(args.folder)

    if args.duplicates:
        find_duplicates(results)

    if args.csv:
        save_to_csv(results)
    if args.json:
        save_to_json(results)


if __name__ == "__main__":
    main()
