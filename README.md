# 📊 File Metadata Analyzer

A Python-based command-line tool to analyze file metadata, compute hashes, detect duplicates, and export results in CSV or JSON format.

---

## 🚀 Features
- Extracts metadata (size, timestamps, hashes)
- Finds duplicate files using SHA256
- Exports data to CSV and JSON
- Displays real-time progress bars
- Color-coded console output for readability

---

## 🛠️ Installation
```bash
git clone https://github.com/sahilmaurya2006/file-metadata-analyzer.git
cd file-metadata-analyzer
pip install -r requirements.txt

💻 Usage

Analyze a folder:
python metadata_analyzer.py -f sample_files

Export results:
python metadata_analyzer.py -f sample_files --csv --json

Check duplicates:
python metadata_analyzer.py -f sample_files --duplicates

Run from global command (after setup install):
meta-analyze -f sample_files --csv

📁 Output

Reports are saved automatically in the /reports folder:
report.csv
report.json
