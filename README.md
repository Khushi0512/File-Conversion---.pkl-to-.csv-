# pkl-to-csv (IoMT)

Converts the NumPy pickle datasets stored inside a zip archive into labelled CSV files, without extracting or changing the archive. It is built for the **IoMT-TrafficData** intrusion-detection dataset (`ML-Based IDS IoMT.zip`), whose ML-ready train/validation/test splits are available only as `.pkl` files.

---

## Why this exists
For the dataset of my project used:
The folder `Dataset & Captures/Datasets/IP-Based/Packets/Pickle Datasets/` holds 9 pickle files with no CSV version:

| Pickle file | Rows | Feature columns | Label columns (one-hot) |
|---|---|---|---|
| `Dataset.pkl` | 1,000,000 | 38 | 2 |
| `Dataset_Binary.pkl` | 1,000,000 | 23 | 2 |
| `Dataset_Multiclass.pkl` | 1,000,000 | 23 | 9 |
| `Training_Binary.pkl` | 562,500 | 23 | 2 |
| `Validation_Binary.pkl` | 187,500 | 23 | 2 |
| `Testing_Binary.pkl` | 250,000 | 23 | 2 |
| `Training_Multiclass.pkl` | 562,500 | 23 | 9 |
| `Validation_Multiclass.pkl` | 187,500 | 23 | 9 |
| `Testing_Multiclass.pkl` | 250,000 | 23 | 9 |

Pickles can only be opened from Python, and loading an untrusted pickle can run arbitrary code. This script turns them into plain CSV files that open in Excel, MATLAB, R or pandas, and it loads them safely.

---

## Features

- **Reads straight from the zip without changing it.** You don't unzip anything. The archive is opened for reading only, and each pickle is copied out, one at a time, to a temporary folder in 16 MB chunks. The temporary copy is deleted right after loading, even if loading fails.
- **Safe loading:** a restricted unpickler rebuilds NumPy objects only. Any other object type in a pickle stops the script with an error instead of running.
- **Real column names:** the 23 feature columns are named from the header of `IP-Based Packets Pre-Processed Dataset.csv` in the same zip (same order, with `is_malicious` and `attack_type` removed). `Dataset.pkl` has no stored names, so its columns are called `f00`–`f37`.
- **Readable labels:** the one-hot label matrix becomes a class index (`label`) and a class name (`label_name`). The original one-hot columns (`y_0 … y_k`) can be kept with `--onehot`.
- **Mixed-type cleanup:** `Dataset.pkl` stores numbers mixed with the text value `'-1'` (object dtype). All values are converted to numbers, so `'-1'` becomes `-1`.
- **Exact values:** floats are written with 17 significant digits, so values read back identical to the pickle (`pandas.read_csv(..., float_precision="round_trip")`).
- **Handles large files:** rows are written in blocks (default 100,000) with progress logging.
- **Finds the zip on its own:** script folder → parent folder → current folder.

---

## Output format

One CSV per pickle, named after it (e.g. `Testing_Multiclass.pkl` → `Testing_Multiclass.csv`).

| Column group | Contents |
|---|---|
| Features (23 files) | `http.content_length`, `http.request`, `http.response.code`, `http.response_number`, `http.time`, `tcp.analysis.initial_rtt`, `tcp.connection.fin`, `tcp.connection.syn`, `tcp.connection.synack`, `tcp.flags.cwr`, `tcp.flags.ecn`, `tcp.flags.fin`, `tcp.flags.ns`, `tcp.flags.res`, `tcp.flags.syn`, `tcp.flags.urg`, `tcp.urgent_pointer`, `ip.frag_offset`, `eth.dst.ig`, `eth.src.ig`, `eth.src.lg`, `eth.src_not_group`, `arp.isannouncement` |
| Features (`Dataset.pkl`) | `f00` – `f37` (column `f27` holds the attack-type code) |
| `label` | Class index (argmax of the one-hot row) |
| `label_name` | Class name (table below) |
| `y_0 … y_k` | Original one-hot columns (only with `--onehot`) |

### Class mapping

| `label` | Multiclass `label_name` | Binary `label_name` |
|---|---|---|
| 0 | Normal | Normal |
| 1 | Apache Killer | Malicious |
| 2 | RUDY | n/a |
| 3 | Slow Read | n/a |
| 4 | Slow Loris | n/a |
| 5 | ARP Spoofing | n/a |
| 6 | CAM Overflow | n/a |
| 7 | MQTT Malaria | n/a |
| 8 | Net Scan | n/a |

---

## Requirements

- Python 3.8+
- NumPy (`python -m pip install numpy`)
- About 2 GB of free disk space for all nine CSVs

---

## Usage

```bash
# Convert all 9 pickles (zip next to the script or in its parent folder)
python pkl_to_csv.py

# Zip somewhere else
python pkl_to_csv.py --zip "E:\ML-Based IDS IoMT.zip"

# Only the test splits
python pkl_to_csv.py --only Testing_Binary Testing_Multiclass

# Keep one-hot columns and choose an output folder
python pkl_to_csv.py --onehot --out D:\iomt_csv
```

### Options

| Option | Description | Default |
|---|---|---|
| `--zip PATH` | Path to `ML-Based IDS IoMT.zip` | Auto-detected |
| `--out DIR` | Output folder | `converted_csv` next to the zip |
| `--only NAME [NAME ...]` | Convert only the listed pickles (names without `.pkl`) | All nine |
| `--onehot` | Also write the one-hot label columns `y_0 … y_k` | Off |
| `--chunk N` | Rows written per block | `100000` |

---

## How it works

1. Find the zip and the output folder.
2. Read the header line of `IP-Based Packets Pre-Processed Dataset.csv` from the zip to get the 23 feature names.
3. For each selected pickle:
   1. Copy the `.pkl` out of the zip into a temporary folder (the archive stays unchanged).
   2. Load it with the NumPy-only unpickler, then delete the temporary copy.
   3. Check that it contains `[X, Y]`, convert `X` to 64-bit floats, and compute `label = argmax(Y)`.
   4. Pick the feature names: the 23 real names if the column count matches, otherwise `f00 …`.
   5. Write the CSV block by block: features, `label`, `label_name`, and the one-hot columns if requested.
4. Log the shape, the class counts and the output path for each file.

---

## Limitations

- `Dataset.pkl` column names aren't stored anywhere in the archive, so its columns use generic names.
- The CSVs are several times larger than the pickles, because text takes more space than binary numbers.
- Existing output files with the same name are overwritten.
- File names and paths are hard-coded for the IoMT-TrafficData layout. Edit `NAMES`, `PKL_DIR` and `HEADER_SRC` to use it with another archive.

---

## Dataset reference

Areia et al., *IoMT-TrafficData: Dataset and Tools for Benchmarking Intrusion Detection in Internet of Medical Things*, IEEE Access, 2024. [IEEE Xplore](https://ieeexplore.ieee.org/abstract/document/10620207/)
