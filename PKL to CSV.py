import argparse
import io
import os
import pickle
import shutil
import sys
import tempfile
import time
import zipfile

try:
    import numpy as np
except ImportError:
    sys.exit("ERROR: numpy is required.  Install it with:  python -m pip install numpy")

ZIP_NAME = "Enter_ZIP_FILE_NAME" #enter zip file name
PKL_DIR = "PARENT_FOLDER/SECONDARY FOLDER(IF ANY)/TARGATTED FOLDER/" #enter the targetted folder path
HEADER_SRC = "PARENT_FOLDER/SECONDARY_FOLDER (IF ANY)/TARGET.csv" #enter required path
NAMES = ["Dataset", "Dataset_Binary", "Dataset_Multiclass",
         "Training_Binary", "Validation_Binary", "Testing_Binary",
         "Training_Multiclass", "Validation_Multiclass", "Testing_Multiclass"]
MULTI = ["Normal", "Apache Killer", "RUDY", "Slow Read", "Slow Loris",
         "ARP Spoofing", "CAM Overflow", "MQTT Malaria", "Net Scan"]
BINARY = ["Normal", "Malicious"]


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


class NumpyOnlyUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "numpy" or module.startswith("numpy."):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked non-NumPy object in pickle: {module}.{name}")


def find_zip(user_path):
    if user_path:
        if os.path.isfile(user_path):
            return os.path.abspath(user_path)
        sys.exit(f"ERROR: zip not found: {user_path}")
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (here, os.path.dirname(here), os.getcwd()):
        p = os.path.join(folder, ZIP_NAME)
        if os.path.isfile(p):
            return p
    sys.exit(f'ERROR: "{ZIP_NAME}" not found next to the script or in its parent folder. '
             f'Pass it with --zip "C:\\path\\to\\{ZIP_NAME}"')


def to_float(X):
    if X.dtype != object:
        return X.astype(np.float64, copy=False)
    out = np.empty(X.shape, dtype=np.float64)
    for j in range(X.shape[1]):
        col = X[:, j]
        try:
            out[:, j] = col.astype(np.float64)
        except (ValueError, TypeError):
            out[:, j] = [float(v) if v not in (None, "") else np.nan for v in col]
    return out


def main():
    ap = argparse.ArgumentParser(description="Convert the IoMT pickle datasets to CSV.")
    ap.add_argument("--zip", help=f'Path to "{ZIP_NAME}" (default: searched next to this script)')
    ap.add_argument("--out", help='Output folder (default: "converted_csv" next to the zip)')
    ap.add_argument("--only", nargs="+", choices=NAMES, help="Convert only these pickles")
    ap.add_argument("--onehot", action="store_true", help="Also write the one-hot label columns y_0..y_k")
    ap.add_argument("--chunk", type=int, default=100000, help="Rows written per block (default 100000)")
    a = ap.parse_args()

    zpath = find_zip(a.zip)
    out_dir = a.out or os.path.join(os.path.dirname(zpath), "converted_csv")
    os.makedirs(out_dir, exist_ok=True)
    log(f"Zip:    {zpath}")
    log(f"Output: {out_dir}")

    with zipfile.ZipFile(zpath) as zf:
        with zf.open(HEADER_SRC) as fh:
            src_cols = fh.readline().decode("utf-8", "replace").rstrip("\r\n").split(",")
        feat23 = [c for c in src_cols if c not in ("is_malicious", "attack_type")]

        for name in (a.only or NAMES):
            member = PKL_DIR + name + ".pkl"
            log(f"=== {name}.pkl")
            tmp = tempfile.mkdtemp(prefix="iomt_", dir=out_dir)
            try:
                path = os.path.join(tmp, name + ".pkl")
                with zf.open(member) as src, open(path, "wb") as dst:
                    shutil.copyfileobj(src, dst, 16 * 1024 * 1024)
                with open(path, "rb") as f:
                    obj = NumpyOnlyUnpickler(f).load()
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

            if not (isinstance(obj, (list, tuple)) and len(obj) == 2):
                log(f"  Skipped: unexpected structure ({type(obj).__name__})")
                continue
            X, Y = obj
            X = to_float(np.asarray(X))
            Y = np.asarray(Y)
            n, k = X.shape[0], X.shape[1]
            labels = Y.argmax(axis=1)
            classes = MULTI if Y.shape[1] == len(MULTI) else BINARY
            fcols = feat23 if k == len(feat23) else [f"f{j:02d}" for j in range(k)]
            header = fcols + ["label", "label_name"] + ([f"y_{j}" for j in range(Y.shape[1])] if a.onehot else [])
            log(f"  X {X.shape}, Y {Y.shape}, feature names: "
                + ("from pre-processed CSV header" if fcols is feat23 else "generic f00..")
                + f", classes: {dict(zip(*[v.tolist() for v in np.unique(labels, return_counts=True)]))}")

            out_csv = os.path.join(out_dir, name + ".csv")
            with open(out_csv, "w", newline="", encoding="utf-8") as fo:
                fo.write(",".join(header) + "\n")
                for s in range(0, n, a.chunk):
                    e = min(n, s + a.chunk)
                    buf = io.StringIO()
                    np.savetxt(buf, X[s:e], delimiter=",", fmt="%.17g")
                    feat_lines = buf.getvalue().splitlines()
                    lab = labels[s:e]
                    extra = Y[s:e].astype(np.int8) if a.onehot else None
                    lines = []
                    for i, fl in enumerate(feat_lines):
                        row = f"{fl},{int(lab[i])},{classes[int(lab[i])]}"
                        if extra is not None:
                            row += "," + ",".join(map(str, extra[i].tolist()))
                        lines.append(row)
                    fo.write("\n".join(lines) + "\n")
                    log(f"  {e:,} / {n:,} rows")
            log(f"  Done -> {out_csv}")
            del obj, X, Y
    log("All conversions finished.")


if __name__ == "__main__":
    main()
