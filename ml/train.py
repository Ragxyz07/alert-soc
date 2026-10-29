"""Train a small, explainable CIC-IDS2017 classifier and BENIGN anomaly model."""
from pathlib import Path
import json
import glob
import os
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             confusion_matrix, classification_report)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
OUT = Path(__file__).resolve().parent
LABEL = "Label"
KEEP = {"BENIGN", "DoS", "PortScan", "BruteForce", "WebAttack"}
PER_CLASS = int(os.getenv("SOC_SAMPLE_PER_CLASS", "12000"))

def canonical_label(value):
    value = str(value).strip()
    low = value.lower()
    if low == "benign": return "BENIGN"
    if "portscan" in low: return "PortScan"
    if low.startswith("dos") or low == "ddos" or low == "heartbleed": return "DoS"
    if "patator" in low or "brute force" in low: return "BruteForce"
    if "web attack" in low or "xss" in low or "sql injection" in low: return "WebAttack"
    return value

def load_sample(limit=PER_CLASS):
    files = sorted(glob.glob(str(DATA / "**" / "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSV files found beneath {DATA}")
    chunks = []
    print("CSV column names and raw label counts:")
    raw_counts = {}
    for file in files:
        header = pd.read_csv(file, nrows=0, encoding="latin1")
        cols = [str(c).strip() for c in header.columns]
        print(f"\n{Path(file).name}: {cols}")
        label_col = next((c for c in header.columns if str(c).strip().lower() == "label"), None)
        counts = {}
        for frame in pd.read_csv(file, encoding="latin1", low_memory=False, chunksize=100000):
            labels = frame[label_col].astype(str).str.strip().value_counts()
            for k, v in labels.items(): counts[k] = counts.get(k, 0) + int(v)
        print(f"Label counts: {counts}")
        for k, v in counts.items(): raw_counts[k] = raw_counts.get(k, 0) + v
        # Keep a bounded random sample per file, retaining rare attack rows.
        frame = pd.read_csv(file, encoding="latin1", low_memory=False)
        frame.columns = [str(c).strip() for c in frame.columns]
        frame[LABEL] = frame[LABEL].map(canonical_label)
        frame = frame[frame[LABEL].isin(KEEP)]
        sampled = []
        for label, group in frame.groupby(LABEL):
            sampled.append(group.sample(min(len(group), limit), random_state=42))
        chunks.extend(sampled)
    data = pd.concat(chunks, ignore_index=True)
    data = data.drop_duplicates()
    data = data.replace([np.inf, -np.inf], np.nan).dropna()
    y = data[LABEL].astype(str)
    X = data.drop(columns=[LABEL])
    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    valid = X.notna().all(axis=1)
    X, y = X.loc[valid], y.loc[valid]
    X = X.loc[:, X.nunique(dropna=False) > 1]
    print("\nMerged class counts:", y.value_counts().to_dict())
    print("Selected classes:", sorted(y.unique().tolist()))
    return X.astype("float32"), y, raw_counts

def train():
    X, y, raw_counts = load_sample()
    if y.nunique() < 2: raise ValueError("Need at least two supported classes to train")
    xtr, xte, ytr, yte = train_test_split(X, y, test_size=.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=120, max_depth=22, min_samples_leaf=2,
                                 class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    clf.fit(xtr, ytr)
    pred = clf.predict(xte)
    labels = sorted(y.unique())
    p, r, f, support = precision_recall_fscore_support(yte, pred, labels=labels, zero_division=0)
    metrics = {
        "accuracy": float(accuracy_score(yte, pred)),
        "per_class": {label: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(support[i])} for i, label in enumerate(labels)},
        "confusion_matrix": confusion_matrix(yte, pred, labels=labels).tolist(),
        "labels": labels, "raw_label_counts": raw_counts,
        "training_rows": int(len(xtr)), "test_rows": int(len(xte)),
        "classification_report": classification_report(yte, pred, labels=labels, zero_division=0, output_dict=True),
    }
    benign = xtr.loc[ytr == "BENIGN"]
    anomaly = IsolationForest(n_estimators=100, contamination="auto", n_jobs=-1, random_state=42).fit(benign)
    model = {"classifier": clf, "anomaly": anomaly, "features": list(X.columns), "labels": labels,
             "benign_median": benign.median().to_dict(), "benign_scale": benign.std().replace(0, 1).fillna(1).to_dict()}
    dump(model, OUT / "model.joblib")
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(classification_report(yte, pred, labels=labels, zero_division=0))
    print("Confusion matrix (labels order", labels, "):\n", metrics["confusion_matrix"])
    return metrics

if __name__ == "__main__": train()
