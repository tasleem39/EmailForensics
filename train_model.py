import argparse
import csv
import glob
import os
import sys

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


REQUIRED_COLUMNS = {"sender", "receiver", "subject", "body", "label", "urls"}
TEXT_COLUMNS = ["sender", "receiver", "subject", "body", "urls"]


def email_text(frame):
    combined = frame[TEXT_COLUMNS].fillna("").astype(str)
    return combined.apply(
        lambda row: "\n".join(f"{field}: {row[field]}" for field in TEXT_COLUMNS), axis=1
    )


def load_training_data(input_path):
    paths = sorted(glob.glob(os.path.join(input_path, "*.csv"))) if os.path.isdir(input_path) else [input_path]
    if not paths:
        raise ValueError(f"No CSV files found in {input_path}")

    frames = []
    used_files = []
    for path in paths:
        data = pd.read_csv(path, engine="python", on_bad_lines="warn")
        if "label" not in data.columns:
            print(f"Skipping {path}: no label column")
            continue
        for column in TEXT_COLUMNS:
            if column not in data.columns:
                data[column] = ""
        data["label"] = pd.to_numeric(data["label"], errors="coerce")
        data = data.dropna(subset=["label"])
        data["label"] = data["label"].astype(int)
        data = data[data["label"].isin([0, 1])]
        if not data.empty:
            frames.append(data[TEXT_COLUMNS + ["label"]])
            used_files.append({"file": path, "rows": len(data)})

    if not frames:
        raise ValueError("No labeled rows with binary 0/1 labels were found")
    return pd.concat(frames, ignore_index=True), used_files


def build_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
            min_df=2,
            max_features=150000,
            sublinear_tf=True,
        )),
        ("character", TfidfVectorizer(
            analyzer="char",
            lowercase=True,
            ngram_range=(3, 5),
            min_df=3,
            max_features=100000,
            sublinear_tf=True,
        )),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="liblinear",
            random_state=42,
        )),
    ])


def main():
    parser = argparse.ArgumentParser(description="Train the email spam classifier.")
    parser.add_argument("--input", default="training", help="CSV file or directory containing CSV files")
    parser.add_argument("--output", default="email_classifier.joblib")
    args = parser.parse_args()

    csv.field_size_limit(sys.maxsize)
    data, used_files = load_training_data(args.input)
    if set(data["label"].unique()) != {0, 1}:
        raise ValueError("The label column must contain exactly 0 and 1 classes.")

    texts = email_text(data)
    labels = data["label"]
    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    model = build_model()
    model.fit(x_train, y_train)
    probabilities = model.predict_proba(x_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)

    print(classification_report(y_test, predictions, digits=4))
    print(f"accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"roc_auc: {roc_auc_score(y_test, probabilities):.4f}")

    artifact = {
        "model": model,
        "label_meaning": {"0": "legitimate", "1": "spam_or_phishing"},
        "training_columns": TEXT_COLUMNS,
        "training_files": used_files,
        "training_rows": len(data),
        "metrics": {
            "accuracy": accuracy_score(y_test, predictions),
            "roc_auc": roc_auc_score(y_test, probabilities),
        },
    }
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    joblib.dump(artifact, args.output, compress=3)
    print(f"saved model: {args.output}")


if __name__ == "__main__":
    main()
