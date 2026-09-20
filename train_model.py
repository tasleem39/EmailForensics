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
TARGET_CLASSES = ("legitimate", "suspicious", "impersonated", "phishing", "fraud")


def email_text(frame):
    combined = frame[TEXT_COLUMNS].fillna("").astype(str)
    return combined.apply(
        lambda row: "\n".join(f"{field}: {row[field]}" for field in TEXT_COLUMNS), axis=1
    )


def load_training_data(input_path):
    paths = sorted(glob.glob(os.path.join(input_path, "**", "*.csv"), recursive=True)) if os.path.isdir(input_path) else [input_path]
    if not paths:
        raise ValueError(f"No CSV files found in {input_path}")

    frames = []
    used_files = []
    for path in paths:
        data = pd.read_csv(path, engine="python", on_bad_lines="warn")
        category = os.path.basename(os.path.dirname(path)).lower()
        label_column = "label"
        if label_column not in data.columns:
            category_label_columns = {
                "impersonated": "impersonated",
                "suspicious": "suspious",
            }
            label_column = category_label_columns.get(category)
        if not label_column or label_column not in data.columns:
            print(f"Skipping {path}: no supported label column")
            continue
        for column in TEXT_COLUMNS:
            if column not in data.columns:
                data[column] = ""
        data["source_label"] = pd.to_numeric(data[label_column], errors="coerce")
        data = data.dropna(subset=["source_label"])
        data["source_label"] = data["source_label"].astype(int)
        data = data[data["source_label"].isin([0, 1])]
        if category not in {"fraud", "impersonated", "suspicious", "phishing"}:
            print(f"Skipping {path}: parent folder must be a threat category")
            continue
        # Positive rows inherit their manually curated folder category. Negative
        # rows are legitimate examples from mixed datasets.
        data["label"] = data["source_label"].map(
            lambda value: category if value == 1 else "legitimate"
        )
        if not data.empty:
            frames.append(data[TEXT_COLUMNS + ["label"]])
            used_files.append({"file": path, "rows": len(data)})

    if not frames:
        raise ValueError("No labeled rows with binary 0/1 labels were found in category folders")
    return pd.concat(frames, ignore_index=True), used_files


def build_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
            min_df=2,
            max_features=50000,
            sublinear_tf=True,
        )),
        ("character", TfidfVectorizer(
            analyzer="char",
            lowercase=True,
            ngram_range=(3, 5),
            min_df=3,
            max_features=30000,
            sublinear_tf=True,
        )),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
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
    classes = set(data["label"].unique())
    missing_classes = set(TARGET_CLASSES) - classes
    if missing_classes:
        raise ValueError(f"Missing required classes: {', '.join(sorted(missing_classes))}")

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
    predictions = model.predict(x_test)

    print(classification_report(y_test, predictions, digits=4))
    print(f"accuracy: {accuracy_score(y_test, predictions):.4f}")

    artifact = {
        "model": model,
        "label_meaning": {str(index): label for index, label in enumerate(model.named_steps["classifier"].classes_)},
        "training_columns": TEXT_COLUMNS,
        "training_files": used_files,
        "training_rows": len(data),
        "classes": list(model.named_steps["classifier"].classes_),
        "metrics": {
            "accuracy": accuracy_score(y_test, predictions),
        },
    }
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    joblib.dump(artifact, args.output, compress=3)
    print(f"saved model: {args.output}")


if __name__ == "__main__":
    main()
