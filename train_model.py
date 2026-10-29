
import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

DATA_PATH = "data/balanced_urls.csv"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")

print("Loading URL dataset...")

df = pd.read_csv(DATA_PATH, usecols=["url", "label"])
df = df.dropna(subset=["url", "label"])

df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()

# Convert dataset labels into the labels used by our app.
df = df[df["label"].isin(["benign", "malicious"])]
df["label"] = df["label"].map({
    "benign": "safe",
    "malicious": "malicious"
})

df = df[df["url"] != ""]
df = df.drop_duplicates(subset=["url"])

print("\nDataset labels:")
print(df["label"].value_counts())

# Use a reproducible sample to keep training manageable
# on a typical laptop.
sample_size = min(100000, len(df))
df = df.groupby("label", group_keys=False).apply(
    lambda group: group.sample(
        n=min(
            len(group),
            max(1, round(sample_size * len(group) / len(df)))
        ),
        random_state=42
    )
).reset_index(drop=True)

print(f"\nTraining with {len(df):,} URLs.")

X_train, X_test, y_train, y_test = train_test_split(
    df["url"],
    df["label"],
    test_size=0.2,
    random_state=42,
    stratify=df["label"]
)

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            max_features=80000,
            min_df=2,
            sublinear_tf=True,
            dtype="float32"
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])

print("\nTraining AI model. Please wait...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions) * 100

print(f"\nTest accuracy: {accuracy:.2f}%")
print("\nClassification report:")
print(classification_report(y_test, predictions))
print("Confusion matrix:")
print(confusion_matrix(
    y_test,
    predictions,
    labels=["safe", "malicious"]
))

os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(model, MODEL_PATH)

print(f"\nModel saved successfully: {MODEL_PATH}")
print("You can now connect this model to your Streamlit app.")
