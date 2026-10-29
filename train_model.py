import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

# Import these from your own feature/dataset module
# Replace url_features with the Python filename
# containing extract_features and training_urls.
from url_features import extract_features, training_urls

X_train = [
    extract_features(url) for url, label in training_urls
]
y_train = [label for url, label in training_urls]

model = make_pipeline(
    StandardScaler(),
    RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )
)

model.fit(X_train, y_train)

with open("url_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("AI model saved as url_model.pkl")