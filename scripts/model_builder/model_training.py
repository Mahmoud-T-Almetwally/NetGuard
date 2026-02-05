import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Configuration
DATA_DIR = "./dataset_builder/data"
MODEL_DIR = "./model_builder/models"
FILE_EXTENDED = os.path.join(DATA_DIR, "features_dataset_with_url.csv")
FILE_BASIC = os.path.join(DATA_DIR, "features_dataset.csv")

os.makedirs(MODEL_DIR, exist_ok=True)

def load_best_dataset():
    if os.path.exists(FILE_EXTENDED):
        print(f"Loading Extended Dataset (HTML + URL): {FILE_EXTENDED}")
        return pd.read_csv(FILE_EXTENDED)
    elif os.path.exists(FILE_BASIC):
        print(f"Loading Basic Dataset (HTML Only): {FILE_BASIC}")
        return pd.read_csv(FILE_BASIC)
    else:
        return None

def train_and_export(X, y, model_name):
    print(f"\n{'='*10} Training {model_name} Model {'='*10}")
    
    # 1. Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # 2. Train Random Forest with Class Weights
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,              
        class_weight="balanced_subsample", 
        random_state=42,
        n_jobs=-1                  
    )
    
    clf.fit(X_train, y_train)
    
    # 3. Evaluate
    y_pred = clf.predict(X_test)
    
    print(f"Confusion Matrix for {model_name}:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    # Check if we caught any positives
    if cm.shape == (2, 2):
        tp = cm[1, 1]
        fn = cm[1, 0]
        print(f"Detected {tp} out of {tp+fn} positive samples in Test Set.")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # 4. Feature Importance (Check if URL features matter)
    feature_importances = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
    print("Top 10 Most Important Features:")
    print(feature_importances.head(10))

    # 5. Export to ONNX
    print(f"Exporting to {model_name}.onnx...")
    
    # Define input type (Float tensor)
    initial_type = [('float_input', FloatTensorType([None, X_train.shape[1]]))]
    
    onx = convert_sklearn(clf, initial_types=initial_type)
    
    output_path = os.path.join(MODEL_DIR, f"{model_name}.onnx")
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())
    
    print(f"Saved: {output_path}")

def main():
    # 1. Load Data
    df = load_best_dataset()
    if df is None:
        print("Error: No dataset found.")
        return
    
    # 2. Preprocessing
    df.fillna(0, inplace=True)
    
    # Define Columns to explicitly ignore (Targets and IDs)
    ignore_cols = [
        'filename', 'file_hash', 'label_class', 
        'target_malware', 'target_adware',
        'original_url', 'protocol', 'domain', 'path', 'query'
    ]
    
    # Create the Features Matrix (X)
    cols_to_drop = [c for c in ignore_cols if c in df.columns]
    X_raw = df.drop(columns=cols_to_drop)

    X = X_raw.select_dtypes(include=['number'])

    # Debugging: Show what we are training on
    print(f"\nFinal Training Features ({X.shape[1]}):")
    print(list(X.columns))
    
    # Sanity Check: If we dropped everything, stop.
    if X.shape[1] == 0:
        print("Error: No numeric features found! Check feature extraction.")
        return

    print(f"Training on {X.shape[0]} samples.")
    
    # 3. Save Feature Names
    feature_list_path = os.path.join(MODEL_DIR, "feature_names.txt")
    with open(feature_list_path, "w") as f:
        for col in X.columns:
            f.write(f"{col}\n")
    print(f"Feature order saved to {feature_list_path}")

    # 4. Train Model 1: Malware Detector
    if df['target_malware'].sum() < 2:
        print("\nWARNING: Not enough Malware samples to train (need at least 2). Skipping.")
    else:
        train_and_export(X, df['target_malware'], "malware_classifier")
    
    # 5. Train Model 2: Adware Detector
    train_and_export(X, df['target_adware'], "adware_classifier")

    print("\nTraining Complete.")
    print("Next Step: Copy the contents of './models' to your Go project's 'data/models' folder.")

if __name__ == "__main__":
    main()