"""
train_model.py — Train DoS Detector with XGBoost + SMOTE
Uses UNSW_NB15 dataset.  Falls back to RandomForest if xgboost not installed.
Run once:  python train_model.py
"""

import os, joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.over_sampling import SMOTE
from config import FEATURE_COLUMNS, MODEL_PATH, SCALER_PATH

# ── 1. Load UNSW_NB15 ────────────────────────────────────────────────────────
TRAIN_CSV = "dataset/UNSW_NB15_training-set.csv"
TEST_CSV  = "dataset/UNSW_NB15_testing-set.csv"

print("📂 Loading dataset …")
df_train = pd.read_csv(TRAIN_CSV)
df_test  = pd.read_csv(TEST_CSV)
df       = pd.concat([df_train, df_test], ignore_index=True)
print(f"   Total rows: {len(df):,}  |  columns: {len(df.columns)}")

# ── 2. Build binary label: 1 = DoS, 0 = Normal ──────────────────────────────
#   We focus on DoS detection specifically
df['dos_label'] = (df['attack_cat'].str.strip() == 'DoS').astype(int)
print(f"   DoS rows : {df['dos_label'].sum():,}")
print(f"   Normal   : {(df['dos_label']==0).sum():,}")

# ── 3. Encode categorical features ──────────────────────────────────────────
le = LabelEncoder()
for col in ['proto', 'service', 'state']:
    df[col] = le.fit_transform(df[col].astype(str))

# ── 4. Select features ───────────────────────────────────────────────────────
X = df[FEATURE_COLUMNS].fillna(0)
y = df['dos_label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 5. SMOTE – oversample minority class ────────────────────────────────────
print("\n⚖️  Applying SMOTE …")
smote = SMOTE(random_state=42, k_neighbors=5)
X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
print(f"   After SMOTE → 0:{(y_train_res==0).sum():,}  1:{(y_train_res==1).sum():,}")

# ── 6. Scale ─────────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train_res)
X_test_sc  = scaler.transform(X_test)

# ── 7. Model — XGBoost preferred, RandomForest fallback ──────────────────────
try:
    from xgboost import XGBClassifier
    print("\n🚀 Training XGBoost …")
    model = XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1
    )
    model_name = "XGBoost"
except ImportError:
    from sklearn.ensemble import RandomForestClassifier
    print("\n⚠️  xgboost not found – using RandomForest (install xgboost for best results)")
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        n_jobs=-1,
        random_state=42
    )
    model_name = "RandomForest"

model.fit(X_train_sc, y_train_res)

# ── 8. Evaluate ───────────────────────────────────────────────────────────────
y_pred = model.predict(X_test_sc)
print(f"\n✅ {model_name} Results:")
print(f"   Accuracy : {accuracy_score(y_test, y_pred)*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=["Normal","DoS"]))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# ── 9. Save ───────────────────────────────────────────────────────────────────
os.makedirs("models", exist_ok=True)
joblib.dump(model,  MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
print(f"\n💾 Model  → {MODEL_PATH}")
print(f"💾 Scaler → {SCALER_PATH}")
print("Training complete.")
