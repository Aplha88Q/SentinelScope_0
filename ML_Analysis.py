"""
SentinelScope - Machine Learning Analysis
==========================================
Applies ML models to classify RDP brute force attack events
exported from Azure Sentinel Log Analytics Workspace.

Dataset columns (exported from Azure):
    USERNAME, TIMESTAMP, LATITUDE, LONGITUDE,
    SOURCEHOST, STATE, COUNTRY, LABEL, DESTINATIONHOST

Models used:
    - Random Forest Classifier
    - Logistic Regression
    - Support Vector Machine (SVM)

Run: python ML_Analysis.py
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
import pickle
import os
import warnings
warnings.filterwarnings('ignore')

# ── Load Data ─────────────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_excel('DTI_Project_new.xlsx')
df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
print(f"Dataset shape: {df.shape}")
print(f"Null values:\n{df.isnull().sum()}\n")

# ── Clean ─────────────────────────────────────────────────────────────────────
df_cleaned = df.dropna(subset=['STATE'])
print(f"Rows after cleaning null STATE: {len(df_cleaned)}")

# ── Encode Features ───────────────────────────────────────────────────────────
le = LabelEncoder()
df_enc = df_cleaned.copy()
df_enc['USERNAME_ENC']   = le.fit_transform(df_enc['USERNAME'])
df_enc['COUNTRY_ENC']    = le.fit_transform(df_enc['COUNTRY'])
df_enc['SOURCEHOST_ENC'] = le.fit_transform(df_enc['SOURCEHOST'])
df_enc['LABEL_ENC']      = le.fit_transform(df_enc['LABEL'])

features = ['LATITUDE', 'LONGITUDE', 'USERNAME_ENC', 'COUNTRY_ENC', 'SOURCEHOST_ENC']
X = df_enc[features]
y = df_enc['LABEL_ENC']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_sc = scaler.fit_transform(X_train)
X_test_sc  = scaler.transform(X_test)

print(f"\nTraining samples: {len(X_train)} | Test samples: {len(X_test)}")

# ── Random Forest ─────────────────────────────────────────────────────────────
print("\n[1] Training Random Forest...")
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_acc  = accuracy_score(y_test, rf_pred)
print(f"    Accuracy: {rf_acc:.4f}")
print(classification_report(y_test, rf_pred))

# Feature importance
feat_imp = pd.Series(rf.feature_importances_, index=features).sort_values(ascending=False)
print("Feature Importances:")
print(feat_imp)

# ── Logistic Regression ───────────────────────────────────────────────────────
print("\n[2] Training Logistic Regression...")
lr = LogisticRegression(max_iter=1000, random_state=42)
lr.fit(X_train_sc, y_train)
lr_pred = lr.predict(X_test_sc)
lr_acc  = accuracy_score(y_test, lr_pred)
print(f"    Accuracy: {lr_acc:.4f}")
print(classification_report(y_test, lr_pred))

# ── Support Vector Machine ────────────────────────────────────────────────────
print("\n[3] Training SVM (RBF kernel)...")
svm = SVC(kernel='rbf', random_state=42)
svm.fit(X_train_sc, y_train)
svm_pred = svm.predict(X_test_sc)
svm_acc  = accuracy_score(y_test, svm_pred)
print(f"    Accuracy: {svm_acc:.4f}")
print(classification_report(y_test, svm_pred))

# ── Model Comparison Chart ────────────────────────────────────────────────────
print("\nGenerating model comparison chart...")
models  = ['Random Forest', 'Logistic Regression', 'SVM']
accs    = [rf_acc, lr_acc, svm_acc]
colors  = ['#ff4757', '#2ed573', '#1e90ff']

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(models, accs, color=colors, width=0.5)
ax.set_ylim(0, 1.1)
ax.set_title('Model Accuracy Comparison — SentinelScope', fontsize=13)
ax.set_ylabel('Accuracy')
for bar, acc in zip(bars, accs):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
            f'{acc:.2%}', ha='center', fontsize=11, fontweight='bold')
ax.grid(True, alpha=0.2, axis='y')
plt.tight_layout()
plt.savefig('model_comparison.png', dpi=150)
plt.show()
print("Saved: model_comparison.png")

# ── Anomaly Detection ─────────────────────────────────────────────────────────
print("\nRunning anomaly detection...")
df['TIMESTAMP'] = pd.to_datetime(df['TIMESTAMP'])
user_counts = df.groupby('USERNAME').apply(
    lambda g: g.set_index('TIMESTAMP').resample('5min').size()
)
anomalies = user_counts[user_counts > 5].reset_index()
anomalies.columns = ['USERNAME', 'TIMESTAMP', 'OCCURRENCES']
print(f"Anomalous bursts detected: {len(anomalies)}")
print(anomalies.sort_values('OCCURRENCES', ascending=False).head(10))

# ── Save Best Model ───────────────────────────────────────────────────────────
os.makedirs('model', exist_ok=True)
with open('model/random_forest.pkl', 'wb') as f:
    pickle.dump(rf, f)
with open('model/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)

best = max(zip(models, accs), key=lambda x: x[1])
print(f"\nBest model: {best[0]} ({best[1]:.2%}) — saved to model/")
