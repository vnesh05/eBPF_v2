import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

df = pd.read_csv("dataset/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

FEATURES = [
    ' Destination Port',
    ' Fwd Packet Length Max',
    ' Fwd Packet Length Min',
    ' Fwd IAT Max',
    ' Fwd Header Length',
    ' Total Fwd Packets',
]
LABEL = ' Label'

X = df[FEATURES]
y = (df[LABEL] == 'PortScan').astype(int)  # 1 = attack, 0 = benign

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)

print("Accuracy: ", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:   ", recall_score(y_test, y_pred))
print("F1 score: ", f1_score(y_test, y_pred))

print("\nTree depth:", clf.get_depth())
print("Number of nodes:", clf.tree_.node_count)
