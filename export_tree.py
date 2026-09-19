import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

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
y = (df[LABEL] == 'PortScan').astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

tree = clf.tree_

left_children = [int(x) for x in tree.children_left]
right_children = [int(x) for x in tree.children_right]
thresholds = [int(t) if t != -2 else -1 for t in tree.threshold]
features = [int(f) for f in tree.feature]
predictions = [int(np.argmax(v[0])) for v in tree.value]

n = len(left_children)

with open("tree_params.h", "w") as f:
    f.write("#ifndef TREE_PARAMS_H\n#define TREE_PARAMS_H\n\n")
    f.write(f"#define TREE_NUM_NODES {n}\n\n")

    def write_array(name, values):
        f.write(f"static const int {name}[TREE_NUM_NODES] = {{\n    ")
        f.write(", ".join(str(v) for v in values))
        f.write("\n};\n\n")

    write_array("tree_left", left_children)
    write_array("tree_right", right_children)
    write_array("tree_threshold", thresholds)
    write_array("tree_feature", features)
    write_array("tree_prediction", predictions)

    f.write("#endif\n")

print(f"Wrote tree_params.h with {n} nodes")
