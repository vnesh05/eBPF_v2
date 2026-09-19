import pandas as pd

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

subset = df[FEATURES + [LABEL]]

print("Label value counts:")
print(subset[LABEL].value_counts())

print("\nAny missing values?")
print(subset.isnull().sum())

print("\nAny infinite values?")
import numpy as np
print(np.isinf(subset[FEATURES]).sum())

print("\nSample rows:")
print(subset.head())
