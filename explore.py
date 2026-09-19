import pandas as pd

df = pd.read_csv("dataset/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")

print("Shape:", df.shape)
print("\nColumn names:")
for col in df.columns:
    print(repr(col))
