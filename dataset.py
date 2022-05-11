import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)

files = ["./dataset_benign.csv", "./dataset_malware.csv"]

data = pd.concat(map(pd.read_csv, files), ignore_index=True)

data = data.sample(frac=1, ignore_index=True)

data.to_csv('./dataset.csv')
