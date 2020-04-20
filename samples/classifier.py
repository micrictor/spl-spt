#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import matplotlib.pyplot as plt
from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn import metrics


malware_df = []
benign_df = []

malwares = ['shade','meterpreter','poshc2']
benigns = ['google','web-browse']

for mal in malwares:
    with open(f"./{mal}/spl.log") as fl:
        malware_df.append(pd.read_json(fl, lines=True))

for name in benigns:
    with open(f"./{name}/spl.log") as fl:
        benign_df.append(pd.read_json(fl, lines=True))

malware_df = pd.concat(malware_df)
malware_df['label'] = True

benign_df = pd.concat(benign_df)
benign_df['label'] = False

df = pd.concat([malware_df,benign_df])
df = df.fillna(0)

def get_column_max(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return max(row[col])
    return 0
    
def get_column_min(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return max(row[col])
    return 0
    
def get_column_avg(row, col):
    if col in row:
        if not isinstance(row[col],list):
            return row[col]
        return sum(row[col]) / len(row[col])
    return 0

df['max_orig_spl'] = df.apply(lambda row: get_column_max(row, 'orig_spl'), axis=1)
df['min_orig_spl'] = df.apply(lambda row: get_column_min(row, 'orig_spl'), axis=1)
df['avg_orig_spl'] = df.apply(lambda row: get_column_avg(row, 'orig_spl'), axis=1)

df['max_resp_spl'] = df.apply(lambda row: get_column_max(row, 'resp_spl'), axis=1)
df['min_resp_spl'] = df.apply(lambda row: get_column_min(row, 'resp_spl'), axis=1)
df['avg_resp_spl'] = df.apply(lambda row: get_column_avg(row, 'resp_spl'), axis=1)

df['max_orig_spt'] = df.apply(lambda row: get_column_max(row, 'orig_spt'), axis=1)
df['min_orig_spt'] = df.apply(lambda row: get_column_min(row, 'orig_spt'), axis=1)
df['avg_orig_spt'] = df.apply(lambda row: get_column_avg(row, 'orig_spt'), axis=1)

df['max_resp_spt'] = df.apply(lambda row: get_column_max(row, 'resp_spt'), axis=1)
df['min_resp_spt'] = df.apply(lambda row: get_column_min(row, 'resp_spt'), axis=1)
df['avg_resp_spt'] = df.apply(lambda row: get_column_avg(row, 'resp_spt'), axis=1)

# Static model for tree visualization

y = df['label']

mod_df = df[['max_orig_spl','min_orig_spl','avg_orig_spl',
'max_resp_spl','min_resp_spl','avg_resp_spl',      'max_orig_spt','min_orig_spt','avg_orig_spt',
'max_resp_spt','min_resp_spt','avg_resp_spt']]

X = dict()
Y = dict()

X['train'], X['test'], Y['train'], Y['test'] = train_test_split(mod_df, y, test_size=0.3)

# Static model to visualize the tree
model = tree.DecisionTreeClassifier(random_state=97)
model = model.fit(X['train'], Y['train'])

fig, axes = plt.subplots(nrows = 1,ncols = 1,figsize = (4,4), dpi=600)
tree.plot_tree(model, feature_names=mod_df.columns, class_names=['malware','clean'], filled=True)
fig.savefig("decision-tree.png")

# Get best and worst case stats

min_acc = float("inf")
max_acc = 0
max_fp = 0
max_fn = 0

print("Testing model over 100 iterations...")
for _ in range(0,100):
    X['train'], X['test'], Y['train'], Y['test'] = train_test_split(mod_df, y, test_size=0.3)
    t_mod = tree.DecisionTreeClassifier()
    t_mod = t_mod.fit(X['train'], Y['train'])

    y_pred = t_mod.predict(X['test'])
    
    min_acc = min(min_acc, metrics.accuracy_score(Y['test'], y_pred))
    max_acc = max(max_acc, metrics.accuracy_score(Y['test'], y_pred))
    
    CM = metrics.confusion_matrix(Y['test'], y_pred)
    max_fp = max(max_fp, CM[0][1])
    max_fn = max(max_fn, CM[1][0])
    
print(f"Sample size: {len(X['test'])}\n")

print(f"Max accuracy :\t\t{max_acc}")
print(f"Min accuracy :\t\t{min_acc}")
print(f"Max false negative:\t{max_fn/len(X['test'])}\t{max_fn}")
print(f"Max false positive:\t{max_fp/len(X['test'])}\t{max_fp}")




