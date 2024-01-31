import csv
import pandas as pd
import joblib
from sklearn import *
from sklearn.model_selection import *
from sklearn.tree import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import *
from sklearn.preprocessing import OneHotEncoder
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import *
import matplotlib.pyplot as plt
import numpy as np

model = joblib.load('TestModel.joblib')

df = pd.read_csv('test.csv')

all_message_types = list(range(-1, 16))
ohe = OneHotEncoder(categories=[all_message_types], drop=None, sparse_output=False).set_output(transform="pandas")
ohetransform = ohe.fit_transform(df[['Message Type']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['Message Type'])

all_QoS = [-1, 0, 1, 2]
ohe = OneHotEncoder(categories=[all_QoS], drop=None, sparse_output=False).set_output(transform="pandas")
ohetransform = ohe.fit_transform(df[['QoS']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['QoS'])

all_flags = [-1, 0, 1]
ohe = OneHotEncoder(categories=[all_flags], drop=None, sparse_output=False).set_output(transform="pandas")
ohetransform = ohe.fit_transform(df[['SYN flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['SYN flag'])
ohetransform = ohe.fit_transform(df[['RESET flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['RESET flag'])
ohetransform = ohe.fit_transform(df[['ACK flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['ACK flag'])
ohetransform = ohe.fit_transform(df[['CLEAN SESSION flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['CLEAN SESSION flag'])
ohetransform = ohe.fit_transform(df[['RETAIN flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['RETAIN flag'])
ohetransform = ohe.fit_transform(df[['WILL flag']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['WILL flag'])

all_Layers = ['IP', 'TCP', 'UDP', 'MQTT']
ohe = OneHotEncoder(categories=[all_Layers], drop=None, sparse_output=False).set_output(transform="pandas")
ohetransform = ohe.fit_transform(df[['Highest Layer']])
df = pd.concat([df, ohetransform], axis=1).drop(columns = ['Highest Layer'])

print(df.head())

column_to_move = df.pop("label")
# insert column with insert(location, column_name, column_value)
df.insert(len(df.columns), "label", column_to_move)

X = df.iloc[:, 0:(len(df.columns) - 1)]
y = df.iloc[:, (len(df.columns) - 1)] # Last Column

#Predictions
predictions = model.predict(X)
print(accuracy_score(y, predictions))

matrix = confusion_matrix(y, predictions, labels=[0,1])
print(matrix)

predicted_as_label_1 = df.loc[predictions == 0]
print("\nRows predicted as Label 1:")
print(predicted_as_label_1)






