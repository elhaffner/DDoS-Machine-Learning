import os 
import zipfile
import csv
import pandas as pd
from sklearn import *
from sklearn.model_selection import *
from sklearn.tree import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import *
from sklearn.preprocessing import OneHotEncoder
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import *
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import random
import joblib
import shutil

def write_to_csv(extracted_file, writer):
    df = pd.read_csv(extracted_file)
    print(extracted_file)
    print(df.head())
    capCount = 0
    for index, row in df.iterrows():
        appendList = []
        
        #Message Type
        if pd.isna(row['mqtt.msgtype']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.msgtype'])

        #QoS
        if pd.isna(row['mqtt.conflag.qos']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.conflag.qos'])
        
        #Highest Layer
        if pd.isna(row['mqtt.msgtype']):
            if pd.isna(row['tcp.srcport']):
                if pd.isna(row['udp.srcport']):       
                    if pd.isna(row['ip.addr']):
                        continue
                    else:
                        appendList.append('IP')
                else:
                    appendList.append('UDP')
            else:
                appendList.append('TCP')
        else:
            appendList.append('MQTT')

        #Frame Length, Time Delta
        appendList.append(row['frame.len'])
        appendList.append(row['frame.time_delta'])

        #TCP Stream
        if pd.isna(row['tcp.stream']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.stream'])
        
        #IRTT
        if pd.isna(row['tcp.analysis.initial_rtt']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.analysis.initial_rtt'])
        
        #TCP Length
        if pd.isna(row['tcp.len']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.len'])

        #Calculated Window size
        if pd.isna(row['tcp.window_size_value']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.window_size_value'])
        
        #SYN
        if pd.isna(row['tcp.flags.syn']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.flags.syn'])
        
        #RESET
        if pd.isna(row['tcp.flags.res']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.flags.res'])
        
        #ACK
        if pd.isna(row['tcp.flags.ack']):
            appendList.append(-1)
        else:
            appendList.append(row['tcp.flags.ack'])
        
        #Clean session
        if pd.isna(row['mqtt.conflag.cleansess']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.conflag.cleansess'])
        
        #Keep Alive
        if pd.isna(row['mqtt.kalive']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.kalive'])
        
        #Retain Flag
        if pd.isna(row['mqtt.conflag.retain']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.conflag.retain'])
        
        #Will Flag
        if pd.isna(row['mqtt.conflag.willflag']):
            appendList.append(-1)
        else:
            appendList.append(row['mqtt.conflag.willflag'])
        
        #Label
        if str(row['ip.src']) in ["192.168.90.100", "192.168.90.101", "192.168.90.102"]:
            appendList.append(1)
        else:
            appendList.append(0)
        
        writer.writerow(appendList)
        capCount += 1
        if capCount % 10000 == 0:
            print(capCount)

    
    
def processCSVFile(extracted_file, model):
    features = ["Message Type", "QoS", "Highest Layer", "Frame length", "Time Delta", "Stream Index", "iRTT", "TCP Length", "Calculated Window Size", "SYN flag", "RESET flag", "ACK flag", "CLEAN SESSION flag", "Keep Alive Time", "RETAIN flag", "WILL flag", "label"]
    with open('test.csv', 'w', newline='') as wfile:
        writer = csv.writer(wfile)
        writer.writerow(features)
        write_to_csv(extracted_file, writer)

        df = pd.read_csv('test.csv')

        all_message_types = list(range(-1, 16))
        ohe = OneHotEncoder(categories=[all_message_types], handle_unknown='ignore', drop=None, sparse_output=False).set_output(transform="pandas")
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

        
        column_to_move = df.pop("label")
        # insert column with insert(location, column_name, column_value)
        df.insert(len(df.columns), "label", column_to_move)

        print(df.head())

        scaler = MinMaxScaler()

        X = df.iloc[:, 0:(len(df.columns) - 1)]
        X = scaler.fit_transform(X) #Scale
        y = df.iloc[:, (len(df.columns) - 1)] # Last Column
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        model.partial_fit(X_train, y_train, classes=[0, 1])

        #Predictions
        predictions = model.predict(X_test)
        print(accuracy_score(y_test, predictions))

        matrix = confusion_matrix(y_test, predictions, labels=[0,1])
        print(precision_score(y_test, predictions))
        print(f1_score(y_test, predictions))

        is_fitted = hasattr(model, 'coef_') and model.coef_ is not None

        if is_fitted:
            print("The model is fitted.")
        else:
            print("The model is not fitted.")


    os.remove('test.csv')
        

def iterate_folder(model):
    for root, dirs, files in os.walk("C:\\Users\\lucas\\OneDrive\\Documents\\CS310\\csvOutput"):
        for file in files:
            file_path = os.path.join(root, file)

            if zipfile.is_zipfile(file_path) and file_path == "C:\\Users\\lucas\\OneDrive\\Documents\\CS310\\csvOutput\\BF1_DoS_AD_26.zip" or file_path == "C:\\Users\\lucas\\OneDrive\\Documents\\CS310\\csvOutput\\NormalData1.zip":
                temp_extract_path = os.path.join(root, "temp_extract")
                shutil.unpack_archive(file_path, temp_extract_path, "zip")
                count = 0
                for extracted_root, extracted_dirs, extracted_files in os.walk(temp_extract_path):
                    for extracted_file in extracted_files:
                        count += 1
                        extracted_file = os.path.join(extracted_root, extracted_file)
                        processCSVFile(extracted_file, model)
                        if count == 1:
                            break
                        
                        ##Processing##
                shutil.rmtree(temp_extract_path)

if __name__ == "__main__":
    model = SGDClassifier(loss="hinge", penalty="l2", max_iter=5)
    iterate_folder(model)

    joblib.dump(model, "TestModel.joblib")
    is_fitted = hasattr(model, 'coef_') and model.coef_ is not None

    if is_fitted:
        print("The model is fitted.")
    else:
        print("The model is not fitted.")