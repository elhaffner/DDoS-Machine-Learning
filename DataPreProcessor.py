import os
import subprocess
import pandas as pd
import json
import csv


class PreProcessor:
    def __init__(self) -> None:
        pass

    def convertJSON(self, file):
        cmd = f'tshark -r "../pcap/{file}" -T json > ../jsonOutput/tmp.json'
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            print("Tshark output:")

        except subprocess.CalledProcessError as e:
            print(f"Error running tshark: {e}")
    
    def convertCSV(self):   
        def nestedIteration(dictionary):
            d1 = {}
            for key, value in dictionary.items():
                if isinstance(value, dict):
                    d2 = nestedIteration(value)
                    d1.update(d2)
                else:
                    d1[key] = value
            return d1 
        with open("../jsonOutput/tmp.json") as output:
            print("Loading data from json")

        data = json.load(output)
        pktCount = 0
        dictList = []
        for pkt in data:
            d1 = nestedIteration(pkt)
            dictList.append(d1)
            pktCount += 1
            if pktCount % 1000 == 0:
                print(pktCount)

        #Can also use json_normalise method
        df = pd.DataFrame(dictList)
        print("Converting to csv")
        df.to_csv(f'../csvOutput/tmp.csv', index=False)

        try:
            os.remove("../jsonOutput/tmp.json")
            print(f"Successfully removed ../jsonOutput/tmp.json")
        except OSError as e:
            print(f"Error removing json file")
    
    def write_to_csv(self, extracted_file, writer):
        df = pd.read_csv(extracted_file)
        df['tcp.analysis.initial_rtt'] = pd.Series([float('nan')] * len(df), dtype=float)
        df['ip.src'] = pd.Series([float('nan')] * len(df), dtype=float)
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
            
            '''
            if str(row['ip.src']) in ["192.168.90.100", "192.168.90.101", "192.168.90.102"]:
                appendList.append(1)
            else:
                appendList.append(0)
            '''
            
            writer.writerow(appendList)
            capCount += 1
            if capCount % 10000 == 0:
                print(capCount)

    def prepareFeatures(self):
        with open("../csvOutput/tmp2.csv", 'w') as input:
            features = ["Message Type", "QoS", "Highest Layer", "Frame length", "Time Delta", "Stream Index", "iRTT", "TCP Length", "Calculated Window Size", "SYN flag", "RESET flag", "ACK flag", "CLEAN SESSION flag", "Keep Alive Time", "RETAIN flag", "WILL flag", "label"]
            writer = csv.writer(input)
            writer.writerow(features)
            self.write_to_csv("../csvOutput/tmp.csv", writer)

        os.remove("../csvOutput/tmp.csv")
    

