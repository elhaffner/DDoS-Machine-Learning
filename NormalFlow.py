import paho.mqtt.client as mqtt
import time
from Client import Client
import multiprocessing
import random


def workers(i, sub_List, pub_List):
    client = Client(sub_List, pub_List)
    client.connect_Client()
    client.start_Client_Loop()

    while True:
        for pub in pub_List:
            client.publish_Message(pub, f"Client {i} published {random.random()}")
            time.sleep(random.uniform(1, 5))

if __name__ == "__main__":
    num_clients = 5
    processes = []

    for i in range(num_clients):
            process = multiprocessing.Process(target=workers, args=[i, [], ["testTopic", "testTopic2"]])
            process.start()
            processes.append(process)
        
    for process in processes:
        process.join()



