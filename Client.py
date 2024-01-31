import paho.mqtt.client as mqtt
from scapy.all import IP, TCP, send


class Client:

    #Initialise connection
    def __init__(self, subscriberList:list = [], publisherList:list = []):
        self.client = mqtt.Client()

        self.subscriberList = subscriberList
        self.publisherList = publisherList

    def connect_Client(self, kalive: int = 60):     
        #def on_connect(client, userdata, flags, rc):
            #print("Connected with result code "+str(rc)) 
        self.client.connect("localhost", 1883, kalive)
        #self.client.on_connect = on_connect

    def start_Client_Loop(self):
        self.client.loop_start()

    def subscribe(self, topic: str):
        self.client.subscribe(topic)

    def subscribe_All(self):
        for subscriber in self.subscriberList:
            self.client.subscribe(subscriber)

    def publish_Message(self, topic: str, message: str):
        print(message)
        self.client.publish(topic, message)
        if topic not in self.publisherList:
            self.publisherList.append(topic)

    def send_syn_packet(self):
        ip_packet = IP(dst='localhost')
        syn_packet = TCP(dport=1883, flags="S")
        packet = ip_packet / syn_packet
        send(packet, verbose=0)


