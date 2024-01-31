import paho.mqtt.client as mqtt
import time

# Callback when the client connects to the broker
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

# Create an MQTT client
client = mqtt.Client()

# Set the callback functions
client.on_connect = on_connect

# Connect to the local MQTT broker running on the default port (1883)
while True:
    client.connect("localhost", 1883, 60)

# Start the MQTT client loop
client.loop_start()

# Send MQTT messages every 5 seconds
#count = 0
#while True:
  #  count +=1
   # client.publish("testTopic", f"Hello, MQTT!, {count}")