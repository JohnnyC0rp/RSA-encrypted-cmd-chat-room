from Client import Client
import socket
import config

client = Client(socket.AF_INET,socket.SOCK_STREAM)
client.connect_and_start(config.ADDR)