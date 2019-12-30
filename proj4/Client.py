from socket import *
import hashlib
import pickle
import sys
import os
import math
import time

#takes the server IP as command line arguments
serverName=''.join(sys.argv[1])

print("Server Name: ", serverName)
#takes the file name as command line arguments
filename = ''.join(sys.argv[2])

#create client socket
clientSocket = socket(AF_INET,SOCK_DGRAM)
clientSocket.settimeout(0.001)

#initializes window variables (upper and lower window bounds, position of next seq number)
base=1
nextSeqnum=1
windowSize=7
window = []

#SENDS DATA
fileOpen= open(filename, 'rb') 
data = fileOpen.read(500)
done = False
lastackreceived = time.time()
serverAddr = (serverName, 8080)

while not done or window:
#	check if the window is full	or EOF has reached
	if(nextSeqnum<base+windowSize) and not done:
#		create packet(seqnum,data,checksum)
		sendPacket = []
		sendPacket.append(nextSeqnum)
		sendPacket.append(data)
		h = hashlib.md5()
		h.update(pickle.dumps(sendPacket))
		sendPacket.append(h.digest())
#		send packet
		clientSocket.sendto(pickle.dumps(sendPacket), serverAddr)
		print ("Sent data", nextSeqnum)
#		increment nextSeqnum
		nextSeqnum = nextSeqnum + 1
#		check if EOF has reached
		if(not data):
			done = True
#		append packet to window
		window.append(sendPacket)
#		read more data
		data = fileOpen.read(500)

#RECEIPT OF AN ACK
	try:
		packet,serverAddress = clientSocket.recvfrom(4096)
		print("Server Address received: ", serverAddress)
		recvPacket = []
		recvPacket = pickle.loads(packet)
#		check value of checksum received against calculated
		check = recvPacket[-1]
		del recvPacket[-1]
		h = hashlib.md5()
		h.update(pickle.dumps(recvPacket))
		if check == h.digest():
			print ("Received ack for", recvPacket[0])
#			slide window and reset timer
			while recvPacket[0]>base and window:
				lastackreceived = time.time()
				del window[0]
				base = base + 1
		else:
			print ("error detected")
#TIMEOUT
	except:
		if(time.time()-lastackreceived>0.01):
			for i in window:
				clientSocket.sendto(pickle.dumps(i), serverAddr)

fileOpen.close()

print ("connection closed")
clientSocket.close()