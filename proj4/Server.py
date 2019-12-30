from socket import *
import pickle
import hashlib
import sys
import os
import math
import time

clientIP="10.0.0.2"

serverSocket=socket(AF_INET,SOCK_DGRAM)
serverSocket.bind((clientIP,8080))
serverSocket.settimeout(3)

#initializes packet variables 
expectedseqnum=1
ACK=1
ack = []

#RECEIVES DATA
curFile = open(sys.argv[1], "wb")
endoffile = False
lastpktreceived = time.time()

while True:

	try:
		recvPacket=[]
		packet,clientAddress= serverSocket.recvfrom(4096)
		clientAddr=(clientAddress, 8080)
		recvPacket = pickle.loads(packet)
#		check value of checksum received (c) against checksum calculated (h) - NOT CORRUPT
		check = recvPacket[-1]
		del recvPacket[-1]
		h = hashlib.md5()
		h.update(pickle.dumps(recvPacket))
		if check == h.digest():
#		check value of expected seq number against seq number received - IN ORDER 
			if(recvPacket[0]==expectedseqnum):
				print ("Received inorder", expectedseqnum)
				if recvPacket[1]:
					curFile.write(recvPacket[1])
				else:
					endoffile = True
				expectedseqnum = expectedseqnum + 1
#				create ACK (seqnum,checksum)
				sndpkt = []
				sndpkt.append(expectedseqnum)
				h = hashlib.md5()
				h.update(pickle.dumps(sndpkt))
				sndpkt.append(h.digest())
				serverSocket.sendto(pickle.dumps(sndpkt), clientAddr)
				print ("New Ack", expectedseqnum)

			else:
#		discard packet and resend ACK for most recently received inorder pkt
				print ("Received out of order", recvPacket[0])
				sndpkt = []
				sndpkt.append(expectedseqnum)
				h = hashlib.md5()
				h.update(pickle.dumps(sndpkt))
				sndpkt.append(h.digest())
				serverSocket.sendto(pickle.dumps(sndpkt), clientAddr)
				print ("Ack", expectedseqnum)
		else:
			print ("error detected")
	except:
		if endoffile:
			if(time.time()-lastpktreceived>3):
				break



curFile.close()
print ('FILE TRANSFER SUCCESSFUL')
