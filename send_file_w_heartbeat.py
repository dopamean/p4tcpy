#!/usr/bin/env python3

import socket
import time

if __name__ == "__main__":
	try:
		s = socket.socket()
		s.connect(("10.0.1.10", 6666)) #send to nonexisting host on same subnet

		print("Sending file!")
		test_msg = "Uploading file..."
		s.send(test_msg.encode())  #  expext bytes-like object   ... csima
		# párhuzamosan próbálja elküldeni amíg nem jön ACK.. de a kód végrehajtás tovább megy

		while True:
			time.sleep(5)
			print("Sending heartbeat!")
			s.send("HEARTBEAT".encode())

		# mi az rb  ? rb was not defined         //
		with open("send_file_w_hearthbeat.py", "rb") as f:
			buffer = f.read(1024)
			while buffer:
				s.send(buffer)
				buffer = f.read(1024)

			print("File sent!")

			while True:
				time.sleep(5)
				print("Sending heartbeat!")
				s.send("HEARTBEAT".encode())

	except KeyboardInterrupt:
		s.shutdown(socket.SHUT_WR)
	#	print(s.recv(1024))  # 
		s.close()
