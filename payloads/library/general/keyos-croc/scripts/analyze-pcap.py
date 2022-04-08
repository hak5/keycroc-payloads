#!/usr/bin/env python3

from scapy.sendrecv import sniff
from scapy.layers.dhcp import DHCP
import os
import atexit

fifo_in = "/root/pyrecv"
fifo_out = "/root/bashrecv"

already_send = False

# remove a FIFO
def remove_fifo(fifo):
	try:
		os.remove(fifo)
	except:
		print("remove FIFO error")

# send result (OS type) to the bash receive FIFO
def send_result(result):
	global already_send

	with open(fifo_out, "w") as fifo:
		fifo.write("os=" + result + "\n")
	
	# result (identified OS) has already been send
	already_send = True


# remove FIFO on exit
def exit_handler():
	remove_fifo(fifo_in)


# try to detect the OS by checking the DHCP request options
def detectOS(options):

	# Windows devices define the vendor_class_id
	if "vendor_class_id" in options:
		if "MSFT" in options["vendor_class_id"]:
			send_result("Windows")

	# Ubuntu (also Kali Linux so probably all debian-based distros) does set option 2 and 17 in the parameter request list
	elif set([2, 12]).issubset(options["param_req_list"]):
		send_result("Linux")

	# macOS does set option 95 in the parameter request list
	elif set([95]).issubset(options["param_req_list"]):
		send_result("Mac")

	# if some devices do not set the given identifiers then the OS can not be determined
	else:
		send_result("Unknown")


# check if packet is DHCP request / discover and if so add DHCP options to a easily parsable dictionary 
def dhcp_callback(pkt):
	if DHCP in pkt and (pkt[DHCP].options[0][1] == 3 or pkt[DHCP].options[0][1] == 1):

		dhcp_options = pkt[DHCP].options
		option_list = {}

		# iterate through all tuples
		for option in dhcp_options:

			# check if we might to convert sth because it contains additional flags, length, etc.
			if isinstance(option[1], (bytes, bytearray)):

				# only client name - remove leading length, flags, a-pr and ptr-ppr result
				if option[0] == "client_FQDN":
					option_list[option[0]] = option[1][3:].decode()

				else:
					option_list[option[0]] = option[1].decode()
			else:
				option_list[option[0]] = option[1]

		print(option_list)
		detectOS(option_list)


# scapy stop function
# stop sniffing if the host OS could have been identified
# (OS type has already been send to the bash process)
def check_already_send(x):
	global already_send
	
	if already_send:
		return True
	else:
		return False


if __name__ == "__main__":

	# register exit handler to be able to remove the fifo
	atexit.register(exit_handler)

	while True:

		with open(fifo_in) as fifo:

			for line in fifo:

				if (line == "sniff"):

					print("sniffing ...")
					
					# sniff for DHCP packets for 5 secs
					# call dhcp_callback() if a DHCP packet has been found and analyze it
					# the identified OS will be send to the bash process via a FIFO (named pipe)
					# to prevent multiple sends (multiple DHCP packets!) and sniffing if the interface
					# is already down, after every packet it will be checked if the identified OS has already been send
					sniff(iface="usb0", filter="udp and (port 67 or 68)", timeout=5, prn=dhcp_callback, stop_filter=check_already_send)

					# no valid DHCP packets have been found --> no result prior send
					# --> send "na" as feedback to the bash process
					if not already_send:
						print("after 5 secs: no valid DHCP packets found - will send 'na'")
						send_result("na")
					
					# reset already_send
					already_send = False

					print("stopped sniffing")

				elif (line == "stop"):
					print("stopping ...")
					exit()

