#!/usr/bin/env python3

import argparse
import subprocess
from time import sleep


# execute a passed shell-command via subprocess
def shell(cmd):
	try:
		process = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
		return process
	except subprocess.CalledProcessError as err:
		print(err)
		return False


# scan for WLAN access points in the range and return result
def scan_aps(interface):
	scan_result = shell("iw dev {} scan | grep SSID | awk '{{ print substr($0, index($0,$2)) }}'".format(interface))
	wlan_aps_list = []

	# scanning to often can result in "device is busy"-errors
	if scan_result: 
		wlan_aps_list = scan_result.decode("utf-8").split("\n")

	return wlan_aps_list


# check if WLAN interface exists and is up, try to start if down
def prepare_interface(interface):
	output = shell("cat /sys/class/net/{}/flags".format(interface))

	if output:
		# 0x1002 is down, 0x1003 is up
		if "0x1003" in output.decode("utf-8"):
			return True
		else:
			# try to start interface
			print("interface is down - starting ...")
			shell("ifconfig {} up".format(interface))
			sleep(1)
			return True
	else:
		# device does not exist
		return False


# check if scanned aps_list does not contain any denylisted AP entries
def denylist_check(denylist, wlan_aps_list):
	found_denied = False

	for rule in denylist:
		if set(rule).issubset(set(wlan_aps_list)):
			found_denied = True
			break

	return found_denied


# check if scanned aps_list does contain any allowlisted AP entries
def allowlist_check(allowlist, wlan_aps_list):
	found_allowed = False

	for rule in allowlist:
		if (rule[0] == "*") or set(rule).issubset(set(wlan_aps_list)):
			found_allowed = True
			break

	return found_allowed



if __name__ == "__main__":

	# ----------------------------------------------

	## syntax examples for -a / -d

	# ./wlanFencing.py -a "AP1" -a "AP2"
	# --> AP1 or AP2

	# ./wlanFencing.py -a "AP1" "AP2"
	# --> AP1 and AP2

	# ./wlanFencing.py -a "AP1" "AP2" -a "AP3"
	# --> (AP1 and AP2) or AP3

	# ----------------------------------------------

	## real world examples

	# continue if AP1 is present
	# ./wlanFencing.py -a "AP1"

	# continue if AP1 and AP2 are present
	# ./wlanFencing.py -a "AP1" "AP2"

	# continue if AP1 is absent
	# ./wlanFencing.py -a "*" -d "AP1"

	# continue if AP1 and AP2 are absent
	# ./wlanFencing.py -a "*" -d "AP1" "AP2"

	# ----------------------------------------------

	parser = argparse.ArgumentParser(prog='wlan_fencing', description='check if WLAN APs are in the range')
	parser.add_argument("-a", "--allow_ap", nargs="+", action='append', help="SSID(s) of the AP(s) that have to be present")
	parser.add_argument("-d", "--deny_ap", nargs="+", action='append', help="SSID(s) of the AP(s) that have to be absent")
	parser.add_argument("-t", "--timeout", help="exit(1) after 30 seconds", action="store_true")

	args = parser.parse_args()
	timeout = args.timeout

	allowlist = args.allow_ap if (args.allow_ap) else []
	denylist = args.deny_ap if (args.deny_ap) else []

	print("Allow:", allowlist)
	print("Deny:", denylist, "\n")

	# default values
	interface = "wlan0"
	sleep_seconds = 2
	max_tries = 15
	iterations = 0

	if not prepare_interface(interface):
		print("WLAN interface does not exist or failed to start - stopping.")
		exit(1)

	while True:

		wlan_aps_list = scan_aps(interface)

		# wlan_aps_list contains at least one element
		if len(wlan_aps_list) != 0:
			
			print(wlan_aps_list)

			if not denylist_check(denylist, wlan_aps_list):
				print("[+] no bad device [+]\n")
				if allowlist_check(allowlist, wlan_aps_list):
					print("A device is found, no denylisted device found.")
					exit(0)

		# exit if waited longer than max_tries
		if timeout and (iterations >= max_tries):
			print("Max tries reached - stopping.")
			exit(1)

		sleep(sleep_seconds)
		iterations += 1
