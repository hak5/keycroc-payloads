# Croc_Getonline

## INTRODUCTION :
  - This project is developed for the HAK5 KeyCroc.
  - Attempt to connect Keycroc automatically to target wifi access point. OPTIONS Nmap, Iw, and Curl to gather essential network information and/or start Reverse SSH tunnel.
  - Payload will use KeyCroc MATCH command to perform specific tasks.

* **TESTED ON**
  - Windows 10
  - Raspberry pi 4 (bullseye image)
  - linux (parrot os)

## INSTALLATION :

  - Enter arming mode on your keycroc to install file.
  - Download the Croc_getonline.txt payload and Place this in the KeyCroc **payload folder**.

## STARTING CROC_GETONLINE :

After install plug into target and type in anywhere:
   - **`getonline_W`**  MATCH word for windows, Attempt connection to wifi access point
   - **`getonline_L`**  MATCH word for Linux, Attempt connection to wifi access point
   - **`getonline_R`**  MATCH word for Raspberry pi, Attempt connection to wifi access point
   - **`getonline_N`**  MATCH word for connecting to known SSID ( EDIT PAYLOAD )
   - **`getonline_F`**  MATCH word for reset wlan0 interface to last known SSID
   - **`getonline_K`**  MATCH word for killing keycroc wlan0 interface
   - **`getonline_S`**  MATCH word for entering ATTACKMODE HID STORAGE
   - **`getonline_H`**  MATCH word for entering ATTACKMODE HID
   - **`getonline_P`**  MATCH word for entering ATTACKMODE HID SERIAL
   - **`getonline_A`**  MATCH word for entering ATTACKMODE HID AUTO_ETHERNET
   - **`getonline_X`**  MATCH word for Remove Croc_Getonline payload, contents and reboot
   - **`getonline_T`**  MATCH word for Stopping ICMP/PORT alert

* **LED STATUS**
  - **`LED WHITE`** Entering ATTACKMODE
  - **`LED ATTACK`** Retrieving wifi access point credentials
  - **`LED SETUP`** Configuring keycroc wlan0 interface to wifi access point
  - **`LED GREEN`** Successful connection to wifi access point
  - **`LED RED`** Payload failed
  - **`LED CYAN`** Performing recon scan
  - **`LED RED FLASH`** ICMP/PORT alert

**NOTE:** for linux edit payload for password needed for sudo permission.

## PAYLOAD OPTIONS :

Editing payload variable options:
- **`option=0`**

   - This option will run payload as normal, attempt to connect Keycroc to wifi access point.

- **`option=1`**

   - This option will run payload as normal, after a successful connection open terminal on target and start ssh session. 
   - ( EDIT PAYLOAD FOR KEYCROC PASSWORD )

- **`option=2`**

   - This option will run payload as normal, after a successful connection attempt a connection to remote_host using SSH. 
   - ( EDIT PAYLOAD FOR REMOTE_HOST, USER_NAME, IP, PASSWORD ON REMOTE_HOST ENTER THIS COMMAND "ssh root@localhost -p port#" )
   - SSHPASS is a requirement for this option, payload will attempt to install if not installed.

- **`option=3`**

   - This option will run payload as normal, after a successful connection attempt a connection to remote_host using netcat. 
   - ( EDIT PAYLOAD FOR REMOTE_HOST, IP START LISTENER ON REMOTE_HOST WITH THIS COMMAND "nc -lnvp PORT# -s IP_REMOTE_HOST" )

- **`option=4`**

  - This option will run payload as normal, after a successful connection open default browser and start web page.
  - ( EDIT PAYLOAD FOR WEB SITE DEFAULT https://forums.hak5.org )

* **Configuring RECON scan with recon=on and recon=off**

The options recon=off and recon=on play a key role in performing basic recon scans using Nmap, Iw, and Curl.

- **`recon=off`**

  - Suppresses active reconnaissance to maintain stealth.
  - Useful for discreet scanning in sensitive environments.

- **`recon=on`**

  - Initiates basic network reconnaissance scans.
  - Utilizes Nmap, Iw, and Curl to gather essential network information and save to /root/udisk/tools/Target_SSID.txt.

* **Configuring ICMP and Port Alerts with alert=on and alert=off**

- **`alert=on`**
 
   - ICMP Alert: It blocks outgoing ICMP and UDP packets with specific destination ports (33434 and 33534) for a minute and then restores the original firewall rules.
   - Port Alert: It drops incoming TCP packets with the SYN flag set for a minute and then restores the original firewall rules.

- **`alert=off`**

   - If alert is set to off, the script does nothing ( : represents a null command in bash ). No alerts are set up.

To summarize, ICMP and Port alerts when alert=on by using the icmp_alert() and port_alert() functions, respectively. It saves the current firewall rules to a backup file and runs the alert functions in the background, storing their respective PIDs in temporary files. If alert=off, the script does nothing related to alerts.

## PAYLOAD INFO :

- **PowerShell script that performs the following actions:**

Gets the drive letter of a volume with the label "KeyCroc" and assigns it to the $MOUNT_POINT variable using the Get-WmiObject cmdlet.
Gets the SSID of the currently connected wireless network and assigns it to the $currentSSID variable using the netsh wlan command and Select-String cmdlet.
Gets the password for the current wireless network and assigns it to the $lastObject variable using the netsh wlan command, Select-String cmdlet, and a series of ForEach-Object and Select-Object cmdlets. The password is then formatted as a string and written to a file at the location specified by $MOUNT_POINT and exits the script.

- **Bash script that performs the following actions:**

Sets the mount point for a volume with the label "KeyCroc" to /media/$(whoami)/KeyCroc.
Gets the SSID of the currently connected wireless network using the iw command, grep, and awk to extract the SSID.
Gets the password for the current wireless network by searching for the SSID in the /etc/wpa_supplicant/wpa_supplicant.conf file and extracting the password using sed.
Writes the SSID and password to a file located at $MOUNT_POINT using tee.
Unmounts the volume at $MOUNT_POINT using umount, and exits the script.

- **Bash script that performs the following actions:**

Sets the mount point for a volume with the label "KeyCroc" to /mnt/usb.
Creates the mount point directory using mkdir with the -p flag to create the directory if it does not exist.
Mounts the volume with the label "KeyCroc" to the mount point directory using the mount command with the -L flag to specify the label of the volume to be mounted.
Gets the SSID of the currently connected wireless network using the iw command, grep, and awk to extract the SSID.
Gets the password for the current wireless network by searching for the SSID in the /etc/NetworkManager/system-connections/ directory and extracting the password using grep and sed.
Writes the SSID and password to a file located at $MOUNT_POINT using tee with sudo to obtain elevated privileges.
Unmounts the volume at $MOUNT_POINT using umount, and exits the script.

Overall, this script retrieving the Wi-Fi password for the currently connected network and storing it in a file located on a specific mounted volume with the label "KeyCroc".

- **Sed command that performs the following actions:** 

By default, sed reads each line of a file. For each cycle, it removes the newline, places the result in the pattern space, goes through a sequence of commands, re-appends the newline and prints the result e.g. sed '' file replicates the cat command. The sed commands are usually placed between '...' and represent a cycle, thus:

- 1{x;s#^#sed -n 1p wifipass.txt#e;x}

1{..} executes the commands between the ellipses on the first line of wifipass.txt. Commands are separated by ;'s
x sed provides two buffers. After removing the newline that delimits each line of a file, the result is placed in the pattern space. Another buffer is provided empty, at the start of each invocation, called the hold space. The x swaps the pattern space for the hold space.
s#^#sed -n 1p wifipass.txt this inserts another sed invocation into the empty hold space and evaluates it by the use of the e flag. The second invocation turns off implicit printing (-n option) and then prints line 1 of wifipass.txt only.
x the hold space is now swapped with the pattern space.Thus, line 1 of wifipass.txt is placed in the hold space.

- 10{G;s/\n(\S+).*/ \1/}

10{..} executes the commands between the ellipses on the tenth line of config.txt.
G append the contents of hold space to the pattern space using a newline as a separator.
s/\n(\S+).*/ \1/ match on the appended hold space and replace it by a space and the first column.

- 11{G;s/\n\S+//}

11{..} executes the commands between the ellipses on the eleventh line of config.txt.
G append the contents of hold space to the pattern space using a newline as a separator.
s/\n\S+// match on the appended hold space and remove the newline and the first column, thus leaving a space and the second column. 
