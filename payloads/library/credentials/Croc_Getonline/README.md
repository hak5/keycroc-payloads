# Croc_Getonline

## INTRODUCTION :
  - This project is developed for the HAK5 KeyCroc
  - Attempt to connect Keycroc automatically to target wifi access point.

* **TESTED ON**
  - Windows 10
  - Raspberry pi 4 (bullseye image)
  - linux (parrot os)

## INSTALLATION :

  - Enter arming mode on your keycroc to install file.
  - Download the Croc_getonline.txt payload and Place this in the KeyCroc **payload folder**

## STARTING GETONLINE :

   - After install plug into target and type in anywhere
   - **getonline_W** <-- MATCH word for windows
   - **getonline_L** <-- MATCH word for Linux
   - **getonline_R** <-- MATCH word for Raspberry pi
   - When the payload is done running the LED will light up green
   - Keycroc should now be connected to target wifi access point
   - NOTE: for linux edit payload for passwd needed for sudo permission

## PAYLOAD INFO :

**PowerShell script that performs the following actions:**

Gets the drive letter of a volume with the label "KeyCroc" and assigns it to the $MOUNT_POINT variable using the Get-WmiObject cmdlet.
Gets the SSID of the currently connected wireless network and assigns it to the $currentSSID variable using the netsh wlan command and Select-String cmdlet.

Gets the password for the current wireless network and assigns it to the $lastObject variable using the netsh wlan command, Select-String cmdlet, and a series of ForEach-Object and Select-Object cmdlets. The password is then formatted as a string and written to a file at the location specified by $MOUNT_POINT.
Dismounts the volume at $MOUNT_POINT using the Dismount-WindowsImage cmdlet, and exits the script.

**Bash script that performs the following actions:**

Sets the mount point for a volume with the label "KeyCroc" to /media/$(whoami)/KeyCroc.
Gets the SSID of the currently connected wireless network using the iw command, grep, and awk to extract the SSID.
Gets the password for the current wireless network by searching for the SSID in the /etc/wpa_supplicant/wpa_supplicant.conf file and extracting the password using sed.
Writes the SSID and password to a file located at $MOUNT_POINT using tee.
Unmounts the volume at $MOUNT_POINT using umount, and exits the script.

**Bash script that performs the following actions:**

Sets the mount point for a volume with the label "KeyCroc" to /mnt/usb.
Creates the mount point directory using mkdir with the -p flag to create the directory if it does not exist.
Mounts the volume with the label "KeyCroc" to the mount point directory using the mount command with the -L flag to specify the label of the volume to be mounted.
Gets the SSID of the currently connected wireless network using the iw command, grep, and awk to extract the SSID.
Gets the password for the current wireless network by searching for the SSID in the /etc/NetworkManager/system-connections/ directory and extracting the password using grep and sed.
Writes the SSID and password to a file located at $MOUNT_POINT using tee with sudo to obtain elevated privileges.
Unmounts the volume at $MOUNT_POINT using umount, and exits the script.

Overall, this script retrieving the Wi-Fi password for the currently connected network and storing it in a file located on a specific mounted volume with the label "KeyCroc".

**-Sed command that performs the following actions:** 

By default, sed reads each line of a file. For each cycle, it removes the newline, places the result in the pattern space, goes through a sequence of commands, re-appends the newline and prints the result e.g. sed '' file replicates the cat command. The sed commands are usually placed between '...' and represent a cycle, thus:

1{x;s#^#sed -n 1p wifipass.txt#e;x}

1{..} executes the commands between the ellipses on the first line of config.txt. Commands are separated by ;'s
x sed provides two buffers. After removing the newline that delimits each line of a file, the result is placed in the pattern space. Another buffer is provided empty, at the start of each invocation, called the hold space. The x swaps the pattern space for the hold space.
s#^#sed -n 1p wifipass.txt this inserts another sed invocation into the empty hold space and evaluates it by the use of the e flag. The second invocation turns off implicit printing (-n option) and then prints line 1 of wifipass.txt only.
x the hold space is now swapped with the pattern space.Thus, line 1 of wifipass.txt is placed in the hold space.

10{G;s/\n(\S+).*/ \1/}

10{..} executes the commands between the ellipses on the tenth line of config.txt.
G append the contents of hold space to the pattern space using a newline as a separator.
s/\n(\S+).*/ \1/ match on the appended hold space and replace it by a space and the first column.

11{G;s/\n\S+//}

11{..} executes the commands between the ellipses on the eleventh line of config.txt.
G append the contents of hold space to the pattern space using a newline as a separator.
s/\n\S+// match on the appended hold space and remove the newline and the first column, thus leaving a space and the second column. 
