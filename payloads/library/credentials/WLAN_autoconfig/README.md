# Autoconfiguration payload 

Starts in `ATTACKMODE HID STORAGE` and extracts with powershell commands SSID, password and keyboard-layout from the target system. 

Then the payload alters the `config.txt` and removes itself from the payloads directtory! **Attention:** the directory `/root/udisk/library/examples/` nust exist that the payload can move itself!

The croc should automatically reboot but this don't work actually - so unplug and replug the croc when the LED start flashing green.

In case another language-version of Windows will have SSID and password in other lines alter this 2 lines accordingly:

    # Config parameters
    name_line=11       # Line-number which contains the SSID
    pass_line=33       # Line-number which contains the password

Happy hacking ;-)
