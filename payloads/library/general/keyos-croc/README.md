# KeyOS Croc
KeyOS Croc is an extension for the [Key Croc](https://hak5.org/products/key-croc) tool by Hak5. The main functionality of this extension is a basic operating system and keyboard layout detection by analyzing DHCP packets and "brute-forcing" (power)shell commands. Besides helper scripts are provided that allow root / admin right detection, easy binary execution (incl. command line arguments) and file extraction. An example for stealing the Firefox cookies.db using a golang executable and a Ducky Script is given.

## Installation
1. Connect Key Croc to Internet, connect via SSH
    - [Configure](https://docs.hak5.org/hc/en-us/articles/360048015093-Getting-the-Key-Croc-Online) the Key Croc to use your WLAN AP
        ```
        # /root/udisk/config.txt
        ...
        SSH ENABLE
        WIFI_SSID <ssid>
        WIFI_PASS <psk>
        DNS 1.1.1.1 8.8.8.8
        ...
        ```
    - Get the IP addr of your Key Croc, e.g. scan your network with `nmap` or use the router's list of conneced hosts
    - Connect to the Key Croc via SSH: `ssh root@X.X.X.X` (PW: `hak5croc`)
2. Clone the repo (`git clone https://github.com/konstantingoretzki/keyos-croc`) and execute `install-keyos.sh` (`cd keyos-croc && chmod +x install-keyos.sh && ./install-keyos.sh`)
3. Customize `/root/udisk/payloads/payload.sh` according to your wishes (see [settings](#settings))
4. Reboot the device (`reboot`)

**Note:** Unfortunately, updating is not currently supported. In order to get the newest KeyOS Croc features you have to either make the changes by hand or reflash to the latest supported Hak5 version (`1.3_510`) and then run the the KeyOS Croc installation process.

## Usage
Depending on your configuration (see [settings](#settings)) the framework can do the following things:
1. WLAN geofencing: wait for WLAN APs to be present or absent
2. Detect the OS
3. Detect the used keyboard layout
	- A) Try to write a file to the mass storage using different keyboard layouts
	- B) Windows only: force to use the 'us' layout using alt codes
4. Check if higher execution rights are available
5. Execute any payload (cross-platform): 
    - A) Ducky Script snippets depending of the OS type, for your own take a look at `scripts/template.sh`
    - B) Binaries (using a wrapper that can work with cmdArgs, use optional higher rights and chooses the correct file depending on the OS type)
6. Save extracted files from the mass drive to the `/root/udisk/loot`-location

The LED will blink yellow if the framework is working. The LED will turn red if there has been an error (take a look into the `/root/udisk/keyos-log.txt`-file for debug information). If the set detections (optional) and the payload execution was successful the LED will turn green.

## How it works

### WLAN geofencing
The WLAN geofencing mode allows to only start with the execution of the detections and the payload if certain WLAN access points (2.4 GHz) are / aren't in range. This is done by scanning for access points in the range and parsing their SSIDs. The syntax is a bit complicated but very flexible and allows multiple devices sets that have to be present / absent.

```
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
```

It is recommended to not use this feature if at the same time the Key Croc is connected to a WLAN access point and is accessed via SSH. Also keep in mind that scanned APs are heavily cached so it can take up to 30 seconds to detect their absence.

### OS detection
The OS detection works by analyzing sniffed DHCP packets (DHCPREQUEST and DHCPDISCOVER) via Python and `scapy`. This method allows a passive OS fingerprint. Compared to scanning the host with a tool like `nmap` this approach is also much faster and more reliable. Due to the usage of DHCP packets new OS types / versions can be easily add simply by tuning the used DHCP options. For more information take a look at [os-fingerprinting.md](./os-fingerprinting.md)

The following OS have been tested and can be recognized:
- Microsoft Windows
    - Windows 10 Pro Build 2004
    - Windows 10 Pro Build 21H1
- Linux
    - Ubuntu 20.04.1 LTS
    - Ubuntu 21.04 (OS detection works but HID e.g. for the layout detection only works with Xorg and **not** Wayland)
- (macOS Catalina 10.15.6 - see [TODO](#todo))

Other OS versions might work aswell. However testing for them is necessary as DHCP options can change from version to version.

### Keyboard layout detection
To determine the keyboard layout a test file is written to a created USB storage device (not the default drive from the Key Croc). The main script (`payload.sh`) runs and checks if a file could be found. If not the write failed and the wrong keyboard layout was selected. Another try will be made.

While this approach isn't that fast, especially if you have a huge subset of possible layouts, it is the only way that can be used cross-platform. Keyboards send the currently pressed keys (by using keycodes) if they get asked by an USB host. However only the OS of the USB host knows how to interpret the returned keycodes and decides wether an keycode will be mapped to e.g. `z` or `y`.

The keyboard layouts for German, English and French are tested and work one after the other without any problems. Other subsets of layouts can be set but the layouts should be supported by the Key Croc framework (language files exist, needed keys are set and work). In addition the layouts of the subset should be tested to work even one after the other, especially if the prior try failed and could therefore leave an unclean state (e.g. the terminal window is still open and all subsequent commands fail).

#### Alt codes
On Windows alt codes can be used to write chars independent of the set keyboard layout. A [helper script](scripts/altcon.py) to convert a string to a sequence of Ducky Script alt codes can be used. However typing alt codes can be quite slow. A proposed and implemented solution is to force the Windows USB host to use the 'us' keyboard layout. To use this method set the `winForceUS` variable to 1. This only works if the OS is Windows (detected or `os` variable set). Keep in mind that the set layouts of the Windows host before will be overwritten!

While there is an alternative ([Unicode codes](https://help.ubuntu.com/stable/ubuntu-help/tips-specialchars.html.en)) on Ubuntu, this can not be used as also hex chars are needed.

## Settings
You can set the features to use by adjusting the `/root/udisk/payloads/payload.sh`-file. You can do this either by editing the file with an editor over SSH or by using the Key Croc's [arming mode](https://docs.hak5.org/hc/en-us/articles/360047380574-Key-Croc-Basics) and editing the file directly from the mounted mass storage (do not forget to safely unplug!).

```
################################################################################
# configure detection (OS, layout and root) and payload
################################################################################

# WLAN AP geofencing
# set to 1 is active, 0 is deactivated
# set the allowed / denied devices in the wlanFencing function
doWlanFencing=0

# OS detection
# if the string is empty then script will try to determine the OS
# if an OS ("Windows", "Linux" or "Mac") is set the detection will be skipped
# and the set element value will be used
os=""

# Layout detection
# keyboard layouts that should be tried
# testing order is from left to right
# if the array only contains one element the detection will be skipped
# and the set element value will be used
# if no value is set the default value ("us") will be used
langs=( de us fr )
# if the OS is Window (detected or the variable is set by the user)
# the framework can use alt codes to force the host the use the 'us' layout
# instead of trying to detect the used keyboard layout
# set to 1 is active, 0 is deactivated
# layouts in the langs array will be ignored in this case
winForceUS=0

# Root / admin detection
# check if higher rights can be get
# set to 1 is active, 0 is deactivated
rootCheck=1


# Payload
# if a custom DUCKY SCRIPT file should be used then set the variable
# to the path of the file, e.g. "/root/udisk/library/stealCookies.sh"
# compatible DUCKY SCRIPT files should be placed in "/root/udisk/library/"
# "/root/udisk/library/template.sh" can be used as a template
# just adjust the QUACK calls in the OS functions
# if a binary should be executed then set the variable to "/root/udisk/library/payload-execute.sh"
# binaries named "win.exe", "lin" and "mac" should be placed in "/root/binaries/"
payload="/root/udisk/library/payload-execute.sh"
#payload="/root/udisk/library/stealFirefoxCookies.sh"
# for binaries optional command line arguments can be passed by setting cmdArgs
# if not needed, set it to an empty string
cmdArgs="cookies"
# file that is created by the DUCKY SCRIPT or binary to detect if the execution is finished
# needed if the type time != execution time
# e.g. when copying large files
# if not needed then set it to an empty string
# the framework will go on will not wait for any created files
doneFile="done.txt"
# maxTries = max seconds to wait for completion of a given payload
# if a payload takes longer than the specified seconds then the execution will be stopped
maxTries=15
# is root/ admin needed for the payload execution?
# if set to 1 the script uses "sudo" as prefix or a "run as admin"-started terminal
# if a root check has been done before, root is not available but needed the execution will be stopped
needRoot=0
# cp wildcard to extract files from the mass storage, comment out or set to empty string if not used
# files will be copied to the "loot" location ("/root/udisk/loot")
extractFiles="cookies[0-9]*.sqlite"

################################################################################
```

Here are some examples for certain workflows:
- OS is Windows, layout is either us or de, execute Ducky Script
    ```
    os="Windows"
    langs=( us de )
    payload="/root/udisk/library/<my-script>.sh"
    ```
- OS should be detected, layout is us, execute binary payload with cmdArgs, extract files
    ```
    os=""
    langs=( us )
    payload="/root/udisk/library/payload-execute.sh"
    cmdArgs="places"
    extractFiles="places[0-9]*.sqlite"
    ```
-  OS and layout are known, check for root, execute binary payload only if root available 
    ```
    os="Linux"
    langs=( us )
    rootCheck=1
    payload="/root/udisk/library/payload-execute.sh"
    needRoot=1
    ```
- OS is Windows, use altcodes to force 'us' layout, execute Ducky Script
    ```
    os="Windows"
    winForceUS=1
    payload="/root/udisk/library/<my-script>.sh"
    ```

## TODO
### Project specific
- [ ] **Testing**: a project like this depends heavily on testing. Every system is different and even the slightest difference can determine if the executions fails or works.
    - [ ] **Test on macOS**: this project is a port of the [aloa-extensions](https://github.com/konstantingoretzki/aloa-extensions) that I've created for the [P4wnP1 A.L.O.A.](https://github.com/RoganDawes/P4wnP1_aloa). While I've tested the original code on macOS, this is currently not the case for this port. It will be a while before I can get my hands on macOS hardware for testing again, so testers are (even on other platforms) welcome ;)
- [x] **US layout**: num lock had to be enabled to be able to type numbers on the us layout. Adjusting the order of the keycodes (prefer numbers over numpad numbers) fixes this.


### Key Croc
- [ ] **Lock state**: add a dedicated script to get the lock states (e.g. num lock or caps lock), LED states should be readable on Windows and Linux.
- [ ] **Jitter**: make it possible to add random delays to prevent triggering anomaly detection systems
- [x] **Altcodes**: fix `write_altcode`-function in order to work independent from the numlock state

### General
- [ ] **HID on Wayland**: on Wayland keystroke injections (even with other frameworks like the [P4wnP1 A.L.O.A.](https://github.com/RoganDawes/P4wnP1_aloa) aren't possible, maybe Wayland is using other keycodes or handling input differently? research is needed

## Troubleshooting
The main steps are logged inside `/root/udisk/keyos-log.txt`. If you experience any issues please take a look into this file. It can also help to run the main `/root/udisk/payloads/payload.sh` interactively to see what happens and which steps might fail. Adjusting the `payload.sh`-file to skip certain checks or stop after a specific detection can reduce the waiting time drastically.

## Credits to
- [lartsch](https://forums.hak5.org/profile/84374-lartsch/): fix [matchless payloads](https://forums.hak5.org/topic/55695-fix-for-matchless-payloads-not-running/) detection, temp. fix for the broken alt codes support
- [emptyhen](https://github.com/emptyhen): fix [broken numbers](https://github.com/hak5/keycroc-payloads/pull/6) on 'us' layout if numlock is off
- [marius56](https://github.com/marius56): idea to use nested lists for the wlanFencing-script
