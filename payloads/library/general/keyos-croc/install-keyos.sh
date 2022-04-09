#!/bin/bash

echo -e "\nPlease make sure that the Key Croc has internet connection! \n"

# version check
# especially needed because some croc files are changed
version=`cat /root/version.txt`
if [ "$version" != "1.3_510" ]
then
    echo -e "\nKey Croc is not on version 1.3_510 - things can break with newer / older version."
    echo -e "Script will stop.\n"
    exit 1
fi

# dependencies
echo "Installing dependencies ..."
apt update
apt install -y sqlite3 python3 python3-pip ntfs-3g
pip3 install scapy

# scripts
echo -e "\nInstalling scripts ..."
mkdir /root/scripts
cp scripts/analyze-pcap.py scripts/image-helper.sh scripts/altcon.py scripts/wlanFencing.py /root/scripts/
cp scripts/payload.sh /root/udisk/payloads/
chmod 751 /root/scripts/*
chmod 751 /root/udisk/payloads/payload.sh

echo -e "\nAdjusting framework files ..."
# fix match-less payloads detection
# thanks to lartsch (https://forums.hak5.org/profile/84374-lartsch/) for this fix
sed -i 's%for p in $(find /root/udisk/payloads -type f.*%for p in \$(find \/root\/udisk\/payloads -type f | xargs grep -cHP \x27\^(?=\[\\s\]\*+\[\^#\])\[\^#\]\*(MATCH)\x27 | grep 0\$ | cut -d\x27:\x27 -f1)%' /usr/local/croc/bin/croc_framework

# add line to ATTACKMODE
sed -i '/# start dhcp server/i  \\n\t\t# Added by KeyOS Croc\n\t\techo -n "sniff" > /root/pyrecv\n' /usr/local/croc/bin/ATTACKMODE

# set default DHCP timeout to sniff timeout
sed -i -r 's/timeout=[0-9]+/timeout=5/g' /usr/local/croc/bin/ATTACKMODE

# fix broken alt codes
sed -i '74,84d' /usr/local/croc/bin/QUACK
sed -i '/numlock = False/a\ \ \ \ hidg_write(\[0, 0, 83, 0, 0, 0, 0, 0\])\n\ \ \ \ time\.sleep(0\.01)\n\ \ \ \ hidg_write(\[0, 0, 83, 0, 0, 0, 0, 0\])\n\n\ \ \ \ with open("\/dev\/hidg0", mode=\x27r\x27) as f:\n\ \ \ \ \ \ \ \ out = f\.read(2)\n\ \ \ \ \ \ \ \ while not out:\n\ \ \ \ \ \ \ \ \ \ \ \ out = f\.read(2)\n\n\ \ \ \ \ \ \ \ numlock = (int(out\.encode(\x27hex\x27), 16) \& 0b00001) == 0b00001\n' /usr/local/croc/bin/QUACK

# payloads - binary
echo -e "\nCopy binary payloads ..."
mkdir /root/binaries
cp payloads/binary/executables/* /root/binaries/
chmod 751 /root/binaries/*

# payloads - Ducky Script
echo -e "Copy Ducky Script payloads ..."
cp payloads/ducky/* /root/udisk/library/
chmod 751 /root/udisk/library/* 

# language files
echo -e "Copy adjusted language files ..."
mv /root/udisk/languages/de.json /root/udisk/languages/de.json.bak
mv /root/udisk/languages/us.json /root/udisk/languages/us.json.bak
mv /root/udisk/languages/fr.json /root/udisk/languages/fr.json.bak
cp languages/* /root/udisk/languages/
chmod 751 /root/udisk/languages/de.json /root/udisk/languages/us.json /root/udisk/languages/fr.json

# drive images
echo -e "\nSetup drive images ..."
mkdir /root/ums
/root/scripts/image-helper.sh create
/root/scripts/image-helper.sh prepareAll

echo -e "\nInstalling done."
echo -e "Please reboot now to be able to use the KeyOS Croc.\n"
