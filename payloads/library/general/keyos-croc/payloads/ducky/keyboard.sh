#!/bin/bash

function quackWindows() {

	# open PowerShell via run menu
	Q GUI r
	Q DELAY 500
	Q STRING powershell
	Q ENTER
	Q DELAY 500

	# get drive path
	Q STRING '$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq'
	Q STRING " 'sneaky'"
	Q STRING ' } | select -expand name'
	Q ENTER

	# create file on path and sync (clear write cache)
	Q STRING '[IO.File]::WriteAllLines((Join-Path $usbPath'
	Q STRING " 'language.txt'), '$DUCKY_LANG') ; Write-VolumeCache"
	Q STRING ' $usbPath[0]'
	Q ENTER
	Q ENTER
	Q STRING "exit"
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

	# create file on path and sync (clear write cache)
	Q STRING "echo '$DUCKY_LANG' > /media/"
	Q STRING '$(users)/sneaky/language.txt && sync'
	Q ENTER
	Q DELAY 1000
	Q ENTER
	Q STRING "exit"
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

        # enable switching buttons via TAB
        Q CONTROL F7

        # create file on path and sync (clear write cache)
        Q STRING "echo '$DUCKY_LANG' > /Volumes/sneaky/language.txt && sync"
        Q ENTER
        Q DELAY 1000
	Q TAB
	Q TAB
	Q SPACE

	# disable switching buttons via TAB
	# --> create clean state
        Q CONTROL F7
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
