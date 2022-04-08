#!/bin/bash

function quackWindows() {

	# open PowerShell via run menu
	Q GUI r
	Q DELAY 1000

	# powershell
        QUACK ALTCODE 112
        QUACK ALTCODE 111
        QUACK ALTCODE 119
        QUACK ALTCODE 101
        QUACK ALTCODE 114
        QUACK ALTCODE 115
        QUACK ALTCODE 104
        QUACK ALTCODE 101
        QUACK ALTCODE 108
        QUACK ALTCODE 108

	Q ENTER
	Q DELAY 500

	# Set-WinUserLanguageList en-US ; exit
        QUACK ALTCODE 83
        QUACK ALTCODE 101
        QUACK ALTCODE 116
        QUACK ALTCODE 45
        QUACK ALTCODE 87
        QUACK ALTCODE 105
        QUACK ALTCODE 110
        QUACK ALTCODE 85
        QUACK ALTCODE 115
        QUACK ALTCODE 101
        QUACK ALTCODE 114
        QUACK ALTCODE 76
        QUACK ALTCODE 97
        QUACK ALTCODE 110
        QUACK ALTCODE 103
        QUACK ALTCODE 117
        QUACK ALTCODE 97
        QUACK ALTCODE 103
        QUACK ALTCODE 101
        QUACK ALTCODE 76
        QUACK ALTCODE 105
        QUACK ALTCODE 115
        QUACK ALTCODE 116
        QUACK ALTCODE 32
        QUACK ALTCODE 101
        QUACK ALTCODE 110
        QUACK ALTCODE 45
        QUACK ALTCODE 85
        QUACK ALTCODE 83
        QUACK ALTCODE 32
        QUACK ALTCODE 59
        QUACK ALTCODE 32
        QUACK ALTCODE 101
        QUACK ALTCODE 120
        QUACK ALTCODE 105
        QUACK ALTCODE 116

	Q ENTER
	Q ENTER
}

case $1 in

  Windows)
    quackWindows
    ;;

  Linux)
    ;;

  Mac)
    ;;

esac
