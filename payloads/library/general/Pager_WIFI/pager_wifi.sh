# Title: Pager WIFI
# Description: Connect keycroc to WiFi Pineapple Pager open AP
# Author: spywill
# Version: 1.0
# Category: Key Croc

MATCH pager_wifi

PAGER_SSID="pager-open"
IFACE=$(iw dev | awk '$1=="Interface"{print $2; exit}')

iw dev "$IFACE" scan 2>/dev/null | grep -q "SSID: $PAGER_SSID"
if [ $? -eq 0 ]; then
	LED SETUP
	kill -9 $(pidof wpa_supplicant) && kill -9 $(pidof dhclient)
	ifconfig wlan0 down

cat > /etc/wpa_supplicant.conf <<EOF
network={
    ssid="$PAGER_SSID"
    key_mgmt=NONE
}
EOF

	ifconfig wlan0 up
	wpa_supplicant -B -D nl80211 -iwlan0 -c /etc/wpa_supplicant.conf && dhclient wlan0
	sleep 3
	systemctl restart ssh.service
else
	LED R
	exit
fi

if iw dev "$IFACE" link | grep -q "SSID: $PAGER_SSID"; then
    LED G
else
    LED R
fi
sleep 5
LED OFF
