

## Debugging

Most difficult part is keeping the network alive in doze/idle mode - most popular commands:

```
adb shell dumpsys deviceidle force-idle
adb shell dumpsys battery unplug
adb shell dumpsys battery reset

adb shell am get-idle PACKAGE
adb shell am set-idle PACKAGE true|false

```

In idle mode, ping does not work - tcpdump shows the packet is sent, but response doesn't make it trough (at least to the shell)

## Tcpdump

```
# Wifi Direct uses 1,6,11 for announcements / discovery - useful to stay in those
# channels even in AP/client mode
iw phy phy0 set channel 6 

# Radio tap shows signal level, freq, low level Wifi frames
wireshark -i wlan0 -I -y IEEE802_11_RADIO

Filters:
wlan_mgt.ssid contains "DIRECT"

```
