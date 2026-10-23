# dmesh-rawnan

Raw NAN is a common implementation of a subset of Wifi Aware/NAN
for Linux and ESP32 (and others if they have the monitor/transmit action frame
capability), along with a subset/extensions for ESP-NOW.

If an Android/iPhone NAN beacon is detected, both Android and ESP32 will sync
on it and participate in SD - but they can emit beacons due to hardware restrictions.

In the absence of a NAN beacon they will send ESP-NOW action frames - with the 
same frame content as the NAN beacons and NAN SD, so most of the code is shared.
The algorithms are similar - but without the exact time base sync, just approximate
wakeups every 512ms synced on previous 'NOW-action-as-beacon' frame.

The purpose is to have a minimal set of primitives over action frames that are broadly
available, to allow sleep synchronization and service discovery for devices that
lack NAN support - and also allow them to participate in the NAN discovery.

## NAN - Wifi Aware

NAN is ONLY used to sync on the beacon and maintain a discovery window in sleepy
devices. Real NAN chips in Android/iPhone sends the beacons.

ESP32 and Linux send/receive service discovery frames - they are action frames.

On ESP32, NAN support requires promiscuous mode - but only for very short intervals
every 512ms (or 4 seconds for battery devices). 

On Linux, monitor mode is required, and an AP needs to run on the interface to
keep the device active and on the right channel. The AP also sends regular beacons
and can be discovered by Android/ESP32.

## ESP-NOW

ESP-NOW is used because on ESP32 the firmware allow receiving ESP-NOW action frames without
requiring the more expensive promiscuous mode. Unfortunately no other action frame is allowed,
except those in the same SSID/AP.

Another reason is that ESP32 allow long-range - using a custom more redundant but lower
speed modulation.

The 'extension' is that we don't follow the IE encoding - but append the payload immediately
after the required ESP-NOW header, more efficient and a bit higher MTU. The first
vendor IE contains metadata/padding only (one pad byte by default); receivers skip
the whole IE and deliver every following byte as the datagram. The 16-byte action
prefix permits aligned in-place ESP TX with the usual 144-byte payload offset.
This replaces the older multi-IE/first-payload-in-IE encoding; peers must be rebuilt together.

## P2P - Wifi Direct

There is some code to parse P2P. This is WIP and may be removed if everything works 
with NAN. This is a form of DNS-SD using Wifi action frames directly, and is similar
to NAN.

The main problem is that on Android NAN can't coexist with P2P, and also Android 
is very unfriendly to open APs (mesh encrypts and authorizes on top of open radio -
FSK, LoRa - and doesn't trust or rely on Wifi encryption). P2P support is intended
for the minimal scope of discovery in Android when AP/STA chains are created (multiple
devices connecting to each other, acting as both AP and STA connected to previous AP
device in the chain).

## Low level formats

### NAN

Beacon is similar to AP, so heavily blocked from user space. It has FF..FF broadcast
DST, source MAC and either the broadcast NAN cluster or the actual NAN cluster.
That's a very interesting feature, since the 3rd address is used for filter and 
create 'virtual interfaces - so NAN avoids the broadcast action frames used by NOW.

The actual beacon data is: 8 bytes timestamp, beacon interval, capability (IBSS/Ad-Hoc !),
followed by TLVs ('IE'): master preference, rank, hop count.

SDF (service discovery frame) is using DA as broadcast or specific MAC, with the cluster MAC
as A3. It starts with "0x04" (public action), 0x09 (vendor action), 0x506F9A - NAN OUI, 0x13 (NAN),
and TLVs.

## NOW

ESP-NOW uses FF..FF or actual DST, and A3 is broadcast or the source address, as if the source was an AP.

Payload starts with 0x7F - vendor specific action - instead of 0x04 (public action frame, followed by 0x09 vendor action
in NAN). Payload is 1470 bytes.

ESP-NOW supports its own encryption - AES-128-CCMP, with 16 bytes overhead.

Technically 0x04 public action frames are supposed to work 'outside BSSID' - but they don't on ESP32.
Only NOW frames are received (outside promiscouous), so a protocol involving ESP32 has to use them.



