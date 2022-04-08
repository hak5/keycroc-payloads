# OS fingerprinting

OS detection works by analyzing DHCP discover and request packets via [scapy](https://scapy.net/) in Python. This can be done by looking for characteristic options that are set / requested by the DHCP client (the device where the Key Croc is plugged in). The order of the options matters.

The provided Python script currently only looks for DHCP Discover and DHCP Request packets. Besides the Vendor ID Class (Option 60) only the existence of specific subsets of options (not their order) of the Parameter Request List (Option 55) can be checked. For support of more options manual decoding and parsing is required.

For debugging `tcpdump` can be used (`tcpdump -i usb0 port 67 or port 68 -w sniff.pcap`) to sniff and a tool like Wireshark can be used to get a closer look of the packet structure and its available options.

## Extracted DHCP options

Some options depend on DHCP packet type (Discover != Request). The Parameter Request List should be the same for all DHCP Discover and DHCP Request packets.

### Windows 10 (Pro, Build 2004):
- Options: 53,61,12,81,60,55,255 (type ?)
    - 60: MSFT 5.0 (Vendor ID Class, set on DHCP Discover and DHCP Request packets)
    - 55: 1,3,6,15,31,33,43,44,46,47,119,121,249,252 (Parameter Request List)
    - Fingerprint: Vendor ID Class
    
### Windows 10 (Pro, Build 21H1):
- Options: 53,61,50,12,60,55,255 (Discover) / 53,61,50,54,12,81,60,55,255 (Request)
    - 60: MSFT 5.0 (Vendor ID Class, set on DHCP Discover and DHCP Request packets)
    - 55: 1,3,6,15,31,33,43,44,46,47,119,121,249,252 (Parameter Request List)
    - Fingerprint: Vendor ID Class

### Ubuntu (20.04.1 LTS, 5.4.0-42):
- Options: 53,61,55,57,12,255 (type ?)
    - 55: 1,2,6,12,15,26,28,121,3,33,40,41,42,119,249,252,17 (Parameter Request List)
    - Fingerprint: **PRL 2,12** (use 17 to differ from 20.04 and 21.04)

### Ubuntu (21.04, 5.11.0-31):
- Options: 53,12,55,255 (Discover) / 53,54,50,12,55,255 (Request)
    - 55: 1,28,2,3,15,6,119,12,44,47,26,121,42 (Parameter Request List)
    - Fingerprint: **PRL 2,12**

### macOS Catalina (10.15.6)
- Options: 53,55,57,61,51,12,255 (type ?)
    - 55: 1,121,3,6,15,119,252,95,44,46 (Parameter Request List)
    - Fingerprint: **PRL 95** (LDAP, possible that this is only the case on the test system)
    
Ubuntu 20.04 and 21.04 share these options exclusively: **PRL 2,28,12,26,42**

## Additional information
More information about the technical details of OS fingerprinting via DHCP packets can be found here:
- D. Hull und G. F. Willard III, “Next Generation DHCP Deployments”, 2005. Available: [https://kuscholarworks.ku.edu/bitstream/handle/1808/584/NGDHCP.pdf](https://kuscholarworks.ku.edu/bitstream/handle/1808/584/NGDHCP.pdf).
- R. Droms,RFC 2131: Dynamic Host Configuration Protocol, 1997.
- S. Alexander und R. Droms, RFC 2132: DHCP Options and BOOTP Vendor Extensions, 1997.
- D. LaPorte und E. Kollmann. (). “Using DHCP for Passive OS Identification”, Available: [https://slideplayer.com/slide/2499137/](https://slideplayer.com/slide/2499137/).
- O. Bilodeau. (2011). “FingerBank - open DHCP fingerprints database”, Available: [https://www.defcon.org/images/defcon-19/dc-19-presentations/Bilodeau/DEFCON-19-Bilodeau-FingerBank.pdf](https://www.defcon.org/images/defcon-19/dc-19-presentations/Bilodeau/DEFCON-19-Bilodeau-FingerBank.pdf).
