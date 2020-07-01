# Payload Library for the Key Croc by Hak5

![Key Croc](https://cdn.shopify.com/s/files/1/0068/2142/files/key-croc.png)

* [Purchase at Hak5.org](https://shop.hak5.org/products/key-croc "Purchase at Hak5.org")
* [Documentation](https://docs.hak5.org/hc/en-us/categories/360003797793-Key-Croc "Documentation")
* [Key Croc Forums](https://forums.hak5.org/forum/106-key-croc/ "Key Croc Forums")
* Discord:  https://discord.gg/WuteWPf

# Payload Submission Style Guide

When submitting payload pull requests to this repository, we ask that your payload use the following style:

## Categories & Directories

Payloads should be submitted to the most approporiate category directory. These include credentials, exfiltration, phishing, prank, recon, etc.

## Naming Conventions

Each payload should have a unique, descriptive directory and filename, e.g., `WIN_powershell_SMB_exfiltration.txt`

The directory name for the payload should match the payload file name.

If the payload is OS specific (I.e., a Windows powershell attack), the filename should be prefixed with that OS. Prefixes include:
* `WIN_` for Windows
* `MAC_` for MacOS
* `LINUX_` for all Linux flavors
* `MULTI_` for multi-OS payloads

If the payload is OS agnostic (I.e., it substitutes text or otherwise make no interaction with the target OS), the filename should not include an OS prefix.

If multiple individual OS specifc payloads are included, the directory name should be prefixed with `MULTI_` while each payload file name therein should be prefixed with the speicif OS.

## Comment Block

Each payload should begin with a comment block containing at least:

```
Title: <name of the payload>
Description: <Brief description of what the payload does>
Author: <name (I.e, twitter/Hak5 forum handle)>
```

Optionally, authors are encouraged to include these additional parameters:
```
# Version: <Number (e.g., 1.0)>
# Props: <people who inspired/helped the payload development>
# Target: <specific OS/version, (e.g., Windows XP SP3)
```

## Payload Documentation

If a payload requires additional documentation for use, such as requiring special dependency installation or use of the LED, it should be documented in the code block. In the case of LED for status, use the following:

```
# LED ERROR: Dependency not found
# LED SETUP: Starting services
# LED ATTACK: Performing attack
# LED SPECIAL: Exfiltrating loot
# LED CLEANUP: Removing temp files
# LED FINISH: Attack complete
```

If custom color/patterns are used instead of standard LED states, designate these status indications accordingly. 

Payloads may optionally include a `readme.md` file for documentation.

## Variables

Payloads should be written in a flexible way such that modifications may be made by changing variables. Variables should use descriptive names where possible. All variables for a payload should be specified, as practical, just below the comment block at the top of the payload file. 

For true or false variables, use `VARIABLE=1` for true and `VARIABLE=0` for false.

In the case that the payload is Cloud C2 aware (e.g., for optional exfiltration or notification), the `CLOUDC2=1` variable should be set.

```
CMD_OBFUSCATION=1
CLOUDC2=1
```
