
# Payload Library for the Key Croc by Hak5

This repository contains payloads and extensions for the Hak5 Bash Bunny. Community developed payloads are listed and developers are encouraged to create pull requests to make changes to or submit new payloads.

## About the Key Croc


The Key Croc by Hak5 is a keylogger armed with pentest tools, remote access and payloads that trigger multi-vector attacks when chosen keywords are typed. It's the ultimate key-logging pentest implant.

-   [Purchase at Hak5](https://hak5.org/products/key-croc "Purchase at Hak5")
-   [Documentation](https://docs.hak5.org/hc/en-us/categories/360003797793-Key-Croc "Documentation")
-   [Bash Bunny Forums](https://forums.hak5.org/forum/106-key-croc/ "Forums")
-   Discord:  [https://hak5.org/discord](https://hak5.org/discord)

![Key Croc](https://cdn.shopify.com/s/files/1/0068/2142/products/keycroc1b_300x.png.jpg)

## Disclaimer
Generally, payloads may execute commands on your device. As such, it is possible for a payload to damage your device. Payloads from this repository are provided AS-IS without warranty. While Hak5 makes a best effort to review payloads, there are no guarantees as to their effectiveness. As with any script, you are advised to proceed with caution.

## Legal
Payloads from this repository are provided for educational purposes only.  Hak5 gear is intended for authorized auditing and security analysis purposes only where permitted subject to local and international laws where applicable. Users are solely responsible for compliance with all laws of their locality. Hak5 LLC and affiliates claim no responsibility for unauthorized or unlawful use.

## Contributing
Once you have developed your payload, you are encouraged to contribute to this repository by submitting a Pull Request. Reviewed and Approved pull requests will add your payload to this repository, where they may be publically available.

Please adhere to the following best practices and style guide when submitting a payload.

### Naming Conventions

Payloads should be submitted to the most approporiate category directory. These include credentials, exfiltration, phishing, prank, recon, etc.

Each payload should have a unique, descriptive directory and filename, e.g., `WIN_powershell_SMB_exfiltration.txt`

The directory name for the payload should match the payload file name.

If the payload is OS specific (I.e., a Windows powershell attack), the filename should be prefixed with that OS. Prefixes include:
* `WIN_` for Windows
* `MAC_` for MacOS
* `LINUX_` for all Linux flavors
* `MULTI_` for multi-OS payloads

If the payload is OS agnostic (I.e., it substitutes text or otherwise make no interaction with the target OS), the filename should not include an OS prefix.

If multiple individual OS specific payloads are included, the directory name should be prefixed with `MULTI_` while each payload file name therein should be prefixed with the specific OS.

Please give your payload a unique and descriptive name. Do not use spaces in payload names. Each payload should be submit into its own directory, with `-` or `_` used in place of spaces, to one of the categories such as exfiltration, phishing, remote_access or recon. Do not create your own category.

### Comments

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
  
### Configuration Options

Payloads should be written in a flexible way such that modifications may be made by changing variables. Variables should use descriptive names where possible. All variables for a payload should be specified, as practical, just below the comment block at the top of the payload file. 

For true or false variables, use `VARIABLE=1` for true and `VARIABLE=0` for false.

In the case that the payload is Cloud C2 aware (e.g., for optional exfiltration or notification), the `CLOUDC2=1` variable should be set.

```
CMD_OBFUSCATION=1
CLOUDC2=1
```

### Payload Documentation

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
