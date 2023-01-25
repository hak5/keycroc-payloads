
# Payload Library for the [Key Croc](https://hak5.org/products/key-croc) by [Hak5](https://hak5.org)

This repository contains payloads and extensions for the Hak5 Key Croc. Community developed payloads are listed and developers are encouraged to create pull requests to make changes to or submit new payloads.

<div align="center">
<img src="https://img.shields.io/github/forks/hak5/keycroc-payloads?style=for-the-badge"/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<img src="https://img.shields.io/github/stars/hak5/keycroc-payloads?style=for-the-badge"/>
<br/>
<img src="https://img.shields.io/github/commit-activity/y/hak5/keycroc-payloads?style=for-the-badge">
<img src="https://img.shields.io/github/contributors/hak5/keycroc-payloads?style=for-the-badge">
</div>
<br/>
<p align="center">
<a href="https://payloadhub.com"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/payloadhub.png?v=1652474600"></a>
<br/>
<a href="https://hak5.org/blogs/payloads/tagged/key-croc">View Featured Key Croc Payloads and Leaderboard</a>
<br/><i>Get your payload in front of thousands. Enter to win over $2,000 in prizes in the <a href="https://hak5.org/pages/payload-awards">Hak5 Payload Awards!</a></i>
</p>


<div align="center">
<a href="https://hak5.org/discord"><img src="https://img.shields.io/discord/506629366659153951?label=Hak5%20Discord&style=for-the-badge"></a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<a href="https://youtube.com/hak5"><img src="https://img.shields.io/youtube/channel/views/UC3s0BtrBJpwNDaflRSoiieQ?label=YouTube%20Views&style=for-the-badge"/></a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<a href="https://youtube.com/hak5"><img src="https://img.shields.io/youtube/channel/subscribers/UC3s0BtrBJpwNDaflRSoiieQ?style=for-the-badge"/></a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
<a href="https://twitter.com/hak5"><img src="https://img.shields.io/badge/follow-%40hak5-1DA1F2?logo=twitter&style=for-the-badge"/></a>
<br/><br/>

</div>

# Shop
- [Purchase the Key Croc - the world's smartest keylogger](https://hak5.org/products/key-croc "Purchase the Key Croc - the world's smartest keylogger")
- [PayloadStudio Pro](https://hak5.org/products/payload-studio-pro "Purchase PayloadStudio Pro")
- [Shop All Hak5 Tools](https://shop.hak5.org "Shop All Hak5 Tools")

## Getting Started
- [Build Payloads with PayloadStudio](#build-your-payloads-with-payloadstudio) | [QUICK START GUIDE](https://docs.hak5.org/key-croc/getting-started/basics "QUICK START GUIDE") 

## Documentation / Learn More
-   [Documentation](https://docs.hak5.org/key-croc "Documentation") 

## Community
*Got Questions? Need some help? Reach out:*
-  [Discord](https://hak5.org/discord/ "Discord") | [Forums](https://forums.hak5.org/forum/106-key-croc/ "Forums")

## Additional Links
<b> Follow the creators </b><br/>
<p >
	<a href="https://twitter.com/notkorben">Korben's Twitter</a> | 
	<a href="https://instagram.com/hak5korben">Korben's Instagram</a>
<br/>
	<a href="https://twitter.com/hak5darren">Darren's Twitter</a> | 
	<a href="https://instagram.com/hak5darren">Darren's Instagram</a>
</p>

<br/>
<h1><a href="https://hak5.org/products/key-croc">About the Key Croc</a></h1>

The Key Croc by Hak5 is a keylogger armed with pentest tools, remote access and payloads that trigger multi-vector attacks when chosen keywords are typed. It's the ultimate key-logging pentest implant.
<b>
<div align="center">
<a href="https://www.youtube.com/watch?v=rDdA4ggyc8E">Launch Video</a>
<br/>
</div>
</b>
<p align="center">
<a href="https://hak5.org/products/key-croc"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/key-croc-diagram1_600x.png?v=1614333513"></a>
<br/><i>Hak5 Key Croc Hardware Features</i>
</p>
<br/>

The Key Croc by Hak5 is a keylogger armed with pentest tools, remote access and payloads that trigger multi-vector attacks when chosen keywords are typed. It's the ultimate key-logging pentest implant.

More than just recording and streaming keystrokes online, it exploits the target with payloads that trigger when keywords of interest are typed.

By emulating trusted devices like serial, storage, HID and Ethernet, it opens multiple attack vectors – from keystroke injection to network hijacking.

Imagine capturing credentials and systematically using them to exfiltrate data. Or pentest from anywhere, live in a web browser with [Hak5 Cloud C²](https://shop.hak5.org/products/c2 "Hak5 Cloud C²").

It's simple too. A hidden button turns it into a flash drive, where changing settings is just editing a text file. And with a root shell your favorite pentest tools like nmap, responder, impacket and metasploit are at the ready.


<p align="center">
<i> Hak5 Key Croc Pattern Matching Payloads</i><br/>
<a href="https://payloadhub.com"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/payload-until_600x.png?v=1614341304"></a><br/>
<i> Hak5 Key Croc Configuration - simply edit config.txt</i><br/>
<a href="https://payloadhub.com"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/key-croc-config_600x.png?v=1614333508"></a>
<br/>
</p>

# About DuckyScript™
<b> With the Key Croc in 2020, DuckyScript 2.0 has been introduced.</b>

While many of the Hak5 Tools run various versions of DuckyScript; like the [Bash Bunny](https://shop.hak5.org/products/bash-bunny) and even the [officially licenced DuckyScript compatible devices from O.MG](https://shop.hak5.org/collections/mischief-gadgets/ "O.MG") - the Key Croc uses an `INTERPRETED` version of DuckyScript

_Interpreted DuckyScript means the payload runs on the device straight from `source code` (the code you write e.g. `QUACK STRING test`)._

The files in this repository are _the source code_ for your payloads and run _directly on the device_ **no compilation required** - simply place your `payload.txt` in the appropriate directory and you're ready to go!

<h1><a href="https://payloadstudio.hak5.org">Build your payloads with PayloadStudio</a></h1>
<p align="center">
Take your DuckyScript™ payloads to the next level with this full-featured,<b> web-based (entirely client side) </b> development environment.
<br/>
<a href="https://payloadstudio.hak5.org"><img src="https://cdn.shopify.com/s/files/1/0068/2142/products/payload-studio-icon_180x.png?v=1659135374"></a>
<br/>
<i>Payload studio features all of the conveniences of a modern IDE, right from your browser. From syntax highlighting and auto-completion to live error-checking and repo synchronization - building payloads for Hak5 hotplug tools has never been easier!
<br/><br/>
Supports your favorite Hak5 gear - USB Rubber Ducky, Bash Bunny, Key Croc, Shark Jack, Packet Squirrel & LAN Turtle!
<br/><br/></i><br/>
<a href="https://hak5.org/products/payload-studio-pro">Become a PayloadStudio Pro</a> and <b> Unleash your hacking creativity! </b>
<br/>
OR
<br/>
<a href="https://payloadstudio.hak5.org/community/"> Try Community Edition FREE</a> 
<br/><br/>
<img src="https://cdn.shopify.com/s/files/1/0068/2142/files/themes1_1_600x.gif?v=1659642557">
<br/>
<i> Payload Studio Themes Preview GIF </i>
<br/><br/>
<img src="https://cdn.shopify.com/s/files/1/0068/2142/files/AUTOCOMPLETE3_600x.gif?v=1659640513">
<br/>
<i> Payload Studio Autocomplete Preview GIF </i>
</p>


## DuckyScript Ecosystem

<h3><a href='https://github.com/keycroc/keycroc-payloads/blob/master/languages'>Languages </a></h3>

Support for different keyboard layouts can be found, modified or contributed to in the <b><a href='https://github.com/keycroc/usbrubberducky-payloads/blob/master/languages'> languages/ </a></b> directory of this repository.

Unlike devices such as the Bash Bunny and USB Rubber Ducky - the Key Croc's language files are *just a bit different*. 
Due to the nature of supporting **real time decoding** and **real time MATCH payloads** the Croc has a bit more on it's plate in regards to what it means to support a keyboard language layout. 

For example, while performing Keystroke Injection - you may only ever require the `1` from the number row, or the right `GUI` key. The Key Croc on the other hand needs to not only know how to interpret _the entire keyboard_ but also a large variety of keyboard combinations to make matching and triggering on payloads work as you would expect it to; accurately and without delay. For these reasons, the Key Croc's language files are monolithic, statically and programatically generated to provide the absolute best possible experience.

The default language is US <a href='https://github.com/hak5/keycroc-payloads/blob/master/languages/us.json'>(languages/us.json)</a>


<h1><a href='https://shop.hak5.org/products/c2'>Hak5 Cloud C² </a></h1>
Cloud C² makes it easy for pen testers and IT security teams to deploy and manage fleets of Hak5 gear from a simple cloud dashboard. 

Cloud C² is available as an instant download. **A free license for Community Edition is available which is not for commercial use and comes with community support.**
The **Professional** and **Teams Editions** are for commercial use with standard support.
<p align="center">
<a href="https://shop.hak5.org/products/c2"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/teams1.png?v=1614035533"></a>
<br/>
<i> Hak5 Cloud C² Web Interface</i>
</p>


Cloud C² is a **self-hosted** web-based command and control suite for networked Hak5 gear that lets you **pentest from anywhere.**

Linux, Mac and Windows computers can host the Cloud C² server while Hak5 gear such as the WiFi Pineapple, LAN Turtle and Packet Squirrel can be provisioned as clients.

Once you have the Cloud C² server running on a public-facing machine (such as a VPS) and the Hak5 devices are provisioned and deployed, you can login to the Cloud C² web interface to manage these devices as if you were directly connected.

With multiple Hak5 devices deployed at a client site, aggregated data provides a big picture view of the wired and wireless environments.


<p align="center">
<a href="https://shop.hak5.org/products/c2"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/teams2.png?v=1614035564"/></a>
<br/>
<i> Hak5 Cloud C² Web Interface - Teams Edition - Sites </i>
</p>


Hak5 Cloud C² Teams edition comes full of features designed to help you manage **all** of your remote Hak5 devices with ease:
 - Multi-User
 - Multi-Site
 - Role-Based Access Control
 - Advanced Auditing
 - Tunneling Services including web Terminal and WiFi Pineapple web interface proxy

<a href="https://shop.hak5.org/products/c2">Learn More</a>

<h1><a href='https://payloadhub.com'>Contributing</a></h1>

<p align="center">
<a href="https://payloadhub.com"><img src="https://cdn.shopify.com/s/files/1/0068/2142/files/payloadhub.png?v=1652474600"></a>
<br/>
<a href="https://payloadhub.com">View Featured Payloads and Leaderboard </a>
</p>


Once you have developed your payload, you are encouraged to contribute to this repository by submitting a Pull Request. Reviewed and Approved pull requests will add your payload to this repository, where they may be publically available.

# Please adhere to the following best practices and style guides when submitting a payload.
### Purely Desctructive payloads will not be accepted. No, it's not "just a prank".

Payloads should be submitted to the most appropriate category directory. These include credentials, exfiltration, phishing, prank, recon, etc.

Subject to change. Please ensure any submissions meet the [latest version](https://github.com/hak5/keycroc-payloads/blob/master/README.md) of these standards before submitting a Pull Request.

## Naming Conventions
Please give your payload a unique, descriptive and appropriate name. Do not use spaces in payload, directory or file names. Each payload should be submit into its own directory, with `-` or `_` used in place of spaces, to one of the categories such as exfiltration, phishing, remote_access or recon. Do not create your own category.

Each payload should have a unique, descriptive directory and filename, e.g., `WIN_powershell_SMB_exfiltration.txt`

The directory name for the payload should match the payload file name.

If the payload is OS specific (I.e., a Windows Powershell attack), the filename should be prefixed with that OS. Prefixes include:
* `WIN_` for Windows
* `MAC_` for MacOS
* `LINUX_` for all Linux flavors
* `MULTI_` for multi-OS payloads

If the payload is OS agnostic (I.e., it substitutes text or otherwise make no interaction with the target OS), the filename should not include an OS prefix.

If multiple individual OS specific payloads are included, the directory name should be prefixed with `MULTI_` while each payload file name therein should be prefixed with the specific OS.


## Payload Configuration
In many cases, payloads will require some level of configuration by the end payload user. Be sure to take the following into careful consideration to ensure your payload is easily tested, used and maintained. 

- Remember to use PLACEHOLDERS for configurable portions of your payload - do not share your personal URLs, API keys, Passphrases, etc...
- Make note of both required and optional configuration(s) in your payload using comments at the top of your payload or "inline" where applicable
- 

## Payload Documentation 
Payloads should begin with `#` comments specifying the title of the payload, the author, the target, and a brief description.
<pre>
Example:
	BEGINNING OF PAYLOAD

	# Title: Example Payload
	# Author: Korben Dallas
	# Description: Opens hidden powershell and
	# Target: Windows 10
	# Props: Hak5, Darren Kitchen, Korben
	# Version: 1.0
	# Category: General
</pre>


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

<h1><a href="https://hak5.org/pages/policy">Legal</a></h1>

Payloads from this repository are provided for educational purposes only.  Hak5 gear is intended for authorized auditing and security analysis purposes only where permitted subject to local and international laws where applicable. Users are solely responsible for compliance with all laws of their locality. Hak5 LLC and affiliates claim no responsibility for unauthorized or unlawful use.

DuckyScript is a trademark of Hak5 LLC. Copyright © 2010 Hak5 LLC. All rights reserved. No part of this work may be reproduced or transmitted in any form or by any means without prior written permission from the copyright owner.
Key Croc and DuckyScript are subject to the Hak5 license agreement (https://hak5.org/license)
DuckyScript is the intellectual property of Hak5 LLC for the sole benefit of Hak5 LLC and its licensees. To inquire about obtaining a license to use this material in your own project, contact us. Please report counterfeits and brand abuse to legal@hak5.org.
This material is for education, authorized auditing and analysis purposes where permitted subject to local and international laws. Users are solely responsible for compliance. Hak5 LLC claims no responsibility for unauthorized or unlawful use.
Hak5 LLC products and technology are only available to BIS recognized license exception ENC favorable treatment countries pursuant to US 15 CFR Supplement No 3 to Part 740.

# Disclaimer
Generally, payloads may execute commands on your device. As such, it is possible for a payload to damage your device. Payloads from this repository are provided AS-IS without warranty. While Hak5 makes a best effort to review payloads, there are no guarantees as to their effectiveness. As with any script, you are advised to proceed with caution.
