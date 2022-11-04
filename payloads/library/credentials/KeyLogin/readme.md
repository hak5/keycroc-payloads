**Title: KeyLogin**

<p>Author: 0iphor13<br>
OS: Windows<br>
Version: 1.1<br>
Requirements: CloudC2 Instance</p>

**What is KeyLogin?**
#
*When using a KeyCroc, what is your goal? Likely credentials or remote access.*
*But many environments, especially within the banking sector are locked down.*
*Taking advantage of available resources not only facilitates the use of payloads, it also enables long, undetected actions during an engagement.*
*KeyLogin makes use of the Windows shortcut [Windows]+L to lock the system. Thanks to the KeyCrocs ability to sniff keystrokes, the password or pin can then be exfiltrated.*
*This payload automates login stealing. It waites for the victim to press enter (to avoid logging wrong credentials), then locks the targets screen and sends the received credentials to your C2 instance.*
*As there are different sorts of authentication types for windows systems, you can/need to configure until which point you want to intercept theses keystrokes. Until ENTER is pressed? Until a certain lenght was typed? It's up to you!*
#
There you go, login credentials, exfiltrated in an automated manner, without the risk of getting caught.

**Instruction:**

- Connect KeyCroc to C2
- Configure payload language and DELAYs
- Plugin KeyCroc & run away (pro tip: In the morning or after lunch your chances to get a good result are much higher)
- You might want to disable to payload after the first success to avoid locking out the user!

KeyCroc will Notify you of the current attack state
![alt text](https://github.com/0iphor13/keycroc-payloads/tree/master/payloads/library/credentials/KeyLogin/notifications.png)

KeyCroc will save the inserted credentials into a seperate file for you
![alt text](https://github.com/0iphor13/keycroc-payloads/tree/master/payloads/library/credentials/KeyLogin/loot.png)


Credit for support:
- Korben
