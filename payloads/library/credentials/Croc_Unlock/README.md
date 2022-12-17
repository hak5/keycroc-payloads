# Croc_Unlock
## INTRODUCTION :
* This project is developed for the HAK5 KeyCroc
  - Pressing **GUI-l** will open windows / linux parrot OS login screen and wait for user to enter passwd with SAVEKEYS command
  - Pressing **CONTROL-ALT-F3** will open Raspberry pi 4 terminal login screen and wait for user to enter passwd with SAVEKEYS command
  - Type in **crocunlock** at the target login screen will delete crocunlock characters and enter user passwd
  - Payload will save passwd at /tools/Croc_Pot/Croc_unlock.txt.filtered, this payload was design to help with Croc_Pot
  - Old passwd will be save at /loot/Croc_Pot/Croc_unlock.txt.filtered

  - **NOTE:** This payload is relying on the ENTER key to be press after user has enter passwd

* **TESTED ON**
  -  Windows 10
  -  Raspberry pi 4
  -  linux parrot OS
 
 ## INSTALLATION :
   - Will need to enter arming mode on your keycroc to install file.
   - File is called **CrocUnlock.txt** Place this in the KeyCroc **payload folder**.
