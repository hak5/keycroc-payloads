# Timed Responder Attack
### Hang back for a few extra minutes and collect network credentials
---
After you've attached the Key Croc, why not take the opportunity to try for some network credentials? Start with your MATCH phrase and a responder attack runs for the total minutes you specify. You'll want to hang around for completion though: the target will briefly lose keyboard connection twice. Afterwards you can leave it behind to continue to quietly gather keystrokes.

The payload was tested on Windows 10.

*Setup*
1. Connect the Key Croc on your PC in ARMING mode
2. If you haven't already, get the additional tools using the INSTALL_EXTRAS script
3. Place `timedresponder.txt` in the payloads directory
4. Change the `GATHER_FOR` variable to the number of seconds to run responder
5. Optionally change the MATCH string to a unique passphrase of your choice
6. Eject the Key Croc safely

The Key Croc is ready for deployment.

*Deploy*
1. Connect the Key Croc to target in attack configuration
2. Look around slyly and make sure you are in the clear for a few minutes
3. Start responder by typing `__responder`
4. The Key Croc will go into both HID and RNDIS mode, indicated by LED magenta
5. While responder is running, the LED will flash with a single yellow blink
6. The logs will be copied to /root/loot, indicated by a fast white blink
7. A brief LED flash of green means your attack is complete.

Take the croc with you, or leave it behind to continue stealing keystokes.

*What’s up with the name SaintCrossbow?*
Most of it is because it wasn’t taken. Other than that, I’m a big fan of the literary Saint by Leslie Charteris: a vigilante type who very kindly takes on problem people, serves his own justice, and has a great deal of fun doing it. Also, I just can’t help but think that crossbows are cool.


