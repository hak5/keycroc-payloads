# Keep Alive
### Don't let the PC fall asleep
---
Like having a mouse wiggler on for your Key Croc, except with keys! Unlike a regular mouse wiggler, this will constantly press Control - so typing while it is active is not recommended.

The payload was tested on Windows 10. It may be run with seconds specified as a parameter while in SSH (just remove the MATCH).

*Setup*
1. Connect the Key Croc and place into arming mode
2. Place `keepalive.txt` in the payloads directory
3. Change the `TOTAL_SEC` variable to increase time - default is an hour.
4. Optionally change the MATCH string to a unique passphrase of your choice
5. Eject the Key Croc safely

The Key Croc is ready for deployment.

*Deploy*
1. Connect the Key Croc to target in attack configuration 
2. Type `__staylive` to start the keep awake routine: it will flash yellow while it is active

*What’s up with the name SaintCrossbow?*

Most of it is because it wasn’t taken. Other than that, I’m a big fan of the literary Saint by Leslie Charteris: a vigilante type who very kindly takes on problem people, serves his own justice, and has a great deal of fun doing it. Also, I just can’t help but think that crossbows are cool.


