# Back Door Account
### Add an account to an unlocked PC before the keystrokes are caught
---
Simple script that adds an administrative user for later access. Only works, of course, if the PC is unlocked. However this is a nice complement to the SkeletonKey payload: just add the new user when you unlock the PC.

The payload was tested on Windows 10.

*Setup*
1. Connect the Key Croc and place into arming mode
2. Place `addadmin.txt` in the payloads directory
3. Change the `BACKDOOR_USER` variable to something that will blend into the environment
4. Change the `BACKDOOR_PASS` variable to a reasonably strong password
5. Optionally change the MATCH string to a unique passphrase of your choice
6. Eject the Key Croc safely

The Key Croc is ready for deployment.

*Deploy*
1. Connect the Key Croc to target in attack configuration
2. If you are lucky enough to find yourself at an unlocked screen, type `__addadmin`
3. With some luck, your user name and password will be added

*Cleanup*
1. Remove the user from the admin group: `net localgroup administrators officeadmin /delete`
2. Remove the user from the system: `net users officeadmin /delete`

*What’s up with the name SaintCrossbow?*
Most of it is because it wasn’t taken. Other than that, I’m a big fan of the literary Saint by Leslie Charteris: a vigilante type who very kindly takes on problem people, serves his own justice, and has a great deal of fun doing it. Also, I just can’t help but think that crossbows are cool.


