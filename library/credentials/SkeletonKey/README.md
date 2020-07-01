# Skeleton Key
### Deploy to target, come back later to unlock automatically - no checking of logs necessary
---
Arm the Key Croc with an automatic lockpick for Windows 10! After preparing the Key Croc for deployment, place it on a target with a lock screen. Once the target unlocks the PC, their first entry into the Key Croc will be their password. The Skeleton Key payload listens for your secret command, and then unlocks the computer automatically with that password.

Like most skeleton keys, this will not be 100% reliable. The target may enter in the wrong password, or maybe drum on the keys before logging in.

The payload was tested on Windows 10 for both PIN and passwords.

*Setup*
1. Connect the Key Croc and place into arming mode
2. Save offline and then delete all logs in the loot directory
3. Place both the `skeletonkey.txt` and `skeletonagain.txt` in the payloads directory
4. Optionally change the MATCH string to a unique passphrase of your choice
5. Eject the Key Croc safely

The Key Croc is ready for deployment.

*Deploy*
1. Ensure the target is on a lock screen
2. Remove target keyboard, place the Key Croc on the USB, and connect keyboard to Key Croc when LED is white
3. Cross your fingers and leave

*Turn Skeleton Key*

You get two shots at it! Afterwards, just analyze the log file.

1. Do not disconnect the Key Croc
2. Enter an incorrect password so you receive "The PIN / password is incorrect - try again" message with the OK button. _Do not click the OK button_ - instead...
3. Type the secret phrase `skeletonknock`
4. Didn't work? They may have used the mouse to get to the password screen. Repeat step #2 and then try `skeletonagain`
5. Still no luck? Looks like it isn't your day, but next time you should have better luck. Open the log on a different PC or via SSH to get the password.

*Now* remove the Key Croc and be on your merry way

*Why SkeletonKnock? I thought this was called _skeleton key_*
You're right! But I thought it less likely for anyone to type `skeletonknock`.

*What’s up with the name SaintCrossbow?*
Most of it is because it wasn’t taken. Other than that, I’m a big fan of the literary Saint by Leslie Charteris: a vigilante type who very kindly takes on problem people, serves his own justice, and has a great deal of fun doing it. Also, I just can’t help but think that crossbows are cool.


