# Croc_Live

Script Description: Keyboard Activity Monitor

The following script serves as a tool to monitor and display keyboard activity, showing both previous keystrokes and live keystrokes in real-time. It operates in the terminal environment and relies on the presence of certain log files.

- Display Previous Keystrokes:
   - The script initiates by printing a message to the terminal, indicating that the previously recorded keystrokes are about to be displayed.
   - It then searches for files named "croc_char.log" within the current directory and its subdirectories.
   - All found log files are concatenated and their contents are displayed, revealing the previous keystrokes recorded in those files.
 
- Waiting for Keyboard Activity:
   - After displaying the previous keystrokes, the script enters a loop, continuously checking for the existence of the file "loot/croc_char.log".
   - During this loop, it prints the message "Waiting for keyboard activity" and clears the line with each iteration. This creates an interactive waiting experience for users until keyboard activity is detected.
 
- Show Live Keystrokes:
   - Once the file "loot/croc_char.log" is present (indicating keyboard activity has started), the script proceeds.
   - A 1-second pause occurs to allow time for the system to update or log any new keyboard activity.
   - The terminal screen is then cleared to prepare for the display of live keystrokes.
   - A message is shown to inform users that live keystrokes will be displayed.
   - The script uses the tail -f command, which continuously follows and outputs new content appended to the "loot/croc_char.log" file. This effectively presents live keystrokes in real-time.

- Usage:

Place the croc_live.sh file in keycroc tools folder.

To utilize this script, simply execute it in the terminal environment. Make sure that the required log files, specifically "croc_char.log" and "loot/croc_char.log," are available and accessible within the current directory. Simply type "bash udisk/tools/croc_live.sh" in terminal.

Please note that this script may have specific use cases, such as monitoring and capturing keyboard activity during specific sessions or tasks. Always ensure you have the necessary permissions to read and access the log files being monitored.
