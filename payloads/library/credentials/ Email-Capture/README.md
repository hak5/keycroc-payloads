# Email-Capture
## INTRODUCTION :
* This project is developed for the HAK5 KeyCroc.
  - Capture target E-mail address & password save to /udisk/tools/target_email.txt.
  - This should work on all operating systems.

## INSTALLATION :
   - Will need to enter arming mode on your keycroc to install file.
   - File is called **Email_Capture.txt** Place this in the KeyCroc **payload folder**.

## PAYLOAD INFO :

This payload will use Key Croc MATCH command using regular expressions pattern.
   - (^[a-zA-Z0-9_\-\.]+@[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{3,5}$)
 
 Here's how the pattern works:
 
  - The pattern starts with a caret (^) which represents the beginning of the string.
  - Then it matches one or more occurrences of any alphanumeric character (a-z, A-Z, 0-9), underscore (), hyphen (-), or period (.) using the character set [a-zA-Z0-9-.]+. This represents the local part of the email address, which is the part before the "@" symbol.
  - The "@" symbol is matched next.
  - Then another character set [a-zA-Z0-9_-.]+ is used to match the domain name of the email address, which can include alphanumeric characters, underscore, hyphen, and period.
  - The domain name is then followed by a period (.), and the top-level domain (TLD) is matched using the character set [a-zA-Z]{3,5}. This ensures that the TLD is between 3 and 5 characters long.
  - Finally, the pattern ends with a dollar sign ($), which represents the end of the string.

Overall, this regular expression pattern is used to validate that a string follows the basic format of an email address. However, it does not guarantee that the email address is actually valid or in use.

  -After MATCH pattern, payload will run the SAVEKEYS command and Attempt to capture password, this will save all characters until ENTER key is pressed.
