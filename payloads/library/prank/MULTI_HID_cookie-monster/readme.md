# :cookie: Cookie Monster
* Author: Cribbit 
* Version: 1.0
* Target: any
* Category: pranks
* Attackmode: HID
* Props: Unkown at Brown University, C. D. Tavares.

## :mag: Match
start_monster

## :book: Description
Recreates the 1969 program from Brown University. This version types messages asking for a cookie. Until the user type `cookie`.

## :placard: Change Log
| Version | Changes                       |
| ------- | ------------------------------|
| 1.0     | Initial release               |

## :pencil: Configuration
The line: `if tail -c 6 "$crocKeys" | grep -q cookie; then` may need changing if the file is unicode to: `if tail -c 12 "$crocKeys" | grep -q cookie; then`
