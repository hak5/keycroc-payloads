# Cookie Monster
* Author: Cribbit 
* Version: 1.0
* Target: any
* Category: pranks
* Attackmode: HID
* Props: Unkown at Brown University, C. D. Tavares.

## Description
Types messages asking for a cookie. until the user type cookie

## Change Log
| Version | Changes                       |
| ------- | ------------------------------|
| 1.0     | Initial release               |

## Match
start_monster

## Configuration
The line: `if tail -c 6 "$crocKeys" | grep -q cookie; then` may need changing if the file is unicode to: `if tail -c 12 "$crocKeys" | grep -q cookie; then`
