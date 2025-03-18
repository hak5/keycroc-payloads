# :phone: Simplex
- Author: Cribbit
- Version: 1.0
- Target: Mutli OS
- Category: General
- Attackmode: None - Needs wifi connection

## :mag: Match
croc_send
croc_listen

## :book: Description
Sends keystrokes from one croc to another.

This is a PoC basicly me playing with netcat. It's quite slow!!

### Listener
On the listener use ‘croc_listen’ this will set up. This will create a netcat listener on the port and pass the incoming traffic to QUACK KEYCODE.

### Sender
On the sending croc set the croc2 variable to the IP address of the listener croc i.e. `croc2=192.168.1.100`
Use ‘croc_send’ this will check the raw log and send new key press over nc to the other croc.

### To stop
Type `exit` on the attached keyboards.

### Note
Set the port variable to an unused port i.e. ‘port=8080’

This is a proof of concept. As there are some limitations due to the way the QUACK command works.
As by default, it releases all key(s) after it send a keycode. 
So, you may have issues with command like `CTRL + C` it may do:
CTRL
CTRL + C
CTRL
If you hit CTRL then the C then let go of C then CTRL.
You could fix this by modifying the QUACK file. If you look for the function `run_ducky_line(context, line, lang_file)`.
Then look for the line `elif cmd == 'KEYCODE':` then 6'ish line down `hidg_write(elements,release_key)`
then change `release_key` to `False` or set the `release_key` variable to false `release_key = False` before the hidg_write line.


## :placard: Change Log
| Version | Changes         |
| ------- | --------------- |
| 1.0     | Initial release |