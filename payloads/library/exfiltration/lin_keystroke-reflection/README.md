# "Linux" Keystroke Reflection

- Title:            "Linux" Keystroke Reflection
- Author:           TW-D
- Version:          1.0
- Target:           Debian-Based Linux Distributions
- Category:         Exfiltration
- Attackmode:       HID

## Description

Implementation of the "Keystroke Reflection" technique for file exfiltration.

The table below presents an estimation of the time taken for a specific number of bytes :

| Bytes | Seconds (xdotool) |
| --- | --- |
| 5 | Between 10 and 15 |
| 10 | Between 20 and 25 |
| 100 | Between 220 and 230 |
| 1000 | Between 2250 and 2260 |

__Note :__ *The target system must have "xxd" and "xdotool" installed.*

## Configuration

From the file "keystroke-reflection_exfiltration.txt" change the value of the following variable :
```

######## SETUP ########

LED SETUP

export DUCKY_LANG="us"

```

## Trigger

>
> MATCH __kr:file=(.*?)\[ENTER\]
>

## Usage

The triggering must be done in a terminal.

```
:~$ hostname > /tmp/EXFIL
:~$ __kr:file=/tmp/EXFIL[ENTER]
```

**OR**

```
:~$ __kr:file=/etc/hostname[ENTER]
```

__Note :__ *After triggering, avoid using the keyboard.*
