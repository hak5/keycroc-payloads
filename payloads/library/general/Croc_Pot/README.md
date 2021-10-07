# Croc_Pot

## INTRODUCTION :
  - This project is developed for the HAK5 KeyCroc (Croc_Pot in development and testing)

* **Croc_Pot_Payload.txt**
  - Will start OS detection scan to see what OS the keycroc is pluged into (usb), collect some data off the target pc, automatically start an SSH session with connected target pc (wifi) and start Croc_Pot script
  - Ensure your keycroc is connected to the target pc wifi first before running **crocpot** If you do not have the target pc wifi credentials Croc_Pot has a payload to get you online (payload called getonline working on windows and Raspberry pi in development for linux version)

* **Croc_Pot.sh**
  - This project is to automate some commands for the keycroc for quicker setup, install payloads, remotely connect to keycroc, nmap tcpdump target pc scan, edited files on your keycroc, send e-mail from your keycroc, SSH to hak5 gear, run hak5 cloud C2 on keycroc, status of your keycroc, and more 

* **TESTED ON**
  - Windows 10
  - Raspberry pi 4 with gnome-terminal installed
  - linux parrot os
  - Sorry no support for MAC OS

## INSTALLATION :

* Two file to this script
  - Will need to enter arming mode on your keycroc to install files.
  - First file is called **Croc_Pot.sh** Place this in the KeyCroc **tools folder**.
  - Second file is called **Croc_Pot_Payload.txt** Place this in the KeyCroc **payload folder**.
  - Edited the Croc_Pot_Payload.txt file for your keycroc passwd. default is (hak5croc)
  - Ensure your KeyCroc is connected (wifi) to the same local network as the target pc

## STARTING CROC_POT :

  - First way to start Croc_Pot.sh is ssh into your keycroc and type **/root/udisk/tools/Croc_Pot.sh**.
  - Second way to start Croc_Pot.sh is type in anywhere **crocpot** this will start Croc_Pot.sh script automatically.
  - It is recommended to start Croc_Pot.sh script with typing in **crocpot** as this payload will collect some data off the target pc. Some of the info that it will collect will be Target pc (ip address, current user name, pc host name, ssid and passwd, mac address), This info will be used in the Croc_Pot.sh script. 
  - **NOTE:** When running **crocpot** scan takes about 30-40 sec to start because of OS detection then Croc_Pot will start.

## SSH MENU :

 * Automatically Accepts SSH Fingerprint with Command Line Options
   - Croc_Pot in some of ssh options will automatically accept the SSH servers fingerprint and add it to the known hosts file we can pass the StrictHostKeyChecking no option to SSH. Example ssh -o "StrictHostKeyChecking no" HOST@IP
   - **NOTE:** Automatically accepting the SSH fingerprint effectively bypasses the security put in place by SSH. You should be careful using this, especially on untrusted networks, including the public internet.

### SSH TO HAK5 GEAR
 * Ensure all hak5 gear is connected to the same local network as your keycroc
   - Recommended to setup ssh PUBLIC AND PRIVATE KEY to each of your hak5 gear, SSH to your gear Without Password
   - SSH keycroc to Bash Bunny setup, first ensure your bash bunny has internet connection and connected to the same pc as your Keycroc, (bash bunny internet setup can be found at docs.hak5.org), Croc_Pot.sh will create a payload for your bash bunny, this file will be saved on your keycroc at tools/Croc_Pot/Bunny_Payload_Shell then copy this file to one of the payload switches on your bash bunny this is to start Reverse SSH Tunnel to keycroc.

### CREATE PUBLIC AND PRIVATE KEY
* Perform SSH Login Without Password Using ssh-keygen & ssh-copy-id
* Step 1: Create public and private keys using ssh-key-gen on local-host
  - jsmith@local-host$ **Note: You are on local-host here**
  - jsmith@local-host$ **ssh-keygen**
  - [Press enter key]
 * Step 2: Copy the public key to remote-host using ssh-copy-id
   - jsmith@local-host$ **ssh-copy-id -i ~/.ssh/id_rsa.pub username@remote-host-ip**
   - jsmith@remote-host's password:
 * Step 3: Login to remote-host without entering the password
   -jsmith@local-host$ **ssh username@remote-host-ip**
 * The above 3 simple steps should get the job done in most cases.
 
 ### Setup Reverse SSH Tunnel
   - Reverse SSH is a technique that can be used to access systems (that are behind a firewall) from the outside world.
   - Here is the command for remote server side
   - **ssh -fN -R 7000:localhost:22 username@your-Machine-ipaddress**
   - Now do an ssh connection request from your machine to your own machine at port 7000:
   - **ssh username@localhost -p 7000**
   - Here, though it may seem like you are doing ssh on localhost but your request would be forwarded to remote host. So, you should use your account ? username ? on remote server and when prompted for password, enter the corresponding password.

### Screenshot
![Screenshot from 2021-08-12 07-54-07](https://user-images.githubusercontent.com/71735542/129192585-d0933663-748a-4000-9102-6e1ceb4a851c.png)
![Screenshot from 2021-08-12 07-57-38](https://user-images.githubusercontent.com/71735542/129192913-8b880ee7-31f3-41ba-ac6b-59188e594460.png)
![Screenshot from 2021-08-12 08-00-12](https://user-images.githubusercontent.com/71735542/129193161-60bea2b4-99f5-4781-8a8c-dbd7d4b3d27f.png)
![Screenshot from 2021-08-12 08-03-59](https://user-images.githubusercontent.com/71735542/129193656-fbfcbc3c-207b-4555-be22-32a66cbe9aea.png)

