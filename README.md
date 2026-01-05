[Privilege Escalation Video](https://youtu.be/p4mg_o639Fg)
***

> This tool is use to enumerate a Windows or Linux machine through a series of operations or escalate your privileges on a Linux machine.

> Read the wiki for more in depth details of each function and extra notes.

# GUI:
## ENUMERATION FUNCTIONS (green)
* Show OS Info - Get the version and build of the operating system
* Show User Info - Get the username of who is logged in, the hostname and the IP of the machine
* List Users - List all users on the system
* List Running Processes - List all current running processes and their PIDs
* Scan Ports - Scan most commonly used ports on the user's IP and return a list of which ports are open
## PRIVILEGE ESCALATION FUNCTIONS (red; Linux only)
* Find Hashed Passwords - Return list of hashed password and which users they are associated with
* Get Admin CLI - Allows you to run admin commands in the terminal (use "$ exit" to stop program)
## FILE FUNCTIONS (purple)
* Write All to File - Runs all functions and writes the information to the file (do not have to run other enumeration functions first)
