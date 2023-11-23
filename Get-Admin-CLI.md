# Summary
Allows you to run admin commands in the terminal
# Functionality
* Exploits a weakness where python has SUID capabilities
* Runs a command in the terminal that grants the user an effective UID of 0
## Notes
* SUID vulnerability must be active to run
* Type "exit" in the CLI when finished
## Replicate Vulnerability
* $ sudo chmod 4755 /usr/bin/python3
