# Summary
Return list of hashed password and which users they are associated with
# Functionality
* Exploits a weakness where a sticky bit is set on the ssh file
* Uses ssh to read the /etc/shadow file and output to a new file
* Compares the file to the users in the [user list](https://github.coventry.ac.uk/thorntonj/13764108_CW/wiki/List-Users) and finds hashed password for each one
* Returns list of dictionaries (User : Password Hash) which is displayed one by one
## Notes
* Sticky bit vulnerability must exist for this to work
## Replicate Vulnerability
* sudo chmod 4777 /usr/bin/ssh
