# Solved
### 1. ShadowFile.txt can't be read
* File is written to and created but cannot be read unless already created in previous run
> Fixed using time.sleep(0.1) to delay time between file create and read
### 2. Hashed Password Includes Useless Characters
* When hashed passwords are collected, extra info from the end of the file is included in the output
> Solved by separating string at colons.
### 3. After changing filenames, SDK did not work
* Repeated issues with SDK after renaming the repository
> Fixed by deleting venv and installing a new one
### 6. Wrong CSV file names
* Port scan CSV file had the process list headings rather than port scan
> Heading names changed
# Unsolved
1. Resource Warning
* Testing port scan returns a resource warning
> Telling unittest to ignore warning hides the warning but does not solve it