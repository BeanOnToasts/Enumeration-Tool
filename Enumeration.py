import platform as p
import socket as sock
from getpass import getuser
from psutil import users, process_iter
from sys import stdout


class Enumeration:
    """
    Class for enumeration functions and information
    Types of Enumeration: OS Information (show_version); User Information (show_user); List Users (list_users);
    List Processes (show_processes); Port Scan (port_scan)
    Each Function explained in own docstring
    """
    vers = p.version()
    rels = p.release()
    usr = getuser()
    usrList = users()
    host = sock.gethostname()
    ip = sock.gethostbyname(host)

    def __init__(self, os):
        self.OS = os

    def show_version(self, vers, rels):
        """
        Procedure to show which version of the OS is running
        On windows, Windows 11 is still Windows 10 so the release needs to be checked too
        """
        if self.OS == "Windows":
            win_ver = vers.split(".")
            win_ver = int(win_ver[2])
            if win_ver > 19045:
                rels = 11
            else:
                rels = p.release()
        return self.OS, rels, vers

    @staticmethod
    def show_user(usr, host, ip):
        """
        Procedure to show the username, hostname and IP of machine
        """
        return usr, host, ip

    def list_users(self):
        """
        Procedure to show all current users
        """
        if self.OS == "Windows":
            user_list = users()
        else:
            from pwd import getpwall
            user_list = getpwall()
        list_usr = []
        for u in user_list:
            if self.OS == "Windows":
                list_usr.append(u.name)
            else:
                real = u[-1]
                real.split("/")
                real = (real[-1])
                if real == "h" and u[0] != 'postgres':
                    list_usr.append((u[0]))
        return list_usr

    @staticmethod
    def show_processes():
        """
        Procedure for listing all active processes on OS
        """
        processes = process_iter()
        proc_list = []
        for P in processes:
            item = [P.pid, (P.name())]
            proc_list.append(item)
        return proc_list

    @staticmethod
    def port_scan(target, auto):
        """
        Port scanner function
        List contains top ~50 common ports
        :param target:
        :type auto: bool
        Auto is used to tell the function to run the loading bar or not
            Used for writing to file so loading bar doesn't show
        """
        ports = [21, 22, 25, 80, 53, 443, 1521, 3306, 3389, 5432, 27017, 49152, 5353, 5672, 5355, 12700, 1380, 8088,
                 6624, 4, 9124, 23, 110, 143, 67, 68, 8080, 123, 1080, 1521, 912, 902, 445, 136, 139, 4, 5222, 5223,
                 5353, 873, 11211, 6379, 2049, 5353, 548, 389, 636, 137, 138, 139, 0]
        # remove duplicate ports
        ports = list(dict.fromkeys(ports))
        # order ports
        ports.sort()
        open_ports = []
        for P in range(0, len(ports)):
            port = ports[P]
            if not auto:
                # percentage of ports scanned
                percent = int(round((((P + 1) / len(ports)) * 100), 0))
                # setting up progress bar
                bar_length = 50
                full = "#" * int(round(percent / (100 / bar_length)))
                empty = "-" * (bar_length - int(round(percent / (100 / bar_length))))
                # Shows percentage completed and progress bar
                stdout.write(f"\r{percent}% [{full}{empty}]")
                stdout.flush()
            soc = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            try:
                # set timeout time for scanning a port
                soc.settimeout(0.1)
                # scan port to check if it's open
                result = soc.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
            # return error if occurred
            except sock.gaierror as e:
                print(sock.gaierror)
                print(e, sock.gaierror)
            if P == len(ports) - 1:
                return open_ports
