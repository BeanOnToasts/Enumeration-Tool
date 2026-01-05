# modules
# $ pip install psutil
import csv
import platform as p
import tkinter as tk

import Enumeration as Enum
import PrivilegeEscalation as PrivEsc

OS = p.system()

# declare all variables from the class
info = Enum.Enumeration(OS)
priv = PrivEsc.Privesc(OS)
ver = info.vers
rel = info.rels
user = info.usr
host = info.host
ip = info.ip
users = info.usrList


def extend(shortlist, longlist):
    """
    procedure to extend length of list to the same as another
    """
    while len(shortlist) < len(longlist):
        shortlist.append("")


def writefile():
    """
    procedure runs all enumeration commands and writes results to csv file
    doesn't need to be run after all the other functions
    """
    print("====Writing To File====")
    # define all the enum variables
    hash_list = [""]
    if OS == "Linux":
        hashes = priv.ssh_privesc
        hash_list = []
        for i, n in enumerate(hashes):
            hash_list.append(hashes[i]['hash'])
    ver_inf = info.show_version(ver, rel)
    op_sys, rels, vers = ver_inf[0], ver_inf[1], ver_inf[2]
    usr_inf = info.show_user(user, host, ip)
    usr, hst, ip_addr = usr_inf[0], usr_inf[1], usr_inf[2]
    usrs = info.list_users()
    procs = info.show_processes()
    ports = info.port_scan(ip, True)
    # make sure all lists are the same length to enumerate through them
    extend(usrs, procs)
    extend(ports, procs)
    extend(hash_list, procs)
    # open the csv file and create all the headings
    try:
        with open('Information.csv', 'w', newline='') as csvfile:
            fieldnames = ['Operating System', 'Release', 'Version', 'Current User', 'Hostname', 'IP Address', 'Users',
                          'Hashed Password', 'Process ID', 'Process Name', 'Open Ports']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            # write the first row under the heading
            writer.writerow(
                {'Operating System': op_sys, 'Release': rels, 'Version': vers, 'Current User': usr, 'Hostname': hst,
                 'IP Address': ip_addr, 'Users': usrs[0], 'Hashed Password': hash_list[0], 'Process ID': procs[0][0],
                 'Process Name': procs[0][1],
                 'Open Ports': ports[0]})
            # enumerate processes list and iterate through all 3 lists, adding values to the csv file
            procs.pop(0)
            usrs.pop(0)
            ports.pop(0)
            hash_list.pop(0)
            for i, element in enumerate(procs):
                # first element of all lists have already been added to the first row
                writer.writerow(
                    {'Users': usrs[i], 'Hashed Password': hash_list[i], 'Process ID': element[0],
                     'Process Name': element[1], 'Open Ports': ports[i]})
            print("====Written to File====")
    except PermissionError:
        print("File already open, close and re-run")
        print("=======================")


def version():
    """
    All these commands are to be used by the buttons + visuals
    Needs to be in a new function so tkinter can run them without needing to pass variables
    Visuals such as titles, loading bars and formatting outputs
    """
    print("========OS Info========")
    ver_inf = info.show_version(ver, rel)
    op_sys, rels, vers = ver_inf[0], ver_inf[1], ver_inf[2]
    print(f"""{op_sys} {rels}
Build {vers}""")
    print("=======================")
    try:
        f = open("osInfo.csv", "w")
        f.write(f"OS,Release,Version\n{op_sys},{rels},{vers}")
        f.close()
    except PermissionError:
        print("File already open, close and re-run")


def usrip():
    print("=======User Info=======")
    usr_inf = info.show_user(user, host, ip)
    usr, hst, ip_addr = usr_inf[0], usr_inf[1], usr_inf[2]
    print(f"""Logged in as {usr} on {hst}
IP: {ip_addr}""")
    print("=======================")
    try:
        f = open("userInfo.csv", "w")
        f.write(f"Username,Hostname,IP Address\n{usr},{hst},{ip_addr}")
        f.close()
    except PermissionError:
        print("File already open, close and re-run")


def userlist():
    print("====Connected Users====")
    try:
        f = open("userList.csv", "w")
        f.write(f"Users")
        f.close()
        f = open("userList.csv", "a")
        usrs = info.list_users()
        for i in usrs:
            print(i)
            f.write(f"\n{i}")
        print("=======================")
        f.close()
    except PermissionError:
        print("File already open, close and re-run")


def processes():
    print("===Running Processes===")
    try:
        f = open("processes.csv", "w")
        f.write(f"Process ID,Process Name")
        f.close()
        process = info.show_processes()
        f = open("processes.csv", "a")
        for i in range(0, len(process)):
            pid = process[i][0]
            name = process[i][1]
            print(f"{pid} || Process name: {name}")
            f.write(f"\n{pid},{name}")
        f.close()
    except PermissionError:
        print("File already open, close and re-run")
    print("=======================")


def scan():
    print("=======Port Scan=======")
    try:
        f = open("ports.csv", "w")
        f.write(f"Open Ports")
        f.close()
        ports = info.port_scan(ip, False)
        f = open("ports.csv", "a")
        for port in ports:
            f.write(f"\n{port}")
        print(f"\nOpen ports: {ports}")
        print("=======================")
        f.close()
    except PermissionError:
        print("File already open, close and re-run")


def ssh_gethash():
    """
    Run ssh privesc and output the data
    """
    if OS == "Linux":
        hash_list = priv.ssh_privesc
        for i, n in enumerate(hash_list):
            usr = hash_list[i]["user"]
            hsh = hash_list[i]["hash"]
            print(f"User: {usr}\nHashed Password: {hsh}\n")
    else:
        print("Can only perform this on Linux machines")


def suid_gethash():
    """
    Run SUID privesc and close program, giving root access
    """
    if OS == "Linux":
        priv.suid_privesc()
    else:
        print("Can only perform this on Linux machines")


def maingui():
    """
    setting up GUI, button for each enumeration method
    """
    window = tk.Tk()
    version_but = tk.Button(
        text="Show OS Info",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="green",
        bg="black",
        fg="green",
        command=version
    )
    user_ip_but = tk.Button(
        text="Show User Info",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="green",
        bg="black",
        fg="green",
        command=usrip
    )
    user_list_but = tk.Button(
        text="List Users",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="green",
        bg="black",
        fg="green",
        command=userlist
    )
    proc_but = tk.Button(
        text="List Running Processes",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="green",
        bg="black",
        fg="green",
        command=processes
    )
    port_scan_but = tk.Button(
        text="Scan Ports",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="green",
        bg="black",
        fg="green",
        command=scan
    )
    auto_but = tk.Button(
        text="Write All to File",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="purple",
        bg="black",
        fg="purple",
        command=writefile
    )
    ssh_privesc = tk.Button(
        text="Find Hashed Passwords",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="red",
        bg="black",
        fg="red",
        command=ssh_gethash
    )
    suid_privesc = tk.Button(
        text="Get Admin CLI\n['exit' when finished]",
        width=25,
        height=3,
        activebackground="#171615",
        activeforeground="red",
        bg="black",
        fg="red",
        command=suid_gethash
    )
    version_but.pack()
    user_ip_but.pack()
    user_list_but.pack()
    proc_but.pack()
    port_scan_but.pack()
    ssh_privesc.pack()
    suid_privesc.pack()
    auto_but.pack()
    window.mainloop()


maingui()
