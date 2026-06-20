import os, subprocess

def ping(host):
    # VULN: os.system with user input
    os.system("ping -c 1 " + host)

def run(cmd):
    # VULN: subprocess with shell
    subprocess.run(cmd, shell=True)
