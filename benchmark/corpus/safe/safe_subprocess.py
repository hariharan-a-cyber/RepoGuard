import subprocess

def ping(host):
    # SAFE: list args, shell=False (default), fixed command
    subprocess.run(["ping", "-c", "1", host], shell=False)
