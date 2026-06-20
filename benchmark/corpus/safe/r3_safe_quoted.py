import subprocess, shlex
def run(name):
    # SAFE: argument quoted, list form
    subprocess.run(["echo", shlex.quote(name)])
