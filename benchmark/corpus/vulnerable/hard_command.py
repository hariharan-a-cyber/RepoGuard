import os
def cleanup(path):
    # VULN: os.popen (a command sink the rule may not list)
    return os.popen("rm -rf " + path).read()
