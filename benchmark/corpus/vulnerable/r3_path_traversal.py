from flask import request, send_file
def download():
    # VULN: user-controlled path into file read
    fname = request.args.get("file")
    return send_file("/var/data/" + fname)
