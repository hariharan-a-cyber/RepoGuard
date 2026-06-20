from flask import request, render_template_string

def page():
    # VULN: user input into template string
    name = request.args.get("name")
    return render_template_string("Hello " + name)
