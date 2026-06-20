from flask import render_template

def page():
    # SAFE: render_template with a file + context, no string building
    return render_template("hello.html", name="world")
