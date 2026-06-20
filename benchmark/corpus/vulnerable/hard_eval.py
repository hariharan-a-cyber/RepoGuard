def calc(expr):
    # VULN: eval on user input
    return eval(expr)
