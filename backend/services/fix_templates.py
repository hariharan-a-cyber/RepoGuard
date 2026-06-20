"""
Pre-built fixes for common vulnerabilities.

DETERMINISTIC_FIXES -> actual replacement code (used for branch commits)
FIX_DESCRIPTIONS    -> human-readable explanation (used for PR comments)
"""

DETERMINISTIC_FIXES = {
    "sql_injection": {
        "node": "db.query('SELECT * FROM table WHERE id = ?', [userInput])",
        "python": "cursor.execute('SELECT * FROM table WHERE id = %s', (user_input,))",
    },
    "hardcoded_secret": {
        "node": "process.env.SECRET_KEY",
        "python": "os.environ['SECRET_KEY']",
    },
    "dangerous_eval": {
        "node": "JSON.parse(userInput)",
        "python": "ast.literal_eval(user_input)",
    },
    "command_injection": {
        "node": "execFile(command, args, callback)  // use execFile, never exec with user input",
        "python": "subprocess.run([command, arg], shell=False)",
    },
    "path_traversal": {
        "node": "path.join(__dirname, 'safe_base', path.basename(userInput))",
        "python": "os.path.join(BASE_DIR, os.path.basename(user_input))",
    },
}

FIX_DESCRIPTIONS = {
    "sql_injection": (
        "Use parameterized queries - never build SQL strings with user input. "
        "Pass values as separate arguments to your query function."
    ),
    "hardcoded_secret": (
        "Move credentials to environment variables. "
        "Rotate/revoke the exposed value immediately - treat it as compromised."
    ),
    "dangerous_eval": (
        "Replace eval/exec with safe alternatives. "
        "Use JSON.parse() for data in Node.js, ast.literal_eval() in Python."
    ),
    "command_injection": (
        "Never pass user input directly to shell commands. "
        "Use execFile() or subprocess with shell=False and an argument list."
    ),
    "path_traversal": (
        "Sanitize file paths with path.basename() before joining - "
        "prevents attackers from escaping your intended directory."
    ),
}


def get_deterministic_fix(vuln_type: str, language: str = "node") -> str | None:
    """
    Returns actual replacement code for committing to a fix branch.
    Returns None if we have no template - fall back to AI.
    """
    fixes = DETERMINISTIC_FIXES.get(vuln_type, {})
    return fixes.get(language) or fixes.get("node")


def get_fix_description(vuln_type: str) -> str:
    """
    Returns a human-readable explanation for the PR comment.
    Always returns something - never None.
    """
    return FIX_DESCRIPTIONS.get(
        vuln_type,
        "Review and apply the recommended security fix before merging."
    )
