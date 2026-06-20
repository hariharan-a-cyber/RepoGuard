import sqlite3

def get_user(conn, user_id):
    # VULN: string-concatenated SQL
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchone()

def search(conn, term):
    # VULN: f-string interpolation into SQL
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE name = '{term}'")
    return cur.fetchall()
