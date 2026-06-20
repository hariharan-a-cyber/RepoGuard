def get_user(conn, user_id):
    # SAFE: parameterized query, no concatenation
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def search(conn, term):
    # SAFE: parameter binding
    cur = conn.cursor()
    cur.execute("SELECT * FROM products WHERE name = %s", (term,))
    return cur.fetchall()
