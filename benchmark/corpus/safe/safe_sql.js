function getUser(db, userId) {
  // SAFE: parameterized query
  return db.query("SELECT * FROM users WHERE id = ?", [userId]);
}
