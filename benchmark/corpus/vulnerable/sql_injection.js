function getUser(db, userId) {
  // VULN: template-literal SQL
  const q = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(q);
}
