function handler(req, res) {
  const id = req.query.id;
  const q = "SELECT * FROM users WHERE id=" + id;
  db.query(q);
  res.send("ok");
}

module.exports = { handler };
