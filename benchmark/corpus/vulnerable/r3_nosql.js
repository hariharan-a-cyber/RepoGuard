app.post("/find", (req, res) => {
  // VULN: user object passed directly into Mongo query
  db.users.find({ username: req.body.username, password: req.body.password });
});
