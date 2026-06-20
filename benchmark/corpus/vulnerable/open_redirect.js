app.get("/go", (req, res) => {
  // VULN: redirect to user-controlled destination
  res.redirect(req.query.next);
});
