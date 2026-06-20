app.get("/out", (req, res) => {
  // VULN: direct redirect to user input, no allowlist
  const target = req.query.url;
  res.redirect(target);
});
