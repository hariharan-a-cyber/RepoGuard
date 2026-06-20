const ALLOWED = { home: "/", profile: "/me" };
app.get("/go", (req, res) => {
  // SAFE: redirect only to allowlisted internal paths
  res.redirect(ALLOWED[req.query.dest] || "/");
});
