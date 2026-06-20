const ROUTES = new Map([["home","/"],["help","/help"]]);
app.get("/nav", (req, res) => {
  // SAFE: looked up in a Map, falls back to root
  res.redirect(ROUTES.get(req.query.to) || "/");
});
