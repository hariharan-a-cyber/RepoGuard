app.get("/home", (req, res) => {
  // SAFE: constant destination, no user input
  res.redirect("/dashboard");
});
