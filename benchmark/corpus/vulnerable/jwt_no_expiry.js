const jwt = require("jsonwebtoken");
function token(user) {
  // VULN: jwt.sign without expiresIn
  return jwt.sign({ id: user.id }, SECRET);
}
