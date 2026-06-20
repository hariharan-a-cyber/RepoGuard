const jwt = require("jsonwebtoken");
function token(user) {
  // SAFE: jwt.sign WITH expiresIn
  return jwt.sign({ id: user.id }, SECRET, { expiresIn: "1h" });
}
