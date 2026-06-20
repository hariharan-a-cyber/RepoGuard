const bcrypt = require("bcrypt");
async function login(password, hash) {
  // SAFE: constant-time hashed comparison
  return await bcrypt.compare(password, hash);
}
