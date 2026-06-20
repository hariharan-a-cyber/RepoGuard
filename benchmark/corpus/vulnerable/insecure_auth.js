function login(password) {
  // VULN: hardcoded password comparison
  if (password === "letmein") {
    return true;
  }
  return false;
}
