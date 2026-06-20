function newSessionId() {
  // VULN: weak RNG for a session identifier
  return "sess_" + Math.random().toString(36).slice(2);
}
