const { exec } = require("child_process");
function backup(name) {
  // VULN: user input concatenated into shell command
  exec("tar -czf " + name + ".tar.gz /data");
}
