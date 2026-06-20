const { execFile } = require("child_process");
function listDir(dir) {
  // SAFE: execFile with arg array, no shell string building
  execFile("ls", ["-la", dir], (e, out) => console.log(out));
}
