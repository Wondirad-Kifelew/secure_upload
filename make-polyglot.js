import fs from "node:fs";

const polyglot = Buffer.from(
  "GIF89a=1;//" + "\0".repeat(20) + "\n" + 'console.log("polyglot executed");'
);

fs.writeFileSync("polyglot-test.gif", polyglot);
console.log("Created polyglot-test.gif —", polyglot.length, "bytes");