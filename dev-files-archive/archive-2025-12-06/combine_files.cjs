const fs = require("fs");
const path = require("path");

// Change this line to set the root directory to the current location
// const rootDir = ".";
const rootDir = "utils";
const outputFile = "utils-Jest-APi-Testing.txt";
const extensionsToInclude = [".ts", ".js", ".css", ".html", ".json", ".tsx"];
const excludedDirs = ["node_modules", ".git", "dist", "build"];

let allContent = "";

function isFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (e) {
    return false;
  }
}

function traverseDirectory(dir) {
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const filePath = path.join(dir, file);
    const relativePath = path.relative(rootDir, filePath);
    const fileStat = fs.statSync(filePath);

    if (fileStat.isDirectory()) {
      if (excludedDirs.includes(path.basename(filePath))) {
        console.log(`Skipping directory: ${relativePath}`);
        continue;
      }
      traverseDirectory(filePath);
    } else if (isFile(filePath)) {
      const fileExtension = path.extname(filePath);
      if (extensionsToInclude.includes(fileExtension)) {
        console.log(`Processing file: ${relativePath}`);
        const content = fs.readFileSync(filePath, "utf-8");

        let commentStart = "";
        let commentEnd = "";

        switch (fileExtension) {
          case ".html":
            commentStart = "";
            break;
          case ".css":
            commentStart = "/* ";
            commentEnd = " */";
            break;
          case ".json":
            commentStart = "// ";
            commentEnd = "";
            break;
          default:
            commentStart = "// ";
            commentEnd = "";
            break;
        }

        allContent += `${commentStart}Path: ${relativePath}${commentEnd}\n\n`;
        allContent += content;
        allContent += "\n\n";
      }
    }
  }
}

traverseDirectory(rootDir);

fs.writeFileSync(outputFile, allContent);

console.log(
  `\nAll matching files have been successfully combined into "${outputFile}".`
);
