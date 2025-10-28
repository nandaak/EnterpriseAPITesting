import fs from "fs";
import path from "path";

function fixTokenFile() {
  console.log("🔧 FIXING TOKEN FILE\n");

  const tokenFilePath = path.join(process.cwd(), "token.txt");

  if (!fs.existsSync(tokenFilePath)) {
    console.log("❌ Token file not found");
    return false;
  }

  try {
    let fileContent = fs.readFileSync(tokenFilePath, "utf8").trim();
    const originalLength = fileContent.length;

    console.log(`📝 Original token length: ${originalLength}`);
    console.log(
      `📝 Starts with "Bearer": ${
        fileContent.startsWith("Bearer ") ? "YES" : "NO"
      }`
    );

    // Remove any "Bearer " prefix if present
    if (fileContent.startsWith("Bearer ")) {
      fileContent = fileContent.substring(7); // Remove "Bearer "
      console.log('✅ Removed "Bearer " prefix from token file');
    }

    // Remove any quotes
    fileContent = fileContent.replace(/['"]/g, "").trim();

    // Save cleaned token
    fs.writeFileSync(tokenFilePath, fileContent, "utf8");

    console.log(`📝 Cleaned token length: ${fileContent.length}`);
    console.log(`📝 Cleaned token preview: ${fileContent.substring(0, 30)}...`);
    console.log("✅ Token file fixed successfully!");

    return true;
  } catch (error) {
    console.error("❌ Error fixing token file:", error.message);
    return false;
  }
}

fixTokenFile();
