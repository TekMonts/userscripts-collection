const fs = require("fs");
const path = require("path");

const SCRIPTS_DIR = path.join(__dirname, "../scripts");
const README_PATH = path.join(__dirname, "../README.md");

function parseMeta(content) {
  const meta = {};
  const lines = content.split("\n");

  for (const line of lines) {
    if (line.includes("@name")) meta.name = line.split("@name")[1].trim();
    if (line.includes("@description")) meta.description = line.split("@description")[1].trim();
    if (line.includes("@version")) meta.version = line.split("@version")[1].trim();
  }

  return meta;
}

function generateTable(scripts) {
  let table = `
## 📦 Available Scripts

| Script | Description | Version | Install |
|--------|------------|--------|--------|
`;

  for (const s of scripts) {
    table += `| ${s.name} | ${s.description} | ${s.version} | [Install](${s.installUrl}) |\n`;
  }

  return table;
}

function main() {
  const files = fs.readdirSync(SCRIPTS_DIR).filter(f => f.endsWith(".user.js"));

  const scripts = files.map(file => {
    const fullPath = path.join(SCRIPTS_DIR, file);
    const content = fs.readFileSync(fullPath, "utf-8");

    const meta = parseMeta(content);

    return {
      ...meta,
      installUrl: `https://raw.githubusercontent.com/TekMonts/userscripts-collection/main/scripts/${file}`
    };
  });

  const table = generateTable(scripts);

  let readme = fs.readFileSync(README_PATH, "utf-8");

  // replace block
  readme = readme.replace(
    /<!-- SCRIPTS_TABLE_START -->([\s\S]*?)<!-- SCRIPTS_TABLE_END -->/,
    `<!-- SCRIPTS_TABLE_START -->\n${table}\n<!-- SCRIPTS_TABLE_END -->`
  );

  fs.writeFileSync(README_PATH, readme);
}

main();
