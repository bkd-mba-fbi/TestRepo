const fs = require("fs");

const inputPath = "reports/retire-report.json";
const outputPath = "reports/retire-report.html";

if (!fs.existsSync(inputPath)) {
  console.error("Report not found:", inputPath);
  process.exit(1);
}

const data = JSON.parse(fs.readFileSync(inputPath, "utf-8"));
let html = `<html><head><meta charset="UTF-8"><title>Retire.js Report</title></head><body>`;
html += `<h1>Retire.js Sicherheitsbericht</h1>`;

if (!data.data || data.data.length === 0) {
  html += `<p><em>Keine Schwachstellen gefunden oder keine Daten im Report.</em></p>`;
} else {
  data.data.forEach((entry) => {
    html += `<h2>Datei: ${entry.file}</h2>`;
    entry.results.forEach((result) => {
      html += `<p><strong>${result.component}</strong> v${result.version}</p>`;
      result.vulnerabilities.forEach((vuln) => {
        let cve = "-";
        if (Array.isArray(vuln.info)) {
          const match = vuln.info.find((url) => url.includes("CVE-"));
          if (match) cve = match.split("/").pop();
        }

        html += `<ul>`;
        html += `<li><strong>Schwere:</strong> ${vuln.severity || "?"}</li>`;
        html += `<li><strong>CVE:</strong> ${cve}</li>`;
        if (vuln.info) {
          html += `<li><strong>Details:</strong><ul>`;
          vuln.info.forEach((link) => {
            html += `<li><a href="${link}">${link}</a></li>`;
          });
          html += `</ul></li>`;
        }
        html += `</ul>`;
      });
    });
  });
}

html += `</body></html>`;
fs.writeFileSync(outputPath, html);
console.log("✅ HTML-Bericht erstellt:", outputPath);
