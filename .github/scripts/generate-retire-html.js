const fs = require('fs');

const data = JSON.parse(fs.readFileSync('retire-report.json', 'utf8'));
let html = `<html><head><title>Retire.js Report</title></head><body>`;
html += `<h1>Retire.js Sicherheitsbericht</h1>`;

data.data.forEach(entry => {
  html += `<h2>Datei: ${entry.file}</h2>`;
  entry.results.forEach(result => {
    html += `<p><strong>${result.component}</strong> v${result.version}</p>`;
    result.vulnerabilities.forEach(vuln => {
      html += `<ul>`;
      html += `<li><strong>Schwere:</strong> ${vuln.severity || 'unbekannt'}</li>`;
      html += `<li><strong>CVE:</strong> ${vuln.identifiers?.cve || '–'}</li>`;
      html += `<li><strong>Beschreibung:</strong> ${vuln.identifiers?.summary || ''}</li>`;
      if (vuln.info) {
        html += `<li><strong>Details:</strong><ul>`;
        vuln.info.forEach(link => {
          html += `<li><a href="${link}">${link}</a></li>`;
        });
        html += `</ul></li>`;
      }
      html += `</ul>`;
    });
  });
});

html += `</body></html>`;
fs.writeFileSync('retire-report.html', html);
console.log('✅ retire-report.html erstellt.');