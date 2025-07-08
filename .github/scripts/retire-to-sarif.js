// .github/scripts/retire-to-sarif.js

const fs = require("fs");
const raw = fs.readFileSync("retire-report.json");
const findings = JSON.parse(raw).data || [];

const sarif = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Retire.js",
          informationUri: "https://retirejs.github.io/retire.js/",
          rules: [],
        },
      },
      results: [],
    },
  ],
};

const rules = new Map();
let ruleIdCounter = 0;

findings.forEach((finding) => {
  finding.results.forEach((res) => {
    res.vulnerabilities.forEach((vuln, idx) => {
      const ruleId = `retire-${res.component}-${ruleIdCounter++}`;
      const cves = vuln.identifiers?.CVE || [];
      const cwes = vuln.identifiers?.CWE || [];
      const helpUris = vuln.info || [];
      const severity = vuln.severity || "medium";

      // Regel pro Schwachstelle
      rules.set(ruleId, {
        id: ruleId,
        name: `${vuln.summary.slice(0, 80)}${vuln.summary.length > 80 ? "…" : ""}`,
        shortDescription: { text: vuln.summary },
        fullDescription: { text: vuln.summary },
        helpUri: helpUris[0] || "",
        properties: {
          tags: ["security", "vulnerability", ...cves, ...cwes],
          severity: severity,
        },
      });

      // Ergebnis zuordnen
      sarif.runs[0].results.push({
        ruleId,
        message: { text: vuln.summary },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: finding.file,
              },
            },
          },
        ],
      });
    });
  });
});

sarif.runs[0].tool.driver.rules = Array.from(rules.values());

fs.writeFileSync("retire-report.sarif", JSON.stringify(sarif, null, 2));
console.log("✅ retire-report.sarif erzeugt (Dependabot-konform).");
