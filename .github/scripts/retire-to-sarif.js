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

let resultId = 0;

findings.forEach((finding) => {
  finding.results.forEach((res) => {
    res.vulnerabilities.forEach((vuln, i) => {
      const ruleId = `retire-${res.component}-${vuln.identifiers?.CVE?.[0] || resultId}`;
      const rule = {
        id: ruleId,
        name: `${res.component}@${res.version || 'unknown'}`,
        shortDescription: { text: vuln.summary || "Unbenannte Schwachstelle" },
        fullDescription: { text: vuln.info?.[0] || "Siehe Retire.js Doku" },
        helpUri: vuln.info?.[0] || "",
        properties: {
          tags: ["security", "vulnerability", ...vuln.identifiers?.CVE || []],
          precision: "high",
          severity: vuln.severity || "medium",
        },
      };

      rules.set(ruleId, rule);

      sarif.runs[0].results.push({
        ruleId,
        message: { text: `[${res.component}@${res.version}] ${vuln.summary}` },
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

      resultId++;
    });
  });
});

sarif.runs[0].tool.driver.rules = Array.from(rules.values());

fs.writeFileSync("retire-report.sarif", JSON.stringify(sarif, null, 2));
console.log("✅ retire-report.sarif erfolgreich erstellt.");
