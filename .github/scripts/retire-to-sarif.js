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
    const vulnSummaries = res.vulnerabilities.map(v => `- ${v.summary}`).join("\n");
    const cves = res.vulnerabilities.flatMap(v => v.identifiers?.CVE || []);
    const cwEs = res.vulnerabilities.flatMap(v => v.identifiers?.CWE || []);
    const helpUris = res.vulnerabilities.flatMap(v => v.info || []);
    const severities = res.vulnerabilities.map(v => v.severity || "medium");

    const ruleId = `retire-${res.component}-${ruleIdCounter++}`;
    rules.set(ruleId, {
      id: ruleId,
      name: `${res.component}@${res.version}`,
      shortDescription: { text: `Schwachstelle in ${res.component}@${res.version}` },
      fullDescription: { text: vulnSummaries },
      helpUri: helpUris[0] || "",
      properties: {
        tags: ["security", "vulnerability", ...cves, ...cwEs],
        severity: severities[0] || "medium",
      },
    });

    sarif.runs[0].results.push({
      ruleId,
      message: {
        text: `In ${res.component}@${res.version} wurden ${res.vulnerabilities.length} Schwachstellen erkannt:\n${vulnSummaries}`,
      },
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

sarif.runs[0].tool.driver.rules = Array.from(rules.values());
fs.writeFileSync("retire-report.sarif", JSON.stringify(sarif, null, 2));
