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
          name: "retire.js",
          informationUri: "https://retirejs.github.io/retire.js/",
          rules: [],
        },
      },
      results: [],
    },
  ],
};

const rules = new Map();

findings.forEach((f, idx) => {
  f.results.forEach((result) => {
    const ruleId = result.identifiers?.summary || `retire-${idx}`;
    const rule = {
      id: ruleId,
      name: result.component,
      shortDescription: { text: result.vulnerabilities[0]?.summary || "Vulnerability" },
      helpUri: result.vulnerabilities[0]?.info[0] || "",
      properties: {
        tags: ["security", "vulnerability"],
        severity: result.vulnerabilities[0]?.severity || "medium",
      },
    };

    rules.set(ruleId, rule);

    sarif.runs[0].results.push({
      ruleId,
      message: { text: rule.shortDescription.text },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file,
            },
          },
        },
      ],
    });
  });
});

sarif.runs[0].tool.driver.rules = Array.from(rules.values());

fs.writeFileSync("retire-report.sarif", JSON.stringify(sarif, null, 2));
