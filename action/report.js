// Stellar Guard PR report script (run by actions/github-script).
//
// Reads the scan results JSON (path in $FINDINGS_PATH), formats a Markdown
// report, posts it as a new PR comment or updates the existing one (found by
// the `<!-- stellar-guard-report -->` marker), and fails the check when any
// finding has severity "high" (matching `stellar-guard scan`'s exit codes).
//
// The `github`, `context`, and `core` globals are provided by
// actions/github-script at runtime. The async IIFE wrapper lets the script
// also be syntax-checked with plain `node --check`.

(async () => {
  const fs = require('fs');

  const findingsPath = process.env.FINDINGS_PATH;
  const scannedPath = process.env.SCANNED_PATH || '.';

  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
  } catch (err) {
    core.setFailed(`Could not read stellar-guard findings from ${findingsPath}: ${err.message}`);
    return;
  }

  // HTML comment marker used to find (and update) this action's comment
  // instead of posting duplicates on repeated pushes to the same PR.
  const marker = '<!-- stellar-guard-report -->';

  const SEVERITY_META = [
    { key: 'high', label: '🔴 High' },
    { key: 'medium', label: '🟠 Medium' },
    { key: 'low', label: '🟡 Low' },
  ];

  // Group findings by severity, preserving input order within each group.
  const groups = {};
  for (const finding of findings) {
    const severity = finding.severity || 'unknown';
    if (!groups[severity]) {
      groups[severity] = [];
    }
    groups[severity].push(finding);
  }

  let body = `## 🛡️ Stellar Guard Security Report\n\n${marker}\n`;

  if (findings.length === 0) {
    body += '\n✅ No issues found.\n';
  } else {
    for (const { key, label } of SEVERITY_META) {
      const list = groups[key];
      if (!list || list.length === 0) {
        continue;
      }
      body += `\n### ${label} severity\n\n| File | Line | Rule | Finding |\n| --- | ---: | --- | --- |\n`;
      for (const finding of list) {
        body += `| \`${finding.file}\` | ${finding.line} | ${finding.rule_id} | ${finding.message} |\n`;
      }
    }
    const high = (groups.high || []).length;
    body += `\n_Scanned \`${scannedPath}\` — ${findings.length} finding(s), ${high} high severity._\n`;
  }

  core.info(`Stellar Guard report:\n${body}`);

  const { owner, repo } = context.repo;
  const issueNumber = context.issue.number;

  if (!issueNumber) {
    core.warning('Not running in a pull request/issue context; skipping the report comment.');
  } else {
    const comments = await github.paginate(github.rest.issues.listComments, {
      owner,
      repo,
      issue_number: issueNumber,
      per_page: 100,
    });
    const existing = comments.find((comment) => comment.body && comment.body.includes(marker));

    if (existing) {
      await github.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existing.id,
        body,
      });
      core.info(`Updated existing report comment #${existing.id} on PR #${issueNumber}`);
    } else {
      await github.rest.issues.createComment({
        owner,
        repo,
        issue_number: issueNumber,
        body,
      });
      core.info(`Created report comment on PR #${issueNumber}`);
    }
  }

  const highCount = (groups.high || []).length;
  if (highCount > 0) {
    core.setFailed(
      `Stellar Guard found ${highCount} high-severity finding(s); the check fails until they are addressed.`
    );
  } else {
    core.info('No high-severity findings; check passes.');
  }
})();
