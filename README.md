# IR Reporting Support Agent

[日本語](README_jp.md)

A tool for **creating** and **reviewing** incident investigation reports, using a Python CLI together
with a coding agent such as Claude Code or Codex. Every finding in a report is linked to evidence
that a human has approved.

- **Create a report** from logs, exports, and notes → `reports/final_report.md`
- **Review a vendor report** (PDF / Word / Markdown / text) as a second opinion → `final_review.md`

## Setup

**Requirements:** Python 3.10+ and a coding agent (Claude Code recommended, Codex also supported).
No separate LLM API key is needed; the agent's own model is used.

```bash
git clone <this-repo>
cd ir-reporting-agent
pip install -e .
```

Start the agent from the repository root:

```bash
claude   # Claude Code (uses .claude/skills/ automatically)
codex    # Codex CLI (reads AGENTS.md automatically)
```

## Usage

### Create a report

1. Create a case directory and put your logs, exports, and notes under `artifacts/`
   (text, CSV, syslog, EVTX text exports, Markdown, etc.):

   ```
   my-case/
   └── artifacts/
       ├── AD01/security_events.evtx.txt
       ├── FS01/edr_process_network.csv
       └── VPN/sslvpn.log
   ```

2. Tell the agent which case to work on, for example:

   ```
   Analyze ./my-case and proceed to the next checkpoint
   ```

   With Codex, add "Follow AGENTS.md".

3. Approve, reject, or modify the content at each of the three checkpoints:

   | Checkpoint | What you review |
   |---|---|
   | 1. Evidence | Extracted evidence candidates |
   | 2. Analysis | Analysis results and open items |
   | 3. Draft | The report draft |

   Reply in chat, or edit the review documents under `my-case/reviews/*.md` directly.

4. The final report is written to `my-case/reports/final_report.md`.

If the work is interrupted, ask the agent to continue, or check the current step yourself:

```bash
ir-agent --case-dir ./my-case status   # "Next step" shows what to do next
```

If you update files in `artifacts/`, ask the agent to run `ingest` again. Affected steps are marked
stale and rerun.

To try it out, use the fictional sample case `sample_cases/case-2026-vpn-compromise`.

### Review a vendor report

Give the agent the report file. No case directory is needed.

```
Review ~/Downloads/vendor_report.pdf against the quality checklists
```

With Codex: `Follow AGENTS.md and review ~/Downloads/vendor_report.pdf`

Output: `reviews/<report-stem>/<run-id>/final_review.md`, containing:

- A checklist evaluation for every item (met / partially met / not met / not applicable / unknown)
- Overclaim findings and improvement suggestions
- Items your organization should confirm separately
- Limitations of the AI-assisted review

> The review only covers what is written in the report. It cannot verify missing logs or what the
> vendor actually did. Final judgment is up to a human reviewer.

## Development

```bash
pip install -e ".[dev]"
pytest          # tests
ruff check .    # lint
mypy ir_agent/  # type check
```

For agent operating rules and workflow details, see [AGENTS.md](AGENTS.md). The review checklists
live in `.claude/skills/ir-review-report/references/`.

`ir-agent bulk-mark-reviews` bulk-approves review documents for testing only. Do not use it on real
cases.

## License

See [LICENSE.txt](LICENSE.txt).
