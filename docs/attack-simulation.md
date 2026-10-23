# Attack Simulation Mode

Most scanners stop at "this endpoint is vulnerable to SQL injection." Nephilex goes
further: for each meaningful finding it produces a safe, self-contained
demonstration of the weakness, aimed at the developer who owns the code.

Enable it with `--attack-sim` or `attack_simulation: true` in config.

## What it produces

For every finding at Medium severity or above, Nephilex generates an
`ExploitScenario` with six parts:

1. **Discovery**, how an attacker would find the weakness in the first place.
2. **Walkthrough**, a step-by-step, read-only explanation of the exploit.
3. **Data at risk**, what could actually be exposed or changed.
4. **Business impact**, the consequence in plain language.
5. **How the fix blocks it**, why the recommended remediation stops the attack.
6. **Before / after**, a concise comparison of the vulnerable and fixed states.

These appear in the Markdown and HTML reports (in a collapsible section) and in
the JSON output under each finding's `exploit` field.

## Safety

The simulation is **descriptive, not executed**:

- Nephilex never sends traffic to a live target.
- It never runs generated exploit code.
- With a real model, the prompt constrains output to an educational,
  non-weaponized walkthrough rather than a copy-paste exploit.

Each scenario is marked `sandbox_ok: true` to record that it was produced in this
isolated, non-executing context, and each simulation notes that no live target
was contacted.

## With and without a model

- **Offline (heuristic provider, the default):** scenarios come from templates
  keyed on the finding's CWE. They are accurate for the common classes (SQLi,
  command injection, hardcoded secrets, and so on) and completely deterministic.
- **With a model (anthropic/openai/ollama):** the agent writes a scenario tailored
  to the specific code, framework, and data flow, which reads more like a real
  penetration-test note. If the model call fails, Nephilex falls back to the template
  so the report is never left incomplete.

## Example

For a SQL injection finding, the offline simulation reads roughly:

> **Discovery:** Fuzz the parameter with a single quote. A resulting SQL error or
> changed response reveals the input reaches the query.
>
> **Walkthrough:** 1. Observe a normal request. 2. Send `' OR '1'='1` in the
> parameter. 3. The WHERE clause becomes always-true, returning rows the user
> should not see. 4. Escalate with UNION SELECT to read other tables.
>
> **Data at risk:** Any data reachable by the database user, often user records,
> password hashes, tokens, and PII.
>
> **How the fix blocks it:** Parameterized queries bind input as data, so
> `' OR '1'='1` is treated as a literal string and the query structure can no
> longer change.

Run it yourself against the bundled example:

```bash
nephilex scan examples/vulnerable-app --attack-sim -f markdown -o report.md
```
