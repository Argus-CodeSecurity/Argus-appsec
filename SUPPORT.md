# Getting help

| You want to | Go to |
|---|---|
| Learn how to use Argus | The [documentation site](https://argus-codesecurity.github.io/Argus-appsec/) |
| Ask a question or discuss an idea | [GitHub Discussions](https://github.com/Argus-CodeSecurity/Argus-appsec/discussions) |
| Report a bug or a false positive/negative | [Open an issue](https://github.com/Argus-CodeSecurity/Argus-appsec/issues/new/choose) |
| Request a feature or a new rule | [Open an issue](https://github.com/Argus-CodeSecurity/Argus-appsec/issues/new/choose) |
| Report a security vulnerability in Argus | Follow [SECURITY.md](SECURITY.md). Never use a public issue. |

## Before opening an issue

- Check you are on the latest release: `pip install -U argus-appsec`, then
  `argus --version`.
- Search existing issues, including closed ones.
- For a false positive or false negative, include the smallest snippet that
  reproduces it, the rule id from the report (for example
  `ast-python.ast-sql-injection`),
  and the command you ran.
- Remove secrets and proprietary code from anything you paste. Argus redacts
  secret values in its own reports, but logs and screenshots may not.

## Response times

Argus is maintained on a best-effort basis by volunteers. Issues are usually
triaged within a week. Security reports follow the timelines in SECURITY.md.
