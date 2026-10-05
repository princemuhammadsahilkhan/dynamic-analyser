# Contributing to Dynamic Analyser

Thank you for your interest in contributing.

## Development setup

```bash
git clone https://github.com/princemuhammadsahilkhan/dynamic-analyser.git
cd dynamic-analyser
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Run tests

Run the lightweight unit suite before submitting a change:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/unit -p "test_*.py"
```

Integration tests require a suitable Android/QEMU environment and should be run selectively on a host with working virtualization support.

## Adding or changing a security rule

When adding a rule:

1. Give it a unique `RULE-XXX` identifier.
2. Define the category, severity, confidence, and triggering evidence precisely.
3. Avoid speculative findings.
4. Never include credentials, tokens, cookies, or other sensitive payloads in finding descriptions.
5. Register the rule in the runner/rule engine where required.
6. Add focused unit coverage for positive and negative cases.
7. Add integration coverage when the behavior depends on the full analysis pipeline.

## Code expectations

- Keep changes focused and reviewable.
- Preserve existing public behavior unless the change intentionally updates it.
- Prefer explicit lifecycle and resource management over host-wide process commands.
- Do not introduce `pkill`, `killall`, or equivalent host-wide cleanup into the analysis workflow.
- Do not commit generated analysis output, local APKs, credentials, or environment files.

## Pull requests

A good pull request should explain:

- What changed and why.
- How it was tested.
- Any environment-specific limitations.
- Any security or compatibility considerations.

Keep commits focused and use clear commit messages.

## Security issues

Please do not disclose suspected vulnerabilities in public issues. Follow [`SECURITY.md`](SECURITY.md) for responsible reporting.

## License

By contributing, you agree that your contributions are provided under the project's [MIT License](LICENSE).
