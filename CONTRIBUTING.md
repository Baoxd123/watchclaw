# Contributing to WatchClaw

Thank you for your interest in contributing to WatchClaw!

## Getting Started

```bash
git clone https://github.com/Baoxd123/watchclaw.git
cd watchclaw
pip install -e ".[dev]"
python -m pytest tests/
```

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests (`python -m pytest tests/ -v`)
5. Commit with a descriptive message
6. Open a Pull Request

## Code Style

- Python 3.11+
- Type hints on all public functions
- Docstrings on all modules and classes
- Tests for all new features (maintain >95% pass rate)

## Adding Rules

Custom security rules go in `configs/default-rules.yaml`. See [docs/rules.md](docs/rules.md) for the rule format and examples.

## Adding Sequence Patterns

New attack sequence patterns are defined in `src/watchclaw/sequence.py`. Each pattern needs:
- A descriptive name
- Ordered list of action types
- Maximum time gap between steps
- Score boost value

## Reporting Issues

- Use GitHub Issues
- Include WatchClaw version (`watchclaw version`)
- Include relevant log snippets from `/tmp/watchclaw/action.log`
- For security vulnerabilities, please email directly instead of opening a public issue

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
