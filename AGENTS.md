# AGENTS.md — wifi-jammer

## This repo
[One sentence: what this repo does]
Stack: Python
Domain: [what this repo is responsible for]

## Rules — thin loader, no submodule
Rules are NOT vendored into this repo. This repo does NOT need a rules submodule.
`AGENTS.md` is only the repo-local loader: domain, commands, conventions, and pointers to `~/.1ai`.

Engineering rules are enforced by machine-level loaders when `setup-dev.sh` has been run:
- Claude Code: SessionStart hook injects `~/.1ai/core/RULES.md`
- OpenCode: plugin injects `~/.1ai/core/RULES.md`
- OMP: wrapper appends `~/.1ai/core/RULES.md` to launch sessions

Primary rules file:
```bash
cat ~/.1ai/core/RULES.md
```

Pre-ship gate:
```bash
cat ~/.1ai/core/GATE.md
```

If `~/.1ai` or auto-load is missing, run:
```bash
bash ~/.1ai/scripts/setup-dev.sh
```

Do NOT add the rules repo as a git submodule. Update rules centrally, then run/sync the thin `AGENTS.md` template.

## Hard rules
1. Read code before writing code.
2. No completion claim without literal receipt.
3. Compile/test/use like a real user before claiming work is ready.
4. Task must match this repo domain.
5. Run GATE.md before commit/PR.

## Repo-specific conventions
- [add conventions specific to this repo]

## Commands
- Dev:   `python -m app`
- Test:  `pytest`
- Build: `python -m compileall .`
- Lint:  `ruff check .`
