# AGENTS.md — Project Rules for AI Agents

These rules apply to any AI agent (OpenClaw, Codex, Claude Code, etc.) working on this repo.

## Git Branching Rules

**Never commit feature or fix code directly to `main`.**

### Workflow

1. **Create a feature branch** before making any code changes:
   ```
   git checkout -b feat/short-description   # new features
   git checkout -b fix/short-description    # bug fixes
   git checkout -b refactor/short-description  # refactoring
   ```

2. **Make commits on the branch** — small, focused commits with clear messages.

3. **Test on the Linux test server** (xiaoqiang) before merging:
   - Deploy the branch: `ssh xiaoqiang "cd ~/.openclaw/extensions/keychat && git fetch && git checkout <branch> && npm install --omit=dev"`
   - Restart gateway and run the Integration Test Checklist (see README)

4. **Merge to main** only after all tests pass:
   ```
   git checkout main
   git merge --no-ff feat/short-description
   ```

5. **Then follow the Release flow** (version bump, tag, push, CI, npm publish).

### What goes directly on `main`

Only these are allowed without a branch:
- Documentation-only changes (README, comments, AGENTS.md)
- Version bumps (`npm version patch`)
- CI/workflow config changes

### Branch naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `refactor/` | Code restructuring (no behavior change) |
| `test/` | Test infrastructure |
| `docs/` | Documentation (if you prefer a branch) |

## Testing Rules

See README → "Integration Test Checklist" for the full 9-item checklist.

**No release without testing.** Every npm publish must be preceded by a full test pass on the Linux test server.

## Code Style

- All documentation, README, comments in **English only**
- Commit messages in English
- Use `console.log` with `[keychat]` prefix for bridge logs
- Rust changes require `cargo check` before commit
