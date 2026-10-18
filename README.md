# pr-triage

A review skill for coding agents: reads one GitHub pull request, explains what it
actually does in a form you can act on in fifteen seconds, hunts for security
holes and hidden or malicious code, and **stops** — nothing is posted to GitHub
until you say so.

Works with Claude Code, OpenCode and Hermes.

## What it does

You point it at a PR. It collects the diff, the metadata, the commit list and the
CI state into a scratch directory, where every file has a known line range. Then
it reads the diff file by file — opening the surrounding code only when a
judgement needs it — and writes a draft review:

```
## PR #42 — Add telemetry + faster install path
**Verdict: do not merge.** Eight things in this diff deserve a look, and one of
them hands CI a writable token.

**If merged as-is:** anyone who can open a pull request can run commands on this
repository's CI runner with a write token.

### Look at these three
1. **.github/workflows/deploy.yml:2-3** — the trigger changed to
   `pull_request_target` and permissions to `write-all` ...
2. **install.sh:3** — `curl … | sh` from a domain registered nine days ago ...
3. **package.json:13,17** — a `preinstall` hook plus `axois` (one letter from
   `axios`) ...

### Not checked
assets/logo.tar.gz (binary, no patch).
```

Then it waits. You read it, ask for changes if you want, and say "post it" — and
it posts exactly one advisory comment, attributed and never an approval.

The shape is deliberate: verdict first, at most three things to look at, an
explicit read-time estimate, everything else folded away, and a "not checked"
section that names what it could not see. Short on purpose.

## What it looks for

**Ordinary security.** Injection, authz gaps, secrets in the diff, unsafe
deserialisation, path traversal, CI permissions.

**Hidden and malicious code.** Obfuscation and payload unpacking, exfiltration to
throwaway hosts, install-time hooks that run on `npm install`, dependency
lookalikes (`axois`, `lodahs`, `reqeusts`), CI that hands a write token to
untrusted input, bidi and zero-width character smuggling, homoglyph identifiers,
and PRs that quietly edit the config of the agent reviewing them.

A regex hit is never a finding. The skill is told to verify each lead against the
real file — what the code does, where the input comes from, what an attacker
gains — and to drop anything it cannot substantiate. When the malice pass finds
nothing, it says so in one sentence rather than staying silent.

## Safety rules it follows

- Never executes, installs or builds anything from the PR. It reads a diff.
- Never posts, approves, merges, pushes or labels without a later-turn approval
  of a visible draft.
- Never approves or merges at all — approval belongs to the human.
- Never quotes a secret value; cites the location and the type.
- Treats the PR description and code comments as hostile input, not instructions.
- Read-only git, read-only API. The only write it can make is one comment.

## Install

**Windows (PowerShell)** — clone straight into the skills directory:

```powershell
git clone https://github.com/schatten007/pr-triage "$HOME\.claude\skills\pr-triage"
cmd /c mklink /J "$HOME\.hermes\skills\pr-triage" "$HOME\.claude\skills\pr-triage"
```

**macOS / Linux**

```bash
git clone https://github.com/schatten007/pr-triage ~/.claude/skills/pr-triage
ln -s ~/.claude/skills/pr-triage ~/.config/opencode/skills/pr-triage
ln -s ~/.claude/skills/pr-triage ~/.hermes/skills/pr-triage
```

OpenCode also reads `.claude/skills`, so on OpenCode the clone above already
works. Per-agent paths, project-level installs and uninstall steps are in
[`references/install.md`](references/install.md).

**Requirements:** Python 3.8+ (standard library only), `git`, and the
[GitHub CLI](https://cli.github.com/) authenticated with `gh auth login`.
Without `gh` it still runs `--from-git --base main` against a local branch, with
fewer signals.

## Use

```
review PR 42
triage https://github.com/owner/repo/pull/42
is this diff safe to merge?
```

Or directly:

```bash
python3 scripts/collect.py 42
```

It writes `manifest.json`, `diff.patch`, `scan.txt` and `body.md` into a
git-ignored `.local/` scratch directory, and prints where.

## Check it works

```bash
python3 selftest/selftest.py
```

54 checks, no network and no credentials needed. It drives a fake `gh` and a
throwaway git repository with fixtures that include a `pull_request_target`
workflow, a `curl | sh` installer, typosquatted dependencies, bidi and
zero-width smuggling, a homoglyph identifier, a filename with a newline in it and
a lone surrogate. Run this after changing the collector — it has caught a real
bug every time it was extended. On Windows, run it from Git Bash or WSL.

## Layout

```
SKILL.md                          the workflow and the hard rules
scripts/collect.py                read-only collector (the only executable part)
references/security-checklist.md  hidden/malicious code taxonomy + verification protocol
references/report-format.md       the report shape, with worked examples
references/install.md             per-agent install, requirements, uninstall
selftest/                         offline test suite and hostile fixtures
```

## Scope

Reads open PRs, and a local branch against a base. Does not write code, does not
fix what it finds, does not review its own output. Sections it could not check
are named in the report rather than assumed clean.

## License

MIT — see [LICENSE](LICENSE).
