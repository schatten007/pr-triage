# Installing pr-triage

One directory serves all three agents. It follows the Agent Skills layout
(`<name>/SKILL.md` plus supporting files), which Claude Code, OpenCode and
Hermes all read.

## The one-folder setup

Keep the skill somewhere permanent, then point each agent at it. On Windows
the link is a directory junction, which needs no administrator rights; on
macOS and Linux it is a symlink.

**Windows (PowerShell)**

```powershell
# clone or copy the skill once, then link it
$src = "$HOME\skills\pr-triage"
New-Item -ItemType Directory -Force "$HOME\.claude\skills" | Out-Null
cmd /c mklink /J "$HOME\.claude\skills\pr-triage" $src
cmd /c mklink /J "$HOME\.hermes\skills\pr-triage" $src

# OpenCode: also reads .claude/skills, so the link above already covers it.
# To be explicit instead:
New-Item -ItemType Directory -Force "$HOME\.config\opencode\skills" | Out-Null
cmd /c mklink /J "$HOME\.config\opencode\skills\pr-triage" $src
```

**macOS / Linux**

```bash
mkdir -p ~/.claude/skills ~/.config/opencode/skills ~/.hermes/skills
SRC=~/skills/pr-triage
ln -s "$SRC" ~/.claude/skills/pr-triage
ln -s "$SRC" ~/.config/opencode/skills/pr-triage
ln -s "$SRC" ~/.hermes/skills/pr-triage
```

Editing the skill in `$SRC` updates it for all three agents at once.

## Where each tool looks

| tool | user-level | project-level | notes |
|---|---|---|---|
| Claude Code | `~/.claude/skills/<name>/SKILL.md` | `.claude/skills/<name>/SKILL.md` | `description` frontmatter is what triggers it |
| OpenCode | `~/.config/opencode/skills/<name>/SKILL.md` | `.opencode/skills/<name>/SKILL.md` | also reads `.claude/skills`, so a Claude Code install is picked up |
| Hermes | `~/.hermes/skills/<name>/SKILL.md` | project skill directory | Bundled skills live in the same tree |

If an agent does not pick the skill up, check two things: that the file is
literally named `SKILL.md` (not `skill.md`, not `pr-triage.md`), and that the
frontmatter `name:` matches the folder name. A skill whose description does
not mention the words the user actually types — "review this PR", "is this
safe" — will silently never fire.

For an agent that does not support skills at all, add one line to its
project instructions file (`AGENTS.md`, `CLAUDE.md`, or equivalent):

```
For pull request review, read <path>/pr-triage/SKILL.md and follow it exactly.
```

## Requirements

- `git` on PATH.
- `gh` (GitHub CLI), authenticated: `gh auth login`. Windows:
  `winget install --id GitHub.cli`. Without `gh`, the collector still runs in
  `--from-git` mode against a local branch, with fewer signals.
- Python 3.8 or newer, as `python3` or `python`. Standard library only, no
  packages to install. Windows: the Store build or python.org both work; if
  `python3` is not on PATH, `python` usually is.

## Check the install

From a repository with an open PR:

```bash
python3 ~/.claude/skills/pr-triage/scripts/collect.py <PR-number>
```

You should see one line of PR metadata, the output directory, and a scan
count. To exercise the collector without touching GitHub:

```bash
python3 <skill-dir>/selftest/selftest.py
```

On Windows, run that from Git Bash or WSL; it drives a fake `gh` and a
throwaway git repository and assumes POSIX file permissions.

That runs fixtures including hostile ones — a `pull_request_target` workflow,
a `curl | sh` installer, a typosquatted dependency, ANSI and bidi smuggling —
in a temporary directory and prints a pass/fail count. It needs no network and
no credentials. If it reports failures, the collector changed; do not use the
skill until you understand why.

## Invoking it

- Claude Code: `/pr-triage 42`, or just "review PR 42" — the description
  handles matching.
- OpenCode: same; the skill appears in its skill list once the folder is in a
  path it scans.
- Hermes: ask for the skill by name, or describe the task.

## Permissions

The skill needs read access to a repository and the ability to run `gh` and
`git` read commands. It does not need write access to post the comment itself
if you prefer to run the final command by hand — in that case, tell the agent
"show me the command, don't run it", and the approval gate becomes a copy-paste.

If your setup sandboxes the agent away from the network (common in container
setups), `gh` will fail and only `--from-git` mode works. In that case the
comment command must run on the host.

## Updating

Replace the directory contents; the links keep working. If you write tooling
against the collector's `manifest.json`, watch its `version` field — it is
generated output, not a setting you edit.

## Uninstall

Remove the three links (or junctions), then the source directory:

```powershell
cmd /c rmdir "$HOME\.claude\skills\pr-triage"
cmd /c rmdir "$HOME\.config\opencode\skills\pr-triage"
cmd /c rmdir "$HOME\.hermes\skills\pr-triage"
Remove-Item -Recurse -Force "$HOME\skills\pr-triage"
```

`rmdir` is the correct command for a junction; do not use `rm -rf` inside the
link, which would delete the source through it.
