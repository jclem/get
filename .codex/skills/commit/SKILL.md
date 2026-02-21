---
name: commit
description: Create and refine git commits, amend history, and push branches for requested code changes. Use when a user asks to craft, rewrite, or improve commit messages, stage specific files, amend previous commits, force-push updated commits, or enforce commit message formatting.
---
Write commit messages with a single imperative first line and optional freeform body.

Commit message format:
1. First line is always exactly one imperative sentence.
2. First line uses no final punctuation mark.
3. First line must describe the primary code change.
4. Example first line: `Add flag for setting HTTP method`.
5. If extra detail is useful, add a blank line and then freeform body text.

Workflow:
1. Check intended files with `git status --short`.
2. Stage changes with `git add` (or `git add -A` when all current changes are required).
3. Read the staged diff with `git diff --cached --stat` before writing the first line.
4. Commit with `git commit -m "<imperative first line>"` for single-line messages.
5. For body text, use `git commit` and write:
   `<imperative first line>`

   `<freeform body>`
6. Amend with `git commit --amend` or `git commit --amend -m "<new imperative first line>"`.
7. Push with `git push`, and use `git push --force-with-lease` when rewriting history.
8. If hooks fail, apply the minimal fix from hook output and rerun.
