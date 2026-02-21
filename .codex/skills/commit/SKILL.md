---
name: commit
description: Create and refine git commits, amend history, and push branches for requested code changes. Use when a user asks to craft, rewrite, or improve commit messages, stage specific files, amend previous commits, or force-push updated commits.
---
Add a clean, accurate git commit workflow for staging, committing, amending, and pushing changes.

1. Confirm intended changes with `git status --short`.
2. Stage files with `git add` (or `git add -A` when all current changes are required).
3. Commit with `git commit -m "<message>"`.
4. Amend when asked with `git commit --amend` or `git commit --amend -m "<new message>"`.
5. Push with `git push`, and use `--force-with-lease` when rewriting history.
6. If hooks fail, apply the minimal fix from hook output and re-run the command sequence.
