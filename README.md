# JunkCleaner

A Windows tool that scans your user folders (Documents, Desktop, Pictures, Videos, Music, Downloads, AppData) for large or unused files, lists them, and lets you choose what to delete. Files go to the Recycle Bin by default.

<img width="1002" height="594" alt="Screenshot 2026-11-11 213907" src="https://github.com/user-attachments/assets/05f6e19f-2339-430f-9ae3-b1f48d349bd1" />

## Run from source

```
python windows_cleaner.py
```

Requires Python 3.8+ on Windows. No extra packages.

## Excluded folders

Click **Excluded folders...** to add any folder on your PC (any drive) that must be left alone. Excluded folders and everything inside them are never scanned, listed or deleted, and nothing that contains one is deleted either. You can also right-click a result and choose **Exclude this folder from scans**. The list is saved in `%APPDATA%\JunkCleaner\excluded_folders.json`.

## Build the .exe with GitHub

- Every push to `main` builds `JunkCleaner.exe`. Download it from the run's **Artifacts** (Actions tab).
- To publish a release, push a tag: `git tag v1.0.0 && git push --tags`. The exe is attached to the release automatically.
- You can also start a build manually from Actions > Build Windows app > Run workflow.
