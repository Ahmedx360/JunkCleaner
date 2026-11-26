# JunkCleaner

A Windows tool that scans your user folders (Documents, Desktop, Pictures, Videos, Music, Downloads, AppData) for large or unused files, lists them, and lets you choose what to delete. Files go to the Recycle Bin by default.

<img width="1002" height="594" alt="Screenshot 2026-11-11 213907" src="https://github.com/user-attachments/assets/05f6e19f-2339-430f-9ae3-b1f48d349bd1" />

## Run from source

```
python windows_cleaner.py
```

Requires Python 3.8+ on Windows. No extra packages.

## Storage usage tab

Open **Storage usage**, choose a local drive, and select **Analyze storage** to build a read-only breakdown of space used by Windows/system files, installed applications, user files, AppData, shared application data, the Recycle Bin, and other content.

Hover over a pie slice to see its size, percentage, file/folder counts, description, and folder path. Right-click a slice or its category row and choose **Open location in File Explorer** to navigate to that location. You can also copy the folder path from the same menu.

The scan does not change or delete files. It does not follow junctions or symbolic links, and it skips cloud-only placeholders. Some protected Windows data may not be readable; that difference is shown as **Unscanned / reserved**. Reported file sizes are logical sizes, so compression, sparse files, and hard links can make the chart differ from the drive's allocated-space figure.

## Excluded folders

Click **Excluded folders...** to add any folder on your PC (any drive) that must be left alone. Excluded folders and everything inside them are never scanned, listed or deleted, and nothing that contains one is deleted either. You can also right-click a result and choose **Exclude this folder from scans**. The list is saved in `%APPDATA%\JunkCleaner\excluded_folders.json`.

## Build the .exe with GitHub

- Every push to `main` builds `JunkCleaner.exe`. Download it from the run's **Artifacts** (Actions tab).
- To publish a release, push a tag: `git tag v1.0.0 && git push --tags`. The exe is attached to the release automatically.
- You can also start a build manually from Actions > Build Windows app > Run workflow.
