"""
Windows Cleaner
===============
Scans Documents, Desktop, Pictures, Videos, Music, Downloads and AppData (plus any
other folder in your profile) for heavy or unused files and folders, shows them
in a list, and lets you decide what to delete.

Only items NOT used for MORE THAN the number of days you enter are listed.

* Manual mode : tick the rows you want and press "Delete selected".
* Smart mode  : "Smart select" ticks only what is very likely safe to remove
                (caches, temp files, old installers, stale Downloads, ...).
                "Smart clean" does the same and then asks for one confirmation.

Safety rules
* Documents / Desktop / Pictures / Videos / Music and everything found in AppData
  (except known caches/temp) are never auto-selected.
* Regular files go to the Recycle Bin (unless "Permanently delete" is ticked).
  Caches/temp folders only lose their files older than the chosen days, and
  permanently, because they are regenerated.
* Junctions / symlinks and cloud-only OneDrive placeholders are never followed.

Run:  python windows_cleaner.py      (Python 3.8+, Windows, no extra packages)
"""
from __future__ import annotations

import ctypes
import glob
import os
import queue
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from ctypes import wintypes
from functools import lru_cache

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:  # lets the core logic be imported/tested without a GUI
    tk = None

MB = 1024 * 1024
DAY = 86400
REPARSE = 0x400          # junctions, symlinks, OneDrive placeholders
HIDDEN_SYSTEM = 0x2 | 0x4
SYSTEM = 0x4
CLOUD_ONLY = 0x1000 | 0x40000 | 0x400000   # offline / OneDrive "online-only" files
HOME = os.path.abspath(os.environ.get("CLEANER_HOME") or os.path.expanduser("~"))

# ---------------------------------------------------------------- rules ----

# (path relative to profile, category, reason, risk). Contents are removed,
# the folder itself is kept. "*" wildcards are allowed.
JUNK = [
    ("AppData/Local/Temp", "Temp files", "Temporary files", "safe"),
    ("AppData/Local/CrashDumps", "Temp files", "Application crash dumps", "safe"),
    ("AppData/Local/Microsoft/Windows/WER", "Temp files", "Windows error reports", "safe"),
    ("AppData/Local/Microsoft/Windows/INetCache", "Cache", "Internet cache", "safe"),
    ("AppData/Local/D3DSCache", "Cache", "Shader cache (rebuilt automatically)", "safe"),
    ("AppData/Local/Google/Chrome/User Data/*/Cache", "Browser cache", "Chrome cache", "safe"),
    ("AppData/Local/Google/Chrome/User Data/*/Code Cache", "Browser cache", "Chrome code cache", "safe"),
    ("AppData/Local/Microsoft/Edge/User Data/*/Cache", "Browser cache", "Edge cache", "safe"),
    ("AppData/Local/Microsoft/Edge/User Data/*/Code Cache", "Browser cache", "Edge code cache", "safe"),
    ("AppData/Local/Mozilla/Firefox/Profiles/*/cache2", "Browser cache", "Firefox cache", "safe"),
    ("AppData/Local/pip/Cache", "Dev cache", "pip download cache", "safe"),
    ("AppData/Local/npm-cache", "Dev cache", "npm download cache", "safe"),
    (".gradle/caches", "Dev cache", "Gradle cache (re-downloaded when needed)", "review"),
    (".nuget/packages", "Dev cache", "NuGet package cache (re-downloaded when needed)", "review"),
    (".m2/repository", "Dev cache", "Maven repository (re-downloaded when needed)", "review"),
]

INSTALLER_EXT = {".exe", ".msi", ".msix", ".iso"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz"}
DEV_DIRS = {"node_modules", "__pycache__", ".venv", "venv"}
LARGE_FILE = 200 * MB    # old files at least this big are labelled "Large & unused"
LISTING_MIN = 1 * MB     # junk folders / dev dirs / installers smaller than this are ignored
NEVER_FLAG = ("ntuser", "usrclass")   # registry hives: never listed


def _norm(rel):
    return os.path.normcase(os.path.join(*rel.split("/"))) if rel else ""


PROTECTED = {_norm(x) for x in (
    "", "AppData", "AppData/Local", "AppData/Roaming",
    "AppData/LocalLow", "Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music")}

_FOLDER_IDS = {
    "Documents": "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
    "Desktop": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "Pictures": "33E28130-4E1E-4676-835A-98395C3BC3BB",
    "Videos": "18989B1D-99B5-455B-841C-AB7C74E4DDFC",
    "Music": "4BD8D571-6D19-48D3-BE97-422220080E43",
    "Downloads": "374DE290-123F-4565-9164-39C4925E467B",
}


@lru_cache(maxsize=None)
def known_folders():
    """((name, path), ...) exactly as Windows reports them, so folders that were
    moved to OneDrive or another drive are still found."""
    if os.name != "nt" or os.environ.get("CLEANER_HOME"):
        return ()

    class GUID(ctypes.Structure):
        _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16),
                    ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]

    out = []
    for name, gid in _FOLDER_IDS.items():
        try:
            u = uuid.UUID(gid)
            g = GUID(u.time_low, u.time_mid, u.time_hi_version,
                     (ctypes.c_ubyte * 8)(*u.bytes[8:]))
            buf = ctypes.c_void_p()
            res = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(buf))
            if buf.value:
                if res == 0:
                    out.append((name, ctypes.wstring_at(buf.value)))
                ctypes.windll.ole32.CoTaskMemFree(buf)
        except Exception:
            pass
    return tuple(out)


def scan_roots():
    """[(path, in_downloads, in_appdata)] - every place the scanner looks at."""
    roots = []

    def add(path, dl=False, ad=False):
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return
        key = os.path.normcase(path)
        for r, _, _ in roots:
            rk = os.path.normcase(r)
            if key == rk or key.startswith(rk + os.sep):
                return                      # already covered by another root
        roots.append((path, dl, ad))

    known = dict(known_folders())
    for name in ("Documents", "Desktop", "Pictures", "Videos", "Music", "Downloads"):
        add(known.get(name) or os.path.join(HOME, name), dl=(name == "Downloads"))
    add(os.path.join(HOME, "AppData"), ad=True)          # hidden, so added explicitly

    try:
        tops = list(os.scandir(HOME))
    except OSError:
        tops = []
    for e in tops:                                       # any other visible profile folder
        n = e.name.lower()
        try:
            if not e.is_dir(follow_symlinks=False):
                continue
            attrs = getattr(e.stat(follow_symlinks=False), "st_file_attributes", 0)
        except OSError:
            continue
        if attrs & (REPARSE | HIDDEN_SYSTEM) or n == "appdata" or n.startswith(("onedrive", ".")):
            continue
        add(e.path)
    return roots


@dataclass
class Item:
    path: str
    size: int
    last_used: float
    category: str
    reason: str
    risk: str                 # "safe" | "review"
    is_dir: bool = False
    contents_only: bool = False
    in_downloads: bool = False
    iid: str = ""
    in_appdata: bool = False
    min_age_days: float = 0.0   # for contents_only: only files older than this are removed

    @property
    def age_days(self):
        return max(0.0, (time.time() - self.last_used) / DAY)


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def dir_stats(path, stop=None, cutoff=None):
    """(total size, newest mtime/atime) of a folder, not following links.
    With cutoff (a timestamp) only files last used BEFORE it are counted."""
    size, newest, stack = 0, 0.0, [path]
    while stack:
        if stop is not None and stop.is_set():
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & REPARSE or e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            last = max(st.st_mtime, st.st_atime)
                            if cutoff is None or last < cutoff:
                                size += st.st_size
                                newest = max(newest, last)
                    except OSError:
                        pass
        except OSError:
            pass
    if newest == 0.0:
        try:
            newest = os.stat(path).st_mtime
        except OSError:
            pass
    return size, newest


# -------------------------------------------------------------- scanning ----

class Scanner(threading.Thread):
    def __init__(self, q, min_size_mb, old_days, stop):
        super().__init__(daemon=True)
        self.q, self.stop = q, stop
        self.min_size = int(min_size_mb * MB)
        self.old_days = old_days
        self.now = time.time()
        self.cutoff = self.now - old_days * DAY    # last used before this => "old enough"
        self.junk_paths = set()                    # handled by _junk, not walked again
        self.seen = 0

    def run(self):
        try:
            self._junk()
            if not self.stop.is_set():
                self._walk()
        except Exception as exc:  # never let the thread die silently
            self.q.put(("progress", f"Scan error: {exc}"))
        self.q.put(("done", None))

    def _junk(self):
        for rel, cat, reason, risk in JUNK:
            pattern = os.path.join(HOME, *rel.split("/"))
            for p in glob.glob(pattern):
                if self.stop.is_set():
                    return
                if not os.path.isdir(p):
                    continue
                self.junk_paths.add(os.path.normcase(os.path.abspath(p)))
                self.q.put(("progress", f"Checking {p}"))
                size, newest = dir_stats(p, self.stop, self.cutoff)   # old files only
                if size >= LISTING_MIN:
                    self.q.put(("item", Item(
                        p, size, newest, cat, f"{reason} - files unused > {self.old_days:g} days",
                        risk, is_dir=True, contents_only=True,
                        in_appdata=rel.startswith("AppData"), min_age_days=self.old_days)))

    def _walk(self):
        for root, in_dl, in_ad in scan_roots():
            if self.stop.is_set():
                return
            self.q.put(("progress", f"Scanning {root}"))
            self._walk_dir(root, in_dl, in_ad)

    def _walk_dir(self, root, in_dl, in_ad):
        stack = [root]
        while stack:
            if self.stop.is_set():
                return
            d = stack.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                try:
                    st = e.stat(follow_symlinks=False)
                    attrs = getattr(st, "st_file_attributes", 0)
                    if e.is_dir(follow_symlinks=False):
                        if attrs & REPARSE or (in_ad and attrs & SYSTEM):
                            continue
                        n = e.name.lower()
                        if n == ".git" or os.path.normcase(e.path) in self.junk_paths:
                            continue
                        if n in DEV_DIRS:
                            if n == "__pycache__":
                                self._dev_dir(e.path, d, n, in_dl, in_ad)
                            elif not in_ad:          # inside AppData these belong to apps
                                self._dev_dir(e.path, d, n, in_dl, in_ad)
                        else:
                            stack.append(e.path)
                    else:
                        if e.is_symlink() or attrs & CLOUD_ONLY or (in_ad and attrs & SYSTEM):
                            continue
                        self._file(e.path, st, in_dl, in_ad)
                except OSError:
                    continue
                self.seen += 1
                if self.seen % 500 == 0:
                    self.q.put(("progress", f"Scanning... {self.seen:,} entries  ({d})"))

    def _dev_dir(self, path, parent, name, in_dl, in_ad):
        size, newest = dir_stats(path, self.stop)
        if size < LISTING_MIN:
            return
        if name == "__pycache__":
            if newest < self.cutoff:
                self.q.put(("item", Item(path, size, newest, "Python cache",
                                         "Python bytecode cache (regenerated automatically)",
                                         "safe", True, False, in_dl, in_appdata=in_ad)))
            return
        project_last = 0.0
        try:
            for e in os.scandir(parent):
                if e.name.lower() in DEV_DIRS:
                    continue
                try:
                    s = e.stat(follow_symlinks=False)
                    project_last = max(project_last, s.st_mtime, s.st_atime)
                except OSError:
                    pass
        except OSError:
            pass
        if project_last == 0.0:
            project_last = os.stat(path).st_mtime
        if project_last < self.cutoff:
            age = (self.now - project_last) / DAY
            self.q.put(("item", Item(path, size, project_last, "Dev dependencies",
                                     f"Reinstallable dependencies; project untouched {int(age)} days",
                                     "review", True, False, in_dl, in_appdata=in_ad)))

    def _file(self, path, st, in_dl, in_ad):
        last = max(st.st_mtime, st.st_atime)
        if last >= self.cutoff:                       # not older than the chosen days
            return
        size = st.st_size
        name = os.path.basename(path).lower()
        if name.startswith(NEVER_FLAG):
            return
        age = int((self.now - last) / DAY)
        ext = os.path.splitext(name)[1]
        pre = "AppData " if in_ad else ""

        def emit(cat, reason, risk):
            if in_ad:
                reason += "  (app data - make sure the app no longer needs it)"
            self.q.put(("item", Item(path, size, last, cat, reason, risk,
                                     False, False, in_dl, in_appdata=in_ad)))

        if in_dl and ext in INSTALLER_EXT and size >= LISTING_MIN:
            emit("Old installer", f"Installer in Downloads, unused {age} days", "safe")
        elif in_dl and ext in ARCHIVE_EXT and size >= LISTING_MIN:
            emit("Old archive", f"Archive in Downloads, unused {age} days", "review")
        elif size >= self.min_size:
            if size >= LARGE_FILE:
                emit(pre + "Large & unused", f"{human(size)} and unused for {age} days", "review")
            else:
                emit(pre + "Old file", f"Not used for {age} days", "review")


# ------------------------------------------------------- smart selection ----

def smart_pick(it, old_days):
    """True when an item is a good candidate for automatic removal."""
    if it.risk == "safe":
        return True
    if it.in_downloads and it.age_days >= old_days:
        return True
    if it.category == "Dev dependencies" and not it.in_appdata and it.age_days >= 180:
        return True
    return False


# -------------------------------------------------------------- deletion ----

_FIELDS = [
    ("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT),
    ("pFrom", wintypes.LPCWSTR), ("pTo", wintypes.LPCWSTR),
    ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
    ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR),
]


class _ShOp(ctypes.Structure):
    _fields_ = _FIELDS


if ctypes.sizeof(ctypes.c_void_p) == 4:
    class _ShOp(ctypes.Structure):  # noqa: F811
        _pack_ = 1
        _fields_ = _FIELDS


def recycle(paths):
    """Move paths to the Recycle Bin. Returns True on success."""
    op = _ShOp()
    op.hwnd = None
    op.wFunc = 3                       # FO_DELETE
    op.pFrom = "\0".join(os.path.abspath(p) for p in paths) + "\0\0"
    op.pTo = None
    op.fFlags = 0x40 | 0x10 | 0x400 | 0x4   # ALLOWUNDO|NOCONFIRM|NOERRORUI|SILENT
    res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return res == 0 and not op.fAnyOperationsAborted


def _on_rm_error(func, path, _exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _rmtree(path):
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_on_rm_error)
    else:
        shutil.rmtree(path, onerror=_on_rm_error)


def _remove_path(path):
    if os.path.islink(path) or (getattr(os.lstat(path), "st_file_attributes", 0) & REPARSE):
        try:
            os.rmdir(path)
        except OSError:
            os.remove(path)
    elif os.path.isdir(path):
        _rmtree(path)
        if os.path.exists(path):
            raise OSError("some files are in use")
    else:
        try:
            os.remove(path)
        except PermissionError:
            os.chmod(path, stat.S_IWRITE)
            os.remove(path)


def _purge_contents(path, cutoff=None):
    """Delete everything inside a folder (or, with cutoff, only what was last used
    before it), skipping what is locked. Returns the number of failures."""
    failed = 0
    try:
        children = list(os.scandir(path))
    except OSError:
        return 1
    for e in children:
        try:
            if cutoff is None:
                _remove_path(e.path)
                continue
            st = e.stat(follow_symlinks=False)
            is_real_dir = (e.is_dir(follow_symlinks=False)
                           and not getattr(st, "st_file_attributes", 0) & REPARSE)
            if is_real_dir:
                failed += _purge_contents(e.path, cutoff)
                if st.st_mtime < cutoff:
                    try:
                        os.rmdir(e.path)          # only succeeds when now empty
                    except OSError:
                        pass
            elif max(st.st_mtime, st.st_atime) < cutoff:
                _remove_path(e.path)
        except OSError:
            failed += 1
    return failed


def check_deletable(it):
    p = os.path.normcase(os.path.abspath(it.path))
    home = os.path.normcase(HOME)
    roots = [home] + [os.path.normcase(os.path.abspath(x)) for _, x in known_folders()]
    if not it.contents_only and p in roots:
        raise ValueError("protected folder")
    base = next((r for r in roots if p.startswith(r + os.sep)), None)
    if base is None:
        raise ValueError("outside your user folders")
    if not it.contents_only and base == home and p[len(home) + 1:] in PROTECTED:
        raise ValueError("protected folder")


def run_delete(items, permanent, q):
    """Delete items, reporting to queue q. Returns via ('deleted', (...))."""
    done, errors, freed = [], [], 0
    to_recycle = []
    total = len(items)

    for i, it in enumerate(items, 1):
        q.put(("progress", f"Deleting {i}/{total}…"))
        try:
            check_deletable(it)
            if not os.path.lexists(it.path):
                done.append(it)
                continue
            if it.contents_only:
                before = it.size
                cutoff = time.time() - it.min_age_days * DAY if it.min_age_days else None
                failed = _purge_contents(it.path, cutoff)
                after, _ = dir_stats(it.path, cutoff=cutoff)
                freed += max(0, before - after)
                it.size = after
                if after < LISTING_MIN:
                    done.append(it)
                if failed:
                    errors.append(f"{it.path}: {failed} item(s) in use were skipped")
            elif permanent:
                _remove_path(it.path)
                freed += it.size
                done.append(it)
            else:
                to_recycle.append(it)
        except Exception as exc:
            errors.append(f"{it.path}: {exc}")

    for start in range(0, len(to_recycle), 25):
        chunk = to_recycle[start:start + 25]
        q.put(("progress", f"Moving to Recycle Bin… {start}/{len(to_recycle)}"))
        recycle([c.path for c in chunk])
        for it in chunk:
            if os.path.lexists(it.path):          # batch failed for this one: retry alone
                recycle([it.path])
            if os.path.lexists(it.path):
                errors.append(f"{it.path}: could not be moved to the Recycle Bin")
            else:
                freed += it.size
                done.append(it)

    q.put(("deleted", (done, freed, errors)))


# ------------------------------------------------------------------- GUI ----

if tk is not None:

    class App(tk.Tk):
        COLS = [
            ("sel", "✓", 40, "center"), ("path", "Path", 420, "w"),
            ("size", "Size", 80, "e"), ("last", "Last used", 95, "center"),
            ("cat", "Category", 120, "w"), ("why", "Why flagged", 300, "w"),
            ("risk", "Risk", 65, "center"),
        ]

        def __init__(self):
            super().__init__()
            self.title("Windows Cleaner")
            self.geometry("1250x700")
            self.q = queue.Queue()
            self.stop = threading.Event()
            self.items = {}
            self.checked = set()
            self.counter = 0
            self.busy = False
            self.sort_state = ("size", True)
            self._build()
            self.after(100, self._poll)

        # ---- layout
        def _build(self):
            top = ttk.Frame(self, padding=8)
            top.pack(fill="x")
            ttk.Label(top, text="List files & folders NOT used for more than").pack(side="left")
            self.old_days = tk.IntVar(value=365)
            ttk.Spinbox(top, from_=1, to=36500, width=6, textvariable=self.old_days).pack(side="left", padx=4)
            ttk.Label(top, text="days     files at least").pack(side="left")
            self.min_mb = tk.IntVar(value=10)
            ttk.Spinbox(top, from_=1, to=100000, width=7, textvariable=self.min_mb).pack(side="left", padx=4)
            ttk.Label(top, text="MB").pack(side="left")
            self.scan_btn = ttk.Button(top, text="Scan", command=self.start_scan)
            self.scan_btn.pack(side="left", padx=12)
            self.stop_btn = ttk.Button(top, text="Stop", command=self.stop.set, state="disabled")
            self.stop_btn.pack(side="left")

            mid = ttk.Frame(self, padding=(8, 0))
            mid.pack(fill="both", expand=True)
            self.tree = ttk.Treeview(mid, columns=[c[0] for c in self.COLS],
                                     show="headings", selectmode="extended")
            for key, title, width, anchor in self.COLS:
                self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
                self.tree.column(key, width=width, anchor=anchor, stretch=(key in ("path", "why")))
            vs = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=vs.set)
            self.tree.pack(side="left", fill="both", expand=True)
            vs.pack(side="right", fill="y")
            self.tree.tag_configure("safe", foreground="#1a7f37")
            self.tree.tag_configure("review", foreground="#9a6700")
            self.tree.bind("<Button-1>", self._on_click)
            self.tree.bind("<space>", self._on_space)
            self.tree.bind("<Double-1>", lambda e: self.open_location())
            self.tree.bind("<Button-3>", self._on_right_click)
            self.menu = tk.Menu(self, tearoff=0)
            self.menu.add_command(label="Show in Explorer", command=self.open_location)
            self.menu.add_command(label="Tick / untick", command=self._toggle_selected_rows)

            bar = ttk.Frame(self, padding=8)
            bar.pack(fill="x")
            ttk.Button(bar, text="Select all", command=lambda: self._set_all(True)).pack(side="left")
            ttk.Button(bar, text="Clear", command=lambda: self._set_all(False)).pack(side="left", padx=4)
            ttk.Button(bar, text="Smart select", command=self.smart_select).pack(side="left", padx=(12, 4))
            ttk.Button(bar, text="Smart clean…", command=self.smart_clean).pack(side="left")
            self.permanent = tk.BooleanVar(value=False)
            ttk.Checkbutton(bar, text="Permanently delete (skip Recycle Bin)",
                            variable=self.permanent).pack(side="left", padx=16)
            self.del_btn = ttk.Button(bar, text="Delete selected", command=self.delete_selected)
            self.del_btn.pack(side="right")
            self.sum_var = tk.StringVar(value="Nothing selected")
            ttk.Label(bar, textvariable=self.sum_var).pack(side="right", padx=16)

            self.status = tk.StringVar(value="Scans Documents, Desktop, Pictures, Videos, Music, Downloads and AppData. "
                                             "Green = safe to remove, amber = review first.")
            ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                      padding=4).pack(fill="x", side="bottom")

        # ---- scanning
        def start_scan(self):
            if self.busy:
                return
            self.tree.delete(*self.tree.get_children())
            self.items.clear()
            self.checked.clear()
            self.counter = 0
            self.stop.clear()
            self._set_busy(True)
            try:
                mb, days = int(self.min_mb.get()), int(self.old_days.get())
                if mb < 1 or days < 1:
                    raise ValueError
            except (tk.TclError, ValueError):
                messagebox.showerror("Invalid settings", "Days and size must be whole numbers of 1 or more.")
                self._set_busy(False)
                return
            Scanner(self.q, mb, days, self.stop).start()
            self._update_summary()

        def _set_busy(self, busy):
            self.busy = busy
            self.scan_btn.config(state="disabled" if busy else "normal")
            self.stop_btn.config(state="normal" if busy else "disabled")
            self.del_btn.config(state="disabled" if busy else "normal")

        def _poll(self):
            try:
                while True:
                    kind, val = self.q.get_nowait()
                    if kind == "item":
                        self._add(val)
                    elif kind == "progress":
                        self.status.set(val)
                    elif kind == "done":
                        self._set_busy(False)
                        total = sum(i.size for i in self.items.values())
                        self.status.set(f"Scan finished: {len(self.items)} items, {human(total)} found.")
                        self.sort_by(self.sort_state[0], keep=True)
                    elif kind == "deleted":
                        self._after_delete(*val)
            except queue.Empty:
                pass
            self.after(100, self._poll)

        def _add(self, it):
            self.counter += 1
            it.iid = str(self.counter)
            self.items[it.iid] = it
            self.tree.insert("", "end", iid=it.iid, tags=(it.risk,), values=self._row(it, False))

        @staticmethod
        def _row(it, checked):
            last = time.strftime("%Y-%m-%d", time.localtime(it.last_used)) if it.last_used else "?"
            path = it.path + (f"  (files older than {it.min_age_days:g} days)" if it.contents_only else "")
            return ("☑" if checked else "☐", path, human(it.size), last,
                    it.category, it.reason, "Safe" if it.risk == "safe" else "Review")

        # ---- selection
        def _set_check(self, iid, state):
            if state:
                self.checked.add(iid)
            else:
                self.checked.discard(iid)
            self.tree.set(iid, "sel", "☑" if state else "☐")

        def _on_click(self, event):
            if self.tree.identify_region(event.x, event.y) == "cell" and self.tree.identify_column(event.x) == "#1":
                iid = self.tree.identify_row(event.y)
                if iid:
                    self._set_check(iid, iid not in self.checked)
                    self._update_summary()
                    return "break"

        def _on_space(self, _event):
            self._toggle_selected_rows()
            return "break"

        def _toggle_selected_rows(self):
            for iid in self.tree.selection():
                self._set_check(iid, iid not in self.checked)
            self._update_summary()

        def _on_right_click(self, event):
            iid = self.tree.identify_row(event.y)
            if iid:
                if iid not in self.tree.selection():
                    self.tree.selection_set(iid)
                self.menu.tk_popup(event.x_root, event.y_root)

        def _set_all(self, state):
            for iid in self.items:
                self._set_check(iid, state)
            self._update_summary()

        def smart_select(self):
            try:
                days = int(self.old_days.get())
            except (tk.TclError, ValueError):
                days = 365
            n = 0
            for iid, it in self.items.items():
                pick = smart_pick(it, days)
                self._set_check(iid, pick)
                n += pick
            self._update_summary()
            self.status.set(f"Smart select ticked {n} items. Review them, then press Delete selected.")

        def smart_clean(self):
            if self.busy:
                return
            if not self.items:
                messagebox.showinfo("Smart clean", "Run a scan first.")
                return
            self.smart_select()
            self.delete_selected(smart=True)

        def _update_summary(self):
            size = sum(self.items[i].size for i in self.checked if i in self.items)
            self.sum_var.set(f"Selected: {len(self.checked)} items, {human(size)}" if self.checked
                             else "Nothing selected")

        # ---- sorting
        def sort_by(self, col, keep=False):
            prev_col, desc = self.sort_state
            if not keep:
                desc = (not desc) if col == prev_col else (col in ("size", "sel"))
            self.sort_state = (col, desc)
            keyf = {
                "size": lambda i: i.size, "last": lambda i: i.last_used,
                "path": lambda i: i.path.lower(), "cat": lambda i: i.category,
                "why": lambda i: i.reason, "risk": lambda i: i.risk,
                "sel": lambda i: i.iid in self.checked,
            }[col]
            ordered = sorted(self.items.values(),
                             key=(lambda i: (i.iid in self.checked)) if col == "sel" else keyf,
                             reverse=desc)
            for idx, it in enumerate(ordered):
                self.tree.move(it.iid, "", idx)

        # ---- actions
        def open_location(self):
            sel = self.tree.selection()
            if not sel:
                return
            it = self.items[sel[0]]
            try:
                if it.is_dir:
                    os.startfile(it.path)
                else:
                    subprocess.Popen(["explorer", "/select,", os.path.normpath(it.path)])
            except OSError as exc:
                messagebox.showerror("Cannot open", str(exc))

        def delete_selected(self, smart=False):
            if self.busy:
                return
            chosen = [self.items[i] for i in self.checked if i in self.items]
            if not chosen:
                messagebox.showinfo("Delete", "Nothing is selected.")
                return
            size = sum(i.size for i in chosen)
            perm = self.permanent.get()
            n_caches = sum(i.contents_only for i in chosen)
            lines = [f"Delete {len(chosen)} items ({human(size)})?", ""]
            if perm:
                lines.append("PERMANENT deletion — nothing can be restored.")
            else:
                lines.append("Files and folders go to the Recycle Bin (restorable).")
                if n_caches:
                    lines.append(f"{n_caches} cache/temp folders lose their old files permanently "
                                 "(they are rebuilt automatically).")
            if any(i.in_appdata and i.risk == "review" for i in chosen):
                lines += ["", "Some items are inside AppData: deleting them can reset or break the app that owns them."]
            if any(i.risk == "review" for i in chosen):
                lines += ["", "Some selected items are marked 'Review' — make sure you don't need them."]
            if not messagebox.askyesno("Smart clean" if smart else "Confirm delete",
                                       "\n".join(lines), icon="warning"):
                return
            self._set_busy(True)
            threading.Thread(target=run_delete, args=(chosen, perm, self.q), daemon=True).start()

        def _after_delete(self, done, freed, errors):
            for it in done:
                if it.iid in self.items:
                    self.tree.delete(it.iid)
                    self.items.pop(it.iid)
                    self.checked.discard(it.iid)
            for iid in list(self.checked):          # partially emptied caches
                if iid in self.items:
                    self.tree.item(iid, values=self._row(self.items[iid], True))
            self._set_busy(False)
            self._update_summary()
            self.status.set(f"Freed {human(freed)}. {len(done)} items removed, {len(errors)} problems.")
            msg = f"Freed about {human(freed)}."
            if errors:
                msg += f"\n\n{len(errors)} problem(s):\n" + "\n".join(errors[:8])
                if len(errors) > 8:
                    msg += f"\n… and {len(errors) - 8} more"
            messagebox.showinfo("Done", msg)


def main():
    if os.name != "nt":
        print("This tool is meant for Windows.")
        return 1
    if tk is None:
        print("tkinter is not available in this Python install.")
        return 1
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    App().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
