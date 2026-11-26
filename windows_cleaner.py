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
* Folders you add under "Excluded folders..." are never scanned, listed or deleted
  (the list is saved between runs).

Administrator mode (opt-in)
* Tick "Include system locations (admin)" to also list C:\\Windows\\Temp, the Windows
  Update download cache and Windows.old. The app asks Windows for administrator
  rights (UAC) and restarts itself elevated; nothing outside the user profile is
  touched unless the box is ticked AND the app is running as administrator.
* Only those three exact folders are ever allowed; anything else outside your
  profile is still refused. System items are deleted permanently (no Recycle Bin).
* Windows.old is never auto-selected and needs its own confirmation.

Run:  python windows_cleaner.py      (Python 3.8+, Windows, no extra packages)
"""
from __future__ import annotations

import contextlib
import ctypes
import glob
import json
import math
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
    from tkinter import filedialog, font as tkfont, messagebox, ttk
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

# ----------------------------------------------------------- exclusions ----
# Folders the user asked us to leave alone. Anything inside them is never
# scanned, listed or deleted, and nothing that contains one is deleted either.

_EXCLUDED = ()      # normalised folder keys, replaced as a whole (thread safe)


def _key(path):
    p = os.path.normcase(os.path.abspath(path))
    return p if len(p) <= 3 else p.rstrip("\\/")


def _prefix(key):
    return key if key.endswith(os.sep) else key + os.sep


def set_exclusions(paths):
    """Activate the given folders as exclusions."""
    global _EXCLUDED
    _EXCLUDED = tuple(dict.fromkeys(_key(p) for p in paths if p))


def is_excluded(path):
    """True when path is an excluded folder or lives inside one."""
    if not _EXCLUDED:
        return False
    k = _key(path)
    return any(k == e or k.startswith(_prefix(e)) for e in _EXCLUDED)


def contains_excluded(path):
    """True when path is, or has inside it, an excluded folder."""
    if not _EXCLUDED:
        return False
    k = _key(path)
    return any(e == k or e.startswith(_prefix(k)) for e in _EXCLUDED)


def exclusions_file():
    return (os.environ.get("CLEANER_EXCLUDE_FILE")
            or os.path.join(os.environ.get("APPDATA") or HOME, "JunkCleaner", "excluded_folders.json"))


def load_exclusions():
    try:
        with open(exclusions_file(), encoding="utf-8") as f:
            data = json.load(f)
        return [p for p in data if isinstance(p, str) and p]
    except (OSError, ValueError, TypeError):
        return []


def save_exclusions(paths):
    """Returns True when the list could be written."""
    try:
        f = exclusions_file()
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(list(paths), fh, indent=2, ensure_ascii=False)
        return True
    except OSError:
        return False


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
        if not os.path.isdir(path) or is_excluded(path):
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


# ------------------------------------------------------ admin / system ----
# Opt-in locations outside the user profile. Only the exact folders returned by
# system_rules() can ever be deleted in admin mode (see check_deletable).

@dataclass(frozen=True)
class SysRule:
    path: str
    category: str
    reason: str
    risk: str                 # "safe" | "review"
    contents_only: bool       # True: empty the folder, keep it. False: remove the folder itself
    services: tuple = ()      # Windows services stopped while deleting, restarted afterwards


def system_rules():
    """The only system locations admin mode may touch (resolved at call time)."""
    win = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    drive = os.environ.get("SystemDrive") or os.path.splitdrive(win)[0] or "C:"
    return [
        SysRule(os.path.join(win, "Temp"), "System temp", "Windows temp files",
                "safe", True),
        SysRule(os.path.join(win, "SoftwareDistribution", "Download"), "Windows Update",
                "Downloaded update files (re-downloaded when needed)", "safe", True,
                services=("wuauserv", "bits")),
        SysRule(os.path.join(drive + os.sep, "Windows.old"), "Windows.old",
                "Previous Windows installation - deleting it removes the option to roll back",
                "review", False),
    ]


def is_admin():
    """True when the process runs elevated (administrator)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Ask Windows (UAC prompt) to start this program again as administrator.
    Returns True when the elevated copy was launched, False when the user said
    no to the prompt or Windows refused."""
    try:
        if getattr(sys, "frozen", False):                  # PyInstaller .exe
            exe, args = sys.executable, sys.argv[1:]
        else:
            exe, args = sys.executable, [os.path.abspath(sys.argv[0])] + sys.argv[1:]
        args = [a for a in args if a != "--admin"] + ["--admin"]
        res = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe,
                                                  subprocess.list2cmdline(args), None, 1)
        return res > 32
    except Exception:
        return False


def _is_reparse(path):
    """True for junctions / symlinks (never followed in admin mode)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & REPARSE) or stat.S_ISLNK(st.st_mode)


def _run_quiet(cmd):
    """Run a console tool without a window. Returns its exit code, or -1 if it could not run."""
    try:
        return subprocess.run(cmd, capture_output=True,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).returncode
    except (OSError, subprocess.SubprocessError, ValueError):
        return -1


@contextlib.contextmanager
def _services_stopped(names):
    """Stop the given services, and start again only those that this call stopped."""
    stopped = []
    try:
        for n in names:
            if _run_quiet(["net", "stop", n, "/y"]) == 0:     # 2 = was not running
                stopped.append(n)
        yield
    finally:
        for n in reversed(stopped):
            _run_quiet(["net", "start", n])


def _force_delete_tree(path):
    """Delete a folder protected by system ACLs (Windows.old): take ownership,
    grant Administrators full control, then remove it. Never follows junctions."""
    _run_quiet(["takeown", "/F", path, "/R", "/D", "Y"])
    _run_quiet(["icacls", path, "/grant", "*S-1-5-32-544:F", "/T", "/C", "/Q"])
    _rmtree(path)
    if os.path.exists(path):
        raise OSError("some files are in use or protected")


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
    system: bool = False        # admin-mode item outside the user profile (see SysRule)

    @property
    def age_days(self):
        return max(0.0, (time.time() - self.last_used) / DAY)


VENDORS = {"google", "microsoft", "mozilla", "jetbrains", "adobe", "apple", "apple computer"}
APPDATA_SPECIAL = {"temp": "Windows Temp", "crashdumps": "Windows Crash Dumps",
                   "d3dscache": "Windows (DirectX)", "inetcache": "Windows Internet Cache"}


def software_name(it):
    """Best guess of the software or folder an item belongs to."""
    if it.system:
        return "Windows"
    path = os.path.abspath(it.path)
    parent = os.path.basename(os.path.dirname(path)) or os.path.basename(path)
    try:
        rel = os.path.relpath(path, HOME)
    except ValueError:                      # different drive
        return parent
    if rel.startswith(".."):
        return parent                       # known folder moved outside the profile
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    if not parts:
        return parent
    first = parts[0].lower()
    if first == "appdata" and len(parts) >= 3:
        name = parts[2]
        if name.lower() in APPDATA_SPECIAL:
            return APPDATA_SPECIAL[name.lower()]
        if name.lower() in VENDORS and len(parts) >= 4:
            return f"{name} {parts[3]}"
        return name
    if first.startswith(".") and len(parts) > 1:   # .gradle, .nuget, .m2 ...
        return parts[0].lstrip(".").capitalize()
    if os.path.basename(path).lower() in DEV_DIRS:  # project that owns the dependencies
        return parent
    return parent if not it.is_dir or it.contents_only else os.path.basename(path)


def bold(text):
    """Treeview cells can't be styled individually, so use Unicode bold letters."""
    out = []
    for ch in text:
        o = ord(ch)
        if "A" <= ch <= "Z":
            out.append(chr(0x1D400 + o - 65))
        elif "a" <= ch <= "z":
            out.append(chr(0x1D41A + o - 97))
        elif "0" <= ch <= "9":
            out.append(chr(0x1D7CE + o - 48))
        else:
            out.append(ch)
    return "".join(out)


class CellTip:
    """Small popup showing the full text of a Treeview cell that is cut off."""

    def __init__(self, tree, plain):
        self.tree, self.plain = tree, plain      # plain(iid, col) -> full text
        self.win = self.label = None
        self.where = None
        self.job = None
        tree.bind("<Motion>", self._motion, add="+")
        tree.bind("<Leave>", lambda e: self.hide(), add="+")
        tree.bind("<ButtonPress>", lambda e: self.hide(), add="+")
        tree.bind("<MouseWheel>", lambda e: self.hide(), add="+")

    def colors(self, bg, fg, border):
        self.bg, self.fg, self.border = bg, fg, border

    def _motion(self, e):
        tree = self.tree
        if tree.identify_region(e.x, e.y) != "cell":
            return self.hide()
        iid, col = tree.identify_row(e.y), tree.identify_column(e.x)
        if not iid or col == "#1":
            return self.hide()
        if (iid, col) == self.where:
            return
        self.hide()
        self.where = (iid, col)
        self.job = tree.after(350, lambda: self._show(iid, col, e.x_root, e.y_root))

    def _show(self, iid, col, x, y):
        if self.where != (iid, col):
            return
        key = self.tree["columns"][int(col[1:]) - 1]
        text = self.plain(iid, key)
        font = tkfont.nametofont(ttk.Style(self.tree).lookup("Treeview", "font") or "TkDefaultFont")
        if not text or font.measure(text) + 12 <= int(self.tree.column(key, "width")):
            return                                 # fits, nothing is cut off
        self.win = tk.Toplevel(self.tree)
        self.win.wm_overrideredirect(True)
        self.win.attributes("-topmost", True)
        tk.Label(self.win, text=text, justify="left", wraplength=700, bg=self.bg, fg=self.fg,
                 relief="solid", bd=1, highlightbackground=self.border,
                 padx=6, pady=3).pack()
        self.win.wm_geometry(f"+{x + 14}+{y + 18}")

    def hide(self):
        self.where = None
        if self.job:
            self.tree.after_cancel(self.job)
            self.job = None
        if self.win:
            self.win.destroy()
            self.win = None


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
                            if not is_excluded(e.path):
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
    def __init__(self, q, min_size_mb, old_days, stop, include_system=False):
        super().__init__(daemon=True)
        self.q, self.stop = q, stop
        self.include_system = include_system
        self.min_size = int(min_size_mb * MB)
        self.old_days = old_days
        self.now = time.time()
        self.cutoff = self.now - old_days * DAY    # last used before this => "old enough"
        self.junk_paths = set()                    # handled by _junk, not walked again
        self.seen = 0

    def run(self):
        try:
            self._junk()
            if self.include_system and is_admin() and not self.stop.is_set():
                self._system()
            if not self.stop.is_set():
                self._walk()
        except Exception as exc:  # never let the thread die silently
            self.q.put(("progress", f"Scan error: {exc}"))
        self.q.put(("done", None))

    def _system(self):
        """Admin mode: the fixed list of system locations, nothing else."""
        for rule in system_rules():
            if self.stop.is_set():
                return
            p = rule.path
            if not os.path.isdir(p) or _is_reparse(p) or is_excluded(p):
                continue
            if not rule.contents_only and contains_excluded(p):
                continue
            self.q.put(("progress", f"Checking {p}"))
            cutoff = self.cutoff if rule.contents_only else None   # Windows.old: always listed
            size, newest = dir_stats(p, self.stop, cutoff)
            if size < LISTING_MIN:
                continue
            reason = rule.reason
            if rule.contents_only:
                reason += f" - files unused > {self.old_days:g} days"
            self.q.put(("item", Item(
                p, size, newest, rule.category, reason, rule.risk,
                is_dir=True, contents_only=rule.contents_only, system=True,
                min_age_days=self.old_days if rule.contents_only else 0.0)))

    def _junk(self):
        for rel, cat, reason, risk in JUNK:
            pattern = os.path.join(HOME, *rel.split("/"))
            for p in glob.glob(pattern):
                if self.stop.is_set():
                    return
                if not os.path.isdir(p) or is_excluded(p):
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
                        if is_excluded(e.path):
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
        if contains_excluded(path):      # the user protects something inside it
            return
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
                emit("Large & unused", f"{human(size)} and unused for {age} days", "review")
            else:
                emit("Old file", f"Not used for {age} days", "review")


# ------------------------------------------------------- smart selection ----

def smart_pick(it, old_days):
    """True when an item is a good candidate for automatic removal."""
    if it.system and not it.contents_only:      # Windows.old is always a manual decision
        return False
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
            if is_excluded(e.path):
                continue
            if contains_excluded(e.path):         # keep it, clean around the protected part
                failed += _purge_contents(e.path, cutoff)
                continue
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


def _check_system(it):
    """Admin-mode gate: elevated + exactly one of the allowed system folders."""
    if not is_admin():
        raise ValueError("administrator rights are required")
    p = os.path.normcase(os.path.abspath(it.path))
    for rule in system_rules():
        if os.path.normcase(os.path.abspath(rule.path)) == p:
            if it.contents_only != rule.contents_only:
                raise ValueError("does not match the allowed system rule")
            if _is_reparse(it.path):
                raise ValueError("is a link or junction")
            return rule
    raise ValueError("not an allowed system location")


def check_deletable(it):
    """Raise ValueError when an item must not be deleted. Returns the matching
    SysRule for an approved system location, otherwise None."""
    if is_excluded(it.path):
        raise ValueError("excluded folder")
    if not it.contents_only and contains_excluded(it.path):
        raise ValueError("contains an excluded folder")
    if it.system:
        return _check_system(it)
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
            rule = check_deletable(it)          # SysRule for admin-mode items, else None
            if not os.path.lexists(it.path):
                done.append(it)
                continue
            # services come from the approved rule, never from the item itself
            with _services_stopped(rule.services if rule else ()):
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
                elif rule:                      # system folder: permanent, ACLs may block
                    _force_delete_tree(it.path)
                    freed += it.size
                    done.append(it)
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




# ------------------------------------------------------ storage analysis ----

STORAGE_COLORS = {
    "Windows / system": "#527fc1",
    "Installed apps": "#39966d",
    "User files": "#c28b3c",
    "App data": "#8b6ac8",
    "Shared app data": "#c56b70",
    "Recycle Bin": "#4d9ca5",
    "System reserved": "#7b8794",
    "Other": "#a77a56",
    "Unscanned / reserved": "#626b75",
}

STORAGE_DESCRIPTIONS = {
    "Windows / system": "Windows installation files, built-in components and the Windows.old folder.",
    "Installed apps": "Programs installed under Program Files folders.",
    "User files": "Files in Windows user profiles, excluding AppData.",
    "App data": "Per-user application settings, caches, databases and other AppData content.",
    "Shared app data": "Shared application data stored in ProgramData.",
    "Recycle Bin": "Items currently held in the drive's Recycle Bin.",
    "System reserved": "System Volume Information, recovery data and paging/hibernation files.",
    "Other": "Files and folders that do not match one of the named Windows locations.",
    "Unscanned / reserved": "The difference between Windows-reported used space and readable file sizes. It can include protected files, filesystem metadata and reserved space.",
}


def storage_drives():
    """Return mounted local fixed/removable drive roots on Windows."""
    if os.name != "nt":
        return []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        roots = []
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = f"{chr(65 + index)}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
            if drive_type in (2, 3, 6):  # removable, fixed, RAM disk
                roots.append(root)
        return roots
    except Exception:
        return []


def storage_bucket(path, drive_root):
    """Return (display category, Explorer folder) for one path on a drive."""
    try:
        relative = os.path.relpath(path, drive_root)
    except ValueError:
        relative = os.path.basename(path)
    parts = [part for part in relative.replace("\\", "/").split("/") if part and part != "."]
    if not parts:
        return "System reserved", drive_root

    first = parts[0].casefold()
    leaf = parts[-1].casefold()
    if first in ("windows", "windows.old", "$winreagent"):
        return "Windows / system", os.path.join(drive_root, parts[0])
    if first in ("program files", "program files (x86)", "program files (arm)"):
        return "Installed apps", os.path.join(drive_root, parts[0])
    if first == "programdata":
        return "Shared app data", os.path.join(drive_root, parts[0])
    if first == "$recycle.bin":
        return "Recycle Bin", os.path.join(drive_root, parts[0])
    if first == "system volume information" or first in ("recovery", "config.msi", "boot"):
        return "System reserved", os.path.join(drive_root, parts[0])
    if leaf in ("pagefile.sys", "hiberfil.sys", "swapfile.sys", "memory.dmp"):
        return "System reserved", drive_root
    if first == "users":
        appdata_at = next((i for i, part in enumerate(parts) if part.casefold() == "appdata"), None)
        if appdata_at is not None:
            return "App data", os.path.join(drive_root, *parts[:appdata_at + 1])
        return "User files", os.path.join(drive_root, parts[0])
    return "Other", os.path.join(drive_root, parts[0])


class StorageScanner(threading.Thread):
    """Read-only whole-drive size scan. It never follows links or deletes files."""

    def __init__(self, q, drive, stop):
        super().__init__(daemon=True)
        self.q, self.drive, self.stop = q, drive, stop
        self.seen = 0
        self.skipped = 0

    def run(self):
        try:
            result = self._scan()
        except Exception as exc:
            self.q.put(("storage_error", str(exc)))
        else:
            self.q.put(("storage_done", result))

    def _scan(self):
        usage = shutil.disk_usage(self.drive)
        buckets = {}
        stack = [self.drive]
        while stack and not self.stop.is_set():
            directory = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if self.stop.is_set():
                            break
                        try:
                            st = entry.stat(follow_symlinks=False)
                            attrs = getattr(st, "st_file_attributes", 0)
                            if entry.is_symlink() or attrs & REPARSE:
                                self.skipped += 1
                                continue
                            if attrs & CLOUD_ONLY:
                                self.skipped += 1
                                continue

                            category, location = storage_bucket(entry.path, self.drive)
                            bucket = buckets.setdefault(category, {
                                "name": category, "size": 0, "files": 0, "folders": 0,
                                "path": location, "description": STORAGE_DESCRIPTIONS[category],
                            })
                            if entry.is_dir(follow_symlinks=False):
                                bucket["folders"] += 1
                                stack.append(entry.path)
                            else:
                                bucket["files"] += 1
                                bucket["size"] += max(0, int(st.st_size))
                        except OSError:
                            self.skipped += 1
                        self.seen += 1
                        if self.seen % 3000 == 0:
                            self.q.put(("storage_progress",
                                        f"Scanning {self.drive} — {self.seen:,} entries checked, "
                                        f"{self.skipped:,} skipped…"))
            except OSError:
                self.skipped += 1

        scanned = sum(item["size"] for item in buckets.values())
        used = max(0, int(usage.total - usage.free))
        remainder = max(0, used - scanned)
        if remainder:
            buckets["Unscanned / reserved"] = {
                "name": "Unscanned / reserved", "size": remainder, "files": 0, "folders": 0,
                "path": self.drive, "description": STORAGE_DESCRIPTIONS["Unscanned / reserved"],
            }

        categories = sorted(buckets.values(), key=lambda item: item["size"], reverse=True)
        return {
            "drive": self.drive, "total": int(usage.total), "used": used,
            "free": int(usage.free), "scanned": scanned, "categories": categories,
            "skipped": self.skipped, "entries": self.seen, "partial": self.stop.is_set(),
        }


# ------------------------------------------------------------------- GUI ----

THEMES = {
    "light": dict(bg="#f0f0f0", fg="#1a1a1a", field="#ffffff", sel="#cce4ff", sel_fg="#000000",
                  head="#e1e1e1", border="#c8c8c8", safe="#1a7f37", review="#9a6700"),
    "dark": dict(bg="#1e1e1e", fg="#e6e6e6", field="#252526", sel="#094771", sel_fg="#ffffff",
                 head="#333337", border="#3c3c3c", safe="#4ec36b", review="#e3b341"),
}


def system_is_dark():
    """True when Windows is set to dark app mode."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except Exception:
        return False


if tk is not None:

    class App(tk.Tk):
        COLS = [
            ("sel", "✓", 40, "center"), ("path", "Path", 380, "w"),
            ("app", "Software / Folder", 150, "w"),
            ("size", "Size", 80, "e"), ("last", "Last used", 95, "center"),
            ("cat", "Category", 120, "w"), ("why", "Why flagged", 300, "w"),
            ("risk", "Risk", 65, "center"),
        ]

        def __init__(self):
            super().__init__()
            self.title("Windows Cleaner (Administrator)" if is_admin() else "Windows Cleaner")
            self.geometry("1250x700")
            self.q = queue.Queue()
            self.stop = threading.Event()
            self.items = {}
            self.checked = set()
            self.counter = 0
            self.busy = False
            self.storage_busy = False
            self.storage_result = None
            self.storage_segments = []
            self.storage_chart_geometry = None
            self.storage_selected_index = None
            self.storage_hover_index = None
            self.storage_tooltip = None
            self.storage_tooltip_label = None
            self.storage_stop = threading.Event()
            self.sort_state = ("size", True)
            self.dark = tk.BooleanVar(value=system_is_dark())
            self.exclusions = load_exclusions()
            set_exclusions(self.exclusions)
            # the elevated copy started by _restart_as_admin() comes back with --admin
            self.include_system = tk.BooleanVar(value=("--admin" in sys.argv and is_admin()))
            self._build()
            self._apply_theme()
            self.after(100, self._poll)

        def _apply_theme(self):
            t = THEMES["dark" if self.dark.get() else "light"]
            st = ttk.Style(self)
            st.theme_use("clam")
            self.configure(bg=t["bg"])
            st.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["field"],
                         bordercolor=t["border"], lightcolor=t["bg"], darkcolor=t["bg"],
                         troughcolor=t["bg"], focuscolor=t["bg"])
            st.configure("TButton", background=t["head"], foreground=t["fg"], padding=4)
            st.map("TButton", background=[("active", t["sel"]), ("disabled", t["bg"])],
                   foreground=[("disabled", t["border"])])
            st.configure("TCheckbutton", background=t["bg"], foreground=t["fg"])
            st.map("TCheckbutton", background=[("active", t["bg"])])
            st.configure("TSpinbox", fieldbackground=t["field"], foreground=t["fg"],
                         background=t["head"], arrowcolor=t["fg"])
            st.configure("TScrollbar", background=t["head"], arrowcolor=t["fg"], troughcolor=t["bg"])
            st.configure("Treeview", background=t["field"], fieldbackground=t["field"],
                         foreground=t["fg"], rowheight=22)
            st.map("Treeview", background=[("selected", t["sel"])],
                   foreground=[("selected", t["sel_fg"])])
            st.configure("Treeview.Heading", background=t["head"], foreground=t["fg"], relief="flat")
            st.configure("TNotebook", background=t["bg"], borderwidth=0)
            st.configure("TNotebook.Tab", background=t["head"], foreground=t["fg"], padding=(14, 7))
            st.map("TNotebook.Tab", background=[("selected", t["field"]), ("active", t["sel"])],
                   foreground=[("selected", t["fg"])])
            st.map("Treeview.Heading", background=[("active", t["sel"])])
            self.tree.tag_configure("safe", foreground=t["safe"])
            self.tree.tag_configure("review", foreground=t["review"])
            self.menu.configure(bg=t["field"], fg=t["fg"], activebackground=t["sel"],
                                activeforeground=t["sel_fg"])
            self.storage_menu.configure(bg=t["field"], fg=t["fg"], activebackground=t["sel"],
                                         activeforeground=t["sel_fg"])
            self.option_add("*TCombobox*Listbox.background", t["field"])
            self.tip.colors(t["head"], t["fg"], t["border"])
            self.storage_canvas.configure(bg=t["bg"])
            self._hide_storage_tooltip()
            self._render_storage_chart()

        # ---- layout
        def _build(self):
            self.tabs = ttk.Notebook(self)
            self.tabs.pack(fill="both", expand=True, padx=8, pady=(8, 0))
            cleaner_page = ttk.Frame(self.tabs)
            storage_page = ttk.Frame(self.tabs)
            self.tabs.add(cleaner_page, text="Junk cleaner")
            self.tabs.add(storage_page, text="Storage usage")

            top = ttk.Frame(cleaner_page, padding=8)
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
            self.excl_btn = ttk.Button(top, text="Excluded folders…", command=self.manage_exclusions)
            self.excl_btn.pack(side="left", padx=12)
            ttk.Checkbutton(top, text="Include system locations (admin)",
                            variable=self.include_system,
                            command=self._on_system_toggle).pack(side="left")
            ttk.Checkbutton(top, text="Dark mode", variable=self.dark,
                            command=self._apply_theme).pack(side="right")

            mid = ttk.Frame(cleaner_page, padding=(8, 0))
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
            self.tip = CellTip(self.tree, self._cell_text)
            self.menu = tk.Menu(self, tearoff=0)
            self.menu.add_command(label="Show in Explorer", command=self.open_location)
            self.menu.add_command(label="Tick / untick", command=self._toggle_selected_rows)
            self.menu.add_command(label="Exclude this folder from scans", command=self.exclude_selected)

            bar = ttk.Frame(cleaner_page, padding=8)
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

            storage_bar = ttk.Frame(storage_page, padding=10)
            storage_bar.pack(fill="x")
            ttk.Label(storage_bar, text="Drive").pack(side="left")
            drive_values = storage_drives()
            home_drive = os.path.splitdrive(HOME)[0] + os.sep
            if home_drive and home_drive not in drive_values:
                drive_values.insert(0, home_drive)
            if not drive_values:
                drive_values = [home_drive or "C:\\"]
            self.storage_drive = tk.StringVar(value=drive_values[0])
            self.drive_combo = ttk.Combobox(storage_bar, textvariable=self.storage_drive,
                                            values=drive_values, width=8, state="readonly")
            self.drive_combo.pack(side="left", padx=6)
            self.storage_scan_btn = ttk.Button(storage_bar, text="Analyze storage",
                                                command=self.start_storage_scan)
            self.storage_scan_btn.pack(side="left", padx=(6, 4))
            self.storage_stop_btn = ttk.Button(storage_bar, text="Stop", command=self.storage_stop.set,
                                                state="disabled")
            self.storage_stop_btn.pack(side="left")
            self.storage_status = tk.StringVar(value="Choose a drive and analyze it to see where its space is used.")
            ttk.Label(storage_bar, textvariable=self.storage_status).pack(side="left", padx=12)

            storage_body = ttk.Frame(storage_page, padding=12)
            storage_body.pack(fill="both", expand=True)
            self.storage_canvas = tk.Canvas(storage_body, width=420, height=390,
                                             highlightthickness=0, bd=0)
            self.storage_canvas.pack(side="left", padx=(0, 18), anchor="n")
            self.storage_canvas.bind("<Motion>", self._storage_canvas_motion)
            self.storage_canvas.bind("<Leave>", lambda _e: self._hide_storage_tooltip())
            self.storage_canvas.bind("<Button-3>", self._storage_chart_right_click)

            storage_details = ttk.Frame(storage_body)
            storage_details.pack(side="left", fill="both", expand=True)
            self.storage_summary = tk.StringVar(value="No storage analysis yet")
            ttk.Label(storage_details, textvariable=self.storage_summary,
                      font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(2, 8))
            self.storage_table = ttk.Treeview(
                storage_details, columns=("category", "size", "share", "files", "folders"),
                show="headings", selectmode="browse", height=13)
            for key, heading, width, anchor in (
                ("category", "Category", 190, "w"), ("size", "Size", 95, "e"),
                ("share", "Share", 65, "e"), ("files", "Files", 70, "e"),
                ("folders", "Folders", 75, "e"),
            ):
                self.storage_table.heading(key, text=heading)
                self.storage_table.column(key, width=width, anchor=anchor, stretch=(key == "category"))
            self.storage_table.pack(fill="both", expand=True)
            self.storage_table.bind("<<TreeviewSelect>>", self._storage_table_select)
            self.storage_table.bind("<Double-1>", lambda _e: self.open_storage_location())
            self.storage_table.bind("<Button-3>", self._storage_table_right_click)
            self.storage_hint = tk.StringVar(value="Hover over a pie slice for details. Right-click a slice or row to open its folder.")
            ttk.Label(storage_details, textvariable=self.storage_hint, wraplength=560,
                      justify="left").pack(anchor="w", pady=(8, 4))
            self.storage_note = tk.StringVar(value="The analysis is read-only. It never changes or deletes files.")
            ttk.Label(storage_details, textvariable=self.storage_note, wraplength=560,
                      justify="left").pack(anchor="w")

            self.storage_menu = tk.Menu(self, tearoff=0)
            self.storage_menu.add_command(label="Open location in File Explorer",
                                           command=self.open_storage_location)
            self.storage_menu.add_command(label="Copy folder path",
                                           command=self.copy_storage_location)

            self.status = tk.StringVar(value="Scans Documents, Desktop, Pictures, Videos, Music, Downloads and AppData. "
                                             "Green = safe to remove, amber = review first.")
            ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                      padding=4).pack(fill="x", side="bottom")

        # ---- admin mode
        def _on_system_toggle(self):
            if not self.include_system.get():
                return
            if is_admin():
                self.status.set("System locations (Windows Temp, Update cache, Windows.old) "
                                "will be included in the next scan.")
                return
            if messagebox.askyesno(
                    "Administrator rights needed",
                    "System locations (C:\\Windows\\Temp, the Windows Update download cache "
                    "and Windows.old) can only be cleaned as administrator.\n\n"
                    "Windows will ask for your permission, then this app restarts with "
                    "administrator rights. The current scan results will be lost.\n\n"
                    "Restart as administrator?", icon="warning"):
                if relaunch_as_admin():
                    self.destroy()                  # the elevated copy takes over
                    return
                messagebox.showwarning("Administrator rights not granted",
                                       "Windows did not grant administrator rights, so "
                                       "system locations stay excluded.")
            self.include_system.set(False)

        # ---- whole-drive storage analysis
        def start_storage_scan(self):
            if self.storage_busy:
                return
            drive = self.storage_drive.get().strip()
            if not drive or not os.path.isdir(drive):
                messagebox.showerror("Storage analysis", "The selected drive is not available.")
                return
            self.storage_stop.clear()
            self._set_storage_busy(True)
            self.storage_status.set(f"Scanning {drive}…")
            self.storage_summary.set("Reading directory entries. This can take a while on large drives.")
            StorageScanner(self.q, drive, self.storage_stop).start()

        def _set_storage_busy(self, busy):
            self.storage_busy = busy
            self.storage_scan_btn.config(state="disabled" if busy else "normal")
            self.storage_stop_btn.config(state="normal" if busy else "disabled")
            self.drive_combo.config(state="disabled" if busy else "readonly")

        def _storage_scan_done(self, result):
            self._set_storage_busy(False)
            self.storage_result = result
            used_pct = (100.0 * result["used"] / result["total"]) if result["total"] else 0.0
            self.storage_summary.set(
                f'{result["drive"]}  •  {human(result["used"])} used of {human(result["total"])} '
                f'({used_pct:.1f}%)  •  {human(result["free"])} free')
            details = (f'{result["entries"]:,} entries checked; {result["skipped"]:,} inaccessible, '
                       f'link or cloud-only entries skipped. '
                       f'{human(result["scanned"])} of readable logical file sizes were counted.')
            if result["partial"]:
                details = "Partial scan — stopped by user. " + details
            details += " File sizes can differ from allocated disk space because of compression, sparse files and hard links."
            self.storage_note.set(details)
            self.storage_status.set("Analysis stopped early." if result["partial"] else "Analysis complete.")
            self._render_storage_chart()

        def _render_storage_chart(self):
            canvas = self.storage_canvas
            canvas.delete("all")
            self.storage_segments = []
            self.storage_chart_geometry = None
            self.storage_table.delete(*self.storage_table.get_children())
            if not self.storage_result:
                canvas.create_text(210, 185, text="Analyze a drive to view its storage breakdown",
                                   fill=THEMES["dark" if self.dark.get() else "light"]["fg"],
                                   width=340, justify="center", font=("Segoe UI", 11))
                return

            t = THEMES["dark" if self.dark.get() else "light"]
            canvas.configure(bg=t["bg"])
            categories = self.storage_result["categories"]
            chart_items = [item for item in categories if item["size"] > 0]
            pie_total = sum(item["size"] for item in chart_items)
            if not chart_items or pie_total <= 0:
                canvas.create_text(210, 185, text="No readable file sizes were found on this drive.",
                                   fill=t["fg"], width=340, justify="center")
                return

            cx, cy, radius = 210, 184, 151
            self.storage_chart_geometry = (cx, cy, radius)
            start = 0.0
            for index, item in enumerate(chart_items):
                extent = 360.0 * item["size"] / pie_total
                color = STORAGE_COLORS.get(item["name"], "#888888")
                arc = canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius,
                                        start=start, extent=extent, style=tk.PIESLICE,
                                        fill=color, outline=t["bg"], width=2)
                segment = {"index": index, "start": start, "extent": extent,
                           "item": item, "arc": arc, "share": item["size"] / pie_total}
                self.storage_segments.append(segment)
                start += extent

            canvas.create_text(cx, cy + radius + 24, text=f'Breakdown of {human(pie_total)}',
                               fill=t["fg"], font=("Segoe UI", 9))

            self.storage_table.delete(*self.storage_table.get_children())
            for index, item in enumerate(categories):
                share = (100.0 * item["size"] / pie_total) if pie_total else 0.0
                self.storage_table.insert(
                    "", "end", iid=str(index),
                    values=(item["name"], human(item["size"]), f"{share:.1f}%",
                            f'{item["files"]:,}', f'{item["folders"]:,}'))

            self.storage_selected_index = None
            self.storage_hint.set("Hover over a pie slice for its description and path. Right-click a slice or row to open the location.")

        def _storage_hit(self, x, y):
            if not self.storage_chart_geometry:
                return None
            cx, cy, radius = self.storage_chart_geometry
            dx, dy = x - cx, cy - y
            if math.hypot(dx, dy) > radius:
                return None
            angle = math.degrees(math.atan2(dy, dx)) % 360.0
            for segment in self.storage_segments:
                delta = (angle - segment["start"]) % 360.0
                if delta < segment["extent"] + 0.15:
                    return segment["index"]
            return None

        def _storage_item(self, index):
            if not self.storage_result:
                return None
            items = self.storage_result["categories"]
            return items[index] if index is not None and 0 <= index < len(items) else None

        def _storage_canvas_motion(self, event):
            index = self._storage_hit(event.x, event.y)
            if index is None:
                self._hide_storage_tooltip()
                self.storage_hover_index = None
                return
            self.storage_hover_index = index
            item = self._storage_item(index)
            if item:
                self._show_storage_tooltip(item, event.x_root, event.y_root)

        def _show_storage_tooltip(self, item, x, y):
            t = THEMES["dark" if self.dark.get() else "light"]
            total = sum(segment["item"]["size"] for segment in self.storage_segments)
            share = 100.0 * item["size"] / total if total else 0.0
            text = (f'{item["name"]}\n{human(item["size"])}  ({share:.1f}% of chart)\n'
                    f'Files: {item["files"]:,}   Folders: {item["folders"]:,}\n'
                    f'{item["description"]}\nLocation: {item["path"]}')
            if self.storage_tooltip is None or not self.storage_tooltip.winfo_exists():
                self.storage_tooltip = tk.Toplevel(self)
                self.storage_tooltip.wm_overrideredirect(True)
                self.storage_tooltip.attributes("-topmost", True)
                self.storage_tooltip_label = tk.Label(
                    self.storage_tooltip, justify="left", anchor="w", wraplength=440,
                    bg=t["field"], fg=t["fg"], relief="solid", bd=1,
                    highlightbackground=t["border"], padx=8, pady=6)
                self.storage_tooltip_label.pack()
            self.storage_tooltip_label.configure(text=text)
            self.storage_tooltip.wm_geometry(f"+{x + 16}+{y + 18}")

        def _hide_storage_tooltip(self):
            if self.storage_tooltip is not None:
                try:
                    self.storage_tooltip.destroy()
                except tk.TclError:
                    pass
            self.storage_tooltip = None
            self.storage_tooltip_label = None

        def _storage_table_select(self, _event=None):
            selected = self.storage_table.selection()
            if selected:
                try:
                    self.storage_selected_index = int(selected[0])
                except ValueError:
                    self.storage_selected_index = None

        def _storage_chart_right_click(self, event):
            index = self._storage_hit(event.x, event.y)
            self._show_storage_menu(index, event)

        def _storage_table_right_click(self, event):
            row = self.storage_table.identify_row(event.y)
            if not row:
                return
            self.storage_table.selection_set(row)
            try:
                index = int(row)
            except ValueError:
                return
            self._show_storage_menu(index, event)

        def _show_storage_menu(self, index, event):
            if self._storage_item(index) is None:
                return
            self.storage_selected_index = index
            row = str(index)
            if self.storage_table.exists(row):
                self.storage_table.selection_set(row)
            self.storage_menu.tk_popup(event.x_root, event.y_root)

        def open_storage_location(self):
            item = self._storage_item(self.storage_selected_index)
            if not item:
                return
            path = item.get("path") or self.storage_result["drive"]
            if not os.path.isdir(path):
                path = os.path.dirname(path) or self.storage_result["drive"]
            if not os.path.isdir(path):
                path = self.storage_result["drive"]
            try:
                os.startfile(path)
            except OSError as exc:
                messagebox.showerror("Cannot open location", f"{path}\n\n{exc}")

        def copy_storage_location(self):
            item = self._storage_item(self.storage_selected_index)
            if not item:
                return
            path = item.get("path") or self.storage_result["drive"]
            self.clipboard_clear()
            self.clipboard_append(path)
            self.storage_status.set(f"Copied location: {path}")

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
            Scanner(self.q, mb, days, self.stop,
                    include_system=self.include_system.get() and is_admin()).start()
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
                    elif kind == "storage_progress":
                        self.storage_status.set(val)
                    elif kind == "storage_error":
                        self._set_storage_busy(False)
                        self.storage_status.set(f"Storage scan failed: {val}")
                        messagebox.showerror("Storage analysis failed", str(val))
                    elif kind == "storage_done":
                        self._storage_scan_done(val)
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

        def _cell_text(self, iid, key):
            it = self.items.get(iid)
            if it is None:
                return ""
            if key == "app":
                return software_name(it)             # plain text for the popup
            return str(self.tree.set(iid, key))

        @staticmethod
        def _row(it, checked):
            last = time.strftime("%Y-%m-%d", time.localtime(it.last_used)) if it.last_used else "?"
            path = it.path + (f"  (files older than {it.min_age_days:g} days)" if it.contents_only else "")
            return ("☑" if checked else "☐", path, bold(software_name(it)), human(it.size), last,
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
                "path": lambda i: i.path.lower(), "app": lambda i: software_name(i).lower(), "cat": lambda i: i.category,
                "why": lambda i: i.reason, "risk": lambda i: i.risk,
                "sel": lambda i: i.iid in self.checked,
            }[col]
            ordered = sorted(self.items.values(),
                             key=(lambda i: (i.iid in self.checked)) if col == "sel" else keyf,
                             reverse=desc)
            for idx, it in enumerate(ordered):
                self.tree.move(it.iid, "", idx)

        # ---- excluded folders
        def _apply_exclusions(self, new_list):
            """Activate + save the exclusion list and drop affected rows from the results."""
            self.exclusions = list(new_list)
            set_exclusions(self.exclusions)
            saved = save_exclusions(self.exclusions)
            for iid, it in list(self.items.items()):
                if is_excluded(it.path) or (not it.contents_only and contains_excluded(it.path)):
                    self.tree.delete(iid)
                    self.items.pop(iid)
                    self.checked.discard(iid)
            self._update_summary()
            self.status.set(f"{len(self.exclusions)} excluded folder(s)."
                            + ("" if saved else " Could not save the list - it will be lost when you close the app."))

        def _add_exclusions(self, folders):
            have = {_key(p) for p in self.exclusions}
            new = [os.path.normpath(f) for f in folders if f and _key(f) not in have]
            if new:
                self._apply_exclusions(self.exclusions + new)
            return bool(new)

        def exclude_selected(self):
            folders = []
            for iid in self.tree.selection():
                it = self.items.get(iid)
                if it:
                    folders.append(it.path if it.is_dir else os.path.dirname(it.path))
            if not folders:
                return
            shown = "\n".join(folders[:6]) + (f"\n… and {len(folders) - 6} more" if len(folders) > 6 else "")
            if messagebox.askyesno("Exclude folders",
                                   f"Never scan or delete these folders again?\n\n{shown}"):
                self._add_exclusions(folders)

        def manage_exclusions(self):
            t = THEMES["dark" if self.dark.get() else "light"]
            win = tk.Toplevel(self)
            win.title("Excluded folders")
            win.geometry("640x340")
            win.configure(bg=t["bg"])
            win.transient(self)
            ttk.Label(win, text="These folders (and everything inside them) are never scanned, listed or deleted.",
                      padding=8).pack(anchor="w")
            body = ttk.Frame(win, padding=(8, 0))
            body.pack(fill="both", expand=True)
            lb = tk.Listbox(body, selectmode="extended", activestyle="none", bg=t["field"], fg=t["fg"],
                            selectbackground=t["sel"], selectforeground=t["sel_fg"],
                            highlightthickness=1, highlightbackground=t["border"], relief="flat")
            sb = ttk.Scrollbar(body, orient="vertical", command=lb.yview)
            lb.configure(yscrollcommand=sb.set)
            lb.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")

            def refresh():
                lb.delete(0, "end")
                for p in self.exclusions:
                    lb.insert("end", p)

            def add():
                folder = filedialog.askdirectory(parent=win, title="Folder to exclude", mustexist=True)
                if folder and self._add_exclusions([folder]):
                    refresh()

            def remove():
                drop = {self.exclusions[i] for i in lb.curselection()}
                if drop:
                    self._apply_exclusions([p for p in self.exclusions if p not in drop])
                    refresh()

            btns = ttk.Frame(win, padding=8)
            btns.pack(fill="x")
            ttk.Button(btns, text="Add folder…", command=add).pack(side="left")
            ttk.Button(btns, text="Remove selected", command=remove).pack(side="left", padx=6)
            ttk.Button(btns, text="Close", command=win.destroy).pack(side="right")
            refresh()

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
            if any(i.system for i in chosen):
                lines += ["", "ADMIN: system items are deleted permanently (not restorable). Windows "
                              "Update and BITS services are paused briefly and restarted afterwards."]
            if not messagebox.askyesno("Smart clean" if smart else "Confirm delete",
                                       "\n".join(lines), icon="warning"):
                return
            if any(i.system and not i.contents_only for i in chosen) and not messagebox.askyesno(
                    "Delete Windows.old?",
                    "Windows.old holds your previous Windows installation.\n\n"
                    "Once it is deleted you can no longer go back to the previous version of "
                    "Windows, and the deletion cannot be undone.\n\nDelete Windows.old anyway?",
                    icon="warning", default="no"):
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
