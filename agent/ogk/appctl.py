"""F2: kiểm soát ứng dụng – đối chiếu SHA-256 (đổi tên tệp vẫn bị nhận), kết thúc + giải thích."""
import hashlib
import os
import time

PROTECTED = ("c:\\windows", "c:\\program files\\windowsapps", "c:\\programdata", "/usr/", "/bin/", "/sbin/",
             "/lib", "/opt/", "/system", "/proc")


def default_procs():
    import psutil
    for p in psutil.process_iter(["pid", "name", "exe"]):
        i = p.info
        yield {"pid": i["pid"], "name": i["name"] or "", "exe": i["exe"] or ""}


def default_kill(pid):
    import psutil
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(1.5)
        except psutil.TimeoutExpired:
            p.kill()
    except psutil.Error:
        pass


class AppController:
    def __init__(self, get_policy, emit, notify, procs=default_procs, visible=lambda: None,
                 kill=default_kill, protected=PROTECTED, self_pid=None, mono=time.monotonic):
        self.get_policy, self.emit, self.notify = get_policy, emit, notify
        self.procs, self.visible, self.kill, self.protected = procs, visible, kill, protected
        self.self_pid = self_pid or os.getpid()
        self.mono, self.running, self._hash, self._last_block = mono, {}, {}, {}

    def sha256(self, exe: str) -> str:
        try:
            st = os.stat(exe)
            key = (exe, st.st_size, st.st_mtime)
            if key not in self._hash:
                h = hashlib.sha256()
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                self._hash[key] = h.hexdigest()
            return self._hash[key]
        except OSError:
            return ""

    @staticmethod
    def match(rules, name, sha):
        verdict = None
        for r in rules:
            hit = (r.get("sha256") and sha and r["sha256"].lower() == sha) or \
                  (not r.get("sha256") and r.get("name") and r["name"].lower() == name.lower())
            if hit:
                if r["action"] == "block":
                    return "block", r
                verdict = ("allow", r)
        return verdict or (None, None)

    def _user_app(self, p, visible):
        exe = (p["exe"] or "").lower()
        if not exe or p["pid"] == self.self_pid or any(exe.startswith(x) for x in self.protected):
            return False
        return visible is None or p["pid"] in visible

    def scan(self):
        pol = self.get_policy()
        if not pol:
            return
        rules, mode, who = pol.get("app_rules", []), pol.get("app_mode", "blocklist"), pol.get("set_by", "")
        visible, seen = self.visible(), {}
        for p in list(self.procs()):
            name, sha = p["name"], (self.sha256(p["exe"]) if p["exe"] else "")
            verdict, rule = self.match(rules, name, sha)
            eligible = self._user_app(p, visible)
            reason = None
            if verdict == "block":
                reason, who_ = f"Ứng dụng {name} nằm trong danh sách bị chặn", rule.get("set_by") or who
            elif verdict is None and mode == "allowlist" and eligible:
                reason, who_ = f"{name} không nằm trong danh sách ứng dụng được phép", who
            if reason:
                self.kill(p["pid"])
                if self.mono() - self._last_block.get(name, -99) > 30:  # tránh spam thông báo
                    self._last_block[name] = self.mono()
                    self.emit("blocked_app", name, 0)
                    self.notify("app", "Ứng dụng đã bị đóng", reason, who_)
                continue
            if eligible:
                seen[name] = p["pid"]
        now = self.mono()
        for name in seen.keys() - self.running.keys():
            self.running[name] = now
            self.emit("app_start", name, 0)
        for name in list(self.running.keys() - seen.keys()):
            self.emit("app_stop", name, now - self.running.pop(name))
