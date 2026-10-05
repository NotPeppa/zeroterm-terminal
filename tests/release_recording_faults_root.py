#!/usr/bin/env python3
"""Root management only: one bounded loop/ext4 and an independent thaw watchdog."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

CAPACITY = 512 * 1024 * 1024


def command(argv, seconds=5, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=seconds, env={**os.environ, "LC_ALL": "C"})


def verify(identity):
    root = Path(identity["root"])
    assert re.fullmatch(r"/var/tmp/bastion-record-fault-[0-9a-f]{32}", str(root))
    assert root.resolve() == root and root.stat().st_ino == identity["root_inode"]
    target = root / "recording-mount"
    image = root / "control/recording512.img"
    assert target == Path(identity["mountpoint"]) and image == Path(identity["image"])
    assert not image.is_symlink() and image.stat().st_uid == 0 and image.stat().st_size == CAPACITY
    assert image.stat().st_ino == identity["image_inode"] and image.stat().st_nlink == 1
    loop = identity["loop_device"]
    assert re.fullmatch(r"/dev/loop[0-9]+", loop) and stat.S_ISBLK(os.stat(loop).st_mode)
    info = json.loads(command(["/usr/sbin/losetup", "--json", "--list", "--output", "NAME,BACK-FILE,OFFSET,SIZELIMIT", loop]).stdout)["loopdevices"]
    assert len(info) == 1 and info[0]["name"] == loop and info[0]["back-file"] == str(image)
    assert int(info[0]["offset"]) == 0 and int(info[0]["sizelimit"]) in (0, CAPACITY)
    assert int((Path("/sys/class/block") / Path(loop).name / "size").read_text()) * 512 == CAPACITY
    mounts = json.loads(command(["/usr/bin/findmnt", "--json", "--nocanonicalize", "--mountpoint", str(target), "--output", "SOURCE,TARGET,FSTYPE,OPTIONS"]).stdout)["filesystems"]
    assert len(mounts) == 1 and mounts[0]["source"] == loop and mounts[0]["target"] == str(target) and mounts[0]["fstype"] == "ext4"
    assert {"nodev", "nosuid", "noexec"}.issubset(set(mounts[0]["options"].split(",")))
    return mounts[0]


def write_public(path, value):
    path.write_text(json.dumps(value) + "\n")
    path.chmod(0o600); os.chown(path, 1000, 1000)


def thaw(identity):
    verify(identity)
    result = command(["/usr/sbin/fsfreeze", "--unfreeze", identity["mountpoint"]], seconds=2, check=False)
    # EINVAL means already thawed, not an arbitrary failed target.
    assert result.returncode == 0 or "Invalid argument" in result.stderr
    return result.returncode


def watchdog(identity):
    assert os.geteuid() == 0
    verify(identity)
    root = Path(identity["root"]); control = root / "control"
    armed = time.monotonic(); deadline = armed + 7.5
    (control / "watchdog.ready").write_text(str(os.getpid()))
    triggered = False
    while time.monotonic() < deadline:
        if not triggered and (control / "freeze.ok").exists():
            # Leave half a second for identity checks + unfreeze inside the eight-second budget.
            deadline = min(armed + 8, time.monotonic() + 7.5); triggered = True
        time.sleep(0.01)
    code = thaw(identity)
    write_public(root / "thaw.done", {"watchdog_pid": os.getpid(), "returncode": code, "armed_elapsed_seconds": round(time.monotonic() - armed, 6), "budget_seconds": 8})
    (control / "watchdog.result.json").write_text(json.dumps({"pid": os.getpid(), "returncode": code, "armed_elapsed_seconds": round(time.monotonic() - armed, 6)}) + "\n")


def run(args):
    assert os.geteuid() == 0
    os.umask(0o077)
    root = args.root.resolve()
    assert re.fullmatch(r"/var/tmp/bastion-record-fault-[0-9a-f]{32}", str(root)) and root == args.root
    assert root.stat().st_uid == 1000 and root.stat().st_mode & 0o777 == 0o700
    assert args.source.resolve() == root / "source-candidate" and args.server.resolve().is_relative_to(args.source.resolve())
    assert hashlib.sha256(args.server.read_bytes()).hexdigest() == args.binary_sha
    control = root / "control"; control.mkdir(mode=0o700)
    image = control / "recording512.img"
    target = root / "recording-mount"; target.mkdir(mode=0o700)
    assert shutil.disk_usage(root).free >= 2 * 1024 * 1024 * 1024
    with image.open("xb") as f:
        os.posix_fallocate(f.fileno(), 0, CAPACITY); f.flush(); os.fsync(f.fileno())
    image.chmod(0o600)
    command(["/usr/sbin/mkfs.ext4", "-F", "-q", "-m", "0", str(image)], seconds=60)
    loop = None; mounted = False; identity = None; peer = None; guard = None
    stages = []
    def event(phase, **data):
        row = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "phase": phase, **data}
        stages.append(row); print(json.dumps(row), flush=True)
        write_public(root / "management-evidence.json", stages)
    try:
        loop = command(["/usr/sbin/losetup", "--find", "--show", "--nooverlap", str(image)]).stdout.strip()
        assert re.fullmatch(r"/dev/loop[0-9]+", loop)
        identity = {"root": str(root), "root_inode": root.stat().st_ino, "image": str(image), "image_inode": image.stat().st_ino, "loop_device": loop, "mountpoint": str(target), "management_pid": os.getpid(), "image_bytes": CAPACITY}
        command(["/usr/bin/mount", "-t", "ext4", "-o", "nodev,nosuid,noexec", loop, str(target)])
        mounted = True; os.chown(target, 1000, 1000); target.chmod(0o700)
        verify(identity)
        assert shutil.disk_usage(target).free > 256 * 1024 * 1024
        event("loop-mount", status="verified", management_uid=os.geteuid(), **identity, initial_free_bytes=shutil.disk_usage(target).free, mount_options="nodev,nosuid,noexec")
        fixture = root / "fixture"; fixture.mkdir(mode=0o700); os.chown(fixture, 1000, 1000)
        log = (control / "driver.log").open("wb")
        environment = os.environ.copy(); environment["PATH"] = "/home/bastion-acceptance/.cargo/bin:/usr/sbin:/usr/bin:/bin"
        peer = subprocess.Popen(["/usr/sbin/runuser", "-u", "bastion-acceptance", "--", sys.executable, str(args.source / "tests/release_recording_faults.py"), "--root", str(fixture), "--manager", str(root), "--source", str(args.source), "--helpers", str(args.helpers), "--records", str(target), "--server", str(args.server), "--binary-sha", args.binary_sha], stdout=log, stderr=log, env=environment)
        event("nonroot-driver-launch", status="observed", runuser_wrapper_pid=peer.pid)
        until = time.monotonic() + 240
        while not (root / "freeze.request").exists() and peer.poll() is None:
            if time.monotonic() >= until: raise RuntimeError("driver did not reach freeze request")
            time.sleep(0.05)
        if peer.poll() is not None:
            event("driver-result", status="observed", exit_code=peer.returncode, freeze_requested=False)
            return peer.returncode
        request = json.loads((root / "freeze.request").read_text())
        driver_pid = int(request["driver_pid"]); gateway_pid = int(request["gateway_pid"])
        for pid in (driver_pid, gateway_pid):
            status = Path(f"/proc/{pid}/status").read_text()
            assert re.search(r"^Uid:\s+1000\s+1000\s+1000\s+1000$", status, re.M)
        parent = gateway_pid
        for _ in range(10):
            if parent == peer.pid: break
            parent = int(re.search(r"^PPid:\s+(\d+)$", Path(f"/proc/{parent}/status").read_text(), re.M)[1])
        assert parent == peer.pid
        assert Path(f"/proc/{gateway_pid}/exe").resolve() == args.server.resolve()
        assert Path(f"/proc/{os.getpid()}").exists()
        verify(identity)
        # Detached root child executes an already-open root-owned copy, not a mutable user path.
        script = control / "watchdog.py"; script.write_bytes(Path(__file__).read_bytes()); script.chmod(0o600)
        script_fd = os.open(script, os.O_RDONLY | os.O_NOFOLLOW)
        guard_log = (control / "watchdog.log").open("wb")
        guard = subprocess.Popen([sys.executable, "-I", f"/proc/self/fd/{script_fd}", "--watchdog-identity", json.dumps(identity)], pass_fds=(script_fd,), stdout=guard_log, stderr=guard_log, start_new_session=True)
        os.close(script_fd)
        until = time.monotonic() + 2
        while not (control / "watchdog.ready").exists():
            assert guard.poll() is None
            if time.monotonic() >= until: raise RuntimeError("independent thaw watchdog not ready")
            time.sleep(0.01)
        assert int((control / "watchdog.ready").read_text()) == guard.pid
        verify(identity)
        started = time.monotonic()
        command(["/usr/sbin/fsfreeze", "--freeze", str(target)], seconds=3)
        (control / "freeze.ok").write_text(str(time.monotonic()))
        write_public(root / "freeze.ready", {"management_pid": os.getpid(), "watchdog_pid": guard.pid, "verified_loop": loop, "freeze_succeeded": True})
        event("verified-freeze", status="observed", driver_pid=driver_pid, gateway_pid=gateway_pid, watchdog_pid=guard.pid, freeze_command_seconds=round(time.monotonic()-started, 6), planned_thaw_budget_seconds=8)
        time.sleep(1)
        wait_channels = []
        for path in Path(f"/proc/{gateway_pid}/task").glob("*/wchan"):
            with path.open() as f: value = f.read().strip()
            if "sb_start_write" in value or "freeze" in value or "percpu" in value: wait_channels.append({"tid": int(path.parent.name), "wchan": value})
        event("blocked-kernel-write", status="observed", own_gateway_pid=gateway_pid, matching_task_wait_channels=wait_channels)
        guard.wait(timeout=10)
        assert guard.returncode == 0 and (root / "thaw.done").exists()
        event("watchdog-thaw", status="verified", **json.loads((root / "thaw.done").read_text()))
        peer.wait(timeout=45); log.close(); guard_log.close()
        event("driver-result", status="observed", exit_code=peer.returncode, freeze_requested=True)
        return peer.returncode
    except Exception as error:
        event("management-failure", status="fail", exception=type(error).__name__)
        return 1
    finally:
        # Thaw first, including controller exceptions. No unrelated device or forced unmount.
        if mounted:
            try:
                code = thaw(identity)
                if not (root / "thaw.done").exists(): write_public(root / "thaw.done", {"management_pid": os.getpid(), "returncode": code, "fallback": True})
            except Exception as error:
                event("cleanup-thaw-failure", status="fail", exception=type(error).__name__)
        if peer is not None and peer.poll() is None:
            try: peer.wait(timeout=35)
            except subprocess.TimeoutExpired:
                # Only this wrapper; descendant processes are recorded by the driver.
                peer.terminate(); peer.wait(timeout=5)
        if guard is not None and guard.poll() is None: guard.wait(timeout=10)
        if mounted:
            verify(identity)
            command(["/usr/bin/umount", str(target)], seconds=10)
            mounted = False
            event("own-unmount", status="verified", exact_target=str(target), loop_device=loop)
        if loop:
            # Do not detach a reused loop: its backing file must still be this exact image.
            info = json.loads(command(["/usr/sbin/losetup", "--json", "--list", "--output", "NAME,BACK-FILE", loop]).stdout)["loopdevices"]
            assert len(info) == 1 and info[0]["back-file"] == str(image)
            command(["/usr/sbin/losetup", "--detach", loop])
            event("own-loop-detach", status="verified", loop_device=loop, backing_file=str(image))
        assert image.resolve() == root / "control/recording512.img" and image.stat().st_uid == 0 and image.stat().st_size == CAPACITY
        image.unlink()
        event("bounded-image-remove", status="verified", image_bytes=CAPACITY, exact_image=str(image), driver_wrapper_alive=bool(peer is not None and peer.poll() is None), watchdog_alive=bool(guard is not None and guard.poll() is None))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watchdog-identity")
    for name in ("root", "source", "helpers", "server"): parser.add_argument("--" + name, type=Path)
    parser.add_argument("--binary-sha")
    args = parser.parse_args()
    if args.watchdog_identity: watchdog(json.loads(args.watchdog_identity))
    else: raise SystemExit(run(args))
