"""Exercise native Linux CPU admission on a dedicated VM against a SoduWork checkout."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time


class CheckFailed(Exception):
    """Messages use fixed diagnostic codes safe for the published report."""


def check(value, code):
    if not value:
        raise CheckFailed(code)


def burn_cpu(core):
    # Never allocate pressure memory. Stop after parent loss or bounded wall time.
    parent = os.getppid()
    signal.alarm(120)
    os.nice(10)
    os.sched_setaffinity(0, {int(core)})
    end = time.monotonic() + 115
    data = b"x" * 32768
    while time.monotonic() < end and os.getppid() == parent:
        for _ in range(256):
            hashlib.sha256(data).digest()


def stop_load(children):
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(5)


def proc_identity(entry):
    """Return PPid and start time (field 22), accounting for ')' inside comm."""
    fields = (entry/"stat").read_text(encoding="utf-8", errors="replace").rsplit(") ",1)[1].split()
    return int(fields[1]), int(fields[19])


class PiObserver:
    def __init__(self, node, cli, work, runner_pid, work_by_task):
        self.node = str(node)
        self.cli = os.fsencode(cli)
        self.work = work
        self.runner_key = (runner_pid, proc_identity(Path("/proc")/str(runner_pid))[1])
        self.task_dirs = work_by_task
        self.argv_seen = {}

    def runner_ancestor(self, parent):
        visited = set()
        while parent > 1 and parent not in visited:
            visited.add(parent)
            grandparent, start = proc_identity(Path("/proc")/str(parent))
            if (parent, start) == self.runner_key:
                return True
            parent = grandparent
        return False

    def sample(self):
        """Use executable + PID birth time + cwd across Pi's process.title rename."""
        live = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                if os.readlink(entry/"exe") != self.node:
                    continue
                parent, birth = proc_identity(entry)
                key = (int(entry.name),birth)
                cwd = Path(os.readlink(entry/"cwd"))
                if cwd == self.work or not cwd.is_relative_to(self.work):
                    continue
                argv = [a for a in (entry/"cmdline").read_bytes().split(bytes([0])) if a]
                if self.cli in argv and b"--version" not in argv and self.runner_ancestor(parent):
                    match = "exactCliArgv"
                elif self.argv_seen.get(key)==cwd:
                    match = "samePidStarttimeAndCwd"
                elif (len(argv)==1 and argv[0].lower() in (b"pi",b"pi-rpc")
                      and (entry/"comm").read_bytes().strip().lower() in (b"pi",b"pi-rpc")
                      and cwd in self.task_dirs.values() and self.runner_ancestor(parent)):
                    match = "piTitleVerifiedRunnerAncestorAndWorkspace"
                else:
                    continue
                # A process may exit or exec while scanning. Revalidate immutable
                # identity and links before retaining this specific observation.
                if (proc_identity(entry)[1]!=birth or os.readlink(entry/"exe")!=self.node
                        or os.readlink(entry/"cwd")!=str(cwd)):
                    continue
                if match=="exactCliArgv":
                    self.argv_seen[key] = cwd
                live[key] = (cwd,match)
            except (OSError, ValueError, IndexError):
                continue
        return live

    async def watch(self):
        while True:
            self.sample()
            await asyncio.sleep(.04)


async def host_samples(report):
    def ticks():
        with open("/proc/stat", encoding="ascii") as source:
            values = [int(v) for v in source.readline().split()[1:9]]
        return (sum(values), values[3]+values[4])
    previous = ticks()
    traces = report.data.setdefault("hostProc", {})
    while True:
        await asyncio.sleep(.5)
        current = ticks()
        total = current[0]-previous[0]
        idle = current[1]-previous[1]
        previous = current
        if total <= 0:
            continue
        percent = round(100.0 * (1 - idle / total), 2)
        with open("/proc/meminfo", encoding="ascii") as source:
            info = {v[0]:int(v[1]) for v in (line.split() for line in source)
                    if v[0] in ("MemTotal:", "MemAvailable:")}
        available = round(info["MemAvailable:"]/1024, 1)
        label = report.data["stage"]
        item = traces.setdefault(label, {"samples":0, "cpuPercentRange":[percent,percent],
                                         "availableMiBRange":[available,available]})
        item["samples"] += 1
        for key, value in (("cpuPercentRange",percent),("availableMiBRange",available)):
            item[key][0] = min(item[key][0],value)
            item[key][1] = max(item[key][1],value)
        item["lastAt"] = report.elapsed()


class Report:
    def __init__(self, target):
        self.target = target
        self.started = time.monotonic()
        self.data = {"schemaVersion": 1, "passed": False, "stage": "setup",
                     "thresholdOverrides": False, "samplerOverrides": False,
                     "platform": platform.system(), "architecture": platform.machine(),
                     "python": platform.python_version(), "wire": [], "api": {},
                     "checks": {}, "modelRequests": []}

    def elapsed(self):
        return round(time.monotonic() - self.started, 3)

    def stage(self, name):
        self.data["stage"] = name
        self.save()
        print(f"native-pressure: {name}", flush=True)

    def save(self):
        self.target.parent.mkdir(parents=True, exist_ok=True)
        temp = self.target.with_suffix(".tmp")
        temp.write_text(json.dumps(self.data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        temp.replace(self.target)


def fixture_env(root, scope, source):
    keys = {"PATH", "LANG", "LC_ALL", "TZ", "LD_LIBRARY_PATH", "SSL_CERT_FILE", "TMPDIR"}
    env = {k: v for k, v in source.items() if k in keys}
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
               NO_PROXY="*", no_proxy="*", DATABASE_URL="sqlite+aiosqlite:///:memory:",
               AUTH_SECRET=secrets.token_hex(32))
    for k, leaf in {"HOME":"home","XDG_CONFIG_HOME":"config","XDG_CACHE_HOME":"cache",
                    "XDG_DATA_HOME":"share","SODUWORK_DATA_ROOT":"data","CODEX_HOME":"codex",
                    "PI_CODING_AGENT_DIR":"pi","SODUWORK_SKILL_ROOTS":"skills"}.items():
        path = root / scope / leaf
        path.mkdir(parents=True, exist_ok=True)
        env[k] = str(path)
    return env


async def until(test, duration, code):
    end = time.monotonic() + duration
    while time.monotonic() < end:
        result = await test()
        if result:
            return result
        await asyncio.sleep(.32)
    raise CheckFailed(code)


async def run(args, root, report):
    import httpx
    import uvicorn
    from fastapi import Request
    from fastapi.responses import StreamingResponse

    repository = args.repo.resolve(strict=True)
    backend = repository / "hub-backend"
    node = Path(args.node or shutil.which("node") or "node").resolve(strict=True)
    if args.pi_cli:
        cli = args.pi_cli.resolve(strict=True)
    else:
        package = repository / "client/node_modules/@earendil-works/pi-coding-agent"
        package_bin = json.loads((package/"package.json").read_text(encoding="utf-8"))["bin"]["pi"]
        cli = (package/package_bin).resolve(strict=True)
    version = subprocess.check_output([str(node), "--version"], text=True).strip()
    pi_package = next((p / "package.json" for p in cli.parents if p.name == "pi-coding-agent"), None)
    check(pi_package is not None, "pi_package_metadata_missing")
    pi_version = json.loads(pi_package.read_text(encoding="utf-8"))["version"]
    commit = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
    check(re.fullmatch(r"[a-f0-9]{40,64}", commit), "invalid_source_identity")
    check(re.fullmatch(r"v\d+\.\d+\.\d+", version), "invalid_node_version")
    check(pi_version == "1.4.0", "unexpected_pi_version")
    cores = sorted(os.sched_getaffinity(0))
    report.data.update(sourceCommit=commit, node=version, pi=pi_version, cpuCount=os.cpu_count(),
                       availableCpus=len(cores), modelFixture="loopback OpenAI-compatible SSE, fixed 5 s per response")
    check(len(cores) == os.cpu_count(), "shared_or_cpu_restricted_environment")
    source = os.environ.copy()
    os.chdir(root)
    os.environ.clear()
    os.environ.update(fixture_env(root, "hub", source))
    password = secrets.token_urlsafe(32)
    dbfile = root / "test.sqlite3"
    os.environ.update(ADMIN_PASS=password, DATABASE_URL="sqlite+aiosqlite:///" + dbfile.as_posix(),
                      REPORT_AUTO="false", REPOSITORY_SYNC_INTERVAL_SECONDS="0",
                      HUB_LOCAL_EXECUTION_ENABLED="false", DB_MIGRATION_MODE="auto",
                      MINIO_ENDPOINT="", CLUSTER_REDIS_URL="", REDIS_URL="")
    sys.path.insert(0, str(backend))
    from app import db, models
    from app.services import device_auth, dispatch_identity, storage
    from app.main import app
    storage._LOCAL_DIR = str(root / "objects")
    work = root / "work"
    work.mkdir()
    work_by_task = {}
    evidence_by_request = []
    observer = None
    observing = None
    tasks = []
    attempts = []
    labels = ("A", "B")
    model = "native-531-fixture"
    identity = "verify-" + secrets.token_hex(5)
    device_id = "device-" + identity
    secret = secrets.token_hex(32)

    @app.post("/fixture/v1/chat/completions")
    async def model_response(request: Request):
        body = await request.json()
        check(body.get("model") == model, "unexpected_model_route")
        messages = body.get("messages", [])
        text = json.dumps(messages, ensure_ascii=True)
        hits = [tag for tag in labels if "NATIVE531_TASK_" + tag in text]
        check(len(hits) == 1, "model_task_marker_mismatch")
        tag = hits[0]
        tool_done = any(m.get("role") == "tool" for m in messages)
        current = observer.sample() if observer is not None else {}
        evidence_by_request.append((tag,current))
        report.data["modelRequests"].append({"task":tag,"afterTool":tool_done,"at":report.elapsed(),
                                             "observedPiCount":len(current)})
        await asyncio.sleep(5)
        if tool_done:
            delta = {"role":"assistant","content":"Delivery complete."}
            finish = "stop"
        else:
            arguments = json.dumps({"path":"dispatch-result.txt", "content":"NATIVE531_DONE_" + tag})
            delta = {"role":"assistant","tool_calls":[{"index":0,"id":"write-" + tag,"type":"function",
                     "function":{"name":"write","arguments":arguments}}]}
            finish = "tool_calls"
        packets = []
        for content, ending in [(delta, None), ({}, finish)]:
            packets.append("data: " + json.dumps({"id":"fixture","object":"chat.completion.chunk","created":1,
                   "model":model,"choices":[{"index":0,"delta":content,"finish_reason":ending}]}) + "\n\n")
        return StreamingResponse(iter(packets + ["data: [DONE]\n\n"]), media_type="text/event-stream")

    async def wire(scope, receive, send):
        if scope["type"] != "websocket":
            return await app(scope, receive, send)
        async def read():
            event = await receive()
            if event.get("text"):
                packet = json.loads(event["text"])
                if packet.get("op") in ("hello", "beat"):
                    keys = ("op","cpuPercent","memoryPercent","memoryAvailableBytes","adaptiveLimit",
                            "resourcePressure","resourceStartAllowed","queueDepth","busy")
                    sample = {k:packet.get(k) for k in keys}
                    sample["at"] = report.elapsed()
                    report.data["wire"].append(sample)
            return event
        return await app(scope, read, send)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    base = "http://127.0.0.1:" + str(sock.getsockname()[1])
    server = uvicorn.Server(uvicorn.Config(wire, log_level="warning", access_log=False))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    runner = None
    loads = []
    log = (root / "runner.log").open("wb")
    host_task = asyncio.create_task(host_samples(report))

    try:
        async def started():
            if serving.done():
                await serving
                raise CheckFailed("hub_exited_before_start")
            return server.started
        await until(started, 90, "hub_start_timeout")
        async with db.SessionLocal() as s:
            user = models.User(id="fixture-user",username="fixture-user",org_id="fixture-org",is_active=True)
            client = models.Client(id=device_id,name="CPU admission fixture",work_root=str(work))
            client.secret_hash = device_auth.hash_secret(secret)
            device_auth.activate(client, user)
            provider = models.ModelProvider(id="fixture-provider",name="Local fixture",kind="openai-compat",
                       base_url=base+"/fixture/v1",api_key="fixture-local",enabled=True)
            definition = models.ModelDef(id="fixture-provider:"+model,provider_id=provider.id,name=model,label=model,enabled=True)
            s.add_all([models.OrgUnit(id="fixture-org",name="Test"),user,client,provider,definition])
            await s.commit()
            credential = device_auth.issue_session(client)[0]

        renv = fixture_env(root, "runner", source)
        renv.update(SODUWORK_DEVICE_SECRET=secret, SODUWORK_BUNDLED_PI_CLI=str(cli),
                    SODUWORK_BUNDLED_NODE=str(node), PATH=str(node.parent)+os.pathsep+renv["PATH"])
        runner = await asyncio.create_subprocess_exec(sys.executable, str(backend/"runner_main.py"),
                 "--config-stdin","--id",identity,"--max-concurrent","1",env=renv,cwd=root,
                 stdin=asyncio.subprocess.PIPE,stdout=log,stderr=log, start_new_session=True)
        conf = dict(hub=base, clientId=device_id, dataRoot=renv["SODUWORK_DATA_ROOT"], workRoot=str(work),
                    tags=["soduwork-client"],capabilityGrants=[])
        runner.stdin.write(("@@SODUWORK_RUNNER_CONFIG@@"+json.dumps(conf)+"\n").encode())
        await runner.stdin.drain()
        headers = {"Authorization":"Device "+credential,"X-Soduwork-Device":device_id}
        async with httpx.AsyncClient(base_url=base, headers=headers, timeout=25, trust_env=False) as api:
            async def req(method, path, **kwargs):
                res = await api.request(method, path, **kwargs)
                if not res.is_success:
                    report.data["lastHttpFailure"] = {"method":method, "route":path.rsplit("/",1)[-1],
                                                       "status":res.status_code}
                    raise CheckFailed("http_request_failed")
                return res.json()
            admin = await req("POST","/api/v1/admin/login",json={"user":"admin","pass":password})
            admin_headers = {"Authorization":"Bearer "+admin["token"]}
            readiness = await req("GET","/readyz")
            check(all(readiness.get(k) is True for k in ("ready","database","cluster")), "hub_not_ready")

            async def discovered():
                check(runner.returncode is None, "runner_exited")
                agents = (await req("GET","/api/v1/ai-agents"))["agents"]
                return next((a for a in agents if a.get("id")=="runner:"+identity+":pi"), None)
            pi = await until(discovered, 90, "pi_inventory_timeout")

            async def sample_after(index, predicate):
                for i, sample in enumerate(report.data["wire"][index:], index):
                    if sample["op"] == "beat" and predicate(sample):
                        return i + 1, sample
            def healthy(s):
                return s["resourceStartAllowed"] is True and s["resourcePressure"] != "critical" and s["cpuPercent"] < 95
            def hot(s):
                return (s["resourceStartAllowed"] is False and s["resourcePressure"]=="critical" and
                        s["cpuPercent"]>=95 and s["memoryPercent"]<92 and s["memoryAvailableBytes"]>=805306368)
            report.stage("native_idle")
            _, idle = await until(lambda: sample_after(0, healthy), 65, "idle_heartbeat_not_observed")
            report.data["checks"]["initialHealthyHeartbeat"] = True
            for tag in labels:
                task = await req("POST","/api/v1/tasks",json=dict(title="NATIVE531_TASK_"+tag,
                         note="NATIVE531_TASK_"+tag+" write dispatch-result.txt",acceptanceCriteria=["File exists"]))
                tasks.append(task["id"])
            check(len(set(tasks)) == 2, "duplicate_task_ids")
            initial_index = len(report.data["wire"])
            report.stage("applying_cpu_load")
            for core in cores:
                loads.append(subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), "--burn-cpu", str(core)],
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            await until(lambda: sample_after(initial_index, hot), 65, "cpu_critical_heartbeat_not_observed")
            report.data["checks"]["nativeCpuCriticalWithoutMemoryPressure"] = True
            report.stage("dispatch_under_pressure")
            for tag, tid in zip(labels, tasks):
                d = await req("POST","/api/v1/tasks/"+tid+"/ai-dispatch",json=dict(assigneeId=pi["id"],
                       assigneeType="agent",brief="NATIVE531_TASK_"+tag+" write dispatch-result.txt",model=model,
                       executionContext=dict(strategy="direct",agent=dict(id="local:pi"))))
                check(d.get("ok") is True and bool(d.get("dispatchId")),"dispatch_ack_missing")
                attempts.append(d["dispatchId"])
                check(d.get("state")=="queued" and d.get("queuePosition")==len(attempts),"dispatch_receipt_mismatch")
            check(len(set(attempts))==2, "duplicate_dispatch_ids")

            async def observe(stage, predicate):
                batch = []
                for tag, tid in zip(labels,tasks):
                    detail = await req("GET","/api/v1/tasks/"+tid+"/ai-status")
                    client = detail.get("runner") or {}
                    admin_view = await req("GET","/api/v1/admin/tasks/"+tid+"/ai-status",headers=admin_headers)
                    p = client.get("workDirAbs")
                    if p:
                        work_by_task[tag] = Path(p).resolve()
                    batch.append({"task":tag,"deviceState":client.get("taskStatus"),"deviceReason":client.get("waitReason"),
                                  "deviceHasReason":"waitReason" in client,"devicePosition":client.get("queuePosition"),
                                  "adminState":admin_view.get("taskStatus") or admin_view.get("status"),
                                  "adminReason":admin_view.get("waitReason"),"adminHasReason":"waitReason" in admin_view,
                                  "adminPosition":admin_view.get("queuePosition")})
                report.data["api"][stage] = {"at":report.elapsed(),"tasks":batch}
                check(not any(t["deviceState"] in ("failed","error","cancelled") for t in batch), "task_execution_failed")
                return batch if predicate(batch) else None
            def state(t, status, reason=None):
                return (t["deviceState"]==t["adminState"]==status and t["deviceReason"]==t["adminReason"]==reason and
                        (reason is not None or not (t["deviceHasReason"] or t["adminHasReason"])))
            def pressured(batch):
                return all(state(t,"queued","resource_pressure") and t["devicePosition"]==t["adminPosition"]==pos
                           for pos,t in enumerate(batch,1))
            def slotted(batch):
                return (state(batch[0],"running") and state(batch[1],"queued","execution_slot") and
                        batch[1]["devicePosition"]==batch[1]["adminPosition"]==1)
            await until(lambda:observe("pressure",pressured),20,"queue_pressure_reasons_missing")
            hold_index = len(report.data["wire"])
            _, held = await until(lambda:sample_after(hold_index,lambda x: hot(x) and (x.get("queueDepth") or 0)>=2),
                                  37,"queued_depth_two_critical_heartbeat_missing")
            report.data["queuedCriticalHeartbeatAt"] = held["at"]
            await until(lambda:observe("pressureRetained",pressured),6,"pressure_reasons_not_retained")
            report.data["checks"]["bothTasksRetainedUntilNextCriticalHeartbeat"] = True
            check(not report.data["modelRequests"] and not any(work.rglob("dispatch-result.txt")),
                  "work_started_while_critical")
            check(all(p.poll() is None for p in loads), "cpu_load_expired_before_release")
            report.data["checks"]["pressureQueuedBothApis"] = True
            report.stage("removing_cpu_load")
            observer = PiObserver(node, cli, work, runner.pid, work_by_task)
            observing = asyncio.create_task(observer.watch())
            await asyncio.sleep(0)
            stop_load(loads)
            report.data["loadReleasedAt"] = report.elapsed()
            release_index = len(report.data["wire"])
            report.data["pressureWorkersReaped"] = sum(p.poll() is not None for p in loads)
            report.stage("slot_after_native_recovery")
            await until(lambda:observe("slot", slotted),35,"slot_transition_missing")
            report.data["checks"]["realOccupiedSlotBothApis"] = True
            await until(lambda:observe("complete",lambda z:all(state(t,"done") for t in z)),110,"task_completion_timeout")
            report.data["checks"]["terminalReasonsAbsentBothApis"] = True
            await until(lambda:sample_after(release_index,healthy),50,"recovery_heartbeat_not_observed")
            report.data["checks"]["nativeRecoveredHeartbeat"] = True

        report.stage("artifacts_processes_database")
        from_ref = [dispatch_identity.execution_ref(d) for d in attempts]
        with sqlite3.connect(dbfile) as con:
            stored = con.execute("SELECT task_id,ref,state,work_dir FROM automation_execution_session").fetchall()
        check(len(stored)==2, "unexpected_sqlite_session_count")
        verified = {}
        methods = {}
        for tag, tid, ref in zip(labels,tasks,from_ref):
            exact = [r for r in stored if r[:3]==(tid,ref,"done")]
            check(len(exact)==1, "sqlite_task_ref_mismatch")
            folder = Path(exact[0][3]).resolve()
            check(folder.is_relative_to(work) and work_by_task.get(tag)==folder,"workspace_identity_mismatch")
            check((folder/"dispatch-result.txt").read_text(encoding="utf-8")=="NATIVE531_DONE_"+tag,"file_content_mismatch")
            owned = set()
            per_task = [sample for request_tag,sample in evidence_by_request if request_tag==tag]
            check(len(per_task)==2, "expected_two_model_requests_per_pi_task")
            for sample in per_task:
                matches = [(key, method) for key,(cwd,method) in sample.items() if cwd==folder]
                check(len(matches)==1, "pi_process_not_uniquely_observed_in_task_workspace")
                key, method = matches[0]
                owned.add(key)
                methods[method] = methods.get(method, 0)+1
            check(len(owned)==1, "pi_process_changed_between_model_requests")
            verified[tag] = next(iter(owned))
        check(len(set(verified.values()))==2, "pi_process_reused_across_tasks")
        report.data["piIdentityProof"] = {"pollIntervalMs":40,"rawArgvObservedForVerifiedProcesses":
                sum(key in observer.argv_seen for key in verified.values()),"requestMatchMethods":methods}
        check(len(set(work_by_task.values()))==2,"workspace_collision")
        report.data["checks"]["sameTaskIdsRefsWorkspacesAfterRecovery"] = True
        records = (root/"runner.log").read_text(encoding="utf-8",errors="replace")
        lines = [l for l in records.splitlines() if "dispatch accepted ref=" in l]
        check(len(lines)==2,"accepted_log_count_mismatch")
        for position, ref in enumerate(from_ref, 1):
            check(sum(f"dispatch accepted ref={ref} queuePosition={position}" in l for l in lines)==1,
                  "accepted_ref_position_mismatch")
        report.data["checks"]["bothAcceptedLogsMatchRefsAndPositions"] = True
        requests=report.data["modelRequests"]
        check([(r["task"],r["afterTool"]) for r in requests]==[("A",False),("A",True),("B",False),("B",True)],
              "unexpected_or_overlapping_pi_turns")
        report.data.update(verifiedFiles=2, sqliteDoneSessions=2, acceptedLogs=2, distinctPiPids=len(set(verified.values())))
        report.data["checks"]["twoIsolatedRealPiDeliveries"] = True
        data = report.data["hostProc"]
        hot_phases = ("applying_cpu_load","dispatch_under_pressure")
        cool_phases = ("slot_after_native_recovery",)
        check(any(data.get(k,{}).get("cpuPercentRange",[0,0])[1] >=95 for k in hot_phases),
              "independent_proc_did_not_confirm_pressure")
        check(any(data.get(k,{}).get("cpuPercentRange",[100,100])[0] <95 for k in cool_phases),
              "independent_proc_did_not_confirm_recovery")
        report.data["checks"]["independentProcConfirmedLoadAndRecovery"] = True
    finally:
        if observing is not None:
            observing.cancel()
            try:
                await observing
            except asyncio.CancelledError:
                pass
        host_task.cancel()
        try:
            await host_task
        except asyncio.CancelledError:
            pass
        stop_load(loads)
        report.data["pressureWorkersReaped"] = sum(p.poll() is not None for p in loads)
        if runner and runner.returncode is None:
            runner.stdin.close()
            try:
                await asyncio.wait_for(runner.wait(), 15)
            except asyncio.TimeoutError:
                os.killpg(runner.pid,signal.SIGTERM)
                try:
                    await asyncio.wait_for(runner.wait(), 5)
                except asyncio.TimeoutError:
                    os.killpg(runner.pid,signal.SIGKILL)
                    await runner.wait()
        report.data["runnerExit"] = runner.returncode if runner else None
        log.close()
        server.should_exit = True
        try:
            await asyncio.wait_for(serving, 35)
        finally:
            sock.close()
        check(runner and runner.returncode==0, "runner_cleanup_failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path(os.environ.get("SODUWORK_531_SUMMARY","native-pressure.json")))
    parser.add_argument("--pi-cli", type=Path)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--dedicated-vm", action="store_true", help="Confirm an explicitly provisioned disposable Linux VM")
    args = parser.parse_args()
    report = Report(args.output.resolve())
    cwd = Path.cwd()
    try:
        check(sys.platform.startswith("linux"), "linux_required")
        check(args.dedicated_vm or (os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("RUNNER_ENVIRONMENT")!="self-hosted"),
              "dedicated_vm_required")
        with tempfile.TemporaryDirectory(prefix="soduwork-native-531-") as tmp:
            try:
                asyncio.run(run(args, Path(tmp).resolve(), report))
            finally:
                os.chdir(cwd)
        report.data["passed"] = True
        report.stage("complete")
        return 0
    except Exception as exc:
        report.data["errorType"] = type(exc).__name__
        if isinstance(exc, ModuleNotFoundError) and re.fullmatch(r"[\w.]+",exc.name or ""):
            report.data["missingModule"] = exc.name
        if isinstance(exc, CheckFailed):
            report.data["failure"] = str(exc)
        report.save()
        print("native-pressure: failed at",report.data["stage"],report.data.get("failure",type(exc).__name__),flush=True)
        return 1


if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="--burn-cpu":
        burn_cpu(sys.argv[2])
    else:
        raise SystemExit(main())
