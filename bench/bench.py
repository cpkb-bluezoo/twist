#!/usr/bin/env python3
# Copyright (C) 2026 Chris Burdess <dog@gnu.org>
#
# This file is part of twist.
#
# twist is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# twist is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program.  If not, see
# <https://www.gnu.org/licenses/>.

"""Compare twist with curl on HTTP downloads and uploads over HTTP/1.1, HTTP/2
and HTTP/3, against one local nginx.

Every scenario is run for both clients, interleaved (curl, twist, twist, curl,
...) so that whatever the machine does meanwhile happens to both.  Each run is
a process, measured with wait4 by a small program of its own (rusage.c): wall time, CPU time (user and system) and
the peak resident set.  What is reported is the ratio twist/curl, as the median
of the ratios of the pairs, with a bootstrap interval, and the medians of each.
A body is checked against its hash before anything is timed.

    bench.py --nginx /usr/sbin/nginx --curl ./curl --twist ../src/twist

See README in this directory.
"""

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROTOS = {"h1": "--http1.1", "h2": "--http2", "h3": "--http3-only"}


class Fail(Exception):
    pass


def run_quiet(argv, **kw):
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          **kw)


def find_nginx(path):
    exe = shutil.which(path)
    if exe is None:
        raise Fail("nginx not found (%s); --nginx PATH" % path)
    out = run_quiet([exe, "-V"])
    flags = (out.stderr + out.stdout).decode("utf-8", "replace")
    for need in ("http_v3_module", "http_dav_module", "http_v2_module"):
        if need not in flags:
            raise Fail("%s lacks --with-%s; see bench/README" % (exe, need))
    return exe


class Origin:
    """nginx on 127.0.0.1, files to get and a place to put."""

    def __init__(self, nginx, big_mb, cpus):
        base = "/dev/shm" if os.path.isdir("/dev/shm") else None
        self.work = tempfile.mkdtemp(prefix="twist-bench.", dir=base)
        self.nginx = nginx
        self.cpus = cpus
        self.proc = None
        self.sizes = {"small": 1024, "medium": 1024 * 1024,
                      "big": big_mb * 1024 * 1024}
        self.hash = {}
        self.port = self.free_port()
        os.makedirs(os.path.join(self.work, "www"))
        os.makedirs(os.path.join(self.work, "up"))
        os.makedirs(os.path.join(self.work, "tmp"))
        for name, size in self.sizes.items():
            data = os.urandom(size)
            with open(os.path.join(self.work, "www", name), "wb") as f:
                f.write(data)
            self.hash[name] = hashlib.sha256(data).hexdigest()
        self.cert = os.path.join(self.work, "cert.pem")
        key = os.path.join(self.work, "key.pem")
        r = run_quiet(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                       "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key,
                       "-out", self.cert, "-days", "2", "-subj", "/CN=127.0.0.1",
                       "-addext", "subjectAltName=IP:127.0.0.1"])
        if r.returncode != 0:
            raise Fail("openssl cannot make a certificate")
        if os.geteuid() == 0:
            # nginx gives up its rights when it starts as root, to a user that
            # has to be able to read and write here.
            for d in (self.work, os.path.join(self.work, "www")):
                os.chmod(d, 0o755)
            for d in ("up", "tmp"):
                os.chmod(os.path.join(self.work, d), 0o777)
            for name in self.sizes:
                os.chmod(os.path.join(self.work, "www", name), 0o644)
            os.chmod(self.cert, 0o644)
            os.chmod(key, 0o644)
        with open(os.path.join(HERE, "nginx.conf.in")) as f:
            conf = f.read()
        conf = conf.replace("@WORK@", self.work).replace("@PORT@",
                                                          str(self.port))
        self.conf = os.path.join(self.work, "nginx.conf")
        with open(self.conf, "w") as f:
            f.write(conf)

    @staticmethod
    def free_port():
        while True:
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
            finally:
                u.close()

    def start(self):
        argv = [self.nginx, "-c", self.conf, "-p", self.work]
        if self.cpus and shutil.which("taskset"):
            argv = ["taskset", "-c", self.cpus] + argv
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE)
        for _ in range(100):
            if self.proc.poll() is not None:
                raise Fail("nginx did not start: %s"
                           % self.proc.stderr.read().decode()[:400])
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise Fail("nginx did not listen")

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.work, ignore_errors=True)

    def url(self, kind, name):
        return "https://127.0.0.1:%d/%s/%s" % (self.port, kind, name)

    def path(self, name):
        return os.path.join(self.work, "www", name)

    def uploaded(self, name):
        return os.path.join(self.work, "up", name)


class Client:
    def __init__(self, name, exe, cpus):
        self.name = name
        self.exe = exe
        self.cpus = cpus
        self.parallel_flag = ["-Z", "--parallel-max", "100"] \
            if name == "twist" else ["--parallel", "--parallel-max", "100"]

    def argv(self, origin, proto, extra, urls_and_outs, upload=None):
        a = [self.exe, "-s", "-S", "--cacert", origin.cert, PROTOS[proto],
             "--connect-timeout", "10", "--max-time", "300"]
        a += extra
        for url, out in urls_and_outs:
            if upload is not None:
                a += ["-T", upload]
            a += ["-o", out, url]
        return a


RUSAGE = None       # the helper that runs a command and reports its usage
RUSAGE_OUT = None


def build_helper():
    """Built where programs may run: memory (/dev/shm) is often noexec.
    Returns the directory, to be removed."""
    global RUSAGE, RUSAGE_OUT
    work = tempfile.mkdtemp(prefix="twist-bench-bin.")
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise Fail("a C compiler is needed for bench/rusage.c")
    RUSAGE = os.path.join(work, "rusage")
    RUSAGE_OUT = os.path.join(work, "rusage.out")
    r = run_quiet([cc, "-O2", "-o", RUSAGE, os.path.join(HERE, "rusage.c")])
    if r.returncode != 0:
        raise Fail("rusage.c: %s" % r.stderr.decode()[:300])
    return work


def measure(argv, cpus):
    """Run ARGV; returns (wall seconds, cpu seconds, max rss bytes, status,
    standard error)."""
    if cpus and shutil.which("taskset"):
        argv = ["taskset", "-c", cpus] + argv
    p = subprocess.run([RUSAGE, RUSAGE_OUT] + argv, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise Fail("rusage failed (%d)" % p.returncode)
    with open(RUSAGE_OUT) as f:
        code, wall, user, system, rss = f.read().split()
    return (float(wall), float(user) + float(system), int(rss), int(code),
            p.stderr.decode("utf-8", "replace"))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                return h.hexdigest()
            h.update(b)


class Scenario:
    def __init__(self, name, op, size, count, parallel, reps, protos=None):
        self.name = name
        self.op = op              # "get" or "put"
        self.size = size          # "small", "medium", "big"
        self.count = count        # requests in a run
        self.parallel = parallel
        self.reps = reps
        self.protos = protos      # None: all

    def command(self, client, origin, proto, out):
        kind = "www" if self.op == "get" else "up"
        url = origin.url(kind, self.size)
        extra = list(client.parallel_flag) if self.parallel else []
        upload = origin.path(self.size) if self.op == "put" else None
        return client.argv(origin, proto, extra, [(url, out)] * self.count,
                           upload)


def scenarios(args):
    def n(base):
        # Fewer than five pairs say nothing about a median.
        return max(5, int(base * args.reps_scale))

    return [
        Scenario("get-small", "get", "small", 1, False, n(30)),
        Scenario("get-small-x50", "get", "small", 50, False, n(15)),
        Scenario("get-small-par100", "get", "small", 100, True, n(15),
                 ("h2", "h3")),
        Scenario("get-medium", "get", "medium", 1, False, n(20)),
        Scenario("get-big", "get", "big", 1, False, n(7)),
        Scenario("put-small", "put", "small", 1, False, n(30)),
        Scenario("put-medium", "put", "medium", 1, False, n(20)),
        Scenario("put-big", "put", "big", 1, False, n(7)),
    ]


def verify(origin, sc, client, proto, work):
    """The body arrives, or arrives at the server, whole."""
    if sc.op == "get":
        out = os.path.join(work, "got")
        if os.path.exists(out):
            os.unlink(out)
        a = client.argv(origin, proto, [], [(origin.url("www", sc.size), out)])
        _, _, _, code, err = measure(a, client.cpus)
        if code != 0 or not os.path.exists(out) \
                or sha256_file(out) != origin.hash[sc.size]:
            raise Fail("%s %s %s: the body is wrong (status %s, %s bytes) %s\n  %s"
                       % (sc.name, client.name, proto, code,
                          os.path.getsize(out) if os.path.exists(out) else "no file",
                          err.strip(), " ".join(a)))
    else:
        dest = origin.uploaded(sc.size)
        if os.path.exists(dest):
            os.unlink(dest)
        # One upload is enough to check.
        a = client.argv(origin, proto, [],
                        [(origin.url("up", sc.size), "/dev/null")],
                        origin.path(sc.size))
        _, _, _, code, err = measure(a, client.cpus)
        if code != 0 or not os.path.exists(dest) \
                or sha256_file(dest) != origin.hash[sc.size]:
            raise Fail("%s %s %s: the server did not get the body (status %s) %s"
                       % (sc.name, client.name, proto, code, err.strip()))


def bootstrap_median(values, rng, n=2000):
    meds = []
    for _ in range(n):
        meds.append(statistics.median(rng.choices(values, k=len(values))))
    meds.sort()
    return meds[int(0.025 * n)], meds[int(0.975 * n) - 1]


def run_pair(sc, origin, proto, clients, reps, work):
    """Interleaved: the order alternates from pair to pair."""
    runs = {c.name: [] for c in clients}
    bad = {c.name: 0 for c in clients}
    for i in range(reps + 1):          # the first pair is a warm-up
        order = clients if i % 2 == 0 else list(reversed(clients))
        for c in order:
            a = sc.command(c, origin, proto, "/dev/null")
            wall, cpu, rss, code, err = measure(a, c.cpus)
            if code != 0:
                bad[c.name] += 1
                if bad[c.name] == 1:
                    print("  %s %s %s failed (%s): %s"
                          % (sc.name, c.name, proto, code, err.strip()[:200]),
                          file=sys.stderr)
                continue
            if i > 0:
                runs[c.name].append((wall, cpu, rss))
    return runs, bad


def summarize(runs, rng):
    c, t = runs["curl"], runs["twist"]
    n = min(len(c), len(t))
    if n < 3:
        return None
    res = {"n": n}
    for k, label in ((0, "wall"), (1, "cpu"), (2, "rss")):
        cv = [x[k] for x in c[:n]]
        tv = [x[k] for x in t[:n]]
        ratios = [tv[i] / cv[i] for i in range(n) if cv[i] > 0]
        lo, hi = bootstrap_median(ratios, rng)
        res[label] = {"curl": statistics.median(cv),
                      "twist": statistics.median(tv),
                      "ratio": statistics.median(ratios),
                      "lo": lo, "hi": hi}
    return res


def fmt_time(s):
    return "%.1f ms" % (s * 1000) if s < 1 else "%.2f s" % s


def fmt_rss(b):
    return "%.1f MiB" % (b / 1048576)


def table(results, meta):
    lines = []
    lines.append("| scenario | proto | n | wall curl | wall twist | wall ratio "
                 "| cpu curl | cpu twist | cpu ratio | rss curl | rss twist |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in results:
        if r.get("skipped"):
            lines.append("| %s | %s | | %s |||||||| " % (r["scenario"], r["proto"],
                                                       r["skipped"]))
            continue
        s = r["stats"]
        if s is None:
            lines.append("| %s | %s | | FAILED (curl %d, twist %d) |||||||| "
                         % (r["scenario"], r["proto"], r["failed"]["curl"],
                            r["failed"]["twist"]))
            continue
        w, c, m = s["wall"], s["cpu"], s["rss"]
        lines.append("| %s | %s | %d | %s | %s | **%.2f** (%.2f-%.2f) | %s | %s "
                     "| **%.2f** (%.2f-%.2f) | %s | %s |"
                     % (r["scenario"], r["proto"], s["n"], fmt_time(w["curl"]),
                        fmt_time(w["twist"]), w["ratio"], w["lo"], w["hi"],
                        fmt_time(c["curl"]), fmt_time(c["twist"]), c["ratio"],
                        c["lo"], c["hi"], fmt_rss(m["curl"]),
                        fmt_rss(m["twist"])))
    head = ["### twist against curl", "",
            "Ratio is twist/curl, the median of the pairs, with the 95% "
            "interval of that median in brackets; below 1 twist is better.",
            "", "- curl: %s" % meta["curl"], "- twist: %s" % meta["twist"],
            "- nginx: %s" % meta["nginx"], "- host: %s" % meta["host"], ""]
    return "\n".join(head + lines) + "\n"


def version_line(exe, flag="--version"):
    r = run_quiet([exe, flag])
    return (r.stdout or r.stderr).decode("utf-8", "replace").splitlines()[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--nginx", default="nginx")
    ap.add_argument("--curl", default="curl")
    ap.add_argument("--twist", default=os.path.join(HERE, "..", "src", "twist"))
    ap.add_argument("--protocols", default="h1,h2,h3")
    ap.add_argument("--only", default="", help="scenario names containing this")
    ap.add_argument("--big-mb", type=int, default=256)
    ap.add_argument("--reps-scale", type=float, default=1.0)
    ap.add_argument("--server-cpus", default="",
                    help="taskset list for nginx, e.g. 0-1")
    ap.add_argument("--client-cpus", default="",
                    help="taskset list for the clients, e.g. 2")
    ap.add_argument("--require-protocols", action="store_true",
                    help="fail, not leave a protocol out, if a client cannot "
                         "speak it")
    ap.add_argument("--mtu", type=int, default=0,
                    help="run in a network namespace of its own whose loopback "
                         "has this MTU, such as 1500 (needs root, unshare and "
                         "ip); the loopback's own is 65536, on which a server "
                         "sends a client that takes them datagrams far larger "
                         "than any network does")
    ap.add_argument("--json", default="", help="write the results here")
    ap.add_argument("--max-ratio", type=float, default=0.0,
                    help="exit 1 if a wall or cpu ratio's whole interval is "
                         "above this")
    args = ap.parse_args()

    if args.mtu and os.environ.get("TWIST_BENCH_MTU") != str(args.mtu):
        for tool in ("unshare", "ip"):
            if shutil.which(tool) is None:
                raise Fail("--mtu needs %s" % tool)
        env = dict(os.environ, TWIST_BENCH_MTU=str(args.mtu))
        try:
            os.execvpe("unshare", ["unshare", "-n", "sh", "-c",
                                   'ip link set lo up && ip link set lo mtu '
                                   '"$0" && exec "$@"', str(args.mtu),
                                   sys.executable] + sys.argv, env)
        except OSError as e:
            raise Fail("--mtu: %s" % e)

    nginx = find_nginx(args.nginx)
    curl = shutil.which(args.curl) or args.curl
    twist = os.path.abspath(args.twist) if os.path.exists(args.twist) \
        else shutil.which(args.twist)
    if twist is None or not os.access(twist, os.X_OK):
        raise Fail("twist not found (%s); --twist PATH" % args.twist)
    clients = [Client("curl", curl, args.client_cpus),
               Client("twist", twist, args.client_cpus)]
    protos = [p for p in args.protocols.split(",") if p]
    rng = random.Random(20260101)
    meta = {"curl": version_line(curl), "twist": version_line(twist),
            "nginx": run_quiet([nginx, "-v"]).stderr.decode().strip(),
            "host": "%s %s, %d cpus%s" % (platform.system(), platform.machine(),
                                          os.cpu_count() or 0,
                                          ", loopback MTU %d" % args.mtu
                                          if args.mtu else "")}
    helper_dir = build_helper()
    origin = Origin(nginx, args.big_mb, args.server_cpus)
    results = []
    status = 0
    try:
        origin.start()
        # A protocol one of the clients cannot speak is left out.
        usable = []
        for p in protos:
            ok = True
            for c in clients:
                a = c.argv(origin, p, [], [(origin.url("www", "small"),
                                            "/dev/null")])
                r = measure(a, c.cpus)
                if r[3] != 0:
                    print("%s cannot do %s here: left out (status %d: %s)"
                          % (c.name, p, r[3], r[4].strip()[:200]),
                          file=sys.stderr)
                    ok = False
            if ok:
                usable.append(p)
        if args.require_protocols and len(usable) != len(protos):
            raise Fail("a protocol asked for cannot be used: %s"
                       % ",".join(p for p in protos if p not in usable))
        for sc in scenarios(args):
            if args.only and args.only not in sc.name:
                continue
            for p in usable:
                if sc.protos is not None and p not in sc.protos:
                    continue
                print("%s %s" % (sc.name, p), file=sys.stderr, flush=True)
                for c in clients:
                    verify(origin, sc, c, p, origin.work)
                runs, bad = run_pair(sc, origin, p, clients, sc.reps,
                                     origin.work)
                stats = summarize(runs, rng)
                results.append({"scenario": sc.name, "proto": p, "stats": stats,
                                "failed": bad, "runs": runs})
                if stats is not None and args.max_ratio > 0:
                    for k in ("wall", "cpu"):
                        if stats[k]["lo"] > args.max_ratio:
                            print("REGRESSION %s %s %s ratio %.2f (%.2f-%.2f)"
                                  % (sc.name, p, k, stats[k]["ratio"],
                                     stats[k]["lo"], stats[k]["hi"]),
                                  file=sys.stderr)
                            status = 1
        for p in protos:
            if p not in usable:
                results.append({"scenario": "(all)", "proto": p,
                                "skipped": "not spoken by both clients here"})
    finally:
        origin.stop()
        shutil.rmtree(helper_dir, ignore_errors=True)
    md = table(results, meta)
    sys.stdout.write(md)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(md)
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"meta": meta, "results": results}, f, indent=1)
    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fail as e:
        print("bench: %s" % e, file=sys.stderr)
        sys.exit(2)
