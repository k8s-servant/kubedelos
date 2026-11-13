#!/usr/bin/env python3
"""Stand-in for the ``trivy`` binary in runner and cache tests. No network, no real Trivy.

``trivy image --download-db-only`` / ``--download-java-db-only`` exits 0. Env vars:
  FAKE_TRIVY_DOWNLOAD_LOG    append the argv as a JSON line here
  FAKE_TRIVY_DOWNLOAD_FAIL   print this to stderr and exit 1

``trivy image ...`` (a scan). Env vars:
  FAKE_TRIVY_PID_FILE        write this process's PID here, before sleeping
  FAKE_TRIVY_CHILD_PID_FILE  spawn a sleeping child in the same process group and write its PID here
  FAKE_TRIVY_SLEEP     seconds to sleep first
  FAKE_TRIVY_MODE      "report" (default): print the report from FAKE_TRIVY_REPORT (or an empty one) with the
                       argv and DOCKER_CONFIG echoed in; "garbage": print non-JSON; "badreport": print
                       JSON that parse_report rejects
  FAKE_TRIVY_RECORD    also write the printed JSON here
  FAKE_TRIVY_STDERR    print this to stderr
  FAKE_TRIVY_EXIT      exit with this code (after printing nothing to stdout) when non-zero
"""

import json
import os
import subprocess
import sys
import time


def download(argv):
    if log := os.environ.get("FAKE_TRIVY_DOWNLOAD_LOG"):
        with open(log, "a") as f:
            f.write(json.dumps(argv) + "\n")
    if fail := os.environ.get("FAKE_TRIVY_DOWNLOAD_FAIL"):
        sys.stderr.write(fail + "\n")
        return 1
    return 0


def scan(argv):
    if pid_file := os.environ.get("FAKE_TRIVY_PID_FILE"):
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    if child_file := os.environ.get("FAKE_TRIVY_CHILD_PID_FILE"):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        with open(child_file, "w") as f:
            f.write(str(child.pid))
    time.sleep(float(os.environ.get("FAKE_TRIVY_SLEEP", "0")))
    if stderr := os.environ.get("FAKE_TRIVY_STDERR"):
        sys.stderr.write(stderr + "\n")
    code = int(os.environ.get("FAKE_TRIVY_EXIT", "0"))
    if code:
        return code

    mode = os.environ.get("FAKE_TRIVY_MODE", "report")
    if mode == "garbage":
        print("this is not json")
        return 0
    if mode == "badreport":
        print(json.dumps({"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}))
        return 0

    if report_file := os.environ.get("FAKE_TRIVY_REPORT"):
        with open(report_file) as f:
            report = json.load(f)
    else:
        report = {"Results": None}
    report["FakeArgv"] = argv
    report["FakeEnv"] = {"DOCKER_CONFIG": os.environ.get("DOCKER_CONFIG")}
    out = json.dumps(report)
    if record := os.environ.get("FAKE_TRIVY_RECORD"):
        with open(record, "w") as f:
            f.write(out)
    print(out)
    return 0


def main():
    argv = sys.argv[1:]
    if "--download-db-only" in argv or "--download-java-db-only" in argv:
        return download(argv)
    if argv[:1] == ["image"]:
        return scan(argv)
    sys.stderr.write(f"fake trivy: unsupported argv {argv}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
