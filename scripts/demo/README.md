# README pictures

The screenshots and the scan GIF in `docs/images/` come from a real scan of a throwaway kind cluster that runs old public
images (`workloads.yaml`), with an empty data directory, so they show nothing from a real cluster. To take them again
after a UI change (needs kind, kubectl, docker, ffmpeg, uv or pip, and Google Chrome):

```bash
export DEMO_DIR="$(mktemp -d)"
scripts/demo/cluster.sh                                   # the kind cluster; kubeconfig in $DEMO_DIR

KUBEDELOS_DATA_DIR="$DEMO_DIR/data" KUBEDELOS_THREAT_FEEDS=true \
  kubedelos ui --kubeconfig "$DEMO_DIR/kubeconfig" --context kind-kubedelos-demo --port 9390 --no-browser &
# copy the printed http://127.0.0.1:9390/?token=... URL

python3 -m venv "$DEMO_DIR/pw" && "$DEMO_DIR/pw/bin/pip" install playwright
"$DEMO_DIR/pw/bin/python" scripts/demo/capture.py "<URL>" "$DEMO_DIR/out" --scan
scripts/demo/gif.sh "$DEMO_DIR/out"                       # writes docs/images/

kill %1 && scripts/demo/cluster.sh --delete
```

`capture.py` drives the installed Chrome through Playwright, so no browser is downloaded. It records the scan as
still frames (the scan itself as a time lapse), and `gif.sh` joins them into a GIF and sizes the screenshots. Run the
scan twice if you want the dashboard to show its change figures: the first run has no earlier one to compare with.
