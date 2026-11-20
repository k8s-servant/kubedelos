#!/usr/bin/env bash
# Turn the frames scripts/demo/capture.py recorded into the README's scan GIF, and size its screenshots for the README:
# scripts/demo/gif.sh OUT_DIR. Writes docs/images/scan.gif and docs/images/*.png. Needs ffmpeg.
set -euo pipefail

OUT="${1:?usage: gif.sh OUT_DIR}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGES="$ROOT/docs/images"
FPS=4      # capture.py's frame rate
WIDTH=960  # the GIF's width; the README shows it at most about 880 px wide
mkdir -p "$IMAGES"

# One palette for the whole clip keeps the colours true and the file small.
ffmpeg -loglevel error -y -framerate "$FPS" -i "$OUT/frames/%04d.png" \
  -vf "scale=$WIDTH:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
  -loop 0 "$IMAGES/scan.gif"

# The screenshots are taken at 2x; 1600 px wide stays sharp on a high-density screen at the README's width. A
# 256-colour palette is plenty for flat UI colours and cuts each file to a third or less.
for png in "$OUT"/*.png; do
  ffmpeg -loglevel error -y -i "$png" \
    -vf "scale=1600:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=256[p];[b][p]paletteuse=dither=none" \
    "$IMAGES/$(basename "$png")"
done
ls -l "$IMAGES"
