#!/bin/bash
# Build docs/media/build/hero.mp4 (~45 s, 1280x720, no audio) from the VHS recordings and title cards.
# Needs: python3, vhs, ffmpeg, Google Chrome (headless, throwaway profile). Run from the repo root.
set -euo pipefail
M=docs/media; B=$M/build; mkdir -p $B
python3 $M/src/make_svgs.py >/dev/null
for t in diagnose call-under-load router; do [ -f $B/$t.mp4 ] || vhs $M/tapes/$t.tape >/dev/null; done
CH="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
PROFILE=$(mktemp -d)
for c in social card-1 card-2 card-3 card-4; do
  printf '<html><body style="margin:0;background:#0d1117"><img src="file://%s/%s/src/%s.svg" style="display:block;width:1280px;height:%spx"></body></html>' \
    "$PWD" "$M" "$c" "$([ $c = social ] && echo 640 || echo 720)" > $B/$c.html
  "$CH" --headless=new --disable-gpu --user-data-dir="$PROFILE" --hide-scrollbars --window-size=1280,720 \
    --virtual-time-budget=2000 --screenshot="$PWD/$B/$c.png" "file://$PWD/$B/$c.html" 2>/dev/null
done
rm -rf "$PROFILE"
fit="scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=0x0d1117,fps=30,format=yuv420p,setsar=1"
still() { ffmpeg -loglevel error -y -loop 1 -t "$2" -i "$B/$1.png" -vf "$fit,fade=t=in:st=0:d=0.4,fade=t=out:st=$(echo "$2 - 0.4" | bc):d=0.4" -c:v libx264 -pix_fmt yuv420p "$B/seg-$1.mp4"; }
clip() { ffmpeg -loglevel error -y -i "$B/$1.mp4" -vf "$fit" -an -c:v libx264 -pix_fmt yuv420p "$B/seg-$1.mp4"; }
still social 3; still card-1 2.5; clip diagnose; still card-2 2.5; clip call-under-load; still card-3 2.5; clip router; still card-4 3.5
printf "file 'seg-%s.mp4'\n" social card-1 diagnose card-2 call-under-load card-3 router card-4 > $B/concat.txt
ffmpeg -loglevel error -y -f concat -safe 0 -i $B/concat.txt -c:v libx264 -crf 26 -preset slow -movflags +faststart -pix_fmt yuv420p $B/hero.mp4
ls -la $B/hero.mp4
