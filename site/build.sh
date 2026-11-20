#!/bin/bash
# Assemble the GitHub Pages site into _site/ (repo root). Used by .github/workflows/pages.yml and `make site`.
set -euo pipefail
rm -rf _site && mkdir -p _site/media
cp site/index.html _site/
cp docs/media/diagnose.gif docs/media/router.gif docs/media/call-under-load.gif docs/media/pipeline.svg \
   docs/media/social-preview.png docs/media/hero.mp4 \
   docs/media/diagnose.mp4 docs/media/router.mp4 docs/media/diagnose-poster.jpg docs/media/router-poster.jpg _site/media/
cp desktop/icon.png _site/media/icon.png
touch _site/.nojekyll
echo "built _site/"
