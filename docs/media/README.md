# Media

Everything here is generated from sources in this folder. It's all recorded with `--demo`, a synthetic network, so it never contains real addresses, names or measurements.

| file | source | how |
|---|---|---|
| `banner-light.svg`, `banner-dark.svg`, `pipeline.svg` | `src/make_svgs.py` | `python3 docs/media/src/make_svgs.py` |
| `social-preview.png` (repo settings > Social preview) | `src/social.svg` | headless Chrome screenshot (see `src/make_hero.sh`) |
| `diagnose.gif`, `call-under-load.gif`, `router.gif` | `tapes/*.tape` | `vhs docs/media/tapes/<name>.tape` |
| `hero.mp4` (about 60 s) | title cards + the three recordings | `bash docs/media/src/make_hero.sh` |
| a real Claude Code session (optional) | `tapes/claude-session.tape` | needs a logged-in `claude`. Record from a checkout outside your home folder, so tool calls don't show your username |

Tools: [vhs](https://github.com/charmbracelet/vhs), ffmpeg, Google Chrome (headless, with a throwaway profile).

GitHub only plays inline video that was uploaded through the web editor. To embed `hero.mp4` in the README:
1. Drag the file into an issue or the README editor on github.com.
2. Paste the `https://github.com/user-attachments/...` link it gives you on its own line.
