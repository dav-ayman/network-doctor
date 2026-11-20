# Real Claude Code session with the plugin loaded from this repo, on the synthetic --demo network.
# Run from the repo root: vhs docs/media/tapes/hero.tape   (needs a logged-in claude CLI)
# Records from the repo path: run it from a checkout outside your home folder (e.g. /tmp) so no username shows in tool calls.
Output docs/media/build/claude-session.mp4
Set Shell "bash"
Set FontSize 16
Set Width 1280
Set Height 820
Set Padding 22
Set Theme "GitHub Dark"
Set TypingSpeed 38ms
Set WindowBar Colorful
Hide
Type "for v in $(env | grep -o '^CLAUDE[A-Z_]*' | grep -v '^CLAUDE_CONFIG_DIR$'); do unset $v; done; export PS1='$ ' NETDOC_HOME=$(mktemp -d) REPO=$PWD; mkdir -p docs/media/build/home-office; cd docs/media/build/home-office; clear"
Enter
Type "claude --setting-sources project --plugin-dir $REPO/plugins/network-doctor --allowedTools 'Bash(python3:*)' 'Read' 'Skill'"
Enter
Sleep 4s
# a fresh folder asks to be trusted first
Down
Enter
Sleep 7s
Type "/clear"
Enter
Sleep 2s
Show
Sleep 1s
Type "my voice keeps breaking up in meetings. what's wrong with my network? (use --demo)"
Sleep 600ms
Enter
Sleep 85s
Hide
Ctrl+C
Ctrl+C
