Output claude-code.mp4
Output claude-code.gif
Set Shell "bash"
Set FontSize 22
Set Width 1400
Set Height 800
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms
Set Framerate 10
Set WindowBar Colorful

Hide
Type "for v in $(env | grep -E '^(CLAUDE|AI_AGENT|TMUX)' | sed 's/=.*//'); do unset $v; done; PS1='$ '; S=/tmp/shop; rm -rf $S; mkdir -p $S; cp -r /home/aras/Projects/checksnap/showcase/claude-code/../demo_project $S/app; ln -s /home/aras/Projects/checksnap/showcase/claude-code/../.. $S/plugin; cp -r /home/aras/Projects/checksnap/showcase/claude-code/scenes $S/scenes; cd $S/app; clear" Enter
Type "alias claude='command claude --setting-sources project --permission-mode acceptEdits --allowedTools mcp__plugin_checksnap_checksnap__checksnap_scan,mcp__plugin_checksnap_checksnap__checksnap_detail,mcp__plugin_checksnap_checksnap__checksnap_list'" Enter
Type "clear; cat ../scenes/hook.txt" Enter
Show
Sleep 2s
Hide
Type "clear; cat ../scenes/install.txt" Enter
Show
Sleep 6s
Hide
Type "claude --plugin-dir ../plugin --model haiku" Enter
Sleep 6s
Down
Enter
Sleep 5s
Ctrl+C
Ctrl+C
Sleep 1s
Type "clear" Enter
Show
Type "claude --plugin-dir ../plugin --model haiku" Sleep 500ms Enter
Sleep 6s
Screenshot s_start.png
Type "scan this project for bugs with checksnap and fix the worst one" Sleep 500ms Enter
Sleep 12s
Enter
Sleep 7s
Enter
Sleep 7s
Enter
Sleep 6s
Screenshot s_done.png
Sleep 2s
Hide
Ctrl+C
Ctrl+C
Sleep 1s
Type "clear; cat ../scenes/numbers.txt" Enter
Show
Sleep 6s
