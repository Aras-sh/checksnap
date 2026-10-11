Output showcase.mp4
Output showcase.gif
Set Shell "bash"
Set FontSize 22
Set Width 1400
Set Height 800
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 18ms
Set Framerate 20
Set WindowBar Colorful

Hide
Type "PS1='$ '; export PATH=$PWD/bin:$PATH; export PYTHONDONTWRITEBYTECODE=1; cd $PWD; clear" Enter
Show
Sleep 300ms

Hide
Type "clear; cat scenes/hook.txt" Enter
Show
Sleep 3s

Hide
Type "clear" Enter
Show
Type "checksnap --list-checks | cut -c1-92" Sleep 500ms Enter
Sleep 5s

Hide
Type "clear; cat scenes/security.txt" Enter
Show
Sleep 1s

Type "checksnap --check-security demo_project | cut -c1-92 | head -22" Sleep 500ms Enter
Sleep 6s

Hide
Type "clear" Enter
Show
Type "checksnap --check-optimization demo_project --static-only | cut -c1-92 | head -12" Sleep 500ms Enter
Sleep 4s

Hide
Type "clear" Enter
Show
Type "checksnap --check-docker demo_project | cut -c1-92 | head -10" Sleep 500ms Enter
Sleep 3500ms
Hide
Type "clear" Enter
Show
Type "checksnap --check-ci demo_project | cut -c1-92 | head -12" Sleep 500ms Enter
Sleep 4500ms

Hide
Type "export SUBQ_API_KEY=demo-not-a-real-key" Enter
Show
Hide
Type "clear; cat scenes/gate.txt" Enter
Show
Sleep 4s

Type "checksnap --check-dataset ../examples/dataset --benchmark ../examples/dataset/benchmark.jsonl" Sleep 500ms Enter
Sleep 4s
Type "n" Sleep 300ms Enter
Sleep 1500ms
Hide
Type "unset SUBQ_API_KEY" Enter
Show
Sleep 1s

Hide
Type "clear; cat scenes/close.txt" Enter
Show
Sleep 8s

