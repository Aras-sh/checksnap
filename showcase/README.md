# Showcase video

Regenerate (offline, needs `vhs`, `ttyd`, `ffmpeg` and `.venv`): `cd showcase && python3 make_scenes.py && vhs showcase.tape`

`make_scenes.py` writes `bin/`, `demo_project/`, `scenes/` and `showcase.tape`. All commands run for real and offline. The privacy-gate scene uses a fake key and answers `n`, so nothing is uploaded.
