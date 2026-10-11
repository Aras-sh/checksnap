"""Cards for claude-code.tape. Numbers come from measure.json."""
import json
from pathlib import Path
H = Path(__file__).parent; (H/"scenes").mkdir(exist_ok=True)
E="\x1b"; B,R=f"{E}[1m",f"{E}[0m"
RED,GRN,YEL,BLU,GRY=(f"{E}[38;5;{c}m" for c in (203,114,221,111,245))
m=json.load(open(H/"measure.json")); r=m["work_requests_with"]; q=m["work_requests_without"]
def card(*l): return "\n\n\n"+"\n\n".join("   "+x for x in l)+"\n"
def w(n,s): (H/"scenes"/n).write_text(s)
w("hook.txt",card(f"{B}{RED}Claude Code + checksnap{R}",f"{B}find bugs without burning your usage{R}",f"{GRY}a plugin: local checks, one compact digest{R}"))
w("install.txt",card(f"{B}{BLU}Install{R}  {GRY}(card: not run live, it edits your config){R}","",
  f"{GRN}/plugin marketplace add Aras-sh/checksnap{R}",f"{GRN}/plugin install checksnap@checksnap{R}","",f"{GRY}Next: a real session, haiku, unedited.{R}"))
w("numbers.txt",card(f"{B}{GRN}Measured{R}  {GRY}same task, haiku, claude -p, 1 run each{R}",
  f"{GRN}+{R} requests repo: ${r['cost_usd']:.4f} vs ${q['cost_usd']:.4f} plain, {r['turns']} vs {q['turns']} turns",
  f"{GRN}+{R} tokens out: {r['output']:,} vs {q['output']:,}; cache read {r['cache_read']//1000}k vs {q['cache_read']//1000}k",
  f"{YEL}!{R} Tiny 4-file project: ${m['work_with']['cost_usd']:.4f} vs ${m['work_without']['cost_usd']:.4f}, barely cheaper",
  f"{B}github.com/Aras-sh/checksnap{R}"))
