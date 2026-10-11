#!/bin/bash
# Same task with and without the checksnap plugin; raw JSON in raw/.
cd "$(dirname "$0")"; R=$PWD/raw; P=/home/aras/Projects/checksnap; mkdir -p $R
T="mcp__plugin_checksnap_checksnap__checksnap_scan,mcp__plugin_checksnap_checksnap__checksnap_detail,mcp__plugin_checksnap_checksnap__checksnap_list"
for d in work work_requests; do
 (cd $d && claude --setting-sources project --plugin-dir $P --model haiku -p "Use the checksnap plugin to scan $PWD for bugs and list the top 5." --allowedTools "$T" --output-format json > $R/${d}_with.json 2>$R/${d}_with.err)
 (cd $d && claude --setting-sources project --model haiku -p "Find the top 5 bugs in this project by reading the files." --allowedTools "Read,Glob,Grep,Bash(ls:*),Bash(cat:*)" --output-format json > $R/${d}_without.json 2>$R/${d}_without.err)
done
python3 - <<'PY'
import json
out={}
for d in ("work","work_requests"):
  for m in ("with","without"):
    j=json.load(open(f"raw/{d}_{m}.json")); u=j["usage"]
    out[f"{d}_{m}"]={"cost_usd":round(j["total_cost_usd"],4),"turns":j["num_turns"],"duration_s":round(j["duration_ms"]/1000,1),
     "input":u["input_tokens"],"output":u["output_tokens"],"cache_create":u["cache_creation_input_tokens"],"cache_read":u["cache_read_input_tokens"]}
json.dump(out,open("measure.json","w"),indent=1); print(json.dumps(out,indent=1))
PY
