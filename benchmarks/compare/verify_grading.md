# snap-verify grading (T7, vulnerable_12)

Source: `raw/verify_vulnerable_12.json` (full findings) and `results.json` t7.vulnerable_12.lowered; code read in `data/t1/verify_vuln/` (identical to `data/bandit/examples/`). Graded by one reviewer (an LLM, not independent of the tool chain) on what the code does, not on what the bandit fixture says it demonstrates. Rubric: TRUE = real weakness in the code as written; FP = constant/inert/benign. "(weak)" = true but low-impact or context-dependent; counted as TRUE. Line numbers are as reported by checksnap.

## A. All 47 downgraded findings

| # | finding (rule file:line) | verdict | reason |
|---|---|---|---|
| 1 | SEC-015 os-chmod.py:7 | BAD downgrade: TRUE | mode 0o007 on /etc/passwd leaves it world-readable/writable/executable |
| 2 | SEC-001 pickle_deserialize.py:7 | correct (FP) | pickle.loads of bytes the same script just dumped; no untrusted input |
| 3 | SEC-008 requests-ssl-verify-disabled.py:22 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 4 | SEC-008 requests-ssl-verify-disabled.py:24 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 5 | SEC-008 requests-ssl-verify-disabled.py:26 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 6 | SEC-008 requests-ssl-verify-disabled.py:28 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 7 | SEC-008 requests-ssl-verify-disabled.py:30 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 8 | SEC-008 requests-ssl-verify-disabled.py:32 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 9 | SEC-008 requests-ssl-verify-disabled.py:34 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 10 | SEC-008 requests-ssl-verify-disabled.py:36 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 11 | SEC-008 requests-ssl-verify-disabled.py:38 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 12 | SEC-008 requests-ssl-verify-disabled.py:40 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 13 | SEC-008 requests-ssl-verify-disabled.py:42 | BAD downgrade: TRUE | httpx call with verify=False disables TLS cert validation (bandit fixture calls it "Okay" only because bandit has no httpx rule) |
| 14 | SEC-011 sql_statements.py:19 | BAD downgrade: TRUE | "%s" formatting of unvalidated value into cur.execute (SQL injection) |
| 15 | EXT-BANDIT-B602 subprocess_shell.py:46 | correct (FP) | no injectable input: shell='True' (truthy) but command is the constant 'pwd' |
| 16 | EXT-BANDIT-B602 subprocess_shell.py:47 | correct (FP) | no injectable input: shell='False' is truthy, but command is the constant 'pwd' |
| 17 | EXT-BANDIT-B602 subprocess_shell.py:48 | correct (FP) | no injectable input: shell='None' is truthy, but command is the constant 'pwd' |
| 18 | EXT-BANDIT-B602 subprocess_shell.py:49 | correct (FP) | no injectable input: shell=1, command is the constant 'pwd' |
| 19 | EXT-BANDIT-B602 subprocess_shell.py:51 | correct (FP) | no injectable input: shell=Popen() is the local stub returning None (falsy), so no shell |
| 20 | EXT-BANDIT-B602 subprocess_shell.py:52 | correct (FP) | no injectable input: shell=[True] truthy, command is the constant 'pwd' |
| 21 | EXT-BANDIT-B602 subprocess_shell.py:53 | correct (FP) | no injectable input: shell={'IS':'True'} truthy, command is the constant 'pwd' |
| 22 | EXT-BANDIT-B602 subprocess_shell.py:54 | correct (FP) | no injectable input: shell=command, constant 'pwd' |
| 23 | EXT-BANDIT-B202 tarfile_extractall.py:26 | BAD downgrade: TRUE | filter="fully_trusted" on an archive from caller-supplied filename: no path-traversal protection |
| 24 | EXT-BANDIT-B303 crypto-md5.py:32 | BAD downgrade: TRUE (weak) | SHA-1 (Cryptodome SHA) with no usedforsecurity=False; purpose unknown, low severity |
| 25 | EXT-BANDIT-B324 crypto-md5.py:39 | correct (FP) | crypt METHOD_BLOWFISH (bcrypt) is not a weak hash |
| 26 | EXT-BANDIT-B324 crypto-md5.py:46 | correct (FP) | crypt METHOD_BLOWFISH (bcrypt) is not a weak hash |
| 27 | EXT-BANDIT-B307 eval.py:3 | correct (FP) | eval("1+1") on a literal |
| 28 | EXT-BANDIT-B108 os-chmod.py:15 | BAD downgrade: TRUE (weak) | fixed /tmp path made mode 0x1ff (0o777): predictable name, world-writable |
| 29 | SEC-005 os_system.py:3 | correct (FP) | os.system('/bin/echo hi') constant command |
| 30 | EXT-BANDIT-B608 sql_statements.py:47 | correct (FP) | a()("SELECT %s...") calls a no-op closure, never reaches a DB (bandit bug-report case) |
| 31 | EXT-BANDIT-B604 subprocess_shell.py:12 | correct (FP) | calls the file's own Popen stub that only prints; constant string anyway |
| 32 | EXT-BANDIT-B202 tarfile_extractall.py:32 | correct (FP) | members=[] extracts nothing |
| 33 | EXT-BANDIT-B403 pickle_deserialize.py:2 | correct (FP) | import notice only; the pickle use is on self-made data |
| 34 | EXT-BANDIT-B404 subprocess_shell.py:1 | correct (FP) | import notice only |
| 35 | EXT-BANDIT-B404 subprocess_shell.py:2 | correct (FP) | import notice only |
| 36 | EXT-BANDIT-B603 subprocess_shell.py:15 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 37 | EXT-BANDIT-B603 subprocess_shell.py:16 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 38 | EXT-BANDIT-B603 subprocess_shell.py:18 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 39 | EXT-BANDIT-B603 subprocess_shell.py:23 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 40 | EXT-BANDIT-B603 subprocess_shell.py:26 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 41 | EXT-BANDIT-B603 subprocess_shell.py:28 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 42 | EXT-BANDIT-B603 subprocess_shell.py:33 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 43 | EXT-BANDIT-B603 subprocess_shell.py:56 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 44 | EXT-BANDIT-B603 subprocess_shell.py:57 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 45 | EXT-BANDIT-B603 subprocess_shell.py:58 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 46 | EXT-BANDIT-B603 subprocess_shell.py:59 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |
| 47 | EXT-BANDIT-B603 subprocess_shell.py:60 | correct (FP) | list args or shell=False/falsy, constant args; INFO-level notice |

Correctly downgraded: **31/47**. True issues wrongly downgraded: **16** (of which 2 weak).

## B. Random sample of 20 not-downgraded findings (`random.Random(1).sample`, over the 87 non-lowered findings in raw order)

| # | finding | verdict | reason |
|---|---|---|---|
| 1 | SEC-008 requests-ssl-verify-disabled.py:10 (HIGH) | TRUE | requests.put verify=False |
| 2 | EXT-BANDIT-B608 sql_statements.py:14 (MEDIUM) | TRUE (weak) | tainted .replace() builds a query string; no execute in file, pattern is injectable |
| 3 | SEC-015 os-chmod.py:11 (HIGH) | TRUE | 0o776 on /etc/passwd: world-writable |
| 4 | SEC-011 sql_statements.py:32 (HIGH) | TRUE | f-string table name in cur.execute |
| 5 | SEC-008 requests-ssl-verify-disabled.py:6 (HIGH) | TRUE | requests.get verify=False |
| 6 | EXT-BANDIT-B103 os-chmod.py:12 (MEDIUM) | TRUE | 0o760 on /etc/passwd: group-writable |
| 7 | SEC-007 mktemp.py:7 (MEDIUM) | TRUE | tempfile.mktemp is race-prone (TOCTOU) |
| 8 | SEC-007 mktemp.py:10 (MEDIUM) | TRUE | tempfile.mktemp is race-prone (TOCTOU) |
| 9 | EXT-BANDIT-B602 subprocess_shell.py:34 (LOW) | FP | shell=True but constant '/bin/ls -l' |
| 10 | EXT-BANDIT-B303 crypto-md5.py:30 (MEDIUM) | TRUE | MD4 .new() |
| 11 | SEC-011 sql_statements.py:23 (HIGH) | TRUE | string concat of identifier into cur.execute |
| 12 | SEC-015 os-chmod.py:17 (HIGH) | TRUE | 0o777 on a variable path |
| 13 | EXT-BANDIT-B103 os-chmod.py:10 (MEDIUM) | TRUE | 0o770 on /etc/passwd: group-writable |
| 14 | EXT-BANDIT-B413 crypto-md5.py:5 (HIGH) | TRUE | imports pyCrypto SHA, abandoned library |
| 15 | EXT-BANDIT-B303 crypto-md5.py:31 (MEDIUM) | TRUE | MD5 .new() |
| 16 | EXT-BANDIT-B324 crypto-md5.py:45 (MEDIUM) | TRUE | crypt.mksalt(METHOD_MD5): weak salt/hash scheme |
| 17 | EXT-BANDIT-B602 subprocess_shell.py:14 (LOW) | FP | shell=True but constant '/bin/gcc --version' |
| 18 | EXT-BANDIT-B413 crypto-md5.py:2 (HIGH) | TRUE | imports pyCrypto MD2, abandoned library |
| 19 | SEC-004 subprocess_shell.py:38 (HIGH) | FP | claims 'formatted command' but format arg is the literal 'something'; constant |
| 20 | SEC-011 sql_statements.py:29 (HIGH) | TRUE (weak) | f-string expression {a + b} in execute; injectable unless numeric |

Sample: 17/20 true = 85% (95% Wilson interval about 64-95%).

## C. Precision estimate (estimate, not a measurement)

- Estimated true findings: 16 (downgraded, exact) + 74 (87 x 17/20, sampled) = 90 of 134.
- Precision before verify: ~67%. After verify (the 87 kept): ~85% (+-15 points). Precision of the 47 downgraded set: 34% true, so verify removed 31 FPs and 16 real issues.
- Estimated recall of true findings after verify: ~82%. Of the 3 FPs in the sample, all are constant-command shell=True, a class snap lowered elsewhere but not here (inconsistent).
- Caveats: one grader, one corpus (12 bandit fixture files, 134 findings clustered by file: 11 of the 16 bad downgrades are the same httpx pattern), sample of 20 is small.
