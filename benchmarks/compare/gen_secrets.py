"""Generate planted fake secrets (60 files) and decoys (60 files). Deterministic (seed 7). All values are random."""
import base64, json, random, string, uuid, hashlib, sys
from pathlib import Path

R = random.Random(7)
UP = string.ascii_uppercase + string.digits
AN = string.ascii_letters + string.digits
rs = lambda n, a=AN: "".join(R.choice(a) for _ in range(n))
b64u = lambda n: base64.urlsafe_b64encode(bytes(R.randrange(256) for _ in range(n))).decode().rstrip("=")


def aws():      return "AKIA" + rs(16, UP)
def aws_sec():  return rs(40, AN + "/+")
def ghp():      return "ghp_" + rs(36)
def slack():    return f"xoxb-{rs(12, string.digits)}-{rs(12, string.digits)}-{rs(24)}"
def jwt():      return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + base64.urlsafe_b64encode(json.dumps({"sub": rs(8), "uid": R.randrange(10**6)}).encode()).decode().rstrip("=") + "." + b64u(32)
def pkey():
    body = "\n".join(base64.b64encode(bytes(R.randrange(256) for _ in range(48))).decode() for _ in range(6))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
def pw():       return R.choice(["hunter2", "Sup3rS3cret!", "P@ssw0rd2024", "letmein_9x", "Tr0ub4dor&3"]) + rs(3)

# kind -> (variable name, value maker)
KINDS = {"aws": ("AWS_ACCESS_KEY_ID", aws), "ghp": ("GITHUB_TOKEN", ghp), "slack": ("SLACK_BOT_TOKEN", slack),
         "pkey": ("PRIVATE_KEY", pkey), "jwt": ("AUTH_TOKEN", jwt), "password": ("DB_PASSWORD", pw)}
FORMATS = ["py", "env", "yaml", "json", "sh", "txt"]


def render(fmt, name, val):
    if fmt == "py":
        v = val.replace("\n", "\\n")
        return f'import os\n\n\ndef connect():\n    host = os.environ.get("HOST", "db.internal")\n    {name.lower()} = "{v}"\n    return host, {name.lower()}\n'
    if fmt == "env":
        return f'APP_ENV=production\nPORT=8080\n{name}="{val}"\nLOG_LEVEL=info\n'.replace("\n-----", "\\n-----") if "\n" not in val else f'APP_ENV=production\n{name}="{val.replace(chr(10), "\\n")}"\n'
    if fmt == "yaml":
        ind = "\n".join("    " + l for l in val.split("\n"))
        return f"service:\n  name: api\n  replicas: 2\n  {name.lower()}: |\n{ind}\n" if "\n" in val else f"service:\n  name: api\n  replicas: 2\n  {name.lower()}: {val}\n"
    if fmt == "json":
        return json.dumps({"service": "api", "retries": 3, name.lower(): val}, indent=2) + "\n"
    if fmt == "sh":
        return f'#!/bin/sh\nset -e\necho starting\nexport {name}="{val}"\nexec ./run.sh\n' if "\n" not in val else f"#!/bin/sh\ncat > key.pem <<EOF\n{val}\nEOF\n"
    return f"deploy notes\n============\nremember to rotate:\n{name} = {val}\n"


def decoys():
    """(name, value) pairs that look secret-ish but are not; rendered in the same 6 formats as the planted files."""
    h = lambda: hashlib.sha256(rs(10).encode()).hexdigest()
    lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    return [
        lambda: ("COMMIT", R.randbytes(20).hex()), lambda: ("CHECKSUM_SHA256", h()), lambda: ("ETAG", hashlib.md5(rs(10).encode()).hexdigest()),
        lambda: ("REQUEST_ID", str(uuid.UUID(int=R.getrandbits(128)))),
        lambda: ("ICON", "data:image/png;base64," + base64.b64encode(bytes(R.randrange(256) for _ in range(90))).decode()),
        lambda: ("DESCRIPTION", lorem), lambda: ("VERSION", f"{R.randrange(9)}.{R.randrange(30)}.{R.randrange(99)}"),
        lambda: ("PASSWORD_FIELD", "password"), lambda: ("USER_PASSWORD_MIN_LENGTH", "12"),
        lambda: ("TOKEN_URL", "https://auth.example.com/oauth/token"),
        lambda: ("INTEGRITY", "sha512-" + base64.b64encode(R.randbytes(64)).decode()), lambda: ("SESSION_ID", rs(12, string.digits))]


def main(out: Path):
    sec, dec = out / "secrets" / "planted", out / "secrets" / "decoys"
    sec.mkdir(parents=True, exist_ok=True); dec.mkdir(parents=True, exist_ok=True)
    truth, i = {}, 0
    for kind, (name, mk) in KINDS.items():
        for k in range(10):
            fmt = FORMATS[(i + k) % len(FORMATS)]
            val = mk(); text = render(fmt, name, val)
            fn = f"{kind}_{k:02d}.{ 'env' if fmt=='env' else fmt}"
            if fmt == "env": fn = f"{kind}_{k:02d}.env"
            (sec / fn).write_text(text)
            line = next(n + 1 for n, l in enumerate(text.splitlines()) if val.split("\n")[0][:20] in l)
            truth[fn] = {"kind": kind, "line": line}
        i += 1
    ds = decoys()
    for k in range(60):
        fmt = FORMATS[(k + k // 12) % len(FORMATS)]
        name, val = ds[k % len(ds)]()
        (dec / f"decoy_{k:02d}.{fmt}").write_text(render(fmt, name, val))
    # dataset (jsonl) variants: 15 planted records files + 15 decoys
    dsd = out / "secrets_ds"; (dsd).mkdir(exist_ok=True)
    recs = []
    for n, (kind, (name, mk)) in enumerate(list(KINDS.items()) * 3):
        v = mk().replace("\n", "\\n")
        recs.append({"id": n, "text": f"please use {name} = {v} for the deploy", "planted": kind})
    (dsd / "planted.jsonl").write_text("\n".join(json.dumps(r) for r in recs[:15]) + "\n")
    drecs = [{"id": n, "text": f"build {R.randbytes(16).hex()} released, id {uuid.UUID(int=R.getrandbits(128))}, v1.2.{n}. {lorem_}"} for n, lorem_ in enumerate(["Lorem ipsum dolor sit amet."] * 15)]
    (dsd / "decoys.jsonl").write_text("\n".join(json.dumps(r) for r in drecs) + "\n")
    (out / "secrets" / "truth.json").write_text(json.dumps(truth, indent=1))
    return truth


if __name__ == "__main__":
    main(Path(sys.argv[1]))
