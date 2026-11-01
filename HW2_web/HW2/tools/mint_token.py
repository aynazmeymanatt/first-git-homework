"""Administrative CLI for demo tokens; this is not a public login endpoint."""
import argparse
import os
from pathlib import Path
import sys
import time

import jwt

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--subject", default="student")
parser.add_argument("--minutes", type=int, default=15)
args = parser.parse_args()
if (not 1 <= args.minutes <= 60 or not args.subject or len(args.subject) > 128
        or any(not 33 <= ord(c) <= 126 for c in args.subject)):
    parser.error("Use an ASCII subject (1..128 characters) and a lifetime of 1..60 minutes")
key_path = Path(os.getenv("JWT_SECRET_FILE", "/run/secrets/jwt_secret"))
try:
    secret = key_path.read_text(encoding="utf-8").strip()
except OSError:
    sys.exit("Cannot read signing key. Generate the secret and run this tool in the proxy container.")
if len(secret.encode()) < 32:
    sys.exit("Signing key is too short")
now = int(time.time())
print(jwt.encode({"sub": args.subject, "iss": os.getenv("JWT_ISSUER", "http-lab"),
                  "aud": os.getenv("JWT_AUDIENCE", "legacy-api"),
                  "iat": now, "exp": now + args.minutes * 60}, secret, algorithm="HS256"))
