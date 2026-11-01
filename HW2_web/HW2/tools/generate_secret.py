"""Create the local signing key once. Never print the key or overwrite it."""
import os
from pathlib import Path
import secrets

path = Path(__file__).resolve().parents[1] / "secrets" / "jwt_secret.txt"
path.parent.mkdir(exist_ok=True)
# Compose mounts the individual key file; protect its host directory.
if os.name == "posix":
    os.chmod(path.parent, 0o700)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
except FileExistsError:
    print("Signing key already exists; unchanged.")
else:
    if os.name == "posix":
        os.fchmod(fd, 0o644)  # Directory is private; container can read the mounted file.
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(secrets.token_urlsafe(48) + "\n")
    print("Created secrets/jwt_secret.txt (keep private; do not commit).")
