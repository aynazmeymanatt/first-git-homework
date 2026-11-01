"""Run against the actual proxy + go-httpbin after Docker Compose starts."""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
import jwt


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    key_path = Path(os.getenv("JWT_SECRET_FILE", str(Path(__file__).resolve().parents[1] / "secrets/jwt_secret.txt")))
    key = key_path.read_text(encoding="utf-8").strip()
    now = int(time.time())
    claims = {"sub": "student", "iss": os.getenv("JWT_ISSUER", "http-lab"),
              "aud": os.getenv("JWT_AUDIENCE", "legacy-api"), "iat": now, "exp": now + 300}
    good = jwt.encode(claims, key, algorithm="HS256")
    expired = jwt.encode({**claims, "exp": now - 60}, key, algorithm="HS256")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(path, credential=None, data=None, method="GET", extra=None):
        headers = {"Authorization": "Bearer " + credential} if credential else {}
        headers.update(extra or {})
        req = urllib.request.Request(args.url.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    checks = 0
    for label, value in [("missing", None), ("invalid", "not-a-jwt"), ("expired", expired)]:
        status, _, _ = request("/get", value)
        assert status == 401, (label, status)
        print("PASS: " + label + " credential => 401")
        checks += 1
    status, _, body = request("/get?course=ie&item=1&item=2", good)
    assert status == 200, status
    payload = json.loads(body)
    assert payload["args"]["item"] == ["1", "2"], payload
    headers = {k.lower(): v for k, v in payload["headers"].items()}
    assert "authorization" not in headers, "JWT leaked to legacy service"
    assert headers["x-authenticated-user"] == ["student"], headers
    print("PASS: valid JWT, duplicate query, trusted identity and token stripping")
    checks += 1
    data = b'{"message":"hello"}'
    status, _, body = request("/post", good, data, "POST", {"Content-Type": "application/json"})
    assert status == 200 and json.loads(body)["json"] == {"message": "hello"}
    print("PASS: POST JSON body reaches go-httpbin")
    checks += 1
    status, _, _ = request("/status/418", good)
    assert status == 418, status
    print("PASS: legacy HTTP status is preserved")
    checks += 1
    status, headers, _ = request("/redirect-to?url=/get&status_code=302", good)
    assert status == 302 and headers.get("Location") == "/get", (status, headers)
    print("PASS: redirect returned without proxy following it")
    checks += 1
    print(f"All {checks} live smoke checks passed.")


if __name__ == "__main__":
    main()
