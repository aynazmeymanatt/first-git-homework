import gzip
import time
import unittest
import httpx
import jwt
from proxy.app import Proxy, Settings, end_to_end

KEY = "test-only-not-a-deployment-key-" + "a" * 40


def token(**changes):
    now = int(time.time())
    claims = {"sub": "student", "iss": "http-lab", "aud": "legacy-api", "iat": now, "exp": now + 300}
    claims.update(changes)
    return jwt.encode(claims, KEY, algorithm="HS256")


class Chunks(httpx.AsyncByteStream):
    def __init__(self, data):
        self.data, self.closed = data, False
    async def __aiter__(self):
        yield self.data[:3]
        yield self.data[3:]
    async def aclose(self):
        self.closed = True


class ProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.calls = []
        self.status = 200
        self.headers = [("content-type", "application/json")]
        self.data = b'{"ok":true}'
        self.error = None
        async def backend(request):
            self.calls.append(request)
            if self.error:
                raise self.error
            self.stream = Chunks(self.data)
            return httpx.Response(self.status, headers=self.headers, stream=self.stream)
        self.upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend), follow_redirects=False)
        self.app = Proxy(Settings(KEY, upstream="http://legacy:8081"), self.upstream)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://proxy")
    async def asyncTearDown(self):
        await self.client.aclose()
        await self.upstream.aclose()
    def auth(self, value=None):
        return {"Authorization": "Bearer " + (token() if value is None else value)}

    async def test_missing_token_never_contacts_backend(self):
        r = await self.client.get("/get")
        self.assertEqual(r.status_code, 401)
        self.assertTrue(r.headers["www-authenticate"].startswith("Bearer"))
        self.assertEqual(self.calls, [])

    async def test_invalid_claims_and_signatures_are_rejected(self):
        bad = ["garbage", token(exp=int(time.time())-5), token(aud="wrong"), token(iss="wrong"),
               token(nbf=int(time.time())+100), token(iat=int(time.time())+100),
               token(sub="bad\r\nheader"), token(sub=""), token(sub=7), token(exp=None), token(exp={})]
        for missing in ["exp", "iat", "iss", "aud", "sub"]:
            claims = jwt.decode(token(), KEY, algorithms=["HS256"], audience="legacy-api")
            del claims[missing]
            bad.append(jwt.encode(claims, KEY, algorithm="HS256"))
        claims = {"sub": "student", "exp": int(time.time()) + 100}
        bad += [jwt.encode(claims, "wrong-key" * 10, algorithm="HS256"),
                jwt.encode(claims, "", algorithm="none"), jwt.encode(claims, KEY, algorithm="HS384")]
        valid = token()
        bad.append(valid[:10] + ("A" if valid[10] != "A" else "B") + valid[11:])
        for value in bad:
            with self.subTest(token=value[:15]):
                r = await self.client.get("/get", headers=self.auth(value))
                self.assertEqual(r.status_code, 401)
        self.assertEqual(self.calls, [])

    async def test_wrong_scheme_and_duplicate_credentials(self):
        for headers in [[], [("Authorization", "Basic abc")], [("Authorization", "Bearer")],
                        [("Authorization", "Bearer " + token())]*2,
                        [("Authorization", "Bearer " + "x"*9000)]]:
            r = await self.client.get("/", headers=headers)
            self.assertEqual(r.status_code, 401)
        self.assertEqual(self.calls, [])

    async def test_get_query_and_auth_header_stripping(self):
        r = await self.client.get("/anything/a%20b?x=1&x=2&name=%D8%B3", headers=self.auth())
        self.assertEqual(r.status_code, 200)
        req = self.calls[0]
        self.assertEqual((req.url.host, req.url.port), ("legacy", 8081))
        self.assertEqual(req.url.raw_path, b"/anything/a%20b?x=1&x=2&name=%D8%B3")
        self.assertNotIn("authorization", req.headers)
        self.assertEqual(req.headers["x-authenticated-user"], "student")
        self.assertEqual(r.headers["cache-control"], "private, no-store")
        self.assertTrue(self.stream.closed)

    async def test_methods_and_binary_request_body(self):
        body = b"\x00\xff\x80binary\r\n"
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "QUERY"]:
            r = await self.client.request(method, "/anything", content=body,
                headers={**self.auth(), "Content-Type": "application/octet-stream"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(self.calls[-1].method, method)
            self.assertEqual(self.calls[-1].content, body)
            self.assertEqual(self.calls[-1].headers["content-type"], "application/octet-stream")

    async def test_spoofed_identity_and_hop_headers(self):
        r = await self.client.get("/headers", headers={**self.auth(), "X-Authenticated-User": "admin",
            "Forwarded": "for=fake", "X-Forwarded-For": "fake", "X-Real-IP": "fake",
            "X-Forwarded-Proto": "https", "Connection": "keep-alive, X-Internal", "X-Internal": "secret"})
        self.assertEqual(r.status_code, 200)
        for name in ["forwarded", "x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-internal"]:
            self.assertNotIn(name, self.calls[0].headers)
        self.assertEqual(self.calls[0].headers["x-authenticated-user"], "student")

    async def test_redirect_is_not_followed(self):
        self.status, self.headers = 302, [("location", "https://unrelated.example/")]
        r = await self.client.get("/redirect", headers=self.auth())
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(r.headers["location"], "https://unrelated.example/")

    async def test_response_status_duplicate_cookies_and_binary(self):
        self.status, self.data = 418, b"\x00\xff\x80\x01"
        self.headers = [("set-cookie", "a=1; Path=/"), ("set-cookie", "b=2; Path=/"),
                        ("connection", "X-Remove"), ("X-Remove", "secret")]
        r = await self.client.get("/anything", headers=self.auth())
        self.assertEqual(r.status_code, 418)
        self.assertEqual(r.content, self.data)
        self.assertEqual(len(r.headers.get_list("set-cookie")), 2)
        self.assertNotIn("x-remove", r.headers)

    async def test_gzip_is_forwarded_without_double_decoding(self):
        packed = gzip.compress(b"hello"*100)
        self.data = packed
        self.headers = [("content-encoding", "gzip"), ("content-length", str(len(packed)))]
        async with self.client.stream("GET", "/gzip", headers=self.auth()) as r:
            self.assertEqual(b"".join([c async for c in r.aiter_raw()]), packed)
            self.assertEqual(r.headers["content-length"], str(len(packed)))

    async def test_upstream_failure_and_timeout(self):
        for error, status in [(httpx.ConnectError("offline"), 502), (httpx.ReadTimeout("slow"), 504)]:
            self.error = error
            r = await self.client.get("/get", headers=self.auth())
            self.assertEqual(r.status_code, status)

    async def test_oversized_body_never_contacts_backend(self):
        r = await self.client.post("/post", content=b"x"*(1024*1024+1), headers=self.auth())
        self.assertEqual(r.status_code, 413)
        self.assertEqual(self.calls, [])

    async def test_head_error_and_success(self):
        r = await self.client.head("/get")
        self.assertEqual((r.status_code, r.content), (401, b""))
        self.data, self.headers = b"", [("content-length", "123")]
        r = await self.client.head("/get", headers=self.auth())
        self.assertEqual((r.status_code, r.content), (200, b""))
        self.assertEqual(r.headers["content-length"], "123")

    async def test_connect_cannot_be_used_as_open_tunnel(self):
        r = await self.client.request("CONNECT", "/", headers=self.auth())
        self.assertEqual(r.status_code, 405)
        self.assertEqual(self.calls, [])

    async def test_audience_array(self):
        r = await self.client.get("/get", headers=self.auth(token(aud=["legacy-api", "other"])))
        self.assertEqual(r.status_code, 200)


class ConfigurationTests(unittest.TestCase):
    def test_weak_key_and_invalid_upstream(self):
        for url in ["file:///etc/passwd", "http://u:p@legacy", "http://legacy/path", "http://legacy/?x=1"]:
            with self.assertRaises(ValueError):
                Settings(KEY, upstream=url)
        with self.assertRaises(ValueError):
            Settings("short")

    def test_connection_fields_case_and_duplicates(self):
        result = end_to_end([(b"Connection", b"X-Custom"), (b"x-custom", b"secret"),
                             (b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2")])
        self.assertEqual(result, [(b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")])


if __name__ == "__main__":
    unittest.main()
