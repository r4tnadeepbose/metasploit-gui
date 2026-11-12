import msgpack
import requests


def _b2s(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {_b2s(k): _b2s(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_b2s(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_b2s(v) for v in value)
    return value


class MsfRpcError(Exception):
    pass


class MsfRpcClient:
    def __init__(self, host="127.0.0.1", port=55553, uri="/api/", ssl=False, verify_ssl=True, timeout=15):
        self.host = host
        self.port = int(port)
        self.uri = uri if uri.startswith("/") else "/" + uri
        self.ssl = bool(ssl)
        self.verify_ssl = bool(verify_ssl)
        self.timeout = timeout
        self.token = None

    @property
    def base_url(self):
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}{self.uri}"

    def call(self, method, *args):
        payload = [method, *args]
        data = msgpack.packb(payload, use_bin_type=True)
        headers = {"Content-Type": "binary/message-pack"}
        try:
            resp = requests.post(
                self.base_url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl if self.ssl else False,
            )
            resp.raise_for_status()
        except Exception as e:
            raise MsfRpcError(f"RPC transport error: {e}") from e
        try:
            unpacked = msgpack.unpackb(resp.content, raw=False, strict_map_key=False)
        except Exception as e:
            raise MsfRpcError(f"Failed to decode RPC response: {e}") from e
        result = _b2s(unpacked)
        if isinstance(result, dict) and result.get("error"):
            msg = result.get("error_message") or result.get("error_string") or str(result.get("error"))
            raise MsfRpcError(msg)
        return result

    def login(self, username, password):
        result = self.call("auth.login", username, password)
        if not isinstance(result, dict) or not result.get("result") == "success":
            raise MsfRpcError(f"Authentication failed: {result}")
        self.token = result.get("token")
        return self.token

    def logout(self):
        if not self.token:
            return None
        try:
            return self.call("auth.logout", self.token)
        finally:
            self.token = None

    def _auth_call(self, method, *args):
        if not self.token:
            raise MsfRpcError("Not authenticated")
        return self.call(method, self.token, *args)

    # Core info
    def core_version(self):
        return self._auth_call("core.version")

    def module_stats(self):
        return self._auth_call("core.module_stats")

    # Modules
    def list_modules(self, mtype):
        method_map = {
            "exploit": "module.exploits",
            "auxiliary": "module.auxiliary",
            "post": "module.post",
            "payload": "module.payloads",
            "encoder": "module.encoders",
            "nop": "module.nops",
        }
        method = method_map.get(mtype, f"module.{mtype}")
        res = self._auth_call(method)
        if isinstance(res, dict):
            return res.get("modules") or []
        return res or []

    def module_info(self, mtype, mname):
        return self._auth_call("module.info", mtype, mname)

    def module_options(self, mtype, mname):
        return self._auth_call("module.options", mtype, mname)

    def module_compatible_payloads(self, mname):
        return self._auth_call("module.compatible_payloads", mname)

    def module_execute(self, mtype, mname, options):
        return self._auth_call("module.execute", mtype, mname, options or {})

    # Jobs & sessions
    def job_list(self):
        return self._auth_call("job.list")

    def job_info(self, job_id):
        return self._auth_call("job.info", str(job_id))

    def job_stop(self, job_id):
        return self._auth_call("job.stop", str(job_id))

    def session_list(self):
        return self._auth_call("session.list")

    def session_stop(self, sid):
        return self._auth_call("session.stop", str(sid))

    def session_shell_read(self, sid):
        return self._auth_call("session.shell_read", str(sid))

    def session_shell_write(self, sid, data):
        if not data.endswith("\n"):
            data += "\n"
        return self._auth_call("session.shell_write", str(sid), data)

    def console_create(self):
        return self._auth_call("console.create")

    def console_read(self, cid):
        return self._auth_call("console.read", str(cid))

    def console_write(self, cid, data):
        if not data.endswith("\n"):
            data += "\n"
        return self._auth_call("console.write", str(cid), data)

    def console_destroy(self, cid):
        return self._auth_call("console.destroy", str(cid))
