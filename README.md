# Kubernetes cluster debug & overview tool
Python tool that helps inspecting and debugging a Kubernetes cluster. It can:

- Show a quick cluster overview (nodes, namespaces, pods, services, ingresses, deployments).
- **Display all nodes with current CPU and memory usage (color-coded, requires metrics-server):**
  - Shows CPU and memory usage as USED/MAX and percent, with green/yellow/red coloring for low/medium/high usage.
  - If metrics-server is not installed, a warning is shown and usage is omitted.
- Test DNS resolution using the cluster DNS.
- Test TCP connectivity to hosts/ports.
- Probe connectivity from inside the cluster by creating a short-lived debug pod and running `curl`/`ping`.
- Inspect TLS/SSL certificate presented by ingress hosts.

## Requirements
- Python 3
- All Python dependencies in `requirements.txt` (install with `pip install -r requirements.txt`)
- metrics-server installed in your cluster for resource usage metrics

## Usage

## Multi-Cluster Support & Secure Access

This tool supports multiple clusters and SSH tunneling if the Kuberenetes API port on the remote machine running the cluster is not opened. All cluster and SSH info is stored in `clustros.yaml` (see below for security advice).

### Example usage

```sh
python3 clustros.py --overview --cluster dev
```

This will:
- Open an SSH tunnel if configured for the cluster (see config example below)
- Show node, namespace, and pod info, with resource usage and color-coded output


#### Cluster operations (require `--cluster`):
- `--overview` for cluster summary (nodes, pods, etc)
- `--extra-checks` for additional cluster checks (API server version, kubelet versions, endpoints, events, PVCs, RBAC, resource quotas)
- `--dns-test HOST` to test DNS resolution (via cluster DNS)
- `--pod-probe CMD` to run an arbitrary shell command from inside the cluster (e.g. `curl -k https://kubernetes.default`, `nslookup kubernetes.default.svc.cluster.local`)

#### Local checks (do not require `--cluster`):
- `--tls-check HOST:PORT` to inspect TLS certificates (from your local machine to the target host:port)

### clustros.yaml config example

See `clustros.yaml.example` for a template. Do NOT commit your real `clustros.yaml` to version control!

```yaml
clusters:
  dev:
    kubeconfig: /path/to/your/kubeconfig
    context: default
    ssh:
      user: your_ssh_user
      host: your.remote.host
      key: /path/to/your/private-key.pem
      local_port: 6443
      remote_host: localhost
      remote_port: 6443
      open_tunnel: true
```