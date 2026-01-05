# Kubernetes cluster debug & overview tool

This small Python tool helps inspect and debug a Kubernetes cluster. It can:

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

This tool supports multiple clusters and SSH tunneling for secure API access. All cluster and SSH info is stored in `clustros.yaml` (see below for security advice).

### Example usage

```sh
python3 clustros.py --overview --cluster dev
```

This will:
- Open an SSH tunnel if configured for the cluster (see config example below)
- Show node, namespace, and pod info, with resource usage and color-coded output

Other flags:
- `--extra-checks` for additional cluster checks (API server version, kubelet versions, endpoints, events, PVCs, RBAC)
- `--dns-test HOST` to test DNS resolution
- `--tcp-test HOST:PORT` to test TCP connectivity
- `--tls-check HOST:PORT` to inspect TLS certificates
- `--pod-probe URL` to run a curl from inside the cluster

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