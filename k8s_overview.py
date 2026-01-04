#!/usr/bin/env python3
"""k8s_overview.py

Small CLI to inspect a Kubernetes cluster and run simple network/SSL probes.

"""
import argparse
import socket
import ssl
import sys
import time
from typing import Optional

import dns.resolver
import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from colorama import init as colorama_init, Fore, Style

# Initialize colorama for Windows terminals
colorama_init(autoreset=True)


def load_clients():
    """Load kube config (local) or in-cluster config and return API clients."""
    try:
        config.load_kube_config()
        print("Loaded kube config from local kubeconfig")
    except Exception:
        try:
            config.load_incluster_config()
            print("Loaded in-cluster kube config")
        except Exception as e:
            print("Failed to load kube config:", e)
            sys.exit(1)

    v1 = client.CoreV1Api()
    apps = client.AppsV1Api()
    net = client.NetworkingV1Api()
    rbac = client.RbacAuthorizationV1Api()
    version_api = client.VersionApi()
    return v1, apps, net, rbac, version_api


def get_node_metrics():
    """Fetch node metrics from metrics.k8s.io API (metrics-server). Returns a dict of nodeName -> (cpu_millicores, mem_bytes) or None if unavailable."""
    try:
        from kubernetes import client, config
        api = client.CustomObjectsApi()
        metrics = api.list_cluster_custom_object(
            group="metrics.k8s.io",
            version="v1beta1",
            plural="nodes"
        )
        usage = {}
        for item in metrics["items"]:
            name = item["metadata"]["name"]
            cpu = item["usage"]["cpu"]
            mem = item["usage"]["memory"]
            # Convert cpu (e.g. '123m') to millicores
            if cpu.endswith('n'):
                cpu_m = int(cpu[:-1]) / 1_000_000
            elif cpu.endswith('u'):
                cpu_m = int(cpu[:-1]) / 1_000
            elif cpu.endswith('m'):
                cpu_m = int(cpu[:-1])
            else:
                cpu_m = int(cpu)
            # Convert memory (e.g. '123456Ki', '123Mi') to bytes
            if mem.endswith('Ki'):
                mem_b = int(mem[:-2]) * 1024
            elif mem.endswith('Mi'):
                mem_b = int(mem[:-2]) * 1024 * 1024
            elif mem.endswith('Gi'):
                mem_b = int(mem[:-2]) * 1024 * 1024 * 1024
            elif mem.endswith('Ti'):
                mem_b = int(mem[:-2]) * 1024 * 1024 * 1024 * 1024
            else:
                mem_b = int(mem)
            usage[name] = (cpu_m, mem_b)
        return usage
    except Exception as e:
        print("Warning: Could not fetch node metrics (metrics-server not installed?):", e)
        return None


def cluster_overview(v1: client.CoreV1Api, apps: client.AppsV1Api, net: client.NetworkingV1Api):
    print("\n== Nodes ==")
    nodes = v1.list_node().items
    node_metrics = get_node_metrics()
    for n in nodes:
        name = n.metadata.name
        status = [c.type for c in n.status.conditions if c.status == 'True']
        roles = ','.join([t for t in (n.metadata.labels or {}).keys() if t.startswith('node-role.kubernetes.io')])
        metrics_str = ""
        if node_metrics and name in node_metrics:
            cpu_m, mem_b = node_metrics[name]
            metrics_str = f" | cpu: {cpu_m}m mem: {mem_b//(1024*1024)}Mi"
        print(f"- {name} roles={roles or 'none'} ready_conditions={status}{metrics_str}")

    print("\n== Namespaces & Pod counts ==")
    for ns in v1.list_namespace().items:
        ns_name = ns.metadata.name
        pods = v1.list_namespaced_pod(ns_name).items
        print(f"- {ns_name}: pods={len(pods)}")

        # list each pod with a colored status
        for p in pods:
            pod_name = p.metadata.name
            phase = (p.status.phase or '').capitalize()

            # determine detailed status (check container states)
            pod_color = Fore.YELLOW
            detailed = phase
            try:
                cs = p.status.container_statuses or []
                # check for CrashLoopBackOff or terminated non-zero exit codes
                problem = False
                for c in cs:
                    st = getattr(c, 'state', None)
                    if st is None:
                        continue
                    waiting = getattr(st, 'waiting', None)
                    terminated = getattr(st, 'terminated', None)
                    if waiting is not None:
                        reason = getattr(waiting, 'reason', '') or ''
                        detailed = f"{phase} ({reason})" if reason else detailed
                        if 'CrashLoopBackOff' in reason or 'CrashLoop' in reason or 'Error' in reason:
                            problem = True
                    if terminated is not None:
                        exit_code = getattr(terminated, 'exit_code', 0)
                        reason = getattr(terminated, 'reason', '') or ''
                        detailed = f"{phase} (Exit {exit_code} {reason})" if exit_code else detailed
                        if exit_code != 0:
                            problem = True

                if phase.lower() == 'running' and not problem:
                    pod_color = Fore.GREEN
                elif problem or phase.lower() in ('failed', 'error'):
                    pod_color = Fore.RED
                else:
                    pod_color = Fore.YELLOW
            except Exception:
                pod_color = Fore.YELLOW

            print(f"    - {pod_name}: {pod_color}{detailed}{Style.RESET_ALL}")


# --- Extra check functions moved to top-level ---
def api_server_version(version_api: client.VersionApi):
    try:
        v = version_api.get_code()
        print("\n== API Server Version ==")
        print(f"git_version={v.git_version} major={v.major} minor={v.minor}")
    except Exception as e:
        print(f"Failed to get API server version: {e}")

def kubelet_versions(v1: client.CoreV1Api):
    print("\n== Kubelet Versions (per node) ==")
    for n in v1.list_node().items:
        info = getattr(n.status, 'node_info', None) or {}
        kv = getattr(info, 'kubelet_version', None)
        print(f"- {n.metadata.name}: kubelet={kv}")

def service_endpoints(v1: client.CoreV1Api):
    print("\n== Service Endpoints ==")
    for ns in v1.list_namespace().items:
        ns_name = ns.metadata.name
        endpoints = v1.list_namespaced_endpoints(ns_name).items
        for ep in endpoints:
            subsets = ep.subsets or []
            addresses = []
            for s in subsets:
                for a in (s.addresses or []):
                    addresses.append(a.ip)
            if addresses:
                print(f"- {ns_name}/{ep.metadata.name}: {len(addresses)} addresses -> {addresses}")

def list_events(v1: client.CoreV1Api, limit: int = 20):
    print("\n== Recent cluster events ==")
    try:
        ev = v1.list_event_for_all_namespaces().items
        ev_sorted = sorted(ev, key=lambda e: getattr(e, 'last_timestamp', getattr(e.metadata, 'creation_timestamp', None)) or '', reverse=True)
        for e in ev_sorted[:limit]:
            ts = getattr(e, 'last_timestamp', None) or getattr(e.metadata, 'creation_timestamp', None)
            print(f"- [{ts}] {e.metadata.namespace}/{e.involved_object.kind} {e.involved_object.name}: {e.message} (type={e.type})")
    except Exception as e:
        print(f"Failed to list events: {e}")

def pvc_summary(v1: client.CoreV1Api):
    print("\n== PVC Summary ==")
    for ns in v1.list_namespace().items:
        ns_name = ns.metadata.name
        try:
            pvcs = v1.list_namespaced_persistent_volume_claim(ns_name).items
        except Exception:
            pvcs = []
        for p in pvcs:
            vol = p.spec.volume_name
            status = p.status.phase
            req = None
            for k, v in (p.spec.resources.requests or {}).items():
                req = f"{k}={v}"
            print(f"- {ns_name}/{p.metadata.name}: status={status} volume={vol} requests={req}")

def rbac_summary(rbac: client.RbacAuthorizationV1Api, v1: client.CoreV1Api):
    print("\n== RBAC Summary ==")
    try:
        crs = rbac.list_cluster_role().items
        crbs = rbac.list_cluster_role_binding().items
        print(f"ClusterRoles: {len(crs)} ClusterRoleBindings: {len(crbs)}")
    except Exception as e:
        print(f"Failed to list cluster-level RBAC: {e}")

    print("\nNamespace Roles/RoleBindings (counts per namespace):")
    for ns in v1.list_namespace().items:
        ns_name = ns.metadata.name
        try:
            rs = rbac.list_namespaced_role(ns_name).items
            rbs = rbac.list_namespaced_role_binding(ns_name).items
            if rs or rbs:
                print(f"- {ns_name}: roles={len(rs)} roleBindings={len(rbs)}")
        except Exception:
            continue


    def list_events(v1: client.CoreV1Api, limit: int = 20):
        print("\n== Recent cluster events ==")
        try:
            ev = v1.list_event_for_all_namespaces().items
            # sort by lastTimestamp if available
            ev_sorted = sorted(ev, key=lambda e: getattr(e, 'last_timestamp', getattr(e, 'metadata', {}).get('creation_timestamp', None)) or '', reverse=True)
            for e in ev_sorted[:limit]:
                ts = getattr(e, 'last_timestamp', None) or getattr(e.metadata, 'creation_timestamp', None)
                print(f"- [{ts}] {e.metadata.namespace}/{e.involved_object.kind} {e.involved_object.name}: {e.message} (type={e.type})")
        except Exception as e:
            print(f"Failed to list events: {e}")


    def pvc_summary(v1: client.CoreV1Api):
        print("\n== PVC Summary ==")
        for ns in v1.list_namespace().items:
            ns_name = ns.metadata.name
            try:
                pvcs = v1.list_namespaced_persistent_volume_claim(ns_name).items
            except Exception:
                pvcs = []
            for p in pvcs:
                vol = p.spec.volume_name
                status = p.status.phase
                req = None
                for k, v in (p.spec.resources.requests or {}).items():
                    req = f"{k}={v}"
                print(f"- {ns_name}/{p.metadata.name}: status={status} volume={vol} requests={req}")


    def rbac_summary(rbac: client.RbacAuthorizationV1Api, v1: client.CoreV1Api):
        print("\n== RBAC Summary ==")
        try:
            crs = rbac.list_cluster_role().items
            crbs = rbac.list_cluster_role_binding().items
            print(f"ClusterRoles: {len(crs)} ClusterRoleBindings: {len(crbs)}")
        except Exception as e:
            print(f"Failed to list cluster-level RBAC: {e}")

        print("\nNamespace Roles/RoleBindings (counts per namespace):")
        for ns in v1.list_namespace().items:
            ns_name = ns.metadata.name
            try:
                rs = rbac.list_namespaced_role(ns_name).items
                rbs = rbac.list_namespaced_role_binding(ns_name).items
                if rs or rbs:
                    print(f"- {ns_name}: roles={len(rs)} roleBindings={len(rbs)}")
            except Exception:
                continue


def dns_test(v1: client.CoreV1Api, name: str, nameserver: Optional[str] = None):
    """Resolve a DNS name using the cluster DNS (or given nameserver)."""
    if nameserver is None:
        try:
            svc = v1.read_namespaced_service('kube-dns', 'kube-system')
            nameserver = svc.spec.cluster_ip
            print(f"Using cluster DNS at {nameserver}")
        except Exception:
            print("Failed to find kube-dns service; using system resolver")

    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        ans = resolver.resolve(name)
        for r in ans:
            print(f"{name} -> {r}")
    except Exception as e:
        print(f"DNS resolution failed: {e}")


def tcp_connect_test(host: str, port: int, timeout: float = 5.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            print(f"TCP connect to {host}:{port} succeeded")
    except Exception as e:
        print(f"TCP connect to {host}:{port} failed: {e}")


def tls_inspect(host: str, port: int = 443, timeout: float = 5.0):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(f"Certificate for {host}:{port}:")
                for k, v in cert.items():
                    print(f"  {k}: {v}")
    except Exception as e:
        print(f"TLS inspect failed: {e}")


def create_debug_pod_and_exec(v1: client.CoreV1Api, namespace: str, command: str, timeout: int = 60):
    name = 'debug-pod-brief-{}'.format(int(time.time()))
    pod_manifest = {
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {'name': name},
        'spec': {
            'containers': [
                {
                    'name': 'debug',
                    'image': 'curlimages/curl:8.4.0',
                    'command': ['sleep', '3600'],
                }
            ],
            'restartPolicy': 'Never',
        },
    }
    try:
        v1.create_namespaced_pod(namespace=namespace, body=pod_manifest)
    except ApiException as e:
        print(f"Failed to create debug pod: {e}")
        return

    # wait for running
    for _ in range(timeout):
        pod = v1.read_namespaced_pod(name=name, namespace=namespace)
        phase = pod.status.phase
        if phase == 'Running':
            break
        if phase == 'Failed' or phase == 'Succeeded':
            break
        time.sleep(1)

    try:
        exec_cmd = ['/bin/sh', '-c', command]
        resp = stream(v1.connect_get_namespaced_pod_exec, name, namespace, command=exec_cmd, stderr=True, stdin=False, stdout=True, tty=False)
        print("--- exec output ---")
        print(resp)
    except Exception as e:
        print(f"Exec failed: {e}")
    finally:
        try:
            v1.delete_namespaced_pod(name=name, namespace=namespace)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description='Kubernetes cluster overview & debug tool')
    parser.add_argument('--overview', action='store_true', help='Show cluster overview')
    parser.add_argument('--dns-test', metavar='HOST', help='Resolve DNS name (cluster DNS if available)')
    parser.add_argument('--tcp-test', metavar='HOST:PORT', help='Test TCP connect to HOST:PORT')
    parser.add_argument('--tls-check', metavar='HOST:PORT', help='Inspect TLS cert for HOST:PORT')
    parser.add_argument('--pod-probe', metavar='URL', help='Create ephemeral pod and curl URL from inside cluster')
    parser.add_argument('--pod-namespace', default='default', help='Namespace to create debug pod in')
    parser.add_argument('--extra-checks', action='store_true', help='Run extra checks: versions, kubelet versions, endpoints, events, PVCs, RBAC')
    args = parser.parse_args()

    v1, apps, net, rbac, version_api = load_clients()

    if args.overview:
        cluster_overview(v1, apps, net)

    if getattr(args, 'extra_checks', False):
        api_server_version(version_api)
        kubelet_versions(v1)
        service_endpoints(v1)
        list_events(v1)
        pvc_summary(v1)
        rbac_summary(rbac, v1)

    if args.dns_test:
        dns_test(v1, args.dns_test)

    if args.tcp_test:
        try:
            host, port_s = args.tcp_test.rsplit(':', 1)
            port = int(port_s)
            tcp_connect_test(host, port)
        except Exception as e:
            print('Invalid tcp-test argument, expected host:port', e)

    if args.tls_check:
        try:
            host, port_s = args.tls_check.rsplit(':', 1)
            port = int(port_s)
            tls_inspect(host, port)
        except Exception as e:
            print('Invalid tls-check argument, expected host:port', e)

    if args.pod_probe:
        # run curl inside an ephemeral pod
        url = args.pod_probe
        cmd = f"curl -sSL -D - '{url}' || echo 'curl failed'"
        create_debug_pod_and_exec(v1, args.pod_namespace, cmd)


if __name__ == '__main__':
    main()
