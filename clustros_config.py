import yaml
import os

class ClusterConfigError(Exception):
    pass

def load_config(config_path):
    """Load the clustros config YAML file."""
    if not os.path.exists(config_path):
        raise ClusterConfigError(f"Config file not found: {config_path}")
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def get_cluster_info(config, cluster_name):
    """Get kubeconfig path, context, and optional ssh tunnel info for a given cluster name."""
    clusters = config.get('clusters', {})
    if cluster_name not in clusters:
        raise ClusterConfigError(f"Cluster '{cluster_name}' not found in config.")
    info = clusters[cluster_name]
    kubeconfig = info.get('kubeconfig')
    context = info.get('context')
    ssh = info.get('ssh')  # May be None
    if not kubeconfig:
        raise ClusterConfigError(f"No kubeconfig specified for cluster '{cluster_name}'")
    return kubeconfig, context, ssh

# Example usage:
# config = load_config('clustros.yaml')
# kubeconfig, context = get_cluster_info(config, 'dev')
