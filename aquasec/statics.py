"""Statics"""

from aquasec.structures import FirewallPolicy


BENCH_REPORTS = ['cis', 'kube_bench', 'linux', 'openshift', 'disa_stig', 'all']

DATA_TYPES = {
    "firewall_policy": FirewallPolicy,
}
