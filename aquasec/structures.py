"""Dataclass Structures"""


from dataclasses import dataclass
from typing import List

from aquasec.exceptions import AquaSecMissingParam
from aquasec.utilities import nested_dataclass


@dataclass
class InboundNetwork:
    allow: str
    resource: str
    port_range: str
    resource_type: str
    is_cloud_metadata_rule: bool


@dataclass
class OutboundNetwork:
    allow: str
    resource: str
    port_range: str
    resource_type: str
    is_cloud_metadata_rule: bool

@nested_dataclass

class FirewallPolicy:
    author: str
    name: str
    type: str
    version: str
    # TODO: Use Nested Funcations
    inbound_networks: List[InboundNetwork]
    outbound_networks: List[OutboundNetwork]

    description: str = ""
    block_icmp_ping: bool = True
    block_metadata_service: bool = True
    # lastupdate: int = time.time() # Issue arrases if this is passed directly

    # check if the inbount and out bound arrays are fine
    def __post_init__(self):
        # TODO: Fix how this is working; possibly not need of a post_init maybe leverage nests
        if not (check_policy(self.inbound_networks) and check_policy(self.outbound_networks)):
            raise AquaSecMissingParam("incorrect rule structure")


def check_policy(rule_list: list) -> bool:
    """Check Firewall Policy is Correctly formated

    Args:
        rule_list (list): _description_

    Returns:
        bool: _description_
    """
    is_valid = True
    try:
        for rule in rule_list:
            allow = rule['allow']
            port_range = rule['port_range']
            resource = rule['resource']
            resource_type = rule['resource_type']
    except KeyError:
        is_valid = False
    return is_valid
