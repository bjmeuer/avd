from __future__ import annotations

from functools import cached_property

from .utils import UtilsMixin


class RouterBgpMixin(UtilsMixin):
    """
    Mixin Class used to generate structured config for one key.
    Class should only be used as Mixin to a AvdStructuredConfig class
    """

    @cached_property
    def router_bgp(self) -> dict | None:
        """
        Return structured config for router_bgp
        """

        if not self._underlay_bgp:
            return None

        neighbors = {}
        neighbor_interfaces = {}
        for p2p_link in self._filtered_p2p_links:
            if not (p2p_link.get("include_in_underlay_protocol", True) is True):
                continue

            neighbor = {
                "remote_as": p2p_link["data"]["peer_bgp_as"],
                "description": p2p_link["data"]["peer"],
                "peer_group": self._peer_group_ipv4_underlay_peers_name,
            }

            if self._underlay_rfc5549:
                # RFC5549

                interface = p2p_link["data"]["interface"]
                neighbor_interfaces[interface] = neighbor
                continue

            # Regular BGP Neighbors
            neighbor["bfd"] = p2p_link.get("bfd")
            if p2p_link["data"]["bgp_as"] != self._bgp_as:
                neighbor["local_as"] = p2p_link["data"]["bgp_as"]

            # Remove None values
            neighbor = {key: value for key, value in neighbor.items() if value is not None}

            neighbor_ip = p2p_link["data"]["peer_ip"].split("/")[0]
            neighbors[neighbor_ip] = neighbor

        router_bgp = {}
        if neighbors:
            router_bgp["neighbors"] = neighbors

        if neighbor_interfaces:
            router_bgp["neighbor_interfaces"] = neighbor_interfaces

        if router_bgp:
            return router_bgp

        return None