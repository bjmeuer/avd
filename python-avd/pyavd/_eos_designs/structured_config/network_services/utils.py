# Copyright (c) 2023-2025 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.
from __future__ import annotations

import ipaddress
from functools import cached_property
from re import fullmatch as re_fullmatch
from typing import TYPE_CHECKING, Protocol

from pyavd._errors import AristaAvdError, AristaAvdInvalidInputsError, AristaAvdMissingVariableError
from pyavd._utils import default, get, get_ip_from_ip_prefix, strip_empties_from_dict
from pyavd.api.interface_descriptions import InterfaceDescriptionData
from pyavd.j2filters import natural_sort

if TYPE_CHECKING:
    from pyavd._eos_designs.schema import EosDesigns

    from . import AvdStructuredConfigNetworkServicesProtocol


class UtilsMixin(Protocol):
    """
    Mixin Class with internal functions.

    Class should only be used as Mixin to a AvdStructuredConfig class.
    """

    @cached_property
    def _local_endpoint_trunk_groups(self: AvdStructuredConfigNetworkServicesProtocol) -> set:
        return set(get(self._hostvars, "switch.local_endpoint_trunk_groups", default=[]))

    @cached_property
    def _vrf_default_evpn(self: AvdStructuredConfigNetworkServicesProtocol) -> bool:
        """Return boolean telling if VRF "default" is running EVPN or not."""
        if not (self.shared_utils.network_services_l3 and self.shared_utils.overlay_vtep and self.shared_utils.overlay_evpn):
            return False

        for tenant in self.shared_utils.filtered_tenants:
            if "default" not in tenant.vrfs:
                continue

            if "evpn" in tenant.vrfs["default"].address_families:
                if self.inputs.underlay_filter_peer_as:
                    msg = "'underlay_filter_peer_as' cannot be used while there are EVPN services in the default VRF."
                    raise AristaAvdError(msg)
                return True

        return False

    @cached_property
    def _vrf_default_ipv4_subnets(self: AvdStructuredConfigNetworkServicesProtocol) -> list[str]:
        """Return list of ipv4 subnets in VRF "default"."""
        subnets = []
        for tenant in self.shared_utils.filtered_tenants:
            if "default" not in tenant.vrfs:
                continue

            for svi in tenant.vrfs["default"].svis:
                ip_address = default(svi.ip_address, svi.ip_address_virtual)
                if ip_address is None:
                    continue

                subnet = str(ipaddress.ip_network(ip_address, strict=False))
                if subnet not in subnets:
                    subnets.append(subnet)

        return subnets

    @cached_property
    def _vrf_default_ipv4_static_routes(self: AvdStructuredConfigNetworkServicesProtocol) -> dict:
        """
        Finds static routes defined under VRF "default" and find out if they should be redistributed in underlay and/or overlay.

        Returns:
        -------
        dict
            static_routes: []
                List of ipv4 static routes in VRF "default"
            redistribute_in_underlay: bool
                Whether to redistribute static into the underlay protocol.
                True when there are any static routes this device is not an EVPN VTEP.
                Can be overridden with "vrf.redistribute_static: False".
            redistribute_in_overlay: bool
                Whether to redistribute static into overlay protocol for vrf default.
                True there are any static routes and this device is an EVPN VTEP.
                Can be overridden with "vrf.redistribute_static: False".
        """
        vrf_default_ipv4_static_routes = set()
        vrf_default_redistribute_static = True
        for tenant in self.shared_utils.filtered_tenants:
            if "default" not in tenant.vrfs:
                continue

            if not (static_routes := tenant.vrfs["default"].static_routes):
                continue

            for static_route in static_routes:
                vrf_default_ipv4_static_routes.add(static_route.destination_address_prefix)

            vrf_default_redistribute_static = default(tenant.vrfs["default"].redistribute_static, vrf_default_redistribute_static)

        if self.shared_utils.overlay_evpn and self.shared_utils.overlay_vtep:
            # This is an EVPN VTEP
            redistribute_in_underlay = False
            redistribute_in_overlay = vrf_default_redistribute_static and vrf_default_ipv4_static_routes
        else:
            # This is a not an EVPN VTEP
            redistribute_in_underlay = vrf_default_redistribute_static and vrf_default_ipv4_static_routes
            redistribute_in_overlay = False

        return {
            "static_routes": natural_sort(vrf_default_ipv4_static_routes),
            "redistribute_in_underlay": redistribute_in_underlay,
            "redistribute_in_overlay": redistribute_in_overlay,
        }

    def _mlag_ibgp_peering_enabled(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> bool:
        """
        Returns True if mlag ibgp_peering is enabled.

        For VRF default we return False unless there is no underlay routing protocol.

        False otherwise.
        """
        if not self.shared_utils.mlag_l3 or not self.shared_utils.network_services_l3:
            return False

        mlag_ibgp_peering = default(vrf.enable_mlag_ibgp_peering_vrfs, tenant.enable_mlag_ibgp_peering_vrfs)
        return bool((vrf.name != "default" or self.shared_utils.underlay_routing_protocol == "none") and mlag_ibgp_peering)

    def _mlag_ibgp_peering_vlan_vrf(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> int | None:
        """
        MLAG IBGP Peering VLANs per VRF.

        Performs all relevant checks if MLAG IBGP Peering is enabled
        Returns None if peering is not enabled
        """
        if not self._mlag_ibgp_peering_enabled(vrf, tenant):
            return None

        if (mlag_ibgp_peering_vlan := vrf.mlag_ibgp_peering_vlan) is not None:
            vlan_id = mlag_ibgp_peering_vlan
        else:
            base_vlan = self.inputs.mlag_ibgp_peering_vrfs.base_vlan
            vrf_id = default(vrf.vrf_id, vrf.vrf_vni)
            if vrf_id is None:
                msg = f"Unable to assign MLAG VRF Peering VLAN for vrf {vrf.name}.Set either 'mlag_ibgp_peering_vlan' or 'vrf_id' or 'vrf_vni' on the VRF"
                raise AristaAvdInvalidInputsError(msg)
            vlan_id = base_vlan + vrf_id - 1

        return vlan_id

    def _exclude_mlag_ibgp_peering_from_redistribute(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> bool:
        """
        Returns True if redistribute_connected is True and MLAG IBGP Peering subnet should be _excluded_ from redistribution for the given vrf/tenant.

        Does _not_ include checks if the peering is enabled at all, so that should be checked first.
        """
        if vrf.redistribute_connected:
            return default(vrf.redistribute_mlag_ibgp_peering_vrfs, tenant.redistribute_mlag_ibgp_peering_vrfs) is False

        return False

    @cached_property
    def _configure_bgp_mlag_peer_group(self: AvdStructuredConfigNetworkServicesProtocol) -> bool:
        """
        Flag set during creating of BGP VRFs if an MLAG peering is needed.

        Decides if MLAG BGP peer-group should be configured.
        Catches cases where underlay is not BGP but we still need MLAG iBGP peering.
        """
        if self.shared_utils.underlay_bgp:
            return False

        # Checking neighbors directly under BGP to cover VRF default case.
        for neighbor_settings in get(self._router_bgp_vrfs, "neighbors", default=[]):
            if neighbor_settings.get("peer_group") == self.inputs.bgp_peer_groups.mlag_ipv4_underlay_peer.name:
                return True

        for bgp_vrf in get(self._router_bgp_vrfs, "vrfs", default=[]):
            if "neighbors" not in bgp_vrf:
                continue
            for neighbor_settings in bgp_vrf["neighbors"]:
                if neighbor_settings.get("peer_group") == self.inputs.bgp_peer_groups.mlag_ipv4_underlay_peer.name:
                    return True

        return False

    @cached_property
    def _rt_admin_subfield(self: AvdStructuredConfigNetworkServicesProtocol) -> str | None:
        """
        Return a string with the route-target admin subfield unless set to "vrf_id" or "vrf_vni" or "id".

        Returns None if not set, since the calling functions will use
        per-vlan numbers by default.
        """
        admin_subfield = self.inputs.overlay_rt_type.admin_subfield
        if admin_subfield is None:
            return None

        if admin_subfield == "bgp_as":
            return self.shared_utils.bgp_as

        if re_fullmatch(r"\d+", str(admin_subfield)):
            return admin_subfield

        return None

    def get_vlan_mac_vrf_id(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vlan: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem.SvisItem
        | EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L2vlansItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> int:
        mac_vrf_id_base = default(tenant.mac_vrf_id_base, tenant.mac_vrf_vni_base)
        if mac_vrf_id_base is None:
            msg = (
                "'rt_override' or 'vni_override' or 'mac_vrf_id_base' or 'mac_vrf_vni_base' must be set. "
                f"Unable to set EVPN RD/RT for vlan {vlan.id} in Tenant '{vlan._tenant}'"
            )
            raise AristaAvdInvalidInputsError(msg)
        return mac_vrf_id_base + vlan.id

    def get_vlan_mac_vrf_vni(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vlan: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem.SvisItem
        | EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L2vlansItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> int:
        mac_vrf_vni_base = default(tenant.mac_vrf_vni_base, tenant.mac_vrf_id_base)
        if mac_vrf_vni_base is None:
            msg = (
                "'rt_override' or 'vni_override' or 'mac_vrf_id_base' or 'mac_vrf_vni_base' must be set. "
                f"Unable to set EVPN RD/RT for vlan {vlan.id} in Tenant '{vlan._tenant}'"
            )
            raise AristaAvdInvalidInputsError(msg)
        return mac_vrf_vni_base + vlan.id

    def get_vlan_rd(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vlan: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem.SvisItem
        | EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L2vlansItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> str:
        """Return a string with the route-destinguisher for one VLAN."""
        rd_override = default(vlan.rd_override, vlan.rt_override, vlan.vni_override)

        if isinstance(rd_override, str) and ":" in rd_override:
            return rd_override

        if rd_override is not None:
            assigned_number_subfield = rd_override
        elif self.inputs.overlay_rd_type.vlan_assigned_number_subfield == "mac_vrf_vni":
            assigned_number_subfield = self.get_vlan_mac_vrf_vni(vlan, tenant)
        elif self.inputs.overlay_rd_type.vlan_assigned_number_subfield == "vlan_id":
            assigned_number_subfield = vlan.id
        else:
            assigned_number_subfield = self.get_vlan_mac_vrf_id(vlan, tenant)

        return f"{self.shared_utils.overlay_rd_type_admin_subfield}:{assigned_number_subfield}"

    def get_vlan_rt(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vlan: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem.SvisItem
        | EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L2vlansItem,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
    ) -> str:
        """Return a string with the route-target for one VLAN."""
        rt_override = default(vlan.rt_override, vlan.vni_override)

        if isinstance(rt_override, str) and ":" in rt_override:
            return rt_override

        if self._rt_admin_subfield is not None:
            admin_subfield = self._rt_admin_subfield
        elif rt_override is not None:
            admin_subfield = rt_override
        elif self.inputs.overlay_rt_type.admin_subfield == "vrf_vni":
            admin_subfield = self.get_vlan_mac_vrf_vni(vlan, tenant)
        elif self.inputs.overlay_rt_type.admin_subfield == "id":
            admin_subfield = vlan.id
        else:
            admin_subfield = self.get_vlan_mac_vrf_id(vlan, tenant)

        if rt_override is not None:
            assigned_number_subfield = rt_override
        elif self.inputs.overlay_rt_type.vlan_assigned_number_subfield == "mac_vrf_vni":
            assigned_number_subfield = self.get_vlan_mac_vrf_vni(vlan, tenant)
        elif self.inputs.overlay_rt_type.vlan_assigned_number_subfield == "vlan_id":
            assigned_number_subfield = vlan.id
        else:
            assigned_number_subfield = self.get_vlan_mac_vrf_id(vlan, tenant)

        return f"{admin_subfield}:{assigned_number_subfield}"

    @cached_property
    def _vrf_rt_admin_subfield(self: AvdStructuredConfigNetworkServicesProtocol) -> str | None:
        """
        Return a string with the VRF route-target admin subfield unless set to "vrf_id" or "vrf_vni" or "id".

        Returns None if not set, since the calling functions will use
        per-vrf numbers by default.
        """
        admin_subfield: str = default(self.inputs.overlay_rt_type.vrf_admin_subfield, self.inputs.overlay_rt_type.admin_subfield)
        if admin_subfield == "bgp_as":
            return self.shared_utils.bgp_as

        if re_fullmatch(r"\d+", admin_subfield):
            return admin_subfield

        return None

    def get_vrf_rd(
        self: AvdStructuredConfigNetworkServicesProtocol, vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem
    ) -> str:
        """Return a string with the route-destinguisher for one VRF."""
        rd_override = vrf.rd_override

        if rd_override is not None:
            if ":" in rd_override:
                return rd_override

            return f"{self.shared_utils.overlay_rd_type_vrf_admin_subfield}:{rd_override}"

        return f"{self.shared_utils.overlay_rd_type_vrf_admin_subfield}:{self.shared_utils.get_vrf_id(vrf)}"

    def get_vrf_rt(
        self: AvdStructuredConfigNetworkServicesProtocol, vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem
    ) -> str:
        """Return a string with the route-target for one VRF."""
        rt_override = vrf.rt_override

        if rt_override is not None and ":" in rt_override:
            return rt_override

        if self._vrf_rt_admin_subfield is not None:
            admin_subfield = self._vrf_rt_admin_subfield
        elif default(self.inputs.overlay_rt_type.vrf_admin_subfield, self.inputs.overlay_rt_type.admin_subfield) == "vrf_vni":
            admin_subfield = self.shared_utils.get_vrf_vni(vrf)
        else:
            # Both for 'id' and 'vrf_id' options.
            admin_subfield = self.shared_utils.get_vrf_id(vrf)

        if rt_override is not None:
            return f"{admin_subfield}:{rt_override}"

        return f"{admin_subfield}:{self.shared_utils.get_vrf_id(vrf)}"

    def get_vlan_aware_bundle_rd(
        self: AvdStructuredConfigNetworkServicesProtocol,
        id: int,  # noqa: A002
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
        is_vrf: bool,
        rd_override: str | None = None,
    ) -> str:
        """Return a string with the route-destinguisher for one VLAN Aware Bundle."""
        admin_subfield = self.shared_utils.overlay_rd_type_vrf_admin_subfield if is_vrf else self.shared_utils.overlay_rd_type_admin_subfield

        if rd_override is not None:
            if ":" in str(rd_override):
                return rd_override

            return f"{admin_subfield}:{rd_override}"

        bundle_number = id + tenant.vlan_aware_bundle_number_base
        return f"{admin_subfield}:{bundle_number}"

    def get_vlan_aware_bundle_rt(
        self: AvdStructuredConfigNetworkServicesProtocol,
        id: int,  # noqa: A002
        vni: int,
        tenant: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem,
        is_vrf: bool,
        rt_override: str | None = None,
    ) -> str:
        """Return a string with the route-target for one VLAN Aware Bundle."""
        if rt_override is not None and ":" in str(rt_override):
            return rt_override

        bundle_number = id + tenant.vlan_aware_bundle_number_base

        if is_vrf and self._vrf_rt_admin_subfield is not None:
            admin_subfield = self._vrf_rt_admin_subfield
        elif is_vrf and default(self.inputs.overlay_rt_type.vrf_admin_subfield, self.inputs.overlay_rt_type.admin_subfield) == "vrf_vni":
            admin_subfield = vni
        else:
            # Both for 'id' and 'vrf_id' options.
            admin_subfield = bundle_number

        if rt_override is not None:
            return f"{admin_subfield}:{rt_override}"

        return f"{admin_subfield}:{bundle_number}"

    def get_vrf_router_id(
        self: AvdStructuredConfigNetworkServicesProtocol,
        vrf: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.VrfsItem,
        router_id: str,
        tenant_name: str,
    ) -> str | None:
        """
        Determine the router ID for a given VRF based on its configuration.

        Args:
            vrf: The VRF object containing OSPF/BGP and vtep_diagnostic details.
            router_id: The router ID type specified for the VRF (e.g., "vtep_diagnostic", "main_router_id", "none", or an IPv4 address).
            tenant_name: The name of the tenant to which the VRF belongs.

        Returns:
            The resolved router ID as a string, or None if the router ID is not applicable.

        Raises:
            AristaAvdInvalidInputsError: If required configuration for "vtep_diagnostic" router ID is missing.
        """
        # Handle "vtep_diagnostic" router ID case
        if router_id == "diagnostic_loopback":
            # Validate required configuration
            if (interface_data := self._get_vtep_diagnostic_loopback_for_vrf(vrf)) is None:
                msg = (
                    f"Invalid configuration on VRF '{vrf.name}' in Tenant '{tenant_name}'. "
                    "'vtep_diagnostic.loopback' along with either 'vtep_diagnostic.loopback_ip_pools' or 'vtep_diagnostic.loopback_ip_range' must be defined "
                    "when 'router_id' is set to 'diagnostic_loopback' on the VRF."
                )
                raise AristaAvdInvalidInputsError(msg)
            # Resolve router ID from loopback interface
            return get_ip_from_ip_prefix(interface_data["ip_address"])
        if router_id == "main_router_id":
            return self.shared_utils.router_id if not self.inputs.use_router_general_for_router_id else None
        # Handle "none" router ID
        if router_id == "none":
            return None

        # Default to the specified router ID
        return router_id

    # only being called for l3_port_channel which is not a sub-interface
    def _get_l3_port_channel_member_ports_cfg(
        self: AvdStructuredConfigNetworkServicesProtocol,
        l3_port_channel: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L3PortChannelsItem,
    ) -> list:
        """Returns structured_configuration (list of ethernet interfaces) representing member ports for one L3 Port-Channel."""
        ethernet_interfaces = []
        channel_group_id = l3_port_channel.name.split("Port-Channel")[-1]
        for member_intf in l3_port_channel.member_interfaces:
            interface_description = member_intf.description
            # derive values for peer from parent L3 port-channel
            # if not defined explicitly for member interface
            peer = member_intf.peer if member_intf.peer else l3_port_channel.peer
            if not interface_description:
                interface_description = self.shared_utils.interface_descriptions.underlay_ethernet_interface(
                    InterfaceDescriptionData(
                        shared_utils=self.shared_utils,
                        interface=member_intf.name,
                        peer=peer,
                        peer_interface=member_intf.peer_interface,
                    ),
                )
            ethernet_interface = {
                "name": member_intf.name,
                "description": interface_description,
                "peer_type": "l3_port_channel_member",
                "peer": peer,
                "peer_interface": member_intf.peer_interface,
                "shutdown": not l3_port_channel.enabled,
                "speed": member_intf.speed if member_intf.speed else None,
                "channel_group": {
                    "id": int(channel_group_id),
                    "mode": l3_port_channel.mode,
                },
            }
            if member_intf.structured_config:
                self.custom_structured_configs.nested.ethernet_interfaces.obtain(member_intf.name)._deepmerge(
                    member_intf.structured_config, list_merge=self.custom_structured_configs.list_merge_strategy
                )
            ethernet_interfaces.append(strip_empties_from_dict(ethernet_interface))
        return ethernet_interfaces

    def _get_l3_port_channel_cfg(
        self: AvdStructuredConfigNetworkServicesProtocol,
        l3_port_channel: EosDesigns._DynamicKeys.DynamicNetworkServicesItem.NetworkServicesItem.L3PortChannelsItem,
        node_index: int,
        vrf_name: str,
        vrf_ospf_enabled: bool,
    ) -> dict:
        """Returns structured_configuration for one L3 Port-Channel."""
        node_type_in_schema = "l3_port_channels"

        interface = {
            "name": l3_port_channel.name,
            "peer": l3_port_channel.peer,
            "mtu": l3_port_channel.mtu if self.shared_utils.platform_settings.feature_support.per_interface_mtu else None,
            "shutdown": not l3_port_channel.enabled,
            "switchport": {"enabled": False if "." not in l3_port_channel.name else None},
            "eos_cli": l3_port_channel.raw_eos_cli,
            "flow_tracker": self.shared_utils.get_flow_tracker(l3_port_channel.flow_tracking),
        }

        if vrf_name != "default":
            interface["vrf"] = vrf_name

        if l3_port_channel.ospf.enabled and vrf_ospf_enabled:
            interface["ospf_area"] = l3_port_channel.ospf.area
            interface["ospf_network_point_to_point"] = l3_port_channel.ospf.point_to_point
            interface["ospf_cost"] = l3_port_channel.ospf.cost
            ospf_authentication = l3_port_channel.ospf.authentication
            if ospf_authentication == "simple" and (ospf_simple_auth_key := l3_port_channel.ospf.simple_auth_key) is not None:
                interface["ospf_authentication"] = ospf_authentication
                interface["ospf_authentication_key"] = ospf_simple_auth_key
            elif ospf_authentication == "message-digest" and (ospf_message_digest_keys := l3_port_channel.ospf.message_digest_keys) is not None:
                ospf_keys = []
                for ospf_key in ospf_message_digest_keys:
                    if not (ospf_key.id and ospf_key.key):
                        continue

                    ospf_keys.append(
                        {
                            "id": ospf_key.id,
                            "hash_algorithm": ospf_key.hash_algorithm,
                            "key": ospf_key.key,
                        },
                    )

                if ospf_keys:
                    interface["ospf_authentication"] = ospf_authentication
                    interface["ospf_message_digest_keys"] = ospf_keys

        ip_address = None
        if l3_port_channel.ip_addresses:
            ip_address = l3_port_channel.ip_addresses[node_index]
        if ip_address:
            interface["ip_address"] = ip_address

        is_subinterface = "." in l3_port_channel.name
        if is_subinterface:
            interface["encapsulation_dot1q"] = {"vlan": default(l3_port_channel.encapsulation_dot1q_vlan, int(l3_port_channel.name.split(".", maxsplit=1)[-1]))}
            if not l3_port_channel.ip_address:
                msg = f"{self.shared_utils.node_type_key_data.key}.nodes[name={self.shared_utils.hostname}].{node_type_in_schema}"
                msg += f"[name={l3_port_channel.name}].ip_address"
                raise AristaAvdMissingVariableError(msg)

        interface_description = (
            l3_port_channel.description
            if not isinstance(node_index, int)
            else l3_port_channel.descriptions[node_index]
            if l3_port_channel.descriptions
            else None
        )
        if not interface_description:
            interface_description = self.shared_utils.interface_descriptions.underlay_port_channel_interface(
                InterfaceDescriptionData(
                    shared_utils=self.shared_utils,
                    interface=l3_port_channel.name,
                    peer=l3_port_channel.peer,
                    peer_interface=l3_port_channel.peer_port_channel,
                ),
            )
        interface["description"] = interface_description
        interface["peer_type"] = "l3_port_channel"
        interface["peer_interface"] = l3_port_channel.peer_port_channel
        # speed is not applicable for port-channel, hence not set

        if l3_port_channel.structured_config:
            self.custom_structured_configs.nested.port_channel_interfaces.obtain(l3_port_channel.name)._deepmerge(
                l3_port_channel.structured_config, list_merge=self.custom_structured_configs.list_merge_strategy
            )

        if self._l3_interface_acls is not None:
            interface.update(
                {
                    "access_group_in": get(self._l3_interface_acls, f"{l3_port_channel.name}..ipv4_acl_in..name", separator=".."),
                    "access_group_out": get(self._l3_interface_acls, f"{l3_port_channel.name}..ipv4_acl_out..name", separator=".."),
                },
            )

        return strip_empties_from_dict(interface)
