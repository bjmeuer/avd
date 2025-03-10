# Copyright (c) 2023-2025 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pyavd._eos_designs.schema import EosDesigns
from pyavd._schema.avdschema import AvdSchema

from .cv_topology import CvTopology
from .filtered_tenants import FilteredTenantsMixin
from .flow_tracking import FlowTrackingMixin
from .inband_management import InbandManagementMixin
from .interface_descriptions import InterfaceDescriptionsMixin
from .ip_addressing import IpAddressingMixin
from .l3_interfaces import L3InterfacesMixin
from .link_tracking_groups import LinkTrackingGroupsMixin
from .mgmt import MgmtMixin
from .misc import MiscMixin
from .mlag import MlagMixin
from .node_config import NodeConfigMixin
from .node_type import NodeTypeMixin
from .node_type_keys import NodeTypeKeysMixin
from .overlay import OverlayMixin
from .platform_mixin import PlatformMixin
from .ptp import PtpMixin
from .routing import RoutingMixin
from .underlay import UnderlayMixin
from .utils import UtilsMixin
from .wan import WanMixin

if TYPE_CHECKING:
    from pyavd._eos_designs.schema import EosDesigns
    from pyavd._schema.avdschema import AvdSchema
    from pyavd.api.pool_manager import PoolManager


class SharedUtilsProtocol(
    FilteredTenantsMixin,
    InbandManagementMixin,
    InterfaceDescriptionsMixin,
    IpAddressingMixin,
    LinkTrackingGroupsMixin,
    L3InterfacesMixin,
    CvTopology,
    MgmtMixin,
    MlagMixin,
    MiscMixin,
    NodeConfigMixin,
    NodeTypeMixin,
    NodeTypeKeysMixin,
    OverlayMixin,
    PlatformMixin,
    PtpMixin,
    WanMixin,
    RoutingMixin,
    UnderlayMixin,
    UtilsMixin,
    FlowTrackingMixin,
    Protocol,
):
    """Protocol for the SharedUtils Class with commonly used methods / cached_properties to be shared between all the python modules loaded in eos_designs."""

    hostvars: dict
    inputs: EosDesigns
    templar: object
    schema: AvdSchema
    pool_manager: PoolManager | None


class SharedUtils(SharedUtilsProtocol):
    """
    Class with commonly used methods / cached_properties to be shared between all the python modules loaded in eos_designs.

    This class is instantiated in 'EosDesignsFacts' class and set as 'shared_utils' property.
    This class is also instantiated in 'eos_designs_structured_config' and the instance is given as argument to
    each python module. The base class '__init__' will set the instance as 'shared_utils' property.

    Since these methods / cached_properties will not be rendered automatically, we can avoid some of the
    general conditions and just return the value. We expect the logic that determines the relevancy of the
    value to be handled in calling function.
    """

    def __init__(self, hostvars: dict, inputs: EosDesigns, templar: object, schema: AvdSchema, pool_manager: PoolManager | None = None) -> None:
        self.hostvars = hostvars
        self.inputs = inputs
        self.templar = templar
        self.schema = schema
        self.pool_manager = pool_manager
