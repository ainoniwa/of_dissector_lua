-- =================================================
--     OpenFlow 1.3 protocol define
-- =================================================
of13_proto = Proto("of13","OpenFlow 1.3")

-- =================================================
--     OpenFlow 1.3 protocol fields define
-- =================================================
-- flags bits. Support true/false filter.
local VALS_BOOL	= {[0] = "False", [1] = "True"}

-- A.1 OpenFlow Header
version_F = ProtoField.uint8("of13.version", "Version", base.HEX)
type_F    = ProtoField.uint8("of13.type",    "Type")
length_F  = ProtoField.uint16("of13.length", "Length")
xid_F     = ProtoField.uint32("of13.xid",    "Transaction ID")

-- A.2.3.1 Flow Match Header
match_F         = ProtoField.string("of13.match",         "Flow Match Header")
match_type_F    = ProtoField.uint16("of13.match_type",    "Type")
match_length_F  = ProtoField.uint16("of13.match_length",  "Length")
match_oxm_F     = ProtoField.uint16("of13.match_oxm",     "OXM")
match_padding_F = ProtoField.string("of13.match_padding", "Padding")

-- A.2.3.2 Flow Match Fileld Structure
oxm_F         = ProtoField.string("of13.oxm",        "Flow Match Fileld Structure")
oxm_class_F   = ProtoField.uint16("of13.oxm_class",  "Match class: member class ie reserved class", base.HEX)
oxm_field_F   = ProtoField.uint8("of13.oxm_field",   "Match field within the class", base.HEX, nil, 0xfe)
oxm_hasmask_F = ProtoField.uint8("of13.oxm_hasmask", "Set if OXM include a bitmask in payload", base.HEX, VALS_BOOL, 0x01)
oxm_length_F  = ProtoField.uint8("of13.oxm_length",  "Length of OXM payload")
-- TODO: XXX
oxm_value_F   = ProtoField.string("of13.oxm_value",  "Value")

-- A.3.1 Handshake
ofp_switch_features_F              = ProtoField.string("of13.feature",              "Switch features")
ofp_switch_features_datapath_id_F  = ProtoField.uint64("of13.feature_datapath_id",  "Datapath unique ID", base.HEX)
ofp_switch_features_n_buffers_F    = ProtoField.uint32("of13.feature_n_buffers",    "Max packets buffered at once")
ofp_switch_features_n_tables_F     = ProtoField.uint8 ("of13.feature_n_tables",     "Number of tables supported by datapath")
ofp_switch_features_auxiliary_id_F = ProtoField.uint8 ("of13.feature_auxiliary_id", "Identify auxiliary connections")
ofp_switch_features_padding_F      = ProtoField.string("of13.feature_padding",      "Align to 64-bits")
ofp_switch_features_capabilities_F = ProtoField.uint32("of13.feature_capabilities", "Bitmap of support ofp_capabilities", base.HEX)
ofp_switch_features_reserved_F     = ProtoField.string("of13.feature_reserved",     "reserved")

ofp_switch_features_capabilities_flow_stats_F    = ProtoField.uint32("of13.feature_cap_flow",         "Flow statistics", base.HEX, VALS_BOOL, 0x00000001)
ofp_switch_features_capabilities_table_stats_F   = ProtoField.uint32("of13.feature_cap_table",        "Table statistics", base.HEX, VALS_BOOL, 0x00000002)
ofp_switch_features_capabilities_port_stats_F    = ProtoField.uint32("of13.feature_cap_port",         "Port statistics", base.HEX, VALS_BOOL, 0x00000004)
ofp_switch_features_capabilities_group_stats_F   = ProtoField.uint32("of13.feature_cap_group",        "Group statistics", base.HEX, VALS_BOOL, 0x00000008)
ofp_switch_features_capabilities_ip_reasm_F      = ProtoField.uint32("of13.feature_cap_ip_reasm",     "Can reassemble IP fragments", base.HEX, VALS_BOOL, 0x00000020)
ofp_switch_features_capabilities_queue_stats_F   = ProtoField.uint32("of13.feature_cap_queue",        "Queue statistics", base.HEX, VALS_BOOL, 0x00000040)
ofp_switch_features_capabilities_port_blocked_F  = ProtoField.uint32("of13.feature_cap_port_blocked", "Switch will block looping ports", base.HEX, VALS_BOOL, 0x00000100)

-- A.4.1 Packet-In Message
packet_in_F           = ProtoField.string("of13.packet_in",           "Packet-In Message")
packet_in_buffer_id_F = ProtoField.uint32("of13.packet_in_buffer_id", "Datapath ID")
packet_in_total_len_F = ProtoField.uint16("of13.packet_in_total_len", "Frame length")
packet_in_reason_F    = ProtoField.uint8("of13.packet_in_reason",     "Reason")
packet_in_table_id_F  = ProtoField.uint8("of13.packet_in_table_id",   "Table ID")
packet_in_cookie_F    = ProtoField.uint64("of13.packet_in_cookie",    "Cookie", base.HEX)
packet_in_padding_F   = ProtoField.string("of13.packet_in_padding",   "Padding")

-- =================================================
--     Enable OpenFlow 1.3 protocol fields
-- =================================================
of13_proto.fields = {
    -- A.1 OpenFlow Header
    version_F,
    type_F,
    length_F,
    xid_F,

    -- A.2.3.1 Flow Match Header
    match_F,
    match_type_F,
    match_length_F,
    match_oxm_F,
    match_padding_F,

    -- A.2.3.2 Flow Match Fileld Structure
    oxm_class_F,
    oxm_field_F,
    oxm_hasmask_F,
    oxm_length_F,
    oxm_value_F,

    -- A.3.1 Handshake
    ofp_switch_features_F,
    ofp_switch_features_datapath_id_F,
    ofp_switch_features_n_buffers_F,
    ofp_switch_features_n_tables_F,
    ofp_switch_features_auxiliary_id_F,
    ofp_switch_features_padding_F,
    ofp_switch_features_capabilities_F,
    ofp_switch_features_reserved_F,

    ofp_switch_features_capabilities_flow_stats_F,
    ofp_switch_features_capabilities_table_stats_F,
    ofp_switch_features_capabilities_port_stats_F,
    ofp_switch_features_capabilities_group_stats_F,
    ofp_switch_features_capabilities_ip_reasm_F,
    ofp_switch_features_capabilities_queue_stats_F,
    ofp_switch_features_capabilities_port_blocked_F,

    -- A.4.1 Packet-In Message
    packet_in_F,
    packet_in_buffer_id_F,
    packet_in_total_len_F,
    packet_in_reason_F,
    packet_in_table_id_F,
    packet_in_cookie_F,
    packet_in_padding_F,
}


-- =================================================
--     OpenFlow 1.3 defined value
-- =================================================

-- A.1 OpenFlow Header
ofp_type = {
    -- Immutable messages
    [0] = "OFPT_HELLO",
    [1] = "OFPT_ERROR",
    [2] = "OFPT_ECHO_REQUEST",
    [3] = "OFPT_ECHO_REPLY",
    [4] = "OFPT_EXPERIMENTER",

    -- Switch configuration messages
    [5] = "OFPT_FEATURES_REQUEST",
    [6] = "OFPT_FEATURES_REPLY",
    [7] = "OFPT_GET_CONFIG_REQUEST",
    [8] = "OFPT_GET_CONFIG_REPLY",
    [9] = "OFPT_SET_CONFIG",

    -- Asynchronous messages
    [10] = "OFPT_PACKET_IN",
    [11] = "OFPT_FLOW_REMOVED",
    [12] = "OFPT_PORT_STATUS",

    -- Controller command messages
    [13] = "OFPT_PACKET_OUT",
    [14] = "OFPT_FLOW_MOD",
    [15] = "OFPT_GROUP_MOD",
    [16] = "OFPT_PORT_MOD",
    [17] = "OFPT_TABLE_MOD",

    -- Statistics messages
    [18] = "OFPT_MULTIPART_REQUEST",
    [19] = "OFPT_MULTIPART_REPLY",

    -- Barrier messages
    [20] = "OFPT_BARRIER_REQUEST",
    [21] = "OFPT_BARRIER_REPLY",

    -- Queue Configuration messages
    [22] = "OFPT_QUEUE_GET_CONFIG_REQUEST",
    [23] = "OFPT_QUEUE_GET_CONFIG_REPLY",

    -- Controller role change request messages
    [24] = "OFPT_ROLE_REQUEST",
    [25] = "OFPT_ROLE_REPLY",

    -- Asynchronous message configuration
    [26] = "OFPT_GET_ASYNC_REQUEST",
    [27] = "OFPT_GET_ASYNC_REPLY",
    [28] = "OFPT_SET_ASYNC",

    -- Meters and rate limiters configuration messages
    [29] = "OFPT_METER_MOD",
}

ofp_port_no = {
    -- Maximum number of physical and logical switch ports.
    [0xffffff00] = "OFPP_MAX",
    -- Reserved OpenFlow Port (fake output "ports").
    -- Send the packet out the input port. This reserved port must be explicitly used in order to send back out of the input port.
    [0xfffffff8] = "OFPP_IN_PORT",
    -- Submit the packet to the first flow table NB: This destination port can only be used in packet-out messages.
    [0xfffffff9] = "OFPP_TABLE",
    -- Process with normal L2/L3 switching.
    [0xfffffffa] = "OFPP_NORMAL",
    -- All physical ports in VLAN, except input port and those blocked or link down.
    [0xfffffffb] = "OFPP_FLOOD",
    -- All physical ports except input port.
    [0xfffffffc] = "OFPP_ALL",
    -- Send to controller.
    [0xfffffffd] = "OFPP_CONTROLLER",
    -- Local openflow "port".
    [0xfffffffe] = "OFPP_LOCAL",
    -- Wildcard port used only for flow mod(delete) and flow stats requests. Selects all flows regardless of output port (including flows with no output port).
    [0xffffffff] = "OFPP_ANY",
}

ofp_port_features = {
    [0]  = "OFPPF_10MB_HD",    -- 10 Mb half-duplex rate support.
    [1]  = "OFPPF_10MB_FD",    -- 10 Mb full-duplex rate support.
    [2]  = "OFPPF_100MB_HD",   -- 100 Mb half-duplex rate support.
    [3]  = "OFPPF_100MB_FD",   -- 100 Mb full-duplex rate support.
    [4]  = "OFPPF_1GB_HD",     -- 1 Gb half-duplex rate support.
    [5]  = "OFPPF_1GB_FD",     -- 1 Gb full-duplex rate support.
    [6]  = "OFPPF_10GB_FD",    -- 10 Gb full-duplex rate support.
    [7]  = "OFPPF_40GB_FD",    -- 40 Gb full-duplex rate support.
    [8]  = "OFPPF_100GB_FD",   -- 100 Gb full-duplex rate support.
    [9]  = "OFPPF_1TB_FD",     -- 1 Tb full-duplex rate support.
    [10] = "OFPPF_OTHER",      -- Other rate", not in the list.
    [11] = "OFPPF_COPPER",     -- Copper medium.
    [12] = "OFPPF_FIBER",      -- Fiber medium.
    [13] = "OFPPF_AUTONEG",    -- Auto-negotiation.
    [14] = "OFPPF_PAUSE",      -- Pause.
    [15] = "OFPPF_PAUSE_ASYM", -- Asymmetric pause.
}

-- A.2.3.1 Flow Match Header
ofp_match_type_string = {
    [0] = "OFPMT_STANDARD",
    [1] = "OFPMT_OXM",
}

-- A.3.9 Role Request Message
ofp_controller_role = {
    [0] = "OFPCR_ROLE_NOCHANGE", -- Don’t change current role.
    [1] = "OFPCR_ROLE_EQUAL",    -- Default role, full access.
    [2] = "OFPCR_ROLE_MASTER",   -- Full access, at most one master.
    [3] = "OFPCR_ROLE_SLAVE",    -- Read-only access.
}

-- A.4.1 Packet-In Message
ofp_packet_in_reason = {
    [0] = "OFPR_NO_MATCH",    -- No matching flow (table-miss flow entry).
    [1] = "OFPR_ACTION",      -- Action explicitly output to controller.
    [2] = "OFPR_INVALID_TTL", -- Packet has invalid TTL
}

ofp_oxm_field_string = {
    [0x0000] = "OFPXMC_NXM_0", -- Backward compatibility with NXM
    [0x0001] = "OFPXMC_NXM_1", -- Backward compatibility with NXM
    [0x8000] = "OFPXMC_OPENFLOW_BASIC", -- Basic class for OpenFlow
    [0xFFFF] = "OFPXMC_EXPERIMENTER", -- Experimenter class
}

oxm_ofb_match_fields = {
    --     {Name,                  bit length, mask support}
    [0]  = {"OFPXMT_OFB_IN_PORT",          32,  nil}, -- Switch input port.
    [1]  = {"OFPXMT_OFB_IN_PHY_PORT",      32,  nil}, -- Switch physical input port.
    [2]  = {"OFPXMT_OFB_METADATA",         64, true}, -- Metadata passed between tables.
    [3]  = {"OFPXMT_OFB_ETH_DST",          48, true}, -- Ethernet destination address.
    [4]  = {"OFPXMT_OFB_ETH_SRC",          48, true}, -- Ethernet source address.
    [5]  = {"OFPXMT_OFB_ETH_TYPE",         16,  nil}, -- Ethernet frame type.
    [6]  = {"OFPXMT_OFB_VLAN_VID",         13, true}, -- VLAN id.
    [7]  = {"OFPXMT_OFB_VLAN_PCP",          3,  nil}, -- VLAN priority.
    [8]  = {"OFPXMT_OFB_IP_DSCP",           6,  nil}, -- IP DSCP (6 bits in ToS field).
    [9]  = {"OFPXMT_OFB_IP_ECN",            2,  nil}, -- IP ECN (2 bits in ToS field).
    [10] = {"OFPXMT_OFB_IP_PROTO",         8,  nil}, -- IP protocol.
    [11] = {"OFPXMT_OFB_IPV4_SRC",        32, true}, -- IPv4 source address.
    [12] = {"OFPXMT_OFB_IPV4_DST",        32, true}, -- IPv4 destination address.
    [13] = {"OFPXMT_OFB_TCP_SRC",         16,  nil}, -- TCP source port.
    [14] = {"OFPXMT_OFB_TCP_DST",         16,  nil}, -- TCP destination port.
    [15] = {"OFPXMT_OFB_UDP_SRC",         16,  nil}, -- UDP source port.
    [16] = {"OFPXMT_OFB_UDP_DST",         16,  nil}, -- UDP destination port.
    [17] = {"OFPXMT_OFB_SCTP_SRC",        16,  nil}, -- SCTP source port.
    [18] = {"OFPXMT_OFB_SCTP_DST",        16,  nil}, -- SCTP destination port.
    [19] = {"OFPXMT_OFB_ICMPV4_TYPE",      8,  nil}, -- ICMP type.
    [20] = {"OFPXMT_OFB_ICMPV4_CODE",      8,  nil}, -- ICMP code.
    [21] = {"OFPXMT_OFB_ARP_OP",          16,  nil}, -- ARP opcode.
    [22] = {"OFPXMT_OFB_ARP_SPA",         32, true}, -- ARP source IPv4 address.
    [23] = {"OFPXMT_OFB_ARP_TPA",         32, true}, -- ARP target IPv4 address.
    [24] = {"OFPXMT_OFB_ARP_SHA",         48, true}, -- ARP source hardware address.
    [25] = {"OFPXMT_OFB_ARP_THA",         48, true}, -- ARP target hardware address.
    [26] = {"OFPXMT_OFB_IPV6_SRC",       128, true}, -- IPv6 source address.
    [27] = {"OFPXMT_OFB_IPV6_DST",       128, true}, -- IPv6 destination address.
    [28] = {"OFPXMT_OFB_IPV6_FLABEL",     20, true}, -- IPv6 Flow Label
    [29] = {"OFPXMT_OFB_ICMPV6_TYPE",      8,  nil}, -- ICMPv6 type.
    [30] = {"OFPXMT_OFB_ICMPV6_CODE",      8,  nil}, -- ICMPv6 code.
    [31] = {"OFPXMT_OFB_IPV6_ND_TARGET", 128,  nil}, -- Target address for ND.
    [32] = {"OFPXMT_OFB_IPV6_ND_SLL",     48,  nil}, -- Source link-layer for ND.
    [33] = {"OFPXMT_OFB_IPV6_ND_TLL",     48,  nil}, -- Target link-layer for ND.
    [34] = {"OFPXMT_OFB_MPLS_LABEL",      20,  nil}, -- MPLS label.
    [35] = {"OFPXMT_OFB_MPLS_TC",          3,  nil}, -- MPLS TC.
    [36] = {"OFPXMT_OFP_MPLS_BOS",         1,  nil}, -- MPLS BoS bit.
    [37] = {"OFPXMT_OFB_PBB_ISID",        24, true}, -- PBB I-SID.
    [38] = {"OFPXMT_OFB_TUNNEL_ID",       64, true}, -- Logical Port Metadata.
    [39] = {"OFPXMT_OFB_IPV6_EXTHDR",      9, true}, -- IPv6 Extension Header pseudo-field
}


-- =================================================
--     OpenFlow 1.3 dissection
-- =================================================
function of13_proto.dissector(buffer, pinfo, tree)

    -- First, get the general header
    local of13_version_range = buffer(0,1)
    local of13_type_range    = buffer(1,1)
    local of13_length_range  = buffer(2,2)
    local of13_xid_range     = buffer(4,4)
    local pointer = 8

    local of13_version       = of13_version_range:uint()
    local of13_type          = of13_type_range:uint()
    local of13_length        = of13_length_range:uint()
    local of13_xid           = of13_xid_range:uint()

    -- Only dissect version is 0x04(=openflow 1.3)
    -- TODO: Before this function, place the version switching function.
    if of13_version == 0x04 then
        -- Add OpenFlow 1.3 Tree
        local of13_tree = tree:add(of13_proto, buffer(), "OpenFlow")

        -- OpenFlow 1.3 general header
        of13_tree:add(version_F, of13_version_range, of13_version):append_text(" (OpenFlow 1.3)")
        of13_tree:add(type_F, of13_type_range, of13_type):append_text(" (" .. ofp_type[of13_type] .. ")")
        of13_tree:add(length_F, of13_length_range, of13_length)
        of13_tree:add(xid_F, of13_xid_range, of13_xid)

        if ofp_type[of13_type] == "OFPT_HELLO" then
            -- A.5.1 Hello
            -- The OFPT_HELLO message has no body; that is, it consists only of an OpenFlow header.
            return
        elseif ofp_type[of13_type] == "OFPT_ERROR" then
            return
        elseif ofp_type[of13_type] == "OFPT_ECHO_REQUEST" then
            -- A.5.2 Echo Request
            --  An Echo Request message consists of an OpenFlow header
            -- plus an arbitrary-length data field. The data fieeld might be
            -- a message timestamp to check latency, various lengths to
            -- measure bandwidth, or zero-size to verify liveness between the
            -- switch and controller.
            return
        elseif ofp_type[of13_type] == "OFPT_ECHO_REPLY" then
            -- A.5.3 Echo Reply
            --  An Echo Reply message consists of an OpenFlow header plus the
            -- unmodified data field of an echo request message.
            return
        elseif ofp_type[of13_type] == "OFPT_EXPERIMENTER" then
            return
        elseif ofp_type[of13_type] == "OFPT_FEATURES_REQUEST" then
            -- A.3.1 Handshake
            --  This message does not contain a body beyond the OpenFlow header.
            return
        elseif ofp_type[of13_type] == "OFPT_FEATURES_REPLY" then
            ofp_features_reply(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
            return
        elseif ofp_type[of13_type] == "OFPT_GET_CONFIG_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_GET_CONFIG_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_SET_CONFIG" then
            return
        elseif ofp_type[of13_type] == "OFPT_PACKET_IN" then
            ofp_packet_in(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        elseif ofp_type[of13_type] == "OFPT_FLOW_REMOVED" then
            return
        elseif ofp_type[of13_type] == "OFPT_PORT_STATUS" then
            return
        elseif ofp_type[of13_type] == "OFPT_PACKET_OUT" then
            return
        elseif ofp_type[of13_type] == "OFPT_FLOW_MOD" then
            return
        elseif ofp_type[of13_type] == "OFPT_GROUP_MOD" then
            return
        elseif ofp_type[of13_type] == "OFPT_PORT_MOD" then
            return
        elseif ofp_type[of13_type] == "OFPT_TABLE_MOD" then
            return
        elseif ofp_type[of13_type] == "OFPT_MULTIPART_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_MULTIPART_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_BARRIER_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_BARRIER_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_QUEUE_GET_CONFIG_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_QUEUE_GET_CONFIG_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_ROLE_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_ROLE_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_GET_ASYNC_REQUEST" then
            return
        elseif ofp_type[of13_type] == "OFPT_GET_ASYNC_REPLY" then
            return
        elseif ofp_type[of13_type] == "OFPT_SET_ASYNC" then
            return
        elseif ofp_type[of13_type] == "OFPT_METER_MOD" then
            return
        end
    end
end

function ofp_features_reply(buffer, pinfo, tree)
    local ofp_switch_features_datapath_id_range  = buffer(0,8)
    local ofp_switch_features_n_buffers_range    = buffer(8,4)
    local ofp_switch_features_n_tables_range     = buffer(12,1)
    local ofp_switch_features_auxiliary_id_range = buffer(13,1)
    local ofp_switch_features_padding_range      = buffer(14,2)
    local ofp_switch_features_capabilities_range = buffer(16,4)
    local ofp_switch_features_reserved_range     = buffer(20,4)
    local pointer = 24

    local ofp_switch_features_datapath_id  = ofp_switch_features_datapath_id_range:uint64()
    local ofp_switch_features_n_buffers    = ofp_switch_features_n_buffers_range:uint()
    local ofp_switch_features_n_tables     = ofp_switch_features_n_tables_range:uint()
    local ofp_switch_features_auxiliary_id = ofp_switch_features_auxiliary_id_range:uint()
    local ofp_switch_features_padding      = tostring(ofp_switch_features_padding_range)
    local ofp_switch_features_capabilities = ofp_switch_features_capabilities_range:uint()
    local ofp_switch_features_reserved     = tostring(ofp_switch_features_reserved_range)

    -- Add Packet-In Tree
    local subtree = tree:add(ofp_switch_features_F, buffer())
    subtree:add(ofp_switch_features_datapath_id_F,  ofp_switch_features_datapath_id_range,  ofp_switch_features_datapath_id)
    subtree:add(ofp_switch_features_n_buffers_F,    ofp_switch_features_n_buffers_range,    ofp_switch_features_n_buffers)
    subtree:add(ofp_switch_features_n_tables_F,     ofp_switch_features_n_tables_range,     ofp_switch_features_n_tables)
    subtree:add(ofp_switch_features_auxiliary_id_F, ofp_switch_features_auxiliary_id_range, ofp_switch_features_auxiliary_id)
    subtree:add(ofp_switch_features_padding_F,      ofp_switch_features_padding_range,      ofp_switch_features_padding)
    cap_tree = subtree:add(ofp_switch_features_capabilities_F, ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_flow_stats_F,   ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_table_stats_F,  ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_port_stats_F,   ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_group_stats_F,  ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_ip_reasm_F,     ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_queue_stats_F,  ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    cap_tree:add(ofp_switch_features_capabilities_port_blocked_F, ofp_switch_features_capabilities_range, ofp_switch_features_capabilities)
    subtree:add(ofp_switch_features_reserved_F,     ofp_switch_features_reserved_range,     ofp_switch_features_reserved)
end

function ofp_packet_in(buffer, pinfo, tree)
    local packet_in_buffer_id_range = buffer(0,4)
    local packet_in_total_len_range = buffer(4,2)
    local packet_in_reason_range    = buffer(6,1)
    local packet_in_table_id_range  = buffer(7,1)
    local packet_in_cookie_range    = buffer(8,8)
    local pointer = 16

    local packet_in_buffer_id = packet_in_buffer_id_range:uint()
    local packet_in_total_len = packet_in_total_len_range:uint()
    local packet_in_reason    = packet_in_reason_range:uint()
    local packet_in_table_id  = packet_in_table_id_range:uint()
    local packet_in_cookie    = packet_in_cookie_range:uint64()

    -- Add Packet-In Tree
    local packet_in_tree = tree:add(packet_in_F, buffer(), "Packet In")
    packet_in_tree:add(packet_in_buffer_id_F, packet_in_buffer_id_range, packet_in_buffer_id)
    packet_in_tree:add(packet_in_total_len_F, packet_in_total_len_range, packet_in_total_len)
    packet_in_tree:add(packet_in_reason_F,    packet_in_reason_range,    packet_in_reason)
    packet_in_tree:add(packet_in_table_id_F,  packet_in_table_id_range,  packet_in_table_id)
    packet_in_tree:add(packet_in_cookie_F,    packet_in_cookie_range,    packet_in_cookie)

    -- Flow Match Header dissector
    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, packet_in_tree)
    pointer = pointer + offset

    -- Padding
    local packet_in_padding_range = buffer(pointer,2)
    pointer = pointer + 2
    local packet_in_padding = tostring(packet_in_padding_range)
    packet_in_tree:add(packet_in_padding_F, packet_in_padding_range, packet_in_padding)

    -- Ethernet dissector(wireshark implements)
    local raw_frame_range = buffer(pointer,buffer:len()-pointer)
    Dissector.get("eth"):call(raw_frame_range:tvb(), pinfo, packet_in_tree)
end


function ofp_match(buffer, pinfo, tree)
    local match_type_range   = buffer(0,2)
    local match_length_range = buffer(2,2)
    --local match_oxm_range = buffer(4,4)
    --local pointer = 8
    local pointer = 4

    local match_type   = match_type_range:uint()
    local match_length = match_length_range:uint()
    --local match_oxm = match_oxm_range:uint()

    local match_tree = tree:add(match_F, buffer(0,pointer), "Flow Match Header")
    match_tree:add(match_type_F, match_type_range, match_type):append_text(" (" .. ofp_match_type_string[match_type] .. ")")
    match_tree:add(match_length_F, match_length_range, match_length)
    --match_tree:add(match_oxm_F, match_oxm_range, match_oxm)

    local alignment = match_length
    while alignment > 8 do
        offset = ofp_oxm_field(buffer(pointer,buffer:len()-pointer), pinfo, match_tree)
        alignment = alignment - offset
    end
    pointer = pointer + (match_length - alignment)

    local match_padding_range = buffer(pointer, alignment)
    local match_padding = tostring(match_padding_range)
    match_tree:add(match_padding_F, match_padding_range, match_padding)    
    pointer = pointer + alignment

    return pointer
end

function ofp_oxm_field(buffer, pinfo, tree)
    local ofp_oxm_class_range  = buffer(0,2)
    local ofp_oxm_fh_range     = buffer(2,1)
    local ofp_oxm_length_range = buffer(3,1)
    local pointer = 4

    local ofp_oxm_class   = ofp_oxm_class_range:uint()
    local ofp_oxm_field   = ofp_oxm_fh_range:bitfield(0, 7)
    local ofp_oxm_hasmask = ofp_oxm_fh_range:bitfield(7, 1)
    local ofp_oxm_length  = ofp_oxm_length_range:uint()

    local ofp_oxm_tree = tree:add(oxm_F, buffer(0, pointer), "Flow Match Field Structure")
    ofp_oxm_tree:add(oxm_class_F, ofp_oxm_class_range, ofp_oxm_class):append_text(" (" .. ofp_oxm_field_string[ofp_oxm_class] .. ")")
    ofp_oxm_tree:add(oxm_field_F, ofp_oxm_fh_range, ofp_oxm_field):append_text(" (" .. oxm_ofb_match_fields[ofp_oxm_field][1] .. ")")
    ofp_oxm_tree:add(oxm_hasmask_F, ofp_oxm_fh_range, ofp_oxm_hasmask)
    ofp_oxm_tree:add(oxm_length_F, ofp_oxm_length_range, ofp_oxm_length)

    local value_bit = oxm_ofb_match_fields[ofp_oxm_field][2]
    local length = math.ceil(value_bit/8)
    local ofp_oxm_value_range = buffer(pointer, length)
    local ofp_oxm_value = ofp_oxm_value_range:uint()
    pointer = pointer + length
    ofp_oxm_tree:add(oxm_value_F, ofp_oxm_value_range, ofp_oxm_value)

    return pointer
end

-- =================================================
--     Register of13_proto
-- =================================================
DissectorTable.get("tcp.port"):add(6633, of13_proto)
