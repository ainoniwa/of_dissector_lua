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
oxm_F         = ProtoField.string("of13.oxm",        "Flow Match Fileld")
oxm_class_F   = ProtoField.uint16("of13.oxm_class",  "Match class: member class ie reserved class", base.HEX)
oxm_field_F   = ProtoField.uint8("of13.oxm_field",   "Match field within the class", base.HEX, nil, 0xfe)
oxm_hasmask_F = ProtoField.uint8("of13.oxm_hasmask", "Set if OXM include a bitmask in payload", base.HEX, VALS_BOOL, 0x01)
oxm_length_F  = ProtoField.uint8("of13.oxm_length",  "Length of OXM payload")
-- TODO: XXX
oxm_value_F   = ProtoField.string("of13.oxm_value",  "Value")

-- A.2.4 Flow Instruction Structures
ofp_instruction_F               = ProtoField.string("of13.instruction", "Flow Instruction")
ofp_instruction_type_F          = ProtoField.string("of13.instruction_type", "Type")
ofp_instruction_length_F        = ProtoField.string("of13.instruction_length", "Length")
ofp_instruction_table_id_F      = ProtoField.string("of13.instruction_table_id", "Table ID")
ofp_instruction_padding_F       = ProtoField.string("of13.instruction_padding", "Padding")
ofp_instruction_metadata_F      = ProtoField.string("of13.instruction_metadata", "Metadata")
ofp_instruction_metadata_mask_F = ProtoField.string("of13.instruction_metadata_mask", "Metadata mask")
ofp_instruction_meter_F         = ProtoField.string("of13.instruction_meter", "Meter")

-- A.2.5 Action Structures
ofp_action_header_F         = ProtoField.string("of13.action",         "Action")
ofp_action_header_type_F    = ProtoField.uint16("of13.action_type",    "One of OFPAT_*")
ofp_action_header_length_F  = ProtoField.uint16("of13.action_length",  "Length of action, including this header")
ofp_action_output_port_F    = ProtoField.uint32("of13.output_port",    "Output port")
ofp_action_output_max_len_F = ProtoField.uint16("of13.output_maxlen",  "Max length to send to controller")
ofp_action_output_padding_F = ProtoField.string("of13.output_padding", "Pad to 64 bits")

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

-- A.3.4.1 Modify Flow Entry Message
ofp_flow_mod_F              = ProtoField.string("of13.flowmod" ,             "Modify Flow Entry Message")
ofp_flow_mod_cookie_F       = ProtoField.uint64("of13.flowmod_cookie",       "Cookie", base.HEX)
ofp_flow_mod_cookie_mask_F  = ProtoField.uint64("of13.flowmod_cookie_mask",  "Cookie mask", base.HEX)
ofp_flow_mod_table_id_F     = ProtoField.uint8("of13.flowmod_table_id",     "Table ID")
ofp_flow_mod_command_F      = ProtoField.uint8("of13.flowmod_command",      "Command")
ofp_flow_mod_idle_timeout_F = ProtoField.uint16("of13.flowmod_idle_timeout", "Idle timeout")
ofp_flow_mod_hard_timeout_F = ProtoField.uint16("of13.flowmod_hard_timeout", "Hard timeout")
ofp_flow_mod_priority_F     = ProtoField.uint16("of13.flowmod_priority",     "Priority")
ofp_flow_mod_buffer_id_F    = ProtoField.uint32("of13.flowmod_buffer_id",    "Buffer ID")
ofp_flow_mod_out_port_F     = ProtoField.uint32("of13.flowmod_out_port",     "Out port")
ofp_flow_mod_out_group_F    = ProtoField.uint32("of13.flowmod_out_group",    "Out group")
ofp_flow_mod_flags_F        = ProtoField.uint16("of13.flowmod_flags",        "Flags", base.HEX)
ofp_flow_mod_padding_F      = ProtoField.string("of13.flowmod_padding",      "Padding")

ofp_flow_mod_flags_send_flow_rem_F = ProtoField.uint16("of13.mod_flag_flow_rem",      "Flow removed", base.HEX, VALS_BOOL, 0x0001)
ofp_flow_mod_flags_check_overlap_F = ProtoField.uint16("of13.mod_flag_check_overlap", "Check overlap", base.HEX, VALS_BOOL, 0x0002)
ofp_flow_mod_flags_reset_counts_F  = ProtoField.uint16("of13.mod_flag_reset_count",   "Reset count", base.HEX, VALS_BOOL, 0x0004)
ofp_flow_mod_flags_no_pkt_counts_F = ProtoField.uint16("of13.mod_flag_no_pkt_count",  "No packet count", base.HEX, VALS_BOOL, 0x0008)
ofp_flow_mod_flags_no_byt_counts_F = ProtoField.uint16("of13.mod_flag_no_byt_count",  "No byte count", base.HEX, VALS_BOOL, 0x0010)

-- A.3.7 Packet-Out Message
packet_out_F             = ProtoField.string("of13.packet_out",            "Packet-Out Message")
packet_out_buffer_id_F   = ProtoField.uint32("of13.packet_out_buffer_id",  "Datapath ID")
packet_out_in_port_F     = ProtoField.uint32("of13.packet_out_in_port",    "Input port")
packet_out_actions_len_F = ProtoField.uint16("of13.packet_out_action_len", "Size of action array")
packet_out_padding_F     = ProtoField.string("of13.packet_out_padding",    "Padding")

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

    -- A.2.4 Flow Instruction Structures
    ofp_instruction_F,
    ofp_instruction_type_F,
    ofp_instruction_length_F,
    ofp_instruction_table_id_F,
    ofp_instruction_padding_F,
    ofp_instruction_metadata_F,
    ofp_instruction_metadata_mask_F,
    ofp_instruction_meter_F,

    -- A.2.5 Action Structures
    ofp_action_header_F,
    ofp_action_header_type_F,
    ofp_action_header_length_F,
    ofp_action_output_port_F,
    ofp_action_output_max_len_F,
    ofp_action_output_padding_F,

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

    -- A.3.4.1 Modify Flow Entry Message
    ofp_flow_mod_F,
    ofp_flow_mod_cookie_F,
    ofp_flow_mod_cookie_mask_F,
    ofp_flow_mod_table_id_F,
    ofp_flow_mod_command_F,
    ofp_flow_mod_idle_timeout_F,
    ofp_flow_mod_hard_timeout_F,
    ofp_flow_mod_priority_F,
    ofp_flow_mod_buffer_id_F,
    ofp_flow_mod_out_port_F,
    ofp_flow_mod_out_group_F,
    ofp_flow_mod_flags_F,
    ofp_flow_mod_padding_F,

    ofp_flow_mod_flags_send_flow_rem_F,
    ofp_flow_mod_flags_check_overlap_F,
    ofp_flow_mod_flags_reset_counts_F,
    ofp_flow_mod_flags_no_pkt_counts_F,
    ofp_flow_mod_flags_no_byt_counts_F,

    -- A.3.7 Packet-Out Message
    packet_out_F,
    packet_out_buffer_id_F,
    packet_out_in_port_F,
    packet_out_actions_len_F,
    packet_out_padding_F,

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

-- A.2.4 Flow Instruction Structures
ofp_instruction_type = {
    [1] = "OFPIT_GOTO_TABLE",        -- Setup the next table in the lookup pipeline
    [2] = "OFPIT_WRITE_METADATA",    -- Setup the metadata field for use later in pipeline
    [3] = "OFPIT_WRITE_ACTIONS",     -- Write the action(s) onto the datapath action set
    [4] = "OFPIT_APPLY_ACTIONS",     -- Applies the action(s) immediately
    [5] = "OFPIT_CLEAR_ACTIONS",     -- Clears all actions from the datapath action set
    [6] = "OFPIT_METER",             -- Apply meter (rate limiter)
    [0xffff] = "OFPIT_EXPERIMENTER", -- Experimenter instruction
}

-- A.2.5 Action Structure
ofp_action_type = {
    [0]      = "OFPAT_OUTPUT",       -- Output to switch port.
    [11]     = "OFPAT_COPY_TTL_OUT", -- Copy TTL "outwards" -- from next-to-outermost to outermost
    [12]     = "OFPAT_COPY_TTL_IN",  -- Copy TTL "inwards" -- from outermost to next-to-outermost
    [15]     = "OFPAT_SET_MPLS_TTL", -- MPLS TTL
    [16]     = "OFPAT_DEC_MPLS_TTL", -- Decrement MPLS TTL
    [17]     = "OFPAT_PUSH_VLAN",    -- Push a new VLAN tag
    [18]     = "OFPAT_POP_VLAN",     -- Pop the outer VLAN tag
    [19]     = "OFPAT_PUSH_MPLS",    -- Push a new MPLS tag
    [20]     = "OFPAT_POP_MPLS",     -- Pop the outer MPLS tag
    [21]     = "OFPAT_SET_QUEUE",    -- Set queue id when outputting to a port
    [22]     = "OFPAT_GROUP",        -- Apply group.
    [23]     = "OFPAT_SET_NW_TTL",   -- IP TTL.
    [24]     = "OFPAT_DEC_NW_TTL",   -- Decrement IP TTL.
    [25]     = "OFPAT_SET_FIELD",    -- Set a header field using OXM TLV format.
    [26]     = "OFPAT_PUSH_PBB",     -- Push a new PBB service tag (I-TAG)
    [27]     = "OFPAT_POP_PBB",      -- Pop the outer PBB service tag (I-TAG)
    [0xffff] = "OFPAT_EXPERIMENTER",
}

ofp_controller_max_len = {
    [0xffe5] = "OFPCML_MAX",       -- maximum max_len value which can be used to request a specific byte length.
    [0xffff] = "OFPCML_NO_BUFFER", -- indicates that no buffering should be applied and the whole packet is to be sent to the controller.
}

-- A.3.4.1 Modify Flow Entry Message
ofp_flow_mod_command = {
    [0] = "OFPFC_ADD",           -- New flow.
    [1] = "OFPFC_MODIFY",        -- Modify all matching flows.
    [2] = "OFPFC_MODIFY_STRICT", -- Modify entry strictly matching wildcards and priority.
    [3] = "OFPFC_DELETE",        -- Delete all matching flows.
    [4] = "OFPFC_DELETE_STRICT", -- Delete entry strictly matching wildcards and priority.
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
    [0x0000] = "OFPXMC_NXM_0",          -- Backward compatibility with NXM
    [0x0001] = "OFPXMC_NXM_1",          -- Backward compatibility with NXM
    [0x8000] = "OFPXMC_OPENFLOW_BASIC", -- Basic class for OpenFlow
    [0xFFFF] = "OFPXMC_EXPERIMENTER",   -- Experimenter class
}

oxm_ofb_match_fields = {
    --     {Name,                  bit length, mask}
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
    [10] = {"OFPXMT_OFB_IP_PROTO",          8,  nil}, -- IP protocol.
    [11] = {"OFPXMT_OFB_IPV4_SRC",         32, true}, -- IPv4 source address.
    [12] = {"OFPXMT_OFB_IPV4_DST",         32, true}, -- IPv4 destination address.
    [13] = {"OFPXMT_OFB_TCP_SRC",          16,  nil}, -- TCP source port.
    [14] = {"OFPXMT_OFB_TCP_DST",          16,  nil}, -- TCP destination port.
    [15] = {"OFPXMT_OFB_UDP_SRC",          16,  nil}, -- UDP source port.
    [16] = {"OFPXMT_OFB_UDP_DST",          16,  nil}, -- UDP destination port.
    [17] = {"OFPXMT_OFB_SCTP_SRC",         16,  nil}, -- SCTP source port.
    [18] = {"OFPXMT_OFB_SCTP_DST",         16,  nil}, -- SCTP destination port.
    [19] = {"OFPXMT_OFB_ICMPV4_TYPE",       8,  nil}, -- ICMP type.
    [20] = {"OFPXMT_OFB_ICMPV4_CODE",       8,  nil}, -- ICMP code.
    [21] = {"OFPXMT_OFB_ARP_OP",           16,  nil}, -- ARP opcode.
    [22] = {"OFPXMT_OFB_ARP_SPA",          32, true}, -- ARP source IPv4 address.
    [23] = {"OFPXMT_OFB_ARP_TPA",          32, true}, -- ARP target IPv4 address.
    [24] = {"OFPXMT_OFB_ARP_SHA",          48, true}, -- ARP source hardware address.
    [25] = {"OFPXMT_OFB_ARP_THA",          48, true}, -- ARP target hardware address.
    [26] = {"OFPXMT_OFB_IPV6_SRC",        128, true}, -- IPv6 source address.
    [27] = {"OFPXMT_OFB_IPV6_DST",        128, true}, -- IPv6 destination address.
    [28] = {"OFPXMT_OFB_IPV6_FLABEL",      20, true}, -- IPv6 Flow Label
    [29] = {"OFPXMT_OFB_ICMPV6_TYPE",       8,  nil}, -- ICMPv6 type.
    [30] = {"OFPXMT_OFB_ICMPV6_CODE",       8,  nil}, -- ICMPv6 code.
    [31] = {"OFPXMT_OFB_IPV6_ND_TARGET",  128,  nil}, -- Target address for ND.
    [32] = {"OFPXMT_OFB_IPV6_ND_SLL",      48,  nil}, -- Source link-layer for ND.
    [33] = {"OFPXMT_OFB_IPV6_ND_TLL",      48,  nil}, -- Target link-layer for ND.
    [34] = {"OFPXMT_OFB_MPLS_LABEL",       20,  nil}, -- MPLS label.
    [35] = {"OFPXMT_OFB_MPLS_TC",           3,  nil}, -- MPLS TC.
    [36] = {"OFPXMT_OFP_MPLS_BOS",          1,  nil}, -- MPLS BoS bit.
    [37] = {"OFPXMT_OFB_PBB_ISID",         24, true}, -- PBB I-SID.
    [38] = {"OFPXMT_OFB_TUNNEL_ID",        64, true}, -- Logical Port Metadata.
    [39] = {"OFPXMT_OFB_IPV6_EXTHDR",       9, true}, -- IPv6 Extension Header pseudo-field
}


-- =================================================
--     OpenFlow 1.3 dissection
-- =================================================
function of13_proto.dissector(buffer, pinfo, tree)

    -- First, get the general header
    local _version_range = buffer(0,1)
    local _type_range    = buffer(1,1)
    local _length_range  = buffer(2,2)
    local _xid_range     = buffer(4,4)
    local pointer = 8

    local _version       = _version_range:uint()
    local _type          = _type_range:uint()
    local _length        = _length_range:uint()
    local _xid           = _xid_range:uint()

    -- Only dissect version is 0x04(=openflow 1.3)
    -- TODO: Before this function, place the version switching function.
    if _version == 0x04 then
        -- Add OpenFlow 1.3 Tree
        local of13_tree = tree:add(of13_proto, buffer(), "OpenFlow 1.3 " .. ofp_type[_type])

        -- OpenFlow 1.3 general header
        of13_tree:add(version_F, _version_range, _version):append_text(" (OpenFlow 1.3)")
        of13_tree:add(type_F,    _type_range,    _type):append_text(" (" .. ofp_type[_type] .. ")")
        of13_tree:add(length_F,  _length_range,  _length)
        of13_tree:add(xid_F,     _xid_range,     _xid)

        if ofp_type[_type] == "OFPT_HELLO" then
            -- A.5.1 Hello
            -- The OFPT_HELLO message has no body; that is, it consists only of an OpenFlow header.
            return
        elseif ofp_type[_type] == "OFPT_ERROR" then
            return
        elseif ofp_type[_type] == "OFPT_ECHO_REQUEST" then
            -- A.5.2 Echo Request
            --  An Echo Request message consists of an OpenFlow header
            -- plus an arbitrary-length data field. The data fieeld might be
            -- a message timestamp to check latency, various lengths to
            -- measure bandwidth, or zero-size to verify liveness between the
            -- switch and controller.
            return
        elseif ofp_type[_type] == "OFPT_ECHO_REPLY" then
            -- A.5.3 Echo Reply
            --  An Echo Reply message consists of an OpenFlow header plus the
            -- unmodified data field of an echo request message.
            return
        elseif ofp_type[_type] == "OFPT_EXPERIMENTER" then
            return
        elseif ofp_type[_type] == "OFPT_FEATURES_REQUEST" then
            -- A.3.1 Handshake
            --  This message does not contain a body beyond the OpenFlow header.
            return
        elseif ofp_type[_type] == "OFPT_FEATURES_REPLY" then
            ofp_features_reply(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        elseif ofp_type[_type] == "OFPT_GET_CONFIG_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_GET_CONFIG_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_SET_CONFIG" then
            return
        elseif ofp_type[_type] == "OFPT_PACKET_IN" then
            ofp_packet_in(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        elseif ofp_type[_type] == "OFPT_FLOW_REMOVED" then
            return
        elseif ofp_type[_type] == "OFPT_PORT_STATUS" then
            return
        elseif ofp_type[_type] == "OFPT_PACKET_OUT" then
            ofp_packet_out(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        elseif ofp_type[_type] == "OFPT_FLOW_MOD" then
            ofp_flow_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        elseif ofp_type[_type] == "OFPT_GROUP_MOD" then
            return
        elseif ofp_type[_type] == "OFPT_PORT_MOD" then
            return
        elseif ofp_type[_type] == "OFPT_TABLE_MOD" then
            return
        elseif ofp_type[_type] == "OFPT_MULTIPART_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_MULTIPART_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_BARRIER_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_BARRIER_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_QUEUE_GET_CONFIG_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_QUEUE_GET_CONFIG_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_ROLE_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_ROLE_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_GET_ASYNC_REQUEST" then
            return
        elseif ofp_type[_type] == "OFPT_GET_ASYNC_REPLY" then
            return
        elseif ofp_type[_type] == "OFPT_SET_ASYNC" then
            return
        elseif ofp_type[_type] == "OFPT_METER_MOD" then
            return
        end
    end
end

function ofp_features_reply(buffer, pinfo, tree)
    local _datapath_id_range  = buffer(0,8)
    local _n_buffers_range    = buffer(8,4)
    local _n_tables_range     = buffer(12,1)
    local _auxiliary_id_range = buffer(13,1)
    local _padding_range      = buffer(14,2)
    local _capabilities_range = buffer(16,4)
    local _reserved_range     = buffer(20,4)
    local pointer = 24

    local _datapath_id  = _datapath_id_range:uint64()
    local _n_buffers    = _n_buffers_range:uint()
    local _n_tables     = _n_tables_range:uint()
    local _auxiliary_id = _auxiliary_id_range:uint()
    local _padding      = tostring(_padding_range)
    local _capabilities = _capabilities_range:uint()
    local _reserved     = tostring(_reserved_range)

    local subtree = tree:add(ofp_switch_features_F, buffer())
    subtree:add(ofp_switch_features_datapath_id_F,  _datapath_id_range,  _datapath_id)
    subtree:add(ofp_switch_features_n_buffers_F,    _n_buffers_range,    _n_buffers)
    subtree:add(ofp_switch_features_n_tables_F,     _n_tables_range,     _n_tables)
    subtree:add(ofp_switch_features_auxiliary_id_F, _auxiliary_id_range, _auxiliary_id)
    subtree:add(ofp_switch_features_padding_F,      _padding_range,      _padding)
    cap_tree = subtree:add(ofp_switch_features_capabilities_F,    _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_flow_stats_F,   _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_table_stats_F,  _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_port_stats_F,   _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_group_stats_F,  _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_ip_reasm_F,     _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_queue_stats_F,  _capabilities_range, _capabilities)
    cap_tree:add(ofp_switch_features_capabilities_port_blocked_F, _capabilities_range, _capabilities)
    subtree:add(ofp_switch_features_reserved_F,     _reserved_range,     _reserved)
end

function ofp_packet_out(buffer, pinfo, tree)
    local _buffer_id_range   = buffer(0,4)
    local _in_port_range     = buffer(4,4)
    local _actions_len_range = buffer(8,2)
    local _padding_range     = buffer(10,6)
    local pointer = 16

    local _buffer_id   = _buffer_id_range:uint()
    local _in_port     = _in_port_range:uint()
    local _actions_len = _actions_len_range:uint()
    local _padding     = tostring(_padding_range)

    local subtree = tree:add(packet_out_F, buffer(), "Packet Out")
    subtree:add(packet_out_buffer_id_F,   _buffer_id_range,   _buffer_id)
    subtree:add(packet_out_in_port_F,     _in_port_range,     _in_port)
    subtree:add(packet_out_actions_len_F, _actions_len_range, _actions_len)
    subtree:add(packet_out_padding_F,     _padding_range,     _padding)

    -- Action Header dissector
    offset = ofp_action_header(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Ethernet dissector(wireshark implements)
    local raw_frame_range = buffer(pointer,buffer:len()-pointer)
    Dissector.get("eth"):call(raw_frame_range:tvb(), pinfo, subtree)
end

function ofp_action_header(buffer, pinfo, tree)
    local _type_range   = buffer(0,2)
    local _length_range = buffer(2,2)
    local pointer = 4

    local _type   = _type_range:uint()
    local _length = _length_range:uint()

    local subtree = tree:add(ofp_action_header_F, buffer(0,_length), "Action header")
    subtree:add(ofp_action_header_type_F,   _type_range,   _type):append_text(" (" .. ofp_action_type[_type] .. ")")
    subtree:add(ofp_action_header_length_F, _length_range, _length)

    if ofp_action_type[_type] == "OFPAT_OUTPUT" then
        offset = ofp_action_output(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    elseif ofp_action_type[_type] == "OFPAT_COPY_TTL_OUT" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_COPY_TTL_IN" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_SET_MPLS_TTL" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_DEC_MPLS_TTL" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_PUSH_VLAN" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_POP_VLAN" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_PUSH_MPLS" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_POP_MPLS" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_SET_QUEUE" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_GROUP" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_SET_NW_TTL" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_DEC_NW_TTL" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_SET_FIELD" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_PUSH_PBB" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_POP_PBB" then
        offset = 0
    elseif ofp_action_type[_type] == "OFPAT_EXPERIMENTER" then
        offset = 0
    end

    pointer = pointer + offset
    return pointer
end

function ofp_action_output(buffer, pinfo, tree)
    local _port_range    = buffer(0,4)
    local _max_len_range = buffer(4,2)
    local _padding_range = buffer(6,6)
    local pointer = 12

    local _port    = _port_range:uint()
    local _max_len = _max_len_range:uint()
    local _padding = tostring(_padding_range)

    if ofp_port_no[_port] == nil then
        tree:add(ofp_action_output_port_F, _port_range, _port)
    else
        tree:add(ofp_action_output_port_F, _port_range, _port):append_text(" (" .. ofp_port_no[_port] .. ")")
    end
    tree:add(ofp_action_output_max_len_F, _max_len_range, _max_len):append_text(" (" .. ofp_controller_max_len[_max_len] .. ")")
    tree:add(ofp_action_output_padding_F, _padding_range, _padding)
    return pointer
end

function ofp_flow_mod(buffer, pinfo, tree)
    local _cookie_range       = buffer(0,8)
    local _cookie_mask_range  = buffer(8,8)
    local _table_id_range     = buffer(16,1)
    local _command_range      = buffer(17,1)
    local _idle_timeout_range = buffer(18,2)
    local _hard_timeout_range = buffer(20,2)
    local _priority_range     = buffer(22,2)
    local _buffer_id_range    = buffer(24,4)
    local _out_port_range     = buffer(28,4)
    local _out_group_range    = buffer(32,4)
    local _flags_range        = buffer(36,2)
    local _padding_range      = buffer(38,2)
    local pointer = 40

    local _cookie       = _cookie_range:uint64()
    local _cookie_mask  = _cookie_mask_range:uint64()
    local _table_id     = _table_id_range:uint()
    local _command      = _command_range:uint()
    local _idle_timeout = _idle_timeout_range:uint()
    local _hard_timeout = _hard_timeout_range:uint()
    local _priority     = _priority_range:uint()
    local _buffer_id    = _buffer_id_range:uint()
    local _out_port     = _out_port_range:uint()
    local _out_group    = _out_group_range:uint()
    local _flags        = _flags_range:uint()
    local _padding      = tostring(_padding_range)

    local subtree = tree:add(ofp_flow_mod_F, buffer(), "")
    subtree:add(ofp_flow_mod_cookie_F,       _cookie_range,       _cookie)
    subtree:add(ofp_flow_mod_cookie_mask_F,  _cookie_mask_range,  _cookie_mask)
    subtree:add(ofp_flow_mod_table_id_F,     _table_id_range,     _table_id)
    subtree:add(ofp_flow_mod_command_F,      _command_range,      _command):append_text(" (" .. ofp_flow_mod_command[_command] .. ")")
    subtree:add(ofp_flow_mod_idle_timeout_F, _idle_timeout_range, _idle_timeout)
    subtree:add(ofp_flow_mod_hard_timeout_F, _hard_timeout_range, _hard_timeout)
    subtree:add(ofp_flow_mod_priority_F,     _priority_range,     _priority)
    subtree:add(ofp_flow_mod_buffer_id_F,    _buffer_id_range,    _buffer_id)
    subtree:add(ofp_flow_mod_out_port_F,     _out_port_range,     _out_port)
    subtree:add(ofp_flow_mod_out_group_F,    _out_group_range,    _out_group)
    flags_tree = subtree:add(ofp_flow_mod_flags_F, _flags_range, _flags)
    flags_tree:add(ofp_flow_mod_flags_send_flow_rem_F, _flags_range, _flags)
    flags_tree:add(ofp_flow_mod_flags_check_overlap_F, _flags_range, _flags)
    flags_tree:add(ofp_flow_mod_flags_reset_counts_F , _flags_range, _flags)
    flags_tree:add(ofp_flow_mod_flags_no_pkt_counts_F, _flags_range, _flags)
    flags_tree:add(ofp_flow_mod_flags_no_byt_counts_F, _flags_range, _flags)
    subtree:add(ofp_flow_mod_padding_F,      _padding_range,      _padding)

    -- Flow Match Header dissector
    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Flow Instruction Structures
    if buffer:len() <= pointer then
        return
    end
    ofp_instruction(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
end

function ofp_instruction(buffer, pinfo, tree)
    if buffer:len() < 4 then
        return
    end

    local _type_range   = buffer(0,2)
    local _length_range = buffer(2,2)
    local pointer = 4

    local _type   = _type_range:uint()
    local _length = _length_range:uint()

    local subtree = tree:add(ofp_instruction_F, buffer(0,_length), "Flow Instruction")
    subtree:add(ofp_instruction_type_F,   _type_range,   _type):append_text(" (" .. ofp_instruction_type[_type] .. ")")
    subtree:add(ofp_instruction_length_F, _length_range, _length)

    if _length < 8 then
        return
    end

    if ofp_instruction_type[_type] == "OFPIT_GOTO_TABLE" then
        local _table_id_range = buffer(pointer,1)
        local _padding_range  = buffer(pointer+1,3)
        pointer = pointer + 4

        local _table_id = _table_id_range:uint()
        local _padding  = tostring(_padding_range)

        subtree:add(ofp_instruction_table_id_F, _table_id_range, _table_id)
        subtree:add(ofp_instruction_padding_F,  _padding_range,  _padding)

    elseif ofp_instruction_type[_type] == "OFPIT_WRITE_METADATA" then
        local _padding_range       = buffer(pointer,4)
        local _metadata_range      = buffer(pointer+4,8)
        local _metadata_mask_range = buffer(pointer+12,8)
        pointer = pointer + 20

        local _padding        = tostring(_padding_range)
        local _metadata       = _metadata_range:uint64()
        local _metadata_mask  = _metadata_mask_range:uint64()

        subtree:add(ofp_instruction_padding_F,  _padding_range,  _padding)
        subtree:add(ofp_instruction_metadata_F, _metadata_range, _metadata)
        subtree:add(ofp_instruction_metadata_mask_F, _metadata_mask_range, _metadata_mask)

    elseif ofp_instruction_type[_type] == "OFPIT_WRITE_ACTIONS" or
           ofp_instruction_type[_type] == "OFPIT_APPLY_ACTIONS" or
           ofp_instruction_type[_type] == "OFPIT_CLEAR_ACTIONS" then
        local _padding_range  = buffer(pointer,4)
        pointer = pointer + 4
        local _padding  = tostring(_padding_range)
        subtree:add(ofp_instruction_padding_F,  _padding_range,  _padding)

        -- Action Header dissector
        offset = ofp_action_header(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset

    elseif ofp_instruction_type[_type] == "OFPIT_METER" then
        local _meter_range  = buffer(pointer,4)
        pointer = pointer + 4
        local _meter  = _meter_range:uint()
        subtree:add(ofp_instruction_meter_F,  _meter_range,  _meter)

    elseif ofp_instruction_type[_type] == "OFPIT_EXPERIMENTER" then
        -- XXX
    end

    if buffer:len() <= pointer then
        return
    end
    ofp_instruction(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
end

function ofp_packet_in(buffer, pinfo, tree)
    local _buffer_id_range = buffer(0,4)
    local _total_len_range = buffer(4,2)
    local _reason_range    = buffer(6,1)
    local _table_id_range  = buffer(7,1)
    local _cookie_range    = buffer(8,8)
    local pointer = 16

    local _buffer_id = _buffer_id_range:uint()
    local _total_len = _total_len_range:uint()
    local _reason    = _reason_range:uint()
    local _table_id  = _table_id_range:uint()
    local _cookie    = _cookie_range:uint64()

    -- Add Packet-In Tree
    local subtree = tree:add(packet_in_F, buffer(), "Packet In")
    subtree:add(packet_in_buffer_id_F, _buffer_id_range, _buffer_id)
    subtree:add(packet_in_total_len_F, _total_len_range, _total_len)
    subtree:add(packet_in_reason_F,    _reason_range,    _reason):append_text(" (" .. ofp_packet_in_reason[_reason] .. ")")
    subtree:add(packet_in_table_id_F,  _table_id_range,  _table_id)
    subtree:add(packet_in_cookie_F,    _cookie_range,    _cookie)

    -- Flow Match Header dissector
    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Padding
    local _padding_range = buffer(pointer,2)
    pointer = pointer + 2
    local _padding = tostring(_padding_range)
    subtree:add(packet_in_padding_F, _padding_range, _padding)

    -- Ethernet dissector(wireshark implements)
    local raw_frame_range = buffer(pointer,buffer:len()-pointer)
    Dissector.get("eth"):call(raw_frame_range:tvb(), pinfo, subtree)
end

function ofp_match(buffer, pinfo, tree)
    local _type_range   = buffer(0,2)
    local _length_range = buffer(2,2)
    local pointer = 4

    local _type   = _type_range:uint()
    local _length = _length_range:uint()

    local subtree = tree:add(match_F, buffer(0,_length), "Flow Match Header")
    subtree:add(match_type_F,   _type_range,   _type):append_text(" (" .. ofp_match_type_string[_type] .. ")")
    subtree:add(match_length_F, _length_range, _length)

    while pointer < _length do
        offset = ofp_oxm_field(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset
    end

    local _padding_range = buffer(pointer, math.ceil(_length/8)*8 - pointer)
    local _padding = tostring(_padding_range)
    subtree:add(match_padding_F, _padding_range, _padding)
    pointer = pointer + (math.ceil(_length/8)*8 - pointer)

    return pointer
end

function ofp_oxm_field(buffer, pinfo, tree)
    local _class_range  = buffer(0,2)
    local _fh_range     = buffer(2,1)
    local _length_range = buffer(3,1)
    local pointer = 4

    local _class   = _class_range:uint()
    local _field   = _fh_range:bitfield(0, 7)
    local _hasmask = _fh_range:bitfield(7, 1)
    local _length  = _length_range:uint()

    local subtree = tree:add(oxm_F, buffer(0, pointer + _length), "Flow Match Field Structure")
    subtree:add(oxm_class_F,   _class_range,  _class):append_text(" (" .. ofp_oxm_field_string[_class] .. ")")
    subtree:add(oxm_field_F,   _fh_range,     _field):append_text(" (" .. oxm_ofb_match_fields[_field][1] .. ")")
    subtree:add(oxm_hasmask_F, _fh_range,     _hasmask)
    subtree:add(oxm_length_F,  _length_range, _length)

    local _value_range = buffer(pointer, _length)
    local _value = tostring(_value_range)
    pointer = pointer + _length
    subtree:add(oxm_value_F, _value_range, _value)

    return pointer
end

-- =================================================
--     Register of13_proto
-- =================================================
DissectorTable.get("tcp.port"):add(6633, of13_proto)
