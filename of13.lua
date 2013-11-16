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
match_F         = ProtoField.string("of13.match",        "Flow Match Header")
match_type_F    = ProtoField.uint16("of13.match_type",   "Type")
match_length_F  = ProtoField.uint16("of13.match_length", "Length")
match_oxm_F     = ProtoField.uint16("of13.match_oxm", "OXM")
match_padding_F = ProtoField.string("of13.match_padding", "Padding")

-- A.2.3.2 Flow Match Fileld Structure
oxm_F         = ProtoField.string("of13.oxm",         "Flow Match Fileld Structure")
oxm_class_F   = ProtoField.uint16("of13.oxm_class",       "Match class: member class ie reserved class", base.HEX)
oxm_field_F   = ProtoField.uint8("of13.oxm_field",   "Match field within the class", base.HEX, nil, 0xfe)
oxm_hasmask_F = ProtoField.uint8("of13.oxm_hasmask", "Set if OXM include a bitmask in payload", base.HEX, VALS_BOOL, 0x01)
oxm_length_F  = ProtoField.uint8("of13.oxm_length",    "Length of OXM payload")
-- TODO: XXX
oxm_value_F   = ProtoField.string("of13.oxm_value",    "Value")

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

    -- A.4.1 Packet-In Message
    packet_in_F,
    packet_in_buffer_id_F,
    packet_in_total_len_F,
    packet_in_reason_F,
    packet_in_table_id_F,
    packet_in_cookie_F,
    packet_in_padding_F,
}


ofp_match_type_string = {
    [0] = "OFPMT_STANDARD",
    [1] = "OFPMT_OXM",
}

ofp_oxm_field_string = {
    [0x0000] = "OFPXMC_NXM_0", -- Backward compatibility with NXM
    [0x0001] = "OFPXMC_NXM_1", -- Backward compatibility with NXM
    [0x8000] = "OFPXMC_OPENFLOW_BASIC", -- Basic class for OpenFlow
    [0xFFFF] = "OFPXMC_EXPERIMENTER", -- Experimenter class
}

oxm_ofb_match_fields = {
    [0] = {"OFPXMT_OFB_IN_PORT",          32,  nil}, -- Switch input port.
    [1] = {"OFPXMT_OFB_IN_PHY_PORT",      32,  nil}, -- Switch physical input port.
    [2] = {"OFPXMT_OFB_METADATA",         64, true}, -- Metadata passed between tables.
    [3] = {"OFPXMT_OFB_ETH_DST",          48, true}, -- Ethernet destination address.
    [4] = {"OFPXMT_OFB_ETH_SRC",          48, true}, -- Ethernet source address.
    [5] = {"OFPXMT_OFB_ETH_TYPE",         16,  nil}, -- Ethernet frame type.
    [6] = {"OFPXMT_OFB_VLAN_VID",         13, true}, -- VLAN id.
    [7] = {"OFPXMT_OFB_VLAN_PCP",          3,  nil}, -- VLAN priority.
    [8] = {"OFPXMT_OFB_IP_DSCP",           6,  nil}, -- IP DSCP (6 bits in ToS field).
    [9] = {"OFPXMT_OFB_IP_ECN",            2,  nil}, -- IP ECN (2 bits in ToS field).
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

of13_type_string = {
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
    [8] = "OFPT_SET_CONFIG",
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
        of13_tree:add(type_F, of13_type_range, of13_type):append_text(" (" .. of13_type_string[of13_type] .. ")")
        of13_tree:add(length_F, of13_length_range, of13_length)
        of13_tree:add(xid_F, of13_xid_range, of13_xid)

        -- packer-in or packet-out
        if of13_type_string[of13_type] == "OFPT_PACKET_IN" then
            ofp_packet_in(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)
        end
    end
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
