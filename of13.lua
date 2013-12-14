-- =================================================
--     OpenFlow 1.3 protocol define
-- =================================================
of13_proto = Proto("of13","OpenFlow 1.3")

-- flags bits. Support true/false filter.
local VALS_BOOL	= {[0] = "False", [1] = "True"}

-- =================================================
--     OpenFlow 1.3 dissection
-- =================================================

-- -------------------------------------------------
--   7.1 OpenFlow Header
-- -------------------------------------------------
ofp_header_version_F = ProtoField.uint8("of13.version", "Version", base.HEX)
ofp_header_type_F    = ProtoField.uint8("of13.type",    "Type")
ofp_header_length_F  = ProtoField.uint16("of13.length", "Length")
ofp_header_xid_F     = ProtoField.uint32("of13.xid",    "Transaction ID")

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
        of13_tree:add(ofp_header_version_F, _version_range, _version):append_text(" (OpenFlow 1.3)")
        of13_tree:add(ofp_header_type_F,    _type_range,    _type):append_text(" (" .. ofp_type[_type] .. ")")
        of13_tree:add(ofp_header_length_F,  _length_range,  _length)
        of13_tree:add(ofp_header_xid_F,     _xid_range,     _xid)

        if ofp_type[_type] == "OFPT_HELLO" then
            -- 7.5.1 Hello
            -- The OFPT_HELLO message has no body; that is, it consists only of an OpenFlow header.
            return

        elseif ofp_type[_type] == "OFPT_ERROR" then
            ofp_error_msg(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_ECHO_REQUEST" then
            -- 7.5.2 Echo Request
            --  An Echo Request message consists of an OpenFlow header
            -- plus an arbitrary-length data field. The data fieeld might be
            -- a message timestamp to check latency, various lengths to
            -- measure bandwidth, or zero-size to verify liveness between the
            -- switch and controller.
            return

        elseif ofp_type[_type] == "OFPT_ECHO_REPLY" then
            -- 7.5.3 Echo Reply
            --  An Echo Reply message consists of an OpenFlow header plus the
            -- unmodified data field of an echo request message.
            return

        elseif ofp_type[_type] == "OFPT_EXPERIMENTER" then
            ofp_experimenter_header(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_FEATURES_REQUEST" then
            -- 7.3.1 Handshake
            --  This message does not contain a body beyond the OpenFlow header.
            return

        elseif ofp_type[_type] == "OFPT_FEATURES_REPLY" then
            ofp_switch_features(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_GET_CONFIG_REQUEST" then
            -- There is no body for OFPT_GET_CONFIG_REQUEST
            return

        elseif ofp_type[_type] == "OFPT_GET_CONFIG_REPLY" or 
               ofp_type[_type] == "OFPT_SET_CONFIG" then
            ofp_switch_config(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_PACKET_IN" then
            ofp_packet_in(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_FLOW_REMOVED" then
            ofp_flow_removed(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_PORT_STATUS" then
            ofp_port_status(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_PACKET_OUT" then
            ofp_packet_out(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_FLOW_MOD" then
            ofp_flow_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_GROUP_MOD" then
            ofp_group_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_PORT_MOD" then
            ofp_port_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_TABLE_MOD" then
            ofp_table_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_MULTIPART_REQUEST" then
            ofp_multipart_request(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_MULTIPART_REPLY" then
            ofp_multipart_reply(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_BARRIER_REQUEST" or
               ofp_type[_type] == "OFPT_BARRIER_REPLY" then
            -- 7.3.8 Barrier Message
            -- This message has no body.
            return

        elseif ofp_type[_type] == "OFPT_QUEUE_GET_CONFIG_REQUEST" then
            ofp_queue_get_config_request(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_QUEUE_GET_CONFIG_REPLY" then
            ofp_queue_get_config_reply(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_ROLE_REQUEST" or
               ofp_type[_type] == "OFPT_ROLE_REPLY" then
            ofp_role_request(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_GET_ASYNC_REQUEST" then
            -- There is no body for OFPT_GET_ASYNC_REQUEST beyond the OpenFlow header.
            return

        elseif ofp_type[_type] == "OFPT_GET_ASYNC_REPLY" or
               ofp_type[_type] == "OFPT_SET_ASYNC" then
            -- The OFPT_SET_ASYNC and OFPT_GET_ASYNC_REPLY messages have the following format:  
            ofp_async_config(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        elseif ofp_type[_type] == "OFPT_METER_MOD" then
            ofp_meter_mod(buffer(pointer,buffer:len()-pointer), pinfo, of13_tree)

        end
    end
end


-- -------------------------------------------------
-- 7.2 Common Structures
-- -------------------------------------------------

-- 7.2.1 Port Structures
-- -------------------------------------------------
ofp_port_port_no_F    = ProtoField.uint32("of13.port_port_no",    "Port")
ofp_port_pad1_F       = ProtoField.uint32("of13.port_pad1",       "Padding")
ofp_port_hw_addr_F    = ProtoField.string("of13.port_hw_addr",    "HW Addr")
ofp_port_pad2_F       = ProtoField.string("of13.port_pad2",       "Padding")
ofp_port_name_F       = ProtoField.string("of13.port_name",       "Name")
ofp_port_config_F     = ProtoField.uint32("of13.port_config",     "Config")
ofp_port_state_F      = ProtoField.uint32("of13.port_state",      "State")
ofp_port_curr_F       = ProtoField.uint32("of13.port_curr",       "Current features")
ofp_port_advertised_F = ProtoField.uint32("of13.port_advertised", "Advertize features")
ofp_port_supported_F  = ProtoField.uint32("of13.port_supported",  "Supported features")
ofp_port_peer_F       = ProtoField.uint32("of13.port_peer",       "Advertize features by peer")
ofp_port_curr_speed_F = ProtoField.uint32("of13.port_curr_speed", "Port bitrate [kbps]")
ofp_port_max_speed_F  = ProtoField.uint32("of13.port_max_speed",  "Max bitrate [kbps]")

function ofp_port(buffer, pinfo, tree)
    local _port_no_range    = buffer(0,4)
    local _pad1_range       = buffer(4,4)
    local _hw_addr_range    = buffer(8,6)
    local _pad2_range       = buffer(14,2)
    local _name_range       = buffer(16,16)
    local _config_range     = buffer(32,4)
    local _state_range      = buffer(36,4)
    local _curr_range       = buffer(40,4)
    local _advertised_range = buffer(44,4)
    local _supported_range  = buffer(48,4)
    local _peer_range       = buffer(52,4)
    local _curr_speed_range = buffer(56,4)
    local _max_speed_range  = buffer(60,4)
    local pointer = 64

    local _port_no    = _port_no_range:uint()
    local _pad1       = tostring(_pad1_range)
    local _hw_addr    = tostring(_hw_addr_range:ether())
    local _pad2       = tostring(_pad2_range)
    local _name       = _name_range:stringz()
    local _config     = _config_range:uint()
    local _state      = _state_range:uint()
    local _curr       = _curr_range:uint()
    local _advertised = _advertised_range:uint()
    local _supported  = _supported_range:uint()
    local _peer       = _peer_range:uint()
    local _curr_speed = _curr_speed_range:uint()
    local _max_speed  = _max_speed_range:uint()

    tree:add(ofp_port_port_no_F   , _port_no_range   , _port_no   )
    tree:add(ofp_port_pad1_F      , _pad1_range      , _pad1      )
    tree:add(ofp_port_hw_addr_F   , _hw_addr_range   , _hw_addr   )
    tree:add(ofp_port_pad2_F      , _pad2_range      , _pad2      )
    tree:add(ofp_port_name_F      , _name_range      , _name      )
    tree:add(ofp_port_config_F    , _config_range    , _config    )
    tree:add(ofp_port_state_F     , _state_range     , _state     )
    tree:add(ofp_port_curr_F      , _curr_range      , _curr      )
    tree:add(ofp_port_advertised_F, _advertised_range, _advertised)
    tree:add(ofp_port_supported_F , _supported_range , _supported )
    tree:add(ofp_port_peer_F      , _peer_range      , _peer      )
    tree:add(ofp_port_curr_speed_F, _curr_speed_range, _curr_speed)
    tree:add(ofp_port_max_speed_F , _max_speed_range , _max_speed )

    return pointer
end

-- 7.2.2 Queue Structures
-- -------------------------------------------------
ofp_packet_queue_queue_id_F = ProtoField.uint32("of13.packet_queue_queue_id", "Queue ID")
ofp_packet_queue_port_F     = ProtoField.uint32("of13.packet_queue_port",     "Port")
ofp_packet_queue_len_F      = ProtoField.uint16("of13.packet_queue_len",      "Length")
ofp_packet_queue_pad_F      = ProtoField.string("of13.packet_queue_pad",      "Padding")

ofp_queue_properties = {
    [1] = "OFPQT_MIN_RATE",
    [2] = "OFPQT_MAX_RATE",
    [0xffff] = "OFPQT_EXPERIMENTER",
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

function ofp_packet_queue(buffer, pinfo, tree)
    local _queue_id_range = buffer(0,4)
    local _port_range     = buffer(4,4)
    local _len_range      = buffer(8,2)
    local _pad_range      = buffer(10,6)
    local pointer = 16

    local _queue_id = _queue_id_range:uint()
    local _port     = _port_range:uint()
    local _len      = _len_range:uint()
    local _pad      = tostring(_pad_range)

    tree:add(ofp_packet_queue_queue_id_F, _queue_id_range, _queue_id)
    tree:add(ofp_packet_queue_port_F    , _port_range    , _port    )
    tree:add(ofp_packet_queue_len_F     , _len_range     , _len     )
    tree:add(ofp_packet_queue_pad_F     , _pad_range     , _pad     )

    -- XXX : ofp_queue_prop_header

    return pointer
end

function ofp_queue_prop_header(buffer, pinfo, tree)
    return 0
end

function ofp_queue_prop_min_rate(buffer, pinfo, tree)
    return 0
end

function ofp_queue_prop_max_rate(buffer, pinfo, tree)
    return 0
end

function ofp_queue_prop_experimenter(buffer, pinfo, tree)
    return 0
end

-- 7.2.3 Flow Match Structures
-- -------------------------------------------------
ofp_match_F         = ProtoField.string("of13.match",        "Flow Match Header")
ofp_match_type_F    = ProtoField.uint16("of13.match_type",   "Type")
ofp_match_length_F  = ProtoField.uint16("of13.match_length", "Length")
ofp_match_ofp_oxm_F = ProtoField.uint16("of13.match_oxm",    "OXM")
ofp_match_pad_F     = ProtoField.string("of13.match_pad",    "Padding")

ofp_oxm_F         = ProtoField.string("of13.oxm",        "Flow Match Fileld")
ofp_oxm_class_F   = ProtoField.uint16("of13.oxm_class",  "Match class: member class ie reserved class", base.HEX)
ofp_oxm_field_F   = ProtoField.uint8("of13.oxm_field",   "Match field within the class", base.HEX, nil, 0xfe)
ofp_oxm_hasmask_F = ProtoField.uint8("of13.oxm_hasmask", "Set if OXM include a bitmask in payload", base.HEX, VALS_BOOL, 0x01)
ofp_oxm_length_F  = ProtoField.uint8("of13.oxm_length",  "Length of OXM payload")
ofp_oxm_value_F   = ProtoField.string("of13.oxm_value",  "Value")
ofp_oxm_mask_F    = ProtoField.string("of13.oxm_mask",   "Mask ")

ofp_match_type_string = {
    [0] = "OFPMT_STANDARD",
    [1] = "OFPMT_OXM",
}

ofp_oxm_field_string = {
    [0x0000] = "OFPXMC_NXM_0",          -- Backward compatibility with NXM
    [0x0001] = "OFPXMC_NXM_1",          -- Backward compatibility with NXM
    [0x0003] = "OFPXMC_BSN_0",          -- Big Switch Networks
    [0x0004] = "OFPXMC_HP_0",           -- HP
    [0x0005] = "OFPXMC_FS_0",           -- Freescale
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

function ofp_match(buffer, pinfo, tree)
    local _type_range   = buffer(0,2)
    local _length_range = buffer(2,2)
    local pointer = 4

    local _type   = _type_range:uint()
    local _length = _length_range:uint()

    local subtree = tree:add(ofp_match_F, buffer(0,_length), "Flow Match Header")
    subtree:add(ofp_match_type_F,   _type_range,   _type):append_text(" (" .. ofp_match_type_string[_type] .. ")")
    subtree:add(ofp_match_length_F, _length_range, _length)

    while pointer < _length do
        offset = ofp_oxm_field(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset
    end

    local _pad_range = buffer(pointer, math.ceil(_length/8)*8 - pointer)
    local _pad = tostring(_pad_range)
    subtree:add(ofp_match_pad_F, _pad_range, _pad)
    pointer = pointer + (math.ceil(_length/8)*8 - pointer)

    return pointer
end

function ofp_oxm_field(buffer, pinfo, tree)
    local _class_range  = buffer(0,2)
    local _fh_range     = buffer(2,1)
    local _length_range = buffer(3,1)
    local pointer = 4

    local _class   = _class_range:uint()
    local _fh      = _fh_range:uint()
    local _field   = _fh_range:bitfield(0, 7)
    local _hasmask = _fh_range:bitfield(7, 1)
    local _length  = _length_range:uint()

    local subtree = tree:add(ofp_oxm_F, buffer(0, pointer + _length), "Flow Match Field Structure")
    subtree:add(ofp_oxm_class_F,   _class_range,  _class):append_text(" (" .. ofp_oxm_field_string[_class] .. ")")
    subtree:add(ofp_oxm_field_F,   _fh_range,     _fh):append_text(" (" .. oxm_ofb_match_fields[_field][1] .. ")")
    subtree:add(ofp_oxm_hasmask_F, _fh_range,     _fh)
    subtree:add(ofp_oxm_length_F,  _length_range, _length)

    local _value_range = buffer(pointer, _length)
    local _mask_range
    if _hasmask == 1 then
        _value_range = buffer(pointer, _length/2)
        _mask_range = buffer(pointer+(_length/2), _length/2)
    end

    if ofp_oxm_field_string[_class] == "OFPXMC_OPENFLOW_BASIC" then
        if _hasmask == 1 then
            if oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IN_PORT" or
               oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IN_PHY_PORT" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())
                subtree:add(ofp_oxm_mask_F, _mask_range,  _mask_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_METADATA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range, tostring(_mask_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_SRC" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ether()))
                subtree:add(ofp_oxm_mask_F, _mask_range, tostring(_mask_range:ether()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_TYPE" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range, tostring(_mask_range))

            -- XXX - combination for VLAN tags. 
            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_VLAN_VID" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_VLAN_PCP" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_DSCP" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_ECN" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_PROTO" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())
                subtree:add(ofp_oxm_mask_F, _mask_range,  _mask_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV4_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV4_DST" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ipv4()))
                subtree:add(ofp_oxm_mask_F,  _mask_range,  tostring(_mask_range:ipv4()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TCP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TCP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_UDP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_UDP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_SCTP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_SCTP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV4_TYPE" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV4_CODE" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())
                subtree:add(ofp_oxm_mask_F, _mask_range,  _mask_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_OP" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range, tostring(_mask_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_SPA" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_TPA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ipv4()))
                subtree:add(ofp_oxm_mask_F,  _mask_range,  tostring(_mask_range:ipv4()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_SHA" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_THA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ether()))
                subtree:add(ofp_oxm_mask_F, _mask_range, tostring(_mask_range:ether()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_FLABEL" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range,  tostring(_mask_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV6_TYPE" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV6_CODE" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())
                subtree:add(ofp_oxm_mask_F, _mask_range,  _mask_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_TARGET" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_SLL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_TLL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_MPLS_LABEL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_MPLS_TC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFP_MPLS_BOS" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range,  tostring(_mask_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_PBB_ISID" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TUNNEL_ID" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())
                subtree:add(ofp_oxm_mask_F, _mask_range,  _mask_range:uint())

            -- XXX
            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_EXTHDR" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range,  tostring(_mask_range))

            else
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
                subtree:add(ofp_oxm_mask_F, _mask_range,  tostring(_mask_range))

            end
        else
            if oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IN_PORT" or
               oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IN_PHY_PORT" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_METADATA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_SRC" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ether()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ETH_TYPE" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_VLAN_VID" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_VLAN_PCP" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_DSCP" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_ECN" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IP_PROTO" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV4_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV4_DST" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ipv4()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TCP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TCP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_UDP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_UDP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_SCTP_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_SCTP_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV4_TYPE" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV4_CODE" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_OP" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_SPA" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_TPA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ipv4()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_SHA" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ARP_THA" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range:ether()))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_SRC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_DST" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_FLABEL" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV6_TYPE" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_ICMPV6_CODE" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_TARGET" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_SLL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_ND_TLL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_MPLS_LABEL" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_MPLS_TC" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFP_MPLS_BOS" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_PBB_ISID" or
                   oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_TUNNEL_ID" then
                subtree:add(ofp_oxm_value_F, _value_range, _value_range:uint())

            elseif oxm_ofb_match_fields[_field][1] == "OFPXMT_OFB_IPV6_EXTHDR" then
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            else
                subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))

            end
        end
    else
        if _hasmask == 1 then
            subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
            subtree:add(ofp_oxm_mask_F,  _mask_range,  tostring(_mask_range))
        else
            subtree:add(ofp_oxm_value_F, _value_range, tostring(_value_range))
        end
    end
    pointer = pointer + _length

    return pointer
end

-- 7.2.4 Flow Instruction Structures
-- -------------------------------------------------
ofp_instruction_F               = ProtoField.string("of13.instruction",               "Flow Instruction")
ofp_instruction_type_F          = ProtoField.string("of13.instruction_type",          "Type")
ofp_instruction_length_F        = ProtoField.string("of13.instruction_length",        "Length")
ofp_instruction_table_id_F      = ProtoField.string("of13.instruction_table_id",      "Table ID")
ofp_instruction_pad_F           = ProtoField.string("of13.instruction_pad",           "Padding")
ofp_instruction_metadata_F      = ProtoField.string("of13.instruction_metadata",      "Metadata")
ofp_instruction_metadata_mask_F = ProtoField.string("of13.instruction_metadata_mask", "Metadata mask")
ofp_instruction_meter_F         = ProtoField.string("of13.instruction_meter",         "Meter")

-- 7.2.4 Flow Instruction Structures
-- -------------------------------------------------
ofp_instruction_type = {
    [1] = "OFPIT_GOTO_TABLE",        -- Setup the next table in the lookup pipeline
    [2] = "OFPIT_WRITE_METADATA",    -- Setup the metadata field for use later in pipeline
    [3] = "OFPIT_WRITE_ACTIONS",     -- Write the action(s) onto the datapath action set
    [4] = "OFPIT_APPLY_ACTIONS",     -- Applies the action(s) immediately
    [5] = "OFPIT_CLEAR_ACTIONS",     -- Clears all actions from the datapath action set
    [6] = "OFPIT_METER",             -- Apply meter (rate limiter)
    [0xffff] = "OFPIT_EXPERIMENTER", -- Experimenter instruction
}

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
        local _pad_range  = buffer(pointer+1,3)
        pointer = pointer + 4

        local _table_id = _table_id_range:uint()
        local _pad  = tostring(_pad_range)

        subtree:add(ofp_instruction_table_id_F, _table_id_range, _table_id)
        subtree:add(ofp_instruction_pad_F,  _pad_range,  _pad)

    elseif ofp_instruction_type[_type] == "OFPIT_WRITE_METADATA" then
        local _pad_range       = buffer(pointer,4)
        local _metadata_range      = buffer(pointer+4,8)
        local _metadata_mask_range = buffer(pointer+12,8)
        pointer = pointer + 20

        local _pad       = tostring(_pad_range)
        local _metadata      = _metadata_range:uint64()
        local _metadata_mask = _metadata_mask_range:uint64()

        subtree:add(ofp_instruction_pad_F,  _pad_range,  _pad)
        subtree:add(ofp_instruction_metadata_F, _metadata_range, _metadata)
        subtree:add(ofp_instruction_metadata_mask_F, _metadata_mask_range, _metadata_mask)

    elseif ofp_instruction_type[_type] == "OFPIT_WRITE_ACTIONS" or
           ofp_instruction_type[_type] == "OFPIT_APPLY_ACTIONS" or
           ofp_instruction_type[_type] == "OFPIT_CLEAR_ACTIONS" then
        local _pad_range  = buffer(pointer,4)
        pointer = pointer + 4
        local _pad  = tostring(_pad_range)
        subtree:add(ofp_instruction_pad_F,  _pad_range,  _pad)

        -- Action Header dissector
        while buffer:len() > pointer do
            offset = ofp_action_header(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
            pointer = pointer + offset
        end

    elseif ofp_instruction_type[_type] == "OFPIT_METER" then
        local _meter_range  = buffer(pointer,4)
        pointer = pointer + 4
        local _meter  = _meter_range:uint()
        subtree:add(ofp_instruction_meter_F,  _meter_range,  _meter)

    elseif ofp_instruction_type[_type] == "OFPIT_EXPERIMENTER" then
        Dissector.get("data"):call(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    end

    return pointer
end

-- 7.2.5 Action Structures
-- -------------------------------------------------
ofp_action_header_F             = ProtoField.string("of13.action",                "Action")
ofp_action_header_type_F        = ProtoField.uint16("of13.action_type",           "One of OFPAT_*")
ofp_action_header_length_F      = ProtoField.uint16("of13.action_length",         "Length of action, including this header")
ofp_action_header_pad_F         = ProtoField.string("of13.action_pad",            "Pad to 64 bits")
ofp_action_output_port_F        = ProtoField.uint32("of13.action_output_port",    "Output port")
ofp_action_output_max_len_F     = ProtoField.uint16("of13.action_output_maxlen",  "Max length to send to controller")
ofp_action_output_pad_F         = ProtoField.string("of13.action_output_pad",     "Pad to 64 bits")
ofp_action_group_group_id_F     = ProtoField.uint32("of13.action_group_id",       "Group ID")
ofp_action_group_queue_id_F     = ProtoField.uint32("of13.action_queue_id",       "Queue ID")
ofp_action_mpls_ttl_mpls_ttl_F  = ProtoField.uint32("of13.action_mpls_ttl",       "MPLS TTL")
ofp_action_mpls_ttl_pad_F       = ProtoField.string("of13.action_mpls_pad",       "Padding")
ofp_action_nw_ttl_nw_ttl_F      = ProtoField.uint8("of13.nw_ttl",                 "IP TTL")
ofp_action_nw_ttl_pad_F         = ProtoField.string("of13.nw_ttl_pad",            "Pad to 64 bits")
ofp_action_push_ethertype_F     = ProtoField.uint16("of13.action_push_type",      "EtherType", base.HEX)
ofp_action_push_pad_F           = ProtoField.string("of13.action_push_pad",       "Padding")
ofp_action_pop_mpls_ethertype_F = ProtoField.uint16("of13.action_pop_mpls_type",  "EtherType", base.HEX)
ofp_action_pop_mpls_pad_F       = ProtoField.string("of13.action_pop_mpls_pad",   "Padding")
ofp_action_set_field_type_F     = ProtoField.uint16("of13.action_set_field_type", "Type")
ofp_action_set_field_len_F      = ProtoField.uint16("of13.action_set_field_len",  "Length")
ofp_action_experimenter_F       = ProtoField.uint32("of13.action_expetimenter",   "Experimenter")

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

    elseif ofp_action_type[_type] == "OFPAT_COPY_TTL_OUT" or
           ofp_action_type[_type] == "OFPAT_COPY_TTL_IN" or
           ofp_action_type[_type] == "OFPAT_DEC_MPLS_TTL" or
           ofp_action_type[_type] == "OFPAT_POP_VLAN" or
           ofp_action_type[_type] == "OFPAT_DEC_NW_TTL" or
           ofp_action_type[_type] == "OFPAT_POP_PBB" then
        offset = 4
        local _pad_range = buffer(pointer,4)
        local _pad = tostring(_pad_range)
        subtree:add(ofp_action_header_pad_F, _pad_range, _pad)
        offset = 4

    elseif ofp_action_type[_type] == "OFPAT_SET_MPLS_TTL" then
        offset = ofp_action_mpls_ttl(buffer(pointer,buffer:len()-pointer), pinfo, subtree)

    elseif ofp_action_type[_type] == "OFPAT_PUSH_VLAN" then
        offset = ofp_action_push(buffer(pointer,buffer:len()-pointer), pinfo, subtree)

    elseif ofp_action_type[_type] == "OFPAT_PUSH_MPLS" then
        offset = ofp_action_push(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    elseif ofp_action_type[_type] == "OFPAT_POP_MPLS" then

        offset = ofp_action_pop_mpls(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    elseif ofp_action_type[_type] == "OFPAT_SET_QUEUE" then

        offset = ofp_action_set_queue(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    elseif ofp_action_type[_type] == "OFPAT_GROUP" then

        offset = ofp_action_group(buffer(pointer,buffer:len()-pointer), pinfo, subtree)

    elseif ofp_action_type[_type] == "OFPAT_SET_NW_TTL" then
        offset = ofp_action_nw_ttl(buffer(pointer,buffer:len()-pointer), pinfo, subtree)

    elseif ofp_action_type[_type] == "OFPAT_SET_FIELD" then
        offset = ofp_oxm_field(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset
        local _pad_range = buffer(pointer, math.ceil(_length/8)*8 - pointer)
        local _pad = tostring(_pad_range)
        subtree:add(ofp_action_header_pad_F, _pad_range, _pad)
        offset = (math.ceil(_length/8)*8) - pointer

    elseif ofp_action_type[_type] == "OFPAT_PUSH_PBB" then
        offset = ofp_action_push(buffer(pointer,buffer:len()-pointer), pinfo, subtree)

    elseif ofp_action_type[_type] == "OFPAT_EXPERIMENTER" then
        offset = ofp_action_experimenter(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    end

    pointer = pointer + offset
    return pointer
end

function ofp_action_output(buffer, pinfo, tree)
    local _port_range    = buffer(0,4)
    local _max_len_range = buffer(4,2)
    local _pad_range = buffer(6,6)
    local pointer = 12

    local _port    = _port_range:uint()
    local _max_len = _max_len_range:uint()
    local _pad = tostring(_pad_range)

    local _port_F = tree:add(ofp_action_output_port_F, _port_range, _port)
    if not ofp_port_no[_port] == nil then
        _port_F:append_text(" (" .. ofp_port_no[_port] .. ")")
    end

    local _max_len_F = tree:add(ofp_action_output_max_len_F, _max_len_range, _max_len)
    if not ofp_controller_max_len[_max_len] == nil then
        _max_len_F:append_text(" (" .. ofp_controller_max_len[_max_len] .. ")")
    end

    tree:add(ofp_action_output_pad_F, _pad_range, _pad)

    return pointer
end

function ofp_action_group(buffer, pinfo, tree)
    local _group_id_range = buffer(0,4)
    local pointer = 4

    local _group_id = _group_id_range:uint()

    tree:add(ofp_action_group_group_id_F, _group_id_range, _group_id)

    return pointer
end

function ofp_action_set_queue(buffer, pinfo, tree)
    local _queue_id_range = buffer(0,4)
    local pointer = 4

    local _queue_id = _queue_id_range:uint()

    tree:add(ofp_action_group_queue_id_F, _queue_id_range, _queue_id)

    return pointer
end

function ofp_action_mpls_ttl(buffer, pinfo, tree)
    local _mpls_ttl_range  = buffer(0,1)
    local _pad_range   = buffer(1,3)
    local pointer = 4

    local _mpls_ttl = _mpls_ttl_range:uint()
    local _pad  = tostring(_pad_range)

    tree:add(ofp_action_mpls_ttl_mpls_ttl_F, _mpls_ttl_range, _mpls_ttl)
    tree:add(ofp_action_mpls_ttl_pad_F,  _pad_range,  _pad)

    return pointer
end

function ofp_action_nw_ttl(buffer, pinfo, tree)
    local _nw_ttl_range  = buffer(0,1)
    local _pad_range = buffer(1,3)
    local pointer = 4

    local _nw_ttl  = _nw_ttl_range:uint()
    local _pad = tostring(_pad_range)

    tree:add(ofp_action_nw_ttl_nw_ttl_F,  _nw_ttl_range,  _nw_ttl)
    tree:add(ofp_action_nw_ttl_pad_F, _pad_range, _pad)

    return pointer
end

function ofp_action_push(buffer, pinfo, tree)
    local _ethertype_range = buffer(0,2)
    local _pad_range   = buffer(2,2)
    local pointer = 4

    local _ethertype = _ethertype_range:uint()
    local _pad   = tostring(_pad_range)

    tree:add(ofp_action_push_ethertype_F, _ethertype_range, _ethertype)
    tree:add(ofp_action_push_pad_F,   _pad_range,   _pad)

    return pointer
end

function ofp_action_pop_mpls(buffer, pinfo, tree)
    local _ethertype_range = buffer(0,2)
    local _pad_range   = buffer(2,2)
    local pointer = 4

    local _ethertype = _ethertype_range:uint()
    local _pad   = tostring(_pad_range)

    tree:add(ofp_action_pop_mpls_ethertype_F, _ethertype_range, _ethertype)
    tree:add(ofp_action_pop_mpls_pad_F,   _pad_range,   _pad)

    return pointer
end

function ofp_action_set_field(buffer, pinfo, tree)
    local _type_range = buffer(0,2)
    local _len_range  = buffer(2,2)
    local pointer = 4

    local _type = _type_range:uint()
    local _len  = _len_range:uint()

    tree:add(ofp_action_set_field_type_F, _type_range, _type)
    tree:add(ofp_action_set_field_len_F , _len_range , _len)

    offset = ofp_oxm_field(buffer(pointer,buffer:len()-pointer), pinfo, tree)
    pointer = pointer + offset

    local _pad_range = buffer(pointer, math.ceil(_len/8)*8 - pointer)
    local _pad = tostring(_pad_range)
    tree:add(ofp_action_set_field_pad_F, _pad_range, _pad)
    pointer = pointer + (math.ceil(_len/8)*8 - pointer)

    return pointer
end

function ofp_action_experimenter(buffer, pinfo, tree)
    local _experimenter_range = buffer(0,4)
    local pointer = 4

    local _experimenter = _experimenter_range:uint()

    tree:add(ofp_action_experimenter_F, _experimenter_range, _experimenter)

    return pointer
end


-- -------------------------------------------------
-- 7.3 Controller-to-Switch Messages
-- -------------------------------------------------

-- 7.3.1 Handshake
-- -------------------------------------------------
ofp_switch_features_F                           = ProtoField.string("of13.feature",                  "Switch features")
ofp_switch_features_datapath_id_F               = ProtoField.uint64("of13.feature_datapath_id",      "Datapath unique ID", base.HEX)
ofp_switch_features_n_buffers_F                 = ProtoField.uint32("of13.feature_n_buffers",        "Max packets buffered at once")
ofp_switch_features_n_tables_F                  = ProtoField.uint8 ("of13.feature_n_tables",         "Number of tables supported by datapath")
ofp_switch_features_auxiliary_id_F              = ProtoField.uint8 ("of13.feature_auxiliary_id",     "Identify auxiliary connections")
ofp_switch_features_pad_F                       = ProtoField.string("of13.feature_pad",              "Align to 64-bits")
ofp_switch_features_capabilities_F              = ProtoField.uint32("of13.feature_capabilities",     "Bitmap of support ofp_capabilities", base.HEX)
ofp_switch_features_reserved_F                  = ProtoField.string("of13.feature_reserved",         "reserved")
ofp_switch_features_capabilities_flow_stats_F   = ProtoField.uint32("of13.feature_cap_flow",         "Flow statistics", base.HEX, VALS_BOOL, 0x00000001)
ofp_switch_features_capabilities_table_stats_F  = ProtoField.uint32("of13.feature_cap_table",        "Table statistics", base.HEX, VALS_BOOL, 0x00000002)
ofp_switch_features_capabilities_port_stats_F   = ProtoField.uint32("of13.feature_cap_port",         "Port statistics", base.HEX, VALS_BOOL, 0x00000004)
ofp_switch_features_capabilities_group_stats_F  = ProtoField.uint32("of13.feature_cap_group",        "Group statistics", base.HEX, VALS_BOOL, 0x00000008)
ofp_switch_features_capabilities_ip_reasm_F     = ProtoField.uint32("of13.feature_cap_ip_reasm",     "Can reassemble IP fragments", base.HEX, VALS_BOOL, 0x00000020)
ofp_switch_features_capabilities_queue_stats_F  = ProtoField.uint32("of13.feature_cap_queue",        "Queue statistics", base.HEX, VALS_BOOL, 0x00000040)
ofp_switch_features_capabilities_port_blocked_F = ProtoField.uint32("of13.feature_cap_port_blocked", "Switch will block looping ports", base.HEX, VALS_BOOL, 0x00000100)

function ofp_switch_features(buffer, pinfo, tree)
    local _datapath_id_range  = buffer(0,8)
    local _n_buffers_range    = buffer(8,4)
    local _n_tables_range     = buffer(12,1)
    local _auxiliary_id_range = buffer(13,1)
    local _pad_range          = buffer(14,2)
    local _capabilities_range = buffer(16,4)
    local _reserved_range     = buffer(20,4)
    local pointer = 24

    local _datapath_id  = _datapath_id_range:uint64()
    local _n_buffers    = _n_buffers_range:uint()
    local _n_tables     = _n_tables_range:uint()
    local _auxiliary_id = _auxiliary_id_range:uint()
    local _pad          = tostring(_pad_range)
    local _capabilities = _capabilities_range:uint()
    local _reserved     = tostring(_reserved_range)

    local subtree = tree:add(ofp_switch_features_F, buffer())
    subtree:add(ofp_switch_features_datapath_id_F,  _datapath_id_range,  _datapath_id)
    subtree:add(ofp_switch_features_n_buffers_F,    _n_buffers_range,    _n_buffers)
    subtree:add(ofp_switch_features_n_tables_F,     _n_tables_range,     _n_tables)
    subtree:add(ofp_switch_features_auxiliary_id_F, _auxiliary_id_range, _auxiliary_id)
    subtree:add(ofp_switch_features_pad_F,          _pad_range,          _pad)
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

-- 7.3.2 Swtich Configuration
-- -------------------------------------------------
ofp_config_flags_F         = ProtoField.uint16("of13.config_flags",         "OFPC_* flags", base.HEX)
ofp_config_miss_send_len_F = ProtoField.uint16("of13.config_miss_send_len", "Max bytes of packet")

function ofp_switch_config(buffer, pinfo, tree)
    local _flags_range         = buffer(0,2)
    local _miss_send_len_range = buffer(2,2)
    local pointer = 4

    local _flags         = _flags_range:uint()
    local _miss_send_len = _miss_send_len_range:uint()

    tree:add(ofp_config_flags_F,         _flags_range,         _flags)
    -- TODO: ofp_config_flags
    tree:add(ofp_config_miss_send_len_F, _miss_send_len_range, _miss_send_len)

    return pointer
end

-- 7.3.3 Flow Table Configuration
-- -------------------------------------------------
ofp_table_mod_table_id_F = ProtoField.uint8("of13.table_mod_table_id", "Table ID")
ofp_table_mod_pad_F      = ProtoField.string("of13.table_mod_pad",     "Padding")
ofp_table_mod_config_F   = ProtoField.uint32("of13.table_mod_config",  "Config")

function ofp_table_mod(buffer, pinfo, tree)
    local _table_id_range = buffer(0,1)
    local _pad_range      = buffer(1,3)
    local _config_range   = buffer(4,4)
    local pointer = 8

    local _table_id = _table_id_range:uint()
    local _pad      = tostring(_pad_range)
    local _config   = _config_range:uint()

    -- XXX : ofp_table
    tree:add(ofp_table_mod_table_id_F, _table_id_range, _table_id)
    tree:add(ofp_table_mod_pad_F     , _pad_range     , _pad     )
    -- XXX : ofp_table_config
    tree:add(ofp_table_mod_config_F  , _config_range  , _config  )

    return pointer
end

-- 7.3.4 Modify State Messages
-- -------------------------------------------------
ofp_flow_mod_F              = ProtoField.string("of13.flowmod" ,             "Modify Flow Entry Message")
ofp_flow_mod_cookie_F       = ProtoField.uint64("of13.flowmod_cookie",       "Cookie", base.HEX)
ofp_flow_mod_cookie_mask_F  = ProtoField.uint64("of13.flowmod_cookie_mask",  "Cookie mask", base.HEX)
ofp_flow_mod_table_id_F     = ProtoField.uint8("of13.flowmod_table_id",      "Table ID")
ofp_flow_mod_command_F      = ProtoField.uint8("of13.flowmod_command",       "Command")
ofp_flow_mod_idle_timeout_F = ProtoField.uint16("of13.flowmod_idle_timeout", "Idle timeout")
ofp_flow_mod_hard_timeout_F = ProtoField.uint16("of13.flowmod_hard_timeout", "Hard timeout")
ofp_flow_mod_priority_F     = ProtoField.uint16("of13.flowmod_priority",     "Priority")
ofp_flow_mod_buffer_id_F    = ProtoField.uint32("of13.flowmod_buffer_id",    "Buffer ID")
ofp_flow_mod_out_port_F     = ProtoField.uint32("of13.flowmod_out_port",     "Out port")
ofp_flow_mod_out_group_F    = ProtoField.uint32("of13.flowmod_out_group",    "Out group")
ofp_flow_mod_flags_F        = ProtoField.uint16("of13.flowmod_flags",        "Flags", base.HEX)
ofp_flow_mod_pad_F          = ProtoField.string("of13.flowmod_pad",          "Padding")

ofp_flow_mod_flags_send_flow_rem_F = ProtoField.uint16("of13.mod_flag_flow_rem",      "Flow removed", base.HEX, VALS_BOOL, 0x0001)
ofp_flow_mod_flags_check_overlap_F = ProtoField.uint16("of13.mod_flag_check_overlap", "Check overlap", base.HEX, VALS_BOOL, 0x0002)
ofp_flow_mod_flags_reset_counts_F  = ProtoField.uint16("of13.mod_flag_reset_count",   "Reset count", base.HEX, VALS_BOOL, 0x0004)
ofp_flow_mod_flags_no_pkt_counts_F = ProtoField.uint16("of13.mod_flag_no_pkt_count",  "No packet count", base.HEX, VALS_BOOL, 0x0008)
ofp_flow_mod_flags_no_byt_counts_F = ProtoField.uint16("of13.mod_flag_no_byt_count",  "No byte count", base.HEX, VALS_BOOL, 0x0010)

ofp_group_mod_command_F  = ProtoField.uint16("of13.group_mod_command",  "Command")
ofp_group_mod_type_F     = ProtoField.uint8("of13.group_mod_type",      "Type")
ofp_group_mod_pad_F      = ProtoField.string("of13.group_mod_pad",      "Padding")
ofp_group_mod_group_id_F = ProtoField.uint32("of13.group_mod_group_id", "Group ID")

ofp_bucket_len_F         = ProtoField.uint16("of13.bucket_len",         "Length")
ofp_bucket_weight_F      = ProtoField.uint16("of13.bucket_weight",      "Weight")
ofp_bucket_watch_port_F  = ProtoField.uint32("of13.bucket_watch_port",  "Watch port")
ofp_bucket_watch_group_F = ProtoField.uint32("of13.bucket_watch_group", "Watch group")
ofp_bucket_pad_F         = ProtoField.string("of13.bucket_pad",         "Padding")

ofp_port_mod_port_no_F   = ProtoField.uint32("of13.ofp_port_mod_port_no",   "Port No")
ofp_port_mod_pad_F       = ProtoField.string("of13.ofp_port_mod_pad",       "Padding")
ofp_port_mod_hw_addr_F   = ProtoField.string("of13.ofp_port_mod_hw_addr",   "HW Addr")
ofp_port_mod_pad2_F      = ProtoField.string("of13.ofp_port_mod_pad2",      "Padding")
ofp_port_mod_config_F    = ProtoField.uint32("of13.ofp_port_mod_config",    "Config")
ofp_port_mod_mask_F      = ProtoField.uint32("of13.ofp_port_mod_mask",      "Mask")
ofp_port_mod_advertise_F = ProtoField.uint32("of13.ofp_port_mod_advertise", "Advertise")
ofp_port_mod_pad3_F      = ProtoField.string("of13.ofp_port_mod_pad3",      "Padding")

ofp_meter_mod_command_F  = ProtoField.uint16("of13.meter_mod_command",  "Command")
ofp_meter_mod_flags_F    = ProtoField.uint16("of13.meter_mod_flags",    "Flags")
ofp_meter_mod_meter_id_F = ProtoField.uint32("of13.meter_mod_meter_id", "Meter ID")

ofp_meter_band_header_type_F       = ProtoField.uint32("of13.ofp_meter_band_header_type_F",       "Type")
ofp_meter_band_header_len_F        = ProtoField.uint32("of13.ofp_meter_band_header_len_F",        "Length")
ofp_meter_band_header_rate_F       = ProtoField.uint32("of13.ofp_meter_band_header_rate_F",       "Rate")
ofp_meter_band_header_burst_size_F = ProtoField.uint32("of13.ofp_meter_band_header_burst_size_F", "Burst size")

ofp_flow_mod_command = {
    [0] = "OFPFC_ADD",           -- New flow.
    [1] = "OFPFC_MODIFY",        -- Modify all matching flows.
    [2] = "OFPFC_MODIFY_STRICT", -- Modify entry strictly matching wildcards and priority.
    [3] = "OFPFC_DELETE",        -- Delete all matching flows.
    [4] = "OFPFC_DELETE_STRICT", -- Delete entry strictly matching wildcards and priority.
}

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
    local _pad_range      = buffer(38,2)
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
    local _pad      = tostring(_pad_range)

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
    subtree:add(ofp_flow_mod_pad_F,      _pad_range,      _pad)

    -- Flow Match Header dissector
    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Flow Instruction Structures
    if buffer:len() > pointer then
        offset = ofp_instruction(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset
    end

    return pointer
end

function ofp_group_mod(buffer, pinfo, tree)
    local _command_range  = buffer(0,2)
    local _type_range     = buffer(2,1)
    local _pad_range      = buffer(3,1)
    local _group_id_range = buffer(4,4)
    local pointer = 8

    local _command  = _command_range:uint()
    local _type     = _type_range:uint()
    local _pad      = tostring(_pad_range)
    local _group_id = _group_id_range:uint()

    -- XXX : ofp_group_mod_command
    tree:add(ofp_group_mod_command_F , _command_range , _command )
    -- XXX : ofp_group_type
    tree:add(ofp_group_mod_type_F    , _type_range    , _type    )
    tree:add(ofp_group_mod_pad_F     , _pad_range     , _pad     )
    -- XXX : ofp_group
    tree:add(ofp_group_mod_group_id_F, _group_id_range, _group_id)

    return pointer
end

function ofp_bucket(buffer, pinfo, tree)
    local _len_range         = buffer(0,2)
    local _weight_range      = buffer(2,2)
    local _watch_port_range  = buffer(4,4)
    local _watch_group_range = buffer(8,4)
    local _pad_range         = buffer(12,4)
    local pointer = 16

    local _len         = _len_range:uint()
    local _weight      = _weight_range:uint()
    local _watch_port  = _watch_port_range:uint()
    local _watch_group = _watch_group_range:uint()
    local _pad         = tostring(_pad_range)

    tree:add(ofp_bucket_len_F        , _len_range        , _len        )
    tree:add(ofp_bucket_weight_F     , _weight_range     , _weight     )
    tree:add(ofp_bucket_watch_port_F , _watch_port_range , _watch_port )
    tree:add(ofp_bucket_watch_group_F, _watch_group_range, _watch_group)
    tree:add(ofp_bucket_pad_F        , _pad_range        , _pad        )

    while _len > pointer do
        offset = ofp_action_header(buffer(pointer,buffer:len()-pointer), pinfo, tree)
        pointer = pointer + offset
    end

    return pointer
end

function ofp_port_mod(buffer, pinfo, tree)
    local _port_no_range   = buffer(0,4)
    local _pad_range       = buffer(4,4)
    local _hw_addr_range   = buffer(8,6)
    local _pad2_range      = buffer(14,2)
    local _config_range    = buffer(16,4)
    local _mask_range      = buffer(20,4)
    local _advertise_range = buffer(24,4)
    local _pad3_range      = buffer(28,4)
    local pointer = 32

    local _port_no   = _port_no_range:uint()
    local _pad       = tostring(_pad_range)
    local _hw_addr   = tostring(_hw_addr_range:ether())
    local _pad2      = tostring(_pad2_range)
    local _config    = _config_range:uint()
    local _mask      = _mask_range:uint()
    local _advertise = _advertise_range:uint()
    local _pad3      = tostring(_pad3_range)

    tree:add(ofp_port_mod_port_no_F  , _port_no_range  , _port_no  )
    tree:add(ofp_port_mod_pad_F      , _pad_range      , _pad      )
    tree:add(ofp_port_mod_hw_addr_F  , _hw_addr_range  , _hw_addr  )
    tree:add(ofp_port_mod_pad2_F     , _pad2_range     , _pad2     )
    tree:add(ofp_port_mod_config_F   , _config_range   , _config   )
    tree:add(ofp_port_mod_mask_F     , _mask_range     , _mask     )
    tree:add(ofp_port_mod_advertise_F, _advertise_range, _advertise)
    tree:add(ofp_port_mod_pad3_F     , _pad3_range     , _pad3     )

    return pointer
end

function ofp_meter_mod(buffer, pinfo, tree)
    local _command_range  = buffer(0,2)
    local _flags_range    = buffer(2,2)
    local _meter_id_range = buffer(4,4)
    local pointer = 8

    local _command  = _command_range:uint()
    local _flags    = _flags_range:uint()
    local _meter_id = _meter_id_range:uint()

    -- XXX : ofp_meter_mod_command
    tree:add(ofp_meter_mod_command_F , _command_range , _command )
    -- XXX : ofp_meter_flags
    tree:add(ofp_meter_mod_flags_F   , _flags_range   , _flags   )
    -- XXX : ofp_meter
    tree:add(ofp_meter_mod_meter_id_F, _meter_id_range, _meter_id)

    while buffer:len() > pointer do
        offset = ofp_meter_band_header(buffer(pointer,buffer:len()-pointer), pinfo, tree)
        pointer = pointer + offset
    end

    return pointer
end

function ofp_meter_band_header(buffer, pinfo, tree)
    local _type_range       = buffer(0,2)
    local _len_range        = buffer(2,2)
    local _rate_range       = buffer(4,4)
    local _burst_size_range = buffer(8,4)
    local pointer = 12

    local _type       = _type_range:uint()
    local _len        = _len_range:uint()
    local _rate       = _rate_range:uint()
    local _burst_size = _burst_size_range:uint()

    -- XXX : ofp_meter_band_type
    tree:add(ofp_meter_band_header_type_F      , _type_range      , _type      )
    tree:add(ofp_meter_band_header_len_F       , _len_range       , _len       )
    tree:add(ofp_meter_band_header_rate_F      , _rate_range      , _rate      )
    tree:add(ofp_meter_band_header_burst_size_F, _burst_size_range, _burst_size)

    -- XXX : ofp_meter_band_type
    if _type == "" then
    end

    return pointer
end

-- 7.3.5 Multipart Messages
-- -------------------------------------------------
ofp_multipart_request_F       = ProtoField.string("of13.multipart_request",       "Multipart Reqeust")
ofp_multipart_request_type_F  = ProtoField.uint16("of13.multipart_request_type",  "Type")
ofp_multipart_request_flags_F = ProtoField.uint16("of13.multipart_request_flags", "Flags")
ofp_multipart_request_pad_F   = ProtoField.string("of13.multipart_request_pad",   "Padding")

ofp_multipart_reply_F         = ProtoField.string("of13.multipart_reply",         "Multipart Reply")
ofp_multipart_reply_type_F    = ProtoField.uint16("of13.multipart_reply_type",    "Type")
ofp_multipart_reply_flags_F   = ProtoField.uint16("of13.multipart_reply_flags",   "Flags")
ofp_multipart_reply_pad_F     = ProtoField.string("of13.multipart_reply_pad",     "Padding")

ofp_multipart_request_flags = {
    [0] = "Last in the next",
    [1] = "OFPMPF_REQ_MORE",
}

ofp_multipart_reply_flags = {
    [0] = "Last in the next",
    [1] = "OFPMPF_REPLY_MORE",
}

ofp_multipart_types = {
    [0] = "OFPMP_DESC",              -- Description of this OpenFlow switch.
    [1] = "OFPMP_FLOW",              -- Individual flow statistics.
    [2] = "OFPMP_AGGREGATE",         -- Aggregate flow statistics.
    [3] = "OFPMP_TABLE",             -- Flow table statistics.
    [4] = "OFPMP_PORT_STATS",        -- Port statistics.
    [5] = "OFPMP_QUEUE",             -- Queue statistics for a port
    [6] = "OFPMP_GROUP",             -- Group counter statistics.
    [7] = "OFPMP_GROUP_DESC",        -- Group description.
    [8] = "OFPMP_GROUP_FEATURES",    -- Group features.
    [9] = "OFPMP_METER",             -- Meter statistics.
    [10] = "OFPMP_METER_CONFIG",     -- Meter configuration.
    [11] = "OFPMP_METER_FEATURES",   -- Meter features.
    [12] = "OFPMP_TABLE_FEATURES",   -- Table features.
    [13] = "OFPMP_PORT_DESC",        -- Port description.
    [0xffff] = "OFPMP_EXPERIMENTER", -- Experimenter extension.
}

function ofp_multipart_request(buffer, pinfo, tree)
    local _type_range    = buffer(0,2)
    local _flags_range   = buffer(2,2)
    local _pad_range = buffer(4,4)
    local pointer = 8

    local _type       = _type_range:uint()
    local _flags      = _flags_range:uint()
    local _flags_more = _flags_range:bitfield(0, 1)
    local _pad    = tostring(_pad_range)

    local subtree = tree:add(ofp_multipart_request_F, buffer(), ofp_multipart_types[_type])
    local _type_F = subtree:add(ofp_multipart_request_type_F, _type_range, _type)
    if not ofp_multipart_types[_type] == nil then
        _type_F:append_text(" (" .. ofp_multipart_types[_type] .. ")")
    end
    local _flags_F = subtree:add(ofp_multipart_request_flags_F, _flags_range, _flags)
    if not ofp_multipart_request_flags[_flags] == nil then
        _flags_F:append_text(" (" .. ofp_multipart_request_flags[_flags] .. ")")
    end
    subtree:add(ofp_multipart_request_pad_F, _pad_range, _pad)

    if buffer:len() <= pointer then
        return
    end

    offset = 0
    if ofp_multipart_types[_type] == "OFPMP_DESC" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_FLOW" then
        -- The request body is struct ofp_flow_stats_request.
        offset = ofp_flow_stats_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_AGGREGATE" then
        -- The request body is struct ofp_aggregate_stats_request.
        offset = ofp_aggregate_stats_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_TABLE" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_PORT_STATS" then
        -- The request body is struct ofp_port_stats_request.
        offset = ofp_port_stats_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_QUEUE" then
        -- The request body is struct ofp_queue_stats_request.
        offset = ofp_queue_stats_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP" then
        -- The request body is struct ofp_group_stats_request.
        offset = ofp_group_stats_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP_DESC" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP_FEATURES" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_METER" or
           ofp_multipart_types[_type] == "OFPMP_METER_CONFIG" then
        -- The request body is struct ofp_meter_multipart_requests.
        offset = ofp_meter_multipart_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_METER_FEATURES" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_TABLE_FEATURES" then
        -- The request body is either empty or contains an array of
        -- struct ofp_table_features containing the controller's
        -- desired view of the switch. If the switch is unable to
        -- set the specified view an error is returned.
        if buffer:len() > pointer then
            offset = ofp_table_features(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)
        end

    elseif ofp_multipart_types[_type] == "OFPMP_PORT_DESC" then
        -- The request body is empty.

    elseif ofp_multipart_types[_type] == "OFPMP_EXPERIMENTER" then
        -- The request and reply bodies begin with
        -- struct ofp_experimenter_multipart_header.
        -- The request and reply bodies are otherwise experimenter-defined.
        offset = ofp_experimenter_multipart_header(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)
    end
    pointer = pointer + offset

    if buffer:len() == pointer then
        return
    end

    if _flags_more == 1 then
        ofp_multipart_request(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, tree)
    elseif _flags_more == 0 then
        Dissector.get("of13"):call(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, tree)
    end
end

function ofp_multipart_reply(buffer, pinfo, tree)
    local _type_range    = buffer(0,2)
    local _flags_range   = buffer(2,2)
    local _pad_range = buffer(4,4)
    local pointer = 8

    local _type       = _type_range:uint()
    local _flags      = _flags_range:uint()
    local _flags_more = _flags_range:bitfield(0, 1)
    local _pad    = tostring(_pad_range)

    local subtree = tree:add(ofp_multipart_reply_F, buffer(), ofp_multipart_types[_type])
    subtree:add(ofp_multipart_reply_type_F, _type_range, _type):append_text(" (" .. ofp_multipart_types[_type] .. ")")
    if ofp_multipart_reply_flags[_flags] == nil then
        subtree:add(ofp_multipart_reply_flags_F, _flags_range, _flags):append_text(" (Not defined)")
    else
        subtree:add(ofp_multipart_reply_flags_F, _flags_range, _flags):append_text(" (" .. ofp_multipart_reply_flags[_flags] .. ")")
    end
    subtree:add(ofp_multipart_reply_pad_F, _pad_range, _pad)

    if buffer:len() <= pointer then
        return
    end

    offset = 0
    if ofp_multipart_types[_type] == "OFPMP_DESC" then
        -- The reply body is struct ofp_desc.
        offset = ofp_desc(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_FLOW" then
        -- The reply body is an array of struct ofp_flow_stats.
        offset = ofp_flow_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_AGGREGATE" then
        -- The reply body is struct ofp_aggregate_stats_reply.
        offset = ofp_aggregate_stats_reply(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_TABLE" then
        -- The reply body is an array of struct ofp_table_stats.
        offset = ofp_table_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_PORT_STATS" then
        -- The reply body is an array of struct ofp_port_stats.
        offset = ofp_port_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_QUEUE" then
        -- The reply body is an array of struct ofp_queue_stats
        offset = ofp_queue_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP" then
        -- The reply is an array of struct ofp_group_stats.
        offset = ofp_group_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP_DESC" then
        -- The reply body is an array of struct ofp_group_desc.
        offset = ofp_group_desc(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_GROUP_FEATURES" then
        -- The reply body is struct ofp_group_features.
        offset = ofp_group_features(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_METER" then
        -- The reply body is an array of struct ofp_meter_stats.
        offset = ofp_meter_stats(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_METER_CONFIG" then
        -- The reply body is an array of struct ofp_meter_config.
        offset = ofp_meter_config(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_METER_FEATURES" then
        -- The reply body is struct ofp_meter_features.
        offset = ofp_meter_features(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_TABLE_FEATURES" then
        -- The reply body is an array of struct ofp_table_features.
        offset = ofp_table_features(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_PORT_DESC" then
        -- The reply body is an array of struct ofp_port.
        offset = ofp_port(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    elseif ofp_multipart_types[_type] == "OFPMP_EXPERIMENTER" then
        -- The request and reply bodies begin with
        -- struct ofp_experimenter_multipart_header.
        -- The request and reply bodies are otherwise experimenter-defined.
        offset = ofp_experimenter_multipart_header(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, subtree)

    end
    pointer = pointer + offset

    if buffer:len() <= pointer then
        return
    end

    if _flags_more == 1 then
        ofp_multipart_reply(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, tree)
    elseif _flags_more == 0 then
        Dissector.get("of13"):call(buffer(pointer,buffer:len()-pointer):tvb(), pinfo, tree)
    end
end

-- 7.3.5.1 Description
ofp_desc_mfr_desc_F   = ProtoField.string("of13.desc_mfr",    "Manufacturer")
ofp_desc_hw_desc_F    = ProtoField.string("of13.desc_hw",     "Hardware")
ofp_desc_sw_desc_F    = ProtoField.string("of13.desc_sw",     "Software")
ofp_desc_serial_num_F = ProtoField.string("of13.desc_serial", "Serial")
ofp_desc_dp_desc_F    = ProtoField.string("of13.desc_dp",     "Description")

function ofp_desc(buffer, pinfo, tree)
    DESC_STR_LEN = 256
    SERIAL_NUM_LEN = 32
    local _mfr_desc_range   = buffer(0,DESC_STR_LEN)
    local _hw_desc_range    = buffer(256,DESC_STR_LEN)
    local _sw_desc_range    = buffer(512,DESC_STR_LEN)
    local _serial_num_range = buffer(768,SERIAL_NUM_LEN)
    local _dp_desc_range    = buffer(800,DESC_STR_LEN)
    local pointer = 1056

    local _mfr_desc   = _mfr_desc_range:stringz()
    local _hw_desc    = _hw_desc_range:stringz()
    local _sw_desc    = _sw_desc_range:stringz()
    local _serial_num = _serial_num_range:stringz()
    local _dp_desc    = _dp_desc_range:stringz()

    tree:add(ofp_desc_mfr_desc_F  , _mfr_desc_range  , _mfr_desc  )
    tree:add(ofp_desc_hw_desc_F   , _hw_desc_range   , _hw_desc   )
    tree:add(ofp_desc_sw_desc_F   , _sw_desc_range   , _sw_desc   )
    tree:add(ofp_desc_serial_num_F, _serial_num_range, _serial_num)
    tree:add(ofp_desc_dp_desc_F   , _dp_desc_range   , _dp_desc   )
    return pointer
end

-- 7.3.5.2 Individual Flow Statistics
ofp_flow_stats_request_table_id_F    = ProtoField.uint8("of13.flow_stats_request_table_id",     "Table ID")
ofp_flow_stats_request_pad1_F        = ProtoField.string("of13.flow_stats_request_pad1",        "Padding")
ofp_flow_stats_request_out_port_F    = ProtoField.uint32("of13.flow_stats_request_out_port",    "Out Port")
ofp_flow_stats_request_out_group_F   = ProtoField.uint32("of13.flow_stats_request_out_group",   "Out Group")
ofp_flow_stats_request_pad2_F        = ProtoField.string("of13.flow_stats_request_pad2",        "Padding")
ofp_flow_stats_request_cookie_F      = ProtoField.uint64("of13.flow_stats_request_cookie",      "Cookie", base.HEX)
ofp_flow_stats_request_cookie_mask_F = ProtoField.uint64("of13.flow_stats_request_cookie_mask", "Cookie Mask", base.HEX)

ofp_flow_stats_F               = ProtoField.string("of13.flow_stats",               "ofp_flow_stats")
ofp_flow_stats_length_F        = ProtoField.uint16("of13.flow_stats_length",        "Length")
ofp_flow_stats_table_id_F      = ProtoField.uint8("of13.flow_stats_table_id",       "Table ID")
ofp_flow_stats_pad1_F          = ProtoField.string("of13.flow_stats_pad1",          "Padding")
ofp_flow_stats_duration_sec_F  = ProtoField.uint32("of13.flow_stats_duration_sec",  "Duration sec")
ofp_flow_stats_duration_nsec_F = ProtoField.uint32("of13.flow_stats_duration_nsec", "Duration nsec")
ofp_flow_stats_priority_F      = ProtoField.uint16("of13.flow_stats_priority",      "Priority")
ofp_flow_stats_idle_timeout_F  = ProtoField.uint16("of13.flow_stats_idle_timeout",  "Idle timeout")
ofp_flow_stats_hard_timeout_F  = ProtoField.uint16("of13.flow_stats_hard_timeout",  "Hard timeout")
ofp_flow_stats_flags_F         = ProtoField.uint16("of13.flow_stats_flags",         "Flags")
ofp_flow_stats_pad2_F          = ProtoField.string("of13.flow_stats_pad2",          "Padding")
ofp_flow_stats_cookie_F        = ProtoField.uint64("of13.flow_stats_cookie",        "Cookie", base.HEX)
ofp_flow_stats_packet_count_F  = ProtoField.uint64("of13.flow_stats_packet_count",  "Packet count")
ofp_flow_stats_byte_count_F    = ProtoField.uint64("of13.flow_stats_byte_count",    "Byte count")

function ofp_flow_stats_request(buffer, pinfo, tree)
    local _table_id_range    = buffer(0,1)
    local _pad1_range        = buffer(1,3)
    local _out_port_range    = buffer(4,4)
    local _out_group_range   = buffer(8,4)
    local _pad2_range        = buffer(12,4)
    local _cookie_range      = buffer(16,8)
    local _cookie_mask_range = buffer(24,8)
    local pointer = 32

    local _table_id    = _table_id_range:uint()
    local _pad1        = tostring(_pad1_range)
    local _out_port    = _out_port_range:uint()
    local _out_group   = _out_group_range:uint()
    local _pad2        = tostring(_pad2_range)
    local _cookie      = _cookie_range:uint64()
    local _cookie_mask = _cookie_mask_range:uint64()

    tree:add(ofp_flow_stats_request_table_id_F   , _table_id_range   , _table_id   )
    tree:add(ofp_flow_stats_request_pad1_F       , _pad1_range       , _pad1       )
    tree:add(ofp_flow_stats_request_out_port_F   , _out_port_range   , _out_port   )
    tree:add(ofp_flow_stats_request_out_group_F  , _out_group_range  , _out_group  )
    tree:add(ofp_flow_stats_request_pad2_F       , _pad2_range       , _pad2       )
    tree:add(ofp_flow_stats_request_cookie_F     , _cookie_range     , _cookie     )
    tree:add(ofp_flow_stats_request_cookie_mask_F, _cookie_mask_range, _cookie_mask)

    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, tree)
    pointer = pointer + offset

    return pointer
end

function ofp_flow_stats(buffer, pinfo, tree)
    local _length_range        = buffer(0,2)
    local _table_id_range      = buffer(2,1)
    local _pad1_range          = buffer(3,1)
    local _duration_sec_range  = buffer(4,4)
    local _duration_nsec_range = buffer(8,4)
    local _priority_range      = buffer(12,2)
    local _idle_timeout_range  = buffer(14,2)
    local _hard_timeout_range  = buffer(16,2)
    local _flags_range         = buffer(18,2)
    local _pad2_range          = buffer(20,4)
    local _cookie_range        = buffer(24,8)
    local _packet_count_range  = buffer(32,8)
    local _byte_count_range    = buffer(40,8)
    local pointer = 48

    local _length        = _length_range:uint()
    local _table_id      = _table_id_range:uint()
    local _pad1          = tostring(_pad1_range)
    local _duration_sec  = _duration_sec_range:uint()
    local _duration_nsec = _duration_nsec_range:uint()
    local _priority      = _priority_range:uint()
    local _idle_timeout  = _idle_timeout_range:uint()
    local _hard_timeout  = _hard_timeout_range:uint()
    local _flags         = _flags_range:uint()
    local _pad2          = tostring(_pad2_range)
    local _cookie        = _cookie_range:uint64()
    local _packet_count  = _packet_count_range:uint64()
    local _byte_count    = _byte_count_range:uint64()

    local subtree = tree:add(ofp_flow_stats_F, buffer(0,_length))
    subtree:add(ofp_flow_stats_length_F,        _length_range       , _length       )
    subtree:add(ofp_flow_stats_table_id_F,      _table_id_range     , _table_id     )
    subtree:add(ofp_flow_stats_pad1_F,          _pad1_range         , _pad1         )
    subtree:add(ofp_flow_stats_duration_sec_F,  _duration_sec_range , _duration_sec )
    subtree:add(ofp_flow_stats_duration_nsec_F, _duration_nsec_range, _duration_nsec)
    subtree:add(ofp_flow_stats_priority_F,      _priority_range     , _priority     )
    subtree:add(ofp_flow_stats_idle_timeout_F,  _idle_timeout_range , _idle_timeout )
    subtree:add(ofp_flow_stats_hard_timeout_F,  _hard_timeout_range , _hard_timeout )
    subtree:add(ofp_flow_stats_flags_F,         _flags_range        , _flags        )
    subtree:add(ofp_flow_stats_pad2_F,          _pad2_range         , _pad2         )
    subtree:add(ofp_flow_stats_cookie_F,        _cookie_range       , _cookie       )
    subtree:add(ofp_flow_stats_packet_count_F,  _packet_count_range , _packet_count )
    subtree:add(ofp_flow_stats_byte_count_F,    _byte_count_range   , _byte_count   )

    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Flow Instruction Structures
    if buffer:len() > pointer then
        offset = ofp_flow_stats(buffer(pointer,buffer:len()-pointer), pinfo, tree)
        pointer = pointer + offset
    end

    return pointer
end

-- 7.3.5.3 Aggregate Flow Statistics
ofp_aggregate_stats_request_table_id_F    = ProtoField.uint8 ("of13.aggregate_stats_request_table_id",    "Tab;e ID")
ofp_aggregate_stats_request_pad1_F        = ProtoField.string("of13.aggregate_stats_request_pad1",        "Padding")
ofp_aggregate_stats_request_out_port_F    = ProtoField.uint32("of13.aggregate_stats_request_out_port",    "Out Port")
ofp_aggregate_stats_request_out_group_F   = ProtoField.uint32("of13.aggregate_stats_request_out_group",   "Out Group")
ofp_aggregate_stats_request_pad2_F        = ProtoField.string("of13.aggregate_stats_request_pad2",        "Padding")
ofp_aggregate_stats_request_cookie_F      = ProtoField.uint64("of13.aggregate_stats_request_cookie",      "Cookie", base.HEX)
ofp_aggregate_stats_request_cookie_mask_F = ProtoField.uint64("of13.aggregate_stats_request_cookie_mask", "Cookie Mask", base.HEX)

ofp_aggregate_stats_reply_packet_count_F = ProtoField.uint64("of13.aggregate_stats_reply_packet_count", "Packet count")
ofp_aggregate_stats_reply_byte_count_F   = ProtoField.uint64("of13.aggregate_stats_reply_byte_count",   "Byte count")
ofp_aggregate_stats_reply_flow_count_F   = ProtoField.uint32("of13.aggregate_stats_reply_flow_count",   "Flow count")
ofp_aggregate_stats_reply_pad_F          = ProtoField.string("of13.aggregate_stats_reply_pad",          "Padding")

function ofp_aggregate_stats_request(buffer, pinfo, tree)
    local _table_id_range    = buffer(0,1)
    local _pad1_range        = buffer(1,3)
    local _out_port_range    = buffer(4,4)
    local _out_group_range   = buffer(8,4)
    local _pad2_range        = buffer(12,4)
    local _cookie_range      = buffer(16,8)
    local _cookie_mask_range = buffer(24,8)
    local pointer = 32

    local _table_id    = _table_id_range:uint()
    local _pad1        = tostring(_pad1_range)
    local _out_port    = _out_port_range:uint()
    local _out_group   = _out_group_range:uint()
    local _pad2        = tostring(_pad2_range)
    local _cookie      = _cookie_range:uint64()
    local _cookie_mask = _cookie_mask_range:uint64()

    tree:add(ofp_aggregate_stats_request_table_id_F   , _table_id_range   , _table_id   )
    tree:add(ofp_aggregate_stats_request_pad1_F       , _pad1_range       , _pad1       )
    tree:add(ofp_aggregate_stats_request_out_port_F   , _out_port_range   , _out_port   )
    tree:add(ofp_aggregate_stats_request_out_group_F  , _out_group_range  , _out_group  )
    tree:add(ofp_aggregate_stats_request_pad2_F       , _pad2_range       , _pad2       )
    tree:add(ofp_aggregate_stats_request_cookie_F     , _cookie_range     , _cookie     )
    tree:add(ofp_aggregate_stats_request_cookie_mask_F, _cookie_mask_range, _cookie_mask)

    return pointer
end

function ofp_aggregate_stats_reply(buffer, pinfo, tree)
    local _packet_count_range = buffer(0,8)
    local _byte_count_range   = buffer(8,8)
    local _flow_count_range   = buffer(16,4)
    local _pad_range          = buffer(20,4)
    local pointer = 24

    local _packet_count = _packet_count_range:uint64()
    local _byte_count   = _byte_count_range:uint64()
    local _flow_count   = _flow_count_range:uint()
    local _pad          = tostring(_pad_range)

    tree:add(ofp_aggregate_stats_reply_packet_count_F, _packet_count_range, _packet_count)
    tree:add(ofp_aggregate_stats_reply_byte_count_F  , _byte_count_range  , _byte_count  )
    tree:add(ofp_aggregate_stats_reply_flow_count_F  , _flow_count_range  , _flow_count  )
    tree:add(ofp_aggregate_stats_reply_pad_F         , _pad_range         , _pad         )

    -- Flow Match Header dissector
    if buffer:len() > pointer then
        offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
        pointer = pointer + offset
    end

    return pointer
end

-- 7.3.5.4 Table Statistics
ofp_table_stats_table_id_F      = ProtoField.uint8("of13.table_stats_table_id",       "Table ID")
ofp_table_stats_pad_F           = ProtoField.string("of13.table_stats_pad",           "Padding")
ofp_table_stats_active_count_F  = ProtoField.uint32("of13.table_stats_active_count",  "Active count")
ofp_table_stats_lookup_count_F  = ProtoField.uint64("of13.table_stats_lookup_count",  "Lookup count")
ofp_table_stats_matched_count_F = ProtoField.uint64("of13.table_stats_matched_count", "Matched count")

function ofp_table_stats(buffer, pinfo, tree)
    local _table_id_range      = buffer(0,1)
    local _pad_range           = buffer(1,3)
    local _active_count_range  = buffer(4,4)
    local _lookup_count_range  = buffer(8,8)
    local _matched_count_range = buffer(16,8)
    local pointer = 24

    local _table_id      = _table_id_range:uint()
    local _pad           = tostring(_pad_range)
    local _active_count  = _active_count_range:uint()
    local _lookup_count  = _lookup_count_range:uint64()
    local _matched_count = _matched_count_range:uint64()

    tree:add(ofp_table_stats_table_id_F     , _table_id_range     , _table_id     )
    tree:add(ofp_table_stats_pad_F          , _pad_range          , _pad          )
    tree:add(ofp_table_stats_active_count_F , _active_count_range , _active_count )
    tree:add(ofp_table_stats_lookup_count_F , _lookup_count_range , _lookup_count )
    tree:add(ofp_table_stats_matched_count_F, _matched_count_range, _matched_count)

    return pointer
end

-- 7.3.5.5 Table Features
ofp_table_features_length_F         = ProtoField.uint16("of13.table_features_length",         "Length")
ofp_table_features_table_id_F       = ProtoField.uint8 ("of13.table_features_table_id",       "Table ID")
ofp_table_features_pad_F            = ProtoField.string("of13.table_features_pad",            "Padding")
ofp_table_features_name_F           = ProtoField.uint64("of13.table_features_name",           "Name")
ofp_table_features_metadata_match_F = ProtoField.uint64("of13.table_features_metadata_match", "Metadata match")
ofp_table_features_metadata_write_F = ProtoField.uint64("of13.table_features_metadata_write", "Metadata write")
ofp_table_features_config_F         = ProtoField.uint32("of13.table_features_config",         "Config")
ofp_table_features_max_entries_F    = ProtoField.uint32("of13.table_features_max_entries",    "Max entries")

function ofp_table_features(buffer, pinfo, tree)
    local _length_range         = buffer(0,2)
    local _table_id_range       = buffer(2,1)
    local _pad_range            = buffer(3,5)
    local _name_range           = buffer(8,32)
    local _metadata_match_range = buffer(40,8)
    local _metadata_write_range = buffer(48,8)
    local _config_range         = buffer(56,4)
    local _max_entries_range    = buffer(60,4)
    local pointer = 64

    local _length         = _length_range:uint()
    local _table_id       = _table_id_range:uint()
    local _pad            = tostring(_pad_range)
    local _name           = tostring(_name_range)
    local _metadata_match = _metadata_match_range:uint64()
    local _metadata_write = _metadata_write_range:uint64()
    local _config         = _config_range:uint()
    local _max_entries    = _max_entries_range:uint()

    tree:add(ofp_table_features_length_F         , _length_range        , _length        )
    tree:add(ofp_table_features_table_id_F       , _table_id_range      , _table_id      )
    tree:add(ofp_table_features_pad_F            , _pad_range           , _pad           )
    tree:add(ofp_table_features_name_F           , _name_range          , _name          )
    tree:add(ofp_table_features_metadata_match_F , _metadata_match_range, _metadata_match)
    tree:add(ofp_table_features_metadata_write_F , _metadata_write_range, _metadata_write)
    tree:add(ofp_table_features_config_F         , _config_range        , _config        )
    tree:add(ofp_table_features_max_entries_F    , _max_entries_range   , _max_entries   )

    -- XXX : ofp_table_feature_prop_header

    return pointer
end

function ofp_table_feature_prop_header(buffer, pinfo, tree)
    return 0
end

-- 7.3.5.6 Port Statistics
ofp_port_stats_request_port_F        = ProtoField.uint32("of13.port_stats_request_port",          "Port")
ofp_port_stats_request_pad_F         = ProtoField.string("of13.port_stats_request_pad",           "Padding")
ofp_port_stats_reply_port_F          = ProtoField.uint32("of13.port_stats_request_port",          "Port")
ofp_port_stats_reply_pad_F           = ProtoField.string("of13.port_stats_request_pad",           "Padding")
ofp_port_stats_reply_rx_packets_F    = ProtoField.uint64("of13.port_stats_request_rx_packets",    "RX packets")
ofp_port_stats_reply_tx_packets_F    = ProtoField.uint64("of13.port_stats_request_tx_packets",    "TX packets")
ofp_port_stats_reply_rx_bytes_F      = ProtoField.uint64("of13.port_stats_request_rx_bytes",      "RX bytes")
ofp_port_stats_reply_tx_bytes_F      = ProtoField.uint64("of13.port_stats_request_tx_bytes",      "TX bytes")
ofp_port_stats_reply_rx_dropped_F    = ProtoField.uint64("of13.port_stats_request_rx_dropped",    "RX dropped")
ofp_port_stats_reply_tx_dropped_F    = ProtoField.uint64("of13.port_stats_request_tx_dropped",    "TX dropped")
ofp_port_stats_reply_rx_errors_F     = ProtoField.uint64("of13.port_stats_request_rx_errors",     "RX error")
ofp_port_stats_reply_tx_errors_F     = ProtoField.uint64("of13.port_stats_request_tx_errors",     "TX error")
ofp_port_stats_reply_rx_frame_err_F  = ProtoField.uint64("of13.port_stats_request_rx_frame_err",  "RX frame error")
ofp_port_stats_reply_rx_over_err_F   = ProtoField.uint64("of13.port_stats_request_rx_over_err",   "RX overrun error")
ofp_port_stats_reply_rx_crc_err_F    = ProtoField.uint64("of13.port_stats_request_rx_crc_err",    "RX CRC error")
ofp_port_stats_reply_collisions_F    = ProtoField.uint64("of13.port_stats_request_collisions",    "Collitions")
ofp_port_stats_reply_duration_sec_F  = ProtoField.uint32("of13.port_stats_request_duration_sec",  "Port alive [sec]")
ofp_port_stats_reply_duration_nsec_F = ProtoField.uint32("of13.port_stats_request_duration_nsec", "Port alive [nsec]")

function ofp_port_stats_request(buffer, pinfo, tree)
    local _port_range = buffer(0,4)
    local _pad_range  = buffer(4,4)
    local pointer = 8

    local _port = _port_range:uint()
    local _pad  = tostring(_pad_range)

    local _port_F = tree:add(ofp_port_stats_request_port_F, _port_range, _port)
    if not ofp_port_no[_port] == nil then
        _port_F:append_text(" (" .. ofp_port_no[_port] .. ")")
    end
    tree:add(ofp_port_stats_request_pad_F, _pad_range, _pad)
    return pointer
end

function ofp_port_stats(buffer, pinfo, tree)
    local _port_range          = buffer(0,4)
    local _pad_range           = buffer(4,4)
    local _rx_packets_range    = buffer(8,8)
    local _tx_packets_range    = buffer(16,8)
    local _rx_bytes_range      = buffer(24,8)
    local _tx_bytes_range      = buffer(32,8)
    local _rx_dropped_range    = buffer(40,8)
    local _tx_dropped_range    = buffer(48,8)
    local _rx_errors_range     = buffer(56,8)
    local _tx_errors_range     = buffer(64,8)
    local _rx_frame_err_range  = buffer(72,8)
    local _rx_over_err_range   = buffer(80,8)
    local _rx_crc_err_range    = buffer(88,8)
    local _collisions_range    = buffer(96,8)
    local _duration_sec_range  = buffer(104,4)
    local _duration_nsec_range = buffer(108,4)
    local pointer = 112

    local _port          = _port_range:uint()
    local _pad           = tostring(_pad_range)
    local _rx_packets    = _rx_packets_range:uint64()
    local _tx_packets    = _tx_packets_range:uint64()
    local _rx_bytes      = _rx_bytes_range:uint64()
    local _tx_bytes      = _tx_bytes_range:uint64()
    local _rx_dropped    = _rx_dropped_range:uint64()
    local _tx_dropped    = _tx_dropped_range:uint64()
    local _rx_errors     = _rx_errors_range:uint64()
    local _tx_errors     = _tx_errors_range:uint64()
    local _rx_frame_err  = _rx_frame_err_range:uint64()
    local _rx_over_err   = _rx_over_err_range:uint64()
    local _rx_crc_err    = _rx_crc_err_range:uint64()
    local _collisions    = _collisions_range:uint64()
    local _duration_sec  = _duration_sec_range:uint()
    local _duration_nsec = _duration_nsec_range:uint()

    local _port_F = tree:add(ofp_port_stats_request_port_F, _port_range, _port)
    if not ofp_port_no[_port] == nil then
        _port_F:append_text(" (" .. ofp_port_no[_port] .. ")")
    end
    tree:add(ofp_port_stats_reply_pad_F          , _pad_range          , _pad          )
    tree:add(ofp_port_stats_reply_rx_packets_F   , _rx_packets_range   , _rx_packets   )
    tree:add(ofp_port_stats_reply_tx_packets_F   , _tx_packets_range   , _tx_packets   )
    tree:add(ofp_port_stats_reply_rx_bytes_F     , _rx_bytes_range     , _rx_bytes     )
    tree:add(ofp_port_stats_reply_tx_bytes_F     , _tx_bytes_range     , _tx_bytes     )
    tree:add(ofp_port_stats_reply_rx_dropped_F   , _rx_dropped_range   , _rx_dropped   )
    tree:add(ofp_port_stats_reply_tx_dropped_F   , _tx_dropped_range   , _tx_dropped   )
    tree:add(ofp_port_stats_reply_rx_errors_F    , _rx_errors_range    , _rx_errors    )
    tree:add(ofp_port_stats_reply_tx_errors_F    , _tx_errors_range    , _tx_errors    )
    tree:add(ofp_port_stats_reply_rx_frame_err_F , _rx_frame_err_range , _rx_frame_err )
    tree:add(ofp_port_stats_reply_rx_over_err_F  , _rx_over_err_range  , _rx_over_err  )
    tree:add(ofp_port_stats_reply_rx_crc_err_F   , _rx_crc_err_range   , _rx_crc_err   )
    tree:add(ofp_port_stats_reply_collisions_F   , _collisions_range   , _collisions   )
    tree:add(ofp_port_stats_reply_duration_sec_F , _duration_sec_range , _duration_sec )
    tree:add(ofp_port_stats_reply_duration_nsec_F, _duration_nsec_range, _duration_nsec)
    return pointer
end

-- 7.3.5.7 Port Description
-- See 7.2.1

-- 7.3.5.8 Queue Statistics
ofp_queue_stats_request_port_no_F  = ProtoField.uint32("of13.queue_stats_request_port_no",  "Port No")
ofp_queue_stats_request_queue_id_F = ProtoField.uint32("of13.queue_stats_request_queue_id", "Queue ID")

ofp_queue_stats_port_no_F       = ProtoField.uint32("of13.queue_stats_port_no",       "Port No")
ofp_queue_stats_queue_id_F      = ProtoField.uint32("of13.queue_stats_queue_id",      "Queue ID")
ofp_queue_stats_tx_bytes_F      = ProtoField.uint64("of13.queue_stats_tx_bytes",      "TX Bytes")
ofp_queue_stats_tx_packets_F    = ProtoField.uint64("of13.queue_stats_tx_packets",    "TX Packets")
ofp_queue_stats_tx_errors_F     = ProtoField.uint64("of13.queue_stats_tx_errors",     "TX Errors")
ofp_queue_stats_duration_sec_F  = ProtoField.uint32("of13.queue_stats_duration_sec",  "Duration sec")
ofp_queue_stats_duration_nsec_F = ProtoField.uint32("of13.queue_stats_duration_nsec", "Duration nsec")

function ofp_queue_stats_request(buffer, pinfo, tree)
    local _port_no_range  = buffer(0,4)
    local _queue_id_range = buffer(4,4)
    local pointer = 8

    local _port_no  = _port_no_range:uint()
    local _queue_id = _queue_id_range:uint()

    tree:add(ofp_queue_stats_request_port_no_F , _port_no_range , _port_no ) 
    tree:add(ofp_queue_stats_request_queue_id_F, _queue_id_range, _queue_id)

    return pointer
end

function ofp_queue_stats(buffer, pinfo, tree)
    local _port_no_range       = buffer(0,4)
    local _queue_id_range      = buffer(4,4)
    local _tx_bytes_range      = buffer(8,8)
    local _tx_packets_range    = buffer(16,8)
    local _tx_errors_range     = buffer(24,8)
    local _duration_sec_range  = buffer(32,4)
    local _duration_nsec_range = buffer(36,4)
    local pointer = 40

    local _port_no       = _port_no_range:uint()
    local _queue_id      = _queue_id_range:uint()
    local _tx_bytes      = _tx_bytes_range:uint64()
    local _tx_packets    = _tx_packets_range:uint64()
    local _tx_errors     = _tx_errors_range:uint64()
    local _duration_sec  = _duration_sec_range:uint()
    local _duration_nsec = _duration_nsec_range:uint()

    tree:add(ofp_queue_stats_port_no_F      , _port_no_range      , _port_no      )
    tree:add(ofp_queue_stats_queue_id_F     , _queue_id_range     , _queue_id     )
    tree:add(ofp_queue_stats_tx_bytes_F     , _tx_bytes_range     , _tx_bytes     )
    tree:add(ofp_queue_stats_tx_packets_F   , _tx_packets_range   , _tx_packets   )
    tree:add(ofp_queue_stats_tx_errors_F    , _tx_errors_range    , _tx_errors    )
    tree:add(ofp_queue_stats_duration_sec_F , _duration_sec_range , _duration_sec )
    tree:add(ofp_queue_stats_duration_nsec_F, _duration_nsec_range, _duration_nsec)

    return pointer
end

-- 7.3.5.9 Group Statistics
ofp_group_stats_request_group_id_F = ProtoField.uint32("of13.group_stats_request_group_id", "Group ID")
ofp_group_stats_request_pad_F      = ProtoField.uint32("of13.group_stats_request_pad",      "Padding")

ofp_group_stats_length_F        = ProtoField.uint16("of13.group_stats_length",        "Length")
ofp_group_stats_pad_F           = ProtoField.string("of13.group_stats_pad",           "Padding")
ofp_group_stats_group_id_F      = ProtoField.uint32("of13.group_stats_group_id",      "Group ID")
ofp_group_stats_ref_count_F     = ProtoField.uint32("of13.group_stats_ref_count",     "Ref count")
ofp_group_stats_pad2_F          = ProtoField.string("of13.group_stats_pad2",          "Padding")
ofp_group_stats_packet_count_F  = ProtoField.uint64("of13.group_stats_packet_count",  "Packet count")
ofp_group_stats_byte_count_F    = ProtoField.uint64("of13.group_stats_byte_count",    "Byte count")
ofp_group_stats_duration_sec_F  = ProtoField.uint32("of13.group_stats_duration_sec",  "Duration sec")
ofp_group_stats_duration_nsec_F = ProtoField.uint32("of13.group_stats_duration_nsec", "Duration nsec")

ofp_bucket_counter_packet_count_F = ProtoField.uint64("of13.bucket_counter_packet_count", "Packet count")
ofp_bucket_counter_byte_count_F   = ProtoField.uint64("of13.bucket_counter_byte_count"  , "Byte count")

function ofp_group_stats_request(buffer, pinfo, tree)
    local _group_id_range = buffer(0,4)
    local _pad_range      = buffer(4,4)
    local pointer = 8

    local _group_id = _group_id_range:uint()
    local _pad      = tostring(_pad_range)

    tree:add(ofp_group_stats_request_group_id_F, _group_id_range, _group_id) 
    tree:add(ofp_group_stats_request_pad_F     , _pad_range     , _pad )

    return pointer
end

function ofp_group_stats(buffer, pinfo, tree)
    local _length_range        = buffer(0,2)
    local _pad_range           = buffer(2,2)
    local _group_id_range      = buffer(4,4)
    local _ref_count_range     = buffer(8,4)
    local _pad2_range          = buffer(12,4)
    local _packet_count_range  = buffer(16,8)
    local _byte_count_range    = buffer(24,8)
    local _duration_sec_range  = buffer(32,4)
    local _duration_nsec_range = buffer(36,4)
    local pointer = 40

    local _length        = _length_range:uint()
    local _pad           = _pad_range:uint()
    local _group_id      = _group_id_range:uint()
    local _ref_count     = _ref_count_range:uint()
    local _pad2          = _pad2_range:uint()
    local _packet_count  = _packet_count_range:uint64()
    local _byte_count    = _byte_count_range:uint64()
    local _duration_sec  = _duration_sec_range:uint()
    local _duration_nsec = _duration_nsec_range:uint()

    tree:add(ofp_group_stats_length_F       , _length_range       , _length       )
    tree:add(ofp_group_stats_pad_F          , _pad_range          , _pad          )
    tree:add(ofp_group_stats_group_id_F     , _group_id_range     , _group_id     )
    tree:add(ofp_group_stats_ref_count_F    , _ref_count_range    , _ref_count    )
    tree:add(ofp_group_stats_pad_F          , _pad2_range         , _pad2         )
    tree:add(ofp_group_stats_packet_count_F , _packet_count_range , _packet_count )
    tree:add(ofp_group_stats_byte_count_F   , _byte_count_range   , _byte_count   )
    tree:add(ofp_group_stats_duration_sec_F , _duration_sec_range , _duration_sec )
    tree:add(ofp_group_stats_duration_nsec_F, _duration_nsec_range, _duration_nsec)

    -- ofp_bucket_counter
    if _length > pointer then
        offset = ofp_bucket_counter(buffer(pointer,_length-pointer), pinfo, tree)
        pointer = pointer + offset
    end

    return pointer
end

function ofp_bucket_counter(buffer, pinfo, tree)
    local _packet_count_range = buffer(0,8)
    local _byte_count_range   = buffer(8,8)
    local pointer = 16

    local _packet_count = _packet_count_range:uint64()
    local _byte_count   = _byte_count_range:uint64()

    tree:add(ofp_bucket_counter_packet_count_F, _packet_count_range, _packet_count)
    tree:add(ofp_bucket_counter_byte_count_F  , _byte_count_range  , _byte_count  )

    return pointer
end

-- 7.3.5.10 Group Description
function ofp_group_desc(buffer, pinfo, tree)
    return 0
end

-- 7.3.5.11 Group Features
ofp_group_features_types_F        = ProtoField.uint32("of13.group_features_types",        "Type")
ofp_group_features_capabilities_F = ProtoField.uint32("of13.group_features_capabilities", "Capabilities")
ofp_group_features_max_groups1_F  = ProtoField.uint32("of13.group_features_max_groups1",  "Max group1")
ofp_group_features_max_groups2_F  = ProtoField.uint32("of13.group_features_max_groups2",  "Max group2")
ofp_group_features_max_groups3_F  = ProtoField.uint32("of13.group_features_max_groups3",  "Max group3")
ofp_group_features_max_groups4_F  = ProtoField.uint32("of13.group_features_max_groups4",  "Max group4")
ofp_group_features_actions1_F     = ProtoField.uint32("of13.group_features_actions1",     "Features action1")
ofp_group_features_actions2_F     = ProtoField.uint32("of13.group_features_actions2",     "Features action2")
ofp_group_features_actions3_F     = ProtoField.uint32("of13.group_features_actions3",     "Features action3")
ofp_group_features_actions4_F     = ProtoField.uint32("of13.group_features_actions4",     "Features action4")

function ofp_group_features(buffer, pinfo, tree)
    local _types_range         = buffer(0,4)
    local _capabilities_range  = buffer(4,4)
    local _max_groups1_range   = buffer(8,4)
    local _max_groups2_range   = buffer(12,4)
    local _max_groups3_range   = buffer(16,4)
    local _max_groups4_range   = buffer(20,4)
    local _actions1_range      = buffer(24,4)
    local _actions2_range      = buffer(28,4)
    local _actions3_range      = buffer(32,4)
    local _actions4_range      = buffer(36,4)
    local pointer = 40

    local _types        = _types_range:uint()
    local _capabilities = _capabilities_range:uint()
    local _max_groups1  = _max_groups1_range:uint()
    local _max_groups2  = _max_groups2_range:uint()
    local _max_groups3  = _max_groups3_range:uint()
    local _max_groups4  = _max_groups4_range:uint()
    local _actions1     = _actions1_range:uint()
    local _actions2     = _actions2_range:uint()
    local _actions3     = _actions3_range:uint()
    local _actions4     = _actions4_range:uint()

    tree:add(ofp_group_features_types_F        , _types_range       , _types       )
    -- XXX : ofp_group_capabilities
    tree:add(ofp_group_features_capabilities_F , _capabilities_range, _capabilities)
    tree:add(ofp_group_features_max_groups1_F  , _max_groups1_range , _max_groups1 )
    tree:add(ofp_group_features_max_groups2_F  , _max_groups2_range , _max_groups2 )
    tree:add(ofp_group_features_max_groups3_F  , _max_groups3_range , _max_groups3 )
    tree:add(ofp_group_features_max_groups4_F  , _max_groups4_range , _max_groups4 )
    tree:add(ofp_group_features_actions1_F     , _actions1_range    , _actions1    )
    tree:add(ofp_group_features_actions2_F     , _actions2_range    , _actions2    )
    tree:add(ofp_group_features_actions3_F     , _actions3_range    , _actions3    )
    tree:add(ofp_group_features_actions4_F     , _actions4_range    , _actions4    )

    return pointer
end

-- 7.3.5.12 Meter Statistics
ofp_meter_multipart_requests_meter_id_F = ProtoField.uint32("of13.meter_multipart_requests_meter_id", "Meter ID")
ofp_meter_multipart_requests_pad_F      = ProtoField.string("of13.meter_multipart_requests_pad",      "Padding")

ofp_meter_stats_meter_id_F        = ProtoField.uint32("of13.meter_stats_meter_id",        "Meter ID")
ofp_meter_stats_length_F          = ProtoField.uint32("of13.meter_stats_length",          "Length")
ofp_meter_stats_pad_F             = ProtoField.uint32("of13.meter_stats_pad",             "Padding")
ofp_meter_stats_flow_count_F      = ProtoField.uint32("of13.meter_stats_flow_count",      "Flow count")
ofp_meter_stats_packet_in_count_F = ProtoField.uint32("of13.meter_stats_packet_in_count", "Packet in count")
ofp_meter_stats_byte_in_count_F   = ProtoField.uint32("of13.meter_stats_byte_in_count",   "Byte in count")
ofp_meter_stats_duration_sec_F    = ProtoField.uint32("of13.meter_stats_duration_sec",    "Duration sec")
ofp_meter_stats_duration_nsec_F   = ProtoField.uint32("of13.meter_stats_duration_nsec",   "Duration nsec")

ofp_meter_band_stats_packet_band_count_F = ProtoField.uint32("of13.meter_band_stats_packet_band_count", "Packet band count")
ofp_meter_band_stats_byte_band_count_F   = ProtoField.uint32("of13.meter_band_stats_byte_band_count",   "Byte band count")

function ofp_meter_multipart_request(buffer, pinfo, tree)
    local _meter_id_range = buffer(0,4)
    local _pad_range      = buffer(4,4)
    local pointer = 8

    local _meter_id = _meter_id_range:uint()
    local _pad      = tostring(_pad_range)

    tree:add(ofp_meter_multipart_requests_meter_id_F, _meter_id_range, _meter_id) 
    tree:add(ofp_meter_multipart_requests_pad_F     , _pad_range     , _pad )

    return pointer
end

function ofp_meter_stats(buffer, pinfo, tree)
    local _meter_id_range        = buffer(0,4)
    local _length_range          = buffer(0,2)
    local _pad_range             = buffer(0,6)
    local _flow_count_range      = buffer(0,4)
    local _packet_in_count_range = buffer(0,8)
    local _byte_in_count_range   = buffer(0,8)
    local _duration_sec_range    = buffer(0,4)
    local _duration_nsec_range   = buffer(0,4)
    local pointer = 40

    local _meter_id        = _meter_id_range:uint()
    local _length          = _length_range:uint()
    local _pad             = tostring(_pad_range)
    local _flow_count      = _flow_count_range:uint()
    local _packet_in_count = _packet_in_count_range:uint64()
    local _byte_in_count   = _byte_in_count_range:uint64()
    local _duration_sec    = _duration_sec_range:uint()
    local _duration_nsec   = _duration_nsec_range:uint()

    tree:add(ofp_meter_stats_meter_id_F       , _meter_id_range       , _meter_id       )
    tree:add(ofp_meter_stats_length_F         , _length_range         , _length         )
    tree:add(ofp_meter_stats_pad_F            , _pad_range            , _pad            )
    tree:add(ofp_meter_stats_flow_count_F     , _flow_count_range     , _flow_count     )
    tree:add(ofp_meter_stats_packet_in_count_F, _packet_in_count_range, _packet_in_count)
    tree:add(ofp_meter_stats_byte_in_count_F  , _byte_in_count_range  , _byte_in_count  )
    tree:add(ofp_meter_stats_duration_sec_F   , _duration_sec_range   , _duration_sec   )
    tree:add(ofp_meter_stats_duration_nsec_F  , _duration_nsec_range  , _duration_nsec  )

    -- XXX : ofp_meter_band_stats

    return pointer
end

function ofp_meter_band_stats(buffer, pinfo, tree)
    local _packet_band_count_range = buffer(0,8)
    local _byte_band_count_range   = buffer(8,8)
    local pointer = 16

    local _packet_band_count = _packet_band_count_range:uint64()
    local _byte_band_count   = _byte_band_count_range:uint64()

    tree:add(ofp_meter_band_stats_packet_band_count_F, _packet_band_count_range, _packet_band_count)
    tree:add(ofp_meter_band_stats_byte_band_count_F  , _byte_band_count_range  , _byte_band_count  )

    return pointer
end

-- 7.3.5.13 Meter Configuration Statistics
function ofp_meter_config(buffer, pinfo, tree)
    return 0
end

-- 7.3.5.14 Meter Features Statistics
function ofp_meter_features(buffer, pinfo, tree)
    return 0
end

-- 7.3.5.15 Experimenter Multipart
function ofp_experimenter_multipart_header(buffer, pinfo, tree)
    return 0
end

-- 7.3.6 Queue configuration Messages
-- -------------------------------------------------
function ofp_queue_get_config_request(buffer, pinto, tree)
end

function ofp_queue_get_config_reply(buffer, pinto, tree)
end

-- 7.3.7 Packet-Out Message
-- -------------------------------------------------
ofp_packet_out_F             = ProtoField.string("of13.packet_out",            "Packet-Out Message")
ofp_packet_out_buffer_id_F   = ProtoField.uint32("of13.packet_out_buffer_id",  "Datapath ID")
ofp_packet_out_in_port_F     = ProtoField.uint32("of13.packet_out_in_port",    "Input port")
ofp_packet_out_actions_len_F = ProtoField.uint16("of13.packet_out_action_len", "Size of action array")
ofp_packet_out_pad_F         = ProtoField.string("of13.packet_out_pad",        "Padding")

function ofp_packet_out(buffer, pinfo, tree)
    local _buffer_id_range   = buffer(0,4)
    local _in_port_range     = buffer(4,4)
    local _actions_len_range = buffer(8,2)
    local _pad_range     = buffer(10,6)
    local pointer = 16

    local _buffer_id   = _buffer_id_range:uint()
    local _in_port     = _in_port_range:uint()
    local _actions_len = _actions_len_range:uint()
    local _pad     = tostring(_pad_range)

    local subtree = tree:add(ofp_packet_out_F, buffer(), "Packet Out")
    subtree:add(ofp_packet_out_buffer_id_F,   _buffer_id_range,   _buffer_id)
    subtree:add(ofp_packet_out_in_port_F,     _in_port_range,     _in_port)
    subtree:add(ofp_packet_out_actions_len_F, _actions_len_range, _actions_len)
    subtree:add(ofp_packet_out_pad_F,     _pad_range,     _pad)

    -- Action Header dissector
    offset = ofp_action_header(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Ethernet dissector(wireshark implements)
    local raw_frame_range = buffer(pointer,buffer:len()-pointer)
    Dissector.get("eth"):call(raw_frame_range:tvb(), pinfo, subtree)
end

-- 7.3.8 Barrier Message
-- -------------------------------------------------

-- 7.3.9 Role Request Message
-- -------------------------------------------------
ofp_controller_role = {
    [0] = "OFPCR_ROLE_NOCHANGE", -- Don’t change current role.
    [1] = "OFPCR_ROLE_EQUAL",    -- Default role, full access.
    [2] = "OFPCR_ROLE_MASTER",   -- Full access, at most one master.
    [3] = "OFPCR_ROLE_SLAVE",    -- Read-only access.
}

function ofp_role_request(buffer, pinfo, tree)
end

-- 7.3.10 Set Asynchronous Configuration Message
-- -------------------------------------------------
function ofp_async_config(buffer, pinfo, tree)
end


-- -------------------------------------------------
-- 7.4 Asynchronous Messages
-- -------------------------------------------------

-- 7.4.1 Packet-In Message
-- -------------------------------------------------
ofp_packet_in_F           = ProtoField.string("of13.packet_in",           "Packet-In Message")
ofp_packet_in_buffer_id_F = ProtoField.uint32("of13.packet_in_buffer_id", "Datapath ID")
ofp_packet_in_total_len_F = ProtoField.uint16("of13.packet_in_total_len", "Frame length")
ofp_packet_in_reason_F    = ProtoField.uint8("of13.packet_in_reason",     "Reason")
ofp_packet_in_table_id_F  = ProtoField.uint8("of13.packet_in_table_id",   "Table ID")
ofp_packet_in_cookie_F    = ProtoField.uint64("of13.packet_in_cookie",    "Cookie", base.HEX)
ofp_packet_in_pad_F       = ProtoField.string("of13.packet_in_pad",       "Padding")

ofp_packet_in_reason = {
    [0] = "OFPR_NO_MATCH",    -- No matching flow (table-miss flow entry).
    [1] = "OFPR_ACTION",      -- Action explicitly output to controller.
    [2] = "OFPR_INVALID_TTL", -- Packet has invalid TTL
}

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
    local subtree = tree:add(ofp_packet_in_F, buffer(), "Packet In")
    subtree:add(ofp_packet_in_buffer_id_F, _buffer_id_range, _buffer_id)
    subtree:add(ofp_packet_in_total_len_F, _total_len_range, _total_len)
    subtree:add(ofp_packet_in_reason_F,    _reason_range,    _reason):append_text(" (" .. ofp_packet_in_reason[_reason] .. ")")
    subtree:add(ofp_packet_in_table_id_F,  _table_id_range,  _table_id)
    subtree:add(ofp_packet_in_cookie_F,    _cookie_range,    _cookie)

    -- Flow Match Header dissector
    offset = ofp_match(buffer(pointer,buffer:len()-pointer), pinfo, subtree)
    pointer = pointer + offset

    -- Padding
    local _pad_range = buffer(pointer,2)
    pointer = pointer + 2
    local _pad = tostring(_pad_range)
    subtree:add(ofp_packet_in_pad_F, _pad_range, _pad)

    -- Ethernet dissector(wireshark implements)
    local raw_frame_range = buffer(pointer,buffer:len()-pointer)
    Dissector.get("eth"):call(raw_frame_range:tvb(), pinfo, subtree)
end

-- 7.4.2 Flow Removed Message
-- -------------------------------------------------
function ofp_flow_removed(buffer, pinfo, tree)
end

-- 7.4.3 Port Status Message
-- -------------------------------------------------
function ofp_port_status(buffer, pinfo, tree)
end

-- 7.4.4 Error Message
-- -------------------------------------------------
function ofp_error_msg(buffer, pinfo, tree)
end


-- -------------------------------------------------
-- 7.5 Symmetric Message
-- -------------------------------------------------

-- 7.5.1 Hello
-- -------------------------------------------------
function ofp_hello(buffer, pinfo, tree)
end

function ofp_hello_elem_header(buffer, pinfo, tree)
end

function ofp_hello_elem_versionbitmap(buffer, pinfo, tree)
end

-- 7.5.2 Echo Request
-- -------------------------------------------------

-- 7.5.3 Echo Reply
-- -------------------------------------------------

-- 7.5.4 Experimenter
-- -------------------------------------------------
function ofp_experimenter_header(buffer, pinfo, tree)
end


-- =================================================
--     Enable OpenFlow 1.3 protocol fields
-- =================================================
of13_proto.fields = {
    -- 7.1 OpenFlow Header
    ofp_header_version_F,
    ofp_header_type_F,
    ofp_header_length_F,
    ofp_header_xid_F,

    -- 7.2.1 Port Structures
    ofp_port_port_no_F,
    ofp_port_pad1_F,
    ofp_port_hw_addr_F,
    ofp_port_pad2_F,
    ofp_port_name_F,
    ofp_port_config_F,
    ofp_port_state_F,
    ofp_port_curr_F,
    ofp_port_advertised_F,
    ofp_port_supported_F,
    ofp_port_peer_F,
    ofp_port_curr_speed_F,
    ofp_port_max_speed_F,

    -- 7.2.2 Queue Structures
    ofp_packet_queue_queue_id_F,
    ofp_packet_queue_port_F,
    ofp_packet_queue_len_F,
    ofp_packet_queue_pad_F,

    -- 7.2.3 Flow Match Structures
    ofp_match_F,
    ofp_match_type_F,
    ofp_match_length_F,
    ofp_match_ofp_oxm_F,
    ofp_match_pad_F,
    ofp_oxm_class_F,
    ofp_oxm_field_F,
    ofp_oxm_hasmask_F,
    ofp_oxm_length_F,
    ofp_oxm_value_F,
    ofp_oxm_mask_F,

    -- 7.2.4 Flow Instruction Structures
    ofp_instruction_F,
    ofp_instruction_type_F,
    ofp_instruction_length_F,
    ofp_instruction_table_id_F,
    ofp_instruction_pad_F,
    ofp_instruction_metadata_F,
    ofp_instruction_metadata_mask_F,
    ofp_instruction_meter_F,

    -- 7.2.5 Action Structures
    ofp_action_header_F,
    ofp_action_header_type_F,
    ofp_action_header_length_F,
    ofp_action_header_pad_F,
    ofp_action_output_port_F,
    ofp_action_output_max_len_F,
    ofp_action_output_pad_F,
    ofp_action_group_group_id_F,
    ofp_action_group_queue_id_F,
    ofp_action_mpls_ttl_mpls_ttl_F,
    ofp_action_mpls_ttl_pad_F,
    ofp_action_nw_ttl_nw_ttl_F,
    ofp_action_nw_ttl_pad_F,
    ofp_action_push_ethertype_F,
    ofp_action_push_pad_F,
    ofp_action_pop_mpls_ethertype_F,
    ofp_action_pop_mpls_pad_F,
    ofp_action_set_field_type_F,
    ofp_action_set_field_len_F,
    ofp_action_experimenter_F,

    -- 7.3.1 Handshake
    ofp_switch_features_F,
    ofp_switch_features_datapath_id_F,
    ofp_switch_features_n_buffers_F,
    ofp_switch_features_n_tables_F,
    ofp_switch_features_auxiliary_id_F,
    ofp_switch_features_pad_F,
    ofp_switch_features_capabilities_F,
    ofp_switch_features_reserved_F,

    ofp_switch_features_capabilities_flow_stats_F,
    ofp_switch_features_capabilities_table_stats_F,
    ofp_switch_features_capabilities_port_stats_F,
    ofp_switch_features_capabilities_group_stats_F,
    ofp_switch_features_capabilities_ip_reasm_F,
    ofp_switch_features_capabilities_queue_stats_F,
    ofp_switch_features_capabilities_port_blocked_F,

    -- 7.3.2 Switch Configuratiion
    ofp_config_flags_F,
    ofp_config_miss_send_len_F,

    -- 7.3.3 Flow Table Configuration
    ofp_table_mod_table_id_F,
    ofp_table_mod_pad_F,
    ofp_table_mod_config_F,

    -- 7.3.4 Modify State Messages
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
    ofp_flow_mod_pad_F,

    ofp_flow_mod_flags_send_flow_rem_F,
    ofp_flow_mod_flags_check_overlap_F,
    ofp_flow_mod_flags_reset_counts_F,
    ofp_flow_mod_flags_no_pkt_counts_F,
    ofp_flow_mod_flags_no_byt_counts_F,

    ofp_group_mod_command_F,
    ofp_group_mod_type_F,
    ofp_group_mod_pad_F,
    ofp_group_mod_group_id_F,

    ofp_bucket_len_F,
    ofp_bucket_weight_F,
    ofp_bucket_watch_port_F,
    ofp_bucket_watch_group_F,
    ofp_bucket_pad_F,

    ofp_port_mod_port_no_F,
    ofp_port_mod_pad_F,
    ofp_port_mod_hw_addr_F,
    ofp_port_mod_pad2_F,
    ofp_port_mod_config_F,
    ofp_port_mod_mask_F,
    ofp_port_mod_advertise_F,
    ofp_port_mod_pad3_F,

    ofp_meter_mod_command_F,
    ofp_meter_mod_flags_F,
    ofp_meter_mod_meter_id_F,

    ofp_meter_band_header_type_F,
    ofp_meter_band_header_len_F,
    ofp_meter_band_header_rate_F,
    ofp_meter_band_header_burst_size_F,

    -- 7.3.5 Multipart Messages
    ofp_multipart_request_F,
    ofp_multipart_request_type_F,
    ofp_multipart_request_flags_F,
    ofp_multipart_request_pad_F,

    ofp_multipart_reply_F,
    ofp_multipart_reply_type_F,
    ofp_multipart_reply_flags_F,
    ofp_multipart_reply_pad_F,

    -- 7.3.5.1 Description
    ofp_desc_mfr_desc_F,
    ofp_desc_hw_desc_F,
    ofp_desc_sw_desc_F,
    ofp_desc_serial_num_F,
    ofp_desc_dp_desc_F,

    -- 7.3.5.2 Individual Flow Statistics
    ofp_flow_stats_request_table_id_F,
    ofp_flow_stats_request_pad1_F,
    ofp_flow_stats_request_out_port_F,
    ofp_flow_stats_request_out_group_F,
    ofp_flow_stats_request_pad2_F,
    ofp_flow_stats_request_cookie_F,
    ofp_flow_stats_request_cookie_mask_F,

    ofp_flow_stats_F,
    ofp_flow_stats_length_F,
    ofp_flow_stats_table_id_F,
    ofp_flow_stats_pad1_F,
    ofp_flow_stats_duration_sec_F,
    ofp_flow_stats_duration_nsec_F,
    ofp_flow_stats_priority_F,
    ofp_flow_stats_idle_timeout_F,
    ofp_flow_stats_hard_timeout_F,
    ofp_flow_stats_flags_F,
    ofp_flow_stats_pad2_F,
    ofp_flow_stats_cookie_F,
    ofp_flow_stats_packet_count_F,
    ofp_flow_stats_byte_count_F,

    -- 7.3.5.3 Aggregate Flow Statistics
    ofp_aggregate_stats_request_table_id_F,
    ofp_aggregate_stats_request_pad1_F,
    ofp_aggregate_stats_request_out_port_F,
    ofp_aggregate_stats_request_out_group_F,
    ofp_aggregate_stats_request_pad2_F,
    ofp_aggregate_stats_request_cookie_F,
    ofp_aggregate_stats_request_cookie_mask_F,

    ofp_aggregate_stats_reply_packet_count_F ,
    ofp_aggregate_stats_reply_byte_count_F,
    ofp_aggregate_stats_reply_flow_count_F,
    ofp_aggregate_stats_reply_pad_F,

    -- 7.3.5.4 Table Statistics
    ofp_table_stats_table_id_F,
    ofp_table_stats_pad_F,
    ofp_table_stats_active_count_F,
    ofp_table_stats_lookup_count_F,
    ofp_table_stats_matched_count_F,

    -- 7.3.5.5 Table Features
    ofp_table_features_length_F,
    ofp_table_features_table_id_F,
    ofp_table_features_pad_F,
    ofp_table_features_name_F,
    ofp_table_features_metadata_match_F,
    ofp_table_features_metadata_write_F,
    ofp_table_features_config_F,
    ofp_table_features_max_entries_F,

    -- 7.3.5.6 Port Statistics
    ofp_port_stats_request_port_F,
    ofp_port_stats_request_pad_F,
    ofp_port_stats_reply_port_F,
    ofp_port_stats_reply_pad_F,
    ofp_port_stats_reply_rx_packets_F,
    ofp_port_stats_reply_tx_packets_F,
    ofp_port_stats_reply_rx_bytes_F,
    ofp_port_stats_reply_tx_bytes_F,
    ofp_port_stats_reply_rx_dropped_F,
    ofp_port_stats_reply_tx_dropped_F,
    ofp_port_stats_reply_rx_errors_F,
    ofp_port_stats_reply_tx_errors_F,
    ofp_port_stats_reply_rx_frame_err_F,
    ofp_port_stats_reply_rx_over_err_F,
    ofp_port_stats_reply_rx_crc_err_F,
    ofp_port_stats_reply_collisions_F,
    ofp_port_stats_reply_duration_sec_F,
    ofp_port_stats_reply_duration_nsec_F,

    -- 7.3.5.8 Queue Statistics
    ofp_queue_stats_request_port_no_F,
    ofp_queue_stats_request_queue_id_F,

    ofp_queue_stats_port_no_F,
    ofp_queue_stats_queue_id_F,
    ofp_queue_stats_tx_bytes_F,
    ofp_queue_stats_tx_packets_F,
    ofp_queue_stats_tx_errors_F,
    ofp_queue_stats_duration_sec_F,
    ofp_queue_stats_duration_nsec_F,

    -- 7.3.5.9 Group Statistics
    ofp_group_stats_request_group_id_F,
    ofp_group_stats_request_pad_F,

    ofp_group_stats_length_F,
    ofp_group_stats_pad_F,
    ofp_group_stats_group_id_F,
    ofp_group_stats_ref_count_F,
    ofp_group_stats_pad2_F,
    ofp_group_stats_packet_count_F,
    ofp_group_stats_byte_count_F,
    ofp_group_stats_duration_sec_F,
    ofp_group_stats_duration_nsec_F,

    ofp_bucket_counter_packet_count_F,
    ofp_bucket_counter_byte_count_F,

    -- 7.3.5.11 Group Features
    ofp_group_features_types_F,
    ofp_group_features_capabilities_F,
    ofp_group_features_max_groups1_F,
    ofp_group_features_max_groups2_F,
    ofp_group_features_max_groups3_F,
    ofp_group_features_max_groups4_F,
    ofp_group_features_actions1_F,
    ofp_group_features_actions2_F,
    ofp_group_features_actions3_F,
    ofp_group_features_actions4_F,

    -- 7.3.5.12 Meter Statistics
    ofp_meter_multipart_requests_meter_id_F ,
    ofp_meter_multipart_requests_pad_F,

    ofp_meter_stats_meter_id_F,
    ofp_meter_stats_length_F,
    ofp_meter_stats_pad_F,
    ofp_meter_stats_flow_count_F,
    ofp_meter_stats_packet_in_count_F,
    ofp_meter_stats_byte_in_count_F,
    ofp_meter_stats_duration_sec_F,
    ofp_meter_stats_duration_nsec_F,

    ofp_meter_band_stats_packet_band_count_F,
    ofp_meter_band_stats_byte_band_count_F,

    -- 7.3.7 Packet-Out Message
    ofp_packet_out_F,
    ofp_packet_out_buffer_id_F,
    ofp_packet_out_in_port_F,
    ofp_packet_out_actions_len_F,
    ofp_packet_out_pad_F,

    -- 7.4.1 Packet-In Message
    ofp_packet_in_F,
    ofp_packet_in_buffer_id_F,
    ofp_packet_in_total_len_F,
    ofp_packet_in_reason_F,
    ofp_packet_in_table_id_F,
    ofp_packet_in_cookie_F,
    ofp_packet_in_pad_F,
}


-- =================================================
--     Register of13_proto
-- =================================================
DissectorTable.get("tcp.port"):add(6633, of13_proto)
DissectorTable.get("tcp.port"):add(6653, of13_proto)
