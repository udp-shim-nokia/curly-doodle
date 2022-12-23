
--
-- Nokia UDP SHIM Protocol Wireshark Dissector
-- Version 1.0.1
-- 2021, March
--

-- ## Add dissector info ##
local nus_info = {
    version = "1.0.1",
    author = "Doug", -- You can change this of course
    -- repository = ""
}

set_plugin_info(nus_info)

-- ## Configuration of dissector ##
    -- Byte order. Set to false to enable Big Endian mode
local is_litle_endian   = false
    -- UDP port. Default is 30000
local shim_port         = 30000
    -- Possible Ethernet dissectors: eth_withoutfcs, eth_withfcs or eth_maybefcs
local ethernet_dissector_name = 'eth_withoutfcs'

-- ## Protocol definition ##
shim_protocol = Proto("NokiaSHIM",  "Nokia SHIM Protocol")

-- $$ HEADER fields $$
local fd_version        = ProtoField.int8('nokiashim.version', 'version', base.DEC)
local fd_direction      = ProtoField.int8('nokiashim.direction', 'direction', base.DEC)
local fd_mirror_type    = ProtoField.int8('nokiashim.mirrortype', 'mirrorType', base.DEC)
local fd_filter_action  = ProtoField.int8('nokiashim.filteraction', 'filterAction', base.DEC)
local fd_int_ref_type   = ProtoField.int8('nokiashim.intreftype', 'interfaceRefType', base.DEC)
local fd_interface      = ProtoField.int32('nokiashim.interface', 'interface', base.DEC)

-- $$ PAYLOAD fields $$
local fd_mirrored_packet   = ProtoField.none('nokiashim.mirroredpacket', 'mirroredPacket', base.HEX)

-- Registering Fields
shim_protocol.fields = { 
	fd_version, fd_direction, fd_mirror_type, fd_filter_action, fd_int_ref_type, fd_interface, -- Header
    fd_mirrored_packet  -- Payload
}

-- ## The dissector. Called each time a packet is captured ##
function shim_protocol.dissector(buffer, pinfo, tree)
    -- Buffer represents all captured data, the entire packet.
    -- We refer to its legth to do some useful calculations
	local length = buffer:len()
    
    -- If, for some reason, there is no read data for the packet, then
    -- we do not have hothing to dissect
	if length == 0 then return end

    -- Name to be shown at 'protocol' column
	--pinfo.cols.protocol = shim_protocol.name

    -- Our main tree.
	local subtree = tree:add(shim_protocol, buffer(), "Nokia SHIM Protocol Data")

    -- Header and Payload subtrees
    local headerSubtree = subtree:add(shim_protocol, buffer(), "Header")
    local payloadSubtree = subtree:add(shim_protocol, buffer(), "Payload (Mirrored Packet)")

    -- $$ HEADER $$

    -- Get all the 32 bits of the header, 
    -- that is the first 4 bytes of packet data
    local shif_header = buffer(0,4):le_uint()
    if is_litle_endian then
        shif_header = buffer(0,4):le_uint()
    else
        shif_header = buffer(0,4):uint()
    end

    -- Decode the bits from first byte
    local version = bit32.extract(shif_header, 28, 4)
    local direction = bit32.extract(shif_header, 27, 1)
    local mirror_type = bit32.extract(shif_header, 26, 1)
    local filter_action = bit32.extract(shif_header, 25, 1)
    local int_ref_type = bit32.extract(shif_header, 24, 1)

    -- Not needed as it corresponds to 3 entire bytes
    -- local interface = bit32.extract(shif_header, 0, 24)

    -- Generate short description strings for fields values
    local direction_str = 'Ingress'    
    if direction==1 then direction_str = 'Egress' end

    local mirror_type_str = 'Ethernet'    
    if mirror_type==1 then mirror_type_str = 'IP-Only' end

    local filter_action_str = 'Drop'    
    if filter_action==1 then filter_action_str = 'Accept' end

    local int_ref_type_str = 'If-Index'    
    if int_ref_type==1 then int_ref_type_str = 'sap-instance-id' end

    -- Add decoded bits to header subtree
    if is_litle_endian then
        headerSubtree:add_le(fd_version, version)
        headerSubtree:add_le(fd_direction, direction):append_text(" (" .. direction_str .. ")")
        headerSubtree:add_le(fd_mirror_type, mirror_type):append_text(" (" .. mirror_type_str .. ")")
        headerSubtree:add_le(fd_filter_action, filter_action):append_text(" (" .. filter_action_str .. ")")
        headerSubtree:add_le(fd_int_ref_type, int_ref_type):append_text(" (" .. int_ref_type_str .. ")")
        --headerSubtree:add_le(fd_interface, interface)
        headerSubtree:add_le(fd_interface, buffer(1,3))
    else
        headerSubtree:add(fd_version, version)
        headerSubtree:add(fd_direction, direction):append_text(" (" .. direction_str .. ")")
        headerSubtree:add(fd_mirror_type, mirror_type):append_text(" (" .. mirror_type_str .. ")")
        headerSubtree:add(fd_filter_action, filter_action):append_text(" (" .. filter_action_str .. ")")
        headerSubtree:add(fd_int_ref_type, int_ref_type):append_text(" (" .. int_ref_type_str .. ")")
        --headerSubtree:add(fd_interface, interface)
        headerSubtree:add(fd_interface, buffer(1,3))
    end

    -- $$ PAYLOAD $$

    --[[
    -- For now, there is not much information on how 
    -- payload can be dissected. So we just identify it at tree
    if is_litle_endian then
        payloadSubtree:add_le(fd_mirrored_packet, buffer(4, length-4)):append_text(" (" .. tostring(length-4) .. " Bytes)")
    else
        payloadSubtree:add(fd_mirrored_packet, buffer(4, length-4)):append_text(" (" .. tostring(length-4) .. " Bytes)")
    end
    ]]

    if mirror_type==0 then
        -- Our mirrored packet is a Ethernet packet
        local ethernet_dissector = Dissector.get(ethernet_dissector_name)
        local tvbr = buffer:range(4)
        local sub_buffer = tvbr:tvb()
        ethernet_dissector:call(sub_buffer, pinfo, payloadSubtree)
    else
        -- Our mirrored packet is an IP packet
        local ip_dissector = Dissector.get('ip')
        local tvbr = buffer:range(4)
        local sub_buffer = tvbr:tvb()
        ip_dissector:call(sub_buffer, pinfo, payloadSubtree)
    end
    pinfo.cols.protocol = shim_protocol.name
end

-- Hook dissection function into existing udp protocol
local tcp_port = DissectorTable.get("udp.port")
tcp_port:add(shim_port, shim_protocol)


-- ##  TEMP ##

function show_dissectors()
    local content=''
    for _, name in ipairs(Dissector.list()) do
        content=content..'Dissector: '..name..'\n'
    end
    
    if not gui_enabled() then return end
    
    -- create new text window and initialize its text
    local win = TextWindow.new("Dissector List")
    win:set(content)
    
    -- add buttons to clear text window and to enable editing
    win:add_button("Clear", function() win:clear() end)
    win:add_button("Enable edit", function() win:set_editable(true) end)
    
    -- add button to change text to uppercase
    win:add_button("Uppercase", function()
            local text = win:get_text()
            if text ~= "" then
                    win:set(string.upper(text))
            end
    end)
    
    -- print "closing" to stdout when the user closes the text window
    win:set_atclose(function() print("closing") end)
    
end
