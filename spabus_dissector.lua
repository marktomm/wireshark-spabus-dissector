spabus = Proto("spabus", "ABB SPA-Bus")

local BROADCAST_ADDR_STR = "900"

-- 0-999 allowed, with 900 being broadcast address
local pf_slave_number           = ProtoField.string("spabus.addr", "Slave number", base.ASCII)
-- local pf_slave_number           = ProtoField.new("Slave number", "spabus.addr", ftypes.UINT16)
-- ASCII character R, W, D, A or N indicating the type of the message (read, write, data, ack or nack).
local pf_message_type_code      = ProtoField.string("spabus.type", "Message type", base.ASCII)
-- 0-999 allowed
local pf_channel_number         = ProtoField.string("spabus.channel", "Channel number", base.ASCII)
local pf_start_channel_number   = ProtoField.string("spabus.startchannel", "Start Channel number", base.ASCII)
local pf_end_channel_number     = ProtoField.string("spabus.endchannel", "End Channel number", base.ASCII)
-- ASCII character I, O, S, V, M, C, F, T, D, L, B or A defining the logical data category
local pf_data_category_number   = ProtoField.string("soabus.datacat", "Data category", base.ASCII)
-- 0-999999 allowed
local pf_data_number            = ProtoField.string("spabus.datanum", "Data number", base.ASCII)
local pf_start_data_number      = ProtoField.string("spabus.startdatanum", "Start Data number", base.ASCII)
local pf_end_data_number        = ProtoField.string("spabus.enddatanum", "End Data number", base.ASCII)

spabus.fields = {pf_slave_number, pf_message_type_code, pf_channel_number, pf_start_channel_number,
                pf_data_category_number, pf_end_channel_number, pf_data_number, pf_start_data_number,
                pf_end_data_number}

function csplit(str, sep)
   local sep, fields = sep or ":", {}
   local pattern = string.format("([^%s]+)", sep)
   string.gsub(str, pattern, function(c) fields[#fields+1] = c end)
   return fields
end

function spabus.dissector(tvb, pinfo, root)
    pinfo.cols.protocol:set("SPA-Bus")
    
    local pktlen = tvb:reported_length_remaining()
    
    local tree = root:add(spabus, tvb:range(0, pktlen))
    
    local addr = tvb:range(0, pktlen):string():match("%d+")
    local msgtype = tvb:range(1 + addr:len(), 1):string() 

    local infostr = nil
    local initoffset = nil
    local offset = nil
    local isRequest = tvb:range(0, 1):string() == ">"
    if isRequest then
        initoffset = 1
        offset = initoffset + addr:len() + msgtype:len() + 1
        infostr = "Request"
    else 
        initoffset = 2
        offset = initoffset + addr:len() + msgtype:len() + 1
        infostr = "Response"
    end
    
    infostr = infostr .. " Addr " .. addr .. " MsgType " ..  msgtype 
    tree:add(pf_slave_number, tvb:range(initoffset, addr:len()))
    -- does not work as described here https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
    -- tried with wireshark 2.2.7 lua 5.2.4 (windows 7 with installer / Ubuntu 16.04.2 compiled from source wireshark-2.2.7)
    -- tree:add_packet_field(pf_slave_number, tvb:range(initoffset, addr:len()), ENC_UTF_8 + ENC_STRING )
    tree:add(pf_message_type_code, tvb:range(initoffset + addr:len(), 1))
    
    if isRequest then
        local startchannel = tvb:range(0, pktlen):string():match("^%d+", offset)
        local endchannel = nil
        
        offset = offset + startchannel:len()
        if tvb:range(0, pktlen):string():match("^/%d+",  offset) then
            tree:add(pf_start_channel_number, tvb:range(offset - startchannel:len() - 1, startchannel:len()))
            offset = offset + 1 -- pass the forward slash
            endchannel = tvb:range(0, pktlen):string():match("^%d+",  offset)
            tree:add(pf_end_channel_number, tvb:range(offset - startchannel:len() - 1, endchannel:len()))
            offset = offset + endchannel:len()
            infostr = infostr .. " StartCh " .. startchannel .. " EndCh " .. endchannel
        else
            infostr = infostr .. " Channel " .. startchannel
            tree:add(pf_channel_number, tvb:range(offset - startchannel:len() - 1, startchannel:len()))
        end
        
        -- range indexes from 0, so -1
        local datacategory = tvb:range(offset - 1, 1):string() 
        tree:add(pf_data_category_number, tvb:range(offset - 1, 1))
        
        offset = offset + 1
        infostr = infostr .. " Data category " .. datacategory
        
        if datacategory ~= "L" and datacategory ~= "B" then
            local startdatanum =  tvb:range(0, pktlen):string():match("^%d+", offset)
            offset = offset + startdatanum:len()
        
            if tvb:range(0, pktlen):string():match("^/%d+",  offset) then
                tree:add(pf_start_data_number, tvb:range(offset - startdatanum:len() - 1, startdatanum:len()))
                offset = offset + 1 -- pass the forward slash
                enddatanum = tvb:range(0, pktlen):string():match("^%d+",  offset)
                offset = offset + enddatanum:len()
                tree:add(pf_end_data_number, tvb:range(offset - enddatanum:len() - 1, enddatanum:len()))
                infostr = infostr .. " Start Data num " .. startdatanum .. " End Data num " .. enddatanum
            else
                tree:add(pf_data_number, tvb:range(offset - startdatanum:len() - 1, startdatanum:len()))
                infostr = infostr .. " Data num " .. startdatanum
            end
        end
    end

    -- Data part
    offset = tvb:range(0, pktlen):string():find(":") + 1
    
    if tvb:range(offset - 1, 1):string() == ":" then
        infostr = infostr .. " No data"
    else
        local datastring = tvb:range(0, pktlen):string():match(":(.*):")
        if datastring then
            local data = csplit(datastring, "/")
            infostr = infostr .. " data " .. datastring
        end
    end
    
    pinfo.cols.info:prepend(infostr)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(22228,spabus)
