local lm     = require "libmoon"
local utils = require "utils"
local log    = require "log"
local memory = require "memory"
local eth = require "proto.ethernet"
local perca = require "proto.perca"
local percc = require "proto.percc"
local percd = require "proto.percd"

local timing_wheel = require "timing_wheel"

local perc = {}

local DATA_PKT_LEN = 1460
local RUN_INDEX = 42
local CONTROL_PACKET_LEN = 78

local MAC_DEFAULT = 0x081122334408

function perc.genEmptyWorkload()
    wl = {}
    wl["wait_time"] = 0
    wl["num_flows"] = 0
    wl["src_mac"] = 0
    wl["dst_mac"] = 0
    wl["duration"] = {}
    wl["flow_id"] = {}
    return wl
end

function perc.genWorkload(dstMac, srcMac, numFlows, duration, flowID_offset, wait_time)
    wl = {}
    -- 0000:01:00.0 / eth2 is plugged into nf1
    -- 0000:01:00.1 / eth3 is plugged into nf0
    wl["wait_time"] = wait_time
    wl["num_flows"] = numFlows
    wl["src_mac"] = srcMac
    wl["dst_mac"] = dstMac
    wl["duration"] = duration
    wl["flow_id"] = {}
    for i=0,numFlows-1 do
       table.insert(wl.flow_id, (flowID_offset + i))
    end
    return wl
end

function perc.createCtrlMemPool()
    return memory.createMemPool(function(buf)
         buf:getPerccPacket():fill{
            -- fields not explicitly set here are initialized to reasonable defaults
            ethSrc = MAC_DEFAULT, -- MAC of the tx device
            ethDst = MAC_DEFAULT,
            ethType = eth.TYPE_PERC,
            perccflowID = 0x1,
            perccleave = 0,
            perccisForward = 1,
            percchopCnt = 0,
            perccbottleneck_id=0xFF,
            perccdemand=0xFFFFFFFF,
            perccinsert_debug=0x1,
            percclabel_0=percc.NEW_FLOW,
            percclabel_1=percc.NEW_FLOW,
            percclabel_2=percc.NEW_FLOW,
            perccalloc_0=0xFFFFFFFF,
            perccalloc_1=0xFFFFFFFF,
            perccalloc_2=0xFFFFFFFF,
            perccindex = RUN_INDEX,
            pktLength = CONTROL_PACKET_LEN
        }
        end)
end

function perc.createDataMemPool()
    return memory.createMemPool(function(buf)
         buf:getPercdPacket():fill{
            ethSrc = MAC_DEFAULT,
            ethDst = MAC_DEFAULT,
            ethType = eth.TYPE_PERC_DATA,
            percdflowID = 0x0,
            percdindex = 0,
            percdseqNo = 0x0,
            percdackNo = 0x0,
            pktLength = DATA_PKT_LEN
                                }
   end)
end


function perc.sendInitCtrlPkts(control_bufs, control_tw, wl, controlTxQueue)
    control_bufs:alloc(CONTROL_PACKET_LEN)
    for i, buf in ipairs(control_bufs) do
       local pkt = buf:getPerccPacket()
       local flow_id = control_tw:remove_and_tick()
       if tableContains(wl.flow_id, flow_id) then
          -- is a valid ctrl pkt to send
          local dst_mac = wl.dst_mac
          local src_mac = wl.src_mac
          pkt.eth:setDst(dst_mac) -- routing
          pkt.eth:setSrc(src_mac) 
          pkt.eth:setType(eth.TYPE_PERC)
          pkt.percc:setflowID(flow_id) -- identifier
          pkt.percc:setlabel_0(percc.NEW_FLOW)
          pkt.percc:setlabel_1(percc.NEW_FLOW)
          pkt.percc:setlabel_2(percc.NEW_FLOW)
       else
          -- is an invalid ctrl pkt
          pkt.eth:setSrc(0) -- so packet is dropped by switch
          pkt.eth:setDst(0)
          pkt.percc:setlabel_0(percc.INACTIVE)
          pkt.percc:setlabel_1(percc.INACTIVE)
          pkt.percc:setlabel_2(percc.INACTIVE)
          buf:free() -- do these need to be freed here?
       end
    end
    controlTxQueue:sendN(control_bufs, wl.num_flows)
end

function perc.reflectCtrlPkts(num_ctrl_rcvd, control_rx_bufs, controlTxQueueExtra, start_time, wl, data_ipg, data_tw)
    for i = 1, num_ctrl_rcvd do
       local pkt = control_rx_bufs[i]:getPerccPacket()
       local flow_id = pkt.percc:getflowID()
       local leave = 0
       if tableContains(wl.flow_id, flow_id) then
          -- this is a ctrl pkt for one of our flows
          local new_rate = pkt.percc:getdemand()
          local new_gap = math.floor(2147483648.0/new_rate)
          local old_gap = data_ipg[flow_id]
          if old_gap == nil then
              data_tw:insert(flow_id, 1) -- first time flow_id is inserted into timing_wheel
          end
          data_ipg[flow_id] = new_gap
          if start_time ~= nil and getRealTime() >= start_time + wl.duration then
              -- flow should end now. Send a leave pkt 
              leave = 1
          end
       else
           -- this is not a ctrl pkt from one of our flows
           leave = pkt.percc:getleave()
           if leave == 1 then
               pkt.eth:setSrc(pkt.eth:getDst()) -- so that the pkt is dropped
           end
       end
       endHostResponse(pkt, leave)
    end
    controlTxQueueExtra:sendN(control_rx_bufs, num_ctrl_rcvd)
end

function perc.sendDataPkts(data_bufs, dataTxQueue, wl, flow_seqNo, data_tw, data_ipg, start_time)
    data_bufs:alloc(DATA_PKT_LEN)
    for i, data_buf in ipairs(data_bufs) do
        -- here we get next flow on timing wheel
        -- and re-insert it after
        local pkt = data_buf:getPercdPacket()
        local flow_id = data_tw:remove_and_tick()
        if tableContains(wl.flow_id, flow_id) then
            -- is a valid flow_id
            local dst_mac = wl.dst_mac
            local src_mac = wl.src_mac
            local seqNo = flow_seqNo[flow_id]
            pkt.eth:setDst(dst_mac)
            pkt.eth:setSrc(src_mac)
            pkt.percd:setflowID(flow_id) -- identifier
            pkt.percd:setseqNo(seqNo) -- identifier
            flow_seqNo[flow_id] = flow_seqNo[flow_id] + DATA_PKT_LEN
            local gap = data_ipg[flow_id]
            if start_time ~= nil and getRealTime() < start_time + wl.duration and gap ~= nil then
                data_tw:insert(flow_id, gap)
            end
        else
           -- is an invalid flow_id (drop the pkt)
           pkt.eth:setDst(0)
           pkt.eth:setSrc(0)
        end
    end
    dataTxQueue:send(data_bufs)
end

----------------------
-- helper functions --
----------------------

function endHostResponse(pkt, leave)
     -- reverse direction
    local direction = pkt.percc:getisForward()
    pkt.percc:setisForward(1 - direction)

    -- swap src and dst mac address
    local tmp = pkt.eth:getSrc()
    pkt.eth:setSrc(pkt.eth:getDst())
    pkt.eth:setDst(tmp)

    pkt.percc:setleave(leave)
end

-- check if elem was inserted into tab
function tableContains(tab, elem)
    for i,v in ipairs(tab) do
        if v == elem then
            return true
        end
    end
    return false
end

return perc

