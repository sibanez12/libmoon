--- A simple TCP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local arp    = require "proto.arp"
local timer  = require "timer"
local filter = require "filter"
local eth = require "proto.ethernet"
local perca = require "proto.perca"
local percc = require "proto.percc"
local percd = require "proto.percd"
local barrier    = require "barrier"

local nf_macno_map = {}
nf_macno_map["nf0"] = 8869393797384 -- "08:11:11:11:11:08"
nf_macno_map["nf1"] = 8942694572552 -- "08:22:22:22:22:08"
nf_macno_map["nf2"] = 9015995347720 -- "08:33:33:33:33:08"
nf_macno_map["nf3"] = 9089296122888 -- "08:44:44:44:44:08"

-- ip4: ether/ 28B IP header/ 16b src port/ 16b dst port
-- percd: ether/ 5B Perc Generic/ 12B Perc Data
-- perc: ether/ 5B Generic/ 56B Perc Control

local PKT_LEN       = 1460 --60
local ACK_LEN = 60
local CONTROL_PACKET_LEN = 78 
local RUN_INDEX = 42

local DATA_BATCH_SIZE = 63
local CONTROL_BATCH_SIZE = 31
local ACK_BATCH_SIZE = 63

local DATA_RX_WAIT = 10
local CONTROL_RX_WAIT = 0
local ACK_RX_WAIT = 0

local MAX_FLOWS     = 24
local INIT_GAP = 5
local TIMING_WHEEL_NUM_SLOTS = 100

local  array32       = require "array32"
local  array64       = require "array64"
local timing_wheel = require"timing_wheel"

-- args.dstMac, args.srcMac, args.numFlows, args.duration, args.offset

-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
    parser:description("Edit the source to modify constants like IPs and ports.")
    parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
    parser:option("-d --dstMac", "Destination MAC address to use for the flows to start up"):args(1):convert(tonumber):default(0x081111111108)
    parser:option("-s --srcMac", "Source MAC address to use for the flows"):args(1):convert(tonumber):default(0x082222222208)
    parser:option("-n --numFlows", "The number of flows to start up"):args(1):convert(tonumber):default(3)
    parser:option("-t --time", "The amount of time for which to send pkts for the flows (sec)"):args(1):convert(tonumber):default(0.01)
    parser:option("-o --offset", "The offset to use to compute flowID values (must be greater than 0)"):args(1):convert(tonumber):default(1)
    parser:option("-w --wait", "Wait this many seconds before sending init ctrl pkts"):args(1):convert(tonumber):default(3)
    return parser:parse()
end

function master(args,...)
    for i, dev in ipairs(args.dev) do
       local dev = device.config{
          port = dev,
          txQueues = 4,
          rxQueues = 3
       }
       args.dev[i] = dev
    end

    device.waitForLinks()
    log:info("Dev 0 mac: %x", nf_macno_map.nf1)
    log:info("Dev 1 mac: %x", nf_macno_map.nf0)

    -- print statistics
    stats.startStatsTask{devices = args.dev}

    local dataQ = 0
    local controlQ = 1
    local ackQ = 2

    local b2 = barrier:new(2)
    -- configure tx rates and start transmit slaves
    for i, dev in ipairs(args.dev) do
          local wl = genWorkload(args.dstMac, args.srcMac, args.numFlows, args.time, args.offset, args.wait)
          if (i == 2) then
             wl = genEmptyWorkload()
          end
          local dataTxQueue = dev:getTxQueue(dataQ)	 
          dataTxQueue:setRate(8000)

          local ackRxQueue = dev:getRxQueue(ackQ)
          local af = dev:l2Filter(eth.TYPE_PERC_ACK, ackRxQueue)
          local controlRxQueue = dev:getRxQueue(controlQ)
          local cf = dev:l2Filter(eth.TYPE_PERC, controlRxQueue)
          local controlTxQueue = dev:getTxQueue(controlQ)
          local controlTxQueueExtra = dev:getTxQueue(3)
          controlTxQueue:setRate(1000)

          lm.startTask("dataSenderTask", wl, dataTxQueue,
         	      ackRxQueue, controlTxQueue, controlRxQueue, controlTxQueueExtra, b2)
    end
    
    lm.waitForTasks()
end

function genEmptyWorkload()
   wl = {}
   wl["wait_time"] = 0
   wl["num_flows"] = 0
   wl["src_mac"] = 0
   wl["dst_mac"] = {}
   wl["duration"] = {}
   wl["flow_id"] = {}
   return wl
end

function genWorkload(dstMacNo, srcMacNo, numFlows, duration, flowID_offset, wait_time)
   wl = {}
   -- 0000:01:00.0 / eth2 is plugged into nf1
   -- 0000:01:00.1 / eth3 is plugged into nf0
   wl["wait_time"] = wait_time
   wl["num_flows"] = numFlows
   wl["src_mac"] = srcMacNo
   wl["dst_mac"] = dstMacNo
   wl["duration"] = duration
   wl["flow_id"] = {}
   for i=0,numFlows-1 do
      table.insert(wl.flow_id, (flowID_offset + i))
   end
   return wl
end


function dataSenderTask(wl, dataTxQueue, ackRxQueue, controlTxQueue, controlRxQueue,
			controlTxQueueExtra, b)
   -- this thread sends and receives control packets

   local control_rx_bufs = memory.bufArray()
   local src_mac = wl.src_mac

   log:info("Starting tx slave at : %x", src_mac)
   -- memory pool with default values for all packets,
   -- this is our archetype

   -- for sending new control packets
   local control_mempool = memory.createMemPool(function(buf)
	 buf:getPerccPacket():fill{
	    -- fields not explicitly set here are initialized to reasonable defaults
	    ethSrc = src_mac, -- MAC of the tx device
	    ethDst = src_mac,
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
	    perccindex=RUN_INDEX,
	    pktLength = CONTROL_PACKET_LEN
	}
	end)
   local control_bufs = control_mempool:bufArray(CONTROL_BATCH_SIZE)

   -- initialize all the flows to start at the same time
   -- so alloc resources on the shared_xx arrays (common_index)
   -- and on the timing wheel
   local control_tw = timing_wheel:new(MAX_FLOWS)

   for i, flow_id in ipairs(wl.flow_id) do
       control_tw:insert(flow_id, i-1)
   end

   init_ctrl_pkts_sent = 0
   log:info("dataSender about to start %d flows", wl.num_flows)

   local last_lm_time = lm.getTime()
   local start_time = last_lm_time + 1
   b:wait()
   while lm.running() do 
      -- check if Ctrl+c was pressed
      -- this actually allocates some buffers from 
      -- the mempool the array is associated with
      -- this has to be repeated for each send 
      -- because sending is asynchronous, we cannot 
      -- reuse the old buffers here		

      -- send first control packets if there are
      -- flows waiting to start
      -- maybe also add a condition to check control_tw if num_pending_fin
      if lm.getTime() > start_time + wl.wait_time and init_ctrl_pkts_sent == 0 then
         sendInitCtrlPkts(control_bufs, control_tw, wl, controlTxQueue)
         init_ctrl_pkts_sent = 1
      end
      
      -- reflect control packets, unless it's a leave packet
      local num_ctrl_rcvd = controlRxQueue:tryRecv(control_rx_bufs, CONTROL_RX_WAIT)
      reflectCtrlPkts(num_ctrl_rcvd, control_rx_bufs, controlTxQueueExtra, start_time, wl)
   end

end

function sendInitCtrlPkts(control_bufs, control_tw, wl, controlTxQueue)
    control_bufs:alloc(CONTROL_PACKET_LEN)
    for i, buf in ipairs(control_bufs) do
       local pkt = buf:getPerccPacket()
       local flow_id = control_tw:remove_and_tick()
       if tableContains(wl.flow_id, flow_id) then
          -- is a valid ctrl pkt to send
          local dst_mac = wl.dst_mac
          pkt.eth:setDst(dst_mac) -- routing
          pkt.eth:setType(eth.TYPE_PERC)
          pkt.percc:setflowID(flow_id) -- identifier
          pkt.percc:setlabel_0(percc.NEW_FLOW)    
       else
          -- is an invalid ctrl pkt
          pkt.eth:setSrc(srcMac) -- so packet is dropped by switch
          pkt.eth:setDst(srcMac)
          pkt.percc:setlabel_0(percc.INACTIVE)
          buf:free() -- do these need to be freed here?
       end
    end
    controlTxQueue:sendN(control_bufs, wl.num_flows)
end

function reflectCtrlPkts(num_ctrl_rcvd, control_rx_bufs, controlTxQueueExtra, start_time, wl) 
    for i = 1, num_ctrl_rcvd do
       local pkt = control_rx_bufs[i]:getPerccPacket()
       local flow_id = pkt.percc:getflowID()
       local leave = 0
       if tableContains(wl.flow_id, flow_id) then
          -- this is a ctrl pkt for one of our flows
          if lm.getTime() >= start_time + wl.wait_time + wl.duration then
              -- send another non-leave ctrl pkt
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
