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

-- set addresses here
local nf_mac_map = {}
nf_mac_map["nf0"] = "08:11:11:11:11:08"
nf_mac_map["nf1"] = "08:22:22:22:22:08"
nf_mac_map["nf2"] = "08:33:33:33:33:08"
nf_mac_map["nf3"] = "08:44:44:44:44:08"

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
local CONTROL_WAIT = 0.0 -- min time before we check for rx control packets

local DATA_BATCH_SIZE = 63
local CONTROL_BATCH_SIZE = 31
local ACK_BATCH_SIZE = 63

local DATA_RX_WAIT = 0
local CONTROL_RX_WAIT = 0
local ACK_RX_WAIT = 0

local NUM_FLOWS     = 12
local INIT_GAP = 20
local TIMING_WHEEL_NUM_SLOTS = 100
local ACK_INTERVAL = 1e-3
local  array32       = require "array32"
local  array64       = require "array64"
local timing_wheel = require"timing_wheel"



-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
   parser:description("Edit the source to modify constants like IPs and ports.")
   parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
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
   log:info("Destination mac 0: %s", nf_macno_map.nf0)
   log:info("Destination mac 1: %s", nf_macno_map.nf1)


   -- print statistics
   stats.startStatsTask{devices = args.dev}

   local dataQ = 0
   local controlQ = 1
   local ackQ = 2


   srcMacNo = {}
   table.insert(srcMacNo, nf_macno_map.nf1)
   table.insert(srcMacNo, nf_macno_map.nf0)

   srcMac = {}
   table.insert(srcMacNo, nf_mac_map.nf1)
   table.insert(srcMacNo, nf_mac_map.nf0)

   -- configure tx rates and start transmit slaves
   for i, dev in ipairs(args.dev) do 
      if (i == 1) then
	 local wl = genWorkload(nf_macno_map.nf0, 10, 1000000, 100)

   	 local dataTxQueue = dev:getTxQueue(dataQ)	 
	 dataTxQueue:setRate(9000)

	 local ackRxQueue = dev:getRxQueue(ackQ)
	 --local af= dev:fiveTupleFilter({dstIp=ACK_CODE,
	 --				dstIpMask=IP32_MASK_STR}, ackRxQueue)
	 local af = dev:l2Filter(eth.TYPE_PERC_ACK, ackRxQueue)

	 local controlRxQueue = dev:getRxQueue(controlQ)
	 local cf = dev:l2Filter(eth.TYPE_PERC, controlRxQueue)

	 local controlTxQueue = dev:getTxQueue(controlQ)
	 local controlTxQueueExtra = dev:getTxQueue(3)
   	 lm.startTask("dataSenderTask", dataTxQueue, srcMacNo[i], srcMac[i], wl,
		      ackRxQueue, controlTxQueue, controlRxQueue, controlTxQueueExtra)

   	 local ackTxQueue = dev:getTxQueue(ackQ)
	 ackTxQueue:setRate(500)

   	 local dataRxQueue = dev:getRxQueue(dataQ)
   	 lm.startTask("dataReceiverTask", dataRxQueue, ackTxQueue, srcMacNo[i], srcMac[i])

   	 -- lm.startTask("ackReceiverTask", ackRxQueue, sa_max_ack_num)

   	 -- local ackTxQueue = dev:getTxQueue(ackQ)
   	 -- local dataRxQueue = dev:getRxQueue(dataQ)
   	 -- lm.startTask("dataReceiverTask", dataRxQueue, ackTxQueue,
   	 -- 	      nf_mac_map.nf0, nf_macno_map.nf0)

      end

      if (i == 2) then
	 local wl = genEmptyWorkload()
	 --local wl = genWorkload(nf_macno_map.nf0, 10, 1000000, 200)

   	 local dataTxQueue = dev:getTxQueue(dataQ)	 
	 dataTxQueue:setRate(9000)

	 local ackRxQueue = dev:getRxQueue(ackQ)
	 --local af= dev:fiveTupleFilter({dstIp=ACK_CODE,
	 --				dstIpMask=IP32_MASK_STR}, ackRxQueue)
	 local af = dev:l2Filter(eth.TYPE_PERC_ACK, ackRxQueue)

	 local controlRxQueue = dev:getRxQueue(controlQ)
	 local cf = dev:l2Filter(eth.TYPE_PERC, controlRxQueue)

	 local controlTxQueue = dev:getTxQueue(controlQ)
	 local controlTxQueueExtra = dev:getTxQueue(3)
   	 lm.startTask("dataSenderTask", dataTxQueue, srcMacNo[i], srcMac[i], wl,
		      ackRxQueue, controlTxQueue, controlRxQueue, controlTxQueueExtra)

   	 local ackTxQueue = dev:getTxQueue(ackQ)
	 ackTxQueue:setRate(500)

   	 local dataRxQueue = dev:getRxQueue(dataQ)
   	 lm.startTask("dataReceiverTask", dataRxQueue, ackTxQueue, srcMacNo[i], srcMac[i])
      end


   end
   lm.waitForTasks()
end


function dataReceiverTask(rxQ, txQ, srcMac, srcMacStr)
   local arr_max_seq_num = array32:new(NUM_FLOWS, 0)
   local arr_flow_id = array32:new(NUM_FLOWS, 0)
   local arr_mac = array64:new(NUM_FLOWS, 0)
   local arr_sender_index = array32:new(NUM_FLOWS, 0)
   local data_discarded = 0

   log:info("Starting data receiver task at : rx %s tx %s", rxQ, txQ)
   local bufs = memory.bufArray()


   -- memory pool with default values for ack packets
   local mempool = memory.createMemPool(function(buf)
	 buf:getPercaPacket():fill{
	    ethSrc = srcMac, --queue, -- MAC of the tx device
	    ethDst = srcMac,
	    ethType = eth.TYPE_PERC_ACK,
	    percaflowID = 0x0,
	    percaindex = RUN_INDEX,
	    percaseqNo = 0x0,
	    percaackNo = 0x0,
	    pktLength = ACK_LEN,
	}
   end)
   
   local ackBufs = mempool:bufArray(ACK_BATCH_SIZE)
   local flow_index = {}

   local max_I_acked = 0	
   local seen = {}
   local next_free_index = 1

   while lm.running() do
      local rx = rxQ:tryRecv(bufs, DATA_RX_WAIT)
      local num_flows = 0

      for i = 1, rx do	 
	 local pkt = bufs[i]:getPercdPacket()
	 local run_index = pkt.percd:getindex()
	 if run_index == RUN_INDEX then
	    local src = pkt.eth:getSrc()
	    local flow_id = pkt.percd:getflowID()
	    local seq_num = pkt.percd:getseqNo()	 
	    local local_index = flow_index[flow_id]
	    table.insert(seen, flow_id)
	    -- so we'll send one ACK per packet and dup-acks
	    if local_index == nil then	    
	       local_index = next_free_index
	       next_free_index = next_free_index + 1
	       -- TODO: check it's available
	       flow_index[flow_id] = local_index
	       arr_mac:write(src, local_index)
	       arr_flow_id:write(flow_id, local_index)
	       arr_max_seq_num:write(seq_num, local_index)
	       num_flows = num_flows + 1
	    else
	       local tmp = arr_max_seq_num:read(local_index)
	       if seq_num == tmp + 1 then
		  -- for in order delivery, check if 
		  -- seq_num == tmp + 1 else seq_num > tmp
		  arr_max_seq_num:write(seq_num, local_index)
	       end
	    end
	 else
	    data_discarded = data_discarded + 1
	 end
	 bufs[i]:free()
      end

      local num = #seen
      ackBufs:alloc(ACK_LEN)
      for _, buf in ipairs(ackBufs) do
	 local pkt = buf:getPercaPacket()
	 if #seen > 0 then
	    local flow_id = table.remove(seen)
	    local local_index = flow_index[flow_id]
	    local seq_num = arr_max_seq_num:read(local_index)
	    local sender_mac = arr_mac:read(local_index)
	    pkt.perca:setflowID(flow_id)
	    pkt.eth:setDst(sender_mac)
	    pkt.perca:setackNo(seq_num+1)	    
	 else
	    buf:free()
	 end
      end
      if num > 0 then
	 txQ:sendN(ackBufs, num)
      end
   end

   for flow_id, index in pairs(flow_index) do
      local src = arr_mac:read(index)
      local seq_num = arr_max_seq_num:read(index)
      local flow_id = arr_flow_id:read(index)
      log:info("dataReceiver at dev %d: local index %s: flow_id %s src %s max_seq_num %s",
	       txQ.dev.id, index, flow_id, src, seq_num)
   end
   log:info("dataReceiver at dev %d discarded %d packets",
	    txQ.dev.id, data_discarded)

end

function genEmptyWorkload()
   wl = {}
   wl["num_flows"] = 0
   wl["dst_mac"] = {}
   wl["size"] = {}
   wl["flow_id"] = {}
   return wl
end

function genWorkload(dstMacNo, numFlows, size, start)
   wl = {}
   -- 0000:01:00.0 / eth2 is plugged into nf1
   -- 0000:01:00.1 / eth3 is plugged into nf0
   wl["num_flows"] = numFlows
   wl["dst_mac"] = {}
   wl["size"] = {}
   wl["flow_id"] = {}
   local flowNum = 0
   while flowNum <= numFlows do
      table.insert(wl.dst_mac, dstMacNo)
      table.insert(wl.size, size)
      table.insert(wl.flow_id, (start+flowNum))
      flowNum = flowNum + 1
      end
   return wl
end

function genWorkload1()
   wl = {}
   wl["num_flows"] = 2
   wl["dst_mac"] = {nf_macno_map.nf0, nf_macno_map.nf0}
   wl["size"] = {1000000, 1000000}
   wl["flow_id"] = {53, 58}
   return wl
end


function dataSenderTask(queue, srcMac, srcMacStr, wl, ackRxQueue, controlTxQueue, controlRxQueue,
			controlTxQueueExtra)
   -- this thread sends data, receives acks
   -- and sends and receives control packets

   local sa_max_ack_num = array32:new(NUM_FLOWS, 0)
   local shared_meta_info = array32:new(NUM_FLOWS, INIT_GAP)

   local ackBufs = memory.bufArray()
   local control_rx_bufs = memory.bufArray()

   log:info("Starting tx slave at : %s / %d", srcMacStr, srcMac)
   local devNo = queue.dev.id + 1
   -- memory pool with default values for all packets,
   -- this is our archetype

   -- for sending new control packets
   local control_mempool = memory.createMemPool(function(buf)
	 buf:getPerccPacket():fill{
	    -- fields not explicitly set here are initialized to reasonable defaults
	    ethSrc = srcMac, -- MAC of the tx device
	    ethDst = srcMac,
	    ethType = eth.TYPE_PERC,
	    perccflowID = 0x1,
	    perccleave = 0,
	    perccisForward = 1,
	    percchopCnt = 0,
	    perccbottleneck_id=0xFF,
	    perccdemand=0xFFFFFFFF,
	    perccinsert_debug=0x1,
	    percclabel_0=percc.INACTIVE,
	    percclabel_1=percc.INACTIVE,
	    percclabel_2=percc.INACTIVE,
	    perccalloc_0=0xFFFFFFFF,
	    perccalloc_1=0xFFFFFFFF,
	    perccalloc_2=0xFFFFFFFF,
	    perccindex=RUN_INDEX,
	    pktLength = CONTROL_PACKET_LEN
	}
	end)
   local control_bufs = control_mempool:bufArray(CONTROL_BATCH_SIZE)

   -- for sending new data packets
   local mempool = memory.createMemPool(function(buf)
	 buf:getPercdPacket():fill{
	    ethSrc = srcMac, --queue, -- MAC of the tx device
	    ethDst = srcMac,
	    ethType = eth.TYPE_PERC_DATA,
	    percdflowID = 0x0,
	    percdindex = RUN_INDEX,
	    percdseqNo = 0x0,
	    percdackNo = 0x0,
	    pktLength = PKT_LEN
				}
   end)

   -- a bufArray is just a list of buffers from a mempool 
   -- that is processed as a single batch
   local bufs = mempool:bufArray(DATA_BATCH_SIZE)

   -- initialize all the flows to start at the same time
   -- so alloc resources on the shared_xx arrays (common_index)
   -- and on the timing wheel
   local tw = timing_wheel:new(TIMING_WHEEL_NUM_SLOTS)
   local control_tw = timing_wheel:new(NUM_FLOWS)
   -- should I check ACKs also in this loop? no

   -- dstMac, dstMacStr)
   -- for now test acking etc. with one flow
   local num_flows_pending_syn = wl.num_flows
   local num_active_flows = 0
   local next_seq_num = {}
   local flow_index = {}
   local flow_size = {}
   local flow_dst_mac = {}
   local last_rate = {}
   local rate_changes = {}
   local control_received = 0
   local control_discarded = 0
   local ack_discarded = 0

   local flow_num = 0
   while flow_num < wl.num_flows do
      local flow_id = wl.flow_id[flow_num+1]
      next_seq_num[flow_id] = 0
      flow_dst_mac[flow_id] = wl.dst_mac[flow_num+1]
      flow_index[flow_id] = flow_num+1 -- TODO: check this index is available in shared_arrays
      flow_size[flow_id] = wl.size[flow_num+1]
      last_rate[flow_id] = 0
      rate_changes[flow_id] = {}
      table.insert(rate_changes[flow_id], 0)
      flow_num = flow_num + 1
      control_tw:insert(flow_id, flow_num)
   end

   local peek0 = tw:peek(0)
   local peek1 = tw:peek(1)
   local peek99 = tw:peek(99)
   local peek100 = tw:peek(100)
   log:info("peeking ahead at tw 0 " .. 
	       peek0 .. " 1 " .. peek1 ..
	       " 99 " .. peek99 .. " 100 " .. peek100)
   
   log:info("dataSender about to start %d flows", num_flows_pending_syn)

   local last_lm_time = lm.getTime()
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
      if num_flows_pending_syn > 0 then
	 log:info(num_flows_pending_syn .. " pending SYNs")
       	 control_bufs:alloc(CONTROL_PACKET_LEN)
	 local first_n_valid = 0
       	 for i, buf in ipairs(control_bufs) do
       	    local pkt = buf:getPerccPacket()
       	    local flow_id = control_tw:remove_and_tick()
       	    if flow_index[flow_id] ~= nil then
	       local dst_mac = flow_dst_mac[flow_id]
       	       pkt.eth:setDst(dst_mac) -- routing
	       pkt.eth:setType(eth.TYPE_PERC)
       	       pkt.percc:setflowID(flow_id) -- identifier
	       pkt.percc:setlabel_0(percc.NEW_FLOW)
       	       num_flows_pending_syn = num_flows_pending_syn - 1
	       if num_flows_pending_syn == 0 then
		  log:info("No more pending SYNs after " .. i .. " bufs")
		  first_n_valid = i
	       end
	       
       	    else
       	       pkt.eth:setSrc(srcMac) -- so packet is dropped by switch
       	       pkt.eth:setDst(srcMac)
	       pkt.percc:setlabel_0(percc.INACTIVE)
	       buf:free()
       	    end
       	 end
      	 controlTxQueue:sendN(control_bufs, first_n_valid)
      end

      if num_active_flows > 0 then
	 bufs:alloc(PKT_LEN)
	 for i, buf in ipairs(bufs) do
	    -- here we get next flow on timing wheel
	    -- and re-insert it after
	    local pkt = buf:getPercdPacket()
	    local flow_id = tw:remove_and_tick()
	    if flow_index[flow_id] ~= nil then
	       local index = flow_index[flow_id]
	       local seq_num = next_seq_num[flow_id]
	       local size = flow_size[flow_id]
	       local dst_mac = flow_dst_mac[flow_id]
	       local next_expected = sa_max_ack_num:read(index)
	       if next_expected < size then	       
		  if seq_num == size then -- keep sending last packet till ACKed
		     seq_num = next_expected
		  end
		  
		  pkt.eth:setDst(dst_mac) -- routing
		  pkt.percd:setflowID(flow_id) -- identifier
		  pkt.percd:setseqNo(seq_num)
		  pkt.percd:setackNo(0)
		  next_seq_num[flow_id] = seq_num + 1
		  local gap = shared_meta_info:read(index)
		  tw:insert(flow_id, gap)
	       else
		  num_active_flows = num_active_flows - 1
	       end
	    else
	       pkt.eth:setDst(srcMac)
	       pkt.eth:setSrc(srcMac)
	       -- 	-- otherwise packet is dropped
	    end
	 end	 
      -- no checksums
      -- send out all packets and frees
      -- old bufs that have been sent
	 queue:send(bufs)
      end
      
      -- reflect control packets, unless it's a leave packet
      local lm_time = lm.getTime()
      if ((lm_time - last_lm_time) > CONTROL_WAIT) then
	 last_lm_time = lm_time
	 local control_rx = controlRxQueue:tryRecv(control_rx_bufs, CONTROL_RX_WAIT)
	 control_received = control_received + control_rx
	 for i = 1, control_rx do
	    local pkt = control_rx_bufs[i]:getPerccPacket()
	    local run_index = pkt.percc:getindex()
	    local flow_id = pkt.percc:getflowID()
	    if run_index == RUN_INDEX then	    
	       local index = flow_index[flow_id]
	       if index ~= nil then
		  -- we store flow_index for flows we started
		  -- extract rate and update gap
		  local new_rate = pkt.percc:getdemand()
		  if new_rate <= 2147483648 and new_rate > 0 then
		     local new_gap = math.floor(2147483648.0/new_rate) 
		     -- e.g., inter-packet gap 6.25, round to 7
		     -- gap indexes start at 0 we would say 6
		     -- to mean send every 7th packet
		     local old_gap = shared_meta_info:read(index)
		     if (old_gap == INIT_GAP) then 
			-- also put first packet on timing wheel flow_num slots into the future
			local shift = tw:insert(flow_id, 1) -- maybe wait until we get first rate?
			--local peek = tw:peek(shift+1)
			num_active_flows = num_active_flows + 1
			--log:info("starting new flow " .. flow_id .. " with gap "
			--	    .. new_gap.. " inserted " .. (shift+1) .. " packets in the future, peeking ahead " .. peek)
		     end
		     -- if (new_rate ~= last_rate[flow_id]) then
		     -- 	last_rate[flow_id] = new_rate
		     -- 	local changes = rate_changes[flow_id]
		     -- 	table.insert(changes, new_rate)
		     -- end
		     -- not sure why we need the old gap, to log?
		     -- what if instantaneous rate is infeasible C, C/2
		     -- if it's inf then maybe we also insert first
		     -- data packet into tw here?	       
		     shared_meta_info:write(new_gap, index)	       
		  end
	       end
	       -- reverse direction
	       local direction = pkt.percc:getisForward()
	       pkt.percc:setisForward(1 - direction)
	       
	       -- switch mac, unless it's a leave, which should be discard
	       local tmp = pkt.eth:getSrc()
	       pkt.eth:setSrc(pkt.eth:getDst())
	       if pkt.percc:getleave() == 0x0 then
		  pkt.eth:setDst(tmp)
	       else
		  control_discarded = control_discarded + 1
	       end

	       -- check if flow is over, if so mark as leave	    
	       if (index ~= nil) then
		  local next_expected = sa_max_ack_num:read(index)
		  if next_expected == flow_size[flow_id] then
		     pkt.percc:setleave(0x1)
		  end
	       end	    
	    else
	       -- log:info("discarding control packet with index " .. run_index .. " run index is " .. RUN_INDEX )
	       control_discarded = control_discarded + 1
	       pkt.eth:setSrc(pkt.eth:getDst())
	    end
	 end	 
	 controlTxQueueExtra:sendN(control_rx_bufs, control_rx)
      end

      -- receive acks
      local rx = ackRxQueue:tryRecv(ackBufs, ACK_RX_WAIT)
      for i = 1, rx do
	 -- save MAC addresses and sequence number
	 local pkt = ackBufs[i]:getPercaPacket()
	 local flow_id = pkt.perca:getflowID()
	 local run_index = pkt.perca:getindex()
	 if run_index == RUN_INDEX and flow_index[flow_id] ~= nil then
	    local index = flow_index[flow_id]
	    local ack_num = pkt.perca:getackNo()
	    -- next expected sequence number	 
	    local tmp = sa_max_ack_num:read(index)
	    if tmp < ack_num then
	       sa_max_ack_num:write(ack_num, index)	       
	    end
	 else
	    ack_discarded = ack_discarded + 1
	 end
	 ackBufs[i]:free()
      end
   end

   for flow_id, index in pairs(flow_index) do
      local dst = flow_dst_mac[flow_id]
      local seq_num = next_seq_num[flow_id]
      local size = flow_size[flow_id]      
      local next_expected = sa_max_ack_num:read(index)
      local rate = last_rate[flow_id]
      local changes = rate_changes[flow_id]
      local num_changes = #changes
      log:info("dataSender / ackReceiver/ controlReflector at dev %d: local index %s flow_id %s dst %s next_seq_num %s next_expected %s size %s last_rate %s # changes %d",
	       queue.dev.id, index, flow_id, dst, seq_num, next_expected, size, rate, num_changes)
      local change_num = 0
      while change_num < #changes do
	 log:info("dataSender / ackReceiver/ controlReflector at dev %d: local flow_id %s rate change # %d %s",
		  queue.dev.id, flow_id, change_num, changes[change_num+1])
	 change_num = change_num + 1
      end
   end
   log:info("dataSender / ackReceiver/ controlReflector at dev %d received %d control packets, discarded %d control packets, %d ack packets.",
	    queue.dev.id, control_received, control_discarded, ack_discarded)

end

