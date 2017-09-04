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

-- set addresses here
local DST_MAC_0       = 8869393797384 --  "08:11:11:11:11:08"
local DST_MAC_1       = 8942694572552 --  "08:22:22:22:22:08"
local DST_MAC_2       = 9015995347720 --  "08:33:33:33:33:08"
local DST_MAC_3       = 9089296122888 --  "08:44:44:44:44:08"

local DST_MAC_0_STR       =   "08:11:11:11:11:08"
local DST_MAC_1_STR       =   "08:22:22:22:22:08"
local DST_MAC_2_STR       =   "08:33:33:33:33:08"
local DST_MAC_3_STR       =   "08:44:44:44:44:08"

local IP32_MASK_STR = "255.255.255.255" --4294967295
local ACK_CODE = "10.2.2.10"

local PKT_LEN       = 1460 --60
local ACK_LEN = 60
local SRC_IP        = "10.0.0.10"
local DST_IP        = "10.1.0.10"
local SRC_PORT_BASE = 1234 -- actual port will be SRC_PORT_BASE * random(NUM_FLOWS)
local DST_PORT      = 1234
local NUM_FLOWS     = 10
local TIMING_WHEEL_NUM_SLOTS = 1000
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
	 txQueues = 3,
	 rxQueues = 3
      }
      args.dev[i] = dev
   end

   device.waitForLinks()
   log:info("Destination mac 0: %s", DST_MAC_0_STR)
   log:info("Destination mac 1: %s", DST_MAC_1_STR)


   -- print statistics
   stats.startStatsTask{devices = args.dev}



   local dataQ = 0
   local controlQ = 1
   local ackQ = 2



   -- configure tx rates and start transmit slaves
   for i, dev in ipairs(args.dev) do 
      if (i == 1) then
	 local wl = genWorkload()

   	 local dataTxQueue = dev:getTxQueue(dataQ)	 
	 dataTxQueue:setRate(9000)

	 local ackRxQueue = dev:getRxQueue(ackQ)
	 local af= dev:fiveTupleFilter({dstIp=ACK_CODE,
					dstIpMask=IP32_MASK_STR}, ackRxQueue)

   	 lm.startTask("dataSenderTask", dataTxQueue, DST_MAC_0, DST_MAC_0_STR, wl, ackRxQueue)


   	 -- lm.startTask("ackReceiverTask", ackRxQueue, sa_max_ack_num)

   	 -- local ackTxQueue = dev:getTxQueue(ackQ)
   	 -- local dataRxQueue = dev:getRxQueue(dataQ)
   	 -- lm.startTask("dataReceiverTask", dataRxQueue, ackTxQueue,
   	 -- 	      DST_MAC_0, DST_MAC_0_STR)

      end

      if (i == 2) then
	 local wl = genWorkload1()

   	 -- local dataTxQueue = dev:getTxQueue(dataQ)	 
	 -- dataTxQueue:setRate(5000)
   	 -- lm.startTask("dataSenderTask", dataTxQueue, DST_MAC_1, DST_MAC_1_STR, wl)

	 -- local ackRxQueue = dev:getRxQueue(ackQ)
	 -- local af= dev:fiveTupleFilter({dstIp=ACK_CODE,
	 -- 				dstIpMask=UINT32_MASK_STR}, ackRxQueue)

   	 -- lm.startTask("ackReceiverTask", ackRxQueue)

   	 local ackTxQueue = dev:getTxQueue(ackQ)
   	 local dataRxQueue = dev:getRxQueue(dataQ)
   	 lm.startTask("dataReceiverTask", dataRxQueue, ackTxQueue,
   		      DST_MAC_1, DST_MAC_1_STR)
      end


   end
   lm.waitForTasks()
end


function dataReceiverTask(rxQ, txQ, srcMac, srcMacStr)
   local arr_max_seq_num = array32:new(NUM_FLOWS, 0)
   local arr_flow_id = array32:new(NUM_FLOWS, 0)
   local arr_mac = array64:new(NUM_FLOWS, 0)
   local arr_sender_index = array32:new(NUM_FLOWS, 0)


   log:info("Starting data receiver task at : rx %s tx %s", rxQ, txQ)
   local bufs = memory.bufArray()


   -- memory pool with default values for ack packets
   local mempool = memory.createMemPool(function(buf)
	 buf:getTcpPacket():fill{
	    ethSrc = srcMac, --queue, -- MAC of the tx device
	    ethDst = srcMac,
	    ip4Src = SRC_IP,
	    ip4Dst = ACK_CODE,
	    tcpSrc = SRC_PORT,
	    tcpDst = DST_PORT,
	    pktLength = ACK_LEN,
				}
   end)
   
   local ackBufs = mempool:bufArray()
   local flow_index = {}

   local max_I_acked = 0	
   local seen = {}
   local next_free_index = 1
   while lm.running() do
      local rx = rxQ:tryRecv(bufs, 1000)
      local num_flows = 0

      for i = 1, rx do
	 -- arrve MAC addresses and sequence number
	 local pkt = bufs[i]:getTcpPacket()
	 local src = pkt.eth:getSrc()
	 local sender_index = pkt.tcp:getDstPort()
	 local flow_id = pkt.tcp:getSrcPort()
	 local seq_num = pkt.tcp:getSeqNumber()
	 
	 local local_index = flow_index[flow_id]
	 table.insert(seen, flow_id) -- so we'll send one ACK per packet and dup-acks
	 if local_index == nil then	    
	    local_index = next_free_index
	    next_free_index = next_free_index + 1
	    -- TODO: check it's available
	    flow_index[flow_id] = local_index
	    arr_mac:write(src, local_index)
	    arr_flow_id:write(flow_id, local_index)
	    arr_sender_index:write(sender_index, local_index)
	    arr_max_seq_num:write(seq_num, local_index)
	    num_flows = num_flows + 1
	 else
	    local tmp = arr_max_seq_num:read(local_index)
	    if seq_num == tmp + 1 then -- for in order delivery, check if seq_num == tmp + 1 else seq_num > tmp
	       arr_max_seq_num:write(seq_num, local_index)
	    end
	 end
	 bufs[i]:free()
      end

      local num = #seen
      ackBufs:alloc(ACK_LEN)
      for _, buf in ipairs(ackBufs) do
	 local pkt = buf:getTcpPacket()
	 if #seen > 0 then
	    local flow_id = table.remove(seen)
	    local local_index = flow_index[flow_id]
	    local seq_num = arr_max_seq_num:read(local_index)
	    local sender_mac = arr_mac:read(local_index)
	    local sender_index = arr_sender_index:read(local_index)
	    pkt.tcp:setSrcPort(flow_id)
	    pkt.eth:setDst(sender_mac)
	    pkt.tcp:setDstPort(sender_index)
	    pkt.tcp:setAckNumber(seq_num+1)
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
      local sender_index = arr_sender_index:read(index)
      log:info("dataReceiver at dev %d: local index %s: flow_id %s src %s max_seq_num %s  sender_index %s",
	       txQ.dev.id, index, flow_id, src, seq_num, sender_index)
   end

end

function genWorkload()
   wl = {}
   wl["num_flows"] = 2
   wl["dst_mac"] = {DST_MAC_1, DST_MAC_1}
   wl["size"] = {1000000, 1000000}
   wl["flow_id"] = {43, 48}
   return wl
end

function genWorkload1()
   wl = {}
   wl["num_flows"] = 2
   wl["dst_mac"] = {DST_MAC_0, DST_MAC_0}
   wl["size"] = {1000000, 1000000}
   wl["flow_id"] = {53, 58}
   return wl
end






function ackReceiverTask(rxQ, sa_max_ack_num)
   log:info("Starting ack receiver task at : %s", rxQ)
   local bufs = memory.bufArray()
   -- pkt has flowId and common index number !?
   -- so we can index directly into share state
   local devNo = rxQ.dev.id+1
   local flow_index = {}
   while lm.running() do
      local rx = rxQ:tryRecv(bufs, 1000)
      for i = 1, rx do
	 -- save MAC addresses and sequence number
	 local pkt = bufs[i]:getTcpPacket()
	 local flow_id = pkt.tcp:getSrcPort()
	 local local_index = pkt.tcp:getDstPort()
	 local ack_num = pkt.tcp:getAckNumber() -- next expected sequence number
	 
	 if local_index < NUM_FLOWS then
	    local tmp = sa_max_ack_num:read(local_index)
	    if tmp == 0 then
	       flow_index[flow_id] = local_index
	    end
	    if tmp < ack_num then
	       sa_max_ack_num:write(ack_num, local_index)
	    end
	 end
	 bufs[i]:free()
      end
   end

   for flow_id, index in pairs(flow_index) do
      local max_ack = sa_max_ack_num:read(index)
      log:info("ackReceiver at dev %d: local index %s flow_id %s max_ack_num %s",
	       rxQ.dev.id, index, flow_id, max_ack)
   end
end

function dataSenderTask(queue, srcMac, srcMacStr, wl, ackRxQueue)
   -- this thread sends data, receives acks
   -- and sends and receives control packets

   local sa_max_ack_num = array32:new(NUM_FLOWS, 0)
   local shared_meta_info = array32:new(4, 3)

   local ackBufs = memory.bufArray()

   log:info("Starting tx slave at : %s / %d", srcMacStr, srcMac)
   local devNo = queue.dev.id + 1
   -- memory pool with default values for all packets,
   -- this is our archetype

   local mempool = memory.createMemPool(function(buf)
	 buf:getTcpPacket():fill{
	    ethSrc = srcMac, --queue, -- MAC of the tx device
	    ethDst = srcMac,
	    ip4Src = SRC_IP,
	    ip4Dst = DST_IP,
	    tcpSrc = SRC_PORT,
	    tcpDst = DST_PORT,
	    pktLength = PKT_LEN
				}
   end)

   -- a bufArray is just a list of buffers from a mempool 
   -- that is processed as a single batch
   local bufs = mempool:bufArray()

   -- initialize all the flows to start at the same time
   -- so alloc resources on the shared_xx arrays (common_index)
   -- and on the timing wheel
   local tw = timing_wheel:new(TIMING_WHEEL_NUM_SLOTS)
   -- should I check ACKs also in this loop? no

   -- dstMac, dstMacStr)
   -- for now test acking etc. with one flow
   local num_active_flows = wl.num_flows
   local next_seq_num = {}
   local flow_index = {}
   local flow_size = {}
   local flow_dst_mac = {}
   local flow_num = 0
   while flow_num < num_active_flows do
      local flow_id = wl.flow_id[flow_num+1]
      next_seq_num[flow_id] = 0
      flow_dst_mac[flow_id] = wl.dst_mac[flow_num+1]
      flow_index[flow_id] = flow_num+1 -- TODO: check this index is available in shared_arrays
      flow_size[flow_id] = wl.size[flow_num+1]
      flow_num = flow_num + 1
      -- also put first packet on timing wheel flow_num slots into the future
      tw:insert(flow_id, flow_num)
   end
   log:info("dataSender about to start %d flows", num_active_flows)

   while lm.running() and num_active_flows > 0 do 
      -- check if Ctrl+c was pressed

      -- when do we reset seq_num to sa_max_ack_num:read(common_index)?
      -- maybe check periodically for all flows if << some condition >>?
      -- such as if last_ack time was too long ago (timeout)
      -- or if we've gotten three dup acks		 
      -- is resetting = go-back-N?
      -- local mi = shared_meta_info:read(common_index)
      -- this actually allocates some buffers from 
      -- the mempool the array is associated with
      -- this has to be repeated for each send 
      -- because sending is asynchronous, we cannot 
      -- reuse the old buffers here		

      bufs:alloc(PKT_LEN)
      for i, buf in ipairs(bufs) do
	 -- here we get next flow on timing wheel
	 -- and re-insert it after
	 -- TODO: maybe wheel as an array in C
	 -- or even array of lists?
	 local pkt = buf:getTcpPacket()
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
	       -- go back N here if next_expected is much smaller than seq num
	       pkt.eth:setDst(dst_mac) -- routing
	       pkt.tcp:setSrcPort(flow_id) -- identifier
	       pkt.tcp:setDstPort(index) -- random info
	       pkt.tcp:setSeqNumber(seq_num)
	       pkt.tcp:setAckNumber(0)
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

      -- receive acks
      local rx = ackRxQueue:tryRecv(ackBufs, 1000)
      for i = 1, rx do
	 -- save MAC addresses and sequence number
	 local pkt = ackBufs[i]:getTcpPacket()
	 local flow_id = pkt.tcp:getSrcPort()
	 if flow_index[flow_id] ~= nil then
	    local index = flow_index[flow_id]
	    local ack_num = pkt.tcp:getAckNumber() -- next expected sequence number	 
	    local tmp = sa_max_ack_num:read(index)
	    if tmp < ack_num then
	       sa_max_ack_num:write(ack_num, index)	       
	    end
	 end
	 ackBufs[i]:free()
      end
   end

   for flow_id, index in pairs(flow_index) do
      local dst = flow_dst_mac[flow_id]
      local seq_num = next_seq_num[flow_id]
      local size = flow_size[flow_id]      
      local next_expected = sa_max_ack_num:read(index)
      log:info("dataSender / ackReceiver at dev %d: local index %s flow_id %s dst %s next_seq_num %s next_expected %s size %s",
	       queue.dev.id, index, flow_id, dst, seq_num, next_expected, size)
   end

end

