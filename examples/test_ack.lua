--- A simple TCP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local arp    = require "proto.arp"
local timer  = require "timer"

-- set addresses here
local DST_MAC_0       = 8869393797384 --  "08:11:11:11:11:08"
local DST_MAC_1       = 8942694572552 --  "08:22:22:22:22:08"
local DST_MAC_2       = 9015995347720 --  "08:33:33:33:33:08"
local DST_MAC_3       = 9089296122888 --  "08:44:44:44:44:08"

local DST_MAC_0_STR       =   "08:11:11:11:11:08"
local DST_MAC_1_STR       =   "08:22:22:22:22:08"
local DST_MAC_2_STR       =   "08:33:33:33:33:08"
local DST_MAC_3_STR       =   "08:44:44:44:44:08"

local PKT_LEN       = 1460 --60
local ACK_LEN = 60
local SRC_IP        = "10.0.0.10"
local DST_IP        = "10.1.0.10"
local SRC_PORT_BASE = 1234 -- actual port will be SRC_PORT_BASE * random(NUM_FLOWS)
local DST_PORT      = 1234
local NUM_FLOWS     = 1000
local ACK_INTERVAL = 1e-3
local  array32       = require "array32"
local  array64       = require "array64"
shared_meta_info = array32:new(4, 0)

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
			txQueues = 1,
			rxQueues = 1
		}
		args.dev[i] = dev
	end

	device.waitForLinks()
	log:info("Destination mac 0: %s", DST_MAC_0_STR)
	log:info("Destination mac 1: %s", DST_MAC_1_STR)


	-- print statistics
	stats.startStatsTask{devices = args.dev}

	lm.startTask("interactiveSlave")
	-- configure tx rates and start transmit slaves
	for i, dev in ipairs(args.dev) do 
	   if (i == 1) then
	    local queue = dev:getTxQueue(0)
	    lm.startTask("txSlave", queue, DST_MAC_0, DST_MAC_0_STR, DST_MAC_1, DST_MAC_1_STR)
	   end
	   if (i == 2) then
	    local rxQ = dev:getRxQueue(0)
	    local txQ = dev:getTxQueue(0)
	    lm.startTask("ackRxSlave", rxQ, txQ, DST_MAC_1, DST_MAC_1_STR)
	    --lm.startTask("ackTxSlave",  txQ, DST_MAC_1)
	   end

	end
	lm.waitForTasks()
end

function interactiveSlave()
 while lm.running() do
  shared_meta_info:write(1, math.random(0, 255))
  end
end


-- do this as two threads one that receives and updates seq no
-- another one that sends ack and updates last ack time
-- also flow_id to common index map is updated by first thread
-- what if you evict a flow id from shared state?
-- nothing happens, just make a new one
-- who should evict? just to avoid conflicts, same thread that
-- allocates. how to allocate? if there's any free
-- id 0, that's available to use else evict.

-- shared state :
-- sa_max_seq_num
-- sa_last_ack_time
-- sa_flow_id
-- sa_mac
-- sa_free 
-- use as a bitmap, read one entry at a time until you find
-- a non 0xFF, get highest bit
-- flow id to index map: 


local sa_free = array32:new(1,0)
local sa_max_seq_num = array32:new(NUM_FLOWS, 0)
local sa_flow_id = array32:new(NUM_FLOWS, 0)
local sa_mac = array64:new(NUM_FLOWS, 0)

-- function ackTxSlave(txQ, srcMac, srcMacStr)
--   log:info("Starting ack slave at : %s", rxQ)
--   local flow_index_copy = {}
--   local mac_copy = {}
--   local sa_free_copy = 0

--   -- memory pool with default values for ack packets
--   local mempool = memory.createMemPool(function(buf)
--   buf:getTcpPacket():fill{
-- 	ethSrc = srcMac, --queue, -- MAC of the tx device
-- 	ethDst = srcMac,
-- 	ip4Src = SRC_IP,
-- 	ip4Dst = DST_IP,
-- 	tcpSrc = SRC_PORT,
-- 	tcpDst = DST_PORT,
-- 	pktLength = 60,
-- 	}
-- 	end)


-- 	local ackBufs = mempool:bufArray()
-- 	local next_index = 0

-- 	local timer = timer:new(ACK_INTERVAL)
--  	while lm.running() do
	
-- 	      if timer:expired() then
-- 	      	 ackBufs:alloc(60) -- PKT_LEN=60
-- 	   	 for i, buf in ipairs(ackBufs) do
-- 		-- check up to 5 indices for each packet
-- 	      local flow_id = sa_flow_id:read(next_index)
-- 	      local tmp = 0
-- 	      while flow_id == 0 and tmp < 5 do
-- 	      	    flow_id = sa_flow_id:read(next_index)
-- 		    next_index = (next_index + 1)%NUM_FLOWS
-- 		    tmp = tmp + 1
-- 		    end

-- 	      if (flow_id > 0) then
-- 	       	if (flow_index_copy[i] ~= flow_id) then
-- 		    mac_copy[flow_id] = sa_mac:read(i)
-- 		    flow_index_copy[flow_id] = i
-- 	       	  end		  
-- 	       	  local seq_num = sa_max_seq_num:read(i)
-- 		  local pkt = buf:getTcpPacket()
-- 		  pkt.tcp:setDstPort(flow_id)
-- 		  pkt.tcp:setAckNumber(seq_num+1)
-- 		  pkt.eth:setDst(mac_copy[flow_id])
-- 		  pkt.tcp:setSeqNumber(0)
-- 	       end -- if flow_id > 0	       
-- 	       -- otherwise ACK packet is just dropped by switch
-- 	   end
--  	   txQ:send(ackBufs)
-- 	   end
--  	end
-- end

function get_index()
 -- find an empty slot
 local tmp = sa_free:read(1)
 local common_index = nil
 if tmp < 1 then
   common_index = 1
    sa_free:write(1, 1)
 else
   common_index = 1
   log:info("OOM")
 end
 return common_index
end


function ackRxSlave(rxQ, txQ, srcMac, srcMacStr)
  log:info("Starting ack rx slave at : %s", rxQ)
  local bufs = memory.bufArray()


   -- memory pool with default values for ack packets
  local mempool = memory.createMemPool(function(buf)
  buf:getTcpPacket():fill{
	ethSrc = srcMac, --queue, -- MAC of the tx device
	ethDst = srcMac,
	ip4Src = SRC_IP,
	ip4Dst = DST_IP,
	tcpSrc = SRC_PORT,
	tcpDst = DST_PORT,
	pktLength = ACK_LEN,
	}
	end)
	local ackBufs = mempool:bufArray()
	local flow_index = {}
	

	while lm.running() do
	 local rx = rxQ:tryRecv(bufs, 1000)
	 local num_flows = 0
	 local seen = {}
	 for i = 1, rx do
	  -- save MAC addresses and sequence number
	  local pkt = bufs[i]:getTcpPacket()
	  local src = pkt.eth:getSrc()
	  local flow_id = pkt.tcp:getSrcPort()
	  local seq_num = pkt.tcp:getSeqNumber()
	  
	  local common_index = flow_index[flow_id]
	  if common_index == nil then
	   table.insert(seen, flow_id)
	   common_index = get_index()
           flow_index[flow_id] = common_index
	   sa_mac:write(src, common_index)
	   sa_flow_id:write(flow_id, common_index)
	   sa_max_seq_num:write(seq_num, common_index)
	   num_flows = num_flows + 1
	  else
	   local tmp = sa_max_seq_num:read(common_index)
	   if seq_num > tmp then
	      sa_max_seq_num:write(common_index, seq_num)
	   end
	  end
	  bufs[i]:free()
	 end

	 ackBufs:alloc(ACK_LEN)
	 local flow_num = 0
	 for _, buf in ipairs(ackBufs) do
	     local pkt = buf:getTcpPacket()
	     local flow_id = 0
	     if flow_num < #seen then
	     	flow_id = seen[flow_num+1]
		pkt.tcp:setDstPort(flow_id)
		local index = flow_index[flow_id]
		local seq_num = sa_max_seq_num:read(index)
		local mac = sa_mac:read(index)
		pkt.tcp:setAckNumber(seq_num+1)
		pkt.eth:setDst(mac)
		flow_num = flow_num + 1
	     end
	 end
	 txQ:send(ackBufs)
	end


	local index = 1
	local src = sa_mac:read(index)
	local seq_num = sa_max_seq_num:read(index)
	local flow_id = sa_flow_id:read(index)
	log:info("index %s src %s seq_num %s flow_id %s", index, src, seq_num, flow_id)


end

function getWorkload()
	 wl = {}
	 wl["dstMac"] = {DST_MAC_0, DST_MAC_1}
	 wl["size"] = {100, 100}
	 return wl
end

function txSlave(queue, srcMac, srcMacStr, dstMac, dstMacStr)
	log:info("Starting tx slave at : %s / %d", srcMacStr, srcMac)

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

	-- initialize per-flow state	
	-- local per_flow_state = {}
	-- per_flow_state["seqNo"] = {}
	-- per_flow_state["index"] = {}

	-- initialize all the flows to start at the same time
	-- so alloc resources on the shared_xx arrays (common_index)
	-- and on the timing wheel

	-- should I check ACKs also in this loop?

	-- for now test acking etc. with one flow
	local num_active_flows = 1
	local seq_num = 0
	local common_index = 1
	local dst_mac = dstMac
	local flow_id = 23
	local flow_size = 256 -- TODO: must use > 8 b wide field 
	while lm.running() and num_active_flows > 0 do 
	-- check if Ctrl+c was pressed
	        local mi = shared_meta_info:read(common_index)
		-- this actually allocates some buffers from 
		-- the mempool the array is associated with
		-- this has to be repeated for each send 
		-- because sending is asynchronous, we cannot 
		-- reuse the old buffers here

		bufs:alloc(PKT_LEN)
		for i, buf in ipairs(bufs) do
		    local pkt = buf:getTcpPacket()
		     if seq_num < flow_size then
		     	   pkt.eth:setDst(dst_mac) -- routing
		 	   pkt.tcp:setSrcPort(flow_id) -- identifier
		-- 	   pkt.tcp:setDstPort(mi) -- random info
			   pkt.tcp:setSeqNumber(seq_num)
		-- 	   pkt.tcp:setAckNumber(0)
		 	   seq_num = seq_num + 1
		 	   if seq_num == 256 then
		 	      num_active_flows = 1
		 	      seq_num = 0
		 	   end
		-- 	-- otherwise packet is dropped
		 	end
		end
		-- no checksums
		-- send out all packets and frees
		-- old bufs that have been sent
		queue:send(bufs)
	end
end

