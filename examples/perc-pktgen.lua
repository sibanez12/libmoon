--- A simple UDP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local arp    = require "proto.arp"
local percc    = require "proto.percc"
local pcap   = require "pcap"

-- set addresses here
local DST_MAC       = "08:44:44:44:44:08" --nil -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local PKT_LEN       = 128
local SRC_IP        = "10.0.0.10"
local DST_IP        = "10.1.0.10"

local nf_mac_map = {}
nf_mac_map["nf0"] = "08:11:11:11:11:08"
nf_mac_map["nf1"] = "08:22:22:22:22:08"
nf_mac_map["nf2"] = "08:33:33:33:33:08"
nf_mac_map["nf3"] = "08:44:44:44:44:08"

local SRC_PORT_BASE = 1234 -- actual port will be SRC_PORT_BASE * random(NUM_FLOWS)
local DST_PORT      = 1234
local NUM_FLOWS     = 1000
-- used as source IP to resolve GW_IP to DST_MAC
-- also respond to ARP queries on this IP
local ARP_IP	= SRC_IP
-- used to resolve DST_MAC
local GW_IP		= DST_IP


-- the configure function is called on startup with a pre-initialized command line parser
function configure(parser)
	parser:description("Edit the source to modify constants like IPs and ports.")
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	return parser:parse()
end

function master(args,...)
	log:info("Check out MoonGen (built on lm) if you are looking for a fully featured packet generator")
	log:info("https://github.com/emmericp/MoonGen")

	-- configure devices and queues
	for i, dev in ipairs(args.dev) do
	   local dev = device.config{
	      port = dev,
	      txQueues = 1,
	      rxQueues = 1,
	   }
	   args.dev[i] = dev
	end
	device.waitForLinks()
	-- print statistics
	stats.startStatsTask{devices = args.dev}
	local snaplen = PKT_LEN
	-- configure tx rates and start transmit slaves
	for i, dev in ipairs(args.dev) do
	   if i == 1 then
	      local queue = dev:getTxQueue(0)
	      lm.startTask("txSlave", queue, DST_MAC, "perc-tx.pcap", snaplen)
	   elseif i == 2 then
	      local queue = dev:getRxQueue(0)
	      lm.startTask("dumper", queue, "perc-rx.pcap", snaplen)
	   end
	end
	lm.waitForTasks()
end

function txSlave(queue, dstMac, filename, snaplen)
	-- memory pool with default values for all packets, this is our archetype
   -- doesn't actually fille anything but ethSrc, ethDst? pcap packet is empty
	local mempool = memory.createMemPool(function(buf)
		buf:getPerccPacket():fill{
			-- fields not explicitly set here are initialized to reasonable defaults
			ethSrc = nf_mac_map.nf1, -- MAC of the tx device
			ethDst = nf_mac_map.nf0, -- nf1
			perccflowID = 0x1,
			perccisControl = percc.PROTO_PERCC,
			perccleave = 0,
			perccisForward = 1,
			percchopCnt = 0,
			perccbottleneck_id=0xFF,
			perccdemand=0xFFFFFFFF,
			perccinsert_debug=0x0,
			percclabel_0=percc.NEW_FLOW,
			percclabel_1=percc.NEW_FLOW,
			percclabel_2=percc.NEW_FLOW,
			perccalloc_0=0xFFFFFFFF,
			perccalloc_1=0xFFFFFFFF,
			perccalloc_2=0xFFFFFFFF,
			pktLength = PKT_LEN
		}
	end)
	-- a bufArray is just a list of buffers from a mempool that is processed as a single batch
	local bufs = mempool:bufArray()
	local writer = pcap:newWriter(filename)
	local batchNo = 1
	while lm.running() do -- check if Ctrl+c was pressed
		-- this actually allocates some buffers from the mempool the array is associated with
	   -- this has to be repeated for each send because sending is asynchronous, we cannot reuse the old buffers here

	   local batchTime = lm.getTime()
	   bufs:alloc(PKT_LEN)
	   for i, buf in ipairs(bufs) do
	      -- packet framework allows simple access to fields in complex protocol stacks
	      if batchNo < 10 and i == 1 then
		 writer:writeBuf(batchTime, buf, snapLen)
	      end
	   end
	   queue:send(bufs)
	   batchNo = batchNo + 1
	end
	write:close()
end

function dumper(queue, filename, snaplen)
   -- default: show everything
   local writer
   local captureCtr, filterCtr
   writer = pcap:newWriter(filename)
   captureCtr = stats:newPktRxCounter("Capture")
   filterCtr = stats:newPktRxCounter("Filter reject")

   local bufs = memory.bufArray()
   while lm.running() do
      local rx = queue:tryRecv(bufs, 100)
      local batchTime = lm.getTime()
      for i = 1, rx do
	 local buf = bufs[i]
	 if writer then
	    writer:writeBuf(batchTime, buf, snapLen)
	    captureCtr:countPacket(buf)
	 else
	    buf:dump()
	 end -- if write
	 buf:free()
      end -- for i = 1, rx
      if writer then
	 captureCtr:update()
	 filterCtr:update()
      end -- if write
   end -- while lm.running()
   if writer then
      captureCtr:finalize()
      filterCtr:finalize()
      log:info("Flushing buffers, this can take a while...")
      writer:close()
   end -- if writer
end

