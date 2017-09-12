--- A simple TCP packet generator
local lm     = require "libmoon"
local device = require "device"
local stats  = require "stats"
local log    = require "log"
local memory = require "memory"
local arp    = require "proto.arp"
local timer  = require "timer"
local filter = require "filter"
local perc = require "perc"
local eth = require "proto.ethernet"
local perca = require "proto.perca"
local percc = require "proto.percc"
local percd = require "proto.percd"
local barrier = require "barrier"
local pcap   = require "pcap"

local nf_macno_map = {}
nf_macno_map["nf0"] = 8869393797384 -- "08:11:11:11:11:08"
nf_macno_map["nf1"] = 8942694572552 -- "08:22:22:22:22:08"
nf_macno_map["nf2"] = 9015995347720 -- "08:33:33:33:33:08"
nf_macno_map["nf3"] = 9089296122888 -- "08:44:44:44:44:08"

-- ip4: ether/ 28B IP header/ 16b src port/ 16b dst port
-- percd: ether/ 5B Perc Generic/ 12B Perc Data
-- perc: ether/ 5B Generic/ 56B Perc Control


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
    parser:option("-d --dstMac", "Destination MAC address to use for the flows to start up"):default("08:11:11:11:11:08")
    parser:option("-s --srcMac", "Source MAC address to use for the flows"):default("08:22:22:22:22:08")
    parser:option("-n --numFlows", "The number of flows to start up"):args(1):convert(tonumber):default(3)
    parser:option("-t --time", "The amount of time for which to send pkts for the flows (sec)"):args(1):convert(tonumber):default(0.01)
    parser:option("-o --offset", "The offset to use to compute flowID values (must be greater than 0)"):args(1):convert(tonumber):default(1)
    parser:option("-w --wait", "Wait this many seconds before sending init ctrl pkts"):args(1):convert(tonumber):default(3)
    parser:option("-f --file", "File to write logged packets into."):default("log.pcap")
    parser:option("-l --snap-len", "Truncate packets to this size."):convert(tonumber):target("snapLen"):default(2048)
    parser:option("-c --cores", "Number of threads to use for logging / writing pcap traces.."):convert(tonumber):default(1)
    return parser:parse()
end

function master(args,...)
    log:info("using dst mac = %s", args.dstMac)
--    log:info("using dst mac = %x", tonumber(args.dstMac))
    for i, dev in ipairs(args.dev) do
       local dvc
       if i == 1 then
           -- runs the perc application
           dvc = device.config{
               port = dev,
               txQueues = 4,
               rxQueues = 3
           }
       else
           -- used for logging pkts
           dvc = device.config{
                     port = dev,
                     txQueues = 1,
                     rxQueues = args.cores,
                     rssQueues = args.cores 
           }
       end
       args.dev[i] = dvc
    end
    device.waitForLinks()

    -- print statistics
    stats.startStatsTask{devices = args.dev}

    local dataQ = 0
    local controlQ = 1
    local ackQ = 2

    -- configure tx rates and start transmit slaves
    for i, dev in ipairs(args.dev) do
        if i == 1 then
            local wl = perc.genWorkload(args.dstMac, args.srcMac, args.numFlows, args.time, args.offset, args.wait)
            local dataTxQueue = dev:getTxQueue(dataQ)	 
            dataTxQueue:setRate(8000)
            local ackRxQueue = dev:getRxQueue(ackQ)
            local af = dev:l2Filter(eth.TYPE_PERC_ACK, ackRxQueue)
            local controlRxQueue = dev:getRxQueue(controlQ)
            local cf = dev:l2Filter(eth.TYPE_PERC, controlRxQueue)
            local controlTxQueue = dev:getTxQueue(controlQ)
            local controlTxQueueExtra = dev:getTxQueue(3)
            controlTxQueue:setRate(1000)
            lm.startTask("dataSenderTask", wl, dataTxQueue, ackRxQueue, controlTxQueue, controlRxQueue, controlTxQueueExtra)
        else
            for i = 1, args.cores do
                lm.startTask("dumper", dev:getRxQueue(i - 1), args, i)
            end
        end
    end
    
    lm.waitForTasks()
end

function dataSenderTask(wl, dataTxQueue, ackRxQueue, controlTxQueue, controlRxQueue,
			controlTxQueueExtra)
   -- this thread sends and receives control packets and sends data packets

   local control_rx_bufs = memory.bufArray()

   -- for sending new control packets
   local control_mempool = perc.createCtrlMemPool()
   local control_bufs = control_mempool:bufArray(CONTROL_BATCH_SIZE)

   -- for sending data packets
   local data_mempool = perc.createDataMemPool()
   local data_bufs = data_mempool:bufArray(DATA_BATCH_SIZE)

   -- initialize all the flows to start at the same time
   -- so alloc resources on the shared_xx arrays (common_index)
   -- and on the timing wheel
   local control_tw = timing_wheel:new(MAX_FLOWS)
   for i, flow_id in ipairs(wl.flow_id) do
       control_tw:insert(flow_id, i-1)
   end

   local data_ipg = {}
   local flow_seqNo = {}
   local data_tw = timing_wheel:new(TIMING_WHEEL_NUM_SLOTS)
   for i, flow_id in ipairs(wl.flow_id) do
       -- initialize inter packet gap table
--       data_ipg[flow_id] = INIT_GAP
       -- initialize seqNos
       flow_seqNo[flow_id] = 0
   end

   init_ctrl_pkts_sent = 0
   log:info("dataSender about to start %d flows", wl.num_flows)

   local last_lm_time = lm.getTime()
   local start_time = last_lm_time + 1
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
         perc.sendInitCtrlPkts(control_bufs, control_tw, wl, controlTxQueue)
         init_ctrl_pkts_sent = 1
      end

      -- reflect control packets
      local num_ctrl_rcvd = controlRxQueue:tryRecv(control_rx_bufs, CONTROL_RX_WAIT)
      perc.reflectCtrlPkts(num_ctrl_rcvd, control_rx_bufs, controlTxQueueExtra, start_time, wl, data_ipg, data_tw)

      perc.sendDataPkts(data_bufs, dataTxQueue, wl, flow_seqNo, data_tw, data_ipg, start_time)
   end

end

function dumper(queue, args, threadId)
    local snapLen = args.snapLen
    local writer
    local captureCtr, filterCtr
    if args.file then
        if args.cores > 1 then
            if args.file:match("%.pcap$") then
                args.file = args.file:gsub("%.pcap$", "")
            end
            args.file = args.file .. "-thread-" .. threadId .. ".pcap"
        else
            if not args.file:match("%.pcap$") then
                args.file = args.file .. ".pcap"
            end
        end
        writer = pcap:newWriter(args.file)
        captureCtr = stats:newPktRxCounter("Capture, thread #" .. threadId)
    end
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
            end
            buf:free()
        end
        if writer then
            captureCtr:update()
        end
    end
    if writer then
        captureCtr:finalize()
        log:info("Flushing buffers, this can take a while...")
        writer:close()
    end
end

