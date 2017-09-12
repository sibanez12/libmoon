------------------------------------------------------------------------
--- @file percc.lua
--- @brief (percc) utility.
--- Utility functions for the percc_header structs 
--- Includes:
--- - percc constants
--- - percc header utility
--- - Definition of percc packets
------------------------------------------------------------------------

--[[
-- Use this file as template when implementing a new protocol (to implement all mandatory stuff)
-- Replace all occurrences of proto with your protocol (e.g. sctp)
-- Remove unnecessary comments in this file (comments inbetween [[...]]
-- Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - proto/proto.lua: add percc.lua to the list so it gets loaded
--]]
require "utils"
local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader

---------------------------------------------------------------------------
---- percc constants 
---------------------------------------------------------------------------

--- percc protocol constants
local percc = {}
percc.LABEL_INACTIVE = 0x0
percc.LABEL_SAT = 0x1
percc.LABEL_UNSAT = 0x2
percc.LABEL_NEW_FLOW = 0x3

---------------------------------------------------------------------------
---- percc header
---------------------------------------------------------------------------

percc.headerFormat = [[
	uint32_t	flowID;
	uint8_t		leave;
        uint8_t         isForward;
        uint8_t         hopCnt;
        uint8_t         bottleneck_id;
        uint32_t         demand;
        uint8_t         insert_debug;
        uint64_t        timestamp;
        uint8_t         label_0;
        uint8_t         label_1;
        uint8_t         label_2;
        uint32_t        alloc_0;
        uint32_t        alloc_1;
        uint32_t        alloc_2;
        uint32_t        linkCap;
        uint32_t        sumSatAdj;
        uint32_t        numFlowsAdj;
        uint32_t        numSatAdj;
        uint32_t        newMaxSat;
        uint32_t        R;
        uint32_t        index;
]]

--- Variable sized member
percc.headerVariableMember = nil

--- Module for percc_address struct
local perccHeader = initHeader()
perccHeader.__index = perccHeader

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'IPv4 constants'. 
local mapNameProto = {
}

--[[ for all members of the header with non-standard data type: set, get, getString 
-- for set also specify a suitable default value
--]]

--- Set the flowID.
--- @param int flowID of the perc header as 32 bit integer.
function perccHeader:setflowID(int)
	int = int or 0
	self.flowID = bswap(int)
end

--- Retrieve the flowID.
--- @return flowID as 32 bit integer.
function perccHeader:getflowID()
	return bswap(self.flowID)
end

--- Retrieve the flowID as string.
--- @return flowID as string.
function perccHeader:getflowIDString()
	return self.flowID
end

--- Set the leave.
--- @param int leave of the percc header as 8 bit integer.
function perccHeader:setleave(int)
	int = int or 0
	self.leave = int
end

--- Retrieve the leave.
--- @return leave as 8 bit integer.
function perccHeader:getleave()
	return self.leave
end

--- Retrieve the leave as string.
--- @return leave as string.
function perccHeader:getleaveString()
	return self.leave
end

--- Set the isForward.
--- @param int isForward of the percc header as 8 bit integer.
function perccHeader:setisForward(int)
	int = int or 0x1
	self.isForward = int
end

--- Retrieve the isForward.
--- @return isForward as 8 bit integer.
function perccHeader:getisForward()
	return self.isForward
end

--- Retrieve the isForward as string.
--- @return isForward as string.
function perccHeader:getisForwardString()
	return self.isForward
end


--- Set the hopCnt.
--- @param int hopCnt of the percc header as 8 bit integer.
function perccHeader:sethopCnt(int)
	int = int or 0
	self.hopCnt = int
end

--- Retrieve the hopCnt.
--- @return hopCnt as 8 bit integer.
function perccHeader:gethopCnt()
	return self.hopCnt
end

--- Retrieve the hopCnt as string.
--- @return hopCnt as string.
function perccHeader:gethopCntString()
	return self.hopCnt
end

--- Set the bottleneck_id.
--- @param int bottleneck_id of the percc header as 8 bit integer.
function perccHeader:setbottleneck_id(int)
	int = int or 0xFF
	self.bottleneck_id = int
end

--- Retrieve the bottleneck_id.
--- @return bottleneck_id as 8 bit integer.
function perccHeader:getbottleneck_id()
	return self.bottleneck_id
end

--- Retrieve the bottleneck_id as string.
--- @return bottleneck_id as string.
function perccHeader:getbottleneck_idString()
	return self.bottleneck_id
end

--- Set the demand.
--- @param int demand of the percc header as 32 bit integer.
function perccHeader:setdemand(int)
	int = int or 0xFFFFFFFF
	self.demand = bswap(int)
end

--- Retrieve the demand.
--- @return demand as 32 bit integer.
function perccHeader:getdemand()
	return tonumber(bit.band(bswap(self.demand), 0xFFFFFFFFULL))
end

--- Retrieve the demand as string.
--- @return demand as string.
function perccHeader:getdemandString()
	return bswap(self.demand)
end

--- Set the insert_debug.
--- @param int insert_debug of the percc header as 8 bit integer.
function perccHeader:setinsert_debug(int)
	int = int or 0
	self.insert_debug = int
end

--- Retrieve the insert_debug.
--- @return insert_debug as 8 bit integer.
function perccHeader:getinsert_debug()
	return self.insert_debug
end

--- Retrieve the insert_debug as string.
--- @return insert_debug as string.
function perccHeader:getinsert_debugString()
	return self.insert_debug
end

--- Set the timestamp.
--- @param int timestamp of the percc header as 64 bit integer.
function perccHeader:settimestamp(int)
	int = int or 0
	self.timestamp = bswap(int)
end

--- Retrieve the timestamp.
--- @return timestamp as 64 bit integer.
function perccHeader:gettimestamp()
	return bswap(self.timestamp)
end

--- Retrieve the timestamp as string.
--- @return timestamp as string.
function perccHeader:gettimestampString()
	return bswap(self.timestamp)
end

--- Set the label_0.
--- @param int label_0 of the percc header as 8 bit integer.
function perccHeader:setlabel_0(int)
	int = int or percc.LABEL_NEW_FLOW
	self.label_0 = int
end

--- Retrieve the label_0.
--- @return label_0 as 8 bit integer.
function perccHeader:getlabel_0()
	return self.label_0
end

--- Retrieve the label_0 as string.
--- @return label_0 as string.
function perccHeader:getlabel_0String()
   local label = self:getlabel_0()
   local cleartext = ""
   if label == percc.LABEL_INACTIVE then
      cleartext = "(LABEL INACTIVE)"
   elseif label == percc.LABEL_SAT then
      cleartext = "(LABEL SAT)"
   elseif label == percc.LABEL_UNSAT then
      cleartext = "(LABEL UNSAT)"
   elseif label == percc.LABEL_NEW_FLOW then
      cleartext = "(LABEL NEW_FLOW)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", label, cleartext)
end

--- Set the label_1.
--- @param int label_1 of the percc header as 8 bit integer.
function perccHeader:setlabel_1(int)
	int = int or percc.LABEL_NEW_FLOW
	self.label_1 = int
end

--- Retrieve the label_1.
--- @return label_1 as 8 bit integer.
function perccHeader:getlabel_1()
	return self.label_1
end

--- Retrieve the label_1 as string.
--- @return label_1 as string.
function perccHeader:getlabel_1String()
   local label = self:getlabel_1()
   local cleartext = ""
   if label == percc.LABEL_INACTIVE then
      cleartext = "(LABEL INACTIVE)"
   elseif label == percc.LABEL_SAT then
      cleartext = "(LABEL SAT)"
   elseif label == percc.LABEL_UNSAT then
      cleartext = "(LABEL UNSAT)"
   elseif label == percc.LABEL_NEW_FLOW then
      cleartext = "(LABEL NEW_FLOW)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", label, cleartext)
end

--- Set the label_2.
--- @param int label_2 of the percc header as 8 bit integer.
function perccHeader:setlabel_2(int)
	int = int or percc.LABEL_NEW_FLOW
	self.label_2 = int
end

--- Retrieve the label_2.
--- @return label_2 as 8 bit integer.
function perccHeader:getlabel_2()
	return self.label_2
end

--- Retrieve the label_2 as string.
--- @return label_2 as string.
function perccHeader:getlabel_2String()
   local label = self:getlabel_2()
   local cleartext = ""
   if label == percc.LABEL_INACTIVE then
      cleartext = "(LABEL INACTIVE)"
   elseif label == percc.LABEL_SAT then
      cleartext = "(LABEL SAT)"
   elseif label == percc.LABEL_UNSAT then
      cleartext = "(LABEL UNSAT)"
   elseif label == percc.LABEL_NEW_FLOW then
      cleartext = "(LABEL NEW_FLOW)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", label, cleartext)
end

-- Usually host should not be modifying any of the following fields
-- So we don't bother to convert between host and network byte order (bswap)
--- Set the alloc_0.
--- @param int alloc_0 of the percc header as 32 bit integer.
function perccHeader:setalloc_0(int)
	int = int or 0xFFFFFFFF
	self.alloc_0 = int
end

--- Retrieve the alloc_0.
--- @return alloc_0 as 32 bit integer.
function perccHeader:getalloc_0()
	return self.alloc_0
end

--- Retrieve the alloc_0 as string.
--- @return alloc_0 as string.
function perccHeader:getalloc_0String()
	return self.alloc_0
end

--- Set the alloc_1.
--- @param int alloc_1 of the percc header as 32 bit integer.
function perccHeader:setalloc_1(int)
	int = int or 0xFFFFFFFF
	self.alloc_1 = int
end

--- Retrieve the alloc_1.
--- @return alloc_1 as 32 bit integer.
function perccHeader:getalloc_1()
	return self.alloc_1
end

--- Retrieve the alloc_1 as string.
--- @return alloc_1 as string.
function perccHeader:getalloc_1String()
	return self.alloc_1
end

--- Set the alloc_2.
--- @param int alloc_2 of the percc header as 32 bit integer.
function perccHeader:setalloc_2(int)
	int = int or 0xFFFFFFFF
	self.alloc_2 = int
end

--- Retrieve the alloc_2.
--- @return alloc_2 as 32 bit integer.
function perccHeader:getalloc_2()
	return self.alloc_2
end

--- Retrieve the alloc_2 as string.
--- @return alloc_2 as string.
function perccHeader:getalloc_2String()
	return self.alloc_2
end


--- Set the linkCap.
--- @param int linkCap of the percc header as 32 bit integer.
function perccHeader:setlinkCap(int)
	int = int or 0
	self.linkCap = int
end

--- Retrieve the linkCap.
--- @return linkCap as 32 bit integer.
function perccHeader:getlinkCap()
	return self.linkCap
end

--- Retrieve the linkCap as string.
--- @return linkCap as string.
function perccHeader:getlinkCapString()
	return self.linkCap
end


--- Set the sumSatAdj.
--- @param int sumSatAdj of the percc header as 32 bit integer.
function perccHeader:setsumSatAdj(int)
	int = int or 0
	self.sumSatAdj = int
end

--- Retrieve the sumSatAdj.
--- @return sumSatAdj as 32 bit integer.
function perccHeader:getsumSatAdj()
	return self.sumSatAdj
end

--- Retrieve the sumSatAdj as string.
--- @return sumSatAdj as string.
function perccHeader:getsumSatAdjString()
	return self.sumSatAdj
end


--- Set the numFlowsAdj.
--- @param int numFlowsAdj of the percc header as 32 bit integer.
function perccHeader:setnumFlowsAdj(int)
	int = int or 0
	self.numFlowsAdj = int
end

--- Retrieve the numFlowsAdj.
--- @return numFlowsAdj as 32 bit integer.
function perccHeader:getnumFlowsAdj()
	return self.numFlowsAdj
end

--- Retrieve the numFlowsAdj as string.
--- @return numFlowsAdj as string.
function perccHeader:getnumFlowsAdjString()
	return self.numFlowsAdj
end


--- Set the numSatAdj.
--- @param int numSatAdj of the percc header as 32 bit integer.
function perccHeader:setnumSatAdj(int)
	int = int or 0
	self.numSatAdj = int
end

--- Retrieve the numSatAdj.
--- @return numSatAdj as 32 bit integer.
function perccHeader:getnumSatAdj()
	return self.numSatAdj
end

--- Retrieve the numSatAdj as string.
--- @return numSatAdj as string.
function perccHeader:getnumSatAdjString()
	return self.numSatAdj
end


--- Set the newMaxSat.
--- @param int newMaxSat of the percc header as 32 bit integer.
function perccHeader:setnewMaxSat(int)
	int = int or 0
	self.newMaxSat = int
end

--- Retrieve the newMaxSat.
--- @return newMaxSat as 32 bit integer.
function perccHeader:getnewMaxSat()
	return self.newMaxSat
end

--- Retrieve the newMaxSat as string.
--- @return newMaxSat as string.
function perccHeader:getnewMaxSatString()
	return self.newMaxSat
end


--- Set the R.
--- @param int R of the percc header as 32 bit integer.
function perccHeader:setR(int)
	int = int or 0
	self.R = int
end

--- Retrieve the R.
--- @return R as 32 bit integer.
function perccHeader:getR()
	return self.R
end

--- Retrieve the R as string.
--- @return R as string.
function perccHeader:getRString()
	return self.R
end

--- Set the index.
--- @param int index of the percc header as 32 bit integer.
function perccHeader:setindex(int)
	int = int or 0
	self.index = bswap(int)
end

--- Retrieve the index.
--- @return index as 32 bit integer.
function perccHeader:getindex()
	return bswap(self.index)
end

--- Retrieve the index as string.
--- @return index as string.
function perccHeader:getindexString()
	return bswap(self.index)
end


--- Set all members of the percc header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: perccXYZ
--- @param pre prefix for namedArgs. Default 'percc'.
--- @code
--- fill() -- only default values
--- fill{ perccXYZ=1 } -- all members are set to default values with the exception of perccXYZ, ...
--- @endcode
function perccHeader:fill(args, pre)
	args = args or {}
	pre = pre or "percc"
	self:setflowID(args[pre .. "flowID"])
	self:setleave(args[pre .. "leave"])
	self:setisForward(args[pre .. "isForward"])
	self:sethopCnt(args[pre .. "hopCnt"])
	self:setbottleneck_id(args[pre .. "bottleneck_id"])
	self:setdemand(args[pre .. "demand"])
	self:setinsert_debug(args[pre .. "insert_debug"])
	self:settimestamp(args[pre .. "timestamp"])
	self:setlabel_0(args[pre .. "label_0"])
	self:setlabel_1(args[pre .. "label_1"])
	self:setlabel_2(args[pre .. "label_2"])
	self:setalloc_0(args[pre .. "alloc_0"])
	self:setalloc_1(args[pre .. "alloc_1"])
	self:setalloc_2(args[pre .. "alloc_2"])
	self:setlinkCap(args[pre .. "linkCap"])
	self:setsumSatAdj(args[pre .. "sumSatAdj"])
	self:setnumFlowsAdj(args[pre .. "numFlowsAdj"])
	self:setnumSatAdj(args[pre .. "numSatAdj"])
	self:setnewMaxSat(args[pre .. "newMaxSat"])
	self:setR(args[pre .. "R"])
	self:setindex(args[pre .. "index"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'percc'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see perccHeader:fill
function perccHeader:get(pre)
	pre = pre or "percc"

	local args = {}
	args[pre .. "flowID"] = self:getflowID() 
	args[pre .. "leave"] = self:getleave() 
	args[pre .. "isForward"] = self:getisForward() 
	args[pre .. "hopCnt"] = self:gethopCnt() 
	args[pre .. "bottleneck_id"] = self:getbottleneck_id() 
	args[pre .. "demand"] = self:getdemand() 
	args[pre .. "insert_debug"] = self:getinsert_debug() 
	args[pre .. "timestamp"] = self:gettimestamp() 
	args[pre .. "label_0"] = self:getlabel_0() 
	args[pre .. "label_1"] = self:getlabel_1() 
	args[pre .. "label_2"] = self:getlabel_2() 
	args[pre .. "alloc_0"] = self:getalloc_0() 
	args[pre .. "alloc_1"] = self:getalloc_1() 
	args[pre .. "alloc_2"] = self:getalloc_2() 
	args[pre .. "linkCap"] = self:getlinkCap() 
	args[pre .. "sumSatAdj"] = self:getsumSatAdj() 
	args[pre .. "numFlowsAdj"] = self:getnumFlowsAdj() 
	args[pre .. "numSatAdj"] = self:getnumSatAdj()
	args[pre .. "newMaxSat"] = self:getnewMaxSat() 
	args[pre .. "R"] = self:getR() 
	args[pre .. "index"] = self:getindex() 
	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function perccHeader:getString()
	return "Perc_control "
	   .. " flowID " .. self:getflowID()
	   .. " index " .. self:getindex() 
	   .. " leave " .. self:getleaveString() 
	   .. " isForward " .. self:getisForward()
	   .. " hopCnt " .. self:gethopCnt()
	   .. " bottleneck_id " .. self:getbottleneck_id()
	   .. " demand " .. self:getdemand()
	   .. " insert_debug " .. self:getinsert_debug()
	   .. " timestamp " .. self:gettimestamp()
	   .. " label_0 " .. self:getlabel_0()
	   .. " label_1 " .. self:getlabel_1()
	   .. " label_2 " .. self:getlabel_2()
	   .. " alloc_0 " .. self:getalloc_0()
	   .. " alloc_1 " .. self:getalloc_1()
	   .. " alloc_2 " .. self:getalloc_2()

end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function perccHeader:resolveNextHeader()
	return nil
end	

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'percc'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see perccHeader:fill
function perccHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

percc.metatype = perccHeader


return percc
