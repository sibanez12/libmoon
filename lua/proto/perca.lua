------------------------------------------------------------------------
--- @file perca.lua
--- @brief (perca) utility.
--- Utility functions for the perca_header structs 
--- Includes:
--- - perca constants
--- - perca header utility
--- - Definition of perca packets
------------------------------------------------------------------------

--[[
-- Use this file as template when implementing a new protocol (to implement all mandatory stuff)
-- Replace all occurrences of proto with your protocol (e.g. sctp)
-- Remove unnecessary comments in this file (comments inbetween [[...]]
-- Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - proto/proto.lua: add perca.lua to the list so it gets loaded
--]]
local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader
local bswap = bswap
local ntoh16, hton16 = ntoh16, hton16
---------------------------------------------------------------------------
---- perca constants 
---------------------------------------------------------------------------

--- perca protocol constants
local perca = {}
perca.PROTO_PERCC = 0x1
perca.PROTO_PERCD = 0x0

---------------------------------------------------------------------------
---- perca header
---------------------------------------------------------------------------

perca.headerFormat = [[
	uint32_t	flowID;
        uint8_t         isControl;
	uint32_t	index;
        uint32_t        seqNo;
        uint32_t        ackNo;
]]

--- Variable sized member
perca.headerVariableMember = nil

--- Module for perca_address struct
local percaHeader = initHeader()
percaHeader.__index = percaHeader

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'PERCA constants'. 
local mapNameProto = {
}

--[[ for all members of the header with non-standard data type: set, get, getString 
-- for set also specify a suitable default value
--]]

--- Set the flowID.
--- @param int flowID of the perc header as 32 bit integer.
function percaHeader:setflowID(int)
	int = int or 0
	self.flowID = bswap(int)
end

--- Retrieve the flowID.
--- @return flowID as 32 bit integer.
function percaHeader:getflowID()
	return bswap(self.flowID)
end

--- Retrieve the flowID as string.
--- @return flowID as string.
function percaHeader:getflowIDString()
	return self.flowID
end

--- Set the isControl.
--- @param int isControl of the perca header as 8 bit integer.
function percaHeader:setisControl(int)
	int = int or perca.PROTO_PERCD
	self.isControl = int
end

--- Retrieve the isControl.
--- @return isControl as 8 bit integer.
function percaHeader:getisControl()
	return self.isControl
end

--- Retrieve the isControl as string.
--- @return isControl as string.
function percaHeader:getisControlString()
   local proto = self:getisControl()
   local cleartext = ""
   if proto == perca.PROTO_PERCC then
      cleartext = "(PERC CONTROL)"
   elseif proto == perca.PROTO_PERCD then
      cleartext = "(PERC DATA)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", proto, cleartext)
end

--- Set the seqNo.
--- @param int seqNo of the perca header as 32 bit integer.
function percaHeader:setseqNo(int)
	int = int or 0
	self.seqNo = bswap(int)
end

--- Retrieve the seqNo.
--- @return seqNo as 32 bit integer.
function percaHeader:getseqNo()
	return bswap(self.seqNo)
end

--- Retrieve the seqNo as string.
--- @return seqNo as string.
function percaHeader:getseqNoString()
	return bswap(self.seqNo)
end

--- Set the ackNo.
--- @param int ackNo of the perca header as 32 bit integer.
function percaHeader:setackNo(int)
	int = int or 0
	self.ackNo = bswap(int)
end

--- Retrieve the ackNo.
--- @return ackNo as 32 bit integer.
function percaHeader:getackNo()
	return bswap(self.ackNo)
end

--- Retrieve the ackNo as string.
--- @return ackNo as string.
function percaHeader:getackNoString()
	return bswap(self.ackNo)
end

--- Set the index.
--- @param int index of the perca header as 32 bit integer.
function percaHeader:setindex(int)
	int = int or 0
	self.index = bswap(int)
end

--- Retrieve the index.
--- @return index as 32 bit integer.
function percaHeader:getindex()
	return bswap(self.index)
end

--- Retrieve the index as string.
--- @return index as string.
function percaHeader:getindexString()
	return bswap(self.index)
end

--- Set the seq.
--- @param int seq of the perca header as 16 bit integer.
function percaHeader:setseq(int)
	int = int or 0
	self.seq = hton16(int)
end

--- Retrieve the seq.
--- @return seq as 16 bit integer.
function percaHeader:getseq()
	return hton16(self.seq)
end

--- Retrieve the seq as string.
--- @return seq as string.
function percaHeader:getseqString()
	return hton16(self.seq)
end


--- Set all members of the perca header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: percaXYZ
--- @param pre prefix for namedArgs. Default 'perca'.
--- @code
--- fill() -- only default values
--- fill{ percaXYZ=1 } -- all members are set to default values with the exception of percaXYZ, ...
--- @endcode
function percaHeader:fill(args, pre)
	args = args or {}
	pre = pre or "perca"
	self:setflowID(args[pre .. "flowID"])
	self:setisControl(args[pre .. "isControl"])
	self:setseqNo(args[pre .. "seqNo"])
	self:setackNo(args[pre .. "ackNo"])
	self:setindex(args[pre .. "index"])

end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'perca'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see percaHeader:fill
function percaHeader:get(pre)
	pre = pre or "perca"

	local args = {}
	args[pre .. "flowID"] = self:getflowID() 
	args[pre .. "isControl"] = self:getisControl() 
	args[pre .. "seqNo"] = self:getseqNo() 
	args[pre .. "ackNo"] = self:getackNo() 
	args[pre .. "index"] = self:getindex() 
	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function percaHeader:getString()
	return "Perc_data "
	   .. " flowID " .. self:getflowID()
	   .. " isControl " .. self:getisControlString()
	   .. " index " .. self:getindex() 
	   .. " seqNo " .. self:getseqNo()
	   .. " ackNo " .. self:getAckNo()
end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function percaHeader:resolveNextHeader()
	return nil
end	

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'perca'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see percaHeader:fill
function percaHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

perca.metatype = percaHeader


return perca
