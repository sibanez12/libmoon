------------------------------------------------------------------------
--- @file percd.lua
--- @brief (percd) utility.
--- Utility functions for the percd_header structs 
--- Includes:
--- - percd constants
--- - percd header utility
--- - Definition of percd packets
------------------------------------------------------------------------

--[[
-- Use this file as template when implementing a new protocol (to implement all mandatory stuff)
-- Replace all occurrences of proto with your protocol (e.g. sctp)
-- Remove unnecessary comments in this file (comments inbetween [[...]]
-- Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - proto/proto.lua: add percd.lua to the list so it gets loaded
--]]
local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader
local bswap = bswap
local ntoh16, hton16 = ntoh16, hton16
---------------------------------------------------------------------------
---- percd constants 
---------------------------------------------------------------------------

--- percd protocol constants
local percd = {}
percd.PROTO_PERCC = 0x1
percd.PROTO_PERCD = 0x0

---------------------------------------------------------------------------
---- percd header
---------------------------------------------------------------------------

percd.headerFormat = [[
	uint32_t	flowID;
        uint8_t         isControl;
	uint32_t		index;
        uint32_t                seqNo;
        uint32_t                ackNo;
]]

--- Variable sized member
percd.headerVariableMember = nil

--- Module for percd_address struct
local percdHeader = initHeader()
percdHeader.__index = percdHeader

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'PERCD constants'. 
local mapNameProto = {
}

--[[ for all members of the header with non-standard data type: set, get, getString 
-- for set also specify a suitable default value
--]]

--- Set the flowID.
--- @param int flowID of the perc header as 32 bit integer.
function percdHeader:setflowID(int)
	int = int or 0
	self.flowID = bswap(int)
end

--- Retrieve the flowID.
--- @return flowID as 32 bit integer.
function percdHeader:getflowID()
	return bswap(self.flowID)
end

--- Retrieve the flowID as string.
--- @return flowID as string.
function percdHeader:getflowIDString()
	return self.flowID
end

--- Set the isControl.
--- @param int isControl of the percd header as 8 bit integer.
function percdHeader:setisControl(int)
	int = int or percd.PROTO_PERCC
	self.isControl = int
end

--- Retrieve the isControl.
--- @return isControl as 8 bit integer.
function percdHeader:getisControl()
	return self.isControl
end

--- Retrieve the isControl as string.
--- @return isControl as string.
function percdHeader:getisControlString()
   local proto = self:getisControl()
   local cleartext = ""
   if proto == percd.PROTO_PERCC then
      cleartext = "(PERC CONTROL)"
   elseif proto == percd.PROTO_PERCD then
      cleartext = "(PERC DATA)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", proto, cleartext)
end

--- Set the seqNo.
--- @param int seqNo of the percd header as 32 bit integer.
function percdHeader:setseqNo(int)
	int = int or 0
	self.seqNo = bswap(int)
end

--- Retrieve the seqNo.
--- @return seqNo as 32 bit integer.
function percdHeader:getseqNo()
	return bswap(self.seqNo)
end

--- Retrieve the seqNo as string.
--- @return seqNo as string.
function percdHeader:getseqNoString()
	return bswap(self.seqNo)
end

--- Set the ackNo.
--- @param int ackNo of the percd header as 32 bit integer.
function percdHeader:setackNo(int)
	int = int or 0
	self.ackNo = bswap(int)
end

--- Retrieve the ackNo.
--- @return ackNo as 32 bit integer.
function percdHeader:getackNo()
	return bswap(self.ackNo)
end

--- Retrieve the ackNo as string.
--- @return ackNo as string.
function percdHeader:getackNoString()
	return bswap(self.ackNo)
end

--- Set the index.
--- @param int index of the percd header as 32 bit integer.
function percdHeader:setindex(int)
	int = int or 0
	self.index = bswap(int)
end

--- Retrieve the index.
--- @return index as 32 bit integer.
function percdHeader:getindex()
	return bswap(self.index)
end

--- Retrieve the index as string.
--- @return index as string.
function percdHeader:getindexString()
	return bswap(self.index)
end

--- Set the seq.
--- @param int seq of the percd header as 16 bit integer.
function percdHeader:setseq(int)
	int = int or 0
	self.seq = hton16(int)
end

--- Retrieve the seq.
--- @return seq as 16 bit integer.
function percdHeader:getseq()
	return hton16(self.seq)
end

--- Retrieve the seq as string.
--- @return seq as string.
function percdHeader:getseqString()
	return hton16(self.seq)
end


--- Set all members of the percd header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: percdXYZ
--- @param pre prefix for namedArgs. Default 'percd'.
--- @code
--- fill() -- only default values
--- fill{ percdXYZ=1 } -- all members are set to default values with the exception of percdXYZ, ...
--- @endcode
function percdHeader:fill(args, pre)
	args = args or {}
	pre = pre or "percd"
	self:setflowID(args[pre .. "flowID"])
	self:setisControl(args[pre .. "isControl"])
	self:setseqNo(args[pre .. "seqNo"])
	self:setackNo(args[pre .. "ackNo"])
	self:setindex(args[pre .. "index"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'percd'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see percdHeader:fill
function percdHeader:get(pre)
	pre = pre or "percd"

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
function percdHeader:getString()
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
function percdHeader:resolveNextHeader()
	return nil
end	

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'percd'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see percdHeader:fill
function percdHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

percd.metatype = percdHeader


return percd
