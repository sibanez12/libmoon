------------------------------------------------------------------------
--- @file percg.lua
--- @brief (percg) utility.
--- Utility functions for the percg_header structs 
--- Includes:
--- - percg constants
--- - percg header utility
--- - Definition of percg packets
------------------------------------------------------------------------

--[[
-- Use this file as template when implementing a new protocol (to implement all mandatory stuff)
-- Replace all occurrences of proto with your protocol (e.g. sctp)
-- Remove unnecessary comments in this file (comments inbetween [[...]]
-- Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - proto/proto.lua: add percg.lua to the list so it gets loaded
--]]
local ffi = require "ffi"
require "proto.template"
local initHeader = initHeader
local bswap = bswap

---------------------------------------------------------------------------
---- percg constants 
---------------------------------------------------------------------------

--- percg protocol constants
local percg = {}
percg.PROTO_PERCC = 0x1
percg.PROTO_PERCD = 0x0


---------------------------------------------------------------------------
---- percg header
---------------------------------------------------------------------------

percg.headerFormat = [[
	uint32_t		flowID;
        uint8_t                 isControl;
]]

--- Variable sized member
percg.headerVariableMember = nil

--- Module for percg_address struct
local percgHeader = initHeader()
percgHeader.__index = percgHeader

-- Maps headers to respective protocol value.
-- This list should be extended whenever a new protocol is added to 'PERCG constants'. 
local mapNameProto = {
	percc = percg.PROTO_PERCC,
	percd = percg.PROTO_PERCD,
}

--[[ for all members of the header with non-standard data type: set, get, getString 
-- for set also specify a suitable default value
--]]

--- Set the flowID.
--- @param int flowID of the percg header as 32 bit integer.
function percgHeader:setflowID(int)
	int = int or 0
	self.flowID = bswap(int)
end

--- Retrieve the flowID.
--- @return flowID as 32 bit integer.
function percgHeader:getflowID()
	return bswap(self.flowID)
end

--- Retrieve the flowID as string.
--- @return flowID as string.
function percgHeader:getflowIDString()
	return self.flowID
end


--- Set the isControl.
--- @param int isControl of the percg header as 8 bit integer.
function percgHeader:setisControl(int)
	int = int or percg.PROTO_PERCC
	self.isControl = int
end

--- Retrieve the isControl.
--- @return isControl as 8 bit integer.
function percgHeader:getisControl()
	return self.isControl
end

--- Retrieve the isControl as string.
--- @return isControl as string.
function percgHeader:getisControlString()
   local proto = self:getisControl()
   local cleartext = ""
   if proto == percg.PROTO_PERCC then
      cleartext = "(PERC CONTROL)"
   elseif proto == percg.PROTO_PERCD then
      cleartext = "(PERC DATA)"
   else
      cleartext = "(unknown)"
   end

   return format("0x%02x %s", proto, cleartext)
end

--- Set all members of the percg header.
--- Per default, all members are set to default values specified in the respective set function.
--- Optional named arguments can be used to set a member to a user-provided value.
--- @param args Table of named arguments. Available arguments: percgXYZ
--- @param pre prefix for namedArgs. Default 'percg'.
--- @code
--- fill() -- only default values
--- fill{ percgXYZ=1 } -- all members are set to default values with the exception of percgXYZ, ...
--- @endcode
function percgHeader:fill(args, pre)
	args = args or {}
	pre = pre or "percg"

	self:setflowID(args[pre .. "flowID"])
	self:setisControl(args[pre .. "isControl"])
end

--- Retrieve the values of all members.
--- @param pre prefix for namedArgs. Default 'percg'.
--- @return Table of named arguments. For a list of arguments see "See also".
--- @see percgHeader:fill
function percgHeader:get(pre)
	pre = pre or ""

	local args = {}
	args[pre .. "flowID"] = self:getflowID() 
	args[pre .. "isControl"] = self:getisControl() 

	return args
end

--- Retrieve the values of all members.
--- @return Values in string format.
function percgHeader:getString()
	return "Perc_generic flowID " .. self:getflowIDString() .. " isControl " .. self:getisControlString()
end

--- Resolve which header comes after this one (in a packet)
--- For instance: in tcp/udp based on the ports
--- This function must exist and is only used when get/dump is executed on 
--- an unknown (mbuf not yet casted to e.g. tcpv6 packet) packet (mbuf)
--- @return String next header (e.g. 'eth', 'ip4', nil)
function percgHeader:resolveNextHeader()
	local proto = self:getisControl()
	for name, _proto in pairs(mapNameProto) do
		if proto == _proto then
			return name
		end
	end
	return nil
end	

--- Change the default values for namedArguments (for fill/get)
--- This can be used to for instance calculate a length value based on the total packet length
--- See proto/ip4.setDefaultNamedArgs as an example
--- This function must exist and is only used by packet.fill
--- @param pre The prefix used for the namedArgs, e.g. 'percg'
--- @param namedArgs Table of named arguments (see See more)
--- @param nextHeader The header following after this header in a packet
--- @param accumulatedLength The so far accumulated length for previous headers in a packet
--- @return Table of namedArgs
--- @see percgHeader:fill
function percgHeader:setDefaultNamedArgs(pre, namedArgs, nextHeader, accumulatedLength)
	return namedArgs
end


------------------------------------------------------------------------
---- Metatypes
------------------------------------------------------------------------

percg.metatype = percgHeader


return percg
