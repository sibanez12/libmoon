--- Barriers to synchronize execution of different tasks
local mod = {}

local ffi = require "ffi"


ffi.cdef [[
    struct array32 { };
    struct array32* make_array32(size_t n, unsigned int init);
    void array32_write(struct array32 *a, unsigned int value, unsigned int index);
    unsigned int array32_read(struct array32 *a, unsigned int index);
]]

local C = ffi.C

local array32 = {}
array32.__index = array32

--- @param n number of tasks
function mod:new(n, init)
    return C.make_array32(n, init)
end

function array32:write(value, index)
    C.array32_write(self, value, index)
end

function array32:read(index)
    return C.array32_read(self, index)
end

ffi.metatype("struct array32", array32)

return mod
