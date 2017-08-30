--- Array of 64 bit unsigned integers
local mod = {}

local ffi = require "ffi"


ffi.cdef [[
    struct array64 { };
    struct array64* make_array64(size_t n, uint64_t init);
    void array64_write(struct array64 *a, uint64_t value, uint64_t index);
    uint64_t array64_read(struct array64 *a, uint64_t index);
]]

local C = ffi.C

local array64 = {}
array64.__index = array64

--- @param n number of tasks
function mod:new(n, init)
    return C.make_array64(n, init)
end

function array64:write(value, index)
    C.array64_write(self, value, index)
end

function array64:read(index)
    return C.array64_read(self, index)
end

ffi.metatype("struct array64", array64)

return mod
