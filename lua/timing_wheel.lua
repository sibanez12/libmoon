--- Barriers to synchronize execution of different tasks
local mod = {}

local ffi = require "ffi"


ffi.cdef [[
    struct timing_wheel { };
    struct timing_wheel* make_timing_wheel(size_t n);
    unsigned int timing_wheel_remove_and_tick(struct timing_wheel* a);

    unsigned int timing_wheel_insert(struct timing_wheel *a, unsigned int value, unsigned int index);
    unsigned int timing_wheel_peek(struct timing_wheel *a, unsigned int index);
]]

local C = ffi.C

local timing_wheel = {}
timing_wheel.__index = timing_wheel

--- @param n number of slots
function mod:new(n)
    return C.make_timing_wheel(n)
end

function timing_wheel:remove_and_tick()
    return C.timing_wheel_remove_and_tick(self)
end

--- @param index number of slots from present to insert value at
--- returns 0 if value was inserted at specified slot
--- returns 0 < i < n if there was no room and value was pushed an extra i slots into the future 
--- returns n if i if value can't be inserted in the timing wheel horizon
function timing_wheel:insert(value, index)
    return C.timing_wheel_insert(self, value, index)
end

function timing_wheel:peek(index)
    return C.timing_wheel_peek(self, index)
end

ffi.metatype("struct timing_wheel", timing_wheel)

return mod
