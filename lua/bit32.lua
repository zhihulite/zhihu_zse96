--[==[ bit32 -- compatibility library for Lua 5.4

  Licensed under the MIT License
  Copyright (c) 2021 Andras Horvath

  The MIT License (MIT)
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.


  This library aims to exactly imitate the bit32 standard library of Lua 5.2
  for newer Lua versions in pure Lua code.

  For most situations, it seems to be a bad idea to use this module instead of
  changing code to use the 64-bit bitwise operators of Lua 5.4.

  The module tries to follow the Lua Reference Manual, accessible online at
  http://www.lua.org/manual/5.2/manual.html#6.7

  Particular care was taken to coerce inputs and return values to 32-bit wide integers.

  As the 5.4 Manual states:
  > Unless otherwise stated, all functions accept numeric arguments in the
  > range (-2^51,+2^51); each argument is normalized to the remainder of
  > its division by 2^32 and truncated to an integer (in some unspecified
  > way), so that its final value falls in the range [0,2^32 - 1].
  > Similarly, all results are in the range [0,2^32 - 1]. Note that
  > bit32.bnot(0) is 0xFFFFFFFF, which is different from -1.

]==]



if _VERSION < "Lua 5.4" then
    error("bit32: Need at least Lua 5.4", 2)
end

warn("bit32: Loading backwards compatibility module.",
    "You should adjust your codebase instead.")


---- Local helpers

local MAX_32 = 0xFFFFFFFF
-- local MAX_32<const> = 0xFFFFFFFF -- <const> is a syntax error in Lua 5.3


local function toint(x)
    return tonumber(x) // 1 | 0
end


local function to32(x)
    return toint(x % (2 ^ 32))
end


local function low_mask(width)
    return MAX_32 >> (32 - width)
end


local function foldl(f, init, fst, ...)
    if (fst == nil) then
        return init
    end
    return foldl(f, f(init, fst), ...)
end


local function check_field_width(field, width)
    if field < 0 or field > 31 then
        error("'field' argument out of range [0,31]", 2)
    end
    if width < 0 or width > 31 then
        error("'width' argument out of range [0,31]", 2)
    end
end


---- Module definition

local bit32 = {}

function bit32.arshift(x, disp)
    x = to32(x)
    disp = toint(disp)
    local sign = (x & (1 << 31)) >> 31
    if sign == 0 then
        return to32(x >> disp)
    elseif disp <= 0 then
        return to32(x >> disp)
    elseif disp > 31 then
        return MAX_32
    else
        local fill = to32(MAX_32 << (32 - disp))
        return to32((x >> disp) | fill)
    end
end

function bit32.band(...)
    return foldl(function(x, y) return x & to32(y) end, MAX_32, ...)
end

function bit32.bnot(x)
    return to32(~to32(x))
end

function bit32.bor(...)
    return foldl(function(x, y) return x | to32(y) end, 0, ...)
end

function bit32.btest(...)
    return bit32.band(...) ~= 0
end

function bit32.bxor(...)
    return foldl(function(a, b) return a ~ to32(b) end, 0, ...)
end

function bit32.extract(n, field, width)
    n = to32(n)
    field = to32(field)
    if width == nil then width = 1 else width = to32(width) end
    check_field_width(field, width)

    return (n >> field) & low_mask(width)
end

function bit32.replace(n, v, field, width)
    n = to32(n)
    field = to32(field)
    if width == nil then width = 1 else width = to32(width) end
    check_field_width(field, width)

    v = to32(v) & low_mask(width)
    local mask = ~low_mask(width) << field
    return (v << field) | (n & mask)
end

function bit32.lrotate(x, disp)
    x = to32(x)
    disp = toint(disp) % 32
    if disp == 0 then
        return x
    elseif disp < 0 then
        return bit32.rrotate(x, -disp)
    else
        return to32(x << disp) | to32(x >> (32 - disp))
    end
end

function bit32.lshift(x, disp)
    return to32(to32(x) << toint(disp))
end

function bit32.rrotate(x, disp)
    x = to32(x)
    disp = toint(disp) % 32
    if disp == 0 then
        return x
    elseif disp < 0 then
        return bit32.lrotate(x, -disp)
    else
        return to32(x >> disp) | to32(x << (32 - disp))
    end
end

function bit32.rshift(x, disp)
    return to32(to32(x) >> toint(disp))
end

return bit32
