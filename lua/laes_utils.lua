-- LAESUtils lua版本
-- 基于自定义 AES 算法的加密/解密工具类
-- 作者: huajiqaq
-- 日期: 2025-07-29

--
-- 注意事项:
-- 1. 由于Lua原生不支持大整数运算，本版本直接使用十六进制字符串操作，与其他语言版本不同，不采用 hex -> number -> 运算 -> number -> hex 的流程，所有加密运算基于字符串级别的十六进制操作实现。
-- 2. Lua数组索引从1开始，代码中已相应调整，代码结构和可读性可能与其他语言版本存在差异。
-- 3. 位运算需要 Lua 5.3+ (使用 ~, &, |, <<, >>) 或通过 `bit`/`bit32` 库实现。
--


local LAESUtils = {}
LAESUtils.__index = LAESUtils
local base64 = require "base64"

-- 构造函数
function LAESUtils.new(encryptConf, decryptConf, isDebug)
    local self = setmetatable({}, LAESUtils)
    self.encryptConf = encryptConf
    self.decryptConf = decryptConf
    self.isDebug = isDebug or false
    return self
end

-- 获取加密配置
function LAESUtils:getEncryptConf()
    return self.encryptConf
end

-- 获取解密配置
function LAESUtils:getDecryptConf()
    return self.decryptConf
end

-- 调试日志输出
function LAESUtils:logDebug(message)
    if self.isDebug then
        print(message)
    end
end

-- 十六进制字符串转字节数组
function LAESUtils.hex_to_bytes(hex_str)
    local bytes = {}
    for i = 1, #hex_str, 2 do
        local hex_byte = hex_str:sub(i, i + 1)
        bytes[#bytes + 1] = tonumber(hex_byte, 16)
    end
    return bytes
end

-- 字节数组转十六进制字符串
function LAESUtils.bytes_to_hex(byte_array)
    local hex_parts = {}
    for i = 1, #byte_array do
        hex_parts[#hex_parts + 1] = string.format("%02x", byte_array[i])
    end
    return table.concat(hex_parts)
end

-- 数据填充
function LAESUtils.pad_data(data)
    local block_size = 16
    local padding_len = block_size - (#data % block_size)
    local fill_bytes = {0xB9, 0xBA, 0xB8, 0xB3, 0xB1, 0xB2, 0xB0, 0xBF, 0xBD, 0xBE, 0xBC, 0xB7, 0xB5, 0xB6, 0xB4, 0x9B}
    local fill_byte = fill_bytes[padding_len]
    
    local padded_data = {}
    for i = 1, #data do
        padded_data[i] = data[i]
    end
    
    for i = 1, padding_len do
        padded_data[#padded_data + 1] = fill_byte
    end
    
    return padded_data
end

-- 根据PKCS#7填充规则计算实际数据长度（移除填充）
function LAESUtils.calculate_adjusted_length(data, length)
    local threshold = 16  -- AES块大小
    local byte_index = length  -- 最后一个字节的索引（Lua索引从1开始）
    
    if not (1 <= byte_index and byte_index <= #data) then
        error("Index out of range")
    end
    
    local last_byte_value = string.byte(data, byte_index)
    local adjusted_length
    
    if last_byte_value <= threshold then
        adjusted_length = length - last_byte_value
    elseif last_byte_value >= length then
        adjusted_length = length
    else
        adjusted_length = length - last_byte_value
    end
    
    return adjusted_length
end

-- 使用查找表转换数据
function LAESUtils:transform(data, lookup_table)
    local output_arr = {}
    for i = 1, #data do
        local byte_val = data[i]
        if byte_val < 0 then
            output_arr[i] = lookup_table[byte_val + 256 + 1]  -- Lua索引从1开始，所以是+256 +1
        else
            output_arr[i] = lookup_table[byte_val + 1]    -- Lua索引从1开始，所以是+1
        end
    end
    return output_arr
end

-- 大数异或核心函数
function LAESUtils:big_xor(hex1, hex2)
  -- 转换为字节数组
  local bytes1 = LAESUtils.hex_to_bytes(hex1)
  local bytes2 = LAESUtils.hex_to_bytes(hex2)

  -- 对齐长度（前补零）
  local max_len = math.max(#bytes1, #bytes2)
  while #bytes1 < max_len do table.insert(bytes1, 1, 0) end
  while #bytes2 < max_len do table.insert(bytes2, 1, 0) end

  -- 逐字节异或
  local result = {}
  for i = 1, max_len do
    result[i] = bytes1[i] ~ bytes2[i]
  end

  return LAESUtils.bytes_to_hex(result)
end

-- 模拟 BigInt 处理函数 将 hex 转换为 4x4 矩阵
function LAESUtils:hex_to_matrix(hex)
  local matrix = {{}, {}, {}, {}}
  for i = 1, #hex, 2 do
    local byte_str = hex:sub(i, i+1)
    local byte = tonumber(byte_str, 16)
    local row = math.floor((i-1)/8) + 1
    table.insert(matrix[row], byte)
  end
  return matrix
end

-- 将状态矩阵转换为字节数组
function LAESUtils:state_to_bytes(state)
    local bytes = {}
    for i = 1, 4 do
        for j = 1, 4 do
            bytes[#bytes + 1] = state[i][j]
        end
    end
    return bytes
end

-- 将状态矩阵转换为十六进制字符串
function LAESUtils:state_to_hex(state)
    return self.bytes_to_hex(self:state_to_bytes(state))
end

-- 通用的XOR数组模板
function LAESUtils:xor_array_template(arr1, arr2, lookup)
    local result = {}
    for i = 1, #arr1 do
        local p1 = (arr2[i] & 0xF) ~ ((arr1[i] << 4) & 0xFF)
        local v1 = (lookup(p1) >> 4) & 0xFF
        local p2 = ((arr2[i] >> 4) & 0xF) ~ ((arr1[i] >> 4) << 4)
        local v2 = (lookup(p2) >> 4) & 0xFF
        result[i] = v1 ~ (v2 << 4)
    end
    return result
end

-- 添加轮密钥
function LAESUtils:add_round_keys(state, round_key, lookup)
    local result = {}
    for i = 1, 4 do
        result[i] = self:xor_array_template(state[i], round_key[i], lookup)
    end
    return result
end

-- 字节替换
function LAESUtils:sub_bytes(s_box, state1, state2)
    local result = {}
    for i = 1, 4 do
        result[i] = {}
        for j = 1, #state1[i] do
            local idx1 = (state2[i][j] & 0xF) ~ ((state1[i][j] << 4) & 0xFF)
            local idx2 = ((state2[i][j] >> 4) & 0xF) ~ ((state1[i][j] >> 4) << 4)
            result[i][j] = ((s_box[idx1 + 1] >> 4) & 0xFF) ~ (((s_box[idx2 + 1] >> 4) & 0xFF) << 4)
        end
    end
    return result
end

-- 行移位
function LAESUtils:shift_rows(s_box, state, state3)
    local result = {}
    for i = 1, 4 do
        result[i] = {}
        for j = 1, #state[i] do
            local idx1 = (state3[i][j] & 0xF) ~ ((state[i][j] << 4) & 0xFF)
            local idx2 = ((state3[i][j] >> 4) & 0xF) ~ ((state[i][j] >> 4) << 4)
            result[i][j] = ((s_box[idx1 + 1] >> 4) & 0xFF) ~ (((s_box[idx2 + 1] >> 4) & 0xFF) << 4)
        end
    end
    return result
end

-- 列混淆
function LAESUtils:mix_columns(s_box, state, state4)
    local result = {}
    for i = 1, 4 do
        result[i] = {}
        for j = 1, #state[i] do
            local idx1 = (state4[i][j] & 0xF) ~ ((state[i][j] << 4) & 0xFF)
            local idx2 = ((state4[i][j] >> 4) & 0xF) ~ ((state[i][j] >> 4) << 4)
            result[i][j] = ((s_box[idx1 + 1] >> 4) & 0xFF) ~ (((s_box[idx2 + 1] >> 4) & 0xFF) << 4)
        end
    end
    return result
end

-- 构建密钥
function LAESUtils:build_key(template, indices, source)
    local key_parts = {}
    for i = 1, #indices do
        local idx = indices[i] + 1  -- Lua索引从1开始
        local hex_val = tonumber(source:sub(idx, idx + 1), 16)
        key_parts[#key_parts + 1] = template[hex_val * 4]
    end
    return table.concat(key_parts)
end

-- 加密核心函数
function LAESUtils:encrypt(input_num, mkey_schedule)
    local encryptConf = self:getEncryptConf()
    local key_schedule = encryptConf.key_schedule
    local s_box = encryptConf.s_box
    local dict1 = encryptConf.dict1
    local dict2 = encryptConf.dict2
    local dict3 = encryptConf.dict3
    local dict4 = encryptConf.dict4
    local dict5 = encryptConf.dict5
    local round_constants = encryptConf.round_constants
    
    local state = self:add_round_keys(self:hex_to_matrix(input_num), 
                                     {mkey_schedule[1], mkey_schedule[2], mkey_schedule[3], mkey_schedule[4]},
                                     function(i) return key_schedule[i + 1] end)
    local key_templates = {
        {template = dict1, indices = {0, 8, 16, 24}},
        {template = dict2, indices = {10, 18, 26, 2}},
        {template = dict3, indices = {20, 28, 4, 12}},
        {template = dict4, indices = {30, 6, 14, 22}},
    }
    
    local states = {}
    for i = 1, #key_templates do
        local t = key_templates[i]
        local new_key = self:build_key(t.template, t.indices, self:state_to_hex(state))
        states[i] = self:hex_to_matrix(new_key)
    end
    for i = 1, 9 do
        state = self:sub_bytes(s_box, states[1], states[2])
        state = self:shift_rows(s_box, state, states[3])
        state = self:mix_columns(s_box, state, states[4])
        
        local round_keys = {}
        for j = 1, 4 do
            round_keys[j] = mkey_schedule[4 * i + j]
        end
        state = self:add_round_keys(state, round_keys, function(idx) return s_box[idx + 1] end)
        
        if i ~= 9 then
            states = {}
            for j = 1, #key_templates do
                local t = key_templates[j]
                local new_key = self:build_key(t.template, t.indices, self:state_to_hex(state))
                states[j] = self:hex_to_matrix(new_key)
            end
        end
    end
    
    local final_indices = {0, 10, 20, 30, 8, 18, 28, 6, 16, 26, 4, 14, 24, 2, 12, 22}
    local state_hex = self:state_to_hex(state)
    local new_key_parts = {}
    for i = 1, #final_indices do
        local idx = final_indices[i] + 1  -- Lua索引调整
        local hex_val = tonumber(state_hex:sub(idx, idx + 1), 16)
        new_key_parts[#new_key_parts + 1] = dict5[hex_val]
    end
    local new_key = table.concat(new_key_parts)
    
    state = self:hex_to_matrix(new_key)
    local final_round_keys = {}
    for i = 1, 4 do
        final_round_keys[i] = mkey_schedule[40 + i]
    end
    state = self:add_round_keys(state, final_round_keys, function(idx) return round_constants[idx + 1] end)
    
    return state
end

-- 根据输入的十六进制密钥字符串生成轮密钥
function LAESUtils:generate_round_keys(key_string)
    -- 将十六进制字符串转换为字节数组
    local bytes_data = self.hex_to_bytes(key_string)
    -- 对字节数组进行异或运算生成密钥字节
    local key_bytes = {}
    for i = 4 + 1, #bytes_data do  -- Lua索引从1开始，所以从5开始
        key_bytes[#key_bytes + 1] = bytes_data[i] ~ bytes_data[(i - 1) % 3 + 1]
    end
    -- 将密钥字节转换回十六进制字符串
    local key_hex = self.bytes_to_hex(key_bytes)
    -- 按32字符长度分割成轮密钥
    local round_keys = {}
    for i = 1, #key_hex, 32 do
        round_keys[#round_keys + 1] = key_hex:sub(i, i + 31)
    end
    return round_keys
end

-- IV转换
function LAESUtils:transform_iv(data, arr)
    local byte_data
    if type(data) == "string" then
        byte_data = {string.byte(data, 1, #data)}
    else
        byte_data = data
    end
    
    local transformed = self:transform(byte_data, arr)
    return self.bytes_to_hex(transformed)
end

-- AES加密函数
function LAESUtils:aes_encrypt(round_keys, input_hex, iv_hex)
    local input_with_iv = self:big_xor(input_hex,iv_hex)
    
    local mkey_schedule = {}
    for i = 1, #round_keys do
        local round_key = round_keys[i]
        local bytes_data = self.hex_to_bytes(round_key)
        for j = 1, #bytes_data, 4 do
            local key_block = {}
            for k = 0, 3 do
                if j + k <= #bytes_data then
                    key_block[k + 1] = bytes_data[j + k]
                end
            end
            mkey_schedule[#mkey_schedule + 1] = key_block
        end
    end
    
    local cipher_state = self:encrypt(input_with_iv, mkey_schedule)
    local cipher_text = self:state_to_hex(cipher_state)
    self:logDebug('Encrypted: ' .. cipher_text)
    return cipher_text
end

-- 处理输入数据
function LAESUtils:process_input(data)
    local decryptConf = self:getDecryptConf()
    local input_array = decryptConf.input_arr
    local data_length = #data
    local data_s = {}
    
    for i = 1, data_length do
        local b = string.byte(data, i)
        data_s[i] = input_array[b + 1]  -- Lua索引调整
    end
    
    -- 填充 0x00
    for j = 1, 256 do
        data_s[data_length + j] = 0x00
    end
    
    return data_s, data_length
end

-- 处理输出数据
function LAESUtils:process_out(data, data_length)
    local decryptConf = self:getDecryptConf()
    local out_array = decryptConf.out_arr
    local data_s = {}
    
    for i = 1, data_length do
        local b = string.byte(data, i)
        if b < 0 then
            data_s[i] = out_array[b + 256 + 1]  -- Lua索引调整
        else
            data_s[i] = out_array[b + 1]    -- Lua索引调整
        end
    end
    
    local index = data_s[#data_s]
    if index < 0 then
        index = index + 256
    end
    
    local n_out = #data_s > index and (#data_s - index) or #data_s
    local data_out = {}
    for i = 1, n_out do
        data_out[i] = data_s[i]
    end
    
    return data_out
end

-- 解密核心函数
function LAESUtils:decrypt(input_num, mkey_schedule)
    local decryptConf = self:getDecryptConf()
    local key_schedule = decryptConf.key_schedule
    local s_box = decryptConf.s_box
    local dict1 = decryptConf.dict1
    local dict2 = decryptConf.dict2
    local dict3 = decryptConf.dict3
    local dict4 = decryptConf.dict4
    local dict5 = decryptConf.dict5
    local round_constants = decryptConf.round_constants
    
    local state = self:add_round_keys(self:hex_to_matrix(input_num), 
                                     {mkey_schedule[1], mkey_schedule[2], mkey_schedule[3], mkey_schedule[4]},
                                     function(i) return key_schedule[i + 1] end)
    
    local key_templates = {
        {template = dict1, indices = {0, 8, 16, 24}},
        {template = dict2, indices = {26, 2, 10, 18}},
        {template = dict3, indices = {20, 28, 4, 12}},
        {template = dict4, indices = {14, 22, 30, 6}},
    }
    
    local states = {}
    for i = 1, #key_templates do
        local t = key_templates[i]
        local new_key = self:build_key(t.template, t.indices, self:state_to_hex(state))
        states[i] = self:hex_to_matrix(new_key)
    end
    
    for i = 1, 9 do
        state = self:sub_bytes(s_box, states[1], states[2])
        state = self:shift_rows(s_box, state, states[3])
        state = self:mix_columns(s_box, state, states[4])
        
        local round_keys = {}
        for j = 1, 4 do
            round_keys[j] = mkey_schedule[4 * i + j]
        end
        state = self:add_round_keys(state, round_keys, function(idx) return s_box[idx + 1] end)
        
        if i ~= 9 then
            states = {}
            for j = 1, #key_templates do
                local t = key_templates[j]
                local new_key = self:build_key(t.template, t.indices, self:state_to_hex(state))
                states[j] = self:hex_to_matrix(new_key)
            end
        end
    end
    
    local final_indices = {0, 26, 20, 14, 8, 2, 28, 22, 16, 10, 4, 30, 24, 18, 12, 6}
    local state_hex = self:state_to_hex(state)
    local new_key_parts = {}
    for i = 1, #final_indices do
        local idx = final_indices[i] + 1  -- Lua索引调整
        local hex_val = tonumber(state_hex:sub(idx, idx + 1), 16)
        new_key_parts[#new_key_parts + 1] = dict5[hex_val]  -- Lua索引调整
    end
    local new_key = table.concat(new_key_parts)
    
    state = self:hex_to_matrix(new_key)
    local final_round_keys = {}
    for i = 1, 4 do
        final_round_keys[i] = mkey_schedule[40 + i]
    end
    state = self:add_round_keys(state, final_round_keys, function(idx) return round_constants[idx + 1] end)
    
    return state
end

-- AES解密函数
function LAESUtils:aes_decrypt(round_keys, input_hex, iv_hex)
    local input_bytes = input_hex
    local mkey_schedule = {}
    
    for i = 1, #round_keys do
        local round_key = round_keys[i]
        local bytes_data = self.hex_to_bytes(round_key)
        for j = 1, #bytes_data, 4 do
            local key_block = {}
            for k = 0, 3 do
                if j + k <= #bytes_data then
                    key_block[k + 1] = bytes_data[j + k]
                end
            end
            mkey_schedule[#mkey_schedule + 1] = key_block
        end
    end
    
    local plain_state = self:decrypt(input_bytes, mkey_schedule)
    local plain_text = self:state_to_hex(plain_state)
    

    local plain_block_hex = self:big_xor(plain_text, iv_hex)
    self:logDebug('Decrypted: ' .. plain_block_hex)
    return plain_block_hex
end

-- 创建预绑定的LAESEncrypt函数
function LAESUtils:create_encryptor(key, iv, is_binary_output)
    local encryptConf = self:getEncryptConf()
    
    -- 预先计算并转换IV
    local iv_hex = self:transform_iv(iv, encryptConf.iv_arr)
    
    -- 预先生成轮密钥
    local round_keys = self:generate_round_keys(key)
    
    -- 返回只需要input_data的函数
    return function(input_data)
        local input_bytes = {string.byte(input_data, 1, #input_data)}
        local transformed_input = self:transform(input_bytes, encryptConf.input_arr)
        local bytes_data = self.pad_data(transformed_input)
        local input_hex = self.bytes_to_hex(bytes_data)
        
        local blocks = {}
        for i = 1, #input_hex, 32 do
            blocks[#blocks + 1] = input_hex:sub(i, i + 31)
        end
        
        local signatures = {}
        local current_iv = iv_hex
        
        for i = 1, #blocks do
            local block = blocks[i]
            local signature = self:aes_encrypt(round_keys, block, current_iv)
            signatures[#signatures + 1] = signature
            current_iv = signature
        end
        
        local final_hex = table.concat(signatures)
        local final_bytes = self.hex_to_bytes(final_hex)
        local transformed = self:transform(final_bytes, encryptConf.out_arr)
        
        -- 转换为字符串用于base64编码
        local byte_string = ""
        for i = 1, #transformed do
            byte_string = byte_string .. string.char(transformed[i])
        end
        
        -- 根据 is_binary_output 参数决定返回格式
        if is_binary_output then
            return byte_string
        else
            return base64.encode(byte_string)
        end
    end
end

-- 创建预绑定的LAESDeCrypt函数
function LAESUtils:create_decryptor(key, iv, is_binary_input)
    local decryptConf = self:getDecryptConf()
    
    -- 预先计算并转换IV
    local iv_hex = self:transform_iv(iv, decryptConf.iv_arr)
    
    -- 预先生成轮密钥
    local round_keys = self:generate_round_keys(key)
    
    -- 返回只需要input_data的函数
    return function(input_data)
        -- 根据 is_binary_input 参数决定是否先 Base64 解码输入
        if is_binary_input then
            local input_bytes = {}
            for i = 1, #input_data do
                input_bytes[i] = string.byte(input_data:sub(i, i))
            end
            input_data = input_bytes
        else
            input_data = base64.decode(input_data)
        end
        local bytes_data, data_len = self:process_input(input_data)
        local input_hex = self.bytes_to_hex(bytes_data)
        
        local blocks = {}
        for i = 1, #input_hex, 32 do
            blocks[#blocks + 1] = input_hex:sub(i, i + 31)
        end
        
        local signatures = {}
        local current_iv = iv_hex
        
        for i = 1, #blocks do
            local block = blocks[i]
            local signature = self:aes_decrypt(round_keys, block, current_iv)
            signatures[#signatures + 1] = signature
            current_iv = blocks[i]
        end
        
        local final_plaintext_hex = table.concat(signatures)
        local plaintext_bytes = {}
        for i = 1, #final_plaintext_hex, 2 do
            local hex_byte = final_plaintext_hex:sub(i, i + 1)
            plaintext_bytes[#plaintext_bytes + 1] = tonumber(hex_byte, 16)
        end
        
        -- 转换为字符串
        local plaintext_string = ""
        for i = 1, #plaintext_bytes do
            plaintext_string = plaintext_string .. string.char(plaintext_bytes[i])
        end
        
        local adjusted_length = self.calculate_adjusted_length(plaintext_string, #bytes_data)
        local adjusted_plaintext = plaintext_string:sub(1, adjusted_length)
        local transformed = self:process_out(adjusted_plaintext, data_len)
        
        -- 转换为字符串用于base64编码
        local result_string = ""
        for i = 1, #transformed do
            result_string = result_string .. string.char(transformed[i])
        end
        
        return result_string
    end
end

return LAESUtils