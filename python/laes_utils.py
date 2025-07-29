# LAESUtils python 版本
# 基于自定义 AES 算法的加密/解密工具类
# 作者: huajiqaq
# 日期: 2025-07-29

import base64
from typing import Any, List, Dict, Callable, Optional

class LAESUtils:
    def __init__(self, encryptConf, decryptConf, isDebug=False):
        """初始化AES加密器"""
        self.encryptConf = encryptConf
        self.decryptConf = decryptConf
        self.isDebug = isDebug 

    def getEncryptConf(self):
        """获取加密配置"""
        return self.encryptConf
    
    def getDecryptConf(self):
        """获取解密配置"""
        return self.decryptConf
    
    def logDebug(self, message):
        """调试日志输出"""
        if self.isDebug:
            print(message)

    @staticmethod
    def hex_to_bytes(hex_str: str) -> List[int]:
        """十六进制字符串转字节数组"""
        return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

    @staticmethod
    def bytes_to_hex(byte_array: List[int]) -> str:
        """字节数组转十六进制字符串"""
        return ''.join(f'{byte:02x}' for byte in byte_array)

    @staticmethod
    def pad_data(data: List[int]) -> List[int]:
        """数据填充"""
        block_size = 16
        padding_len = block_size - (len(data) % block_size)
        fill_bytes = [0xB9, 0xBA, 0xB8, 0xB3, 0xB1, 0xB2, 0xB0, 0xBF, 0xBD, 0xBE, 0xBC, 0xB7, 0xB5, 0xB6, 0xB4, 0x9B]
        fill_byte = fill_bytes[padding_len - 1]
        return data + [fill_byte] * padding_len

    @staticmethod
    def calculate_adjusted_length(data: bytes, length: int) -> int:
        """ 根据PKCS#7填充规则计算实际数据长度（移除填充）
            :param data: 解密后的字节数据
            :param length: 加密数据的长度
            :return: 移除填充后的实际长度
        """

        threshold = 16  # AES块大小
        byte_index = length - 1  # 最后一个字节的索引

        if not (0 <= byte_index < len(data)):
            raise IndexError("Index out of range")

        last_byte_value = data[byte_index]

        if last_byte_value <= threshold:
            adjusted_length = length - last_byte_value
        elif last_byte_value >= length:
            adjusted_length = length
        else:
            adjusted_length = length - last_byte_value

        return adjusted_length

    def transform(self, data: List[int], lookup_table: List[int]) -> List[int]:
        """使用查找表转换数据"""
        output_arr = bytearray(len(data))
        for i in range(len(data)):
            if data[i] < 0:
                output_arr[i] = lookup_table[data[i] + 256]
            else:
                output_arr[i] = lookup_table[data[i]]
        return output_arr

    def text_to_matrix(self, text: int) -> List[List[int]]:
        """将大整数转换为4x4矩阵"""
        matrix = []
        for i in range(16):
            byte = (text >> (8 * (15 - i))) & 0xFF
            if i % 4 == 0:
                matrix.append([byte])
            else:
                matrix[i // 4].append(byte)
        return matrix

    def state_to_bytes(self, state: List[List[int]]) -> List[int]:
        """将状态矩阵转换为字节数组"""
        return [byte for row in state for byte in row]

    def state_to_hex(self, state: List[List[int]]) -> str:
        """将状态矩阵转换为十六进制字符串"""
        return self.bytes_to_hex(self.state_to_bytes(state))

    def xor_array_template(self, arr1: List[int], arr2: List[int], lookup: Callable[[int], int]) -> List[int]:
        """通用的XOR数组模板"""
        result = []
        for i in range(len(arr1)):
            p1 = (arr2[i] & 0xF) ^ ((arr1[i] << 4) & 0xFF)
            v1 = (lookup(p1) >> 4) & 0xFF
            p2 = ((arr2[i] >> 4) & 0xF) ^ ((arr1[i] >> 4) << 4)
            v2 = (lookup(p2) >> 4) & 0xFF
            result.append(v1 ^ (v2 << 4))
        return result

    def add_round_keys(self, state: List[List[int]], round_key: List[List[int]], lookup: Callable[[int], int]) -> List[List[int]]:
        """添加轮密钥"""
        return [self.xor_array_template(state[i], round_key[i], lookup) for i in range(4)]

    def sub_bytes(self, s_box:List[int], state1: List[List[int]], state2: List[List[int]]):
        """字节替换"""
        return [[(s_box[state2[i][j] & 0xF ^ ((state1[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^ 
                 ((s_box[(state2[i][j] >> 4 & 0xF) ^ ((state1[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4)
                 for j in range(len(state1[i]))] for i in range(4)]

    def shift_rows(self, s_box:List[int], state: List[List[int]], state3: List[List[int]]):
        """行移位"""
        return [[(s_box[state3[i][j] & 0xF ^ ((state[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^ 
                 ((s_box[(state3[i][j] >> 4 & 0xF) ^ ((state[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4)
                 for j in range(len(state[i]))] for i in range(4)]

    def mix_columns(self, s_box:List[int], state: List[List[int]], state4: List[List[int]]):
        """列混淆"""
        return [[(s_box[state4[i][j] & 0xF ^ ((state[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^ 
                 ((s_box[(state4[i][j] >> 4 & 0xF) ^ ((state[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4)
                 for j in range(len(state[i]))] for i in range(4)]

    def build_key(self, template: Dict[int, str], indices: List[int], source: str) -> str:
        """构建密钥"""
        return ''.join([template[int(source[i:i+2], 16) * 4] for i in indices])


    def encrypt(self, input_num: int, mkey_schedule: List[List[int]]) -> List[List[int]]:
        """加密核心函数"""
        encryptConf = self.getEncryptConf()
        key_schedule: List[int] = encryptConf["key_schedule"]
        s_box: List[int] = encryptConf["s_box"]
        dict1: Dict[int, str] = encryptConf["dict1"]
        dict2: Dict[int, str] = encryptConf["dict2"]
        dict3: Dict[int, str] = encryptConf["dict3"]
        dict4: Dict[int, str] = encryptConf["dict4"]
        dict5: Dict[int, str] = encryptConf["dict5"]
        round_constants: List[int] = encryptConf["round_constants"]

        state = self.add_round_keys(self.text_to_matrix(input_num), mkey_schedule[0:4], lambda i: key_schedule[i])
        
        key_templates = [
            {'template': dict1, 'indices': [0, 8, 16, 24]},
            {'template': dict2, 'indices': [10, 18, 26, 2]},
            {'template': dict3, 'indices': [20, 28, 4, 12]},
            {'template': dict4, 'indices': [30, 6, 14, 22]},
        ]
        
        states = []
        for t in key_templates:
            new_key = self.build_key(t['template'], t['indices'], self.state_to_hex(state))
            states.append(self.text_to_matrix(int(new_key, 16)))
        
        for i in range(1, 10):
            state = self.sub_bytes(s_box, states[0], states[1])
            state = self.shift_rows(s_box, state, states[2])
            state = self.mix_columns(s_box, state, states[3])
            state = self.add_round_keys(state, mkey_schedule[4*i:4*(i+1)], lambda i: s_box[i])
            
            if i != 9:
                states = []
                for t in key_templates:
                    new_key = self.build_key(t['template'], t['indices'], self.state_to_hex(state))
                    states.append(self.text_to_matrix(int(new_key, 16)))
        
        final_indices = [0, 10, 20, 30, 8, 18, 28, 6, 16, 26, 4, 14, 24, 2, 12, 22]
        new_key = ''.join([dict5[int(self.state_to_hex(state)[i:i+2], 16)] for i in final_indices])
        
        state = self.text_to_matrix(int(new_key, 16))
        state = self.add_round_keys(state, mkey_schedule[40:44], lambda i: round_constants[i])
        return state

    def generate_round_keys(self, key_string: str) -> List[str]:
        """根据输入的十六进制密钥字符串生成轮密钥"""
        # 将十六进制字符串转换为字节数组
        bytes_data = self.hex_to_bytes(key_string)
        # 对字节数组进行异或运算生成密钥字节
        key_bytes = [bytes_data[i] ^ bytes_data[i % 3] for i in range(4, len(bytes_data))]
        # 将密钥字节转换回十六进制字符串
        key_hex = self.bytes_to_hex(key_bytes)
        # 按32字符长度分割成轮密钥
        round_keys = [key_hex[i:i+32] for i in range(0, len(key_hex), 32)]
        return round_keys
    
    def transform_iv(self, data, arr):
        """IV转换"""
        if isinstance(data, str):
            byte_data = data.encode('utf-8')
        else:
            byte_data = bytes(data)
            
        return self.transform(bytearray(byte_data), arr).hex()

    def aes_encrypt(self, round_keys: List, input_hex: str, iv_hex: str) -> str:
        """AES加密函数"""
        input_num = int(input_hex, 16)
        iv_num = int(iv_hex, 16)
        input_with_iv = input_num ^ iv_num
        
        mkey_schedule = []
        for round_key in round_keys:
            bytes_data = self.hex_to_bytes(round_key)
            mkey_schedule.extend([bytes_data[i:i+4] for i in range(0, len(bytes_data), 4)])
        cipher_state = self.encrypt(input_with_iv, mkey_schedule)
        cipher_text = self.state_to_hex(cipher_state)
        self.logDebug(f'Encrypted: {cipher_text}')
        return cipher_text


    def process_input(self, data: bytes) -> tuple[bytearray, int]:
        decryptConf: Dict[str, Any] = self.getDecryptConf()
        input_array: List[int] = decryptConf["input_arr"]
        data_length = len(data)
        data_s = bytearray(data_length + 256)
        for i in range(data_length):
            b = data[i]
            data_s[i] = input_array[b]
        # 填充 0x00
        for j in range(256):
            data_s[data_length + j] = 0x00
        return data_s, data_length

    def process_out(self, data: bytes, data_length: int) -> bytearray:
        decryptConf: Dict[str, Any] = self.getDecryptConf()
        out_array: List[int] = decryptConf["out_arr"]
        data_s = bytearray(data_length)
        for i in range(len(data_s)):
            b = data[i]
            if b < 0:
                data_s[i] = out_array[b + 256]
            else:
                data_s[i] = out_array[b]
        index = data_s[-1]
        if index < 0:
            index += 256
        n_out = len(data_s) - index if len(data_s) > index else len(data_s)
        data_out = data_s[:n_out]
        return data_out
    

    def decrypt(self, input_num: int, mkey_schedule: List[List[int]]) -> List[List[int]]:
        """解密核心函数"""
        decryptConf = self.getDecryptConf() 
        key_schedule: List[int] = decryptConf["key_schedule"]
        s_box: List[int] = decryptConf["s_box"]
        dict1: Dict[int, str] = decryptConf["dict1"]
        dict2: Dict[int, str] = decryptConf["dict2"]
        dict3: Dict[int, str] = decryptConf["dict3"]
        dict4: Dict[int, str] = decryptConf["dict4"]
        dict5: Dict[int, str] = decryptConf["dict5"]
        round_constants: List[int] = decryptConf["round_constants"]

        state = self.add_round_keys(self.text_to_matrix(input_num), mkey_schedule[0:4], lambda i: key_schedule[i])
        
        key_templates = [
            {'template': dict1, 'indices': [0, 8, 16, 24]},
            {'template': dict2, 'indices': [26, 2, 10, 18]},
            {'template': dict3, 'indices': [20, 28, 4, 12]},
            {'template': dict4, 'indices': [14, 22, 30, 6]},
        ]
        
        states = []
        for t in key_templates:
            new_key = self.build_key(t['template'], t['indices'], self.state_to_hex(state))
            states.append(self.text_to_matrix(int(new_key, 16)))
        
        for i in range(1, 10):
            state = self.sub_bytes(s_box, states[0], states[1])
            state = self.shift_rows(s_box, state, states[2])
            state = self.mix_columns(s_box, state, states[3])
            state = self.add_round_keys(state, mkey_schedule[4*i:4*(i+1)], lambda i: s_box[i])
            
            if i != 9:
                states = []
                for t in key_templates:
                    new_key = self.build_key(t['template'], t['indices'], self.state_to_hex(state))
                    states.append(self.text_to_matrix(int(new_key, 16)))
        
        final_indices = [0, 26, 20, 14, 8, 2, 28, 22, 16, 10, 4, 30, 24, 18, 12, 6]
        new_key = ''.join([dict5[int(self.state_to_hex(state)[i:i+2], 16)] for i in final_indices])
        
        state = self.text_to_matrix(int(new_key, 16))
        state = self.add_round_keys(state, mkey_schedule[40:44], lambda i: round_constants[i])
        return state

    def aes_decrypt(self, round_keys: List, input_hex: str, iv_hex: str) -> str:
        """AES解密函数"""
        
        input_bytes = int(input_hex, 16)
        mkey_schedule = []
        for round_key in round_keys:
            bytes_data = self.hex_to_bytes(round_key)
            mkey_schedule.extend([bytes_data[i:i+4] for i in range(0, len(bytes_data), 4)])
        plain_state = self.decrypt(input_bytes, mkey_schedule)
        plain_text = self.state_to_hex(plain_state)

        decrypted_block_int = int(plain_text, 16)
        prev_block_int = int(iv_hex, 16)
        plain_block_int = decrypted_block_int ^ prev_block_int
        plain_block_hex = f"{plain_block_int:032x}"
        self.logDebug(f'Decrypted: {plain_block_hex}')
        return plain_block_hex

    def create_encryptor(self, key: str, iv: List, is_binary_output: bool = False) -> Callable[[str], str]:
        """创建预绑定的LAESEncrypt函数"""
        encryptConf = self.getEncryptConf()
    
        # 预先计算并转换IV
        iv_hex = self.transform_iv(iv, encryptConf["iv_arr"])
    
        # 预先生成轮密钥
        round_keys = self.generate_round_keys(key)
    
        # 返回只需要input_data的函数
        def encrypt(input_data: str) -> str:
            bytes_data = self.pad_data(list(self.transform(input_data.encode(), encryptConf["input_arr"])))
            input_hex = self.bytes_to_hex(bytes_data)
        
            blocks = [input_hex[i:i+32] for i in range(0, len(input_hex), 32)]
            signatures = []
            current_iv = iv_hex
        
            for block in blocks:
                signature = self.aes_encrypt(round_keys, block, current_iv)
                signatures.append(signature)
                current_iv = signature
        
            final_bytes = self.hex_to_bytes(''.join(signatures))
            transformed = self.transform(final_bytes, encryptConf["out_arr"])
        
            # 根据 is_binary_output 参数决定返回格式
            if is_binary_output:
                return bytes(transformed).decode('latin1')
            else:
                return base64.b64encode(bytes(transformed)).decode()
    
        return encrypt

    def create_decryptor(self, key: str, iv: List, is_binary_input: bool = False) -> Callable[[str], str]:
        """创建预绑定的LAESDeCrypt函数"""
        decryptConf = self.getDecryptConf()
    
        # 预先计算并转换IV
        iv_hex = self.transform_iv(iv, decryptConf["iv_arr"])
    
        # 预先生成轮密钥
        round_keys = self.generate_round_keys(key)
    
        # 返回只需要input_data的函数
        def decrypt(input_data: str) -> str:
            # 根据 is_binary_input 参数决定是否先 Base64 解码输入
            if is_binary_input:
                input_bytes = list(input_data.encode('latin1'))
            else:
                input_bytes = list(base64.b64decode(input_data))
        
            bytes_data, data_len = self.process_input(input_bytes)
            input_hex = self.bytes_to_hex(bytes_data)
        
            blocks = [input_hex[i:i+32] for i in range(0, len(input_hex), 32)]
            signatures = []
            current_iv = iv_hex
        
            for block in blocks:
                signature = self.aes_decrypt(round_keys, block, current_iv)
                signatures.append(signature)
                current_iv = block
        
            final_plaintext_hex = "".join(signatures)
            plaintext_bytes = bytes.fromhex(final_plaintext_hex)
            adjusted_length = self.calculate_adjusted_length(plaintext_bytes, len(bytes_data))
            transformed = self.process_out(plaintext_bytes[:adjusted_length], data_len)
            return bytes(transformed).decode('utf-8')
    
        return decrypt