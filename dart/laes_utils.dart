// LAESUtils dart版本
// 基于自定义 AES 算法的加密/解密工具类
// 作者: huajiqaq
// 日期: 2025-07-29

import 'dart:convert';
import 'dart:typed_data';

/// LAES加密工具类
class LAESUtils {
  Map<String, dynamic> encryptConf;
  Map<String, dynamic> decryptConf;
  bool isDebug;

  /// 构造函数，初始化AES加密器
  LAESUtils(this.encryptConf, this.decryptConf, {this.isDebug = false});

  void logDebug(String message) {
    if (isDebug) {
        print(message);
    }
  }

  /// 获取加密配置
  Map<String, dynamic> getEncryptConf() {
    return encryptConf;
  }

  /// 获取解密配置
  Map<String, dynamic> getDecryptConf() {
    return decryptConf;
  }

  /// 十六进制字符串转字节数组
  static List<int> hexToBytes(String hexStr) {
    List<int> result = [];
    for (int i = 0; i < hexStr.length; i += 2) {
      result.add(int.parse(hexStr.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  /// 字节数组转十六进制字符串
  static String bytesToHex(List<int> byteArray) {
    return byteArray.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join('');
  }

  /// 数据填充
  static List<int> padData(List<int> data) {
    const int blockSize = 16;
    int paddingLen = blockSize - (data.length % blockSize);
    List<int> fillBytes = [0xB9, 0xBA, 0xB8, 0xB3, 0xB1, 0xB2, 0xB0, 0xBF, 0xBD, 0xBE, 0xBC, 0xB7, 0xB5, 0xB6, 0xB4, 0x9B];
    int fillByte = fillBytes[paddingLen - 1];
    return data + List.filled(paddingLen, fillByte);
  }

  /// 根据PKCS#7填充规则计算实际数据长度（移除填充）
  static int calculateAdjustedLength(Uint8List data, int length) {
    const int threshold = 16; // AES块大小
    int byteIndex = length - 1; // 最后一个字节的索引

    if (byteIndex < 0 || byteIndex >= data.length) {
      throw RangeError('索引超出范围');
    }

    int lastByteValue = data[byteIndex];
    int adjustedLength;

    if (lastByteValue <= threshold) {
      adjustedLength = length - lastByteValue;
    } else if (lastByteValue >= length) {
      adjustedLength = length;
    } else {
      adjustedLength = length - lastByteValue;
    }

    return adjustedLength;
  }

  /// 使用查找表转换数据
  Uint8List transform(List<int> data, List<int> lookupTable) {
    Uint8List outputArr = Uint8List(data.length);
    for (int i = 0; i < data.length; i++) {
      if (data[i] < 0) {
        outputArr[i] = lookupTable[data[i] + 256];
      } else {
        outputArr[i] = lookupTable[data[i]];
      }
    }
    return outputArr;
  }

  /// 将大整数转换为4x4矩阵
  List<List<int>> textToMatrix(BigInt text) {
    List<List<int>> matrix = [];
    for (int i = 0; i < 16; i++) {
      int byte = ((text >> (8 * (15 - i))) & BigInt.from(0xFF)).toInt();
      if (i % 4 == 0) {
        matrix.add([byte]);
      } else {
        matrix[i ~/ 4].add(byte);
      }
    }
    return matrix;
  }

  /// 将状态矩阵转换为字节数组
  List<int> stateToBytes(List<List<int>> state) {
    List<int> result = [];
    for (var row in state) {
      result.addAll(row);
    }
    return result;
  }

  /// 将状态矩阵转换为十六进制字符串
  String stateToHex(List<List<int>> state) {
    return bytesToHex(stateToBytes(state));
  }

  /// 通用的XOR数组模板
  List<int> xorArrayTemplate(List<int> arr1, List<int> arr2, int Function(int) lookup) {
    List<int> result = [];
    for (int i = 0; i < arr1.length; i++) {
      int p1 = (arr2[i] & 0xF) ^ ((arr1[i] << 4) & 0xFF);
      int v1 = (lookup(p1) >> 4) & 0xFF;
      int p2 = ((arr2[i] >> 4) & 0xF) ^ ((arr1[i] >> 4) << 4);
      int v2 = (lookup(p2) >> 4) & 0xFF;
      result.add(v1 ^ (v2 << 4));
    }
    return result;
  }

  /// 添加轮密钥
  List<List<int>> addRoundKeys(List<List<int>> state, List<List<int>> roundKey, int Function(int) lookup) {
    List<List<int>> result = [];
    for (int i = 0; i < 4; i++) {
      result.add(xorArrayTemplate(state[i], roundKey[i], lookup));
    }
    return result;
  }

  /// 字节替换
  List<List<int>> subBytes(List<int> sBox, List<List<int>> state1, List<List<int>> state2) {
    List<List<int>> result = [];
    for (int i = 0; i < 4; i++) {
      List<int> row = [];
      for (int j = 0; j < state1[i].length; j++) {
        int val = (sBox[state2[i][j] & 0xF ^ ((state1[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^
                  ((sBox[(state2[i][j] >> 4 & 0xF) ^ ((state1[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4);
        row.add(val);
      }
      result.add(row);
    }
    return result;
  }

  /// 行移位
  List<List<int>> shiftRows(List<int> sBox, List<List<int>> state, List<List<int>> state3) {
    List<List<int>> result = [];
    for (int i = 0; i < 4; i++) {
      List<int> row = [];
      for (int j = 0; j < state[i].length; j++) {
        int val = (sBox[state3[i][j] & 0xF ^ ((state[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^
                  ((sBox[(state3[i][j] >> 4 & 0xF) ^ ((state[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4);
        row.add(val);
      }
      result.add(row);
    }
    return result;
  }

  /// 列混淆
  List<List<int>> mixColumns(List<int> sBox, List<List<int>> state, List<List<int>> state4) {
    List<List<int>> result = [];
    for (int i = 0; i < 4; i++) {
      List<int> row = [];
      for (int j = 0; j < state[i].length; j++) {
        int val = (sBox[state4[i][j] & 0xF ^ ((state[i][j] << 4) & 0xFF)] >> 4 & 0xFF) ^
                  ((sBox[(state4[i][j] >> 4 & 0xF) ^ ((state[i][j] >> 4) << 4)] >> 4 & 0xFF) << 4);
        row.add(val);
      }
      result.add(row);
    }
    return result;
  }

  /// 构建密钥
  String buildKey(Map<int, String> template, List<int> indices, String source) {
    StringBuffer result = StringBuffer();
    for (int i in indices) {
      int value = int.parse(source.substring(i, i + 2), radix: 16) * 4;
      result.write(template[value]);
    }
    return result.toString();
  }

  /// 加密核心函数
  List<List<int>> encrypt(BigInt inputNum, List<List<int>> mkeySchedule) {
    Map<String, dynamic> encryptConf = getEncryptConf();
    List<int> keySchedule = List<int>.from(encryptConf["key_schedule"]);
    List<int> sBox = List<int>.from(encryptConf["s_box"]);
    Map<int, String> dict1 = Map<int, String>.from(encryptConf["dict1"]);
    Map<int, String> dict2 = Map<int, String>.from(encryptConf["dict2"]);
    Map<int, String> dict3 = Map<int, String>.from(encryptConf["dict3"]);
    Map<int, String> dict4 = Map<int, String>.from(encryptConf["dict4"]);
    Map<int, String> dict5 = Map<int, String>.from(encryptConf["dict5"]);
    List<int> roundConstants =  List<int>.from(encryptConf["round_constants"]);

    List<List<int>> state = addRoundKeys(
        textToMatrix(inputNum), 
        mkeySchedule.sublist(0, 4), 
        (i) => keySchedule[i]
    );

    List<Map<String, dynamic>> keyTemplates = [
      {'template': dict1, 'indices': [0, 8, 16, 24]},
      {'template': dict2, 'indices': [10, 18, 26, 2]},
      {'template': dict3, 'indices': [20, 28, 4, 12]},
      {'template': dict4, 'indices': [30, 6, 14, 22]},
    ];

    List<List<List<int>>> states = [];
    for (var t in keyTemplates) {
      String newKey = buildKey(t['template'], List<int>.from(t['indices']), stateToHex(state));
      states.add(textToMatrix(BigInt.parse(newKey, radix: 16)));
    }

    for (int i = 1; i < 10; i++) {
      state = subBytes(sBox, states[0], states[1]);
      state = shiftRows(sBox, state, states[2]);
      state = mixColumns(sBox, state, states[3]);
      state = addRoundKeys(state, mkeySchedule.sublist(4 * i, 4 * (i + 1)), (i) => sBox[i]);

      if (i != 9) {
        states = [];
        for (var t in keyTemplates) {
          String newKey = buildKey(t['template'], List<int>.from(t['indices']), stateToHex(state));
          states.add(textToMatrix(BigInt.parse(newKey, radix: 16)));
        }
      }
    }

    List<int> finalIndices = [0, 10, 20, 30, 8, 18, 28, 6, 16, 26, 4, 14, 24, 2, 12, 22];
    StringBuffer newKeyBuffer = StringBuffer();
    String stateHex = stateToHex(state);
    for (int i in finalIndices) {
      int value = int.parse(stateHex.substring(i, i + 2), radix: 16);
      newKeyBuffer.write(dict5[value]);
    }

    state = textToMatrix(BigInt.parse(newKeyBuffer.toString(), radix: 16));
    state = addRoundKeys(state, mkeySchedule.sublist(40, 44), (i) => roundConstants[i]);
    return state;
  }

  /// 根据输入的十六进制密钥字符串生成轮密钥
  List<String> generateRoundKeys(String keyString) {
    List<int> bytesData = hexToBytes(keyString);
    List<int> keyBytes = [];
    for (int i = 4; i < bytesData.length; i++) {
      keyBytes.add(bytesData[i] ^ bytesData[i % 3]);
    }
    String keyHex = bytesToHex(keyBytes);
    List<String> roundKeys = [];
    for (int i = 0; i < keyHex.length; i += 32) {
      roundKeys.add(keyHex.substring(i, i + 32));
    }
    return roundKeys;
  }

  /// IV转换
  String transformIv(dynamic data, List<int> arr) {
    Uint8List byteData;
    if (data is String) {
      byteData = Uint8List.fromList(utf8.encode(data));
    } else {
      byteData = Uint8List.fromList(List<int>.from(data));
    }
    return transform(byteData, arr).map((b) => b.toRadixString(16).padLeft(2, '0')).join('');
  }

  /// AES加密函数
  String aesEncrypt(List<String> roundKeys, String inputHex, String ivHex) {
    BigInt inputNum = BigInt.parse(inputHex, radix: 16);
    BigInt ivNum = BigInt.parse(ivHex, radix: 16);
    BigInt inputWithIv = inputNum ^ ivNum;

    List<List<int>> mkeySchedule = [];
    for (String roundKey in roundKeys) {
      List<int> bytesData = hexToBytes(roundKey);
      for (int i = 0; i < bytesData.length; i += 4) {
        mkeySchedule.add(bytesData.sublist(i, i + 4));
      }
    }
    List<List<int>> cipherState = encrypt(inputWithIv, mkeySchedule);
    String cipherText = stateToHex(cipherState);
    logDebug('Encrypted: $cipherText');
    return cipherText;
  }

  /// 处理输入数据
  Map<String, dynamic> processInput(Uint8List data) {
    Map<String, dynamic> decryptConf = getDecryptConf();
    List<int> inputArray = List<int>.from(decryptConf["input_arr"]);
    int dataLength = data.length;
    Uint8List dataS = Uint8List(dataLength + 256);
    
    for (int i = 0; i < dataLength; i++) {
      int b = data[i];
      dataS[i] = inputArray[b];
    }
    // 填充 0x00
    for (int j = 0; j < 256; j++) {
      dataS[dataLength + j] = 0x00;
    }
    return {'data': dataS, 'length': dataLength};
  }

  /// 处理输出数据
  Uint8List processOut(Uint8List data, int dataLength) {
    Map<String, dynamic> decryptConf = getDecryptConf();
    List<int> outArray = List<int>.from(decryptConf["out_arr"]);
    Uint8List dataS = Uint8List(dataLength);
    
    for (int i = 0; i < dataS.length; i++) {
      int b = data[i];
      if (b < 0) {
        dataS[i] = outArray[b + 256];
      } else {
        dataS[i] = outArray[b];
      }
    }
    
    int index = dataS.last;
    if (index < 0) {
      index += 256;
    }
    int nOut = dataS.length > index ? dataS.length - index : dataS.length;
    return Uint8List.fromList(dataS.sublist(0, nOut));
  }

  /// 解密核心函数
  List<List<int>> decrypt(BigInt inputNum, List<List<int>> mkeySchedule) {
    Map<String, dynamic> decryptConf = getDecryptConf();
    List<int> keySchedule = List<int>.from(decryptConf["key_schedule"]);
    List<int> sBox = List<int>.from(decryptConf["s_box"]);
    Map<int, String> dict1 = Map<int, String>.from(decryptConf["dict1"]);
    Map<int, String> dict2 = Map<int, String>.from(decryptConf["dict2"]);
    Map<int, String> dict3 = Map<int, String>.from(decryptConf["dict3"]);
    Map<int, String> dict4 = Map<int, String>.from(decryptConf["dict4"]);
    Map<int, String> dict5 = Map<int, String>.from(decryptConf["dict5"]);
    List<int> roundConstants = List<int>.from(decryptConf["round_constants"]);

    List<List<int>> state = addRoundKeys(
        textToMatrix(inputNum), 
        mkeySchedule.sublist(0, 4), 
        (i) => keySchedule[i]
    );

    List<Map<String, dynamic>> keyTemplates = [
      {'template': dict1, 'indices': [0, 8, 16, 24]},
      {'template': dict2, 'indices': [26, 2, 10, 18]},
      {'template': dict3, 'indices': [20, 28, 4, 12]},
      {'template': dict4, 'indices': [14, 22, 30, 6]},
    ];

    List<List<List<int>>> states = [];
    for (var t in keyTemplates) {
      String newKey = buildKey(t['template'], List<int>.from(t['indices']), stateToHex(state));
      states.add(textToMatrix(BigInt.parse(newKey, radix: 16)));
    }

    for (int i = 1; i < 10; i++) {
      state = subBytes(sBox, states[0], states[1]);
      state = shiftRows(sBox, state, states[2]);
      state = mixColumns(sBox, state, states[3]);
      state = addRoundKeys(state, mkeySchedule.sublist(4 * i, 4 * (i + 1)), (i) => sBox[i]);

      if (i != 9) {
        states = [];
        for (var t in keyTemplates) {
          String newKey = buildKey(t['template'], List<int>.from(t['indices']), stateToHex(state));
          states.add(textToMatrix(BigInt.parse(newKey, radix: 16)));
        }
      }
    }

    List<int> finalIndices = [0, 26, 20, 14, 8, 2, 28, 22, 16, 10, 4, 30, 24, 18, 12, 6];
    StringBuffer newKeyBuffer = StringBuffer();
    String stateHex = stateToHex(state);
    for (int i in finalIndices) {
      int value = int.parse(stateHex.substring(i, i + 2), radix: 16);
      newKeyBuffer.write(dict5[value]);
    }

    state = textToMatrix(BigInt.parse(newKeyBuffer.toString(), radix: 16));
    state = addRoundKeys(state, mkeySchedule.sublist(40, 44), (i) => roundConstants[i]);
    return state;
  }

  /// AES解密函数
  String aesDecrypt(List<String> roundKeys, String inputHex, String ivHex) {
    BigInt inputBytes = BigInt.parse(inputHex, radix: 16);
    List<List<int>> mkeySchedule = [];
    
    for (String roundKey in roundKeys) {
      List<int> bytesData = hexToBytes(roundKey);
      for (int i = 0; i < bytesData.length; i += 4) {
        mkeySchedule.add(bytesData.sublist(i, i + 4));
      }
    }
    
    List<List<int>> plainState = decrypt(inputBytes, mkeySchedule);
    String plainText = stateToHex(plainState);

    BigInt decryptedBlockInt = BigInt.parse(plainText, radix: 16);
    BigInt prevBlockInt = BigInt.parse(ivHex, radix: 16);
    BigInt plainBlockInt = decryptedBlockInt ^ prevBlockInt;
    String plainBlockHex = plainBlockInt.toRadixString(16).padLeft(32, '0');
    logDebug('Decrypted: $plainBlockHex');
    return plainBlockHex;
  }

  /// 创建预绑定的加密函数
  String Function(String) createEncryptor(String key, dynamic iv, {bool isBinaryOutput = false}) {
    Map<String, dynamic> encryptConf = getEncryptConf();
    
    // 预先计算并转换IV
    String ivHex = transformIv(iv, List<int>.from(encryptConf["iv_arr"]));
    
    // 预先生成轮密钥
    List<String> roundKeys = generateRoundKeys(key);
    
    // 返回只需要input_data的函数
    return (String inputData) {
      List<int> bytesData = padData(List<int>.from(transform(
          Uint8List.fromList(utf8.encode(inputData)), 
          List<int>.from(encryptConf["input_arr"])
      )));
      String inputHex = bytesToHex(bytesData);
      
      List<String> blocks = [];
      for (int i = 0; i < inputHex.length; i += 32) {
        blocks.add(inputHex.substring(i, i + 32));
      }
      
      List<String> signatures = [];
      String currentIv = ivHex;
      
      for (String block in blocks) {
        String signature = aesEncrypt(roundKeys, block, currentIv);
        signatures.add(signature);
        currentIv = signature;
      }
      
      List<int> finalBytes = hexToBytes(signatures.join(''));
      Uint8List transformed = transform(finalBytes, List<int>.from(encryptConf["out_arr"]));
      // 根据 isBinaryOutput 参数决定返回格式
      if (isBinaryOutput) {
        return String.fromCharCodes(transformed);
      } else {
        return base64Encode(transformed);
      }
    };
  }

  /// 创建预绑定的解密函数
  String Function(String) createDecryptor(String key, dynamic iv, {bool isBinaryInput = false}) {
    Map<String, dynamic> decryptConf = getDecryptConf();
    
    // 预先计算并转换IV
    String ivHex = transformIv(iv, List<int>.from(decryptConf["iv_arr"]));
    
    // 预先生成轮密钥
    List<String> roundKeys = generateRoundKeys(key);
    
    // 返回只需要input_data的函数
    return (String inputData) {
    // 根据 isBinaryInput 参数决定是否先 Base64 解码输入
    List<int> inputBytes;
    if (isBinaryInput) {
      inputBytes = inputData.codeUnits;
    } else {
      inputBytes = base64Decode(inputData);
    }
      Map<String, dynamic> processResult = processInput(Uint8List.fromList(inputBytes));
      Uint8List bytesData = processResult['data'];
      int dataLen = processResult['length'];
      String inputHex = bytesToHex(bytesData);
      
      List<String> blocks = [];
      for (int i = 0; i < inputHex.length; i += 32) {
        blocks.add(inputHex.substring(i, i + 32));
      }
      
      List<String> signatures = [];
      String currentIv = ivHex;
      
      for (String block in blocks) {
        String signature = aesDecrypt(roundKeys, block, currentIv);
        signatures.add(signature);
        currentIv = block;
      }
      
      String finalPlaintextHex = signatures.join('');
      List<int> plaintextBytes = [];
      for (int i = 0; i < finalPlaintextHex.length; i += 2) {
        plaintextBytes.add(int.parse(finalPlaintextHex.substring(i, i + 2), radix: 16));
      }
      
      int adjustedLength = calculateAdjustedLength(Uint8List.fromList(plaintextBytes), bytesData.length);
      Uint8List transformed = processOut(Uint8List.fromList(plaintextBytes.sublist(0, adjustedLength)), dataLen);
      return utf8.decode(transformed);
    };
  }
}