import hmac
import hashlib
from typing import Optional

def hmac_sha1(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA1 哈希计算"""
    return hmac.new(key, message, hashlib.sha1).digest()

def bytes_to_hex(binary: bytes) -> str:
    """字节转16进制字符串"""
    return binary.hex()

def generate_zhihu_signature(
    api_version: str,
    uuid: Optional[str],
    backup_device_id: Optional[str],
    device_info: str,
    client_id: str,
    timestamp: str,
    secret_key: str
) -> str:
    """
    生成知乎API签名
    
    :param api_version: API版本号 (如 "2")
    :param uuid: uuid (可能为空)
    :param backup_device_id: 备用设备ID
    :param device_info: 设备信息
    :param client_id: 客户端标识 (如 "1355")
    :param timestamp: 请求时间戳
    :param secret_key: 加密密钥
    :return: 40位SHA1签名 (小写16进制)
    """
    # 确定签名拼接模式
    if not uuid:
        signature_base = (
            f"{client_id}{api_version}{device_info}{timestamp}"
            if not backup_device_id else
            f"{client_id}{backup_device_id}{device_info}{timestamp}"
        )
    else:
        signature_base = f"{client_id}{api_version}{device_info}{uuid}{timestamp}"

    # 计算签名
    signature = hmac_sha1(
        key=secret_key.encode('utf-8'),
        message=signature_base.encode('utf-8')
    )
    
    return bytes_to_hex(signature)

from urllib.parse import urlencode, quote
# com.zhuhu.android.cloudid.model.DeviceInfo
def generate_zhihu_formdata():
    params_dict = {
        # app版本号
        "app_build": "21210",
        # 一般都是这个值
        "app_ticket": "fetch empty",
        # app版本名
        "app_version": "10.12.0",
        # 蓝牙是否开启 0未开启 1开启
        "bt_ck": "1",
        # app包名
        "bundle_id": "com.zhihu.android",
        # cpu数量
        "cp_ct": "8",
        # cpu频率
        "cp_fq": "3532800",
        # 读取/proc/cpuinfo文件第一行数字内容
        "cp_tp": "0",
        # cpu使用率 (知乎写的有问题 有概率Infinity)
        # 读取 /proc/stat 获取系统总CPU使用时间 读取 /proc/[pid]/stat 获取本进程CPU使用时间 * - 间隔10ms测量两次 计算进程占用CPU的相对比例
        "cp_us": "Infinity",
        # 蓝牙设备名
        "d_n": "PKR110",
        # jvm虚拟机剩余内存(Mb)
        "fr_mem": "0",
        # 使用StatFS 获取内部存储剩余空间
        "fr_st": "162081",
        # 经纬度
        "latitude": "0.0",
        # 经纬度
        "longitude": "0.0",
        # 国家
        "mcc": "cn",
        # 是否开启通知权限
        "nt_st": "0",
        # oaid
        "oaid": "A8974DDF490149FFBD6ECB3FB5E7BF9223e1e9b1f6f987bd398af8869de9d67d",
        # 手机品牌
        "ph_br": "OnePlus",
        # 手机型号
        "ph_md": "PKR110",
        # 安卓版本
        "ph_os": "Android 15",
        # 手机序列号
        "ph_sn": "unknown",
        "pre_install": "undefined",
        # 运营商
        "pvd_nm": "中国移动",
        "tt_mem": "182",
        # 使用StatFS 获取内存剩余空间
        "tt_st": "470233",
        # 获取时区秒数
        "tz_of": "28800",
        # 一般都是0
        "zx_expired": "0"
    }
    
    return urlencode(params_dict, doseq=True, quote_via=quote)

if __name__ == "__main__":
    # 测试用例
    test_signature = generate_zhihu_signature(
        api_version="2",
        uuid="T7DT9CGe3xpLBQJJcE6uMbhRvUE_WO5JI94=",
        backup_device_id=None,
        device_info=generate_zhihu_formdata(),
        client_id="1355",
        timestamp="1754463834",
        secret_key="dd49a835-56e7-4a0f-95b5-efd51ea5397f"
    )
    
    expected_signature = "d7118b914760ecd953ebfd852675c9cef3417f61"
    print(f"Generated signature: {test_signature}")
    print(f"Verification: {'PASS' if test_signature == expected_signature else 'FAIL'}")