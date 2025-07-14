from mitmproxy import http
import json
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import binascii
deskey='31113001'
def jsonjiami(message: str, deskey: str=deskey) -> str:
    """
    DES-CBC 加密函数 (对应 JsonJiaMi)
    :param message: 要加密的字符串
    :param deskey: 密钥字符串 (长度必须为8字节)
    :return: Base64 编码的加密结果
    """
    # 处理密钥和初始向量（使用UTF-8编码，截断/填充至8字节）
    key_bytes = deskey.encode('utf-8')[:8].ljust(8, b'\0')[:8]
    iv_bytes = key_bytes  # 与密钥相同
    
    # 准备明文数据（PKCS#7填充）
    padded_data = pad(message.encode('utf-8'), 8)
    
    # 创建加密器并执行加密
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
    encrypted_bytes = cipher.encrypt(padded_data)
    
    # 转换为Base64字符串（模拟JS的转换流程）
    hex_str = encrypted_bytes.hex().upper()
    base64_str = base64.b64encode(bytes.fromhex(hex_str)).decode('utf-8')
    
    return base64_str

def jsonjiemi(message: str, deskey: str=deskey) -> str:
    """
    DES-CBC 解密函数 (对应 JsonJieMi)
    :param message: Base64 编码的加密字符串
    :param deskey: 密钥字符串 (长度必须为8字节)
    :return: 解密后的原始字符串（解密失败返回原始输入）
    """
    try:
        # 处理密钥和初始向量
        key_bytes = deskey.encode('utf-8')[:8].ljust(8, b'\0')[:8]
        iv_bytes = key_bytes  # 与密钥相同
        
        # Base64 解码并转换为字节
        decoded_bytes = base64.b64decode(message)
        
        # 创建解密器并执行解密
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)
        decrypted_bytes = cipher.decrypt(decoded_bytes)
        
        # 移除PKCS#7填充并返回UTF-8字符串
        result = unpad(decrypted_bytes, 8).decode('utf-8')
        return result
    
    except (binascii.Error, UnicodeDecodeError, ValueError):
        # 捕获所有可能的异常：Base64解码错误、填充错误、解码失败等
        return message


class ServerSideProxy:
    def request(self, flow: http.HTTPFlow):
        """加密Burp Suite的请求，转发给服务器"""
        if flow.request.method == "POST" and "/WebService/wxPublicInterface.asmx/IoControl" in flow.request.path:
            try:
                content_type = flow.request.headers.get("Content-Type", "")
                
                # 处理JSON格式
                if "application/json" in content_type:

                    json_body = json.loads(flow.request.get_text())
                    if 'DESJson' in json_body and json_body['DESJson']:
                        encrypted = jsonjiami(json_body['DESJson'])
                        json_body['DESJson'] = encrypted
                        flow.request.text = json.dumps(json_body)
                        print(f"[服务器代理] JSON请求加密成功")

                
                # 恢复原始Content-Type
                if content_type:
                    flow.request.headers["Content-Type"] = content_type
                    
            except Exception as e:
                print(f"[服务器代理] 请求加密错误: {str(e)}")

    def response(self, flow: http.HTTPFlow):
        """解密服务器响应，转发给Burp Suite"""
        if flow.request.method == "POST" and "/WebService/wxPublicInterface.asmx/IoControl" in flow.request.path:
            try:
                content_type = flow.response.headers.get("Content-Type", "")
                
                if "application/json" in content_type:
                    json_body = json.loads(flow.response.get_text())
                    
                    if 'd' in json_body and json_body['d']:
                        decrypted = jsonjiemi(json_body['d'])
                        json_body['d'] = decrypted
                        flow.response.text = json.dumps(json_body)
                        print(f"[服务器代理] 响应解密成功: {decrypted[:100]}...\n")
                
                # 恢复原始Content-Type
                if content_type:
                    flow.response.headers["Content-Type"] = content_type
                    
            except Exception as e:
                print(f"[服务器代理] 响应解密错误: {str(e)}")

addons = [ServerSideProxy()]