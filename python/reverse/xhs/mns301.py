import base64
import hashlib
import json
import math
import random


class XhsSigner:
    def __init__(self):
        # S-Box (RC4 Key State)
        self.S_BOX = [
            108, 71, 200, 252, 102, 41, 228, 110, 198, 188, 243, 68, 179, 10, 96, 53,
            237, 46, 115, 61, 74, 185, 19, 217, 133, 212, 167, 205, 55, 111, 146, 116,
            201, 67, 151, 202, 229, 25, 178, 135, 235, 69, 112, 52, 195, 144, 78, 203,
            0, 83, 33, 231, 181, 140, 43, 175, 142, 248, 148, 145, 162, 187, 76, 88,
            2, 22, 77, 105, 16, 164, 139, 147, 124, 246, 121, 120, 176, 224, 44, 251,
            194, 31, 169, 218, 189, 95, 253, 155, 45, 223, 24, 150, 106, 249, 186, 126,
            23, 209, 191, 250, 92, 4, 90, 51, 21, 193, 196, 226, 183, 3, 210, 34, 114,
            129, 168, 99, 79, 15, 127, 40, 208, 32, 30, 27, 190, 1, 29, 220, 14, 156,
            119, 100, 60, 138, 214, 58, 234, 173, 87, 131, 104, 93, 221, 233, 57, 9,
            240, 75, 117, 177, 215, 152, 98, 232, 89, 174, 122, 38, 85, 8, 206, 94,
            70, 6, 109, 128, 5, 80, 18, 160, 182, 26, 101, 149, 28, 171, 72, 227, 64,
            137, 222, 199, 244, 219, 13, 225, 97, 184, 103, 241, 180, 165, 132, 161, 7,
            107, 39, 73, 170, 17, 130, 192, 236, 66, 118, 134, 211, 81, 153, 207, 20,
            197, 82, 48, 154, 254, 247, 56, 113, 143, 62, 172, 125, 49, 245, 230, 242,
            12, 65, 11, 36, 37, 63, 84, 238, 50, 86, 35, 141, 159, 47, 239, 204, 216,
            91, 59, 123, 54, 157, 158, 166, 255, 42, 163, 213, 136
        ]

        # 自定义 Base64 字典表
        self.B64_ALPHABET = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"

        # Signature 生成所需的源数组 (dssts source)
        self.SIGN_SOURCE = [115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21]

        # Signature XOR 密钥表
        self.SIGN_KEYS = [215, 1, 18, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]

    def _int_to_le_bytes(self, val, length=4):
        return [(val >> (8 * i)) & 0xFF for i in range(length)]

    def generate_random_seed(self):
        # 生成一个 0 到 4294967295 之间的随机整数
        random_value = random.random() * (2 ** 32 - 1)
        random_timestamp = int(random_value)
        return random_timestamp

    def make_payload(self, uri, a1, loadts, sequence, random_seed, new_timestamp, xor_key=41):
        payload = []

        # --- 1. Header ---
        header = [119, 104, 96, 41]
        payload.extend(header)

        # --- 2. Timestamp (Random Seed) ---
        ts_bytes = self._int_to_le_bytes(random_seed, 4)
        ts_byte0 = ts_bytes[0]
        payload.extend(ts_bytes)

        # --- 3. Env Fingerprint A ---
        # 使用新时间戳计算 Env Fingerprint A 部分的8个字节
        result = new_timestamp % (2 ** 32)
        bytes_ts = list(result.to_bytes(4, byteorder='little'))
        calculated_result = [b ^ xor_key for b in bytes_ts]

        # 获取 t1 和其字节
        t1 = math.floor(new_timestamp / (2 ** 32))
        t1_bytes = list(t1.to_bytes(4, byteorder='little'))
        t1_result = [b ^ xor_key for b in t1_bytes]

        # 校验和计算（后三位字节相加）
        checksum = sum(bytes_ts[1:4]) % 256
        final_value = (checksum + t1_bytes[0] + t1_bytes[1]) % 256
        modified_first_byte = final_value ^ xor_key

        # 替换 calculated_result 的第一个字节
        calculated_result[0] = modified_first_byte

        # 拼接最终结果
        final_result = calculated_result + t1_result
        payload.extend(final_result)

        # --- 4. 其它数据部分 ---

        env_b_val = list(loadts.to_bytes(8, byteorder='little'))
        payload.extend(env_b_val)

        # --- 5. Sequence ---
        payload.extend(self._int_to_le_bytes(sequence, 4))

        # --- 6. Size A ---
        payload.extend(self._int_to_le_bytes(1314, 4))  # 1312 是windows元素数量，会变化。Object.getOwnPropertyNames(window);

        # --- 7. Size B ---
        uri_bytes = uri.encode('utf-8')
        payload.extend(self._int_to_le_bytes(len(uri_bytes), 4))

        # --- 8. MD5 XOR ---
        md5_str = hashlib.md5(uri_bytes).hexdigest()
        md5_part = md5_str[:16]
        for i in range(0, len(md5_part), 2):
            val = int(md5_part[i:i + 2], 16)
            payload.append(val ^ ts_byte0)

        # --- 9. A1 Cookie ---
        a1_bytes = list(a1.encode('utf-8'))
        payload.append(len(a1_bytes))
        payload.extend(a1_bytes)

        # --- 10. AppID ---
        app_id = "xhs-pc-web"
        app_bytes = list(app_id.encode('utf-8'))
        payload.append(len(app_bytes))
        payload.extend(app_bytes)

        # --- 11. Signature ---
        sig_final = [1]
        current_keys = [ts_byte0] + self.SIGN_KEYS[1:]
        for i in range(len(self.SIGN_SOURCE)):
            val = self.SIGN_SOURCE[i] ^ current_keys[i]
            sig_final.append(val)

        payload.extend(sig_final)

        return payload

    def rc4_encrypt(self, data):
        s = self.S_BOX[:]
        i = 0
        j = 0
        res = []
        for byte in data:
            i = (i + 1) % 256
            a = s[i]
            j = (j + a) % 256
            b = s[j]
            s[i] = b
            s[j] = a
            k = s[(a + b) % 256]
            res.append(byte ^ k)
        return res

    def custom_base64_encode(self, input_bytes):
        result = []
        length = len(input_bytes)
        for i in range(0, length, 3):
            b1 = input_bytes[i]
            b2 = input_bytes[i + 1] if i + 1 < length else 0
            b3 = input_bytes[i + 2] if i + 2 < length else 0
            triple = (b1 << 16) | (b2 << 8) | b3
            idx1 = (triple >> 18) & 0x3F
            idx2 = (triple >> 12) & 0x3F
            idx3 = (triple >> 6) & 0x3F
            idx4 = triple & 0x3F
            result.append(self.B64_ALPHABET[idx1])
            result.append(self.B64_ALPHABET[idx2])
            result.append(self.B64_ALPHABET[idx3] if i + 1 < length else "=")
            result.append(self.B64_ALPHABET[idx4] if i + 2 < length else "=")
        return "".join(result)

    def sign_request(self, uri, a1, loadts, sequence, random_seed, new_timestamp):
        # 组装
        payload = self.make_payload(uri, a1, loadts, sequence, random_seed, new_timestamp)
        print(payload)
        # 加密
        encrypted = self.rc4_encrypt(payload)
        # 编码
        encoded = self.custom_base64_encode(encrypted)
        return f"mns0301_{encoded}"

    def get_xys_sign(self, x3):
        """
        data_dict: 对应 JS 中的变量 f (包含 x0, x1, x2, x3 等)
        """
        f = {
            "x0": '4.2.6',
            "x1": "xhs-pc-web",
            "x2": "Windows",
            "x3": x3,
            "x4": "object"
        }
        # 1. 序列化 (对应 JSON.stringify)
        # 注意：JS 的 JSON.stringify 产生的中文是 UTF-8 格式，且通常没有空格
        json_str = json.dumps(f, separators=(',', ':'), ensure_ascii=False)

        # 2. 转字节 (对应 encodeUtf8)
        byte_data = json_str.encode('utf-8')

        # 3. 标准 Base64 编码
        std_b64 = base64.b64encode(byte_data).decode('utf-8')

        # 4. 码表映射
        # 标准码表
        std_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        # 自定义码表
        custom_table = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"

        # 创建映射关系
        trans_table = str.maketrans(std_table, custom_table)

        # 5. 替换字符并拼接前缀
        final_sign = "XYS_" + std_b64.translate(trans_table)

        return final_sign


# ==========================================
# 验证脚本
# ==========================================
if __name__ == "__main__":
    # 参数准备
    uri_param = '/api/sns/web/v1/feed{"source_note_id":"692eaaac000000001f00efce","image_formats":["jpg","webp","avif"],"extra":{"need_body_topic":"1"},"xsec_source":"pc_feed","xsec_token":"xxxxxxxxx"}'
    a1_cookie = "19xxxxxxxxxxxxxxxxxxxxxxxxxxx"  # cookie中获取
    loadts = 1764672165088  # cookie中获取
    current_sequence = 59  # window.sessionStorage.getItem('sc')基础之上加1
    current_random_seed = 2138369300  # 随机值
    current_new_timestamp = 1764741525595  # 新的时间戳,当前时间

    signer = XhsSigner()
    xs_value = signer.sign_request(
        uri=uri_param,
        a1=a1_cookie,
        loadts=loadts,
        sequence=current_sequence,
        random_seed=current_random_seed,
        new_timestamp=current_new_timestamp
    )

    print(f"Generated X-s: {xs_value}")


    x_s = signer.get_xys_sign(xs_value)
    print(x_s)

