from capstone import (
    CS_MODE_64, CS_MODE_32, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_MIPS, CS_ARCH_ARM64,
)

from unicorn.unicorn_const import (
    UC_MODE_MIPS32, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_BIG_ENDIAN,
    UC_MODE_LITTLE_ENDIAN, UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_ARM64,
)

from unicorn.x86_const import (
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
    UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
    UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_AL, UC_X86_REG_AH, UC_X86_REG_AX,
    UC_X86_REG_EAX, UC_X86_REG_BL, UC_X86_REG_BH, UC_X86_REG_BX, UC_X86_REG_EBX,
    UC_X86_REG_CL, UC_X86_REG_CH, UC_X86_REG_CX,UC_X86_REG_ECX, UC_X86_REG_DL,
    UC_X86_REG_DH, UC_X86_REG_DX, UC_X86_REG_EDX
)

from unicorn.arm_const import (
    UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
    UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR,
    UC_ARM_REG_CPSR, UC_ARM_REG_PC
)

from unicorn.arm64_const import (
    UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7, UC_ARM64_REG_X8,
    UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12, UC_ARM64_REG_X13,
    UC_ARM64_REG_X14, UC_ARM64_REG_X15, UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18,
    UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28,
    UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_NZCV, UC_ARM64_REG_PC
)

from unicorn.mips_const import (
    UC_MIPS_REG_SP, UC_MIPS_REG_V0, UC_MIPS_REG_V1, UC_MIPS_REG_A0, UC_MIPS_REG_A1,
    UC_MIPS_REG_A2, UC_MIPS_REG_A3, UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2,
    UC_MIPS_REG_T3, UC_MIPS_REG_T4, UC_MIPS_REG_T5, UC_MIPS_REG_T6, UC_MIPS_REG_T7,
    UC_MIPS_REG_T8, UC_MIPS_REG_T9, UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S2,
    UC_MIPS_REG_S3, UC_MIPS_REG_S4, UC_MIPS_REG_S5, UC_MIPS_REG_S6, UC_MIPS_REG_S7,
    UC_MIPS_REG_GP, UC_MIPS_REG_FP, UC_MIPS_REG_PC
)

from binaryninja import log_info

# ERR
GA_ERR_NULL = 1
GA_ERR_WRITE = 2
GA_ERR_READ = 3
GA_ERR_FETCH = 4
GA_ERR_READ_UNMAPPED = 5
GA_ERR_READ_UNRESOLVED = 11
GA_ERR_WRITE_UNMAPPED = 6
GA_ERR_WRITE_UNRESOLVED = 12
GA_ERR_FETCH_UNMAPPED = 7
GA_ERR_FETCH_UNRESOLVED = 13
GA_ERR_WRITE_PROT = 8
GA_ERR_FETCH_PROT = 9
GA_ERR_READ_PROT = 10
GA_ERR_UNKNOWN = 14
GA_ERR_RECURSION = 15
GA_ERR_INTR = 16

# SENTINELS
REG_NOT_ANALYZED = 0xdeadcafebeefbabe
REG_CONTROLLED = 0xcafedeadbabebeef

err_desc = {
    GA_ERR_NULL:'Null dereference occured',
    GA_ERR_WRITE:'Invalid write',
    GA_ERR_READ:'Invalid read',
    GA_ERR_FETCH:'Invalid fetch',
    GA_ERR_READ_UNMAPPED:'Attempt to read unmapped memory',
    GA_ERR_READ_UNRESOLVED:'Error reading from location',
    GA_ERR_WRITE_UNMAPPED:'Attempt to write to unmapped memory',
    GA_ERR_WRITE_UNRESOLVED:'Error writing to location',
    GA_ERR_FETCH_UNMAPPED:'Gadget branching is not supported',
    GA_ERR_WRITE_PROT:'Attempt to write to non-writable memory',
    GA_ERR_FETCH_PROT:'Attempt to execute non-executable memory',
    GA_ERR_READ_PROT:'Attempt to read non-readable memory',
    GA_ERR_UNKNOWN:'An unknown error stopped analysis',
    GA_ERR_RECURSION:'Maximum recursion reached while following dereferences',
    GA_ERR_INTR:'Interrupts cannot be emulated by analysis'
}

i386 = {
    'bitmode':32,
    # Tokens for string parsing
    # List registers by least significant access first
    'registers':['ax','bx','cx','dx','ah','al','bh','bl','ch','cl','dh','dl','eax','ebx','ecx','edx','esi','edi','ebp'],
    'sp':['esp'],
    'pc':['eip'],
    'prestateOpts':['eax','ebx','ecx','edx','esi','edi','ebp'],
    'presets':{
        'stack_pivot':'disasm.str.contains("pop esp") or disasm.str.contains("xchg esp, [a-z0-9]{2,3}") or disasm.str.contains("xchg [a-z0-9]{2,3}, esp")',
        'ppr':'(disasm.str.count("pop")==2 and disasm.str.contains("ret") and inst_cnt==3)',
        'jmp_reg':'disasm.str.contains("jmp [a-z0-9]{2,3} ;")'
    },
    'blacklist':['int1', 'int3','int 1','int 3','loop','xmm','zmm','ymm'],
    'uregs':{
        'sp':UC_X86_REG_ESP,
        'al':UC_X86_REG_AL,
        'ah':UC_X86_REG_AH,
        'ax':UC_X86_REG_AX,
        'eax':UC_X86_REG_EAX,
        'bl':UC_X86_REG_BL,
        'bh':UC_X86_REG_BH,
        'bx':UC_X86_REG_BX,
        'ebx':UC_X86_REG_EBX,
        'cl':UC_X86_REG_CL,
        'ch':UC_X86_REG_CH,
        'cx':UC_X86_REG_CX,
        'ecx':UC_X86_REG_ECX,
        'dl':UC_X86_REG_DL,
        'dh':UC_X86_REG_DH,
        'dx':UC_X86_REG_DX,
        'edx':UC_X86_REG_EDX,
        'esi':UC_X86_REG_ESI,
        'edi':UC_X86_REG_EDI,
        'ebp':UC_X86_REG_EBP,
        'esp':UC_X86_REG_ESP,
        'eip':UC_X86_REG_EIP
    },
    'upc':UC_X86_REG_EIP,
    'loweraccess':{
        'eax':['ax','ah','al'],
        'ebx':['bx','bh','bl'],
        'ecx':['cx','ch','cl'],
        'edx':['dx','dh','dl'],
        'ebp':['bp'],
        'esi':['si'],
        'edi':['di']
    },
    'alignment':1,
    'delay_slot':False
}

amd64 = {
    'bitmode':64,
    'registers':i386['registers'] + ['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15'],
    'sp':['rsp','esp'],
    'pc':['rip','eip'],
    'prestateOpts':['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15'],
    'presets':{
        'stack_pivot':'disasm.str.contains("pop [re]sp") or disasm.str.contains("xchg [re]sp, [a-z0-9]{2,3}") or disasm.str.contains("xchg [a-z0-9]{2,3}, [re]sp")',
        'execve':'(disasm.str.contains("syscall") and inst_cnt==1) or rax==0x3b or rdi==0xdeadbeef or rsi==0 or rdx==0',
        'ppr':'(disasm.str.count("pop")==2 and disasm.str.contains("ret") and inst_cnt==3)',
        'jmp_reg':'disasm.str.contains("jmp [a-z0-9]{2,3} ;")',
        'csu':'disasm.str.contains("pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15")',
        'srop':'rax==0xf or (disasm.str.contains("syscall") and inst_cnt==1)'
    },
    'blacklist':['int1','int3','int 1','int 3','loop','ymm','zmm','xmm'],
    'uregs':{
        'sp':UC_X86_REG_RSP,
        'rax':UC_X86_REG_RAX,
        'rbx':UC_X86_REG_RBX,
        'rcx':UC_X86_REG_RCX,
        'rdx':UC_X86_REG_RDX,
        'rsi':UC_X86_REG_RSI,
        'rdi':UC_X86_REG_RDI,
        'rbp':UC_X86_REG_RBP,
        'rsp':UC_X86_REG_RSP,
        'r8':UC_X86_REG_R8,
        'r9':UC_X86_REG_R9,
        'r10':UC_X86_REG_R10,
        'r11':UC_X86_REG_R11,
        'r12':UC_X86_REG_R12,
        'r13':UC_X86_REG_R13,
        'r14':UC_X86_REG_R14,
        'r15':UC_X86_REG_R15
    },
    'upc':UC_X86_REG_RIP,
    'loweraccess':{
        'rax':['eax','ax','ah','al'],
        'rbx':['ebx','bx','bh','bl'],
        'rcx':['ecx','cx','ch','cl'],
        'rdx':['edx','dx','dh','dl'],
        'rsi':['esi','si','sil'],
        'rdi':['edi','di','dil'],
        'rbp':['ebp','bp','bpl'],
        'r8':['r8d','r8w','r8b'],
        'r9':['r9d','r9w','r9b'],
        'r10':['r10d','r10w','r10b'],
        'r11':['r11d','r11w','r11b'],
        'r12':['r12d','r12w','r12b'],
        'r13':['r13d','r13w','r13b'],
        'r14':['r14d','r14w','r14b'],
        'r15':['r15d','r15w','r15b']
    },
    'alignment':1,
    'delay_slot':False
}
amd64['uregs'].update(i386['uregs'])

armv7 = {
    'bitmode':32,
    'registers':['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','lr'],
    'sp':['sp'],
    'pc':['pc'],
    'prestateOpts':['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','lr'],
    'presets':{},
    'blacklist':['ldrdeq ','strheq ','strdeq '],
    'uregs':{
        'sp':UC_ARM_REG_SP,
        'r0':UC_ARM_REG_R0,
        'r1':UC_ARM_REG_R1,
        'r2':UC_ARM_REG_R2,
        'r3':UC_ARM_REG_R3,
        'r4':UC_ARM_REG_R4,
        'r5':UC_ARM_REG_R5,
        'r6':UC_ARM_REG_R6,
        'r7':UC_ARM_REG_R7,
        'r8':UC_ARM_REG_R8,
        'r9':UC_ARM_REG_R9,
        'r10':UC_ARM_REG_R10,
        'r11':UC_ARM_REG_R11,
        'r12':UC_ARM_REG_R12,
        'lr':UC_ARM_REG_LR,
        'cpsr':UC_ARM_REG_CPSR,
        'pc':UC_ARM_REG_PC
    },
    'upc':UC_ARM_REG_PC,
    'loweraccess':{},
    'alignment':4,
    'delay_slot':False
}

aarch64 = {
    'bitmode':64,
    'registers':['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','x29','x30'],
    'sp':['x29'],
    'pc':['x30'],
    'prestateOpts':['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','x11','x12','x13','x14','x15','x16','x17','x18','x19','x20','x21','x22','x23','x24','x25','x26','x27','x28'],
    'presets':{},
    'blacklist':[],
    'uregs':{
        'sp':UC_ARM64_REG_SP,
        'x0':UC_ARM64_REG_X0,
        'x1':UC_ARM64_REG_X1,
        'x2':UC_ARM64_REG_X2,
        'x3':UC_ARM64_REG_X3,
        'x4':UC_ARM64_REG_X4,
        'x5':UC_ARM64_REG_X5,
        'x6':UC_ARM64_REG_X6,
        'x7':UC_ARM64_REG_X7,
        'x8':UC_ARM64_REG_X8,
        'x9':UC_ARM64_REG_X9,
        'x10':UC_ARM64_REG_X10,
        'x11':UC_ARM64_REG_X11,
        'x12':UC_ARM64_REG_X12,
        'x13':UC_ARM64_REG_X13,
        'x14':UC_ARM64_REG_X14,
        'x15':UC_ARM64_REG_X15,
        'x16':UC_ARM64_REG_X16,
        'x17':UC_ARM64_REG_X17,
        'x18':UC_ARM64_REG_X18,
        'x19':UC_ARM64_REG_X19,
        'x20':UC_ARM64_REG_X20,
        'x21':UC_ARM64_REG_X21,
        'x22':UC_ARM64_REG_X22,
        'x23':UC_ARM64_REG_X23,
        'x24':UC_ARM64_REG_X24,
        'x25':UC_ARM64_REG_X25,
        'x26':UC_ARM64_REG_X26,
        'x27':UC_ARM64_REG_X27,
        'x28':UC_ARM64_REG_X28,
        'x29':UC_ARM64_REG_X29,
        'x30':UC_ARM64_REG_X30,
        'cpsr':UC_ARM64_REG_NZCV,
        'pc':UC_ARM64_REG_PC
    },
    'upc':UC_ARM64_REG_X30,
    'loweraccess':{
        'x0':['w0'],
        'x1':['w1'],
        'x2':['w2'],
        'x3':['w3'],
        'x4':['w4'],
        'x5':['w5'],
        'x6':['w6'],
        'x7':['w7'],
        'x8':['w8'],
        'x9':['w9'],
        'x10':['w10'],
        'x11':['w11'],
        'x12':['w12'],
        'x13':['w13'],
        'x14':['w14'],
        'x15':['w15'],
        'x16':['w16'],
        'x17':['w17'],
        'x18':['w18'],
        'x19':['w19'],
        'x20':['w20'],
        'x21':['w21'],
        'x22':['w22'],
        'x23':['w23'],
        'x24':['w24'],
        'x25':['w25'],
        'x26':['w26'],
        'x27':['w27'],
        'x28':['w28'],
        'x29':['w29'],
        'x30':['w30']
    },
    'alignment':4,
    'delay_slot':False
}

# https://stackoverflow.com/questions/21512801/mips32-and-mips64-instructions
mipsel32 = {
    'bitmode':32,
    'registers':['$v0','$v1','$a0','$a1','$a2','$a3','$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7','$t8','$t9','$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7','$gp','$fp'],
    'sp':['$sp'],
    'pc':['$pc'],
    'prestateOpts':['$v0','$v1','$a0','$a1','$a2','$a3','$t0','$t1','$t2','$t3','$t4','$t5','$t6','$t7','$t8','$t9','$s0','$s1','$s2','$s3','$s4','$s5','$s6','$s7','$gp','$fp'],
    'presets':{
        # From ROPgadget https://github.com/JonathanSalwan/ROPgadget/blob/90d9ff7223bdc8064b437045dec1dbd270043698/ropgadget/core.py#L126
        'stackfinder': r'disasm.str.contains("addiu [^;]*, \\$sp")',
        'system':'disasm.str.contains("addiu $a0, $sp", regex=False) or $a0==0xdeadbeef',
        'tails':'disasm.str.contains("lw [$]t[0-9], 0x[0-9a-z]{0,4}[(][$]s[0-9][)]") or disasm.str.contains("move $t9,", regex=False)',
        'lia0':r'disasm.str.contains("li \\$a0")',
        'registers':r'disasm.str.contains("lw \\$ra, 0x[0-9a-z]{0,4}\\(\\$sp\\)")',
        'sleep_a0':'$a0 > 0 and $a0 < 600'
    },
    'blacklist':[],
    'uregs':{
        'sp':UC_MIPS_REG_SP,
        '$sp':UC_MIPS_REG_SP,
        '$v0':UC_MIPS_REG_V0,
        '$v1':UC_MIPS_REG_V1,
        '$a0':UC_MIPS_REG_A0,
        '$a1':UC_MIPS_REG_A1,
        '$a2':UC_MIPS_REG_A2,
        '$a3':UC_MIPS_REG_A3,
        '$t0':UC_MIPS_REG_T0,
        '$t1':UC_MIPS_REG_T1,
        '$t2':UC_MIPS_REG_T2,
        '$t3':UC_MIPS_REG_T3,
        '$t4':UC_MIPS_REG_T4,
        '$t5':UC_MIPS_REG_T5,
        '$t6':UC_MIPS_REG_T6,
        '$t7':UC_MIPS_REG_T7,
        '$t8':UC_MIPS_REG_T8,
        '$t9':UC_MIPS_REG_T9,
        '$s0':UC_MIPS_REG_S0,
        '$s1':UC_MIPS_REG_S1,
        '$s2':UC_MIPS_REG_S2,
        '$s3':UC_MIPS_REG_S3,
        '$s4':UC_MIPS_REG_S4,
        '$s5':UC_MIPS_REG_S5,
        '$s6':UC_MIPS_REG_S6,
        '$s7':UC_MIPS_REG_S7,
        '$gp':UC_MIPS_REG_GP,
        '$fp':UC_MIPS_REG_FP,
        '$pc':UC_MIPS_REG_PC
    },
    'upc':UC_MIPS_REG_PC,
    'loweraccess':{},
    'alignment':4,
    'delay_slot':True
}

'''
i386, amd64
'''
cop_x86 = (
    (b'\xff',2,b'\xff[\x10\x11\x12\x13\x16\x17]','call'),					            # call [reg]
    # (b'\xf2\xff',3,b'\xf2\xff[\x10\x11\x12\x13\x16\x17]','call'),				        # bnd call [reg]
    (b'\xff',2,b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]','call'),				            # call reg
    # (b'\xf2\xff',3,b'\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]','call'),			        # bnd call reg
    (b'\xff\x14\x24',3,b'\xff\x14\x24','call'),						                    # call [rsp]
    # (b'\xf2\xff\x14\x24',4,b'\xf2\xff\x14\x24','call'),				                # bnd call [rsp]
    (b'\xff\x55\x00',3,b'\xff\x55\x00','call'),						                    # call [rbp]
    # (b'\xf2\xff\x55\x00',4,b'\xf2\xff\x55\x00','call'),					            # bnd call [rbp]
    (b'\xff',3,b'\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}','call'),				        # call [reg+n]
    # (b'\xf2\xff',4,b'\xf2\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}','call'),	            # bnd call [reg+n]
    (b'\xff',6,b'\xff[\x90\x91\x92\x93\x94\x96\x97][\x00-\x0ff]{4}','call')		        # call [reg+n]
)

rop_x86 = (
    (b'\xc3',1,b'\xc3','ret'),								                            # ret
    (b'\xc2',3,b'\xc2[\x00-\xff]{2}','ret')							                    # ret n
)

jop_x86 = (
    (b'\xff',2,b'\xff[\x20\x21\x22\x23\x26\x27]','jmp'),					            # jmp [reg]
    # (b'\xf2\xff',3,b'\xf2\xff[\x20\x21\x22\x23\x26\x27]','jmp'),				        # bnd jmp [reg]
    (b'\xff',2,b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]','jmp'),				            # jmp reg
    # (b'\xf2\xff',3,b'\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]','jmp'),			        # bnd jmp reg
    (b'\xff\x24\x24',3,b'\xff\x24\x24','jmp'),						                    # jmp [rsp]
    # (b'\xf2\xff\x24\x24',4,b'\xf2\xff\x24\x24','jmp'),					                # bnd jmp [rsp]
    (b'\xff\x65\x00',3,b'\xff\x65\x00','jmp'),						                    # jmp [rbp]
    # (b'\xf2\xff\x65\x00',4,b'\xf2\xff\x65\x00','jmp'),					                # bnd jmp [rbp]
    (b'\xff',6,b'\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}','jmp'),			        # jmp [reg+n]
    # (b'\xf2\xff',7,b'\xf2\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}','jmp'),        # bnd jmp [reg+n]
    (b'\xff\xa4\x24',7,b'\xff\xa4\x24[\x00-\xff]{4}','jmp'),				            # jmp [rsp+n]
    # (b'\xf2\xff\xa4\x24',8,b'\xf2\xff\xa4\x24[\x00-\xff]{4}','jmp'),			        # bnd jmp [rsp+n]
    (b'\xff',3,b'\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}','jmp')				            # jmp [reg+n]
    # (b'\xf2\xff',4,b'\xf2\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}','jmp')		        # bnd jmp [reg+n]
)

sys_x86 = (
    (b'\xcd\x80',2,b'\xcd\x80','int 0x80'),							                    # int 0x80
    (b'\x0f\x05',2,b'\x0f\x05','syscall'),						                    # syscall
    (b'\x0f\x34',2,b'\x0f\x34','sysenter'),						                    # sysenter
    (b'\x65\xff\x15\x10\x00\x00\x00',7,b'\x65\xff\x15\x10\x00\x00\x00','call gs:[10]')  # call gs:[10]
)

'''
armv7
'''
rop_armv7 = (
    (b'\xe8',4,b'[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe]\xe8','pop'),  # pop {[reg]*,pc} LE
    (b'\xe9',4,b'[\x00-\xff][\x80-\xff][\x10-\x1e\x30-\x3e\x50-\x5e\x70-\x7e\x90-\x9e\xb0-\xbe\xd0-\xde\xf0-\xfe]\xe9','ldm')  # ldm [reg], {*,pc} LE
)

jop_armv7 = (
    (b'\xff\x2f\xe1',4,b'[\x10-\x1e]\xff\x2f\xe1','bx'),  # bx reg LE
    (b'\xff\x2f\xe1',4,b'[\x30-\x3e]\xff\x2f\xe1','blx'),  # blx reg LE
    (b'\xf0\xa0\xe1',4,b'[\x00-\x0f]\xf0\xa0\xe1','mov'),  # mov pc, reg LE
    (b'\x01\x80\xdb\xe8',4,b'\x01\x80\xdb\xe8','ldm')  # ldm sp!, {pc} LE
)
'''
thumb2
'''
rop_thumb = (
    (b'\xbd',2,b'[\x00-\xff]\xbd','pop'),  # pop {regs,pc}
    (b'\xbd\xe8',4,b'\xbd\xe8[\x80-\xff][\x00-\xff]','pop')  # pop.w {regs,pc}
)

jop_thumb = (
    (b'\x47',2,b'[\x00-\x7f]\x47','bx'),  # bx reg
    (b'\x47',2,b'[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xd0\xd8\xe0\xe8\xf0\xf8]\x47','blx')  # blx reg
)

'''
aarch64
'''
rop_aarch64 = (
    (b'\x5f\xd6',4,b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x5f\xd6','ret'),  # ret reg
    (b'\x03\x5f\xd6',4,b'[\x00\x20\x40\x60\x80]\x03\x5f\xd6','ret'),  # ret reg
    (b'\xc0\x03\x5f\xd6',4,b'\xc0\x03\x5f\xd6','ret')  # ret
)

jop_aarch64 = (
    (b'\x1f\xd6',4,b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x1f\xd6','br'),  # br reg
    (b'\x03\x1f\xd6',4,b'[\x00\x20\x40\x60\x80]\x03\x1f\xd6','br'),  # br reg
    (b'\x3f\xd6',4,b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x3f\xd6','blr'),  # blr reg
    (b'\x03\x3f\xd6',4,b'[\x00\x20\x40\x60\x80]\x03\x3f\xd6','blr')  # blr reg
)

sys_aarch64 = (
    (b'\x01\x00\x00\xd4',4,b'\x01\x00\x00\xd4','svc'),  # svc #0
    ()
)

'''
mipsel32
'''
jop_mipsel32 = (
    (b'\x09\xf8\x20\x03',4,b'\x09\xf8\x20\x03','jalr'),  # jalr t9
    (b'\x08\x00\x20\x03',4,b'\x08\x00\x20\x03','jr'),  # jr t9
    (b'\x08\x00\xe0\x03',4,b'\x08\x00\xe0\x03','jr')  # jr ra
)

'''
mips32
'''
jop_mips32 = (
    (b'\x03\x20\xf8\x09',4,b'\x03\x20\xf8\x09','jalr'),  # jalr t9
    (b'\x03\x20\x00\x08',4,b'\x03\x20\x00\x08','jr'),  # jr t9
    (b'\x03\xe0\x00\x08',4,b'\x03\xe0\x00\x08','jr')  # jr ra
)

mnemonics_armv7 = ('bx [a-z0-9]{2,3}','blx [a-z0-9]{2,3}','ldmda [^}]*, {[^}]*, pc}','pop {[^}]*, pc}')
mnemonics_mips = ('jr','jalr')
mnemonics_aarch64 = ('ret','br','blr','bl #0x[0-9a-f]*','b #0x[0-9a-f]*','svc #0')
mnemonics_x86 = ('jmp','call','ret','retf')


ctrl_x86 = {
    "rop":rop_x86,
    "jop":jop_x86,
    "cop":cop_x86,
    "sys":sys_x86,
    "mnemonics":mnemonics_x86
}

ctrl_armv7 = {
    "rop":rop_armv7,
    "jop":jop_armv7,
    "cop":(),
    "sys":(),
    "mnemonics":mnemonics_armv7
}

ctrl_aarch64 = {
    "rop":rop_aarch64,
    "jop":jop_aarch64,
    "cop":(),
    "sys":sys_aarch64,
    "mnemonics":mnemonics_aarch64
}

ctrl_mipsel32 = {
    "rop":(),
    "jop":jop_mipsel32,
    "cop":(),
    "sys":(),
    "mnemonics":mnemonics_mips
}

ctrl_mips32 = {
    "rop":(),
    "jop":jop_mips32,
    "cop":(),
    "sys":(),
    "mnemonics":mnemonics_mips
}

ctrl_thumb = {
    "rop":rop_thumb,
    "jop":jop_thumb,
    "cop":(),
    "sys":(),
    "mnemonics":mnemonics_armv7
}

gadgets = {
    "x86":ctrl_x86,
    "x86_64":ctrl_x86,
    "armv7":ctrl_armv7,
    "mipsel32":ctrl_mipsel32,
    "aarch64":ctrl_aarch64,
    "thumb":ctrl_thumb,
    "mips32":ctrl_mips32
}

arch = {
    'x86':i386,
    'x86_64':amd64,
    'armv7':armv7,
    'aarch64':aarch64,
    'thumb':armv7,
    'mipsel32':mipsel32,
    'mips32':mipsel32
}

ubitmode = {
    'x86':UC_MODE_32,
    'x86_64':UC_MODE_64,
    'armv7':UC_MODE_ARM,
    'mipsel32':UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN,
    'aarch64':UC_MODE_ARM,
    'thumb':UC_MODE_THUMB,
    'mips32':UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN
}

uarch = {
    'x86':UC_ARCH_X86,
    'x86_64':UC_ARCH_X86,
    'armv7':UC_ARCH_ARM,
    'mipsel32':UC_ARCH_MIPS,
    'aarch64':UC_ARCH_ARM64,
    'thumb':UC_ARCH_ARM,
    'mips32':UC_ARCH_MIPS
}

capstone_arch = {
    'x86':CS_ARCH_X86,
    'x86_64':CS_ARCH_X86,
    'armv7':CS_ARCH_ARM,
    'aarch64':CS_ARCH_ARM64,
    'mipsel32':CS_ARCH_MIPS,
    'thumb':CS_ARCH_ARM,
    'mips32':CS_ARCH_MIPS
}


def bitmode(arch):
    if 'x86_64' in arch:
        return CS_MODE_64
    elif 'x86' in arch:
        return CS_MODE_32
    elif 'armv7' in arch:
        return CS_MODE_ARM
    elif 'mipsel32' in arch:
        return CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN
    elif 'aarch64' in arch:
        return CS_MODE_ARM
    elif 'thumb' in arch:
        return CS_MODE_THUMB
    elif 'mips32' in arch:
        return CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN


def debug_notify(msg, loc):
    log_info(str(msg),loc)

def flush(bv):
    bv.session_data['RopView']['cache']['rop_disasm'] = {}
    bv.session_data['RopView']['cache']['rop_asm'] = {}
    bv.session_data['RopView']['cache']['jop_disasm'] = {}
    bv.session_data['RopView']['cache']['jop_asm'] = {}
    bv.session_data['RopView']['cache']['cop_disasm'] = {}
    bv.session_data['RopView']['cache']['cop_asm'] = {}
    bv.session_data['RopView']['cache']['sys_disasm'] = {}
    bv.session_data['RopView']['cache']['sys_asm'] = {}
    bv.session_data['RopView']['cache']['analysis'] = {}
    bv.store_metadata("RopView.rop_disasm",bv.session_data['RopView']['cache']['rop_disasm'])
    bv.store_metadata("RopView.rop_asm",bv.session_data['RopView']['cache']['rop_asm'])
    bv.store_metadata("RopView.jop_disasm",bv.session_data['RopView']['cache']['jop_disasm'])
    bv.store_metadata("RopView.jop_asm",bv.session_data['RopView']['cache']['jop_asm'])
    bv.store_metadata("RopView.cop_disasm",bv.session_data['RopView']['cache']['cop_disasm'])
    bv.store_metadata("RopView.cop_asm",bv.session_data['RopView']['cache']['cop_asm'])
    bv.store_metadata("RopView.sys_disasm",bv.session_data['RopView']['cache']['sys_disasm'])
    bv.store_metadata("RopView.sys_asm",bv.session_data['RopView']['cache']['sys_asm'])
