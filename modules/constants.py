from capstone import *
from keystone import *
from unicorn.unicorn_const import *
from unicorn.x86_const import *

GA_ERR_STACKPIVOT = 1
GA_ERR_FOLLOW_UNMAPPED = 2
GA_ERR_READ_UNMAPPED = 3
GA_ERR_WRITE_UNMAPPED = 4
GA_ERR_DEREF_PC = 5
GA_NULL_DEREF = 6

i386 = {
    'controls':[b'\xc3',b'\xc2',b'\xca',b'\xcb'],
    'bitmode':32,
    # Tokens for string parsing
    'registers':['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip',
    ' ax',' bx',' cx',' dx',' ah',' al',' bh',' bl',' ch',' cl',' dh',' dl',
    '[ax','[bx','[cx','[dx','[ah','[al','[bh','[bl','[ch','[cl','[dh','[dl'],
    'sp':['esp'],
    'pc':['eip'],
    'uregs':{
        'sp':UC_X86_REG_ESP,
        'eax':UC_X86_REG_EAX,
        'ebx':UC_X86_REG_EBX,
        'ecx':UC_X86_REG_ECX,
        'edx':UC_X86_REG_EDX,
        'esi':UC_X86_REG_ESI,
        'edi':UC_X86_REG_EDI,
        'ebp':UC_X86_REG_EBP,
        'esp':UC_X86_REG_ESP,
        'eip':UC_X86_REG_EIP,
        'ax':UC_X86_REG_AX,
        'bx':UC_X86_REG_BX,
        'cx':UC_X86_REG_CX,
        'dx':UC_X86_REG_DX,
        'ah':UC_X86_REG_AH,
        'al':UC_X86_REG_AL,
        'bh':UC_X86_REG_BH,
        'bl':UC_X86_REG_BL,
        'ch':UC_X86_REG_CH,
        'cl':UC_X86_REG_CL,
        'dh':UC_X86_REG_DH,
        'dl':UC_X86_REG_DL
    }
}

amd64 = {
    'controls':[b'\xc3',b'\xc2',b'\xca',b'\xcb'],
    'bitmode':64,
    'registers':['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15']+i386['registers'],
    'sp':['rsp','esp'],
    'pc':['rip','eip'],
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
        'r15':UC_X86_REG_R15,
    }
}
amd64['uregs'].update(i386['uregs'])

arm32 = {}
arm64 = {}
mips = {}

arch = {
    'x86':i386,
    'x86_64':amd64,
    'arm32':arm32,
    'arm64':arm64
}

ubitmode = {
    'x86':UC_MODE_32,
    'x86_64':UC_MODE_64
}

uarch = {
    'x86':UC_ARCH_X86,
    'x86_64':UC_ARCH_X86,
    'arm64':UC_ARCH_ARM64,
    'arm':UC_ARCH_ARM,
    'mips':UC_ARCH_MIPS,
    'ppc':UC_ARCH_PPC
}

capstone_arch = {
    'x86':0,
    'x86_64':CS_ARCH_X86,
    'arm32':0,
    'arm64':0
}

keystone_arch = {
    'x86':0,
    'x86_64':KS_ARCH_X86,
    'arm32':0,
    'arm64':0
}

def bitmode(arch):
    if '64' in arch:
        return (CS_MODE_64,KS_MODE_64)