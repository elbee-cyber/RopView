from capstone import *
from unicorn.unicorn_const import *
from unicorn.x86_const import *

i386 = []
amd64 = {
    'controls':[b'\xc3'],
    'bitmode':64,
    'registers':['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15'],
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
    }
}
arm32 = []
arm64 = []

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

def bitmode(arch):
    if '64' in arch:
        return CS_MODE_64