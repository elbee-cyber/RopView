from capstone import *
from keystone import *
from unicorn.unicorn_const import *
from unicorn.x86_const import *
from binaryninja import log_info

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
    GA_ERR_UNKNOWN:'An unknown error stopped analysis'
}

i386 = {
    'ret':[b'\xc3',b'\xc2',b'\xca',b'\xcb'],
    'bitmode':32,
    # Tokens for string parsing
    # List registers by least significant access first
    'registers':['ax','bx','cx','dx','ah','al','bh','bl','ch','cl','dh','dl','eax','ebx','ecx','edx','esi','edi','ebp'],
    'sp':['esp'],
    'pc':['eip'],
    'prestateOpts':['eax','ebx','ecx','edx','esi','edi','ebp'],
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
        'eax':[' ax',' ah',' al'],
        'ebx':[' bx',' bh',' bl'],
        'ecx':[' cx',' ch',' cl'],
        'edx':[' dx',' dh',' dl'],
        'ebp':[' bp'],
        'esi':[' si'],
        'edi':[' di']
    }
}

amd64 = {
    'ret':[b'\xc3',b'\xc2',b'\xca',b'\xcb'],
    # jmp rax , jmp rcx , jmp rdx , jmp rbx , jmp rsp , jmp rbp , jmp rsi , jmp rdi , (jmp (r8-r15))
    'jumps':[b'\xff\xe0',b'\xff\xe1',b'\xff\xe2',b'\xff\xe3',b'\xff\xe4',b'\xff\xe5',b'\xff\xe6',b'\xff\xe7'],
    'bitmode':64,
    'registers':i386['registers']+['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15'],
    'sp':['rsp','esp'],
    'pc':['rip','eip'],
    'prestateOpts':['rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15'],
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
        'rax':['eax',' ax',' ah',' al'],
        'rbx':['ebx',' bx',' bh',' bl'],
        'rcx':['ecx',' cx',' ch',' cl'],
        'rdx':['edx',' dx',' dh',' dl'],
        'rsi':['esi',' si','sil'],
        'rdi':['edi',' di','dil'],
        'rbp':['ebp',' bp',' bpl'],
        'r8':['r8d','r8w','r8b'],
        'r9':['r9d','r9w','r9b'],
        'r10':['r10d','r10w','r10b'],
        'r11':['r11d','r11w','r11b'],
        'r12':['r12d','r12w','r12b'],
        'r13':['r13d','r13w','r13b'],
        'r14':['r14d','r14w','r14b'],
        'r15':['r15d','r15w','r15b']
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
    'x86':CS_ARCH_X86,
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
    elif 'x86' in arch:
        return (CS_MODE_32,KS_MODE_32)

def debug_notify(msg):
    log_info(str(msg),'RopView - Debug')