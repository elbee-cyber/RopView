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
GA_ERR_RECURSION = 15

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
    GA_ERR_RECURSION:'Maximum recursion reached while following dereferences'
}

i386 = {
    'ret':[b'\xc3',b'\xc2',b'\xca',b'\xcb'],
    'bitmode':32,
    # Tokens for string parsing
    # List registers by least significant access first
    'registers':['ax','bx','cx','dx','ah','al','bh','bl','ch','cl','dh','dl','eax','ebx','ecx','edx','esi','edi','ebp'],
    'sp':['esp'],
    'pc':['eip'],
    'stack_pivots':['pop esp'],
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
    'stack_pivots':['pop rsp','pop esp'],
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

'''
i386, amd64
'''
cop_x86 = (
	(b'\xff',2,b'\xff[\x10\x11\x12\x13\x16\x17]','call'),					            # call [reg]
	#(b'\xf2\xff',3,b'\xf2\xff[\x10\x11\x12\x13\x16\x17]','call'),				        # bnd call [reg]
	(b'\xff',2,b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]','call'),				            # call reg
	#(b'\xf2\xff',3,b'\xf2\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]','call'),			        # bnd call reg
	(b'\xff\x14\x24',3,b'\xff\x14\x24','call'),						                    # call [rsp]
	#(b'\xf2\xff\x14\x24',4,b'\xf2\xff\x14\x24','call'),				                # bnd call [rsp]
	(b'\xff\x55\x00',3,b'\xff\x55\x00','call'),						                    # call [rbp]
	#(b'\xf2\xff\x55\x00',4,b'\xf2\xff\x55\x00','call'),					            # bnd call [rbp]
	(b'\xff',3,b'\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}','call'),				        # call [reg+n]
	#(b'\xf2\xff',4,b'\xf2\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}','call'),	            # bnd call [reg+n]
	(b'\xff',6,b'\xff[\x90\x91\x92\x93\x94\x96\x97][\x00-\x0ff]{4}','call')		        # call [reg+n]
)

rop_x86 = (
	(b'\xc3',1,b'\xc3','ret'),								                            # ret
	(b'\xc2',3,b'\xc2[\x00-\xff]{2}','ret')							                    # ret n
)

jop_x86 = (
	(b'\xff',2,b'\xff[\x20\x21\x22\x23\x26\x27]','jmp'),					            # jmp [reg]
	#(b'\xf2\xff',3,b'\xf2\xff[\x20\x21\x22\x23\x26\x27]','jmp'),				        # bnd jmp [reg]
	(b'\xff',2,b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]','jmp'),				            # jmp reg
	#(b'\xf2\xff',3,b'\xf2\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]','jmp'),			        # bnd jmp reg
	(b'\xff\x24\x24',3,b'\xff\x24\x24','jmp'),						                    # jmp [rsp]
	#(b'\xf2\xff\x24\x24',4,b'\xf2\xff\x24\x24','jmp'),					                # bnd jmp [rsp]
	(b'\xff\x65\x00',3,b'\xff\x65\x00','jmp'),						                    # jmp [rbp]
	#(b'\xf2\xff\x65\x00',4,b'\xf2\xff\x65\x00','jmp'),					                # bnd jmp [rbp]
	(b'\xff',6,b'\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}','jmp'),			        # jmp [reg+n]
	#(b'\xf2\xff',7,b'\xf2\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}','jmp'),        # bnd jmp [reg+n]
	(b'\xff\xa4\x24',7,b'\xff\xa4\x24[\x00-\xff]{4}','jmp'),				            # jmp [rsp+n]
	#(b'\xf2\xff\xa4\x24',8,b'\xf2\xff\xa4\x24[\x00-\xff]{4}','jmp'),			        # bnd jmp [rsp+n]
	(b'\xff',3,b'\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}','jmp')				            # jmp [reg+n]
	#(b'\xf2\xff',4,b'\xf2\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}','jmp')		        # bnd jmp [reg+n]
)

sys_x86 = (
	(b'\xcd\x80',2,b'\xcd\x80','int 0x80'),							                    # int 0x80
	(b'\x0f\x05',2,b'\x0f\x05','syscall'),							                    # syscall
	(b'\x0f\x34',2,b'\0x0f\x34','sysenter'),						                    # sysenter
	(b'\x65\xff\x15\x10\x00\x00\x00',7,b'\x65\xff\x15\x10\x00\x00\x00','call gs:[10]')	# call gs:[10]
)

mnemonics_x86 = ('jmp','call','ret')

ctrl_x86 = {
    "rop":rop_x86,
    "jop":jop_x86,
    "cop":cop_x86,
    "sys":sys_x86,
    "mnemonics":mnemonics_x86
}

gadgets = {
    "x86":ctrl_x86,
    "x86_64":ctrl_x86
}

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
    'x86':KS_ARCH_X86,
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