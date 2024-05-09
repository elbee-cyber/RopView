from capstone import *

i386 = []
amd64 = {
    'controls':[b'\xc3'],
    'bitmode':64,
    'registers':['rax']
    }
arm32 = []
arm64 = []

arch = {
    'x86':i386,
    'x86_64':amd64,
    'arm32':arm32,
    'arm64':arm64
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