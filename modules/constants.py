i386 = []
amd64 = {
    'controls_raw':[b'\xc3'],
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