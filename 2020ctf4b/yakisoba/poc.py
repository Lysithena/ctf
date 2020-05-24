import angr
from claripy import *
proj = angr.Project('./yakisoba')
state = proj.factory.entry_state()
sm = proj.factory.simgr(state)
sm.explore(find=0x4006d2,avoid=0x4006f7)
if sm.found:
    for i in sm.found:
        print(i.posix.dumps(0))
