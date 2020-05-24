import angr
from claripy import *
proj = angr.Project('./mask',load_options={'auto_load_libs':False})
#state = proj.factory.entry_state()
sym_arg = BVS('sym_arg',8*40)
argv=['mask',sym_arg]
state = proj.factory.entry_state(args=argv)
print(state.regs.rip)
sm = proj.factory.simgr(state)
sm.explore(find=0x4012cf,avoid={0x4012dd,0x4011a9})
if sm.found:
    for i in sm.found:
        print(i.posix.dumps(0))
        print(i.solver.eval(sym_arg,cast_to=bytes).decode('utf-8','ignore'))
