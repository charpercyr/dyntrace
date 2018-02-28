
class Process:
    def __init__(self, dt, proc):
        self.dt = dt
        self.proc = proc

    def add_tracepoint(self, loc, tracer, name=None, tracer_args=None):
        pass

    def remove_tracepoint(self, name):
        pass

    def list_tracepoints(self):
        pass

    def list_symbols(self):
        pass