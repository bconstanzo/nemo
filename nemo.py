import datetime
import struct


# En primer lugar, definimos una clase abstracta para estandarizar la interfaz
# de las clases que manejan el acceso a los dumps. Las clases que heredan de
# AbstractDump son las que controlan el acceso al volcado de memoria en última
# instancia, y varían según el formato del mismo.
# Estrictamente hablando, en realidad más que "AbstractDump", esta clase está
# implementando el espacio de direcciones de x86-32+PAE, y con la herencia se
# evita hacer un esquema de composión (como hace Volatility).
class AbstractArch:
    def __init__(self, mem):
        self.mem = mem
    
    def vtop(self, addr, debug=False):
        raise NotImplementedError
    
    
    def parse_vaddr(self, addr):
        raise NotImplementedError
    
    
    def __repr__(self):
        return f"{self.__class__.__name__}"


class ArchX86(AbstractArch):
    def __init__(self, mem):
        super().__init__(mem)
        self.st_uint32 = struct.Struct("<L")

    def vtop(self, addr, debug=False):
        # Así como está implementada la función, no revisa los flags que se
        # encuentran presentes en el PDE y el PTE, asique no maneja las large
        # pages, ni tampoco interpreta el valid bit
        st = self.st_uint32
        mem = self.mem
        dbase = mem.dirbase
        pdi, pti, offset = self.parse_vaddr(addr)
        pde, = st.unpack(mem.read(dbase + pdi * 4, 4))
        pde  = pde  & 0xfffff000 
        pte, = st.unpack(mem.read(pde   + pti * 4, 4))
        pte  = pte  & 0xfffff000
        paddr = pte + offset
        # Principalmente sirvieron para debugging, pero estos prints pueden
        # resultar útiles para ver cómo es la traducción de direcciones.
        if debug:
            print(f"Virtual Addr: {hex(addr)}")
            print(f"Parsed as:")
            print(f"\n".join([f"--PDI  : {hex(pdi)}",
                              f"--PTI  : {hex(pti)}",
                              f"--OFFS : {hex(offset)}",
                            ]))
            print(f"PDE  : {hex(pde)}")
            print(f"PTE  : {hex(pte)}")
        return paddr
    
    
    def parse_vaddr(self, addr):
        # 0b 0000 0000 0000 0000 0000 0000 0000 0000
        # 0b 1111 1111 1100 0000 0000 0000 0000 0000
        # 0b 0000 0000 0011 1111 1111 0000 0000 0000
        pdi  = (addr & 0xffc00000) >> 22
        pti  = (addr & 0x003ff000) >> 12
        offs =  addr & 0x00000fff
        return pdi, pti, offs

        
class ArchX86PAE(ArchX86):
    def vtop(self, addr, debug=False):
        # Así como está implementada la función, no revisa los flags que se
        # encuentran presentes en el PDE y el PTE, asique no maneja las large
        # pages, ni tampoco interpreta el valid bit
        st = self.st_uint32
        mem = self.mem
        dbase = mem.dirbase
        pdpi, pdi, pti, offset = self.parse_vaddr(addr)
        pdpe, = st.unpack(mem.read(dbase + pdpi * 8, 4))
        pdpe  = pdpe & 0xfffff000
        pde,  = st.unpack(mem.read(pdpe  + pdi  * 8, 4))
        pde   = pde  & 0xfffff000 
        pte,  = st.unpack(mem.read(pde   + pti  * 8, 4))
        pte   = pte  & 0xfffff000
        paddr = pte + offset
        # Principalmente sirvieron para debugging, pero estos prints pueden
        # resultar útiles para ver cómo es la traducción de direcciones.
        if debug:
            print(f"Virtual Addr: {hex(addr)}")
            print(f"Parsed as:")
            print(f"\n".join([f"--PDPI : {hex(pdpi)}",
                              f"--PDI  : {hex(pdi)}",
                              f"--PTI  : {hex(pti)}",
                              f"--OFFS : {hex(offset)}",
                            ]))
            print(f"PDPE : {hex(pdpe)}")
            print(f"PDE  : {hex(pde)}")
            print(f"PTE  : {hex(pte)}")
        return paddr
    
    
    # Si bien parse_virtual_address podría ser reemplazada (inline), resulta más
    # cómodo que esté de manera aislada.
    def parse_vaddr(self, addr):
        # 0b 0000 0000 0000 0000 0000 0000 0000 0000
        pdpi = (addr & 0xc0000000) >> 30
        pdi  = (addr & 0x3fe00000) >> 21
        pti  = (addr & 0x001ff000) >> 12
        offs =  addr & 0x00000fff
        return pdpi, pdi, pti, offs

class AbstractDump:
    def __init__(self, path, archclass):
        self.dirbase = 0
        self.process_head = 0
        self.arch = archclass(self)
    
    def __repr__(self):
        return "\n".join([
            self.__class__.__name__,
            "\tDirBase: " + hex(self.dirbase),
        ])

    def read(self, pos, length):
        pass

    def vtop(self, addr, debug=False):
        return self.arch.vtop(addr, debug)


# Analice el funcionamiento de esta clase para entender cómo maneja el acceso
# al volcado
class RawDump(AbstractDump):
    def __init__(self, path, archclass):
        super().__init__(path, archclass)
        self.mem = open(path, "rb")
    
    def read(self, pos, length):
        self.mem.seek(pos)
        return self.mem.read(length)


        
# Una excepción especial para el caso de tratar de leer una posición que no
# está mapeada por los runs del CrashDump.
class OutsideRangesException(Exception):
    pass


class CrashDump(AbstractDump):
    def __init__(self, path, archclass):
        # En el caso de CrashDump hay que incorporar el parsing de los primeros
        # 4KiB (serían 8KiB en el caso de CrashDump64)
        # De este encabezado se casa información valiosa, incluyendo el DTB (o
        # DirBase).
        # Hay que parsear también los rangos de los Runs, para poder manejar
        # adecuadamente las lecturas.
        super().__init__(path, archclass)
        self.mem = open(path, "rb")
        self.st_uint32 = struct.Struct("<L")
        # Ahora hay que parsear el encabezado del CrashDump para sacar los
        # punteros de interés e interpretar la lista de runs.
        raw_header = self.mem.read(4096)
        self._raw_header = raw_header
        self.dirbase, = self.st_uint32.unpack(raw_header[0x10: 0x14])
        self.process_head, = self.st_uint32.unpack(raw_header[0x1c: 0x20])
        runs = raw_header[0x64:0x320]
        st_parseruns = struct.Struct("<2L")
        self.ranges = []
        fpos = 1 << 12  # efectivamente es 4096, se busca hacer un poco más
                        # explícito que estamos hablando de un offset en
                        # páginas dentro del volcado
        nruns, last_page = st_parseruns.unpack(runs[0:8])
        for i in range(1, nruns + 1):
            start_addr, length = st_parseruns.unpack(runs[i*8: i*8 + 8])
            start_addr *= 4096
            length *= 4096
            self.ranges.append((fpos, start_addr, length))
            fpos += length

    
    def read(self, pos, length):
        # Tenemos que buscar sobre qué run se mapea la posición que se busca
        # leer -- la búsqueda lineal no es el método más rápido pero es simple
        for fpos, saddr, rlength in self.ranges:
            if saddr > pos:
                raise OutsideRangesException(
                    "Tried to read: %s - (saddr: %s)" % (hex(pos), hex(saddr))
                )
            if saddr <= pos <= saddr + rlength:
                break  # encontramos el run que contiene la posición buscada
        # print("Page in dump : %s" % hex(fpos))
        fpos = fpos + (pos - saddr)  # nos ubicamos en el offset
        # print("Offset to    : %s" % hex(fpos))
        self.mem.seek(fpos)
        return self.mem.read(length)


# Alguna función de utilidad que facilita el trabajo desde las clases.
def crash_to_raw(crash, raw):
    """
    Convierte un CrashDump a formato raw.
    
    @param crash: instancia de CrashDump.
    @param raw: file (abierto en modo "rb")
    """
    zpage = b"\x00" * 4096
    fpos = 0
    for r in crash.ranges:
        _, saddr, length = r
        while fpos < saddr:
            raw.write(zpage)
            fpos += 4096
        for i in range(length >> 12):
            page = crash.read(saddr + (i << 12), 4096)
            raw.write(page)
            fpos += 4096


def pretty_pslist(plist, fields=None):
    if fields is None:  # esta es una forma de manejar el argumento por defecto
        fields = [
            ("pid", "PID", 8),
            ("image_name", "Name", 15),
            ("create_time", "Create Time", 30),
            ("exit_time", "Exit Time", 30),
        ]
    attr, name, col_len = fields[0]
    header = " ".join([(r"%-"+("%d" % f[2]) + "s") % f[1] for f in fields])
    headli = " ".join(["-" * f[2] for f in fields])
    proto  = " ".join([(r"%-"+("%d" % f[2]) + "s") for f in fields])
    print(header)
    print(headli)
    for ps in plist:
        print(proto % tuple([getattr(ps, f[0]) for f in fields]))


def wintime(raw):
    """Parsea los bytes (en raw) de un LARGE_INTEGER para obtener una fecha/hora
    en formato Windows.
    """
    lo, hi = struct.unpack("<LL", raw)
    value = (hi << 32) + lo
    # este algoritmo es el que implementamos en FileValidators para hacer el
    # manejo de las fechas en formato Windows NT
    tics = value
    days = tics // 864_000_000_000
    rem = tics - days * 864_000_000_000
    hours = rem // 36_000_000_000
    rem -= hours * 36_000_000_000
    minutes = rem // 600_000_000
    rem -= minutes * 600_000_000
    seconds = rem // 10_000_000
    rem -= seconds * 10_000_000
    microseconds = rem // 100
    td = datetime.timedelta(days)  # así se manejan fácil los bisiestos
    hours, minutes, seconds, microseconds = map(int, [hours, minutes, seconds, microseconds])
    retval = datetime.datetime(1601, 1, 1, hours, minutes, seconds, microseconds) + td
    if value == 0:
        retval = None
    return retval


# Implemente las clases para representar los procesos en memoria. Vea las
# estructuras EPROCESS y sus estructuras embebidas con WinDbg. El comando que 
# debe utilizar dt. Por ejemplo, para ver _EPROCEES debe ingresar:
#   dt !_eprocess
# Considere la función pretty_pslist() para decidir qué campos debe parsear de
# la estructura _EPROCESS.


class EProcess:

    fullsize = 0x2d8

    def __init__(self, rawdata, base_addr=0):
        self.base_addr = base_addr
        self.pcb = KProcess(rawdata[0x0: 0x98])
        self.active_process_links = ListEntry(rawdata[0xb8: 0xb8 + 8])
        image_name, = struct.unpack("<15s", rawdata[0x16c: 0x16c + 15])
        self.image_name = (image_name.replace(b"\x00", b"")).decode("ascii")
        self.pid, = struct.unpack("<L", rawdata[0xb4: 0xb8])
        self.create_time = wintime(rawdata[0xa0: 0xa8])
        self.exit_time = wintime(rawdata[0xa8: 0xb0])
        

    
    def __repr__(self):
        return f"Process '{self.image_name}' @ {hex(self.base_addr)}"


class ListEntry:

    fullsize = 0x8

    def __init__(self, rawdata):
        self.flink, self.blink = struct.unpack("<2L", rawdata)
    
    def __repr__(self):
        return f"ListEntry - FLink: {hex(self.flink)} BLink: {hex(self.blink)}"


class KProcess:
    
    fullsize = 0x98
    
    def __init__(self, rawdata):
        self.dispatcher_header = DispatcherHeader(rawdata[0x0: 0x10])
        self.profile_list_head = ListEntry(rawdata[0x10: 0x18])
        self.directory_table_base, = struct.unpack("<L", rawdata[0x18: 0x1c])
    
    def __repr__(self):
        return "< KProcess >"


class DispatcherHeader:
    
    fullsize = 0x10
    
    def __init__(self, rawdata):
        pass
    
    def __repr__(self):
        return "< Dispatcher Header >"



# Implemente las funciones pslist() y dlllist().
def pslist(dump):
    pslist_head = dump.process_head
    next_ps = ListEntry(dump.read(dump.vtop(pslist_head), 8))
    ret = []
    psize = EProcess.fullsize
    while next_ps.flink != pslist_head:
        ps = EProcess(
            dump.read(dump.vtop(next_ps.flink - 0xb8), psize),
            next_ps.flink - 0xb8
        )
        ret.append(ps)
        next_ps = ps.active_process_links
    return ret


def dlllist(dump):
    pass










