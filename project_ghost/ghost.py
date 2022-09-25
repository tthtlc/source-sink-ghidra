# GhOST is a binary analysis tool for performing static taint analysis & to aid in finding buffer overflow vulnerabilities.
# @author Haziq, Joven, Sree, Kai Guan, Shawn
# @category GhOST
# @keybinding
# @menupath
# @toolbar

#####################################################################################################################
# Imports

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import HighParam, PcodeOp
from ghidra.program.model.symbol import RefType, SymbolType, SourceType
from ghidra.program.database.symbol import CodeSymbol
from ghidra.program.model.lang import Processor
import logging
import csv
import cgi
import os
import logging
from datetime import datetime
import sys
import uuid
# The external packages are included in the ./lib subdirectory instead of being listed in a
# requirements.txt because it can be quite troublesome to install packages on Ghidra's Jython.
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_PATH, 'lib')) 
import yaml
import pydot

#####################################################################################################################
# Config
with open(os.path.join(SCRIPT_PATH, 'config.yaml'), 'r') as f:
    config = yaml.safe_load(f)
    
# Tracing Options
AUTO_DEFINE_UNDEFINED_FUNCTIONS             = config["auto_define_undefined_functions"]             # bool
SUPRESS_CANNOT_FIND_PARENT_FUNCTION_WARNING = config["supress_cannot_find_parent_function_warning"] # bool
SOURCE_SINK_PARAMETER_SIGNATURES            = config["source_sink_parameter_signatures"]            # dict[dict[str, list[int]]]

FIND_BETTER_ARG_MAX_ITERATIONS              = config["find_better_arg_max_iterations"]              # int
MAX_FUNCCALL_OUTPUT_TRACE_DEPTH             = config["max_funccall_output_trace_depth"]             # int

TRACE_SYMBOL_OFFSET                         = config["trace_symbol_offset"]                         # bool

# Source & Sink Definitions
SINK_FUNCS                                  = config["sink_functions"]                              # dict[str, list[int]]
SOURCE_FUNCS                                = config["source_functions"]                            # list[str]
SOURCE_GLOBAL_SYMBOLS                       = config["source_global_symbols"]                       # list[str]
FLAG_MAIN_AS_SOURCE                         = config["flag_main_as_source"]                         # bool

# Output Options
PRE_RENDER_GRAPH_SVG                        = config["pre_render_graph_svg"]                        # bool
PRE_RENDER_GRAPH_PDF                        = config["pre_render_graph_pdf"]                        # bool
PRE_RENDER_GRAPH_PNG                        = config["pre_render_graph_png"]                        # bool
OUTPUT_INDIVIDUAL_PATHS_GRAPH               = config["output_individual_paths_graph"]               # bool
OUTPUT_GLOBAL_GRAPH                         = config["output_global_graph"]                         # bool
SPLIT_GLOBAL_GRAPH_BY_FUNCS                 = config["split_global_graph_by_funcs"]                 # bool
OUTPUT_DECOMPILED_C_AND_DISASSEMBLY_HTML    = config["output_decompiled_c_and_disassembly_html"]    # bool
OUTPUT_RELATIVE_PATHS                       = config["output_relative_paths"]                       # bool

#####################################################################################################################

# Output Directory Setup
try: # Grab from environment variables (Usually passed via the launcher script)
    OUTPUT_DIR = os.environ["OUTPUT_DIRECTORY"]
except: # Default directory
    OUTPUT_DIR = os.path.join(
        SCRIPT_PATH, 
        "GhOST Output", 
        "{}-{}".format(
            getCurrentProgram().getName(),
            datetime.now().strftime("%y%m%d_%H%M%S")
            )
        )

try:
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
except Exception as e:
    print "Failed to create root output directory. \nError message: {}".format(e)
    sys.exit(1)

# Subdirectories & Files
OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS = "Potentially Vulnerable"
OUTPUT_DIR_UNKNOWN_PATHS = "Unknown"
OUTPUT_DIR_GLOBAL_GRAPHS = "Global Graph"
OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML = "Decompiled C.html"
OUTPUT_FILEPATH_CALLER_CALLEE_CSV = "Caller-Callee Function Calls.csv"

if OUTPUT_RELATIVE_PATHS:
    # By default the working directory is Ghidra's directory, so we need to change it to the specified output directory 
    # as everything is output relative to the working directory.
    os.chdir(OUTPUT_DIR) 
    OUTPUT_DIR = ""
else: 
    # Set output directories to be absolute path
    OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS           = os.path.join(OUTPUT_DIR, OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS)
    OUTPUT_DIR_UNKNOWN_PATHS                          = os.path.join(OUTPUT_DIR, OUTPUT_DIR_UNKNOWN_PATHS)
    OUTPUT_DIR_GLOBAL_GRAPHS                          = os.path.join(OUTPUT_DIR, OUTPUT_DIR_GLOBAL_GRAPHS)
    OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML = os.path.join(OUTPUT_DIR, OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML)
    OUTPUT_FILEPATH_CALLER_CALLEE_CSV                 = os.path.join(OUTPUT_DIR, OUTPUT_FILEPATH_CALLER_CALLEE_CSV)

try:
    if OUTPUT_INDIVIDUAL_PATHS_GRAPH and not os.path.exists(OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS):
        os.makedirs(OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS)
    if OUTPUT_INDIVIDUAL_PATHS_GRAPH and not os.path.exists(OUTPUT_DIR_UNKNOWN_PATHS):
        os.makedirs(OUTPUT_DIR_UNKNOWN_PATHS)
    if OUTPUT_GLOBAL_GRAPH           and not os.path.exists(OUTPUT_DIR_GLOBAL_GRAPHS):
        os.makedirs(OUTPUT_DIR_GLOBAL_GRAPHS)
except Exception as e:
    print "Failed to create output directories. \nError message: {}".format(e)
    sys.exit(1)

#####################################################################################################################
# Logger Initialization
logger = logging.getLogger()
logger.setLevel(logging.NOTSET)
logger_format = logging.Formatter('[%(asctime)s][%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')

LOG_LEVELS_MAP = {
    "CRITICAL"  : logging.CRITICAL,
    "ERROR"     : logging.ERROR,
    "WARNING"   : logging.WARNING,
    "INFO"      : logging.INFO,
    "DEBUG"     : logging.DEBUG,
    "NOTSET"    : logging.NOTSET,
}

console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVELS_MAP[config["console_log_level"]])
console_handler.setFormatter(logger_format)
logger.addHandler(console_handler)

logfile_path = os.path.join(OUTPUT_DIR, "ghost.log")
file_handler = logging.FileHandler(logfile_path, mode="w")
file_handler.setLevel(LOG_LEVELS_MAP[config["file_log_level"]])
file_handler.setFormatter(logger_format)
logger.addHandler(file_handler)

#####################################################################################################################
# Tracing-related Setup

# Decompiler Initialization
options = DecompileOptions()
monitor = ConsoleTaskMonitor()
decompiler_interface = DecompInterface()
decompiler_interface.setOptions(options)
decompiler_interface.openProgram(getCurrentProgram())

# Misc. Initialization
listing = currentProgram.getListing()
processor = currentProgram.getLanguage().getProcessor()
function_manager = currentProgram.getFunctionManager()

# Global Symbols
global_namespace = currentProgram.getNamespaceManager().getGlobalNamespace()
global_symbols = tuple(currentProgram.getSymbolTable().getSymbols(global_namespace))
# Custom map of where some interesting global symbols are used
GLOBAL_SYMBOLS_TRACE_MAP = {} # dict[ghidra.program.model.address.Address, ghidra.program.model.symbol.Symbol]
for gs in global_symbols:
    if gs.getSymbolType() != SymbolType.LABEL:
        continue
    for ref in gs.getReferences():
        if ref.getSource() != SourceType.ANALYSIS:
            continue
        GLOBAL_SYMBOLS_TRACE_MAP[ref.getFromAddress()] = gs

#####################################################################################################################
# Custom Error

class InvalidFuncErr(Exception):
    pass

#####################################################################################################################
# Tracing Classes

class TraceType(object):
    """Enumerated type for the different ways that a sink-to-source trace can be found.
    
    See Also:
        TraceInfo
    """

    # A function is called in many places, so a single parameter can be traced to many arguments
    ParamToArg                  = "ParamToArg" 

    # The variable may be the parameter of a function
    ArgIsParam                  = "ArgIsParam" 

    # The variable comes from a Function call's output (i.e. Traced from varnode.getDef(), whereby its a CALL pcode).
    # This value can be an Arg of a FuncCall, or the ReturnVal varnode of a Func.
    VarIsFuncCallOutput         = "VarIsFuncCallOutput" 

    # Source of FuncCallOutput is to continue tracing from the Func's ReturnVal
    FuncCallOutputToReturnVal   = "FuncCallOutputToReturnVal" 

    # Alternative to FuncCallOutputToReturnVal, as for Thunk functions, we don't have the internal function code, 
    # so we can't properly trace the return varnode. Thus we just link it to the input arguments.
    FuncCallOutputToArgs        = "FuncCallOutputToArgs" 

    # When the same variable is referenced/used multiple times in the same function. E.g. It could indicate the 
    # same variable being passed-by-reference to many function calls
    SameVarInFunc               = "SameVarInFunc" 

    # Linking an arg in a FuncCall to the param in a Func (loop into the usages of the Param/Arg as it may 
    # be a pass-by-reference)
    ArgUsagePassedIntoFunc      = "ArgUsagePassedIntoFunc" 

    # After a trace of ArgUsagePassedIntoFunc, link back the last usage of the Param/Arg to the original Arg 
    # it came from (i.e. exiting back to the original arg it came from so it can continue back on its original path)
    ArgUsagePassedIntoFuncExit  = "ArgUsagePassedIntoFuncExit" 

    # When tracing thunk function arguments, we cannot see the internal code of the function, so we just assume 
    # that all other arguments will affect each other. (e.g. strcpy(src, dst) should trace from src arg to dst arg)
    ArgToOtherArgs              = "ArgToOtherArgs" 
    
class TraceInfo(object):
    """Handles the linking of a sink to a source, also representing a backwards trace.
    
    Attributes:
        source_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
        sink_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
        trace_type (TraceType)
    
    Notes:
        - Obtaining a TraceInfo instance should be done via the get_instance method as it handles deduplication.
        - Initializing a TraceInfo instance also automatically adds itself to the forward_traces and backward_traces 
          attributes of the source and sink nodes respectively.
        - The trace_queue attribute is under the class object. This acts as the main tracing queue, whereby new traces
          are automatically added to the queue, and the main program loop can get the next instance for further tracing.
    """
    def __init__(self, source_node, sink_node, trace_type):
        """Initializes TraceInfo object, linking the source and sink nodes forward and backward traces respectively.
        
        Parameters:
            source_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
            sink_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
            trace_type (TraceType)
            
        See Also:
            self.get_instance()
        """
        self.source_node = source_node
        self.sink_node = sink_node
        self.trace_type = trace_type
        source_node.forward_traces.append(self)
        sink_node.backward_traces.append(self)

    @classmethod
    def get_instance(cls, source_node, sink_node, trace_type):
        """Gets an existing instance of a trace with the same source-sink-type, else it creates a new instance.

        Gets a TraceInfo instance either by returning an already existing one or initializing a new one if it does not 
        already exist. This is to prevent duplicate representations and otherwise repeated tracings of the same trace.
        
        Also automatically adds new instances to the trace_queue.

        Parameters:
            source_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
            sink_node (Param | ArbitraryParam | ReturnVal | Arg | FuncCallOutput)
            trace_type (TraceType)

        Returns:
            TraceInfo
        """
        if not hasattr(cls, 'instances'):
            cls.instances = {}
            cls.trace_queue = []
        unique_key = (source_node, sink_node, trace_type, )
        if unique_key in cls.instances:
            logger.debug("Got duplicate traceinfo")
            return cls.instances[unique_key]
        instance = cls(source_node, sink_node, trace_type)
        cls.instances[unique_key] = instance
        cls.trace_queue.append(instance)
        return instance

    @classmethod
    def get_next_in_queue(cls):
        """For the main tracing loop to get the next instance to continue the tracing
        
        Returns:
            TraceInfo | None
        """
        try:
            return cls.trace_queue.pop()
        except:
            return None
        

    def __str__(self): 
        """Describes the backward trace from sink node to source node
        """
        return "{} [ {} ] --> [ {} ]".format(self.trace_type, self.sink_node, self.source_node)
    

class VarnodeUpgraderMixin():
    """Provides supplementary methods to get a corresponding varnode with more information.
    
    Attributes:
        varnode (ghidra.program.model.pcode.Varnode | None):
            It is required that the superclass of this mixin has the varnode attribute, as this mixin will analyze based 
            on this varnode object. This will also be replaced by the upgraded varnode if one is found.
        origin_varnode (ghidra.program.model.pcode.Varnode | None):
            As the "upgraded" varnode will replace the varnode attribute, this attribute will keep track of the original
            varnode so that tracing operations on the varnode level (i.e. Arg.trace_to_func_call_output()) can start 
            tracing from the original varnode location.
        high_var (ghidra.program.model.pcode.HighVariable | None):
            The result of the upgraded varnode's getHigh() method.
        sym (ghidra.program.model.pcode.HighSymbol | None):
            The corresponding symbol of the upgraded varnode.
        name (str | None):
            The name of the upgraded varnode.
        buffer_size (int | None):
            The buffer size obtained from the upgraded varnode symbol.
    """
    
    def varnode_upgrade(self):
        """Run all upgrades. 
        
        Analyzes the object's varnode attribute to get better corresponding data.
        """
        self._varnode_upgrader_setup()
        if not self.varnode:
            return
        self._find_sym_trace_def(self.varnode)
    
    
    def varnode_upgrade_output(self):
        """Run all upgrades (special variant for FuncCallOutput). 
        
        Analyzes the object's varnode attribute to get better corresponding data.
        """
        self._varnode_upgrader_setup()
        if not self.varnode:
            return
        self._find_sym_trace_descend(self.varnode)
        
    def _varnode_upgrader_setup(self):
        """Initializes the attributes as None first.
        """
        self.origin_varnode = self.varnode
        self.high_var = None
        if self.varnode is not None:
            self.high_var = self.varnode.getHigh()
        self.name = None
        if self.high_var:
            self.name = self.high_var.getName()
        self.buffer_size = None
        self.sym = None
        
        
    def _find_sym_trace_def(self, varnode):
        """Tries to find a better varnode by matching the available symbol objects.
        
        Parameters:
            varnode (ghidra.program.model.pcode.Varnode)
        """
        process_queue = [varnode]
        iteration_count = 0
        while (len(process_queue) > 0) and (iteration_count < FIND_BETTER_ARG_MAX_ITERATIONS):
            iteration_count += 1
            process_vn = process_queue.pop(0)
            process_vn_high = process_vn.getHigh()
            if process_vn_high:
                process_vn_sym = process_vn_high.getSymbol()
                if process_vn_sym:
                    process_vn_sym_name = process_vn_sym.getName()
                    if process_vn_sym_name not in ("UNNAMED", None):
                        logger.debug("Found by symbol name {} at iteration {}".format(process_vn_sym_name, iteration_count))
                        self.__set_attributes_via_varnode_and_symbol(process_vn, process_vn_sym)
                        return 
            try:
                varnode_pc_address = process_vn.getPCAddress()
                if varnode_pc_address in GLOBAL_SYMBOLS_TRACE_MAP:
                    logger.debug("Found symbol by global symbols trace map")
                    self.__set_attributes_via_varnode_and_symbol(process_vn, GLOBAL_SYMBOLS_TRACE_MAP[varnode_pc_address])
                    return 
            except java.lang.NullPointerException:
                # This normally happens when the varnode was obtained from a Param. 
                # The varnode seems to be valid in the sense that it is not None, 
                # but when .getPCAddress() is invoked, this error occurs.
                logger.debug("java.lang.NullPointerException in getting the varnode PC Address for {} in {}".format(self, self.get_parent()))
            
            logger.debug("Iteration {} going into getDef".format(iteration_count))
            vn_def = process_vn.getDef()
            if vn_def is None:
                logger.debug("vndef is None")
                continue
            if vn_def.getOpcode() == PcodeOp.CALL:
                logger.debug("vndef is CALL pcode")
                continue # dont get arg info from another funccall
            process_queue.extend(vn_def.getInputs())
            
        
    def _find_sym_trace_descend(self, varnode):
        """Tries to find a better varnode by matching the available symbol objects (slight variation for FuncCallOutput).
        
        Parameters:
            varnode (ghidra.program.model.pcode.Varnode)
        """
        process_queue = [varnode]
        iteration_count = 0
        while (len(process_queue) > 0) and (iteration_count < FIND_BETTER_ARG_MAX_ITERATIONS):
            iteration_count += 1
            process_vn = process_queue.pop(0)
            process_vn_high = process_vn.getHigh()
            if process_vn_high:
                process_vn_sym = process_vn_high.getSymbol()
                if process_vn_sym:
                    process_vn_sym_name = process_vn_sym.getName()
                    if process_vn_sym_name not in ("UNNAMED", None):
                        logger.debug("Found by symbol name {} at iteration {}".format(process_vn_sym_name, iteration_count))
                        self.__set_attributes_via_varnode_and_symbol(process_vn, process_vn_sym)
                        return 
            
            logger.debug("Iteration {} going into getLoneDescend".format(iteration_count))
            vn_desc = process_vn.getLoneDescend()
            if vn_desc is None:
                logger.debug("vn descend is None")
                continue
            if vn_desc.getOpcode() == PcodeOp.CALL:
                logger.debug("vn descend is CALL pcode")
                continue # dont get arg info from another funccall
            process_queue.append(vn_desc.getOutput())
    
    def __set_attributes_via_varnode_and_symbol(self, varnode, symbol):
        """Sets the attributes based on the upgraded varnode and symbol found.

        Parameters:
            varnode (ghidra.program.model.pcode.Varnode): 
                The upgraded varnode found.
            symbol (ghidra.program.model.pcode.HighSymbol): 
                The symbol that the upgraded varnode is based on.
        """
        self.varnode = varnode
        self.high_var = varnode.getHigh()
        self.sym = symbol
        self.name = symbol.getName()
        if self.name in (None, "UNNAMED"): # Fallback to high variable name just in case
            self.name = self.high_var.getName() 
        if isinstance(symbol, CodeSymbol):
            return # CodeSymbol (i.e. the symbols obtained from global_symbols_trace_map do not have the getStorage method; they have no buffer size) 
        self.buffer_size = symbol.getStorage().size()
        return 


class Func(object):
    """Represents a decompiled function.
    
    Attributes:
        entry_address (ghidra.program.model.address.Address)
        func (ghidra.program.model.listing.Function)
        name (str)
        params (list[Param])
        high_func (ghidra.program.model.pcode.HighFunction | None)
        pcode_ops (list[ghidra.program.model.pcode.PcodeOpAST]):
            The PcodeOpAST objects for the decompiled pcode of this function. They are saved in this attribute because
            they are accessed a lot and it is relatively slow to get them via the Ghidra API every time.
            This needs to be set first using the get_pcode_ops() method.
        func_calls (list[FuncCall]):
            The corresponding FuncCall objects (i.e. the places where this function is called). 
            This has to be obtained by separately invoking the find_func_calls() method when it is needed.
            This is to prevent the recursion of the FuncCall initializing its caller_func (Func), which initializes its
            FuncCall's caller_func (Func), and so on (Recursion is not ideal as described in the main() function).
        is_traced (bool):
            Whether the tracing for this function is already done (this is to prevent re-tracing the same thing).
        vn_sym_map (dict[ghidra.program.model.pcode.Varnode, ghidra.program.model.pcode.HighSymbol]):
            Several methods may need the symbol of a varnode with this function, thus this stores the saved results of 
            the get_symbol() method to prevent re-processing the same thing.
        return_val (ReturnVal)
        instances_at (dict[ghidra.program.model.address.Address, Func]):
            Class attribute used by the get_instance_at() method for deduplication of instances.
            Maps the entrypoint addresses to the corresponding Func objects.
        instances_containing (dict[ghidra.program.model.address.Address, Func]):
            Class attribute used by the get_instance_containing() method for deduplication of instances.
            Maps the addresses to the corresponding Func objects.

    See Also:
        Param
        ReturnVal
        FuncCall
    """
    def __init__(self, entry_addr):
        """Initializes the Func and its corresponding Param and ReturnVal objects.
        
        Parameters:
            entry_address (ghidra.program.model.address.Address)
            
        Raises:
            InvalidFuncErr: If the entry_address given does not correlate to an actual function as per the Ghidra API.
            
        See Also:
            self.get_instance_at()
            self.get_instance_containing()
        """
        self.entry_address = entry_addr
        self.func = getFunctionAt(entry_addr)
        if self.func is None:
            msg = "0x{} is in an invalid function".format(entry_addr)
            raise InvalidFuncErr(msg)
        self.name = self.func.getName()
        self.params = [Param(self, i) for i in range(len(self.func.getParameters()))]
        self.high_func = self.get_high_function(self.func)
        self.is_traced = False
        self.func_calls = None # Get by invoking self.find_func_calls() whenever it is needed
        self.pcode_ops = None # Get by invoking self.get_pcode_ops() whenever it is needed
        self.return_val = ReturnVal(self)
        self.vn_sym_map = {}

    
    def __str__(self):
        return "0x{} {}({}) <=> {}".format(self.entry_address, self.name, ", ".join(str(i) for i in self.params), self.return_val)

    @classmethod 
    def get_instance_at(cls, entry_addr): 
        """Gets an existing instance of the Func at entry_addr, else it creates a new one. 
        
        It only creates a new instance if an instance corresponding to the entry_addr has not already been created.
        Otherwise it returns the existing instance. This is because the program traces all the paths, so it may go in 
        and out of a function multiple times. By returning existing instances, the same information can be accessed 
        without needing to re-process, making the program much faster.
                
        Notes:
            - Saves newly initialized Func objects to the instances_at attribute for deduplication
            - Also supresses the InvalidFuncErr. The reason is described in this example:
              In the asus_httpd test case, the Ghidra decompiler shows a call to func_0x00018404(auStack1052,sVar1,param_2).
              However, jumping to the function, or the address 0x00018404 does not have any decompiler results. 
              The listing view (disassembly) also shows no function.
            
        Parameters:
            entry_address (ghidra.program.model.address.Address)
                
        Returns:
            Func | None
        """
        if not hasattr(cls, 'instances_at'):
            cls.instances_at = {}

        if entry_addr in cls.instances_at:
            return cls.instances_at[entry_addr]
        try:
            instance = cls(entry_addr)
        except InvalidFuncErr:
            logger.error("Error in initializing Func at 0x{}".format(entry_addr))
            instance = None
        cls.instances_at[entry_addr] = instance
        return instance

    @classmethod 
    def get_instance_containing(cls, addr): 
        """Similar to get_instance_at, but gets the instance containing the given address.

        Given an address in a function whereby its entrypoint is not known, find the 
        entrypoint and proceed with get_instance_at.
              
        Notes:
            - Saves newly initialized Func objects to the instances_containing attribute for deduplication

        Parameters:
            addr (ghidra.program.model.address.Address)

        Returns:
            Func | None
        """
        if not hasattr(cls, 'instances_containing'):
            cls.instances_containing = {}
            
        caller_func = getFunctionContaining(addr)
        if AUTO_DEFINE_UNDEFINED_FUNCTIONS and caller_func is None:
            caller_func = cls.define_undefined_function_containing(addr)
        if caller_func is None:
            if not SUPRESS_CANNOT_FIND_PARENT_FUNCTION_WARNING:
                logger.warning("Couldn't find parent function containing the address 0x{}".format(addr))
            cls.instances_containing[addr] = None
            return None
        entrypoint = caller_func.getEntryPoint()
        instance = cls.get_instance_at(entrypoint)
        cls.instances_containing[addr] = instance
        return instance


    @classmethod 
    def get_instances_by_name(cls, function_name):
        """Get all functions in the function manager matching the specified name.

        Parameters:
            function_name (str)

        Returns:
            list[Func]
        """
        # This function does not have an instances_xxxx attribute for preventing 
        # re-calculatinon as it's currently only called once per sink at the 
        # start of the program. 
        # Deduplication itself is also already provided by cls.get_instance_at()
        instances = []
        all_functions = function_manager.getFunctions(True)  # True means forward
        for func in all_functions:
            if func.getName() != function_name:
                continue
            entrypoint = func.getEntryPoint()
            instance = cls.get_instance_at(entrypoint)
            instances.append(instance)
            logger.debug("Found Func {} @ 0x{}".format(function_name, entrypoint))
        return instances
    
    def get_pcode_ops(self):
        """Get the PcodeOpAST objects for the decompiled pcode of this function. 
        
        Notes:
            - The results are saved in the pcode_ops attribute 
              
        Returns:
            list[ghidra.program.model.pcode.PcodeOpAST]
        """
        if self.pcode_ops is not None:
            return self.pcode_ops
        self.pcode_ops = []
        if self.high_func:
            self.pcode_ops = list(self.high_func.getPcodeOps())
        return self.pcode_ops
    
    
    def get_symbol(self, varnode):
        """Get the corresponding symbol and buffer size for a given varnode
        
        Notes:
            - The results are saved in the vn_sym_map attribute to prevent re-processing the same thing.

        Returns:
            tuple[Symbol, int] | None
        """
        if self.high_func is None:
            return None
        if varnode in self.vn_sym_map:
            return self.vn_sym_map[varnode]
        
        for sym in self.high_func.getLocalSymbolMap().getSymbols():
            
            sym_hvar = sym.getHighVariable()
            if sym_hvar:
                for sym_instance in sym_hvar.getInstances():
                    if sym_instance != varnode:
                        continue
                    ret = sym, sym.getStorage().size(),
                    self.vn_sym_map[varnode] = ret
                    logger.debug("Matched symbol via instance check for {}".format(sym))
                    return ret
                    
            if TRACE_SYMBOL_OFFSET:
                # Another less accurate check, because not all symbols have HighVariable
                for sym_varnode in sym.getStorage().getVarnodes():
                    if sym_varnode.getOffset() != varnode.getOffset():
                        continue
                    ret = sym, sym.getStorage().size(),
                    self.vn_sym_map[varnode] = ret
                    logger.debug("Matched symbol via offset check for {}".format(sym))
                    return ret
        self.vn_sym_map[varnode] = None
        return None

    def find_func_calls(self):
        """Get the corresponding FuncCall objects of this function (i.e. where this function is called at)

        Notes:
            - The result is stored in the func_calls attribute
        """
        if self.func_calls is not None:
            return

        instances = []
        # Find references (UNCONDITIONAL_CALL) to this func
        for ref in getReferencesTo(self.entry_address):
            if ref.getReferenceType() != RefType.UNCONDITIONAL_CALL:
                continue
            caller_func = Func.get_instance_containing(ref.getFromAddress())
            if caller_func is None:
                continue
            # Find caller function (to get the pcodes)
            for pcode_op in caller_func.get_pcode_ops():
                # Find CALL pcode of the reference's address
                if pcode_op.getOpcode() != PcodeOp.CALL:
                    continue
                if pcode_op.getSeqnum().getTarget() != ref.getFromAddress():
                    continue
                fc = FuncCall.get_instance(pcode_op)
                if fc is None:
                    continue
                instances.append(fc)
        self.func_calls = instances
        return
    
    def trace_var_usage(self, node):
        """Trace all the usages of the same node within the function.
        
        Example:
            In this pseudocode, there will be two traces to link the variable `x`,
            one trace from line 4 to line 3, another from line 3 to line 2.
            ```
            1   def main():
            2        x = someFunc()
            3        someOtherFunc(x)
            4        return x
            ```
        
        Args:
            node (Param | ReturnVal | Arg | ParamArg)
            
            
        Returns:
            None | list[] | list[list[TraceInfo]]
            
            If there are results found, they will be in this format:
            [
              [Arg -> Arg, Arg -> Arg], 
              [FuncCallOutput -> Arg, Arg -> Arg],
              [FuncCallOutput -> Arg], 
              ...
            ]
            Each inner list represents a segment. Each segment will be where Args will flow to each other, 
            and are separated when there is a FuncCallOutput. This separation is because a FuncCallOutput will mean that
            the variable will definitely have its value overriden by the new output, so it does not make sense for that
            part to be linked.
        """
        logger.debug("Checking same usages of {} in {}".format(node, self))
        if not self.high_func:
            return 
        if not node.varnode:
            return
        
        # ---------- Finding same vars ---------- #
        same_vars_in_func = []
        for pcode in self.get_pcode_ops():
            if pcode.getOpcode() != PcodeOp.CALL:
                continue
            fc = FuncCall.get_instance(pcode)
            if fc is None:
                continue
            
            for arg in fc.args: 
                # Same symbol check - each arg
                if node.sym and node.sym == arg.sym:
                    logger.debug("Found sym match to {} of {}".format(arg, fc))
                    same_vars_in_func.append(arg)
                    continue
            
            # Same symbol check - funccall output
            if node.sym and node.sym == fc.output.sym:
                logger.debug("Found match to {} of {}".format(fc.output, fc))
                same_vars_in_func.append(fc.output)
                continue

        logger.debug("{} matches for trace_var_usage".format(len(same_vars_in_func)))
        
        
        # ---------- Linking traces of same vars ---------- #
        traces = [[]] # 2nd-level list is for splitting the SameVarInFunc traces into different segments (see the comment for the FuncCallOutput check)
        for i in range(len(same_vars_in_func)):
            same_vars_in_func[i].is_traced_same_var = True
            if i == 0:
                continue
            
            # Don't link a FuncCallOutput as the sink. The value of the FuncCallOutput depends 
            # on the Func's ReturnVal, so it does not make sense to have a source flow into a 
            # FuncCallOutput as a sink via SameVarInFunc.
            if isinstance(same_vars_in_func[i], FuncCallOutput): 
                # Add another list to represent another trace segment (if this condition activates, 
                # that means that the traces are not one continuous flow. There are multiple different 
                # segments of traces. 
                # E.g. 
                #   [Arg -> Arg, Arg -> Arg], 
                #   [FuncCallOutput -> Arg, Arg -> Arg],
                #   [FuncCallOutput -> Arg], ...
                if traces[-1] != []:
                    traces.append([])
                continue
            traces[-1].append(TraceInfo.get_instance(same_vars_in_func[i-1], same_vars_in_func[i], TraceType.SameVarInFunc))
        if traces[-1] == []: # if nothing was added, remove the empty segment
            traces.pop()
        return traces 
        
    def get_arbitrary_param(self):
        """Get the existing ArbitraryParam instance, else create a new one and add it to the params attribute.
        
        Attributes:
            params (list[Param]): Adds an ArbitraryParam object to the end of the list if it is not already initialized.
            
        Returns:
            ArbitraryParam
        """
        if self.params == [] or not isinstance(self.params[-1], ArbitraryParam):
            self.params.append(ArbitraryParam(self))
        return self.params[-1]

    @staticmethod
    def get_high_function(function):
        """Get the Ghidra API's high-level function object from the corresponding low-level function object.

        Args:
            function (ghidra.program.model.listing.Function)

        Returns:
            ghidra.program.model.pcode.HighFunction | None
        """
        decompiler_response = decompiler_interface.decompileFunction(function, 60, monitor)
        high_function = decompiler_response.getHighFunction()
        return high_function

    @staticmethod
    def define_undefined_function_containing(address, iteration_limit=2000):
        """Given an address that is called under a UndefinedFunction, define it in order to get a Function object.
        
        When tracing, we have a certain address whereby a callee function is called by the caller. In many cases we need
        to get the caller Function object to continue tracing. However, sometimes ghidra may have something like 
        "UndefinedFunction_00022e04" which seems to works as a function, but I am not sure why it is not automatically 
        defined as one. This is a problem a getting the Function object of such undefined functions will result in None,
        thus we are finding, defining, and returning it here.
        
        Parameters:
            address (ghidra.program.model.address.Address): 
                An address that is inside the undefined function. E.g. the callee's reference's getFromAddress()
            iteration_limit (int):
                Give up on finding the undefined function after checking through this number of instructions. Defaults to 2000.

        Notes:
            - This function is not very accurate and may cause problems. See the `auto_define_undefined_functions` flag 
              in the config to enable/disable usage of this function.
            - The current implementation checks against a few specific assembly instructions that could signify the 
              start of a function. This means that for now, it will only work for ARM binaries because only instructions
              for ARM are defined. 
            - In addition, since only there are only a few instructions in the check, it may not detect all undefined 
              functions.
            - Furthermore, the check can go past the actual 'UndefinedFunction' and it tries to define a function 
              somewhere else or defines an already existing function, causing inconsistencies or even errors in the
              tracing.

        Reference:
            For more information, or to add instructions for other architectures, see the script included with Ghidra 
            as per the link:
            https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/FindUndefinedFunctionsScript.java

        Returns:
            Function | None
        """
        if not processor.equals(Processor.findOrPossiblyCreateProcessor("ARM")):
            logger.warning("Signatures for defining an undefined function not implemented for non-ARM architectures")
            return None
        
        assembly_instruction = listing.getInstructionAt(address) # instruction at the callee's Reference.getFromAddress()
        count = 0
        while assembly_instruction.toString() not in ( # These assembly instructions signify a function starting point
            u'cpy r0,r5', # From asus_httpd @ 0x00026e28
            u'stmdb sp!,{r4 r5 r6 r7 r9 r10 r11 lr}', # From asus_httpd @ 0x0005d620
            u'stmdb sp!,{r3 r4 r5 r6 r7 lr}', # From a_dnsmasq @ 0x00022e04
            # Reference for signatures below: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/FindUndefinedFunctionsScript.java
            u'stmdb sp!,{r4 r5 r6 r7 lr}',
            u'stmdb sp!,{r4 r5 r7 lr}',
            u'stmdb sp!,{r4 r7 lr}',
            u'stmdb sp!,{r7 lr}'):
            if count > iteration_limit:
                logger.debug("Unable to define undefined function containing 0x{} - Iteration limit has been reached".format(address))
                return None
            count += 1
            assembly_instruction = getInstructionBefore(assembly_instruction)
        undefined_caller_address = assembly_instruction.getAddress()
        logger.debug("Defined undefined function containing 0x{} - Matched signature {} at {}".format(address, assembly_instruction.toString(), undefined_caller_address))
        return createFunction(undefined_caller_address, None)

class Param(VarnodeUpgraderMixin, object):
    """Represents a parameter of a function (Func).
    
    Attributes:
        func (Func)
        index (int)
        forward_traces (list[TraceInfo])
        backward_traces (list[TraceInfo])
        is_traced (bool):
            Whether the tracing for this object is already done (this is to prevent re-tracing the same thing).
        is_traced_same_var (bool):
            Similar to is_traced, but for tracing via the corresponding Func's trace_var_usage() method. 
            This is because that method traces all of the same variables, so even if tracing was not started for this 
            object in particular, a similar variable tracing via the trace_var_usage() method may have resulted in a
            trace to this object as well. Thus, this other flag is needed for keeping track of the individual tracing
            methods vs the Func's trace_var_usage() method.
            
    Notes:
        - Param is differentiated from Arg in the sense that a parameter (Param) is the variable of a function (Func), 
          while an argument (Arg) is a variable of a function call (FuncCall). When a function is called more than once,
          multiple Args, one from each time that it is called, will correspond to the same parameter.
          
    See Also:
        VarnodeUpgraderMixin
        Func
    """
    def __init__(self, func, index):
        """Initializes the Param.
        
        Parameters:
            func (Func)
            index (int)
        """
        self.func = func
        self.index = index
        self.forward_traces = []
        self.backward_traces = []
        self.is_traced = False # 
        self.is_traced_same_var = False

    def __str__(self):
        return "Param{}".format(self.index+1)
    
    def get_parent(self):
        """Gets the corresponding Func.
        
        This method is available for Param, ReturnVal, Arg, and FuncCallOutput as a convenient way to get the
        corresponding parent (i.e. Param and ReturnVal => Func, Arg and FuncCallOutput => FuncCall).
        
        Returns:
            Func
        """
        return self.func
    
    def trace_to_arg(self):
        """Trace from this parameter to the arguments from all the places where the function is called.
        """
        self.func.find_func_calls()
        for fc in self.func.func_calls:
            arg = fc.args[self.index]
            TraceInfo.get_instance(arg, self, TraceType.ParamToArg) 

    def trace_source_all(self):
        """Main tracing method to start all the other appropriate tracing methods.
        """
        
        # Only process specific types of tracing based on past traces:
        if not self.is_traced: 
            for trace in self.forward_traces: 
                # ArgIsParam means that it was traced from within this Func, so we now need to trace 
                # the flow of Args passed in from outside the Func.
                if trace.trace_type != TraceType.ArgIsParam:
                    continue
                self.trace_to_arg()
                self.is_traced = True
                break
            
        # Only process specific types of tracing based on past traces:
        if not self.is_traced_same_var:
            for trace in self.backward_traces: 
                # ArgUsagePassedIntoFunc means that the trace was from passing in a value outside of this Func, 
                # so now we need to check trace the flow of that value within this Func.
                if trace.trace_type != TraceType.ArgUsagePassedIntoFunc:
                    continue
                self.varnode = self.func.func.getParameters()[self.index].getVariableStorage().getLastVarnode()
                self.sym = None
                vn_sym, _ = self.func.get_symbol(self.varnode) or (None, None)
                if vn_sym:
                    self.sym = vn_sym

                logger.debug(
                    "Starting trace_var_usage for Param with sym {} ({})".format(
                        self.sym,
                        self.sym.getName() if self.sym else "NoName",
                        )
                    )
                linked_traces = self.func.trace_var_usage(self)
                if not linked_traces: # if None or []
                    break
                for segment in linked_traces: 
                    last_linked_node = segment[-1].sink_node
                    TraceInfo.get_instance(last_linked_node, trace.source_node, TraceType.ArgUsagePassedIntoFuncExit)
            self.is_traced_same_var = True  

                

class ArbitraryParam(Param):
    """Params that match to an arbitrary number of arguments. Inherits from Param.
    
    Example:
        For sprintf(str, format, ...), only the 1st and 2nd arguments are required. Only these 2 are detected in 
        Ghidra's function signature; any arbitrary arguments after that are not included. 
        However, Ghidra will still detect that 3 or more arguments are passed when the function is called:
        E.g. sprintf(str, "%d + %d is equal %d", a, b, c);
        As Param is only defined based in the function signature, we have this ArbitraryParam to account for the rest
        of them. Thus, the a, b, and c variables of the sprintf call will be linked to this ArbitraryParam object.
    
    See Also:
        Param
    """
    def __init__(self, func): 
        """Initializes the ArbitraryParam.
        
        Parameters:
            func (Func): The function that the param belongs to.
        """
        super(ArbitraryParam, self).__init__(func, None)
        
    def __str__(self):
        return "ArbitraryParams"
    
    

    def trace_source_all(self):
        """Starts all the appropriate tracing methods.
        """
        if not self.is_traced:
            self.func.find_func_calls()
            self.is_traced = True

class ReturnVal(VarnodeUpgraderMixin, object):
    """Represents the return value of a function (Func).
    
    Attributes:
        func (Func)
        forward_traces (list[TraceInfo])
        backward_traces (list[TraceInfo])
        is_traced (bool):
            Whether the tracing for this object is already done (this is to prevent re-tracing the same thing).
        is_traced_same_var (bool):
            Similar to is_traced, but for tracing via the corresponding Func's trace_var_usage() method. 
            This is because that method traces all of the same variables, so even if tracing was not started for this 
            object in particular, a similar variable tracing via the trace_var_usage() method may have resulted in a
            trace to this object as well. Thus, this other flag is needed for keeping track of the individual tracing
            methods vs the Func's trace_var_usage() method.
        varnode (ghidra.program.model.pcode.Varnode)
        
    See Also:
        VarnodeUpgraderMixin
        Func
    """
    def __init__(self, func):
        """Initializes the ReturnVal.
        
        Parameters:
            func (Func)
        """
        self.func = func 
        self.forward_traces = [] # Forwards in terms of execution flow: Where does this value flow to?
        self.backward_traces = [] # Backwards in terms of execution flow: Where is this value sourced from?
        self.is_traced = False
        self.is_traced_same_var = False
        
        self.varnode = self.__find_return_val_varnode()
        self.varnode_upgrade()
    
        
    def trace_source_all(self):
        """Main tracing method to start all the other appropriate tracing methods.
        """
        
        if not self.is_traced:
            self.trace_func_call_output()
            self.is_traced = True
            
        if not self.is_traced_same_var:
            linked_traces = self.func.trace_var_usage(self) 
            
            
            if linked_traces:
                for segment in linked_traces: 
                    last_linked_node = segment[-1].sink_node
                    TraceInfo.get_instance(last_linked_node, self, TraceType.ArgUsagePassedIntoFuncExit)

            self.is_traced_same_var = True
            
    def trace_func_call_output(self):
        """If this return value comes from a funccalloutput
        
        Example:
            ```
            x = someFunc(...)
            return x
            ```
        """
        if not self.varnode:
            return
        
        process_queue = [self.varnode] 
        iteration_count = 0
        while len(process_queue) > 0 and iteration_count < FIND_BETTER_ARG_MAX_ITERATIONS:
            iteration_count += 1
            process_vn = process_queue.pop(0)
            vn_def = process_vn.getDef()
            if vn_def is None:
                continue
            if vn_def.getOpcode() == PcodeOp.CALL:
                fc = FuncCall.get_instance(vn_def)
                if fc is None:
                    continue
                TraceInfo.get_instance(self, fc.output, TraceType.VarIsFuncCallOutput)
                return
            
            
            
            process_queue.extend(vn_def.getInputs())
            
    def trace_param(self):
        """Return varnode could be parameter 
        """
        if not self.high_var:
            return
        
    def __find_return_val_varnode(self):
        """Find the RETURN pcode op(s) and get the varnode corresponding to the return value.
        """
        
        for p in self.func.get_pcode_ops():
            if p.getOpcode() == PcodeOp.RETURN:
                return_vns = p.getInputs()
                return_vn = return_vns[0]
                if len(return_vns) == 2: 
                    return_vn = return_vns[1]
                break
        else:
            logger.warning("No return pcode for Func in 0x{} {}()".format(self.get_parent().entry_address, self.get_parent().name))
            return None
        
        if return_vn.isConstant() and return_vn.getOffset() in (0,1):
            # Simply returning status code:
            # ---  RETURN (const, 0x0, 4)
            # ---  RETURN (const, 0x1, 4)
            return None
            
        process_queue = [return_vn]
        iteration_count = 0
        while len(process_queue) > 0 and iteration_count < FIND_BETTER_ARG_MAX_ITERATIONS:
            iteration_count += 1
            process_vn = process_queue.pop(0)
            if isinstance(process_vn.getHigh(), HighParam):
                return process_vn
            vn_def = process_vn.getDef()
            if vn_def is None:
                continue
            if vn_def.getOpcode() == PcodeOp.CALL:
                continue # dont get arg info from another funccall
            if vn_def.getOpcode() == PcodeOp.PTRSUB:
                return vn_def.getInput(1) # The varnode corresponding to an actual stack variable is the 2nd input
                
            if vn_def.getOpcode() == PcodeOp.COPY:
                return vn_def.getInput(0) 
            process_queue.extend(vn_def.getInputs())
        
        logger.debug("Couldn't find better ReturnVal for Func in 0x{} {}()".format(self.get_parent().entry_address, self.get_parent().name))
        return return_vn
            
        
    def get_name(self):
        if self.varnode is None:
            return "StatusCodeReturn"
        if self.name == "UNNAMED" or self.name is None:
            return "UnnamedReturn"
        return self.name

    def __str__(self):
        if self.buffer_size:
            return "{}[{}]".format(self.get_name(), self.buffer_size)
        return "{}".format(self.get_name())
    
    def get_parent(self):
        """Gets the corresponding Func.
        
        This method is available for Param, ReturnVal, Arg, and FuncCallOutput as a convenient way to get the
        corresponding parent (i.e. Param and ReturnVal => Func, Arg and FuncCallOutput => FuncCall).
        
        Returns:
            Func
        """
        return self.func
    
class FuncCall(object):
    """Represents a function call (i.e. where a function is invoked).
    
    Attributes:
        call_pcode (ghidra.program.model.pcode.PcodeOpAST)
        addr (ghidra.program.model.address.Address)
        caller_func (ghidra.program.model.listing.Function)
        callee_func (ghidra.program.model.listing.Function)
        args (list[Arg])
        output (FuncCallOutput)
        instances (dict[ghidra.program.model.address.Address, FuncCall]):
            Class attribute used by the get_instance() method for deduplication of instances.
            Maps the addresses of the function call instruction to the corresponding FuncCall objects.
            
    See Also:
        Arg
        FuncCallOutput
        Func
    """
    def __init__(self, call_pcode):
        """Initializes the FuncCall and its corresponding Arg and FuncCallOutput objects.
        
        Parameters:
            call_pcode (ghidra.program.model.pcode.PcodeOpAST)
            
        Raises:
            InvalidFuncErr: If the call_pcode's target address (i.e. the address of the function being called) 
                            does not correlate to an actual function as per the Ghidra API.

        Notes:
            - Initialization of this FuncCall object will also automatically get/initialize 
              the corresponding Func object for both caller and calee functions.
        """
        self.call_pcode = call_pcode
        self.addr = call_pcode.getSeqnum().getTarget()
        self.caller_func = Func.get_instance_containing(self.addr)
        self.callee_func = Func.get_instance_at(call_pcode.getInput(0).getAddress())
        if self.callee_func is None: # FuncCall must have a proper function to call
            raise InvalidFuncErr
        self.args = [Arg(self, i, vn) for i, vn in enumerate(call_pcode.getInputs()[1:])]
        self.output = FuncCallOutput(self, call_pcode.getOutput())

    @classmethod 
    def get_instance(cls, call_pcode): 
        """Gets an existing instance of the FuncCall corresponding to the call_pcode, else it creates a new one. 
        
        Similarly to Func.get_instance_at(), this method only creates a new instance if an instance corresponding to the
        call_pcode has not already been created. Otherwise it returns the existing instance. This is because the program
        traces all the paths, so it may go in and out of a function multiple times. By returning existing instances, the
        same information can be accessed without needing to re-process, making the program much faster.
                
        Notes:
            - Also supresses the InvalidFuncErr. The reason for this is the same as described in Func.get_instance_at()

        Parameters:
            call_pcode (ghidra.program.model.pcode.PcodeOpAST)
              
        Attributes:
            instances (dict[ghidra.program.model.address.Address, FuncCall]):
                Adds newly initialized Func objects to this attribute for deduplication
            
        Returns:
            FuncCall | None
        """
        if not hasattr(cls, 'instances'):
            cls.instances = {}
        addr = call_pcode.getSeqnum().getTarget()
        if addr in cls.instances:
            return cls.instances[addr]
        try:
            instance = cls(call_pcode)
        except InvalidFuncErr:
            instance = None
        cls.instances[addr] = instance
        return instance

    def __str__(self):
        return "0x{} {}({}) <=> {}".format(self.addr, self.callee_func.name, ", ".join(str(i) for i in self.args), self.output)

    
class Arg(VarnodeUpgraderMixin, object):
    """Represents an argument of a function call (FuncCall)
    
    Attributes:
        func_call (FuncCall)
        index (int)
        varnode (ghidra.program.model.pcode.Varnode)
        forward_traces (list[TraceInfo])
        backward_traces (list[TraceInfo])
        is_traced (bool):
            Whether the tracing for this object is already done (this is to prevent re-tracing the same thing).
        is_traced_same_var (bool):
            Similar to is_traced, but for tracing via the corresponding Func's trace_var_usage() method. 
            This is because that method traces all of the same variables, so even if tracing was not started for this 
            object in particular, a similar variable tracing via the trace_var_usage() method may have resulted in a
            trace to this object as well. Thus, this other flag is needed for keeping track of the individual tracing
            methods vs the Func's trace_var_usage() method.
            
    See Also:
        VarnodeUpgraderMixin
        FuncCall
    """
    def __init__(self, func_call, index, varnode):
        """Initializes the Arg.
        
        Parameters:
            func_call (FuncCall)
            index (int)
            varnode (ghidra.program.model.pcode.Varnode)
        """
        self.func_call = func_call
        self.index = index
        self.varnode = varnode
        self.forward_traces = []
        self.backward_traces = []
        self.is_traced = False # Whether it has already run self.trace_source_all so we can check to not re-trace anything
        self.is_traced_same_var = False # SameVarInFunc tracing can happen even without source_trace_all
        self.varnode_upgrade()

    def get_name(self):
        if self.name == "UNNAMED" or self.name is None:
            return "UnnamedArg{}".format(self.index+1)
        return self.name

    def __str__(self):
        if self.buffer_size:
            return "{}[{}]".format(self.get_name(), self.buffer_size)
        return "{}".format(self.get_name())
    
    def get_parent(self):
        """Gets the corresponding FuncCall.
        
        This method is available for Param, ReturnVal, Arg, and FuncCallOutput as a convenient way to get the
        corresponding parent (i.e. Param and ReturnVal => Func, Arg and FuncCallOutput => FuncCall).
        
        Returns:
            FuncCall
        """
        return self.func_call
        
    def trace_source_all(self):
        """Main tracing method to start all the other appropriate tracing methods.
        """
        
        if not self.is_traced:
            if isinstance(self.high_var, HighParam):
                self.trace_source_param()
            else:
                self.trace_to_func_call_output()
            if  ( 
                    # Only applies for thunk functions because they do not have code inside for us to trace
                    (self.func_call.callee_func.func.isThunk())
                    # Do not do this trace if it was traced from another Arg already (Prevent chaining of ArgToOtherArgs)
                    and not (len(self.forward_traces) == 1 and self.forward_traces[0].trace_type == TraceType.ArgToOtherArgs)
                ):
                self.trace_to_other_args()
            else:
                if not (len(self.forward_traces) == 1 and self.forward_traces[0].trace_type == TraceType.ParamToArg):
                    # The arg_usage_inside_func (i.e. how the arg is modified as it passes through the callee function) 
                    # only needs to be known if the Arg was traced from further down past the FuncCall. If this ParamArg 
                    # was traced exclusively via ParamToArg, that means that the sink came from within the callee Func 
                    # itself, so there is no need to trace what happens below the FuncCall. Remember that this program 
                    # is for sink-to-source tracing, so we only need to trace upwards.
                    self.trace_arg_usage_inside_func()
            self.is_traced = True
        if not self.is_traced_same_var and self.func_call.caller_func:
            self.func_call.caller_func.trace_var_usage(self) 
            self.is_traced_same_var = True

    def trace_to_other_args(self):
        """Link this arg to the other arguments of the FuncCall
        
        When the the FuncCall's callee is a thunk function, we cannot check the usages of the param inside the function, 
        but the other args may still affect the value of this arg. 
        
        Example:
            In strcpy(src, dst), the src arg should trace to the dst arg.
        """

        # Functions with source_sink_parameter_signatures: Don't link the wrong way. 
        # E.g. For strcpy(dest, src), the trace should have the arg #0 (dest) as the sink_node and the arg #1 (src) as the source_node.
        # See the source_sink_parameter_signatures option in the config file for the full explanation. 
        callee_name = self.func_call.callee_func.name
        if callee_name in SOURCE_SINK_PARAMETER_SIGNATURES:
            dest_param_indexes = SOURCE_SINK_PARAMETER_SIGNATURES[callee_name]["destination_parameter_indexes"]
            if self.index not in dest_param_indexes:
                return
            src_param_indexes = SOURCE_SINK_PARAMETER_SIGNATURES[callee_name]["source_parameter_indexes"]
            for idx in src_param_indexes:
                TraceInfo.get_instance(self.func_call.args[idx], self, TraceType.ArgToOtherArgs)
            return

        # As we can't know which arg is dest/src for every function (especially user-defined functions), 
        # we just link to every other arg.
        for arg in self.func_call.args:
            # Don't link to itself
            if arg == self:
                continue
            
            TraceInfo.get_instance(arg, self, TraceType.ArgToOtherArgs)
        
    def trace_arg_usage_inside_func(self): 
        """Link the arg to the corresponding parameters and its usage inside the FuncCall's callee function.
        
        This is because the argument may be a reference to a buffer that is modified when passed in to the callee.
        """
        try:
            param = self.func_call.callee_func.params[self.index]
        except IndexError:
            logger.debug("Found arg without param of matching index. Placing it in arbitrary args")
            param = self.func_call.callee_func.get_arbitrary_param()
        TraceInfo.get_instance(self, param, TraceType.ArgUsagePassedIntoFunc)
        
    def trace_to_func_call_output(self):
        # Trying out repeated tracing loop: 
        # Note that it may trace to multiple FuncCallOutputs because of the MULTIEQUAL P-Code (See https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/additionalpcode.html)
        logger.debug("Entering loop for getDef to find all corresponding FuncCallOutputs of varnode @ 0x{} in {} of {}".format(self.origin_varnode.getPCAddress(), self, self.get_parent()))
        varnode_processing_queue = [self.origin_varnode]
        # NOTE: For the deduplication_list, this is to prevent unnecessary computations because seemingly the same  
        #       varnode could be encountered multiple times. I am not entirely sure why Ghidra does it like this but for
        #       example, a MULTIEQUAL pcode can have multiple of its input varnodes being the same:
        #       Pcode:                  (ram, 0x349f0, 4) MULTIEQUAL (ram, 0x349f0, 4) , (ram, 0x349f0, 4) , (ram, 0x349f0, 4)
        #       Varnode.getUniqueId():  5698                         5716                5716                5682
        #                                                            ^--------same-------^
        deduplication_list = [self.origin_varnode.getUniqueId()]
        process_counter = 0
        while len(varnode_processing_queue) > 0:
            vn_def = varnode_processing_queue.pop(0).getDef()
            process_counter += 1
            if process_counter % 100 == 0:
                logger.debug("Looped {} times for varnode getDef trace for FuncCallOutput".format(process_counter))
            if process_counter >= MAX_FUNCCALL_OUTPUT_TRACE_DEPTH:
                logger.warning("Hit max iteration limit of {} in trying to trace varnode at 0x{}. Exiting to continue tracing other items.".format(process_counter, self.origin_varnode.getPCAddress()))
                return
            if vn_def is None:
                continue
            if vn_def.getOpcode() != PcodeOp.CALL:
                # Only trace to the next inputs if its not a FuncCall
                for inp in vn_def.getInputs():
                    # Do not trace constants
                    if inp.isConstant():
                        continue
                    inp_vn_unique_id = inp.getUniqueId()
                    if inp_vn_unique_id in deduplication_list:
                        continue
                    varnode_processing_queue.append(inp)
                    deduplication_list.append(inp_vn_unique_id)
                    logger.debug("Added varnode 0x{} {} from pcode {}".format(inp.getPCAddress(), inp, vn_def))
                continue
            fc = FuncCall.get_instance(vn_def)
            if fc is None:
                continue
            logger.debug("Found trace to function call output of {}. Adding trace.".format(fc))
            TraceInfo.get_instance(fc.output, self, TraceType.VarIsFuncCallOutput)

    def trace_source_param(self):
        """Trace by linking varnode to caller function's parameter
        """
        if not self.func_call.caller_func:
            logger.debug("Traced a variable at 0x{} to a function parameter, but was unable to get its corresponding function. The function is likely an UndefinedFunction. Skipping trace.".format(self.func_call.addr))
            return None # This HighParam is a parameter of a UndefinedFunction which could not be automatically defined. See define_undefined_function_containing().
        
        # Do not link to Func Param if it is already linked to a previous
        # usage of ParamArg (this link would've come from Func.trace_var_usage()/TraceType.SameVarInFunc)
        for trace in self.backward_traces:
            if trace.trace_type == TraceType.SameVarInFunc:
                return 
        
        # Find correcponding Func Param and link to it
        param_idx = self.high_var.getSlot()
        try:
            param = self.func_call.caller_func.params[param_idx]
        except IndexError:
            logger.debug("Found arg without param of matching index. Placing it in arbitrary args")
            param = self.func_call.caller_func.get_arbitrary_param()
        TraceInfo.get_instance(param, self, TraceType.ArgIsParam)

class FuncCallOutput(VarnodeUpgraderMixin, object):
    """Represents a return value of a function call (FuncCall)
    
    Attributes:
        func_call (FuncCall)
        varnode (ghidra.program.model.pcode.Varnode)
        forward_traces (list[TraceInfo])
        backward_traces (list[TraceInfo])
        is_traced (bool):
            Whether the tracing for this object is already done (this is to prevent re-tracing the same thing).
            
    See Also:
        VarnodeUpgraderMixin
        FuncCall
    """
    def __init__(self, func_call, varnode):
        """Initializes the FuncCallOutput.
        
        Parameters:
            func_call (FuncCall)
            varnode (ghidra.program.model.pcode.Varnode)
        """
        self.func_call = func_call 
        self.varnode = varnode
        self.forward_traces = [] 
        self.backward_traces = []
        self.is_traced = False 
    
        self.varnode_upgrade_output()

    def trace_source_all(self):
        """Main tracing method to start all the other appropriate tracing methods.
        """
        if not self.is_traced:
            if self.func_call.callee_func.func.isThunk():
                self.trace_to_args()
            else:
                self.trace_return_val()
            self.is_traced = True
        
    def trace_return_val(self):
        """The source of FuncCallOutput is to continue tracing from the Func's ReturnVal 
        """
        return_val = self.func_call.callee_func.return_val
        TraceInfo.get_instance(return_val, self, TraceType.FuncCallOutputToReturnVal)

    def trace_to_args(self):
        # For information about SOURCE_SINK_PARAMETER_SIGNATURES, see Arg.trace_to_other_args() or source_sink_parameter_signatures option in the config.yaml
        callee_name = self.func_call.callee_func.name
        if callee_name in SOURCE_SINK_PARAMETER_SIGNATURES:
            dest_param_indexes = SOURCE_SINK_PARAMETER_SIGNATURES[callee_name]["destination_parameter_indexes"]
            if "ret" not in dest_param_indexes:
                return
            src_param_indexes = SOURCE_SINK_PARAMETER_SIGNATURES[callee_name]["source_parameter_indexes"]
            for idx in src_param_indexes:
                TraceInfo.get_instance(self.func_call.args[idx], self, TraceType.FuncCallOutputToArgs)
            return

        # As we can't know which arg is dest/src for every function (especially user-defined functions), 
        # we just link to every other arg.
        for arg in self.func_call.args:
            TraceInfo.get_instance(arg, self, TraceType.FuncCallOutputToArgs)
    
    def get_name(self):
        if self.name == "UNNAMED" or self.name is None:
            return "UnnamedOut"
        return self.name

    def __str__(self):
        if self.buffer_size:
            return "{}[{}]".format(self.get_name(), self.buffer_size)
        return "{}".format(self.get_name())
    
    def get_parent(self):
        """Gets the corresponding FuncCall.
        
        This method is available for Param, ReturnVal, Arg, and FuncCallOutput as a convenient way to get the
        corresponding parent (i.e. Param and ReturnVal => Func, Arg and FuncCallOutput => FuncCall).
        
        Returns:
            FuncCall
        """
        return self.func_call


#####################################################################################################################
# Output Functions

class OutputGraph(object):
    """Contains methods to output graph. 
    
    Notes:
        - Information used for graphing is obtained via the other classes, 
          thus the graph(s) should only be created after the main tracing is done.
    """

    @staticmethod
    def _get_filtered_traces(sink_funcs):
        """Gets all the traces, filtering out any unnecessary ones that do not stem from a sink function.
        
        Gets traces starting from the target parameters of the sink functions, and traverses the backward_traces to 
        the end. This filters out any stray traces that usually come from Func.trace_var_usage().
        
        Returns:
            list[TraceInfo]
        """
        
        nodes_for_tracing = []
        for func_call in FuncCall.instances.values():
            if func_call is None:
                continue
            if func_call.callee_func.name not in sink_funcs:
                continue
            target_param_indexes = sink_funcs[func_call.callee_func.name]
            if len(target_param_indexes) == 0:
                nodes_for_tracing.extend(func_call.args)
            else:
                for target_param_index in target_param_indexes:
                    nodes_for_tracing.append(func_call.args[target_param_index])
                
        logger.info("Condensing traces...")
        condensed_traces = []
        nodes_index = 0
        while nodes_index < len(nodes_for_tracing): 
            node_to_process = nodes_for_tracing[nodes_index]
            node_parent = node_to_process.get_parent()
            logger.debug("Tracing node {} of {}".format(node_to_process, node_parent))
            for trace_to_process in node_to_process.backward_traces:
                logger.debug("Processing trace: {}".format(trace_to_process))
                if trace_to_process.source_node in nodes_for_tracing:
                    logger.debug("The node was already traced.")
                    logger.debug("Linking to existing node & Skipping to next trace.")
                    trace = TraceInfo.get_instance(trace_to_process.source_node, node_to_process, trace_to_process.trace_type)
                    if trace in condensed_traces:
                        logger.debug("The trace was already found. Skipping to next trace.")
                        continue
                    condensed_traces.append(trace)
                    continue
                nodes_for_tracing.append(trace_to_process.source_node)
                trace = TraceInfo.get_instance(trace_to_process.source_node, node_to_process, trace_to_process.trace_type)
                if trace in condensed_traces:
                    logger.debug("The trace was already found. Skipping to next trace.")
                    continue
                condensed_traces.append(trace)
            logger.debug("Completed tracing node {} of {}".format(node_to_process, node_parent))
            nodes_index += 1
        return condensed_traces

    @staticmethod
    def _get_all_individual_path_traces(sink_funcs):
        """Traverse all the traces to split them into each individual path.
        
        Each path will start at a sink function call and the traces will be traversed in a 
        sink-to-source direction until there are no more traces.
        
        Returns:
            list[list[TraceInfo]]:
                A list containing inner lists which contains TraceInfo objects linking a full path.
                Each inner list represents one full path, with the first element being the TraceInfo 
                from the sink node, and the last element being the TraceInfo towards the end of the 
                traced path (no more traces beyond that node).
        """
        starting_nodes = [] # Start each path at the sink (generate sink-to-source)
        for func_call in FuncCall.instances.values():
            if func_call is None:
                continue
            if func_call.callee_func.name not in sink_funcs:
                continue
            target_param_indexes = sink_funcs[func_call.callee_func.name]
            if len(target_param_indexes) == 0:
                starting_nodes.extend(func_call.args)
            else:
                for target_param_index in target_param_indexes:
                    starting_nodes.append(func_call.args[target_param_index])
        
        
        # Backwards tracing, root-to-leaf type of algorithm to split traces into each individual full path
        logger.info("Processing paths...")
        paths = []
        for starting_node in starting_nodes:
            traced_path = []
            # This list will be a 2D list something like this:
            # [
            #   [TraceInfo, TraceInfo, TraceInfo],
            #   [TraceInfo, TraceInfo, TraceInfo, TraceInfo] <-- This list is the backward_traces of the previous lists index [-1] TraceInfo
            #   [TraceInfo, TraceInfo] <-- This list is the backward_traces of the previous lists index [-1] TraceInfo
            # ]
            # Whereby it traverses forwards from each TraceInfo, thus when it goes all the way to the end (i.e. when the last list's index [-1] TraceInfo has no more backward_traces),
            # the last TraceInfo of all the lists combined will form a single path. This repeats until all paths are exhausted.
            traced_path.append(starting_node.backward_traces[:]) # NOTE: The [:] is required to create a copy of the list, or else modifications to the list when altering the path/output queue will modify the actual source var Arg/Param/etc object as well.
            total_paths_counter = 0 # For giving status information, debugging and logging only

            while len(traced_path) > 0:  
                logger.debug("Checking if path list is empty")
                if len(traced_path[-1]) == 0:
                    traced_path.pop()
                    logger.debug("Latest path list was empty; removed.")
                    if len(traced_path) > 0:
                        latest_completed_trace = traced_path[-1].pop()
                        latest_completed_trace.source_node.completed_individual_path_processing = True
                        
                        logger.debug("Removed corresponding path node as well")
                    continue
                next_node_in_path = traced_path[-1][-1].source_node
                logger.debug("Next node to add to path: {}".format(next_node_in_path))
                
                if getattr(next_node_in_path, "completed_individual_path_processing", False):
                    logger.debug("Found previously completed segment trace")
                    current_segment = list(l[-1] for l in traced_path)
                    for cached_segment in getattr(next_node_in_path, "individual_paths_segment_cache", []):
                        paths.append(current_segment.extend(cached_segment))
                        
                    logger.debug("Full paths have been saved from cached segment trace")
                
                    traced_path[-1].pop()
                    logger.debug("Removed latest path node")
                    total_paths_counter += 1
                        
                    continue
                
                if len(next_node_in_path.backward_traces) > 0: # There is still more up in the path, continue adding...
                    next_node_backward_traces = next_node_in_path.backward_traces[:]
                    logger.debug("Checking duplicates in next_node's forward traces: {}".format(next_node_in_path.backward_traces))        
                    
                    # Remove if the trace is already in the current path (Do not want the path to infinitely loop around itself)
                    for next_trace_idx in reversed(range(len(next_node_backward_traces))): # reversed() so that the item can be removed while preserving the indexes of the rest of the list
                        for node_in_current_path in (l[-1] for l in traced_path):
                            if next_node_backward_traces[next_trace_idx] == node_in_current_path:
                                logger.debug("Removing duplicate node from next traces (already under current path): {}".format(next_node_backward_traces[next_trace_idx]))
                                next_node_backward_traces.pop(next_trace_idx)
                                break # pop from next_node_backward_traces and proceed to check the next item in next_node_backward_traces     
                    if len(next_node_backward_traces) != 0: # Check again in case all the backward_traces were removed due to being duplicates
                        traced_path.append(next_node_backward_traces)
                        logger.debug("Added next_node's forward traces: {}".format(next_node_in_path.backward_traces))
                        continue
                    
                logger.debug("next_node's forward traces are now empty! End of path has been reached. Saving full path.")
                
                # First cache the individual segments of the path so that we don't need to process it again if it loops around
                path_to_save = list(l[-1] for l in traced_path)
                for idx, trace in enumerate(path_to_save):
                    if idx == len(path_to_save)-1:
                        continue
                    segment_to_cache = path_to_save[idx+1:]
                    try:
                        trace.individual_paths_segment_cache.append(segment_to_cache)
                    except AttributeError:
                        trace.individual_paths_segment_cache = [segment_to_cache]
                # Save path
                paths.append(path_to_save)
                
                traced_path[-1].pop()
                logger.debug("Removed latest path node")
                total_paths_counter += 1
            logger.debug("All {} paths have been found for source var: {}".format(total_paths_counter, starting_node))
        
        return paths
        
        
    @classmethod
    def output_individual_paths(cls, func_color="#c9e4d8", val_color="#a7d3a9", source_color="#11069d", sink_color="#9b0748"):
        """Outputs a graph for every path found (i.e. From each sink FuncCall to each end-of-path node).
        
        Notes:
            - Attributes pertaining to graph information will be added to the Func and FuncCall objects
            - Output directories are set via the config.yaml
        
        Parameters:
            func_color (str):
                The background color for a Func. Defaults to "#c9e4d8".
            val_color (str):
                The background color for a Param/ReturnVal/Arg/FuncCallOutput. Defaults to "#a7d3a9".
            source_color (str):
                The font color for FuncCalls whereby the callee is a source function. Defaults to "#11069d".
            sink_color (str):
                The font color for FuncCalls whereby the callee is a sink function. Defaults to "#9b0748".
        """

        individual_paths = cls._get_all_individual_path_traces(SINK_FUNCS)
        
        total_paths = len(individual_paths)
        for path_counter_idx, path in enumerate(individual_paths):
            logger.info("Outputting paths {}/{}".format(path_counter_idx+1, total_paths))
            
            path_start = path[0].sink_node
            path_start_parent = path_start.get_parent()
            path_end = path[-1].source_node
            path_end_parent = path_end.get_parent()
            graph_name = "SplitPath-0x{}_{}_{}-to-0x{}_{}_{}-{}".format(
                path_start_parent.entry_address if isinstance(path_start_parent, Func) else path_start_parent.addr,
                path_start_parent.name          if isinstance(path_start_parent, Func) else path_start_parent.callee_func.name,
                cls._format_graph_port_name(path_start),
                path_end_parent.entry_address   if isinstance(path_end_parent, Func)   else path_end_parent.addr,
                path_end_parent.name            if isinstance(path_end_parent, Func)   else path_end_parent.callee_func.name,
                cls._format_graph_port_name(path_end),
                uuid.uuid4().hex
                )
            graph = pydot.Dot(
                graph_name, 
                graph_type="digraph"
                )
            graph.set_node_defaults(shape="plain")

            found_source_in_path = False
            
            # Graph Funcs
            graphed_funcs = []
            for trace in path:
                
                for node in (trace.source_node, trace.sink_node):
                    node_parent = node.get_parent()
                    if isinstance(node_parent, FuncCall):
                        node_parent = node_parent.caller_func
                        if node_parent is None:
                            continue
                    if node_parent in graphed_funcs:
                        continue
                    graphed_funcs.append(node_parent)
                    cluster_func = pydot.Cluster(str(node_parent.entry_address),bgcolor=func_color)
                    graph.add_subgraph(cluster_func)
                    node_parent.graph_cluster = cluster_func

                    node_func = pydot.Node(
                        "func_0x{}_{}".format(node_parent.entry_address, node_parent.name), 
                        label=cls._format_graph_node_label(node_parent, val_color),
                        href=cls._format_href_to_decompiled_funcs(node_parent)
                        )
                    cluster_func.add_node(node_func)
                    node_parent.graph_node = node_func
                    
                    node_parent.child_graph_nodes = [] # More will be added later when graphing FuncCalls

            # Graph FuncCalls
            graphed_funccalls = []
            for trace in path:
                source_func_call = trace.source_node.get_parent()
                sink_func_call = trace.sink_node.get_parent()
                for funccall in (source_func_call, sink_func_call):
                    if isinstance(funccall, Func): 
                        continue # Only graph FuncCalls here
                    if funccall in graphed_funccalls:
                        continue
                    graphed_funccalls.append(funccall)
                    
                    # Color text based on source or sink
                    node_fontcolor = "black" 
                    if funccall.callee_func.name in SINK_FUNCS:
                        node_fontcolor = sink_color
                    elif funccall.callee_func.name in SOURCE_FUNCS:
                        node_fontcolor = source_color
                        found_source_in_path = True
                    
                    node_funccall = pydot.Node(
                        "funccall_0x{}_{}".format(funccall.addr, funccall.callee_func.name), 
                        label=cls._format_graph_node_label(funccall, val_color),
                        fontcolor=node_fontcolor,
                        href=cls._format_href_to_decompiled_funcs(funccall)
                        )
                    
                    funccall.graph_node = node_funccall
                    if funccall.caller_func: # Note: caller_func is None usually happens when the FuncCall is under a "UndefinedFunction" (see define_undefined_function_containing())
                        funccall.caller_func.graph_cluster.add_node(node_funccall)
                        funccall.caller_func.child_graph_nodes.append(node_funccall)
                    else:
                        graph.add_node(node_funccall)
                    
            
            # Align items
            # Under each cluster, make invisible edges between its nodes so as to force the addresses to be in ascending order.
            for func in graphed_funcs:
                addresses = []
                graph_node_addr_map = {}
                for i in func.child_graph_nodes:
                    addr = int(i.get_name().split("_")[1][2:], 16) # E.g. split "funccall_0x00101236_strcpy" to "00101236" then to int so it can be sorted numerically
                    addresses.append(addr) 
                    graph_node_addr_map[addr] = i
                addresses.sort()
                prev_graph_node = func.graph_node
                for i in addresses:
                    edge = pydot.Edge(prev_graph_node, graph_node_addr_map[i], style="invis")
                    prev_graph_node = graph_node_addr_map[i]
                    graph.add_edge(edge)


            # Graph TraceInfos
            for trace in path:
                
                trace_source_parent = trace.source_node.get_parent()
                trace_sink_parent = trace.sink_node.get_parent()
                
                logger.debug("Graphing TraceInfo {} | Source parent: {}, Sink parent: {}".format(trace, trace_source_parent, trace_sink_parent))

                if not isinstance(trace.source_node, Param):
                    if trace.source_node.name in SOURCE_GLOBAL_SYMBOLS:
                        trace_source_parent.graph_node.set_fontcolor(source_color)
                        found_source_in_path = True
                else: 
                    if FLAG_MAIN_AS_SOURCE and trace_source_parent.name == "main":
                        trace_source_parent.graph_node.set_fontcolor(source_color)
                        found_source_in_path = True
                        
                if not isinstance(trace.sink_node, Param):
                    if trace.sink_node.name in SOURCE_GLOBAL_SYMBOLS:
                        trace_sink_parent.graph_node.set_fontcolor(source_color)
                        found_source_in_path = True 
                    

                # Color traces based on significance of the traces
                edge_color = "black"
                    
                # Extra 
                source_extra_attributes = ""
                sink_extra_attributes = ""
                
                edge = pydot.Edge(
                    "{}:{}{}".format(
                        trace_source_parent.graph_node.get_name(),
                        cls._format_graph_port_name(trace.source_node),
                        source_extra_attributes
                    ), 
                    "{}:{}{}".format(
                        trace_sink_parent.graph_node.get_name(), 
                        cls._format_graph_port_name(trace.sink_node),
                        sink_extra_attributes
                    ),
                    color=edge_color
                    )
                graph.add_edge(edge)
                    

            if found_source_in_path:
                filepath_template = os.path.join(OUTPUT_DIR_POTENTIALLY_VULNERABLE_PATHS, "{}.{{}}".format(graph_name))
            else:
                filepath_template = os.path.join(OUTPUT_DIR_UNKNOWN_PATHS, "{}.{{}}".format(graph_name))
                
            
            full_filepath = filepath_template.format("dot")
            logger.debug("Saving raw dot graph to file ({})".format(full_filepath))
            graph.write_raw(full_filepath) 
            logger.debug("Graph saved sucessfully")
            
            if PRE_RENDER_GRAPH_SVG:
                full_filepath = filepath_template.format("svg")
                logger.debug("Saving svg graph to file ({})".format(full_filepath))
                graph.write_svg(full_filepath)
            logger.debug("Graph saved sucessfully")
            
            if PRE_RENDER_GRAPH_PNG:
                full_filepath = filepath_template.format("png")
                logger.debug("Saving png graph to file ({})".format(full_filepath))
                graph.write_png(full_filepath)
            logger.debug("Graph saved sucessfully")
                
            if PRE_RENDER_GRAPH_PDF:
                full_filepath = filepath_template.format("pdf")
                logger.debug("Saving pdf graph to file ({})".format(full_filepath))
                graph.write_pdf(full_filepath)
            logger.debug("Graph saved sucessfully")
                
            full_filepath = filepath_template.format("csv")
            logger.debug("Saving csv to file ({})".format(full_filepath))
            output_funccall_csv(full_filepath, graphed_funccalls)
            logger.debug("CSV saved sucessfully")
            
        logger.info("All paths have been output.")


    @classmethod
    def output_global(cls, func_color="#c9e4d8", val_color="#a7d3a9", source_color="#11069d", sink_color="#9b0748"):
        """Outputs a global graph (i.e. All the Func and FuncCall objects will be graphed with their respective traces).
        
        Notes:
            - Attributes pertaining to graph information will be added to the Func and FuncCall objects
            - Output directories are set via the config.yaml
        
        Parameters:
            func_color (str):
                The background color for a Func. Defaults to "#c9e4d8".
            val_color (str):
                The background color for a Param/ReturnVal/Arg/FuncCallOutput. Defaults to "#a7d3a9".
            source_color (str):
                The font color for FuncCalls whereby the callee is a source function. Defaults to "#11069d".
            sink_color (str):
                The font color for FuncCalls whereby the callee is a sink function. Defaults to "#9b0748".
        """
        
        graph = pydot.Dot("GhOSTGlobalOutput", graph_type="digraph")
        graph.set_node_defaults(shape="plain")

        
        filtered_traces = cls._get_filtered_traces(SINK_FUNCS)
            
            
        # Graph Funcs
        logger.info("Graphing Funcs...")
        graphed_funcs = []
        for trace in filtered_traces:
            for node in (trace.source_node, trace.sink_node):
                node_parent = node.get_parent()
                if isinstance(node_parent, FuncCall):
                    node_parent = node_parent.caller_func
                    if node_parent is None:
                        continue
                if node_parent in graphed_funcs:
                    continue
                graphed_funcs.append(node_parent)
                cluster_func = pydot.Cluster(str(node_parent.entry_address),bgcolor=func_color)
                graph.add_subgraph(cluster_func)
                node_parent.graph_cluster = cluster_func

                node_func = pydot.Node(
                    "func_0x{}_{}".format(node_parent.entry_address, node_parent.name), 
                    label=cls._format_graph_node_label(node_parent, val_color),
                    href=cls._format_href_to_decompiled_funcs(node_parent)
                    )
                cluster_func.add_node(node_func)
                node_parent.graph_node = node_func
                
                node_parent.child_graph_nodes = [] # More will be added later when graphing FuncCalls
                if SPLIT_GLOBAL_GRAPH_BY_FUNCS:
                    node_parent.relevant_graph_edges = []


        # Graph FuncCalls
        logger.info("Graphing FuncCalls...")
        graphed_funccalls = []
        for trace in filtered_traces:
            source_func_call = trace.source_node.get_parent()
            sink_func_call = trace.sink_node.get_parent()
            for funccall in (source_func_call, sink_func_call):
                if isinstance(funccall, Func): 
                    continue # Only graph FuncCalls here
                if funccall in graphed_funccalls:
                    continue
                graphed_funccalls.append(funccall)
                
                # Color text based on source or sink
                node_fontcolor = "black" 
                if funccall.callee_func.name in SINK_FUNCS:
                    node_fontcolor = sink_color
                elif funccall.callee_func.name in SOURCE_FUNCS:
                    node_fontcolor = source_color
                    
                node_funccall = pydot.Node(
                    "funccall_0x{}_{}".format(funccall.addr, funccall.callee_func.name), 
                    label=cls._format_graph_node_label(funccall, val_color),
                    fontcolor=node_fontcolor,
                    href=cls._format_href_to_decompiled_funcs(funccall)
                    )
                funccall.graph_node = node_funccall
                if funccall.caller_func: # Note: caller_func is None usually happens when the FuncCall is under a "UndefinedFunction" (see define_undefined_function_containing())
                    funccall.caller_func.graph_cluster.add_node(node_funccall)  
                    funccall.caller_func.child_graph_nodes.append(node_funccall)
                else:
                    graph.add_node(node_funccall)
                
        
        # Align items
        logger.info("Aligning graph items...")
        # Under each cluster, make invisible edges between its nodes so as to force the addresses to be in ascending order.
        for func in graphed_funcs:
            addresses = []
            graph_node_addr_map = {}
            for i in func.child_graph_nodes:
                addr = int(i.get_name().split("_")[1][2:], 16) # E.g. split "funccall_0x00101236_strcpy" to "00101236" then to int so it can be sorted numerically
                addresses.append(addr) 
                graph_node_addr_map[addr] = i
            addresses.sort()
            prev_graph_node = func.graph_node
            for i in addresses:
                edge = pydot.Edge(prev_graph_node, graph_node_addr_map[i], style="invis")
                prev_graph_node = graph_node_addr_map[i]
                if SPLIT_GLOBAL_GRAPH_BY_FUNCS:
                    func.relevant_graph_edges.append(edge)
                else:
                    graph.add_edge(edge)

        
        # Graph TraceInfos
        logger.info("Graphing traces...")
        for trace in filtered_traces:
            
            trace_source_parent = trace.source_node.get_parent()
            trace_sink_parent = trace.sink_node.get_parent()
            
            logger.debug("Graphing TraceInfo {} | Source parent: {}, Sink parent: {}".format(trace, trace_source_parent, trace_sink_parent))
                
            # Color traces based on significance of the traces
            edge_color = "black"
            if trace.trace_type in (TraceType.ParamToArg):
                edge_color = "gray"
                
            # Extra 
            source_extra_attributes = ""
            sink_extra_attributes = ""
            
            edge = pydot.Edge(
                "{}:{}{}".format(
                    trace_source_parent.graph_node.get_name(),
                    cls._format_graph_port_name(trace.source_node),
                    source_extra_attributes
                ), 
                "{}:{}{}".format(
                    trace_sink_parent.graph_node.get_name(), 
                    cls._format_graph_port_name(trace.sink_node),
                    sink_extra_attributes
                ),
                color=edge_color
                )
            
            if SPLIT_GLOBAL_GRAPH_BY_FUNCS:
                trace_source_parent_func = trace_source_parent
                if isinstance(trace_source_parent, FuncCall):
                    trace_source_parent_func = trace_source_parent_func.caller_func
                trace_sink_parent_func = trace_sink_parent
                if isinstance(trace_sink_parent_func, FuncCall):
                    trace_sink_parent_func = trace_sink_parent_func.caller_func
                    
                if trace_source_parent_func == trace_sink_parent_func: # Only add edge if it links within the same parent function
                    if trace_sink_parent_func is None:
                        graph.add_edge(edge)
                    else:
                        trace_sink_parent_func.relevant_graph_edges.append(edge) 
                
            else:
                graph.add_edge(edge)
                

        
        if SPLIT_GLOBAL_GRAPH_BY_FUNCS:
            for func in graphed_funcs:
                split_func_graph = pydot.Dot(
                    "GhOSTGlobalOutput_SplitFunc{}".format(
                        cls._format_graph_node_label(func, val_color)
                        ), 
                    graph_type="digraph"
                    )
                split_func_graph.set_node_defaults(shape="plain")
                split_func_graph.add_subgraph(func.graph_cluster)
                for edge in func.relevant_graph_edges:
                    split_func_graph.add_edge(edge)
                    
                
                func_filename = "GlobalSplitFunc-0x{}_{}".format(func.entry_address, func.name)
                filepath_template = os.path.join(OUTPUT_DIR_GLOBAL_GRAPHS, "{}.{{}}".format(func_filename))
                
                full_filepath = filepath_template.format("dot")
                logger.info("Saving split function graph (raw dot format) to file ({})".format(full_filepath))
                split_func_graph.write_raw(full_filepath) 
                
                if PRE_RENDER_GRAPH_SVG: 
                    full_filepath = filepath_template.format("svg")
                    logger.info("Saving split function graph (svg format) to file ({})".format(full_filepath))
                    split_func_graph.write_svg(full_filepath)
            
                if PRE_RENDER_GRAPH_PNG:
                    full_filepath = filepath_template.format("png")
                    logger.debug("Saving split function graph (png format) to file ({})".format(full_filepath))
                    split_func_graph.write_png(full_filepath)
                
                if PRE_RENDER_GRAPH_PDF:
                    full_filepath = filepath_template.format("pdf")
                    logger.debug("Saving pdf graph to file ({})".format(full_filepath))
                    split_func_graph.write_pdf(full_filepath)
                    
                logger.debug("Graph output successful")
                

        else:
            filename = "Global"
            filepath_template = os.path.join(OUTPUT_DIR_GLOBAL_GRAPHS, "{}.{{}}".format(filename))
            
            full_filepath = filepath_template.format("dot")
            logger.info("Saving raw dot graph to file ({})".format(full_filepath))
            graph.write_raw(full_filepath) 
            
            if PRE_RENDER_GRAPH_SVG:
                full_filepath = filepath_template.format("svg")
                logger.info("Saving svg graph to file ({})".format(full_filepath))
                graph.write_svg(full_filepath)
                
            if PRE_RENDER_GRAPH_PNG:
                full_filepath = filepath_template.format("png")
                logger.debug("Saving png graph to file ({})".format(full_filepath))
                graph.write_png(full_filepath)
                
            if PRE_RENDER_GRAPH_PDF:
                full_filepath = filepath_template.format("pdf")
                logger.debug("Saving pdf graph to file ({})".format(full_filepath))
                graph.write_pdf(full_filepath)
                
            logger.debug("Graph output successful")
            
        logger.info("Saving csv to file ({})".format(OUTPUT_FILEPATH_CALLER_CALLEE_CSV))
        output_funccall_csv(OUTPUT_FILEPATH_CALLER_CALLEE_CSV, graphed_funccalls)
        logger.info("CSV saved sucessfully")
        
    
    @classmethod
    def _format_href_to_decompiled_funcs(cls, node):
        """Format the href for linking the graph nodes to the corresponding address in the decompiled/disassembled html output.
        
        Parameters:
            node (Func | FuncCall)
            
        Returns:
            str: The formatted href string
            
            
        See Also:
            output_decompiled_c_and_disassembly_html()
        """
        if not OUTPUT_DECOMPILED_C_AND_DISASSEMBLY_HTML:
            return ""
        
        if isinstance(node, Func):
            href_addr = node.entry_address
        elif isinstance(node, FuncCall):
            href_addr = node.addr
            
        if OUTPUT_RELATIVE_PATHS:
            file_uri_string = os.path.join("../",OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML)+"#{}".format(href_addr)
        else:
            file_uri_string = "file:///"+OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML+"#{}".format(href_addr)

        # The string '\G' value will be replaced by the graph name (ref. https://www.graphviz.org/pdf/dot.1.pdf and https://graphviz.org/docs/attr-types/escString/) 
        # As this is a format for a filepath, it is easy for the filepath to contain the '\G'. 
        # E.g. C:\...\...\GhOST Output\...\Decompiled C.html
        #                ^^
        file_uri_string = file_uri_string.replace(r"\G", r"\\G")
        return file_uri_string
            
    @classmethod
    def _format_graph_port_name(cls, node):
        """Format a Param/ReturnVal/Arg/FuncCallOutput as port name for the <td> element of the node label.
        
        Parameters:
            node (Param | ReturnVal | Arg | FuncCallOutput)
            
        Returns:
            str: The formatted name
            
        See Also:
            cls._format_graph_node_label()
        """
        if isinstance(node, Param):
            return "param{}".format(node.index)
        if isinstance(node, ReturnVal):
            return "returnval"
        if isinstance(node, Arg):
            return "arg{}".format(node.index)
        if isinstance(node, FuncCallOutput):
            return "funccall"
            
        logger.error("Unhandled case for formatting graph port name")
        return "GraphPortNameFormattingUnhandled"

    
    @classmethod
    def _format_graph_node_label(cls, node, val_color):
        """Format a node into the string for the graphviz node label.
        
        This includes styles and highlighting for the nodes, as each 
        Func/FuncCall node is split into multiple ports with each port 
        representing an individual value (Param/ReturnVal/Arg/FuncCallOutput).
        
        Parameters:
            node (Func | FuncCall)
            val_color (str): A color representation that is supported by graphviz/pydot
            
        Returns:
            str: The formatted label
            
        See Also:
            cls._format_graph_port_name()
        """
        label_template = """<
                <table {table_attributes}>
                    <tr>
                        <td>0x{addr} </td>
                        <td>{func_name}(</td>{input_val_tds}
                        <td>) &lt;=&gt;</td>{output_val_td}
                    </tr>
                </table>
            >"""
        val_template = """
                        <td bgcolor="{val_color}" port="{port_name}">{val_str}</td>"""
        input_val_seperator = """
                        <td>,</td>"""
        
        if isinstance(node, Func):
            # Format Params
            input_val_tds = ""
            for param in node.params:
                input_val_tds += val_template.format(
                    val_color=val_color,
                    port_name=cls._format_graph_port_name(param),
                    val_str=str(param)
                )
                if param.index < len(node.params)-1:
                    input_val_tds += input_val_seperator
            # Format ReturnVal
            output_val_td = val_template.format(
                    val_color=val_color,
                    port_name=cls._format_graph_port_name(node.return_val),
                    val_str=str(node.return_val)
            )
            # Format Func
            return label_template.format(
                table_attributes='cellspacing="0" cellborder="0"',
                addr = node.entry_address,
                func_name = node.name,
                input_val_tds = input_val_tds,
                output_val_td = output_val_td,
            )
        
        if isinstance(node, FuncCall):
            # Format Args
            input_val_tds = ""
            for arg in node.args:
                input_val_tds += val_template.format(
                    val_color=val_color,
                    port_name=cls._format_graph_port_name(arg),
                    val_str=str(arg)
                )
                if arg.index < len(node.args)-1:
                    input_val_tds += input_val_seperator
            # Format FuncCallOutput
            output_val_td = val_template.format(
                    val_color=val_color,
                    port_name=cls._format_graph_port_name(node.output),
                    val_str=str(node.output)
            )
            # Format FuncCall
            return label_template.format(
                table_attributes='cellspacing="0" cellborder="0" border="0"',
                addr = node.addr,
                func_name = node.callee_func.name,
                input_val_tds = input_val_tds,
                output_val_td = output_val_td,
            )

        logger.error("Unhandled case for formatting graph label")
        return "GraphLabelFormattingUnhandled"

def output_funccall_csv(filepath, funccalls):
    """Outputs a csv file of all the callers and callees in a set of FuncCalls.
    
    Parameters:
        filepath (str)
        funccalls (list[FuncCall])
    """
    with open("{}".format(filepath), "w+") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Caller Address", 
            "Caller Name", 
            "Caller Parameters", 
            "Callee Address", 
            "Callee Name", 
            "Callee Arguments"
            ])
        for funccall in funccalls:
            writer.writerow([
                funccall.caller_func.entry_address                      if funccall.caller_func else "Unknown", 
                funccall.caller_func.name                               if funccall.caller_func else "UndefinedFunction",
                ", ".join(str(p) for p in funccall.caller_func.params)  if funccall.caller_func else "?",
                funccall.addr,
                funccall.callee_func.name,
                ", ".join(str(a) for a in funccall.args)
            ]) 

def output_decompiled_c_and_disassembly_html(filepath):
    """Outputs the decompiled C code and disassembly of all the functions in the current program to a html file.
    
    The HTML elements will have ids for the address of each function and function call so as to be able to 
    jump to a specific address. The links to these ids are from the graph. 
    
    Parameters:
        filepath (str)
    
    See Also:
        OutputGraph._format_href_to_decompiled_funcs() for the information on where it is linked from.
    
    """
    function_string_template = """
<table width='100%'>
    <tr>
        <td id='{entrypoint_address}'><b>{name} entrypoint addr: </b>{entrypoint_address}</td>
    </tr>
    <tr>
        <td width='50%' style='border: 1px solid black; padding: 10px; vertical-align:top;'>
            <pre style='word-wrap: break-word;'>{decompiled_c}</pre>
        </td>
        <td width='50%' style='border: 1px solid black; padding: 10px; vertical-align:top;'>
            {disassembly}
        </td>
    </tr>
</table>
"""
    disassembly_string_template="""<pre style='padding: 0;margin: 0;' id='{address}'>0x{address}      {disassembled_instruction}</pre>
            """
            
    html_string = ""
    functions = function_manager.getFunctions(True)
    for f in functions:
        decompiled_function_results = decompiler_interface.decompileFunction(f, 0, monitor)
        decompiled_c = decompiled_function_results.getDecompiledFunction().getC()
        
        function_address_set = f.getBody()
        code_units = listing.getCodeUnits(function_address_set, True) # The CodeUnit type gives us access to the disassembled instructions
        disassembly_string = ""
        for cu in code_units:
            disassembly_string += disassembly_string_template.format(
                address=cu.getAddress(), 
                disassembled_instruction=cu.toString()
                )
        html_string += function_string_template.format(
            entrypoint_address=str(f.getEntryPoint()), 
            name=str(f.getName()), 
            decompiled_c=cgi.escape(decompiled_c),
            disassembly=disassembly_string
            )
        
    with open(filepath, "w+") as f:
        f.write(html_string)


#####################################################################################################################
# Startup Code

def main():
    """The main startup code for tracing and output.
    
    The target parameters of the sink functions are first initialized, then
    moved into the main tracing loop that repeatedly traces the next trace via 
    the TraceInfo queue. The outputs are done after all traces are processed and
    no more traces can be found.
    
    Notes:
        - While recursion would be more convenient implementation-wise instead of the iterative queue system, 
          it is not used because python does not do well with recursion.
    """
    logger.info("Tracing start: {}".format(datetime.now()))
    # Initialize sink's Func & FuncCalls
    for sink_name in SINK_FUNCS:
        funcs = Func.get_instances_by_name(sink_name)
        for f in funcs:
            for p in f.params:
                p.trace_to_arg()

    # Start tracing loop via TraceInfo queue
    next_trace = TraceInfo.get_next_in_queue()
    progress_counter = 0
    while next_trace:
        logger.debug("Tracing {}".format(next_trace))
        if next_trace.trace_type in (TraceType.ArgUsagePassedIntoFunc):
            next_trace.sink_node.trace_source_all()
        else:
            next_trace.source_node.trace_source_all()
        next_trace = TraceInfo.get_next_in_queue()
        progress_counter += 1
        if progress_counter % 100 == 0:
            logger.info("Traces counter: {}/{} [total completed/total found]".format(progress_counter, len(TraceInfo.instances)))
            if progress_counter == 30000:
                logger.warning("For debugging purposes the tracing loop has been stopped")
                break
    logger.info("Tracing end: {}".format(datetime.now()))
    
    # Outputs
    if OUTPUT_GLOBAL_GRAPH:
        OutputGraph.output_global()
    if OUTPUT_INDIVIDUAL_PATHS_GRAPH:
        OutputGraph.output_individual_paths()
    if OUTPUT_DECOMPILED_C_AND_DISASSEMBLY_HTML:
        output_decompiled_c_and_disassembly_html(OUTPUT_FILEPATH_DECOMPILED_C_AND_DISASSEMBLY_HTML)
    logger.info("Output completed: {}".format(datetime.now()))

print """
================= Reminder of Decompiler Parameter ID =================
If you are not using the launcher script (i.e. you are using the GUI),
make sure to manually enable "Decompiler Parameter ID" in Ghidra's 
analysis options, or else the program may not be able to trace fully.
=======================================================================
"""
# By default, Ghidra analyses function calls and the functions separately and does not propagate the results 
# (See https://reverseengineering.stackexchange.com/questions/26577/ghidra-wrong-function-arguments-and-returns). 
# This means that for example, Ghidra may say that functionX has 3 parameters, but in another part of the program 
# when the function is called, it may detect that only 2 arguments are passed to the function. This example is a 
# commonly encountered error in the script whereby it is unable to get the extra argument. Thus, the 
# `Decompiler Parameter ID` option needs to be enabled for Ghidra to propagate the results of its analysis in 
# order for this script to work.
#
# In another example, Ghidra may say that functionY has 2 parameters, but when it is called, 3 arguments are passed to 
# the function. In some cases, this is correct, for example in `sprintf(str, format, ...)` whereby the 3rd argument and 
# onwards are arbitrarily passed in. The way the program handles this is to link the arbitrary functions to another 
# object class, ArbitraryParams. However, without the Decompiler Parameter ID enabled, the program may incorrectly link 
# to to an ArbitraryParams object even if there is suppored to be a normal parameter. 

    
# NOTE: The main startup code was moved to the main() function for time profiling purposes.
#       It will take significantly longer to run due to the profiler overhead, but the relevant profiling 
#       code is left here for if analysis needs to be done on the time taken for the different parts of the 
#       program to run. Analysis results will be output to the console.
# import profile
# profile.run("main()")
main()
