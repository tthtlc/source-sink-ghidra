// Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
// ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)

// Ghidra Script for Taint Analysis in FinjectRoute


//@author Melodi Joy Halim
//@category FinjectRoute
//@keybinding
//@menupath
//@toolbar



import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.task.TaskMonitor;


// Ghidra APIs needed for Tracing

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.util.VarnodeContext;


// Java Structures Required

import java.util.List;
import java.util.HashMap;
import java.util.ArrayList;
import java.math.BigInteger;
import java.util.stream.Collectors;


// For Decompilation To C

import ghidra.app.decompiler.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;


// For JSON Conversion

import org.json.JSONObject;
import org.json.JSONArray;


// For File Operations

import java.io.File;
import java.io.FileWriter;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.IOException;

import java.util.Formatter;
import java.time.format.DateTimeFormatter;  
import java.time.LocalDateTime;    


// Other

import ghidra.util.exception.CancelledException;



public class Taint_Analysis_Script extends HeadlessScript {


// === DEFINITIONS ===


	// Default Tool Settings

	// --> Controls

	int verbosityLevel = 0;
	int depthLimit = 15;
	boolean saveLogs = true;
	String scriptLocation;
	PrintStream console = System.out;
	PrintStream logstream;

	// --> Display

	public String ANSI_RESET = "\u001B[0m";			// return back to normal colour
	public String ANSI_GREEN = "\u001B[32m";			// Non-vulnerable Sinks (Constant)
	public String ANSI_YELLOW = "\u001B[33m";			// Potentially Vulnerable Sinks (To be traced)
	public String ANSI_RED_BACKGROUND = "\u001B[41m";	// VULNERABLE SINKS (final output)

	// --> Setting Datetime

	DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
	String datetime = dtf.format(LocalDateTime.now());



	// Reference

	// --> Sink Names

	public List<String>sinkNames = new ArrayList<String>() {{

		add("system");
		add("execl");
		add("execve");
		add("execlp");
		add("popen");

	}};


	// --> Special Thunk Functions (External Library) To Take Note Of

	// Note: this is needed because if the user input is modified by these functions,
	// FinjectRoute cannot trace into these EXTERNAL library functions to see what had happened to any tracked nodes 
	// (because they are external thunk functions and their code is not found in the binary)
	// (e.g. strcpy, strcat, etc.).

	public List<String>modifyingThunkFunctions = new ArrayList<String>() {{

		// For these thunks, in general, the destination is stored in the first parameter (i.e. RDI)
			// whereas the subsequent parameters are the sources (can be multiple, e.g. sprintf has multiple sources)
			// so we will trace ONLY the first source parameter (i.e. the 2nd parameter in RSI)
			// which is one of our tool's limitations.

		add("strcpy");
		add("strcat");
		add("sprintf");
		add("memcpy");
		add("recv");

	}};

	public HashMap<String, Integer> followOneParamThunkFunctions = new HashMap<String, Integer>() {{

		// For these thunks, we are not going to assume anything is changed in there
		// and follow a specific parameter input to the thunk function that may hold the user input

		// if a thunk function is not specified here or in the previous list (assuming EAX is a tracked node), 
		// by default the first parameter will be tracked 

		put("strtok", 1);
		put("strchr", 1);

	}};



	// Taint Analysis Variables

	// --> Decompilation Interface

	DecompInterface decompLib;


	// --> Task Monitor

	TaskMonitor monitor;

	
	// --> Program Structures

	AddressFactory addressFactory;
	FunctionManager funcManager;
	Listing programListing;
	VarnodeContext varnodeContext;


	// --> Architecture-specific Registers
	
	String comArchitecture;
	Register stackPointer;
	Register returnRegister;
	ArrayList<Register> paramRegisters = new ArrayList<Register>();



	// --> Final Result Structures

	String sourceComment = "";
	ArrayList<SinkTaint> finalResult = new ArrayList<SinkTaint>();




	// 6 Custom Structures For Taint Analysis

	// --> SinkTaint (contains all paths of each parameter of a sink reference to vulnerable source)

	public class SinkTaint {

		private Address callRefAddress;
		private Function startingFunction;
		private ArrayList<TaintPath> taintPaths;

		public SinkTaint (Function func, Address call, ArrayList<TaintPath> taintPaths) {

			this.startingFunction = func;
			this.callRefAddress = call;
			this.taintPaths = taintPaths;

		}


		// Call Reference Address

		public Address getCall() {
			return callRefAddress;
		}


		// Starting Function

		public Function getFunc() {
			return startingFunction;
		}


		// Taint Paths

		public ArrayList<TaintPath> getTaintPaths() {
			return taintPaths;
		}

		public void addTaintPath(TaintPath newTaintPath) {
			taintPaths.add(newTaintPath);
		}

		public boolean allNodesConstant() {
			for (TaintPath taintPath : taintPaths) {
				if (!taintPath.allNodesConstant()) {
					return false;
				}
			}
			return true;
		}


	}


	// --> TaintPath (path of each parameter of a sink reference to vulnerable source)

	public class TaintPath {

		int depthLevel;
		private ArrayList<Function> functionsPassedThru;
		private ArrayList<ArrayList<String>> assemblyPassedThru;
		private ArrayList<Varnode> nodes;
		private ArrayList<MemoryPosition> memPositions;

		public TaintPath(ArrayList<Varnode> nodes, ArrayList<MemoryPosition> memPositions){

			depthLevel = 0;
			
			this.functionsPassedThru = new ArrayList<Function>();
			this.assemblyPassedThru = new ArrayList<ArrayList<String>>();

			this.nodes = nodes;
			this.memPositions = memPositions;
		}


		// Depth Level

		public int getDepthLevel(){
			return depthLevel;
		}

		public void incrementDepthLevel(){
			this.depthLevel++;
		}

		public void setDepthLevel(int newDepthLevel){
			this.depthLevel = newDepthLevel;
		}


		// Functions Passed Through in Taint (For Decompilation in Appendix)

		public ArrayList<Function> getFunctionsPassedThru(){
			return functionsPassedThru;
		}

		public Function getPreviousFunctionPassedThru(){
			return functionsPassedThru.get(functionsPassedThru.size() - 2);
		}

		public void setFunctionsPassedThru(ArrayList<Function> functionsPassedThru){
			this.functionsPassedThru = functionsPassedThru;
		}

		public void addFunctionPassedThru(Function function){
			this.functionsPassedThru.add(function);
		}


		// Assembly Passed Through in Taint (For Graph and Main Content)

		public ArrayList<ArrayList<String>> getAssemblyPassedThru(){
			return assemblyPassedThru;
		}

		public void setAssemblyPassedThru(ArrayList<ArrayList<String>> newAssembly){
			this.assemblyPassedThru = newAssembly;
		}

		public void addNewBlock(){
			assemblyPassedThru.add(new ArrayList<String>());
		}

		public void addAssemblyToLatestBlock(String instruction){
			assemblyPassedThru.get(assemblyPassedThru.size()-1).add(instruction);
		}


		// Nodes

		public ArrayList<Varnode> getNodes(){
			return nodes;
		}

		public void setNodes(ArrayList<Varnode> registers) {
			this.nodes = registers;
		}

		public void addNode(Varnode node) {
			this.nodes.add(node);
		}

		public void removeNode(Varnode node) {
			
			this.nodes.remove(node);

			ArrayList<MemoryPosition> memPosLeft = new ArrayList<MemoryPosition>(); 
			for (MemoryPosition pos : getMemPositions()){
				if (pos.getRegister().toString().equals(node.toString())) { continue; }
				memPosLeft.add(pos);
			}
			this.memPositions = memPosLeft;

		}

		public Boolean notATrackedNode(Varnode node) {
			for(Varnode nd : getNodes()) {
				if(nd.toString().equals(node.toString())) {
					return false;
				}
			}
			for(MemoryPosition pos : getMemPositions()) {
				if(pos.getRegister().toString().equals(node.toString())) {
					return false;
				}
			}
			return true;
		}

		public Boolean allNodesConstant() {
			if (getMemPositions().isEmpty()){
				for (Varnode node : getNodes()) {
					if (!node.isConstant()) {
						return false;
					}
				}
				return true;
			}
			return false;
		}


		// Stack Offset / Memory Position Operations

		public ArrayList<MemoryPosition> getMemPositions() {
			return memPositions;
		}

		public void setMemPositions(ArrayList<MemoryPosition> memPositions) {
			this.memPositions = memPositions;
		}

		public void addMem(MemoryPosition memPosition) {
			this.memPositions.add(memPosition);
		}

		public Boolean notATrackedMemoryPosition(Varnode register, Varnode offset) {
			for(MemoryPosition memPos : getMemPositions()) {
				if(varnodeContext.getRegister(memPos.getRegister()).getName().equals(varnodeContext.getRegister(register).getName()) 
					&& memPos.getOffset().toString().equals(offset.toString())) 
				{
					return false;
				}
			}
			return true;
		}

		public void removeStackPointer(){
			ArrayList<MemoryPosition> updated = new ArrayList<MemoryPosition>();
			Boolean removed = false;
			for (MemoryPosition pos : getMemPositions()) {
				if (removed) {
					updated.add(pos);
				} else if (!varnodeContext.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
					updated.add(pos);
				} else {
					removed = true;
				}
			}
			setMemPositions(updated);
		}

	}


	// --> Block (represents a CodeBlock in the simple block model decompilation)

	public class Block {

		// Properties

		private Function blockFunction;
		private ArrayList<AssemInstruction> blockInstructions;

		private Address entryPoint;
		private ArrayList<Address> addresses;
		private ArrayList<Address> sources;
		private ArrayList<Address> destinations;


		// Initialization

		public Block ( Address entryPoint, Function blockFunction, 
			ArrayList<AssemInstruction> blockInstructions,
			ArrayList<Address> addresses,
			ArrayList<Address> sources,
			ArrayList<Address> destinations ) 
		{

			this.entryPoint = entryPoint;
			this.blockFunction = blockFunction;
			this.blockInstructions = blockInstructions;
			this.addresses = addresses;
			this.sources = sources;
			this.destinations = destinations;
		}


		// Getting Properties

		public Address getEntryPoint() {
			return this.entryPoint;
		}

		public Function getBlockFunction() {
			return this.blockFunction;
		}

		public ArrayList<AssemInstruction> getInstructions() {
			return this.blockInstructions;
		}

		public ArrayList<Address> getAddresses() {
			return this.addresses;
		}

		public ArrayList<Address> getSources() {
			return this.sources;
		}

		public ArrayList<Address> getDestinations() {
			return this.destinations;
		}


	}

	// --> AssemInstruction (represents one assembly instruction found in a CodeBlock)

	public class AssemInstruction {

		private Address instructionAddress;
		private Instruction originalInstruction;
		private ArrayList<String> resultObjects;		// according to Ghidra documentation, likely only Register or Address
		private ArrayList<String> inputObjects;			// according to Ghidra documentation, likely only Scalars, Registers and Addresses
		private ArrayList<PcodeInstruction> pcodeOps;

		// Constructor

		public AssemInstruction (ArrayList<PcodeInstruction> pcodeOps) {

			this.pcodeOps = pcodeOps;

		}

		// Instruction Address

		public Address getInstrAddr() {
			return instructionAddress;
		}
		
		public void setInstrAddr(Address instrAddr) {
			this.instructionAddress = instructionAddress;
		}


		// Assembly Instruction

		public Instruction getInstruction() {
			return originalInstruction;
		}

		public void setInstruction(Instruction instruction) {
			this.originalInstruction = instruction;
		}

		// Result Objects

		public ArrayList<String> getResultObjects() {
			return resultObjects;
		}

		public void setResultObjects(ArrayList<String> resultObjects) {
			this.resultObjects = resultObjects;
		}
		
		public void addResultObjects(String resultObject) {
			this.resultObjects.add(resultObject);
		}

		// Input Objects

		public ArrayList<String> getInputObjects() {
			return inputObjects;
		}

		public void setInputObjects(ArrayList<String> inputObjects) {
			this.inputObjects = inputObjects;
		}
		
		public void addInputObjects(String inputObject) {
			this.inputObjects.add(inputObject);
		}


		// PcodeInstructions

		public ArrayList<PcodeInstruction> getOps() {
			return pcodeOps;
		}
		
		public void addToOps(PcodeInstruction op) {
			this.pcodeOps.add(op);
		}

	}


	// --> PcodeInstruction (represents one PcodeOp in an AssemInstruction<Instruction>)

	public class PcodeInstruction {

		private String operator;
		private PcodeOp originalPcodeOp;
		private Address address;
		private Varnode output;
		private ArrayList<Varnode> inputs;

		public PcodeInstruction (String mnemonic, PcodeOp pcodeOp, Address address, ArrayList<Varnode> inputs) {
			this.operator = mnemonic;
			this.originalPcodeOp = pcodeOp;
			this.address = address;
			this.inputs = inputs;
		}
		
		public PcodeInstruction(String operatorMnemonic, Varnode output, ArrayList<Varnode> inputs) {
			this.operator = operatorMnemonic;
			this.output = output;
			this.inputs = inputs;
		}
		
		public PcodeInstruction(String operatorMnemonic, ArrayList<Varnode> inputs) {
			this.operator = operatorMnemonic;
			this.inputs = inputs;
		}


		// Get Properties
		
		public String getMnemonic() {
			return operator;
		}

		public Varnode getOutput() {
			return output;
		}

		public ArrayList<Varnode> getInputs() {
			return inputs;
		}

		public Address getAddress() {
			return address;
		}

		public PcodeOp getOp() {
			return originalPcodeOp;
		}


		// Set Properties

		public void setOutput(Varnode output) {
			this.output = output;
		}


	}


	// --> MemoryPosition (replacement of a Stack Varnode with a stack pointer and offset pair, but is also used to represent a constant)

	public class MemoryPosition {

		private Varnode register;
		private Varnode offset;
		
		public MemoryPosition(Varnode register, Varnode offset) {
			this.register = register;
			this.offset = offset;
		}

		public Varnode getOffset() {
			return offset;
		}

		public void setOffset(Varnode offset) {
			this.offset = offset;
		}

		public Varnode getRegister() {
			return register;
		}

		public void setRegister(Varnode register) {
			this.register = register;
		}

	}




	// Pcode Operation Classifications

	// --> Control Flow

	List<String> jmps = new ArrayList<String> () {{
		add("CALL");
		add("CALLIND");
		add("BRANCHIND");
		add("BRANCH");
		add("CBRANCH");
		add("RETURN");
	}};

	// --> Stack Operations

	List<String> stackOps = new ArrayList<String> () {{
		add("PUSH");
		add("POP");
	}};

	// --> Cast Operations (e.g. Truncation/Extension/Floating Point Conversion)

	List<String> casts = new ArrayList<String>() {{
		add("INT_NEGATE");
		add("INT_ZEXT");
		add("INT_SEXT");
		add("TRUNC");
		add("INT2FLOAT");
		add("CAST");
	}};

	// --> More General Operations

	List<String> generalOps = new ArrayList<String>() {{

		add("INT_EQUAL");
		add("INT_NOTEQUAL");

		add("INT_LESS");
		add("INT_SLESS");
		add("INT_LESSEQUAL");
		add("INT_SLESSEQUAL");

		add("INT_ADD");
		add("INT_SUB");

		add("INT_CARRY");
		add("INT_SCARRY");
		add("INT_SBORROW");

		add("INT_XOR");
		add("INT_AND");
		add("INT_OR");

		add("INT_LEFT");
		add("INT_RIGHT");
		add("INT_SRIGHT");

		add("INT_MULT");
		add("INT_DIV");
		add("INT_REM");
		add("INT_SDIV");
		add("INT_SREM");
	}};







// === SETUP FUNCTIONS & MINOR UTILITIES === (next section at line ?)

	// Tool Functions

	// --> Verbosity Controlled Print

	public void vprint(int vLevel, int printLevel, String message, Object... args){


		if (!saveLogs && verbosityLevel < vLevel) return;


		// Formatting Output

		// --> Adding Newlines and Tabs

		if (printLevel == 0) {
			message = "\n" + message;
		} else {
			message = "\t".repeat(printLevel) + message;
		}

		// --> Formatting with Non-String Arguments

		if (args.length > 0) {
			message = new Formatter().format(message, args).toString();
		}


		// Output to Console / Save to Logs

		if (verbosityLevel >= vLevel){
			System.setOut(console);
			System.out.println(message);
		}

		if (saveLogs){
			System.setOut(logstream);
			System.out.println(message);
		}

	}


	// --> Setting Up Decompiler

	private DecompInterface setUpDecompiler(Program program) {

		DecompInterface decompInterface = new DecompInterface();

		DecompileOptions options;
		options = new DecompileOptions();
		PluginTool tool = state.getTool();

		if (tool != null) {

			OptionsService service = tool.getService(OptionsService.class);

			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, program);
			}

		}

		decompInterface.setOptions(options);
		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;

	}


	// --> Decompilation to C Code

	public String decompilationToC(Function fn){

		return decompLib.decompileFunction(fn, decompLib.getOptions().getDefaultTimeout(), getMonitor()).getDecompiledFunction().getC();

	}

	// --> Converting to JSON

	public String jsonConverter() {

		JSONObject resultJSON = new JSONObject();

		JSONArray vulnSinks = new JSONArray();
		JSONArray nonVulnSinks = new JSONArray();
		JSONArray functionDecomps = new JSONArray();

		ArrayList<String> uniqueFunctionsPassedThru = new ArrayList<String>();

		for (SinkTaint sinkTaint : finalResult){

			JSONObject oneSink = new JSONObject();

			// Sink Information

			oneSink.put("Sink Name", new JSONObject(
				String.format("{\"%s (0x%s)\":\"0x%s\"}",
					sinkTaint.getFunc().getName(),
					sinkTaint.getFunc().getEntryPoint(),
					sinkTaint.getCall().toString()
				)
			));


			// Source Comment

			oneSink.put("Source Comment", sourceComment);


			// Path Information + Function Decompilations

			JSONArray paths = new JSONArray();

			for (TaintPath taintPath : sinkTaint.getTaintPaths()){

				JSONArray onepath = new JSONArray();

				ArrayList<Function> functionsPassedThru = taintPath.getFunctionsPassedThru();


				// Getting the Path Information

				for (int i = 0; i < functionsPassedThru.size(); i++){


					if (!uniqueFunctionsPassedThru.contains(functionsPassedThru.get(i).getName())){
						JSONObject functionDecomp = new JSONObject();
						functionDecomp.put(functionsPassedThru.get(i).getName(), decompilationToC(functionsPassedThru.get(i))); 
						functionDecomps.put(functionDecomp);
						uniqueFunctionsPassedThru.add(functionsPassedThru.get(i).getName());
					}


					ArrayList<String> blockOfInstructions = taintPath.getAssemblyPassedThru().get(i);

					if (blockOfInstructions.size() == 0) {continue;}

					
					JSONArray instructions = new JSONArray();

					for (int j = blockOfInstructions.size(); j-- > 0;){

						instructions.put(blockOfInstructions.get(j));

					}



					JSONObject block = new JSONObject();

					block.put(
						String.format("%s @ 0x%s", 
							functionsPassedThru.get(i).getName(), 
							functionsPassedThru.get(i).getEntryPoint()
						), 
						instructions
					);

					onepath.put(block);

				}

				if (!paths.toString().contains(onepath.toString())){
					paths.put(onepath);
				}

			}


			oneSink.put("Paths", paths);


			// Vulnerability Classification

			if (sinkTaint.allNodesConstant()) { nonVulnSinks.put(oneSink); }
			else { vulnSinks.put(oneSink); }

		}

		resultJSON.put("vulnerable", vulnSinks);
		resultJSON.put("non-vulnerable", nonVulnSinks);
		resultJSON.put("function decompilations", functionDecomps);

		return resultJSON.toString();
	}

	// --> Generating JSON File

	public void jsonOutputFile() {
		
		// JSON String

		String content = jsonConverter();

		// Ensuring tempJSON is already there

		File tempJSONDir = new File(scriptLocation + "/tempJSON");
		tempJSONDir.mkdir();

		// File Name

		String filename = scriptLocation + "/tempJSON/" + getProgramFile().getName() + "_" + datetime + ".json";

		// Creating JSON File

		File jsonOutput = new File(filename);

		try{

			if (jsonOutput.createNewFile()) {
		    	vprint(0, 0, "JSON Output Created: " + jsonOutput.getName());
		    } else {
		        vprint(5, 0, "ERROR: JSON file with same name already created.");
		    }

		} catch (IOException e) {
	    	vprint(5, 0, "ERROR: JSON file could not be created due to IO Exception.");
	    	e.printStackTrace();
	    }

	    // Writing to JSON File

	    try {

	    	FileWriter jsonWriter = new FileWriter(filename);

	    	jsonWriter.write(content);
	    	jsonWriter.close();
	    	vprint(0, 0, "Results Written to JSON.\n\n");

	    } catch (IOException e) {
	    	vprint(5, 0, "ERROR: Could not write results to JSON file due to IO Exception.");
	    	e.printStackTrace();
	    }
	}

	// --> Create Log File 

	public File createLogFile() {

		// Creating / Checking for Log Folder

		File logs = new File(scriptLocation + "/../Logs/Taint_Analysis_Logs");
		logs.mkdir();


		// Log File Name

		String logFileName = scriptLocation + "/../Logs/Taint_Analysis_Logs/" + getProgramFile().getName() + "_" + datetime + ".txt";


		// Creating Log File

		File log = new File(logFileName);

		try {
			if (log.createNewFile()) {
		    	System.out.println("\nLog File Created: " + log.getName());
		    } else {
		        System.out.println("ERROR: Log file with same name already created.");
		    }
		} catch (IOException e) {
		    	System.out.println("ERROR: Log file could not be created due to IO Exception.");
		    	e.printStackTrace();
	    }

		return log;
	}


	// Tracing Setup (Architecture-Specific Registers)

	// --> Get Computer Architecture

	public String getComArchitecture(){

		String[] languageID = currentProgram.getCompilerSpec().getLanguage().getLanguageID().getIdAsString().split(":");
		vprint(0,0,"Architecture Detected: "+languageID[0] + "-" + languageID[2]);
		return languageID[0] + "-" + languageID[2];

	}

	// --> Get Architecture Return Register

	public Register getArchReturnRegister(String comArch, VarnodeContext varnodeContext) {
		switch(comArch) {
			case "x86-64": {vprint(0,1,"Return Register: RAX"); return varnodeContext.getRegister("RAX");}
			case "x86-32": {vprint(0,1,"Return Register: EAX"); return varnodeContext.getRegister("EAX");}
			case "ARM-32": {vprint(0,1,"Return Register: r0"); return varnodeContext.getRegister("r0");}
			default: {vprint(0,1,"Return Register: v0"); return varnodeContext.getRegister("v0");}
		}
	}

	// --> Get Architecture Parameter Register

	public ArrayList<Register> getArchParameterRegister(String comArch, VarnodeContext varnodeContext) {
		ArrayList<Register> parameters = new ArrayList<Register>();
		switch(comArch) {
			case "x86-64": {
				parameters.add(varnodeContext.getRegister("RDI"));
				parameters.add(varnodeContext.getRegister("RSI"));
				parameters.add(varnodeContext.getRegister("RDX"));
				parameters.add(varnodeContext.getRegister("RCX"));
				parameters.add(varnodeContext.getRegister("R8"));
				parameters.add(varnodeContext.getRegister("R9"));
				vprint(0,1,"Parameter Registers: %s", parameters);
				return parameters;
			}
			case "x86-32": return parameters;
			case "ARM-32": {
				parameters.add(varnodeContext.getRegister("r0"));
				parameters.add(varnodeContext.getRegister("r1"));
				parameters.add(varnodeContext.getRegister("r2"));
				parameters.add(varnodeContext.getRegister("r3"));
				vprint(0,1,"Parameter Registers: %s", parameters);
				return parameters;
			}
			default: {
				parameters.add(varnodeContext.getRegister("a0"));
				parameters.add(varnodeContext.getRegister("a1"));
				parameters.add(varnodeContext.getRegister("a2"));
				parameters.add(varnodeContext.getRegister("a3"));
				vprint(0,1,"Parameter Registers: %s", parameters);
				return parameters;
			}
		}
	}


	// Tracing Setup (Building Block List)

	// --> Build Block from CodeBlock

	public ArrayList<Block> generateBlockList() {

		ArrayList<Block> blockListGenerated = new ArrayList<Block> ();			// List of Blocks

		for (Function function : funcManager.getFunctionsNoStubs(true)) {

			AddressSetView addressSetView = function.getBody();
			try{

				CodeBlockIterator codeBlocks = new SimpleBlockModel(currentProgram).getCodeBlocksContaining(addressSetView, monitor);
			
				while(codeBlocks.hasNext()){

					CodeBlock codeBlock = codeBlocks.next();
					Block block = new Block (
						codeBlock.getFirstStartAddress(),
						function,
						buildAssemInstructions(codeBlock),
						getCodeBlockAddresses(codeBlock, "address"),
						getCodeBlockAddresses(codeBlock, "source"),
						getCodeBlockAddresses(codeBlock, "destination")

					);

					blockListGenerated.add(block);
				}
			} catch (CancelledException error) {
				System.out.println("ERROR: Problem retrieving basic blocks (CodeBlocks) when generating blockList");
			}
		}

		return blockListGenerated;

	}

	// --> Build AssemInstructions for CodeBlock

	public ArrayList<AssemInstruction> buildAssemInstructions(CodeBlock codeBlock){

		InstructionIterator listingInstructions = currentProgram.getListing().getInstructions(codeBlock, true);

		ArrayList<AssemInstruction> assemInstructions = new ArrayList<AssemInstruction>();
		
		while(listingInstructions.hasNext()) {

			Instruction listingInstruction = listingInstructions.next();
			AssemInstruction assemInstruction = new AssemInstruction(new ArrayList<PcodeInstruction>());
			

			assemInstruction.setInstruction(listingInstruction);
			assemInstruction.setResultObjects(new ArrayList<String>());
			assemInstruction.setInputObjects(new ArrayList<String>());


			for(Object res : listingInstruction.getResultObjects()) {assemInstruction.addResultObjects(res.toString());}
			for(Object in : listingInstruction.getInputObjects()) {assemInstruction.addInputObjects(in.toString());}

			assemInstruction.setInstrAddr(listingInstruction.getAddress());

			for (PcodeOp pcodeOp : listingInstruction.getPcode(true)) {

				ArrayList<Varnode> inputs = new ArrayList<Varnode>();

				for(int i = 0; i < pcodeOp.getNumInputs(); i++) {
					inputs.add(pcodeOp.getInput(i));
				}

				PcodeInstruction pcodeInstruction = new PcodeInstruction(
					pcodeOp.getMnemonic(),
					pcodeOp,
					listingInstruction.getAddress(),
					inputs
				);

				if (!pcodeOp.getMnemonic().equals("STORE")
					&& !jmps.contains(pcodeOp.getMnemonic())) {

					pcodeInstruction.setOutput(pcodeOp.getOutput());

				}

				assemInstruction.addToOps(pcodeInstruction);
			}
			assemInstructions.add(assemInstruction);
		}
		return assemInstructions;
	}


	// --> Get Addresses for CodeBlocks (Addresses, Sources, Destinations)
	
	public ArrayList<Address> getCodeBlockAddresses(CodeBlock codeBlock, String addressType) {

		ArrayList<Address> addresses = new ArrayList<Address>();
		CodeBlockReferenceIterator blockRefIter;

		try{

			switch (addressType) {

				case "address" : {

					codeBlock.getAddresses(true).forEachRemaining(addresses::add);
				
				}; break;

				case "source" : {

					blockRefIter = codeBlock.getSources(monitor);
					while(blockRefIter.hasNext()) {
						addresses.add(blockRefIter.next().getSourceAddress());
					}

				}; break;

				case "destination" : {

					blockRefIter = codeBlock.getDestinations(monitor);
					while(blockRefIter.hasNext()) {
						addresses.add(blockRefIter.next().getDestinationAddress());
					}
				}; break;

				default : break;
			}
		} catch (CancelledException e) {

			// (!) Error to be added here soon...
		
		}

		return addresses;
	}


	// --> Getting Block by Address

	public Block getBlockByAddress(ArrayList<Block> blockList, Address address){
		for (Block block : blockList){
			if (block.getAddresses().contains(address)) {
				return block;
			}
		}
		return null;
	}

	// --> Build Sink Call Map

	public HashMap<Function, ArrayList<Address>> generateSinkCallMap() {

		HashMap<Function, ArrayList<Address>> sinkCallMapGenerated = new HashMap<Function, ArrayList<Address>>();	// Identified Sink Calls

		for (Symbol sym : currentProgram.getSymbolTable().getDefinedSymbols()) {

			if (sinkNames.contains(sym.getName()) && !sym.isExternal()) {

				for(Reference ref : sym.getReferences()) {

					Function sinkFunction = funcManager.getFunctionAt(sym.getAddress());
					Function parentFunction = funcManager.getFunctionContaining(ref.getFromAddress());
					Address calledAddr = ref.getFromAddress();

					if(parentFunction != null && !sinkNames.contains(parentFunction.getName())) {
						if(sinkCallMapGenerated.get(sinkFunction) == null) {

							ArrayList<Address> addresses = new ArrayList<Address>();
							addresses.add(calledAddr);
							sinkCallMapGenerated.put(sinkFunction, addresses);
						
						} else {

							sinkCallMapGenerated.get(sinkFunction).add(calledAddr);
						}
					}
				}
			}
		}

		return sinkCallMapGenerated;

	}


	// Making a Copy of TaintPath for the SinkTaint

	public TaintPath makeCopy(SinkTaint sinkTaint, TaintPath taintPath){
		
		TaintPath clone = new TaintPath(new ArrayList<Varnode>(), new ArrayList<MemoryPosition>());

		clone.setDepthLevel(taintPath.getDepthLevel());

		taintPath.getNodes().forEach(node -> clone.addNode(node));
		taintPath.getMemPositions().forEach(pos -> clone.addMem(new MemoryPosition(pos.getRegister(), pos.getOffset())));
		taintPath.getFunctionsPassedThru().forEach(function -> clone.addFunctionPassedThru(function));

		ArrayList<ArrayList<String>> clonedAssembly = new ArrayList<ArrayList<String>>();
		for (ArrayList<String> block : taintPath.getAssemblyPassedThru()) {
			ArrayList<String> newBlock = new ArrayList<String>();
			block.forEach(instruction -> newBlock.add(instruction));
			clonedAssembly.add(newBlock);
		}
		clone.setAssemblyPassedThru(clonedAssembly);

		sinkTaint.addTaintPath(clone);

		return clone;
	}




// ==== TAINT ANALYSIS === (MAIN SECTION)

	public void run() throws Exception {

		System.out.println("\n\n#########################################################################\n");

		// Processing Tool Options/Arguments

		String[] args = getScriptArgs();

		for (int i = 0; i < args.length ; i++){
			if (args[i].startsWith("@")) {
				
				switch(args[i]){

					case "@l": { saveLogs = false; }; break;

					case "@s": { scriptLocation = args[i+1]; }; break;
					
					case "@v": {
						try{
							verbosityLevel = Integer.parseInt(args[i+1]);
							if (verbosityLevel > 5 || verbosityLevel < 0){
								System.out.println("Verbosity level specified does not exist (a number from 0 and 5).");
								System.out.println("Default Verbosity Level 0 assumed.");
								verbosityLevel = 0;
							} else {
								System.out.println("Verbosity Level successfully set to " + args[i+1]);
							}
						} catch (NumberFormatException e){
							System.out.println("Verbosity level specified is invalid (enter a number).");
							System.out.println("Default Verbosity Level 0 assumed.");
						}
					}; break;

					case "@d": {
						try{
							depthLimit = Integer.parseInt(args[i+1]);
							if (depthLimit > 40 || depthLimit < 0){
								System.out.println("Depth limit specified does not exist (a number from 0 and 200).");
								System.out.println("Default Depth Limit 15 assumed.");
								depthLimit = 15;
							} else {
								System.out.println("Depth Limit successfully set to " + args[i+1]);
							}
						} catch (NumberFormatException e){
							System.out.println("Depth Limit specified is invalid (enter a number).");
							System.out.println("Default Depth Limit 15 assumed.");
						}
					}; break;

					default: {
						System.out.println("option specified does not exist.");
					}; break;
				}
			}
		}

		System.out.println(String.format("Verbosity Level: " + verbosityLevel));
		System.out.println(String.format("Depth Limit: " + depthLimit));

		// Log Setup

		if (saveLogs){
		    logstream = new PrintStream(new FileOutputStream(createLogFile()));
		}

		vprint(0,0,"#########################################################################");


		// Variable Setup

		monitor = getMonitor();
		decompLib = setUpDecompiler(currentProgram);
		if(!decompLib.openProgram(currentProgram)) {
    		System.out.print(String.format("\nDecompiler error: %s\n", decompLib.getLastMessage()));
    		return;
    	}

		funcManager = currentProgram.getFunctionManager();
		addressFactory = currentProgram.getAddressFactory();
		varnodeContext = new VarnodeContext(currentProgram, currentProgram.getProgramContext(), currentProgram.getProgramContext());

		comArchitecture = getComArchitecture();
		stackPointer = currentProgram.getCompilerSpec().getStackPointer();
		returnRegister = getArchReturnRegister(comArchitecture, varnodeContext);
		paramRegisters = getArchParameterRegister(comArchitecture, varnodeContext);


		// List of Blocks (All Blocks in Program)

		ArrayList<Block> blockList = generateBlockList();



		// Sink Call Map (Identified Calls / References to Sinks)

		HashMap<Function, ArrayList<Address>> sinkCallMap = generateSinkCallMap();



		// === GOING THROUGH EACH SINK CALL ===

		vprint(0,0,"#########################################################################");

		for (Function sink : sinkCallMap.keySet()) {

			// Going Through Each Sink Call/Reference

			for (Address callAddr : sinkCallMap.get(sink)) {


				// Get First Parameter Varnode (Register & Stack Varnodes)

				Parameter param = sink.getParameters()[0];

				vprint(3, 0, "Vulnerable Parameter of sink (%s) @ %s : %s", 
					sink.getName(), 
					sink.getEntryPoint().toString(), 
					param.getFormalDataType().getName()
				);

				// --> Check if register or stack varnode

				ArrayList<Varnode> registerParam = new ArrayList<Varnode>();
				ArrayList<MemoryPosition> stackParam = new ArrayList<MemoryPosition>();

				Varnode varnodeFound = param.getFirstStorageVarnode();

				if (varnodeFound.isRegister()) {

					vprint(3, 2, "REGISTER Parameter: %s", varnodeFound.toString());

					registerParam.add(varnodeFound);

				} else {

					if (varnodeFound.isFree()) {

						stackParam.add(
							new MemoryPosition (
								varnodeContext.getRegisterVarnode(stackPointer), 
								new Varnode (
									addressFactory.getConstantAddress(varnodeFound.getAddress().getOffset()),
									varnodeFound.getSize()	
								)
							)
						);

						vprint(3, 2, "STACK Parameter: %s => %s + %s", 
							varnodeFound.toString(), 
							stackParam.get(0).getRegister().toString(), 
							stackParam.get(0).getOffset().toString()
						);
					}
				}


				// Starting Taint Path

				TaintPath startingTaintPath = new TaintPath(registerParam, stackParam);


				// List of TaintPath per SinkTaint (currently only containing starting TaintPath)

				ArrayList<TaintPath> taintPaths = new ArrayList<TaintPath>();
				taintPaths.add(startingTaintPath);


				// SinkTaint for Current Sink

				SinkTaint sinkTaint = new SinkTaint(sink, callAddr, taintPaths);


				// Starting Block

				Block startBlock = getBlockByAddress(blockList, callAddr);


				// === TRACING BEGINS HERE ===

				vprint(3,1, "");

				vprint(3,1,"============================");

				vprint(3,1,"Sink (%s) @ 0x%s --> STARTING PATH", sink.getName(), callAddr);

				goingIntoABlock(sinkTaint, sinkTaint.getTaintPaths().get(0), blockList, startBlock);

				vprint(3,1,"============================");


				finalResult.add(sinkTaint);


				vprint(1,0,"#########################################################################");

				checkStatus(sinkTaint);

			}
		}

		// Generate JSON File w/ Results

		jsonOutputFile();

	}




	// === TRACE FUNCTIONS ===

	public void goingIntoABlock(SinkTaint sinkTaint, TaintPath taintPath, ArrayList<Block> blockList, Block block) {

		vprint(3,2,"===============");

		// --> See which function the block passed through belongs to and add it to the path

		taintPath.addFunctionPassedThru(block.getBlockFunction());

		// --> Add a new block to the path

		taintPath.addNewBlock();

		// --> Increment Depth Level

		taintPath.incrementDepthLevel();


		// --> Looking for things inside a block

		goingThroughAssemblyInABlock(sinkTaint, taintPath, blockList, block);


		// --> Going to the next Block after going through all the current block's assembly instructions

		if (taintPath.getDepthLevel() <= depthLimit) {		// if every node in the path is constant, it's likely not vulnerable already
			
			// Get Source Blocks & Remove Null Blocks from Among Them

			ArrayList<Block> sourceBlocks = new ArrayList<Block>();
			for (Address src : block.getSources()) {
				Block srcBlock = getBlockByAddress(blockList, src);
				if (srcBlock != null) {
					sourceBlocks.add(srcBlock);
				}
			}

			// If there are Source Blocks, Trace into Those Source Blocks (Next Block)

			if(sourceBlocks.size() > 0) {

				if(sourceBlocks.size() > 1) {
				    for(int index = 1; index < sourceBlocks.size(); index++) {
					    TaintPath clone = makeCopy(sinkTaint, taintPath);
					    vprint(4,0,"--> NEW PATH CREATED");
					    goingIntoABlock(sinkTaint, clone, blockList, sourceBlocks.get(index));
					    vprint(4,0,"--> Continuing back to previous path...");
				    }
			    }

				goingIntoABlock(sinkTaint, taintPath, blockList, sourceBlocks.get(0));	// If there is only one source block, no need for clone

			}
		}
	}

	public void goingThroughAssemblyInABlock(SinkTaint sinkTaint, TaintPath taintPath, ArrayList<Block> blockList, Block block){


		// ---> Go through the block's assembly instructions

		ArrayList<AssemInstruction> assembly = block.getInstructions();

		for (int i = assembly.size() ; i-- > 0;) {

			vprint(3,2,"Assembly Instruction #%d, Block #%d: %s", i+1, taintPath.getDepthLevel(), assembly.get(i).getInstruction());

			if (taintPath.getDepthLevel() >= depthLimit){ break; }
			
			AssemInstruction assemInstruction = assembly.get(i);
			int numOfPcodeInstruction = assemInstruction.getOps().size();
			
			if(numOfPcodeInstruction > 0){		// just in case assembly instruction is a NOP

				PcodeOp lastPcodeInInstruction = assemInstruction.getOps().get(assemInstruction.getOps().size() - 1).getOp();

				if ((i == assembly.size() - 1) && (taintPath.getDepthLevel() == 1)) {		// --> First assembly instruction of the start block right before the sink call
					
					// starting assembly instruction to go through in first block, but does not need to be analyzed.

					if (PcodeOp.CALL == lastPcodeInInstruction.getOpcode()){	// Giving CALL Instructions their Function Names

						Function calledFunc = funcManager.getFunctionAt(lastPcodeInInstruction.getInput(0).getAddress());

						taintPath.addAssemblyToLatestBlock(String.format("0x%s   CALL %s", 
							assemInstruction.getInstruction().getAddress(),
							calledFunc.getName()));
					
					} 

				} else {

					if (PcodeOp.CALL == lastPcodeInInstruction.getOpcode()) {		// --> WHEN A CALL INSTRUCTION IS ENCOUNTERED

						Function calledFunc = funcManager.getFunctionAt(lastPcodeInInstruction.getInput(0).getAddress());

						// --> Checking for some specific external thunk functions being called

						if (calledFunc.isThunk()) {
						
							// If the last pcode instruction is a CALL, check if it's referring to an external library function (i.e. thunk function)
							// if it is one of the thunks we are looking for

							if (modifyingThunkFunctions.contains(calledFunc.getName())){

								// Retrieve what is passed into RDI from the last instruction (i.e. the first parameter that is the destination)
								AssemInstruction prevAssemInstruction = assembly.get(i - 1);
								Varnode destination = prevAssemInstruction.getOps().get(0).getOp().getInput(0);

								// Retrieve the varnode of RSI
								Varnode firstSource = varnodeContext.getRegisterVarnode(paramRegisters.get(1));		// first source varnode (2nd parameter)

								if(!taintPath.notATrackedNode(destination)){	// if nodes contain the destination varnode (1st parameter)
									
									taintPath.addNode(firstSource);

									taintPath.addAssemblyToLatestBlock(
										String.format("0x%s   %s( %s , %s )",
											assemInstruction.getInstruction().getAddress(),
											calledFunc.getName(),
											destination.isRegister() ? varnodeContext.getRegister(destination).getName() : destination,
											paramRegisters.get(1)
										)
									);
								}

								// Special Comment for recv since it is a notable source
								if (calledFunc.getName().equals("recv")){

									sourceComment = "recv encountered with tracked node as parameter, likely vulnerable socket source (e.g. httpd)";
									
									taintPath.addNode(firstSource);
									taintPath.addAssemblyToLatestBlock(
										String.format("0x%s   %s(%s)",
											assemInstruction.getInstruction().getAddress(),
											calledFunc.getName(),
											paramRegisters.get(1)
										)
									);
								}

							} else { 

								if (!taintPath.notATrackedNode(varnodeContext.getRegisterVarnode(returnRegister))){	// if the return register is currently a tracked node

									if (followOneParamThunkFunctions.keySet().contains(calledFunc.getName())) {	// Thunk Function (Other Cases Not Handled by FinjectRoute yet)

											Register param = paramRegisters.get(
												followOneParamThunkFunctions.get(
													calledFunc.getName()
												) - 1
											);

											taintPath.addNode(varnodeContext.getRegisterVarnode(param));

											taintPath.addAssemblyToLatestBlock(
												String.format("0x%s   %s(%s)",
													assemInstruction.getInstruction().getAddress(),
													calledFunc.getName(),
													param
												)
											);

											// strtok is special because after the 1st time it is called, it uses NULL, which cannot be traced
											if (!calledFunc.getName().equals("strtok") && 
												!assembly.get(i - 1).getOps().get(0).getOp().getInput(0).toString().equals("(const, 0x0, 8)")){

												taintPath.removeNode(varnodeContext.getRegisterVarnode(returnRegister));
											}

									} else {

										taintPath.addAssemblyToLatestBlock(
											String.format("0x%s   %s",
												assemInstruction.getInstruction().getAddress(),
												calledFunc.getName()
											)
										);

										taintPath.removeNode(varnodeContext.getRegisterVarnode(returnRegister));

									}
								}
							}
						} 

						// --> If CALL is NOT to an external function

						else {	// CALL to a function that exists in the binary

							if (!calledFunc.getName().equals(taintPath.getPreviousFunctionPassedThru().getName())){	 // prevent recursive tracing


								// Find the last block of the called function
								// Note: this method will not work if the function is indeed the last function found by the function manager

								FunctionIterator programFunctions = funcManager.getFunctions(true);
								while (programFunctions.hasNext()){
									if (programFunctions.next().getName().equals(calledFunc.getName())) {
										Address lastAddress = programFunctions.next().getEntryPoint().add(-1);
										Block lastBlockOfCalledFunc = getBlockByAddress(blockList, lastAddress);
										
										if (lastBlockOfCalledFunc != null){
											
											goingIntoABlock(sinkTaint, taintPath, blockList, lastBlockOfCalledFunc);

											// Returning Back to Current Block

											taintPath.addFunctionPassedThru(block.getBlockFunction());
											taintPath.addNewBlock();
											taintPath.incrementDepthLevel();
										}

										break;
									}
								}

							}

						}

					} else {	// NOT a CALL

						goingThroughPcodeOfAssemblyInstruction(taintPath, assemInstruction, block);

					}

				}

			}
		}
	}


	public void goingThroughPcodeOfAssemblyInstruction (TaintPath taintPath, AssemInstruction assemInstruction, Block block) {


		// We look for Matching Input & Output Objects:

		// --> Find Matching Output Objects (between AssemInstruction and Nodes in TracePath)

		ArrayList<Varnode> matchedOutput = new ArrayList<Varnode>();
		for (String out : assemInstruction.getResultObjects()) {
			for (Varnode node : taintPath.getNodes()){
				if(node.isRegister() && varnodeContext.getRegister(node).getName().equals(out)) {
					matchedOutput.add(node);
				}
				if (node.toString().contains(out.replaceFirst("^0+(?!$)", "")) && (out.startsWith("00") || out.startsWith("-00"))){
					matchedOutput.add(node);
				}
			}
		}

		// --> Find Matching Input Objects (between AssemInstruction and Nodes in TracePath)

		ArrayList<MemoryPosition> matchedInput = new ArrayList<MemoryPosition>();
		
		MemoryPosition stackPos = null;
		for (MemoryPosition pos : taintPath.getMemPositions()) {
			if(varnodeContext.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
				stackPos = pos;
			}
		}

		ArrayList<String> inputs = assemInstruction.getInputObjects();

		if (inputs.contains(stackPointer.getName()) && stackPos != null){
			matchedInput.add(stackPos);
		} else {
			for (String in : inputs) {
				if (in.startsWith("0x") || in.startsWith("-0x") || in.startsWith("00") || in.startsWith("-00")) {
					for (MemoryPosition pos : taintPath.getMemPositions()) {
						String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
						try {
							long input = 0;
							if(in.startsWith("-")) {	// Check if negative
								if (in.startsWith("-0x")) { input = new BigInteger(in.replaceFirst("^-0x", ""), 16).longValue(); }
								else { input = new BigInteger(in, 16).longValue(); }
								input *= -1;
							} else {
								if (in.startsWith("0x")) { input = new BigInteger(in.replaceFirst("^0x", ""), 16).longValue(); }
								else { input = new BigInteger(in, 16).longValue(); }
							}
							long off = new BigInteger(offset, 16).longValue();
							if((input == off || (input *= -1) == off) && inputs.contains(varnodeContext.getRegister(pos.getRegister()).getName())) {
								matchedInput.add(pos);
							}
						} catch(NumberFormatException e) {
							continue;
						}
					} 
				}
			}
		}

		vprint(4, 2,"-----------");
		vprint(4, 3, "Result Objects: %s", assemInstruction.getResultObjects());
		vprint(4, 3, "Input Objects: %s", assemInstruction.getInputObjects());


		// If there are any Matched Input or Output objects:
				
		if(!matchedOutput.isEmpty() || !matchedInput.isEmpty()) {

			vprint(4, 3, "** Input/Output Object matched! **", assemInstruction.getInputObjects());
			vprint(4, 3, "Matched Input: %s", matchedInput);
			vprint(4, 3, "Matched Output: %s", matchedOutput);

			// Adding Assembly Instruction as Relevant

			taintPath.addAssemblyToLatestBlock(String.format("0x%s   %s", 
				assemInstruction.getInstruction().getAddress(),
				assemInstruction.getInstruction()));
		

			// Deal with the Pcode

			ArrayList<PcodeInstruction> ops = assemInstruction.getOps();

			vprint(4,4,"-----------");
			for (PcodeInstruction op : ops){
				vprint(4,4,op.getOp().toString());
			}
			vprint(4,4,"-----------");

			if(stackOps.contains(assemInstruction.getInstruction().getMnemonicString())) {	// If Assembly Instruction Matched is Stack Operation (i.e. PUSH, POP)
				
				vprint(5,5,"**STACK OPERATION (PUSH/POP) FOUND**");

				ArrayList<String> reg = taintPath.getMemPositions().stream().map(m -> varnodeContext.getRegister(m.getRegister()).getName()).collect(Collectors.toCollection(ArrayList::new));
				if (reg.contains(stackPointer.getName())) {
					PcodeOp firstPcodeInstruction = assemInstruction.getOps().get(0).getOp();
					if (firstPcodeInstruction.getOpcode() == PcodeOp.COPY) {	// If COPY is the first Pcode Instruction in Stack Operation Assembly Instruction
						Varnode in = firstPcodeInstruction.getInput(0);
						if (taintPath.notATrackedNode(in)){
							taintPath.addNode(in);	// add varnode to nodes
							vprint(5,6,"COPY: input %s added to tracked nodes.", in.toString());
						}

					} else if (firstPcodeInstruction.getOpcode() == PcodeOp.INT_ADD) { // If INT_ADD is the first Pcode Instruction in Stack Operation Assembly Instruction
						MemoryPosition newPos = new MemoryPosition(firstPcodeInstruction.getInput(0), firstPcodeInstruction.getInput(1));
						if (taintPath.notATrackedMemoryPosition(newPos.getRegister(), newPos.getOffset())) {

							taintPath.addMem(newPos);	// add MemoryPosition to memory positions

							vprint(5,6,"INT_ADD: memory position %s + %s created and added to tracked memory positions.", 
								firstPcodeInstruction.getInput(0),
								firstPcodeInstruction.getInput(1)
							);
						}
					}
				}

				vprint(5,5,"**REMOVING MEMORY POSITIONS WITH STACK POINTER**");

				taintPath.removeStackPointer();	// remove MemoryPosition with stackPointer as register from memory positions
			}

			if(assemInstruction.getResultObjects().isEmpty()){	// If there is nothing returned from the Assembly Instruction Matched (STORE / COPY)
				
				vprint(5,5,"**NO RETURN OBJECTS DETECTED FOR ASSEMBLY INSTRUCTION**");

				ArrayList<Varnode> copied = new ArrayList<Varnode>();
				for (MemoryPosition pos : matchedInput) {
					taintPath.getMemPositions().remove(pos);	// remove all existing StackOffsets that were matched
					vprint(5, 6, "**INPUT OBJECT TO INSTRUCTION %s + %s REMOVED FROM TRACKED MEMORY POSITIONS**",
						pos.getRegister().toString(),
						pos.getOffset().toString()
					);
				}
				
				Boolean inputSet = false;
				for (PcodeInstruction op : ops){
					PcodeOp originalPcodeOp = op.getOp();
					if ((originalPcodeOp.getOpcode() == PcodeOp.COPY) && (!originalPcodeOp.getInput(0).isUnique())) {
						copied.add(originalPcodeOp.getInput(0));
						vprint(5, 6, "COPY: input %s added to tracked nodes.", originalPcodeOp.getInput(0));
					}
					if ( (originalPcodeOp.getOpcode() == PcodeOp.STORE) 
						&& ( !( (originalPcodeOp.getNumInputs() == 3) ? originalPcodeOp.getInput(2).isUnique() : originalPcodeOp.getInput(1).isUnique() ) ) 
					) {	// If STORE input is virtual, the last varnode of the pcode operation is a unique
						inputSet = true;
						taintPath.addNode( (originalPcodeOp.getNumInputs() == 3) ? originalPcodeOp.getInput(2) : originalPcodeOp.getInput(1) );
						vprint(5, 6, "STORE: input %s added to tracked nodes.",
							(originalPcodeOp.getNumInputs() == 3) ? originalPcodeOp.getInput(2) : originalPcodeOp.getInput(1)
						);
					}
				}

				if (!inputSet) {
					vprint(5, 6, "STORE NOT ENCOUNTERED: adding all matched input objects to tracked nodes.");
					for (Varnode cpy : copied) {
						taintPath.addNode(cpy);
						vprint(5, 7, "matched input object %s added", cpy.toString());
					}
				}

			}

			else {	// If there are things returned (output) from the Assembly Instruction Matched (OTHER PCODE)

				StackFrame frame = funcManager.getFunctionContaining(assemInstruction.getInstruction().getAddress()).getStackFrame();
				
				for (int i = ops.size(); i-- > 0;) {
					
					PcodeOp op = ops.get(i).getOp();

					Varnode output = op.getOutput();	// resulting varnode of pcode instruction

					ArrayList<Long> varOffsets = new ArrayList<Long>();		// list of variables in the function's stackframe
					for (Variable variable : frame.getStackVariables()) {
						varOffsets.add((long)variable.getStackOffset());
					}

					ArrayList<Varnode> trackedNodes = taintPath.getNodes();
					ArrayList<Varnode> trackedMemRegisters = new ArrayList<Varnode>();
					taintPath.getMemPositions().forEach(mp -> trackedMemRegisters.add(mp.getRegister()));

					if (trackedNodes.contains(output) || trackedMemRegisters.contains(output)) {

						vprint(5,5,"** OUTPUT %s OF PCODE INSTRUCTION DETECTED IN TRACKED NODES**", output.toString());

						if(generalOps.contains(op.getMnemonic())) {
							
							if( op.getOpcode() == PcodeOp.INT_ADD || op.getOpcode() == PcodeOp.INT_SUB ) {

								Varnode destination = op.getInput(0);
								Varnode source = op.getInput(1);
								
								if(destination.isRegister()) {
									if(source.isConstant()) {

										vprint(5, 6, "INT_ADD/INT_SUB: CONSTANT REGISTER DETECTED");

										if(!destination.toString().equals(output.toString())) {
											taintPath.removeNode(output);
											if(taintPath.notATrackedMemoryPosition(destination, source)) {
												taintPath.addMem(new MemoryPosition(destination, source));
											}
										}		

									} else {

										vprint(5, 6, "INT_ADD/INT_SUB: NON-CONSTANT REGISTER DETECTED");

										taintPath.removeNode(output);
										taintPath.addNode(source);
									}
								}
							}

						}
						if (casts.contains(op.getMnemonic())) {
							continue;
						}
						if(op.getOpcode() == PcodeOp.COPY) {
							trackedNodes.remove(output);
							taintPath.addNode(op.getInput(0));
							vprint(5, 5, "COPY: input %s added to tracked nodes.", op.getInput(0));
						}
						if (op.getOpcode() == PcodeOp.LOAD) {
							trackedNodes.remove(output);
							if(op.getNumInputs() == 2) {
								taintPath.addNode(op.getInput(1));
								vprint(5, 5, "LOAD: input %s added to tracked nodes.", op.getInput(1));
							} else {
								taintPath.addNode(op.getInput(0));
								vprint(5, 5, "LOAD: input %s added to tracked nodes.", op.getInput(0));
							}
						}
					}
				}
			}
		}

	}


	// Console Output Status Check

	public void checkStatus(SinkTaint sinkTaint){
		vprint(1, 0, "Taint for Sink (%s @ 0x%s) called/referenced @ 0x%s\n", 
			sinkTaint.getFunc().getName(),
			sinkTaint.getFunc().getEntryPoint().toString(), 
			sinkTaint.getCall().toString()
		);

		int counter = 0;
		for (TaintPath taintPath : sinkTaint.getTaintPaths()){

			vprint(2, 1, "############################");
			vprint(2, 1, "Nodes:");
			for (Varnode node : taintPath.getNodes()){
				vprint(2, 2, node.toString());
			}
			vprint(2, 1, "");
			vprint(2, 1, "Memory Positions:");
			for (MemoryPosition pos : taintPath.getMemPositions()) {
				vprint(2, 2, pos.getRegister().toString() + " (register) + " + pos.getOffset().toString() + " (offset)");
			}
			vprint(2, 1, "############################\n");

			vprint(2, 1, "Path #%d", counter);

			for (int i = 0; i < taintPath.getFunctionsPassedThru().size() ; i++){
				if (taintPath.getAssemblyPassedThru().get(i).size() > 0) {
					vprint(2, 2, "Function: %s @ %s  -->  Depth Level #%s", 
						taintPath.getFunctionsPassedThru().get(i), 
						taintPath.getFunctionsPassedThru().get(i).getEntryPoint().toString(),
						i
					);
					for (String instruction : taintPath.getAssemblyPassedThru().get(i)){
						vprint(2, 3, instruction);
					}
					vprint(2, 2, "");
				}
			}

			counter++;
		}

		vprint(1, 0, "\nRESULT: " + (sinkTaint.allNodesConstant() ? "non-vulnerable" : "potentially vulnerable!"));
		vprint(1, 0, "#########################################################################");
	}


}

// Inspired by: INFILTRATE 2019 Malloctrace.java by Alexei Bulazel, and other scripts