"use strict";

//
// Utility functions.
//

const Log = host.diagnostics.debugLog;
const Logln = p => host.diagnostics.debugLog(p + '\n');
const Hex = p => '0x' + p.toString(16);
const Dec = p => '0n' + p.toString(10);
const ReadWstring = p => host.memory.readWideString(p);

function ReadShort(Address) {
    let Value = null;
    try {
        Value = host.memory.readMemoryValues(
           Address, 1, 2
        )[0];
    } catch(e) {
    }

    return Value;
}

function Is32BitOr64Bit(ptr) {
    var strNum = Hex(ptr);
    if (strNum.length-2 > 8) {
        return false;
    } else {
        return true;
    }
}

function ReadDword(Address) {
    let Value = null;
    try {
        Value = host.memory.readMemoryValues(
           Address, 1, 4
        )[0];
    } catch(e) {
    }

    return Value;
}

function ReadQword(Address) {
    let Value = null;
    try {
        Value = host.memory.readMemoryValues(
           Address, 1, 8
        )[0];
    } catch(e) {
    }

    return Value;
}

let ProcessIs64 = function() {
    let Is64Bit = true;
    try { host.createPointerObject(0, 'nt', '_KGDTENTRY64*'); } catch(e) { Is64Bit = false; }
    return Is64Bit;
}
 
let CallPrintf = function(frontfmtTxt= "", showTxt = "", execTxt = "", backfmtTxt = "")
{
    if(execTxt.length == 0)
        execTxt = showTxt;
     
    if(showTxt.length == 0)
        return;
 
    let cmd = ".printf /D \""+ frontfmtTxt +" <link cmd=\\\"" + execTxt + "\\\">" + showTxt + "</link> " + backfmtTxt +"\" ";
    host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd, false);
    Logln("");
}
 
function read_u8(addr) {
    return host.memory.readMemoryValues(addr, 1, 1)[0];
}
 
function read_u16(addr) {
    return host.memory.readMemoryValues(addr, 1, 2)[0];
}
 
function read_u32(addr) {
    return host.memory.readMemoryValues(addr, 1, 4)[0];
}

function read_handle(addr)
{
    return read_u16(addr);
}
 
function read_u64(addr) {
    return host.memory.readMemoryValues(addr, 1, 8)[0];
}

function read_addr_arch(addr)
{
    if(ProcessIs64()) {
        return read_u64(addr);
    } else {
        return read_u32(addr);
    }
}
 
function dbgtools()
{
    CallPrintf("#1. JavaScript plugin Contents:", "dbgtools", "dx Debugger.State.Scripts.dbgtools.Contents");
    CallPrintf("#2. Bind this JavaScripts to ", "@$dbgtool", "dx @$dbgtool = Debugger.State.Scripts.dbgtools.Contents");

    Logln("#3. Analyze Rpc Parameters:")
        CallPrintf("\t3.1. NdrClientCall2 Function:", "!NdrClientCall2()", "!NdrClientCall2", "");
        CallPrintf("\t3.2. NdrServerCall2 Function:", "!NdrServerCall2()", "!NdrServerCall2", "");
    
    Logln("#4. Analyze Consent Parameters,Support Function:");
        CallPrintf("\t4.1. Parameters Address:", "!consentparse(Address)", "!consentparse", "");
        CallPrintf("\t4.2. Function:", "AiLaunchProcess[x64]", "!consentparse", "");
        CallPrintf("\t4.3. Function:", "CuiGetTokenForApp[x64]", "!consentparse", "");

    CallPrintf("#5. Analyze class rpcss!CProcess:", "!CProcess(Address)", "!CProcess", "");
}
 
function initializeScript()
{
    Logln("dbgtools> JavaScript loaded!");
    Logln("dbgtools> Run !dbgtools show help");
 
    return [
            new host.apiVersionSupport(1, 9),
            new host.functionAlias(dbgtools, 'dbgtools'),
            new host.functionAlias(appinfo_SUT_CONSENTUI_PARAM_HEADER, 'consentparse'),
            new host.functionAlias(NdrClientCall2, 'NdrClientCall2'),
            new host.functionAlias(RpcInvoke, 'RpcInvoke'),
            new host.functionAlias(NdrServerCall2, 'NdrServerCall2'),
            new host.functionAlias(CProcess, 'CProcess')
        ];
}
 
function uninitializeScript()
{
    // Add code here that you want to run every time the script is unloaded.
    // We will just send a message to indicate that function was called.
    Logln("***> dbgtools JavaScript unloaded");
}

function eprocess_query_thread(EProcess, FindFunction)
{
    Logln(EProcess + " " + FindFunction);

    return;

    var ctl = host.namespace.Debugger.Utility.Control;

    var threadsinfo = ctl.ExecuteCommand();
    
    let threads = host.currentProcess.Threads;

    let hasConsent = false;
    for(const thd of threads) {
        const frames = thd.Stack.Frames;
        let bHasConsent = frames.Any (
            f => { 
                return f.toString().includes(FindFunction);
            }
        );

        if(bHasConsent)
        {
            var tid = thd.Id;;
            // dx -r1 @$RPC.host.currentProcess.Threads[3948]
            CallPrintf("", 
            "dx -r1 @$RPC.host.currentProcess.Threads[0x"+tid.toString(16)+"]",
            "",
            "")

            CallPrintf("", 
            "dx -r1 @$RPC.host.currentProcess.Threads[0x"+tid.toString(16)+"].Stack.Frames",
            "",
            "")

            break;
        }
    }
}

function CProcess(Addr) {
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
    let ctl = host.namespace.Debugger.Utility.Control;

    if(Addr != null) {
        ParseCProcess(Addr);
    }
    else {
        var cuiHeaderAddr = 0;
        if(breakpoint.toString().includes("!CBList::Insert")) {
            ParseCProcess(Regs.rdx);
        }
    }
}

let ParseCProcess = function(Addr) {
    var base = parseInt(Addr, 16);
    var offset = 0;
    var addr = base;

    Logln("CProcess:");

    offset = 8*0, addr = base+offset;
    var vftable = read_u64(addr);
    CallPrintf("\t[+"+Hex(offset)+"] vftable:", "dqs " + Hex(vftable),
        "", Hex(addr));

    offset = 8*3, addr = base+offset;
    var CToken = read_u64(addr);
    CallPrintf("\t[+"+Hex(offset)+"] CToken:", "dt CToken " + Hex(CToken),
        "", Hex(addr));

    offset = 8*4, addr = base+offset;
    var desktopInfo = read_u64(addr);
    var desktopInfoPath = ReadWstring(desktopInfo);
    CallPrintf("\t[+"+Hex(offset)+"] desktopInfo:",
        "du " + Hex(desktopInfo),
        "",
        Hex(addr));
        Logln("\t\t-->" + desktopInfoPath);

    offset = 8*13, addr = base+offset;
    var uuid = read_u64(addr);
    var desktopInfoPath = ReadWstring(desktopInfo);
    CallPrintf("\t[+"+Hex(offset)+"] uuid:",
        "dt _GUID " + Hex(addr),
        "",
        Hex(addr));
    
    offset = 8*15, addr = base+offset;
    var ClientProcess = read_u64(addr);
    CallPrintf("\t[+"+Hex(offset)+"] ClientProcess:", "!handle " + Hex(ClientProcess),
        "", Hex(addr));

    offset = 8*16, addr = base+offset;
    var lpfiletime = read_u64(addr);
    CallPrintf("\t[+"+Hex(offset)+"] lpFileTime:", "dt LPFILETIME " + Hex(addr),
        "", Hex(addr));

    offset = 8*48, addr = base+offset;
    var lpExePath = read_u64(addr);
    var ExePath = ReadWstring(lpExePath);
    CallPrintf("\t[+"+Hex(offset)+"] lpExePath:",  
        "du'" + Hex(lpExePath), 
        "",
        Hex(lpExePath));
        Logln("\t\t-->" + ExePath);

    offset = 8*51, addr = base+offset;
    var mid_stub_desc = read_u64(addr);
    CallPrintf("\t[+"+Hex(offset)+"] mid_stub_desc:",
        "dt __MIDL_ILocalObjectExporter_0001 " + Hex(mid_stub_desc),
        "", Hex(addr));


    offset = 8*107, addr = base+offset;
    var architecture = read_u32(addr);
    CallPrintf("\t[+"+Hex(offset)+"] architecture:",
        "dd architecture " + Dec(architecture) + " l1",
        "", Hex(addr));


}

function appinfo_query_consent_thread()
{
    var ctl = host.namespace.Debugger.Utility.Control;
    let threads = host.currentProcess.Threads;
    let hasConsent = false;
    for(const thd of threads) {
        const frames = thd.Stack.Frames;
        let bHasConsent = frames.Any(
            f => { 
                return f.toString().includes("RAiGetTokenForCOM") || 
                f.toString().includes("AipGetTokenForService") ||
                f.toString().includes("AiCheckLUA") || 
                f.toString().includes("AiLaunchConsentUI");
            }
        );

        if(bHasConsent)
        {
            var tid = thd.Id;;
            // dx -r1 @$RPC.host.currentProcess.Threads[3948]
            CallPrintf("", 
            "dx -r1 @$RPC.host.currentProcess.Threads[0x"+tid.toString(16)+"]",
            "",
            "")

            CallPrintf("", 
            "dx -r1 @$RPC.host.currentProcess.Threads[0x"+tid.toString(16)+"].Stack.Frames",
            "",
            "")

            break;
        }
    }
}

function RPCSS_connect() {
    Logln("rpcss_connect");
    let breakpoint = host.currentThread.Stack.Frames[0];
    if(false == breakpoint.toString().includes("rpcss!_Connect")) {
        return;
    }

    let Regs = host.currentThread.Registers.User;
    var ctl = host.namespace.Debugger.Utility.Control;

    var output = ctl.ExecuteCommand("dU @r8");
    var arry = Array.from(output);
    if(arry.length > 0) {
        if(output[0].toString().includes("consent.exe") == false) {
            ctl.ExecuteCommand("g",false);
            return;
        }
    }

    for(var line of output) {
        Logln("+" + line);
    }
}

// consent parameters
// !consentparam
let ParseCuiHeader = function(Addr)
{
    var base = parseInt(Addr, 16);
    var offset = 0;
    var addr = base;

    Logln("_CONSENTUI_PARAM_HEADER:")

    offset = 16*0.5, addr = base+offset;
    var nSecFlag = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] nSecFlag:", Hex(nSecFlag), "", Hex(addr));

    offset = 16*1, addr = base+offset;
    var nSecFlag1 = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] nSecFlag1:", Hex(nSecFlag1), "", Hex(addr));

    offset = 16*1, addr = base+offset;
    var hwnd = read_u64(addr);
    CallPrintf("  [+"+Hex(offset)+"] hwnd:", Hex(hwnd), "!handle " + Hex(hwnd), Hex(hwnd));

    offset = 16*1.5, addr = base+offset;
    var clientHd = read_handle(addr);
    CallPrintf("  [+"+Hex(offset)+"] rpcClientHd:", Hex(clientHd), "!handle " +  Hex(clientHd), Hex(clientHd));

    offset = 16*1+8, addr = base+offset;
    var Token = read_handle(addr);
    CallPrintf("  [+"+Hex(offset)+"] token:",  Hex(Token),"!handle " + Hex(Token), Hex(addr));

    offset = 16*2, addr = base+offset;
    var requestUacLevelError = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] requestUacLevelError:", Dec(requestUacLevelError), "", Hex(addr));
    
    offset = 16*2+8, addr = base+offset;
    var chidVal5 = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] chidVal5:", Hex(chidVal5), "", Hex(addr));

    offset = 16*3, addr = base+offset;
    var nConsentFlag = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] nConsentFlag:", Hex(nConsentFlag), "", Hex(addr));

    offset = 16*6, addr = base+offset;
    var lpGuid = (addr);
    CallPrintf("  [+"+Hex(offset)+"] lpGuid:", "dt _GUID " + Hex(lpGuid), "", Hex(addr));

    Logln("  -------");

    offset = 16*6, addr = base+offset;
    var ReBackHandle = read_handle(addr);
    CallPrintf("  [+"+Hex(offset)+"] ReBackHandle:", "!handle " + Hex(ReBackHandle), "", Hex(addr));

    {
        offset = 16*7;
        var comAddr = base+offset;
        var lpFriendlyName = ReadWstring(comAddr);
        CallPrintf("  [+"+Hex(comAddr-base)+"] lpFriendlyName:", "du " + Hex(comAddr)  , "", Hex(comAddr));
        Logln("    --> " + lpFriendlyName);

        offset = (lpFriendlyName.length + 1) * 2;
        comAddr += offset;
        var lpServerBinary = ReadWstring(comAddr);
        CallPrintf("  [+"+Hex(comAddr-base)+"] lpServerBinary: ", "du " + Hex(comAddr), "", Hex(comAddr));
        Logln("    --> " + lpServerBinary);

        offset = (lpServerBinary.length + 1) * 2;
        comAddr += offset;
        var lpIconReference = ReadWstring(comAddr);
        CallPrintf("  [+"+Hex(comAddr-base)+"] lpIconReference: ", "du " + Hex(comAddr), "", Hex(comAddr));
        Logln("    --> " + lpIconReference);
        
        offset = (lpIconReference.length + 1) * 2;
        comAddr += offset;
        var lpRequestorExePath = ReadWstring(comAddr);
        CallPrintf("  [+"+Hex(comAddr-base)+"] lpRequestorExePath: ", "du " + Hex(comAddr), "", Hex(comAddr));
        Logln("    --> " + lpRequestorExePath);
    }
    
    offset = 16*11, addr = base+offset;
    var dialogflag = read_u32(addr);
    CallPrintf("  [+"+Hex(offset)+"] dialogflag:", Hex(dialogflag), "", Hex(addr));
    
    offset = 16*12, addr = base+offset;
    var pEventHandle = read_handle(addr);
    CallPrintf("  [+"+Hex(offset)+"] pEventHandle:", "!handle " + Hex(pEventHandle), "", Hex(addr));
}

function appinfo_SUT_CONSENTUI_PARAM_HEADER(Addr)
{
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
    let ctl = host.namespace.Debugger.Utility.Control;

    if(Addr != null)
    {
        ParseCuiHeader(Addr);
    }
    else
    {
        var cuiHeaderAddr = 0;
        if(breakpoint.toString().includes("!AiLaunchProcess"))
        {
            let bufferAddr = Regs.rbp + 0x40;

            var bufferStr = ReadWstring(bufferAddr);
            Logln("ConsentUI Input Paras> " + bufferStr.toString());
            cuiHeaderAddr = bufferStr.split(' ')[3];
            CallPrintf("", "dd " + Hex(cuiHeaderAddr), "", "");
        }
        else if(breakpoint.toString().includes("!CuiGetTokenForApp"))
        {
            let bufferAddr = Regs.rdx;
            Logln("ConsentUI Input Paras> " + Hex(bufferAddr));
            cuiHeaderAddr = bufferAddr;
        }

        if(cuiHeaderAddr != 0)
        {
            ParseCuiHeader((cuiHeaderAddr));
        }
    }
}

function NdrServerCall2(midlAddr, bLog = false) {
    var ctl = host.namespace.Debugger.Utility.Control;
    let RPC_MESSAGE = 0;
    let PORT_MESSAGE = 0;
    
    var timeout = ctl.ExecuteCommand(".time");
    CallPrintf(timeout[0].split('time:')[1], "NdrServerCall2() Stack", "dx -r1 Debugger.State.Scripts.CodeFlow.Contents.host.currentThread.Stack.Frames", "");

    if(midlAddr != null)
    {
        RPC_MESSAGE = midlAddr;
    }
    else
    {
        var Regs = host.currentThread.Registers.User;
        bLog = false;
        let breakpoint = host.currentThread.Stack.Frames[0];
        if(breakpoint.toString().includes("NdrServerCall2")) {
        } else {
            Logln("No NdrServerCall2");
            return;
        }

        const Frames = Array.from(host.currentThread.Stack.Frames);
        for(const [Idx, Frame] of Frames.entries()) {
            // host.diagnostics.debugLog(">>> Stack Entry -> " + Idx + ":  " + Frame + " \n");
            if(breakpoint.toString().includes("NdrServerCall2")) {
                RPC_MESSAGE = Regs.rcx;
                PORT_MESSAGE = Regs.rbp;
            }
        }

        if(RPC_MESSAGE == 0) { 
            RPC_MESSAGE = Regs.rcx;
            PORT_MESSAGE = Regs.rbp;
        }
    }

    dealNdrServerCall2(RPC_MESSAGE, PORT_MESSAGE);
}

let dealNdrServerCall2 = function(RPC_MESSAGE, PORT_MESSAGE, bLog = false) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var CallInfo = "";

    if(RPC_MESSAGE) {
        ctl.ExecuteCommand("dt _RPC_MESSAGE "+ Hex(RPC_MESSAGE) ,false);
    }
    if(PORT_MESSAGE) {
        ctl.ExecuteCommand("dt _PORT_MESSAGE "+ Hex(PORT_MESSAGE) ,false);
        
        ctl.ExecuteCommand("dt _CLIENT_ID "+ Hex(PORT_MESSAGE+0x8) ,false);


    }

    // para1
    CallInfo += dealStub(RPC_MESSAGE+0x28, false);
 
    // para2
    CallInfo += read_u16(RPC_MESSAGE+0x1c);
 
    Logln("\t[RPC] GUID&Procederes:" + CallInfo);
}

// dx @$dbgtools = Debugger.State.Scripts.dbgtools.Contents
// dx @$dbgtools.NdrClientCall2()
// bu RPCRT4!Invoke+0x73-2d "u r10 l5;gc"
function RpcInvoke(bEnable)
{
    let ctl = host.namespace.Debugger.Utility.Control;
    if(bEnable) {
        ctl.ExecuteCommand(`bu RPCRT4!Invoke+0x73-2d ".echo 'rpcrt4!Invoke Function:'; r @r10; u r10 l5;gc"`)
    }
}

function NdrClientCall2(midlAddr, strAddr, bLog = true)
{
    var ctl = host.namespace.Debugger.Utility.Control;
    let _MIDL_STUB_DESC = 0;
    let lclor__MIDL_ProcFormatString = 0;

    if(host.currentProcess.Attributes.CommandLine.toString().includes("vmtoolsd.exe"))
    {
        ctl.ExecuteCommand("g");
        return;
    }

    // Logln("ProcessIs64:" + ProcessIs64());
    var timeout = ctl.ExecuteCommand(".time");
    CallPrintf(timeout[0].split('time:')[1], "NdrClientCall2() Stack", "dx -r1 Debugger.State.Scripts.CodeFlow.Contents.host.currentThread.Stack.Frames", "");

    if(midlAddr != null)
    {
        _MIDL_STUB_DESC = parseInt(midlAddr);
        lclor__MIDL_ProcFormatString = parseInt(strAddr);
    }
    else
    {
        var Regs = host.currentThread.Registers.User;
        bLog = false;
        let breakpoint = host.currentThread.Stack.Frames[0];
        if( false == breakpoint.toString().includes("NdrClientCall2") ) {
            if(breakpoint.toString().includes("NdrServerCall2")) {
            } else {
                Logln("No NdrClientCall2");
                return;
            }
        }

        if(false == host.currentProcess.Attributes.CommandLine.toString().includes("RPCSS")) {
            // return;
        }

        if(bLog == true) {
            host.diagnostics.debugLog(">>> Printing stack:");
            ctl.ExecuteCommand("k 4", false);
        }
        
        var ndr4Flag = false;
        var osc4Flag = false;
        var para1 = 0;
        var para2 = 0;

        const Frames = Array.from(host.currentThread.Stack.Frames);
        for(const [Idx, Frame] of Frames.entries()) {
            if(Frame.toString().includes("RPCRT4!NdrClientCall2+0x1f")) {
                var reqFun = Frames[Idx+1].toString().split('+');
                CallPrintf("\t[RPC] Request Function:" , Frames[2], "x " + reqFun[0]);
                break;
            }
        }

        for(const [Idx, Frame] of Frames.entries()) {
            // host.diagnostics.debugLog(">>> Stack Entry -> " + Idx + ":  " + Frame + " \n");
            if(Frame.toString().includes("RPCRT4!NdrClientCall4")) {
                var reqFun = Frames[2].toString().split('+');
                CallPrintf("\t[RPC] Request Function:" , Frames[2], "x " + reqFun[0]);
                para1 = Regs.ebp + 8;
                para2 = Regs.ebp + 12;
                _MIDL_STUB_DESC = read_u32(para1);
                lclor__MIDL_ProcFormatString = read_u32(para2);
                break;
            } else if (Frame.toString().includes("combase!Connect")) {
                para1 = Regs.rsi;
                para2 = Regs.rbp;
                _MIDL_STUB_DESC = (para1);
                lclor__MIDL_ProcFormatString = (para2);
                break;
            } else if (Frame.toString().includes("combase!ObjectStublessClient")) {
                if(ProcessIs64()) {
                    if(Frames[1].toString().includes("NdrClientCall4") == false) {
                        _MIDL_STUB_DESC = Regs.rcx;
                        lclor__MIDL_ProcFormatString = Regs.rdx;
                    } else {
                        para1 = Regs.eax;
                        para2 = Regs.ecx;
                        _MIDL_STUB_DESC = read_u32(para1);
                        lclor__MIDL_ProcFormatString = read_u32(para2);
                    }
                }
                else {
                    _MIDL_STUB_DESC = Regs.esp + 4;
                    lclor__MIDL_ProcFormatString = Regs.esp + 8;
                }
                break;
            } else if (Frame.toString().includes("combase!ServerAllocateOXIDAndOIDs")) {
                para1 = Regs.rdi;
                para2 = Regs.rsi;
                
                _MIDL_STUB_DESC = (para1);
                lclor__MIDL_ProcFormatString = (para2);
                break;
            } else if(breakpoint.toString().includes("NdrServerCall2")) {
                _MIDL_STUB_DESC = Regs.rcx + 0x28;
                break;
            }
        }
        
        if(_MIDL_STUB_DESC == 0) {
            para1 = Regs.rcx;
            para2 = Regs.rdx;
            
            _MIDL_STUB_DESC = (para1);
            lclor__MIDL_ProcFormatString = (para2);
        }
    
        if(bLog) {
            Logln("para1: 0x" + para1.toString(16));
            Logln("para2: 0x" + para2.toString(16));
        }
        
    }

    dealNdrClientCall2(bLog, _MIDL_STUB_DESC, lclor__MIDL_ProcFormatString);
     
    // ctl.ExecuteCommand("g");
}

let dealNdrClientCall2 = function(bLog, addr_stub, addr_fmtStr = 0) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var CallInfo = "";

    // para1
    CallInfo += dealStub(addr_stub);

    // para2
    CallInfo += dealFormat(addr_fmtStr);
 
    Logln("\t[RPC] GUID&Procederes:" + CallInfo);
}

let dealStub = function(addr_stub, bLogCaller = true, bLog = false) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var CallInfo = "";
    if(addr_stub != undefined) {
        // Logln("addr_stub:" + Hex(addr_stub));
        var addr_rpc_interface = Is32BitOr64Bit(addr_stub) ? read_u32(addr_stub) : read_u64(addr_stub);
        var RpcInterfaceInformation = read_u32(addr_rpc_interface);

        if(RpcInterfaceInformation == 0) {
            Logln("Empty RpcInterfaceInformation");
            ctl.ExecuteCommand("g;", false);
            return;
        }

        var addr_syntax_interface = addr_rpc_interface + 4;
        if(bLog) {
            CallPrintf("", "<Para1 pStubDescriptor>", "dt _MIDL_STUB_DESC " + Hex(addr_stub), "");
 
            CallPrintf("_MIDL_STUB_DESC \t\t",
                "pStubDescriptor",
                "dt _MIDL_STUB_DESC " + Hex(addr_stub),
                Hex(addr_stub));
            
            CallPrintf("RPC_CLIENT_INTERFACE \t",
                "pStubDescriptor.RpcInterfaceInformation",
                "dt RPC_CLIENT_INTERFACE " + Hex(addr_stub),
                Hex(addr_stub));
            
            CallPrintf("_RPC_SYNTAX_IDENTIFIER \t",
                "pStubDescriptor.RpcInterfaceInformation.InterfaceId",
                "dx -r1 (*((_RPC_SYNTAX_IDENTIFIER *)" + Hex(addr_syntax_interface) + "))",
                Hex(addr_syntax_interface));
        }

        var command = "dt _GUID " + Hex(addr_syntax_interface);

        // ctl.ExecuteCommand(command,false);
        var output = ctl.ExecuteCommand(command);
        
        var arry = Array.from(output);
        if(arry.length > 0) {
            CallInfo += output[1];
            if(CallInfo.toString().includes("00000000")) {
                Logln("Empty GUID");
            }
            CallInfo += ":";
        }

        if(bLogCaller) Logln("\t[RPC] Caller Info:\n\t\tName:"+host.currentProcess.Name 
            + "\n\t\tPID:"+ host.currentProcess.Id 
            + "\n\t\tCommand:"+host.currentProcess.Attributes.CommandLine);
        
        CallPrintf("\t[RPC]", 
        "GUID", command, "");
     } else {
        Logln("RpcInterfaceInformation(_MIDL_STUB_DESC) is NULL,Parameter is: ");
        CallPrintf("_MIDL_STUB_DESC \t\t",
        "pStubDescriptor",
        "dt combase!_MIDL_STUB_DESC 0x" + addr_stub.toString(16),
        "0x" + addr_stub.toString(16));
 
        // ctl.ExecuteCommand("g");
    }

    return CallInfo;
}

let dealFormat = function(addr_fmtStr, bLog = false) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var CallInfo = "";
    if(addr_fmtStr != 0) {
        var Format = addr_fmtStr;
        if(bLog) {
            CallPrintf("", "<Para2 pFormat>", "dt combase!lclor__MIDL_ProcFormatString 0x" + addr_fmtStr.toString(16), "");
            /*
                00 68 00 00 00 00 00 00-84 00 32 00 00 00 16 00
                handle_type = 0x00
                Oi_flags    = 0x0068
                rpc_flags   = 0x00000000
                proc_num    = 0x0000
                stack_size  = 0x0084
            */
    
            CallPrintf("combase!lclor__MIDL_ProcFormatString \t",
            "pFormat.Format",
            "dt combase!lclor__MIDL_ProcFormatString 0x" + Format.toString(16),
            "0x" + Format.toString(16));
        }
         
        var hand_type = read_u8(Format);
        Format += 1;
 
        var Oi_flags = read_u8(Format);
        Format += 1;
 
        var rpc_flags = read_u32(Format);
        Format += 4;
 
        var proc_num = read_u16(Format);
        Format += 2;
 
        var stack_size = read_u16(Format);
        if(bLog)
        {
            Logln("\t hand_type: 0x" + hand_type.toString(16));
            Logln("\t Oi_flags: 0x" + Oi_flags.toString(16));
            Logln("\t rpc_flags: 0x" + rpc_flags.toString(16));
            Logln("\t proc_num: 0x" + proc_num.toString(16));
            Logln("\t stack_size: 0x" + stack_size.toString(16));
        }

        CallInfo += proc_num.toString(10);
    } else {
            Logln("addr_fmtStr2:" + Hex(addr_fmtStr));
    }

    return CallInfo;
}