"use strict";

//
// Utility functions.
//

const Log = host.diagnostics.debugLog;
const Logln = p => host.diagnostics.debugLog(p + '\n');
const Hex = p => '0x' + p.toString(16);
const Dec = p => '0n' + p.toString(10);


/*
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
    let ctl = host.namespace.Debugger.Utility.Control;
*/
function ReadWstring(Address) {
    let Value = null;
    try {
        Value = host.memory.readWideString(Address);
    } catch(e) {
        return "";
    }
    return Value;
}

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
    try {
        return host.memory.readMemoryValues(addr, 1, 4)[0];
    } catch (e){ return 0; }
}

function read_handle(addr)
{
    try {return read_u16(addr);} catch(e) {return 0;}
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
 
function template()
{
    CallPrintf("#1. JavaScript plugin Template:", "CodeFlow", "dx Debugger.State.Scripts.dbgtools.Contents");
}
 
function initializeScript()
{
    Logln("template> JavaScript loaded!");
    Logln("template> Run !template show help");
 
    return [
            new host.apiVersionSupport(1, 9),
            new host.functionAlias(template, 'template'),
            new host.functionAlias(FindNTWrite, 'NtWriteVirtualMemory'),
            new host.functionAlias(stopin360tray, 'stopin360tray'),
            new host.functionAlias(queryStringInAddress, 'qs'),
        ];
}
 
function uninitializeScript()
{
    // Add code here that you want to run every time the script is unloaded.
    // We will just send a message to indicate that function was called.
    Logln("***> template JavaScript unloaded");
}

function extractObjectValue(output) {
    // 正则表达式匹配 Object: 后面的十六进制地址
    var strInput = output.toString();
    for (var line of output) {
        var regex = /Object: (\w+)/;
        var match = line.match(regex);
        if (match) {
            return match[1];
        }
    }
    return null;
}

function extractImageValue(output) {
    // 正则表达式匹配 Object: 后面的十六进制地址
    var strInput = output.toString();
    for (var line of output) {
        var regex = /Image: (\w+\.exe)/;
        var match = line.match(regex);
        if (match) {
            return match[1];
        }
    }
    return null;
}



function extractTimeValue(output) {
    // 正则表达式匹配 Object: 后面的十六进制地址
    var strInput = output.toString();
    for (var line of output) {
        var regex = /time: (\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d{3} \d{4})/;
        var match = line.match(regex);
        if (match) {
            return match[1];
        }
    }
    return null;
}

function FindNTWrite() {
    // host.namespace.Debugger.State.DebuggerVariables.curregisters.User
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
    let ctl = host.namespace.Debugger.Utility.Control;
    var ProInfo = "";

    // var time = ctl.ExecuteCommand(".time");
    // ProInfo = (extractTimeValue(time));
    ProInfo += "[ProcessInfo] ";

    var output = ctl.ExecuteCommand(`!handle ${Regs.rcx}`);
    var objectValue = extractObjectValue(output);
    if(objectValue) {
        ProInfo += objectValue;
        var processOP = ctl.ExecuteCommand(`!process 0x${objectValue} 0`);
        var processName = extractImageValue(processOP);
        if(false == processOP.toString().includes("Chanjet.TP.WebServer.FastCGI.exe")) {
            ProInfo += ` ${processName}`;
            Logln(ProInfo);
            ctl.ExecuteCommand("g");
            return;
        } else {
            ProInfo += `[[[[ ${processName} ]]]]`;
            Logln(ProInfo);
        }
    }
}

function stopin360tray(eprocess) {
    Logln(eprocess);
    var ctl = host.namespace.Debugger.Utility.Control;
    var output = ctl.ExecuteCommand(".process");
    for (var line of output) {
        Logln("LINE:" + line.toString());
        if(line.toString().includes(eprocess.toString())) {
            Logln("---> FIND <---" + line.toString());
        } else {
            ctl.ExecuteCommand("gc", false);
            return;
        }
    }

}


function queryStringInAddress() {
    let Regs1 = host.namespace.Debugger.State.DebuggerVariables.curregisters.User;
    let ctl = host.namespace.Debugger.Utility.Control;

    var strAddr = Regs.esp;
    Logln("esp:" + Hex(strAddr));
}

function SeePara1() {
    
}