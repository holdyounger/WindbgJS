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
 
function SearchModuleHelp()
{
    CallPrintf("#1. JavaScript plugin SearchModule:", "CodeFlow", "dx Debugger.State.Scripts.CodeFlow.Contents");
}

function ListAllProcess()
{
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
    let ctl = host.namespace.Debugger.Utility.Control;
    

    var processes = [];
    var currentProcess = null;
    var processInfoText = ctl.ExecuteCommand('!process 0 0');
    // Logln(processInfoText)
    const pList = Array.from(processInfoText);
    for(var line of processInfoText) {
        // Logln(line);
        var line = line.trim();
        if (line.startsWith("PROCESS")) {
            // 解析出进程ID
            var processId = line.toString().split(' ')[1];
            currentProcess = {
                id: processId,
                name: ""
            };
            processes.push(currentProcess);
        } else if (line.includes("Image:")) {
            // 解析出进程名
            var name = line.toString().split(' ')[1];
            // Logln("name:" + name);
            currentProcess.name = name;
        }
    }
    return processes;
}
 
function SearchModule(ModuleName)
{
    let ctl = host.namespace.Debugger.Utility.Control;
    var processList = [""];
    var parsedProcesses = ListAllProcess();
    for (var i = 0; i < parsedProcesses.length; i++) {
        var process = parsedProcesses[i];
        // Logln("Process ID: " + process.id + ", Process Name: " + process.name + "\n");
        if(!processList.includes(process.name))
            processList.push(process.name);
    }

    for (var i = 0; i < processList.length; i++) {
        Logln(i + " " + processList[i]);
        var findRet= ctl.ExecuteCommand("!process /m " +  ModuleName + " 0 0 " + processList[i]);
        if(findRet)
        {
            Logln("Find Module, Target process is" + processList[i]);
            break;
        }

    }
}
 
function initializeScript()
{
    Logln("SearchModule> JavaScript loaded!");
    Logln("SearchModule> Run !SearchModule show help");
 
    return [
            new host.apiVersionSupport(1, 9),
            new host.functionAlias(SearchModuleHelp, 'SearchModuleHelp'),
            new host.functionAlias(SearchModule, 'SearchModule'),
        ];
}
 
function uninitializeScript()
{
    // Add code here that you want to run every time the script is unloaded.
    // We will just send a message to indicate that function was called.
    Logln("***> SearchModule JavaScript unloaded");
}

