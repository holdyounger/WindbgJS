"use strict";

//
// Utility functions.
//

const Log = host.diagnostics.debugLog;
const Logln = p => host.diagnostics.debugLog(p + '\n');
const Hex = p => '0x' + p.toString(16);
const Dec = p => '0n' + p.toString(10);

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
    CallPrintf("#1. JavaScript plugin Template:", "CodeFlow", "dx Debugger.State.Scripts.CodeFlow.Contents");
}
 
function initializeScript()
{
    Logln("template> JavaScript loaded!");
    Logln("template> Run !template show help");
 
    return [
            new host.apiVersionSupport(1, 9),
            new host.functionAlias(template, 'template'),
            new host.functionAlias(SearchString, 'SearchString')
        ];
}
 
function uninitializeScript()
{
    // Add code here that you want to run every time the script is unloaded.
    // We will just send a message to indicate that function was called.
    Logln("***> template JavaScript unloaded");
}

function searchMemory(startAddress, length, str, isUnicode) {

    if(length > 0x5000) {
        return
    }

    const command = isUnicode ? `s -u ${startAddress} L${length} "${str}"` : `s -a ${startAddress} L${length} "${str}"`;

    // Logln("[Search] command:" + command);

    const output = host.namespace.Debugger.Utility.Control.ExecuteCommand(command, false);
}

/*
    let breakpoint = host.currentThread.Stack.Frames[0];
    let Regs = host.currentThread.Registers.User;
*/
//dx -r1 Debugger.State.Scripts.CodeFlow.Contents.host.currentProcess.Memory.ManagedHeap
function SearchString(str) {
    Logln("Input:"+str);

    let ctl = host.namespace.Debugger.Utility.Control;
    var output = ctl.ExecuteCommand("!address"); // -c:\".echo %1 %3 %5\"
    // var output = ctl.ExecuteCommand("!address -f:PAGE_EXECUTE_READWRITE "); // -c:\".echo %1 %3 %5\"

    var array = output.ToArray();
    for(var line of array) {
        // Logln(line);
        if(line.toString().includes("MEM_")) {
            var simpleStr = line.toString().replace("+ ", "").trimStart().replace(/\s+/g, ' ');
            var memInfo = simpleStr.toString().split(" ");
            
            if(0) {
                var idx = 0;
                for (var value of memInfo) {
                    Logln(idx + "," + value);
                    idx += 1;
                }
            }
            // return;
            // Logln("memInfo:" + "0x"+memInfo[0] + "0x"+memInfo[2]);

            // 调用搜索内存函数 
            const results = searchMemory("0x"+memInfo[0], "0x"+memInfo[2], str, true);
        }
    }
}