@echo off
setlocal enabledelayedexpansion

echo 开始工作，当前目录为: %cd%

REM 创建一个临时文件夹，用于测试权限
set "testFolder=C:\Windows\System32\AdminTest1"

REM 尝试创建一个文件夹
mkdir "%testFolder%" 2>nul

REM 检查是否成功创建
if exist "%testFolder%" (
    rmdir "%testFolder%"
) else (
    echo 当前进程没有管理员权限,结束运行
	pause
	goto:eof
)

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "DEL=%%a"
)

:start

:: 提示用户选择
call :ColorText 02 "请选择一个选项："
echo.
echo 1: 网络调试
echo 2: 串口调试
echo 3: 退出

:: 使用 choice 命令获取用户输入
choice /C 123 /M "请输入你的选择:"

set USER_CHOICE=%ERRORLEVEL%

:: 根据用户选择执行不同的处理逻辑
if "%USER_CHOICE%"=="1" (
    echo 你选择了选项1
    rem 在这里添加选项1的处理逻辑
	bcdedit.exe -set TESTSIGNING ON
	bcdedit.exe -set loadoptions DDISABLE_INTEGRITY_CHECKS
	bcdedit /set nointegritychecks on
	bcdedit /debug on
	bcdedit /bootdebug on
	rem 输入ip
	set /p InputIp="请输入调试主机IP地址:"
	echo 输入IP为:!InputIp!
	rem 输入调试端口
	set /P InputPort="请输入调式端口地址:"
	echo 输入端口为:!InputPort!
	bcdedit /dbgsettings net hostip:!InputIp! port:!InputPort!
	echo 请手动配置总线编号、设备编号和功能编号
	bcdedit
	pause
	goto:eof
)

if "%USER_CHOICE%"=="2" (
	echo test1
    call :ColorText 0b "开始配置串口调试："
	bcdedit /set testsigning on
	rem 启动
	bcdedit /debug on
	rem 永久禁用数字签名
	bcdedit.exe /set nointegritychecks on
)

if "%USER_CHOICE%"=="3" (
    echo 你选择了退出
    exit
)

:: 参数1为空情况下打印提示
if "%~1"=="" (
	call :ColorText 0C "[Error]没有提供参数1"
	echo.
	
	call :UsagePrint
	echo.
	
	goto:eof
)

goto:eof

:UsagePrint
	call :ColorText 02 "[Usage]:"
	echo.

	call :ColorText 02 "    %~nx0 [OutputDir] [ui version]"
	echo.
goto:eof

:: call :ColorText 0C "red"
:: call :ColorText 0b "blue"
:: call :ColorText 02 "green"
:: call :ColorText 19 "yellow"
:: call :ColorText 2F "black"
:: call :ColorText 4e "white"
:ColorText
@echo off
:: 移除冒号
set "input=%~2"
set "input=!input::=：!"
<nul set /p ".=%DEL%" > "!input!"
findstr /v /a:%1 /R "^$" "!input!" nul
del "!input!" > nul 2>&1
goto :eof

pause