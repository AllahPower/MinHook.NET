# MinHook.NET

## Introduction

MinHook.NET is a pure managed C# port of the brilliant MinHook library by Tsuda Kageyu (https://github.com/TsudaKageyu/minhook).  The library has the capability of inline hooking native API calls, utilising .NET delegates for both the detoured and original function that is commonly called with the detour.

The project has attempted to keep within the simplistic spirit of the original MinHook library.

## Quick Start

Simple example demonstrating the hooking of the MessageBoxW Windows API

```c#
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int MessageBoxW(IntPtr hWnd, String text, String caption, uint type);

    //We need to declare a delegate that matches the prototype of the hooked function
    [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]
    delegate int MessageBoxWDelegate(IntPtr hWnd, string text, string caption, uint type);

    //A variable to store the original function so that we can call
    //within our detoured MessageBoxW handler
    MessageBoxWDelegate MessageBoxW_orig;

    //Our actual detour handler function
    int MessageBoxW_Detour(IntPtr hWnd, string text, string caption, uint type) {
        return MessageBoxW_orig(hWnd, "HOOKED: " + text, caption, type);
    }

    void ChangeMessageBoxMessage() {

		using (HookEngine engine = new HookEngine()) {

			MessageBoxW_orig = engine.CreateHook("user32.dll", "MessageBoxW", new MessageBoxWDelegate(MessageBoxW_Detour));
			engine.EnableHooks();

			//Call the PInvoke import to test our hook is in place
			MessageBoxW(IntPtr.Zero, "Text", "Caption", 0);
		}
    }
```

## Native Hook Safety

Keep the engine alive for as long as any detour or original delegate can be called.
Stop callers and wait for in-flight calls to finish before disposing the engine.
Disabling an inline patch is not a callback-draining mechanism. A delegate returned
by `CreateHook` is invalid after its owning engine is disposed.

Layers created by one engine are disabled in reverse creation order. Disabling an
older layer while another engine or library owns the current patch is rejected
without modifying the newer patch. Remove the newer layer first, then retry.
Changes while a managed debugger is attached are rejected rather than silently
patching running threads without suspension.

Thread instruction pointers are not yet redirected when they point inside a
patched prologue or trampoline. Concurrent patching and disposal therefore still
require a separate thread-context fix; this branch does not claim to solve it.
The managed suspension path also does not establish a process-wide GC-safe
critical section or synchronize independent engines.

## Regression Tests

The native regression suite uses xUnit v3 and Windows executable-memory fixtures.
No game process, UI dialog, or external native binary is required. Run both process
architectures with matching dotnet hosts:

```powershell
dotnet build tests/MinHook.NET.Tests/MinHook.NET.Tests.csproj -c Release -p:TargetFrameworks=net9.0 -p:PlatformTarget=x64 -p:GeneratePackageOnBuild=false
dotnet tests/MinHook.NET.Tests/bin/x64/Release/net9.0/MinHook.NET.Tests.dll
dotnet build tests/MinHook.NET.Tests/MinHook.NET.Tests.csproj -c Release -p:TargetFrameworks=net9.0 -p:PlatformTarget=x86 -p:GeneratePackageOnBuild=false
& "${env:ProgramFiles(x86)}/dotnet/dotnet.exe" tests/MinHook.NET.Tests/bin/x86/Release/net9.0/MinHook.NET.Tests.dll
```

The allocation test covers warmed-up patch/restore operations, not hook creation
or process-thread enumeration. Instruction encodings use stack buffers and typed
native writes: MemoryMarshal on .NET and .NET Standard, fixed pointers on .NET
Framework. No runtime fallback or new library package dependency is introduced.

## TODO

* When enabling hooks, enumerate threads and update thread context if any are running at the hook instructions that are being patched
* Redirect thread instruction pointers when disabling hooks before freeing trampolines
* Add concurrent native-worker stress tests in isolated child processes

## Thanks

* The original MinHook library that this project is based on - https://github.com/TsudaKageyu/minhook
* The SharpDisasm project and Udis86 disassembler that the project is ported from -  https://github.com/spazzarama/SharpDisasm
