using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    public sealed class HookEngine : IDisposable {

        MemoryAllocator memoryAllocator = new MemoryAllocator();
        Dictionary<Delegate, Hook> originalHookMapping = new Dictionary<Delegate, Hook>();
        Dictionary<Delegate, Hook> detourHookMapping = new Dictionary<Delegate, Hook>();
        List<IntPtr> suspendedThreads = new List<IntPtr>();
        // Dictionary enumeration order is not guaranteed on .NET Framework.
        readonly List<Hook> hooksInCreationOrder = new List<Hook>();
        bool disposed;
        int suspendedThreadCount;

        public Func CreateHook<Func>(string dll, string function, Func detour) where Func : Delegate {

            IntPtr target = GetProcAddress(GetModuleHandle(dll), function);

            if (target == IntPtr.Zero)
                throw new EntryPointNotFoundException($"Function {function} could not be found in DLL {dll}");

            return CreateHook<Func>(target, detour); 
        }

        public Func CreateHook<Func>(IntPtr target, Func detour) where Func : Delegate {

            if(target == IntPtr.Zero || detour == null) {
                throw new ArgumentException($"target or detour cannot be null");
            }

            lock (this) {
                ThrowIfDisposed();
                if (detourHookMapping.ContainsKey(detour)) throw new ArgumentException("Detour is already registered", nameof(detour));
                MemorySlot slot = memoryAllocator.AllocateBuffer(target);
                try {
                    var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), slot);
                    Func original = (Func)Marshal.GetDelegateForFunctionPointer(hook.Original, typeof(Func));
                    originalHookMapping.Add(original, hook);
                    try {
                        detourHookMapping.Add(detour, hook);
                        hooksInCreationOrder.Add(hook);
                    } catch {
                        originalHookMapping.Remove(original);
                        detourHookMapping.Remove(detour);
                        throw;
                    }
                    return original;
                } catch {
                    memoryAllocator.FreeBuffer(slot);
                    throw;
                }
            }
        }

        public void EnableHooks() {
            lock (this) {
                ThrowIfDisposed();
                foreach (Hook hook in hooksInCreationOrder) SetHookState(hook, true);
            }
        }

        public void DisableHooks() {
            lock (this) {
                ThrowIfDisposed();
                for (int i = hooksInCreationOrder.Count - 1; i >= 0; i--) SetHookState(hooksInCreationOrder[i], false);
            }
        }

        public void EnableHook(Delegate original) {
            lock (this) {
                ThrowIfDisposed();
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SetHookState(originalHookMapping[original], true);
            }
        }

        public void DisableHook(Delegate original) {
            lock (this) {
                ThrowIfDisposed();
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SetHookState(originalHookMapping[original], false);
            }
        }

        void SetHookState(Hook hook, bool enable) {
            if (hook.Enabled == enable) return;
            try {
                SuspendThreads();
                hook.Enable(enable);
            } finally {
                ResumeThreads();
            }
        }

        void ThrowIfDisposed() {
            if (disposed) throw new ObjectDisposedException(nameof(HookEngine));
        }

        void SuspendThreads() {

            //Suspending all threads when debugging causes deadlocks.
            if (Debugger.IsAttached) {
                throw new NotSupportedException("Changing hooks while a managed debugger is attached is not supported.");
            }

            //TODO: Currently doesn't move thread IP if any of the threads
            //are executing within the location of a hook prologue at the time.
            //This will probably crash the program if that scenario happens (rare)

            // Finish managed enumeration and buffer growth before suspending any thread.
            using (Process currentProc = Process.GetCurrentProcess()) {
                foreach (ProcessThread thread in currentProc.Threads) {
                    using (thread) {
                        if (thread.Id == GetCurrentThreadId()) continue;
                        IntPtr handle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                        if (handle == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                        try { suspendedThreads.Add(handle); }
                        catch { CloseHandle(handle); throw; }
                    }
                }
            }
            while (suspendedThreadCount < suspendedThreads.Count) {
                if (SuspendThread(suspendedThreads[suspendedThreadCount]) == -1) {
                    int error = Marshal.GetLastWin32Error();
                    ResumeThreads();
                    throw new System.ComponentModel.Win32Exception(error);
                }
                suspendedThreadCount++;
            }
        }

        void ResumeThreads() {

            int error = 0;
            for (int i = 0; i < suspendedThreadCount; i++) {
                if (ResumeThread(suspendedThreads[i]) == uint.MaxValue && error == 0) error = Marshal.GetLastWin32Error();
            }
            suspendedThreadCount = 0;
            foreach (IntPtr handle in suspendedThreads) {
                if (!CloseHandle(handle) && error == 0) error = Marshal.GetLastWin32Error();
            }
            suspendedThreads.Clear();
            if (error != 0) throw new System.ComponentModel.Win32Exception(error);
        }

        public void Dispose() {
            lock (this) {
                if (disposed) return;
                DisableHooks();
                memoryAllocator.Dispose();
                originalHookMapping.Clear();
                detourHookMapping.Clear();
                hooksInCreationOrder.Clear();
                disposed = true;
                GC.SuppressFinalize(this);
            }
        }
    }
}
