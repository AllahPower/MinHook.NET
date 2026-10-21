using System;
using System.Runtime.InteropServices;
using static MinHook.Trampoline;
using static MinHook.Utils;

namespace MinHook {
    internal sealed class Hook
    {
        public bool Enabled { get; private set; } = false;
        public bool QueueEnabled { get; private set; } = false;
        public IntPtr Original { get; private set; }
        internal IntPtr Target { get { return trampoline.Target; } }

        Trampoline trampoline;
        
        public Hook(IntPtr target, IntPtr detour, MemorySlot memorySlot) {
            trampoline = new Trampoline(target, detour, memorySlot);
            Original = trampoline.Tramp;
        }

        public void Enable(bool enable = true) {

            if (Enabled == enable) return;

            MemoryProtection oldProtect;
            int patchSize = RelativeJumpSize;
            IntPtr patchTarget = trampoline.Target;

            if (trampoline.PatchAbove) {
                patchTarget -= RelativeJumpSize;
                patchSize += ShortJumpSize;
            }

            JMPCALL_REL jmp = new JMPCALL_REL(0xE9);
            IntPtr destination = IntPtr.Size == 8 ? trampoline.Relay : trampoline.Detour;
            jmp.SetOperand(unchecked((uint)((long)destination - ((long)patchTarget + RelativeJumpSize))));
            JMP_REL_SHORT shortJmp = new JMP_REL_SHORT(0xEB, unchecked((byte)-(RelativeJumpSize + ShortJumpSize)));
            bool ownsPatch = enable
                ? NativeMemory.Equals(patchTarget, trampoline.Backup, patchSize)
                : NativeMemory.Equals(patchTarget, ref jmp) &&
                    (!trampoline.PatchAbove || NativeMemory.Equals(trampoline.Target, ref shortJmp));
            if (!ownsPatch) {
                throw new InvalidOperationException("Target bytes have changed. Remove newer hooks before changing this hook.");
            }

            if(!VirtualProtect(patchTarget, (UIntPtr)patchSize, MemoryProtection.ExecuteReadWrite, out oldProtect)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to change memory protection");
            }

            if (enable) {

                NativeMemory.Write(patchTarget, ref jmp);

                if (trampoline.PatchAbove) {
                    NativeMemory.Write(trampoline.Target, ref shortJmp);
                }
            } else {

                NativeMemory.Restore(patchTarget, trampoline.Backup, patchSize);
            }

            Enabled = enable;
            bool protectionRestored = VirtualProtect(patchTarget, (UIntPtr)patchSize, oldProtect, out _);
            int protectionError = protectionRestored ? 0 : Marshal.GetLastWin32Error();
            bool cacheFlushed = FlushInstructionCache((IntPtr)(-1), patchTarget, (UIntPtr)patchSize);
            if (!protectionRestored) throw new System.ComponentModel.Win32Exception(protectionError, "Failed to restore memory protection");
            if (!cacheFlushed) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Failed to flush instruction cache");
        }
    }
}
