using System;
using System.Runtime.InteropServices;

namespace UserDataPermissions
{
    /// <summary>
    /// from http://blog.salamandersoft.co.uk/index.php/2009/10/setting-the-owner-of-files-and-directories-in-c/
    /// </summary>
    sealed class UnmanagedCode
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr tokenHandle,
            [MarshalAs(UnmanagedType.Bool)]bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState,
            UInt32 bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        static extern bool OpenProcessToken
            (IntPtr processHandle, int desiredAccess, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue
                (string host, string name, ref LUID lpLuid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        const int SE_PRIVILEGE_ENABLED = 0x00000002;
        const int TOKEN_QUERY = 0x00000008;
        const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        //http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
        const string SE_RESTORE_PRIVILEGE = "SeRestorePrivilege";

        public static void GiveRestorePrivilege()
        {
            TOKEN_PRIVILEGES tokenPrivileges;
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Luid = new LUID();
            tokenPrivileges.Attributes = SE_PRIVILEGE_ENABLED;

            IntPtr tokenHandle = RetrieveProcessToken();

            try
            {
                bool success = LookupPrivilegeValue
                            (null, SE_RESTORE_PRIVILEGE, ref tokenPrivileges.Luid);
                if (success == false)
                {
                    int lastError = Marshal.GetLastWin32Error();
                    throw new Exception(
                        string.Format("Could not find privilege {0}. Error {1}",
                                            SE_RESTORE_PRIVILEGE, lastError));
                }

                success = AdjustTokenPrivileges(
                                                    tokenHandle, false,
                                                    ref tokenPrivileges, 0,
                                                    IntPtr.Zero, IntPtr.Zero);
                if (success == false)
                {
                    int lastError = Marshal.GetLastWin32Error();
                    throw new Exception(
                        string.Format("Could not assign privilege {0}. Error {1}",
                                        SE_RESTORE_PRIVILEGE, lastError));
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }       

        static IntPtr RetrieveProcessToken()
        {
            IntPtr processHandle = GetCurrentProcess();
            IntPtr tokenHandle = IntPtr.Zero;
            bool success = OpenProcessToken(processHandle,
                                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                            ref tokenHandle);
            if (success == false)
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Exception(
                    string.Format("Could not retrieve process token. Error {0}",
                                        lastError));
            }
            return tokenHandle;
        }
    }
}
