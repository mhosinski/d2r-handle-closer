// Program.cs
// Target: net8.0-windows, x64, UseWindowsForms=true
// Run elevated (either via manifest or "Run as administrator")

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Collections.Generic;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayContext());
    }
}

public sealed class TrayContext : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly HandleKiller _killer = new HandleKiller();

    private bool _enabled = true; // start enabled
    private readonly ToolStripMenuItem _toggleMenuItem;

    public TrayContext()
    {
        var menu = new ContextMenuStrip();

        _toggleMenuItem = new ToolStripMenuItem("Stop monitoring");
        _toggleMenuItem.Click += (_, __) => ToggleMonitoring();

        var exit = new ToolStripMenuItem("Exit");
        exit.Click += (_, __) => ExitThread();

        menu.Items.Add(_toggleMenuItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _tray = new NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Visible = true,
            Text = "D2R Handle Closer",
            ContextMenuStrip = menu
        };

        _timer = new System.Windows.Forms.Timer { Interval = 3000 };
        _timer.Tick += OnTick;
        _timer.Start();
    }

    private void ToggleMonitoring()
    {
        _enabled = !_enabled;
        _toggleMenuItem.Text = _enabled ? "Stop monitoring" : "Start monitoring";
        _tray.Text = _enabled ? "D2R Handle Closer (On)" : "D2R Handle Closer (Off)";
    }

    private void OnTick(object? sender, EventArgs e)
    {
        if (!_enabled) return;

        try
        {
            int closed = _killer.CloseNamedEventHandlesInProcess(
                "D2R.exe",
                @"\Sessions\1\BaseNamedObjects\DiabloII Check For Other Instances");

            if (closed > 0 && _tray != null && _tray.Visible)
            {
                _tray.BalloonTipTitle = "D2R Handle Closer";
                _tray.BalloonTipText = $"Closed {closed} matching handle(s).";
                _tray.ShowBalloonTip(2000);
            }
        }
        catch (Win32Exception wex)
        {
            Debug.WriteLine($"Win32 error: {wex.Message}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex);
        }
    }

    protected override void ExitThreadCore()
    {
        try { _timer?.Stop(); } catch { /* ignore */ }
        if (_tray != null)
        {
            _tray.Visible = false;
            _tray.Dispose();
        }
        base.ExitThreadCore();
    }
}

internal sealed class HandleKiller
{
    // --- NT & Win32 interop ---

    private const int SystemExtendedHandleInformation = 64; // From community usage (e.g., Process Hacker)
    private const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;

    private enum OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2,
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryObject(
        IntPtr Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        IntPtr ObjectInformation,
        int ObjectInformationLength,
        out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;            // PVOID
        public IntPtr UniqueProcessId;   // HANDLE (actually PID)
        public IntPtr HandleValue;       // HANDLE
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_INFORMATION_EX
    {
        public IntPtr NumberOfHandles; // ULONG_PTR
        public IntPtr Reserved;
        // Followed by SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[NumberOfHandles]
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;        // bytes
        public ushort MaximumLength; // bytes
        public IntPtr Buffer;        // PWSTR
    }

    public int CloseNamedEventHandlesInProcess(string processName, string exactObjectName)
    {
        HashSet<int> pids = Process
            .GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(processName))
            .Select(p => p.Id)
            .ToHashSet();

        if (pids.Count == 0) return 0;

        var handles = GetAllSystemHandles();
        if (handles.Length == 0) return 0;

        int closedCount = 0;

        foreach (var h in handles)
        {
            int pid = (int)h.UniqueProcessId;
            if (!pids.Contains(pid))
                continue;

            IntPtr hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
                continue;

            try
            {
                // Duplicate to our process first to query its name
                if (!DuplicateHandle(hProcess, h.HandleValue, Process.GetCurrentProcess().Handle,
                                     out IntPtr localHandle, 0, false, DUPLICATE_SAME_ACCESS))
                {
                    continue;
                }

                string? name = null;
                try
                {
                    name = QueryObjectName(localHandle);
                }
                finally
                {
                    if (localHandle != IntPtr.Zero) CloseHandle(localHandle);
                }

                if (string.IsNullOrEmpty(name))
                    continue;

                if (string.Equals(name, exactObjectName, StringComparison.Ordinal))
                {
                    // Close in source process
                    if (DuplicateHandle(hProcess, h.HandleValue, Process.GetCurrentProcess().Handle,
                                        out IntPtr dummy, 0, false, DUPLICATE_CLOSE_SOURCE))
                    {
                        if (dummy != IntPtr.Zero) CloseHandle(dummy);
                        closedCount++;
                    }
                }
            }
            finally
            {
                if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            }
        }

        return closedCount;
    }

    private SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[] GetAllSystemHandles()
    {
        int len = 0x10000;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(len);
                int ret = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, len, out int needed);
                if (ret == 0) // STATUS_SUCCESS
                    break;

                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                // STATUS_INFO_LENGTH_MISMATCH
                if (ret == unchecked((int)0xC0000004))
                {
                    len = Math.Max(len * 2, needed);
                    continue;
                }

                throw new Win32Exception($"NtQuerySystemInformation failed with 0x{ret:X8}");
            }

            var header = Marshal.PtrToStructure<SYSTEM_HANDLE_INFORMATION_EX>(buffer);
            long count = header.NumberOfHandles.ToInt64();

            IntPtr firstEntry = IntPtr.Add(buffer, Marshal.SizeOf<SYSTEM_HANDLE_INFORMATION_EX>());
            var entries = new SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[count];

            int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            for (long i = 0; i < count; i++)
            {
                IntPtr entryPtr = IntPtr.Add(firstEntry, checked((int)(i * entrySize)));
                entries[i] = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);
            }
            return entries;
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }

    private string? QueryObjectName(IntPtr handle)
    {
        int len = 0x1000;
        IntPtr buffer = IntPtr.Zero;

        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(len);
                int ret = NtQueryObject(handle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, buffer, len, out int needed);
                if (ret == 0) // STATUS_SUCCESS
                    break;

                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;

                // STATUS_BUFFER_OVERFLOW or STATUS_INFO_LENGTH_MISMATCH
                if (ret == unchecked((int)0x80000005) || ret == unchecked((int)0xC0000004))
                {
                    len = Math.Max(len * 2, needed);
                    continue;
                }

                return null;
            }

            UNICODE_STRING us = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return null;

            int charCount = us.Length / 2;
            return Marshal.PtrToStringUni(us.Buffer, charCount);
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }
    }
}
