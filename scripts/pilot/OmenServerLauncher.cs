using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

internal static class Launcher
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        try
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            try
            {
                using (var stream = typeof(Launcher).Assembly.GetManifestResourceStream("workspace"))
                {
                    if (stream != null)
                    {
                        using (var reader = new StreamReader(stream))
                        {
                            string embedded = reader.ReadToEnd().Trim();
                            if (!string.IsNullOrEmpty(embedded) && Directory.Exists(embedded) &&
                                File.Exists(Path.Combine(embedded, "scripts", "pilot", "Start-Omen-College-Pilot.ps1")))
                            {
                                root = embedded;
                            }
                        }
                    }
                }
            }
            catch { }
#if RAVENX_RELEASE
            VerifyReleaseHome(root);
#endif
            Application.Run(new LauncherForm(root));
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "RAVEN-X Server", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static void VerifyReleaseHome(string root)
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\');
        string full = Path.GetFullPath(root).TrimEnd('\\');
        if (!full.StartsWith(programFiles + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Extract the verified server ZIP into a protected folder under Program Files.");
        var trusted = new[] { "S-1-3-0", "S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" };
        const int writeMask = 0x100D0156 | 0x40000000;
        Action<string> check = path =>
        {
            FileAttributes attributes = File.GetAttributes(path);
            FileSystemSecurity acl = (attributes & FileAttributes.Directory) != 0
                ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                !trusted.Contains(acl.GetOwner(typeof(SecurityIdentifier)).Value) ||
                acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(rule =>
                    rule.AccessControlType == AccessControlType.Allow && !trusted.Contains(rule.IdentityReference.Value) &&
                    ((int)rule.FileSystemRights & writeMask) != 0))
                throw new InvalidOperationException("The release directory must be owned and writable only by trusted Windows administrators.");
        };
        for (string current = full; ; current = Path.GetDirectoryName(current))
        {
            check(current);
            if (String.Equals(current, programFiles, StringComparison.OrdinalIgnoreCase)) break;
        }
        string scripts = Path.Combine(full, "scripts");
        check(scripts);
        check(Path.Combine(scripts, "pilot"));
        check(Path.Combine(scripts, "pilot", "Start-Omen-College-Pilot.ps1"));
        check(Path.Combine(scripts, "pilot", "Get-OmenLanAddress.ps1"));
        foreach (string file in new[] { "manage-gemini-credentials.ps1", "server-runtime.ps1", "release-integrity.ps1", "managed-python.ps1" })
            check(Path.Combine(scripts, file));
    }

    private static string ReleaseSwitch()
    {
#if RAVENX_RELEASE
        return " -ReleasePackage";
#else
        return "";
#endif
    }

    internal static ProcessStartInfo PilotStartInfo(string root, string pilot, string address, int port,
        bool lan, bool ai, string localModel, bool gemini, bool liveGemini, string email)
    {
        if (ai && !Regex.IsMatch(localModel ?? "", @"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\z"))
            throw new ArgumentException("Enter the model identifier shown in LM Studio.");
        string script = Path.Combine(root, "scripts", "pilot", "Start-Omen-College-Pilot.ps1");
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script +
                "\" -ManagedByLauncher -WaitForLauncherJob -PilotName " + pilot + " -LabAddress " + address + " -Port " + port +
                (lan ? "" : " -LoopbackOnly") + (ai ? " -AiModelId " + localModel : " -DisableLocalAi") +
                (gemini ? (liveGemini ? " -EnableGeminiLive" : " -EnableGeminiDemo") : "") + ReleaseSwitch() +
                (email == null ? "" : " -AdministratorEmail \"" + email + "\""),
            WorkingDirectory = root,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        // Build the Windows PowerShell 5.1 module path even when the
        // launcher was opened from PowerShell 7.
        info.EnvironmentVariables.Remove("PSModulePath");
        return info;
    }

    internal static void OpenGeminiKeyPrompt(string root)
    {
#if RAVENX_RELEASE
        VerifyReleaseHome(root);
#endif
        string script = Path.Combine(root, "scripts", "manage-gemini-credentials.ps1");
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File \"" + script +
                "\" -Action Set" + ReleaseSwitch(),
            WorkingDirectory = root,
            UseShellExecute = false
        };
        info.EnvironmentVariables.Remove("PSModulePath");
        using (var process = Process.Start(info)) { }
    }
}

// Closing the last handle terminates only this launcher's pilot and descendants.
internal sealed class PilotJob : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        internal long ProcessTime, JobTime;
        internal uint Flags;
        internal UIntPtr MinWorkingSet, MaxWorkingSet;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint Priority, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        internal BasicLimits Limits;
        internal ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        internal UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    private readonly SafeFileHandle handle;
    internal PilotJob()
    {
        handle = CreateJobObject(IntPtr.Zero, null);
        if (handle.IsInvalid) throw new System.ComponentModel.Win32Exception();
        var limits = new ExtendedLimits();
        limits.Limits.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf(limits)))
        {
            var error = new System.ComponentModel.Win32Exception();
            handle.Dispose();
            throw error;
        }
    }
    internal void Attach(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.Handle)) throw new System.ComponentModel.Win32Exception();
    }
    public void Dispose() { handle.Dispose(); }
}

internal sealed class LauncherForm : Form
{
    private readonly string workspace;
    private static readonly string DataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RAVEN-X");
    private readonly ComboBox profile = new ComboBox { Dock = DockStyle.Fill, MaxLength = 32 };
    private readonly ComboBox address = new ComboBox { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly NumericUpDown port = new NumericUpDown { Minimum = 1024, Maximum = 65535, Value = 8443, Width = 105 };
    private readonly CheckBox lan = new CheckBox { Text = "Allow LAN clients", AutoSize = true, Checked = true };
    private readonly CheckBox ai = new CheckBox { Text = "Enable local AI (LM Studio)", AutoSize = true };
    private readonly ComboBox localModel = new ComboBox { Width = 225, MaxLength = 128, AccessibleName = "LM Studio model ID" };
    private readonly CheckBox gemini = new CheckBox { Text = "Enable Gemini API", AutoSize = true };
    private readonly CheckBox liveGemini = new CheckBox { Text = "Allow Gemini on live assessments", AutoSize = true };
    private readonly Label status = new Label { AutoSize = true, Text = "Stopped", Margin = new Padding(12, 8, 0, 0) };
    private readonly Button start = ButtonFor("Start server");
    private readonly Button stop = ButtonFor("Stop server");
    private readonly Button refresh = ButtonFor("Refresh addresses");
    private readonly Button geminiKey = ButtonFor("Set Gemini key…");
    private readonly Button portal = ButtonFor("Open portal");
    private readonly Button enrollment = ButtonFor("Enrollment");
    private readonly Button fleet = ButtonFor("Fleet");
    private readonly Button copy = ButtonFor("Copy client settings");
    private readonly Button saveCa = ButtonFor("Save public CA…");
    private readonly TextBox connection = new TextBox { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true };
    private readonly TextBox log = new TextBox
    {
        Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
        Font = new Font("Consolas", 9), BackColor = Color.FromArgb(242, 246, 249)
    };
    private Process worker;
    private PilotJob workerJob;
    private readonly Timer stopDeadline = new Timer { Interval = 30000 };
    private bool canForceStop;
    private bool stopping, closeWhenStopped;
    private bool refreshingAddresses;
    private string url, caPath, sha;

    internal LauncherForm(string workspace)
    {
        this.workspace = workspace;
        Text = "RAVEN-X Omen Server";
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(820, 620);
        MinimumSize = new Size(790, 570);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(247, 250, 252);
        ForeColor = Color.FromArgb(24, 42, 51);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(18) };
        Controls.Add(layout);
        var title = new Label { Text = "Omen server", Font = new Font("Segoe UI", 20, FontStyle.Bold), AutoSize = true };
        var setup = new TableLayoutPanel { ColumnCount = 3, Dock = DockStyle.Top, AutoSize = true };
        setup.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        setup.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 44));
        setup.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 22));
        setup.Controls.Add(Caption("Pilot profile"), 0, 0);
        setup.Controls.Add(Caption("Omen LAN IPv4"), 1, 0);
        setup.Controls.Add(Caption("HTTPS port"), 2, 0);
        setup.Controls.Add(profile, 0, 1);
        setup.Controls.Add(address, 1, 1);
        setup.Controls.Add(port, 2, 1);
        localModel.Items.AddRange(new object[] { "google/gemma-3-4b", "meta-llama-3.1-8b-instruct" });
        localModel.SelectedIndex = 0;
        var options = Row(lan, refresh);
        var localOptions = Row(ai, localModel);
        var cloudOptions = Row(gemini, liveGemini);
        var actions = Row(start, stop, geminiKey, status);
        var links = Row(portal, enrollment, fleet, copy, saveCa);
        layout.Controls.Add(title);
        layout.Controls.Add(setup);
        layout.Controls.Add(options);
        layout.Controls.Add(localOptions);
        layout.Controls.Add(cloudOptions);
        layout.Controls.Add(actions);
        layout.Controls.Add(Caption("Client connection"));
        connection.Height = 82;
        connection.Dock = DockStyle.Top;
        layout.Controls.Add(connection);
        layout.Controls.Add(links);
        layout.Controls.Add(Caption("Server log"));
        layout.Controls.Add(log);
        for (int row = 0; row < 10; row++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        if (Directory.Exists(DataRoot))
            foreach (string path in Directory.GetDirectories(DataRoot, "*-pilot").OrderBy(path => path))
            {
                string name = Path.GetFileName(path);
                profile.Items.Add(name.Substring(0, name.Length - "-pilot".Length));
            }
        profile.Text = "home";
        Shown += delegate { RefreshAddresses(); };
        refresh.Click += delegate { RefreshAddresses(); };
        geminiKey.Click += delegate { RunUi(() => Launcher.OpenGeminiKeyPrompt(workspace)); };
        lan.CheckedChanged += delegate { UpdateControls(); };
        ai.CheckedChanged += delegate { UpdateControls(); };
        gemini.CheckedChanged += delegate {
            if (!gemini.Checked) liveGemini.Checked = false;
            UpdateControls();
        };
        start.Click += delegate { StartPilot(); };
        stop.Click += delegate { if (canForceStop) ConfirmForceStop(); else StopPilot(); };
        stopDeadline.Tick += delegate
        {
            stopDeadline.Stop();
            if (worker == null || !stopping) return;
            canForceStop = true;
            status.Text = "Shutdown is taking longer than expected";
            UpdateControls();
            if (closeWhenStopped) ConfirmForceStop();
        };
        Disposed += delegate { stopDeadline.Dispose(); };
        portal.Click += delegate { OpenPortal("/"); };
        enrollment.Click += delegate { OpenPortal("/#/enrollment"); };
        fleet.Click += delegate { OpenPortal("/#/fleet"); };
        copy.Click += delegate { RunUi(() => Clipboard.SetText(connection.Text)); };
        saveCa.Click += delegate { RunUi(ExportPublicCa); };
        FormClosing += OnClosing;
        UpdateControls();
    }

    private static Button ButtonFor(string text)
    {
        return new Button { Text = text, AutoSize = true, Height = 33, Padding = new Padding(5, 1, 5, 1) };
    }

    private static Label Caption(string text)
    {
        return new Label { Text = text, AutoSize = true, Margin = new Padding(3, 7, 3, 3) };
    }

    private static FlowLayoutPanel Row(params Control[] controls)
    {
        var row = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        row.Controls.AddRange(controls);
        return row;
    }

    private void RunUi(Action action)
    {
        try { action(); }
        catch (Exception error)
        {
            MessageBox.Show(this, error.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async void RefreshAddresses()
    {
        if (refreshingAddresses) return;
        refreshingAddresses = true;
        var previous = address.SelectedItem as string;
        address.Items.Clear();
        UpdateControls();
        try
        {
            var candidates = await System.Threading.Tasks.Task.Run(() => ReadLanAddresses(workspace));
            if (IsDisposed) return;
            address.Items.AddRange(candidates);
            if (previous != null && address.Items.Contains(previous)) address.SelectedItem = previous;
            else if (address.Items.Count != 0) address.SelectedIndex = 0;
            else AppendLog("No eligible LAN address. Use a trusted Private network, a VirtualBox host-only adapter, or clear Allow LAN clients for local testing.");
        }
        catch (Exception error) { if (!IsDisposed) AppendLog(error.Message); }
        finally
        {
            refreshingAddresses = false;
            if (!IsDisposed) UpdateControls();
        }
    }

    internal static string[] ReadLanAddresses(string root)
    {
        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" +
                Path.Combine(root, "scripts", "pilot", "Get-OmenLanAddress.ps1") + "\"",
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        info.EnvironmentVariables.Remove("PSModulePath");
        using (var process = Process.Start(info))
        {
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(20000))
            {
                process.Kill();
                throw new TimeoutException("Windows network discovery timed out. Click Refresh addresses to retry.");
            }
            if (process.ExitCode != 0) throw new InvalidOperationException("Windows network discovery failed. " + errors.Result.Trim());
            return output.Result.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Where(value => { IPAddress ip; return IPAddress.TryParse(value, out ip) && ip.ToString() == value; }).ToArray();
        }
    }

    private void StartPilot()
    {
        RunUi(() =>
        {
            string name = profile.Text.Trim();
            if (!Regex.IsMatch(name, @"\A[a-zA-Z0-9][a-zA-Z0-9-]{0,31}\z"))
                throw new InvalidOperationException("Use 1 to 32 letters, digits or hyphens for the pilot name.");
            string host = lan.Checked ? address.SelectedItem as string : "127.0.0.1";
            if (host == null) throw new InvalidOperationException("Select a LAN address or clear Allow LAN clients.");
            string destination = Path.Combine(DataRoot, name + "-pilot");
            string email = null, password = null;
            if (!Directory.Exists(destination) && !PromptForAdministrator(out email, out password)) return;
            log.Clear();
            url = "https://" + host + ":" + port.Value;
            caPath = Path.Combine(destination, "tls", "ca.pem");
            sha = null;
            status.Text = "Starting…";
            var child = new Process { StartInfo = Launcher.PilotStartInfo(workspace, name, host, (int)port.Value,
                lan.Checked, ai.Checked, localModel.Text.Trim(), gemini.Checked, liveGemini.Checked, email), EnableRaisingEvents = true };
            child.OutputDataReceived += (sender, e) => ShowLine(child, e.Data, true);
            child.ErrorDataReceived += (sender, e) => ShowLine(child, e.Data, false);
            var job = new PilotJob();
            bool started = false;
            child.Exited += (sender, e) =>
                System.Threading.ThreadPool.QueueUserWorkItem(delegate
                {
                    job.Dispose();
                    if (worker == child) child.WaitForExit();
                    if (!IsDisposed) BeginInvoke((Action)(() => FinishPilot(child)));
                });
            try
            {
                child.Start();
                started = true;
                job.Attach(child);
                // The runner waits for this line before it can spawn descendants.
                byte[] line = Encoding.ASCII.GetBytes("RAVENX_START\n");
                child.StandardInput.BaseStream.Write(line, 0, line.Length);
                child.StandardInput.BaseStream.Flush();
            }
            catch
            {
                status.Text = "Start failed";
                job.Dispose();
                if (started) child.StandardInput.Close();
                child.Dispose();
                throw;
            }
            worker = child;
            workerJob = job;
            child.BeginOutputReadLine();
            child.BeginErrorReadLine();
            UpdateControls();
            if (password != null)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password + "\n");
                try
                {
                    child.StandardInput.BaseStream.Write(bytes, 0, bytes.Length);
                    child.StandardInput.BaseStream.Flush();
                }
                catch (IOException) { AppendLog("The server stopped before it could read the administrator password."); }
                finally { Array.Clear(bytes, 0, bytes.Length); password = null; }
            }
        });
    }

    private void StopPilot()
    {
        if (worker == null || stopping) return;
        stopping = true;
        status.Text = "Stopping…";
        stopDeadline.Start();
        UpdateControls();
        try { worker.StandardInput.Close(); }
        catch (IOException) { }
    }

    private void ConfirmForceStop()
    {
        if (workerJob == null || !canForceStop) return;
        if (MessageBox.Show(this, "The server is still shutting down. End its remaining workers now? Active requests may be interrupted.",
            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
        {
            if (workerJob == null) return;
            workerJob.Dispose();
            canForceStop = false;
            status.Text = "Ending server workers…";
            UpdateControls();
        }
    }

    private void FinishPilot(Process child)
    {
        if (worker != child) return;
        int exitCode = child.ExitCode;
        AppendLog("Pilot process exited with code " + exitCode + ".");
        status.Text = stopping || exitCode == 0 ? "Stopped" : "Start or server failed";
        worker = null;
        workerJob = null;
        stopDeadline.Stop();
        canForceStop = false;
        stopping = false;
        url = caPath = sha = null;
        child.Dispose();
        UpdateControls();
        if (closeWhenStopped) Close();
    }

    private void ShowLine(Process child, string line, bool stdout)
    {
        if (line == null || IsDisposed) return;
        BeginInvoke((Action)(() =>
        {
            if (worker != child) return;
            string publicLine = Regex.Replace(line, @"\x1B\[[0-9;]*m", "");
            if (stdout && !stopping && publicLine == "RAVENX_LAUNCHER_READY")
            {
                status.Text = "Running";
                AppendLog("Pilot is ready.");
            }
            else
            {
                AppendLog(publicLine);
                if (stdout && status.Text == "Starting…" &&
                    Regex.IsMatch(publicLine, @"\APublic CA SHA-256: [0-9A-F]{64}\z"))
                    sha = publicLine.Substring("Public CA SHA-256: ".Length);
            }
            UpdateControls();
        }));
    }

    private void AppendLog(string line)
    {
        if (log.TextLength > 65000)
        {
            log.Select(0, 16000);
            log.SelectedText = "";
        }
        log.AppendText(line + Environment.NewLine);
    }

    private void UpdateControls()
    {
        bool idle = worker == null;
        bool connected = !stopping && status.Text == "Running" && url != null && caPath != null && sha != null;
        profile.Enabled = port.Enabled = lan.Enabled = ai.Enabled = gemini.Enabled = idle;
        start.Enabled = idle && (!lan.Checked || (!refreshingAddresses && address.SelectedItem != null));
        address.Enabled = refresh.Enabled = idle && lan.Checked && !refreshingAddresses;
        localModel.Enabled = idle && ai.Checked;
        liveGemini.Enabled = idle && gemini.Checked;
        stop.Enabled = !idle && (!stopping || canForceStop);
        stop.Text = canForceStop ? "Force stop" : "Stop server";
        portal.Enabled = fleet.Enabled = enrollment.Enabled = copy.Enabled = saveCa.Enabled = connected;
        string text = connected ? "HTTPS URL: " + url + "\r\nPublic CA SHA-256: " + sha + "\r\nCA file: " + caPath :
            "Connection details appear once the server is running.";
        if (connection.Text != text) connection.Text = text;
    }

    private void OpenPortal(string path)
    {
        RunUi(() => Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), url + path));
    }

    private void ExportPublicCa()
    {
        byte[] bytes = File.ReadAllBytes(caPath);
        using (var digest = System.Security.Cryptography.SHA256.Create())
            if (BitConverter.ToString(digest.ComputeHash(bytes)).Replace("-", "") != sha)
                throw new InvalidOperationException("The CA file changed. Restart the pilot to refresh its connection details.");
        using (var dialog = new SaveFileDialog { FileName = "ca.pem", Filter = "Public certificate|*.pem" })
            if (dialog.ShowDialog(this) == DialogResult.OK)
                File.WriteAllBytes(dialog.FileName, bytes);
    }

    private void OnClosing(object sender, FormClosingEventArgs e)
    {
        if (worker == null) return;
        e.Cancel = true;
        if (canForceStop) { closeWhenStopped = true; ConfirmForceStop(); return; }
        if (stopping || MessageBox.Show(this, "Stop the pilot and close the launcher?", Text,
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
        {
            closeWhenStopped = true;
            StopPilot();
        }
    }

    private bool PromptForAdministrator(out string email, out string password)
    {
        email = password = null;
        using (var dialog = new Form
        {
            Text = "Create pilot administrator", StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog, MinimizeBox = false, MaximizeBox = false,
            ClientSize = new Size(445, 250), Font = Font
        })
        {
            var fields = new TableLayoutPanel { ColumnCount = 1, Dock = DockStyle.Fill, Padding = new Padding(12) };
            var user = new TextBox { Dock = DockStyle.Top };
            var secret = new TextBox { UseSystemPasswordChar = true, MaxLength = 128, Dock = DockStyle.Top };
            var confirm = new TextBox { UseSystemPasswordChar = true, MaxLength = 128, Dock = DockStyle.Top };
            var ok = ButtonFor("Continue");
            var cancel = ButtonFor("Cancel");
            cancel.DialogResult = DialogResult.Cancel;
            fields.Controls.Add(Caption("Administrator email"));
            fields.Controls.Add(user);
            fields.Controls.Add(Caption("Password (12–128 characters)"));
            fields.Controls.Add(secret);
            fields.Controls.Add(Caption("Confirm password"));
            fields.Controls.Add(confirm);
            fields.Controls.Add(Row(ok, cancel));
            dialog.Controls.Add(fields);
            dialog.AcceptButton = ok;
            dialog.CancelButton = cancel;
            ok.Click += delegate
            {
                if (!Regex.IsMatch(user.Text.Trim(), @"\A[^\s@""\\]+@[^\s@""\\]+\z") ||
                    secret.TextLength < 12 || secret.Text != confirm.Text)
                {
                    MessageBox.Show(dialog, "Enter a valid email and matching passwords of at least 12 characters.");
                    return;
                }
                dialog.DialogResult = DialogResult.OK;
            };
            if (dialog.ShowDialog(this) != DialogResult.OK) return false;
            email = user.Text.Trim();
            password = secret.Text;
            secret.Clear();
            confirm.Clear();
            return true;
        }
    }
}
