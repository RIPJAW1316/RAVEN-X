using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

internal static class ClientRemoval
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new RemovalWindow());
    }

    internal static ProcessStartInfo StartInfo(bool uninstall, bool preview)
    {
        string source;
        using (var reader = new StreamReader(typeof(ClientRemoval).Assembly.GetManifestResourceStream("cleanup")))
            source = reader.ReadToEnd();

        string command = "$ProgressPreference = 'SilentlyContinue'\r\n" +
            "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\r\n" +
            "try { & {\r\n" + source + "\r\n} -Mode " + (uninstall ? "Uninstall" : "Recovery") +
            (preview ? " -WhatIf" : " -Confirm:$false") +
            " 6>&1 | ForEach-Object { [Console]::WriteLine($_.ToString()) }" +
            "\r\nexit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        if (encoded.Length > 30000) throw new InvalidOperationException("The embedded cleanup command is too long.");

        var info = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -OutputFormat Text -EncodedCommand " + encoded,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        info.EnvironmentVariables.Remove("PSModulePath");
        return info;
    }
}

internal sealed class RemovalWindow : Form
{
    private readonly Button recover = new Button { Text = "Recover failed install", AutoSize = true };
    private readonly Button uninstall = new Button { Text = "Uninstall client", AutoSize = true };
    private readonly CheckBox preview = new CheckBox { Text = "Preview changes only", AutoSize = true };
    private readonly Label status = new Label { Text = "Ready", AutoSize = true };
    private readonly TextBox output = new TextBox
    {
        Dock = DockStyle.Fill, ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical
    };
    private bool running;

    internal RemovalWindow()
    {
        Text = "RAVEN-X Client Removal";
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(690, 425);
        MinimumSize = new Size(620, 340);
        StartPosition = FormStartPosition.CenterScreen;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(16) };
        layout.Controls.Add(new Label { Text = "RAVEN-X client removal", Font = new Font("Segoe UI", 18, FontStyle.Bold), AutoSize = true });
        layout.Controls.Add(new Label
        {
            Text = "Recovery clears a failed installation. Uninstall also removes the local enrollment identity.",
            AutoSize = true, MaximumSize = new Size(610, 0)
        });
        var actions = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        actions.Controls.AddRange(new Control[] { recover, uninstall, preview });
        layout.Controls.Add(actions);
        layout.Controls.Add(status);
        layout.Controls.Add(output);
        for (int row = 0; row < 4; row++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(layout);
        recover.Click += async (sender, e) => await RunRemoval(false);
        uninstall.Click += async (sender, e) => await RunRemoval(true);
        FormClosing += (sender, e) => { if (running) e.Cancel = true; };
    }

    private async Task RunRemoval(bool removeIdentity)
    {
        bool onlyPreview = preview.Checked;
        if (!onlyPreview)
        {
            string message = removeIdentity
                ? "Remove the agent, scheduled task, and local enrollment identity from this computer?"
                : "Clear files and tasks left by a failed RAVEN-X client installation?";
            if (MessageBox.Show(this, message, Text, MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
        }
        running = true;
        recover.Enabled = uninstall.Enabled = preview.Enabled = false;
        status.Text = onlyPreview ? "Checking client state…" : "Removing client artifacts…";
        output.Clear();
        try
        {
            using (var worker = new Process { StartInfo = ClientRemoval.StartInfo(removeIdentity, onlyPreview) })
            {
                worker.Start();
                var stdout = worker.StandardOutput.ReadToEndAsync();
                var stderr = worker.StandardError.ReadToEndAsync();
                await Task.WhenAll(stdout, stderr);
                await Task.Run(() => worker.WaitForExit());
                output.Text = (stdout.Result + stderr.Result).TrimEnd();
                status.Text = worker.ExitCode == 0
                    ? (onlyPreview ? "Preview complete" : "Complete")
                    : "Stopped. See the details below.";
            }
        }
        catch (Exception error)
        {
            output.Text = error.Message;
            status.Text = "Cleanup could not run";
        }
        finally
        {
            running = false;
            recover.Enabled = uninstall.Enabled = preview.Enabled = true;
        }
    }
}
