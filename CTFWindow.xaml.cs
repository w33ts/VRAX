using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;

namespace ReconSuite
{
    public partial class CTFWindow : Window
    {
        private TcpListener listener;
        private TcpClient client;
        private NetworkStream stream;
        private Thread listenerThread;
        private Thread receiveThread;
        private bool isListening = false;
        private bool isConnected = false;
        private readonly object streamLock = new object();
        private long totalBytesReceived = 0;
        private DateTime connectionStartTime;

        public CTFWindow()
        {
            InitializeComponent();

            var timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            
           
        }

        

        private void UpdateStatus(string status, bool isError = false)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = status;
                StatusIndicator.Fill = isError ?
                    System.Windows.Media.Brushes.Red :
                    (isConnected ? System.Windows.Media.Brushes.LimeGreen :
                    (isListening ? System.Windows.Media.Brushes.Yellow :
                    System.Windows.Media.Brushes.Gray));
            });
        }

        private void PortInput_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (int.TryParse(PortInput.Text, out int port))
            {
                if (port < 1 || port > 65535)
                    PortInput.Foreground = System.Windows.Media.Brushes.Red;
                else
                    PortInput.Foreground = System.Windows.Media.Brushes.White;
            }
            else
            {
                PortInput.Foreground = System.Windows.Media.Brushes.Red;
            }
        }

        private void StartListener_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(PortInput.Text, out int port) || port < 1 || port > 65535)
            {
                MessageBox.Show("Enter a valid port (1-65535)", "Invalid Port",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
                isListening = true;

                StartListenerBtn.IsEnabled = false;
                StopListenerBtn.IsEnabled = true;

                AppendOutput($"[*] Listening on port {port}\n");
                AppendOutput($"[*] Waiting for connection...\n");
                UpdateStatus($"Listening on port {port}");

                listenerThread = new Thread(ListenForConnections);
                listenerThread.IsBackground = true;
                listenerThread.Start();
            }
            catch (Exception ex)
            {
                AppendOutput($"[!] Failed to start: {ex.Message}\n");
                UpdateStatus("Error", true);
            }
        }

        private void ListenForConnections()
        {
            while (isListening)
            {
                try
                {
                    var newClient = listener.AcceptTcpClient();

                    Dispatcher.Invoke(() =>
                    {
                        if (!isConnected)
                        {
                            client = newClient;
                            HandleNewConnection();
                        }
                        else
                        {
                            AppendOutput($"[!] Rejected connection from {newClient.Client.RemoteEndPoint} - already connected\n");
                            newClient.Close();
                        }
                    });
                }
                catch
                {
                    break;
                }
            }
        }

        private void HandleNewConnection()
        {
            try
            {
                var endPoint = client.Client.RemoteEndPoint.ToString();
                stream = client.GetStream();
                isConnected = true;
                connectionStartTime = DateTime.Now;

                ClientInfoText.Text = endPoint;
                ConnectionStatusText.Text = "Connected";
                ConnectionStatusText.Foreground = System.Windows.Media.Brushes.LimeGreen;

                CommandInput.IsEnabled = true;
                SendBtn.IsEnabled = true;
                InterruptBtn.IsEnabled = true;
                DisconnectBtn.IsEnabled = true;

                AppendOutput($"[+] Connected from {endPoint}\n");
                AppendOutput($"[+] Shell established at {DateTime.Now:HH:mm:ss}\n");
                AppendOutput("────────────────────────────────────────\n");

                UpdateStatus($"Connected to {endPoint}");

                receiveThread = new Thread(ReceiveData);
                receiveThread.IsBackground = true;
                receiveThread.Start();

                LogToFile($"Connection from {endPoint}");
            }
            catch (Exception ex)
            {
                AppendOutput($"[!] Connection error: {ex.Message}\n");
                Disconnect();
            }
        }

        private void ReceiveData()
        {
            byte[] buffer = new byte[4096];

            while (isConnected && client != null && client.Connected)
            {
                try
                {
                    int bytesRead = stream.Read(buffer, 0, buffer.Length);

                    if (bytesRead > 0)
                    {
                        string data = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                        Dispatcher.Invoke(() =>
                        {
                            OutputBox.AppendText(data);
                            OutputScroll.ScrollToEnd();

                            totalBytesReceived += bytesRead;
                            BytesReceivedText.Text = $"{totalBytesReceived} bytes received";
                        });

                        LogToFile($"Received: {data.Length} bytes");
                    }
                    else
                    {
                        Dispatcher.Invoke(() => AppendOutput("[!] Connection closed by remote host\n"));
                        Disconnect();
                        break;
                    }
                }
                catch
                {
                    Dispatcher.Invoke(() => AppendOutput("[!] Connection lost\n"));
                    Disconnect();
                    break;
                }
            }
        }

        private void SendCommand(string command)
        {
            if (!isConnected || stream == null)
            {
                AppendOutput("[!] Not connected\n");
                return;
            }

            try
            {
                byte[] data = Encoding.UTF8.GetBytes(command + "\n");
                stream.Write(data, 0, data.Length);

                Dispatcher.Invoke(() =>
                {
                    OutputBox.AppendText($"$ {command}\n");
                });

                LogToFile($"Sent: {command}");
            }
            catch (Exception ex)
            {
                AppendOutput($"[!] Send failed: {ex.Message}\n");
                Disconnect();
            }
        }

        private void SendCommand_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(CommandInput.Text))
            {
                SendCommand(CommandInput.Text);
                CommandInput.Clear();
            }
        }

        private void CommandInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && !string.IsNullOrWhiteSpace(CommandInput.Text))
            {
                SendCommand(CommandInput.Text);
                CommandInput.Clear();
                e.Handled = true;
            }
        }

        private void QuickCommand_Click(object sender, RoutedEventArgs e)
        {
            
        }

        private void Interrupt_Click(object sender, RoutedEventArgs e)
        {
            if (isConnected && stream != null)
            {
                try
                {
                    byte[] interrupt = new byte[] { 0x03 }; // Ctrl+C
                    stream.Write(interrupt, 0, interrupt.Length);
                    AppendOutput("^C\n");
                }
                catch
                {
                    AppendOutput("[!] Failed to send interrupt\n");
                }
            }
        }

        private void Disconnect_Click(object sender, RoutedEventArgs e)
        {
            Disconnect();
        }

        private void Disconnect()
        {
            try
            {
                isConnected = false;

                stream?.Close();
                client?.Close();

                stream = null;
                client = null;

                Dispatcher.Invoke(() =>
                {
                    ClientInfoText.Text = "None";
                    ConnectionStatusText.Text = "Disconnected";
                    ConnectionStatusText.Foreground = System.Windows.Media.Brushes.Red;
                    ConnectedSinceText.Text = "--:--:--";

                    CommandInput.IsEnabled = false;
                    SendBtn.IsEnabled = false;
                    InterruptBtn.IsEnabled = false;
                    DisconnectBtn.IsEnabled = false;

                    AppendOutput("[*] Disconnected\n");
                });

                UpdateStatus("Disconnected");
            }
            catch (Exception ex)
            {
                AppendOutput($"[!] Disconnect error: {ex.Message}\n");
            }
        }

        private void StopListener_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                isListening = false;

                Disconnect();

                listener?.Stop();
                listener = null;

                StartListenerBtn.IsEnabled = true;
                StopListenerBtn.IsEnabled = false;

                AppendOutput("[*] Listener stopped\n");
                UpdateStatus("Stopped");

                StatusIndicator.Fill = System.Windows.Media.Brushes.Gray;
            }
            catch (Exception ex)
            {
                AppendOutput($"[!] Stop error: {ex.Message}\n");
            }
        }

        private void AppendOutput(string text)
        {
            Dispatcher.Invoke(() =>
            {
                OutputBox.AppendText(text);
                OutputScroll.ScrollToEnd();
            });
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            OutputBox.Clear();
            totalBytesReceived = 0;
            BytesReceivedText.Text = "0 bytes received";
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string filename = $"shell_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                File.WriteAllText(filename, OutputBox.Text);

                MessageBox.Show($"Log saved to:\n{filename}", "Export Successful",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LogToFile(string entry)
        {
            try
            {
                string logFile = $"ctf_listener_{DateTime.Now:yyyyMMdd}.log";
                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] {entry}\n");
            }
            catch { }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            StopListener_Click(null, null);
            base.OnClosing(e);
        }
    }
}