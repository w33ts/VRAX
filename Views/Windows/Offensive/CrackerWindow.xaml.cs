using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace VRAX
{
    public partial class CrackerWindow : Window
    {
        private CancellationTokenSource _cts;
        private bool _isRunning = false;
        private long _totalAttempts = 0;
        private DateTime _startTime;
        private DispatcherTimer _updateTimer;
        private long _wordlistSize = 0;

        private readonly SolidColorBrush _tacticalGreen = new SolidColorBrush(Color.FromRgb(68, 255, 68));
        private readonly SolidColorBrush _tacticalRed = new SolidColorBrush(Color.FromRgb(255, 68, 68));
        private readonly SolidColorBrush _tacticalOrange = new SolidColorBrush(Color.FromRgb(255, 170, 68));
        private readonly SolidColorBrush _tacticalGold = new SolidColorBrush(Color.FromRgb(255, 170, 0));
        private readonly SolidColorBrush _tacticalWhite = new SolidColorBrush(Color.FromRgb(224, 224, 224));
        private readonly SolidColorBrush _tacticalGray = new SolidColorBrush(Color.FromRgb(136, 136, 136));

        private static readonly string[] MUTATIONS = {
            "", "123", "!", "1", "12", "1!", "!1", "@", "2024", "2023", "2025",
            "01", "99", "69", "21", "007", "!!", "123!", "321", "@123", "#", "$",
            "%", "^", "&", "*", "()", "000", "111", "222", "333"
        };

        public CrackerWindow()
        {
            InitializeComponent();

            _updateTimer = new DispatcherTimer();
            _updateTimer.Interval = TimeSpan.FromMilliseconds(500);
            _updateTimer.Tick += UpdateTimer_Tick;

            LogLine(">>> VRAX HASH CRACKER ENGINE v1.0 INITIALIZED");
            LogLine(">>> MULTI-THREADED PROCESSOR: READY");
            LogLine(">>> AWAITING TARGET CONFIGURATION");
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            if (_isRunning)
            {
                TimeSpan elapsed = DateTime.Now - _startTime;

                if (elapsed.TotalSeconds > 0)
                {
                    double rate = _totalAttempts / elapsed.TotalSeconds;
                    Dispatcher.Invoke(() => RateLabel.Text = $"{rate:N0} H/s");
                }

                if (_wordlistSize > 0)
                {
                    double progress = Math.Min(99.0, ((double)_totalAttempts / (_wordlistSize * 10)) * 100);
                    Dispatcher.Invoke(() =>
                    {
                        CrackProgress.Value = progress;
                        ProgressText.Text = $"{progress:N1}%";
                    });
                }
            }
        }

        private void BrowseWordlist_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|Wordlists (*.lst)|*.lst|All Files (*.*)|*.*",
                Title = "Select Wordlist File",
                Multiselect = false,
                CheckFileExists = true
            };

            if (openFileDialog.ShowDialog() == true)
            {
                string filePath = openFileDialog.FileName;
                WordlistPath.Text = filePath;

                try
                {
                    FileInfo fileInfo = new FileInfo(filePath);
                    _wordlistSize = CountFileLines(filePath);

                    LogLine($"[+] WORDLIST LOADED: {Path.GetFileName(filePath)}");
                    LogLine($"[+] FILE SIZE: {FormatBytes(fileInfo.Length)}");
                    LogLine($"[+] ENTRIES: {_wordlistSize:N0}");
                }
                catch (Exception ex)
                {
                    LogLine($"[!] ERROR READING FILE: {ex.Message}");
                    MessageBox.Show($"Error reading file: {ex.Message}", "File Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private long CountFileLines(string filePath)
        {
            long count = 0;
            using (var reader = File.OpenText(filePath))
            {
                while (reader.ReadLine() != null)
                {
                    count++;
                }
            }
            return count;
        }

        private string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double size = bytes;

            while (size >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                size /= 1024;
                suffixIndex++;
            }

            return $"{size:N1} {suffixes[suffixIndex]}";
        }

        private async void StartCrack_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning)
            {
                LogLine("[!] ATTACK ALREADY IN PROGRESS");
                return;
            }

            string targetHash = HashInput.Text.Trim().ToLower();
            string wordlistPath = WordlistPath.Text;
            string hashType = ((ComboBoxItem)HashTypeCombo.SelectedItem).Content.ToString();
            string ssid = SsidInput.Text.Trim();

            if (string.IsNullOrEmpty(targetHash))
            {
                MessageBox.Show("Please enter a target hash to crack.", "Input Required",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!File.Exists(wordlistPath))
            {
                MessageBox.Show("Please select a valid wordlist file.", "File Required",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (hashType.Contains("WPA2") && string.IsNullOrEmpty(ssid))
            {
                MessageBox.Show("WPA2 cracking requires SSID (Network Name).", "Input Required",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _cts = new CancellationTokenSource();
            _isRunning = true;
            _totalAttempts = 0;
            _startTime = DateTime.Now;
            _updateTimer.Start();

            Dispatcher.Invoke(() =>
            {
                CoreStatus.Text = "ACTIVE";
                CoreStatus.Foreground = _tacticalGreen;
                ResultLabel.Text = "[CRACKING IN PROGRESS...]";
                ResultLabel.Foreground = _tacticalOrange;
            });

            LogLine("");
            LogLine(">>> ===========================================");
            LogLine($">>> CRACKING SESSION STARTED: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            LogLine($">>> TARGET HASH: {targetHash.Substring(0, Math.Min(32, targetHash.Length))}...");
            LogLine($">>> ALGORITHM: {hashType}");
            LogLine($">>> WORDLIST: {Path.GetFileName(wordlistPath)} ({_wordlistSize:N0} entries)");
            if (!string.IsNullOrEmpty(ssid)) LogLine($">>> SSID: {ssid}");
            LogLine($">>> MUTATION ENGINE: {(ChkMutate.IsChecked == true ? "ENABLED" : "DISABLED")}");
            LogLine($">>> ADVANCED RULES: {(ChkRules.IsChecked == true ? "ENABLED" : "DISABLED")}");
            LogLine($">>> THREADS: {Environment.ProcessorCount}");
            LogLine(">>> ===========================================");

            try
            {
                CrackResult result = await CrackHashAsync(targetHash, wordlistPath, hashType, ssid);

                if (result.Success)
                {
                    await Dispatcher.InvokeAsync(() => DisplaySuccess(result.Password, result.ElapsedTime));
                }
                else if (!_cts.Token.IsCancellationRequested)
                {
                    await Dispatcher.InvokeAsync(() => DisplayFailure(result.ElapsedTime));
                }

                if (!result.Success && ChkBruteforce.IsChecked == true && !_cts.Token.IsCancellationRequested)
                {
                    await BruteforceFallbackAsync(targetHash, hashType, ssid);
                }
            }
            catch (OperationCanceledException)
            {
                LogLine("[!] OPERATION CANCELLED BY USER");
                LogLine($"[!] TOTAL ATTEMPTS: {_totalAttempts:N0}");
            }
            catch (Exception ex)
            {
                LogLine($"[CRITICAL_ERROR] {ex.Message}");
                await Dispatcher.InvokeAsync(() =>
                    MessageBox.Show($"Cracking failed: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error));
            }
            finally
            {
                await Dispatcher.InvokeAsync(EndCrackingSession);
            }
        }

        private async Task<CrackResult> CrackHashAsync(string targetHash, string wordlistPath, string hashType, string ssid)
        {
            CrackResult result = new CrackResult();
            result.StartTime = DateTime.Now;

            await Task.Run(async () =>
            {
                int batchSize = 10000;
                var batch = new List<string>(batchSize);

                using (var fileStream = File.OpenRead(wordlistPath))
                using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, 65536))
                {
                    string line;
                    while ((line = await streamReader.ReadLineAsync()) != null)
                    {
                        if (_cts.Token.IsCancellationRequested)
                            break;

                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        batch.Add(line.Trim());

                        if (batch.Count >= batchSize)
                        {
                            if (await ProcessBatchAsync(batch, targetHash, hashType, ssid, result))
                            {
                                break;
                            }
                            batch.Clear();
                        }
                    }

                    if (batch.Count > 0 && !result.Success && !_cts.Token.IsCancellationRequested)
                    {
                        await ProcessBatchAsync(batch, targetHash, hashType, ssid, result);
                    }
                }

                result.ElapsedTime = DateTime.Now - result.StartTime;
            }, _cts.Token);

            return result;
        }

        private async Task<bool> ProcessBatchAsync(List<string> batch, string targetHash, string hashType, string ssid, CrackResult result)
        {
            bool foundInBatch = false;

            await Task.Run(() =>
            {
                ParallelOptions options = new ParallelOptions
                {
                    CancellationToken = _cts.Token,
                    MaxDegreeOfParallelism = Environment.ProcessorCount
                };

                Parallel.ForEach(batch, options, (password, state) =>
                {
                    if (result.Success || _cts.Token.IsCancellationRequested)
                    {
                        state.Stop();
                        return;
                    }

                    var candidates = GenerateCandidates(password);

                    foreach (var candidate in candidates)
                    {
                        Interlocked.Increment(ref _totalAttempts);
                        string computedHash = ComputeHash(candidate, hashType, ssid);

                        if (computedHash == targetHash)
                        {
                            lock (result)
                            {
                                result.Success = true;
                                result.Password = candidate;
                                foundInBatch = true;
                            }
                            state.Stop();
                            break;
                        }
                    }
                });
            }, _cts.Token);

            return foundInBatch;
        }

        private IEnumerable<string> GenerateCandidates(string basePassword)
        {
            yield return basePassword;

            bool mutateEnabled = false;
            bool rulesEnabled = false;

            Dispatcher.Invoke(() =>
            {
                mutateEnabled = ChkMutate.IsChecked == true;
                rulesEnabled = ChkRules.IsChecked == true;
            });

            if (mutateEnabled)
            {
                foreach (var mutation in MUTATIONS.Take(15))
                {
                    if (!string.IsNullOrEmpty(mutation))
                    {
                        yield return basePassword + mutation;
                    }
                }
            }

            if (rulesEnabled)
            {
                yield return basePassword.ToUpper();
                yield return basePassword.ToLower();

                if (basePassword.Length > 1)
                {
                    yield return char.ToUpper(basePassword[0]) + basePassword.Substring(1).ToLower();
                    yield return new string(basePassword.Reverse().ToArray());
                }

                yield return basePassword.Replace('a', '@').Replace('s', '$').Replace('i', '1');
            }
        }

        private string ComputeHash(string input, string hashType, string ssid)
        {
            try
            {
                if (hashType.Contains("WPA2"))
                {
                    using (var pbkdf2 = new Rfc2898DeriveBytes(input,
                           Encoding.UTF8.GetBytes(ssid), 4096, HashAlgorithmName.SHA1))
                    {
                        return BitConverter.ToString(pbkdf2.GetBytes(32)).Replace("-", "").ToLower();
                    }
                }

                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes;

                if (hashType.Contains("NTLM"))
                {
                    inputBytes = Encoding.Unicode.GetBytes(input);
                    hashBytes = MD5.HashData(inputBytes);
                }
                else if (hashType.Contains("SHA-512"))
                {
                    hashBytes = SHA512.HashData(inputBytes);
                }
                else if (hashType.Contains("SHA-256"))
                {
                    hashBytes = SHA256.HashData(inputBytes);
                }
                else if (hashType.Contains("SHA-1"))
                {
                    hashBytes = SHA1.HashData(inputBytes);
                }
                else
                {
                    hashBytes = MD5.HashData(inputBytes);
                }

                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
            catch
            {
                return string.Empty;
            }
        }

        private async Task BruteforceFallbackAsync(string targetHash, string hashType, string ssid)
        {
            LogLine("[BRUTEFORCE] INITIATING FALLBACK BRUTEFORCE (4-6 CHARACTERS)");

            const string charset = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%";
            bool found = false;
            string foundPassword = string.Empty;

            await Task.Run(() =>
            {
                for (int len = 4; len <= 6 && !found && !_cts.Token.IsCancellationRequested; len++)
                {
                    LogLine($"[BRUTEFORCE] TESTING {len} CHARACTER COMBINATIONS");

                    var combinations = GenerateCombinations(charset, len);

                    Parallel.ForEach(combinations, new ParallelOptions
                    {
                        MaxDegreeOfParallelism = Environment.ProcessorCount,
                        CancellationToken = _cts.Token
                    }, (combination, state) =>
                    {
                        if (found || _cts.Token.IsCancellationRequested)
                        {
                            state.Stop();
                            return;
                        }

                        Interlocked.Increment(ref _totalAttempts);
                        string hash = ComputeHash(combination, hashType, ssid);

                        if (hash == targetHash)
                        {
                            found = true;
                            foundPassword = combination;
                            state.Stop();
                        }
                    });

                    if (found)
                        break;
                }
            }, _cts.Token);

            if (found)
            {
                await Dispatcher.InvokeAsync(() =>
                    DisplaySuccess(foundPassword, DateTime.Now - _startTime));
            }
            else
            {
                LogLine("[BRUTEFORCE] NO MATCH FOUND IN BRUTEFORCE RANGE");
            }
        }

        private IEnumerable<string> GenerateCombinations(string charset, int length)
        {
            var indices = new int[length];
            var chars = charset.ToCharArray();

            while (true)
            {
                var combination = new char[length];
                for (int i = 0; i < length; i++)
                {
                    combination[i] = chars[indices[i]];
                }
                yield return new string(combination);

                int pos = length - 1;
                while (pos >= 0 && ++indices[pos] == chars.Length)
                {
                    indices[pos] = 0;
                    pos--;
                }

                if (pos < 0)
                    break;
            }
        }

        private void DisplaySuccess(string password, TimeSpan elapsedTime)
        {
            ResultLabel.Text = password;
            ResultLabel.Foreground = _tacticalGreen;
            CrackProgress.Value = 100;
            ProgressText.Text = "100%";

            LogLine("");
            LogLine(">>> ===========================================");
            LogLine(">>> ✅ PASSWORD CRACKED SUCCESSFULLY!");
            LogLine($">>> PASSWORD: {password}");
            LogLine($">>> TIME ELAPSED: {elapsedTime.TotalSeconds:N2} seconds");
            LogLine($">>> ATTEMPTS: {_totalAttempts:N0}");
            LogLine($">>> AVERAGE RATE: {_totalAttempts / elapsedTime.TotalSeconds:N0} H/s");
            LogLine(">>> ===========================================");

            CoreStatus.Text = "SUCCESS";
            CoreStatus.Foreground = _tacticalGreen;
        }

        private void DisplayFailure(TimeSpan elapsed)
        {
            LogLine("");
            LogLine(">>> ===========================================");
            LogLine(">>> ❌ NO MATCH FOUND IN WORDLIST");
            LogLine($">>> TOTAL ATTEMPTS: {_totalAttempts:N0}");
            LogLine($">>> TIME ELAPSED: {elapsed.TotalSeconds:N2} seconds");
            LogLine($">>> AVERAGE RATE: {_totalAttempts / elapsed.TotalSeconds:N0} H/s");
            LogLine(">>> RECOMMENDATION: Try a different wordlist or enable bruteforce");
            LogLine(">>> ===========================================");

            ResultLabel.Text = "[NO MATCH FOUND]";
            ResultLabel.Foreground = _tacticalRed;
        }

        private void EndCrackingSession()
        {
            _updateTimer.Stop();
            _isRunning = false;

            CoreStatus.Text = "IDLE";
            CoreStatus.Foreground = _tacticalGold;
        }

        private void StopCrack_Click(object sender, RoutedEventArgs e)
        {
            if (_isRunning)
            {
                _cts?.Cancel();
                LogLine("[!] STOP SIGNAL RECEIVED - TERMINATING...");
            }
        }

        private void LogLine(string message)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                CrackOutput.Text += $"{message}\n";
                CrackScroll.ScrollToEnd();
            }));
        }

        private void CopyResult_Click(object sender, RoutedEventArgs e)
        {
            if (!ResultLabel.Text.StartsWith("[") && !string.IsNullOrEmpty(ResultLabel.Text))
            {
                Clipboard.SetText(ResultLabel.Text);
                LogLine($"[+] Password copied to clipboard: {ResultLabel.Text}");
            }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            base.OnClosing(e);

            if (_isRunning)
            {
                var result = MessageBox.Show("Cracking is in progress. Are you sure you want to close?",
                    "Confirm Close", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.No)
                {
                    e.Cancel = true;
                }
                else
                {
                    _cts?.Cancel();
                }
            }
        }

        private class CrackResult
        {
            public bool Success { get; set; }
            public string Password { get; set; }
            public DateTime StartTime { get; set; }
            public TimeSpan ElapsedTime { get; set; }
        }

        private void HashTypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }
    }
}
