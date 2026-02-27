using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace VRAX
{
    public partial class DirectoryWindow : Window
    {
        private string _target;
        private bool _isFuzzing = false;
        private CancellationTokenSource _cts;
        private ObservableCollection<FuzzResult> _results = new ObservableCollection<FuzzResult>();
        private static readonly HttpClient _client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        private DispatcherTimer _updateTimer;
        private Stopwatch _stopwatch;
        private int _totalProcessed = 0;
        private int _totalHits = 0;
        private int _activeThreads = 0;
        private long _scanId;
        private readonly string connStr = "Data Source=recon.db;Version=3;";

        private static readonly string[] COMMON_EXTENSIONS = { "", ".php", ".html", ".asp", ".aspx", ".jsp", ".js", ".json", ".xml", ".txt", ".bak", ".old" };

        public DirectoryWindow(string target)
        {
            InitializeComponent();
            _target = target;
            TargetUrl.Text = target.StartsWith("http") ? target : $"http://{target}/";
            DirGrid.ItemsSource = _results;

            _client.DefaultRequestHeaders.Clear();
            _client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
            _client.DefaultRequestHeaders.Add("Accept", "*/*");

            _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _updateTimer.Tick += UpdateTimer_Tick;

            _stopwatch = new Stopwatch();

            Log(">>> GHOSTBUSTER ENGINE INITIALIZED");
            Log(">>> READY FOR TARGET ACQUISITION");

            InitializeScanId();
        }

        private void InitializeScanId()
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT id FROM scans WHERE target = @target ORDER BY id DESC LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@target", _target);

                var result = cmd.ExecuteScalar();
                if (result != null)
                {
                    _scanId = Convert.ToInt64(result);
                    Log($">>> SCAN ID ACQUIRED: {_scanId}");
                }
                else
                {
                    using var insertCmd = new SQLiteCommand("INSERT INTO scans (target, start_time, status) VALUES (@target, @start, 'directory_scan')", conn);
                    insertCmd.Parameters.AddWithValue("@target", _target);
                    insertCmd.Parameters.AddWithValue("@start", DateTime.Now);
                    insertCmd.ExecuteNonQuery();

                    _scanId = conn.LastInsertRowId;
                    Log($">>> NEW SCAN ID CREATED: {_scanId}");
                }
            }
            catch (Exception ex)
            {
                Log($">>> ERROR GETTING SCAN ID: {ex.Message}");
                _scanId = DateTime.Now.Ticks;
            }
        }

        private void UpdateTimer_Tick(object sender, EventArgs e)
        {
            if (_stopwatch.IsRunning)
            {
                ElapsedTime.Text = _stopwatch.Elapsed.ToString(@"hh\:mm\:ss");

                double rps = _stopwatch.Elapsed.TotalSeconds > 0 ? _totalProcessed / _stopwatch.Elapsed.TotalSeconds : 0;
                RequestRate.Text = $"{rps:F1}";

                TotalRequests.Text = _totalProcessed.ToString("N0");
                ThreadCount.Text = _activeThreads.ToString();

                HexMonitor.Text = $"0x{_totalProcessed:X6}";
            }
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LiveStatus.Text = message;
            });
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                Title = "Select Directory Wordlist"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                WordlistPath.Text = openFileDialog.FileName;
                Log($">>> WORDLIST LOADED: {Path.GetFileName(openFileDialog.FileName)}");

                try
                {
                    long lineCount = File.ReadLines(openFileDialog.FileName).Count();
                    Log($">>> DICTIONARY SIZE: {lineCount:N0} entries");
                }
                catch { }
            }
        }

        private async void StartFuzz_Click(object sender, RoutedEventArgs e)
        {
            if (_isFuzzing)
            {
                _cts?.Cancel();
                Log(">>> ABORT SIGNAL RECEIVED >> TERMINATING");
                return;
            }

            if (!File.Exists(WordlistPath.Text))
            {
                Log(">>> ERROR: WORDLIST FILE NOT FOUND");
                MessageBox.Show("Please select a valid wordlist file.", "ERROR", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string baseUrl = TargetUrl.Text.Trim();
            if (!baseUrl.StartsWith("http://") && !baseUrl.StartsWith("https://"))
            {
                baseUrl = "http://" + baseUrl;
            }

            if (!baseUrl.EndsWith("/"))
            {
                baseUrl += "/";
            }

            _isFuzzing = true;
            _totalProcessed = 0;
            _totalHits = 0;
            _activeThreads = 0;

            StartBtn.Content = "STOP SCAN";
            StartBtn.Background = new SolidColorBrush(Color.FromRgb(10, 0, 0));
            StartBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(255, 49, 49));

            _results.Clear();
            _cts = new CancellationTokenSource();

            Log(">>> ═══════════════════════════════════════════════════");
            Log($">>> FUZZING INITIATED >> TARGET: {baseUrl}");
            Log(">>> ═══════════════════════════════════════════════════");

            EngineStatus.Text = "ACTIVE";
            EngineStatus.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 65));

            string[] lines = File.ReadAllLines(WordlistPath.Text);
            var wordlist = lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim()).Distinct().ToArray();

            FuzzProgress.Maximum = wordlist.Length;
            FuzzProgress.Value = 0;

            _stopwatch.Restart();
            _updateTimer.Start();

            int maxThreads = 50;
            var semaphore = new SemaphoreSlim(maxThreads);

            try
            {
                Log($">>> SCANNING {wordlist.Length:N0} UNIQUE PATHS...");
                Log($">>> USING {maxThreads} CONCURRENT THREADS");

                int batchSize = 100;
                for (int i = 0; i < wordlist.Length; i += batchSize)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    var batch = wordlist.Skip(i).Take(batchSize).ToArray();

                    var batchTasks = batch.Select(word => ProcessWordFast(baseUrl, word, semaphore));
                    await Task.WhenAll(batchTasks);

                    Dispatcher.Invoke(() =>
                    {
                        double progress = (double)_totalProcessed / wordlist.Length * 100;
                        ProgressText.Text = $"{progress:F1}%";
                        FuzzProgress.Value = _totalProcessed;
                    });
                }

                _stopwatch.Stop();
                _updateTimer.Stop();

                Log(">>> ═══════════════════════════════════════════════════");
                Log($">>> SCAN COMPLETE >> {_totalHits} ENDPOINTS DISCOVERED");
                Log($">>> TOTAL REQUESTS: {_totalProcessed:N0}");
                Log($">>> SPEED: {_totalProcessed / Math.Max(1, _stopwatch.Elapsed.TotalSeconds):F1} req/sec");
                Log($">>> ELAPSED TIME: {_stopwatch.Elapsed:hh\\:mm\\:ss}");
                Log(">>> ═══════════════════════════════════════════════════");

                SaveResultsToDatabase();

                if (_totalHits > 0)
                {
                    MessageBox.Show($"Scan complete!\n\nDiscovered: {_totalHits} endpoints\nTotal requests: {_totalProcessed:N0}\nSpeed: {_totalProcessed / Math.Max(1, _stopwatch.Elapsed.TotalSeconds):F1} req/sec\nTime: {_stopwatch.Elapsed:hh\\:mm\\:ss}\n\nResults saved to database.",
                        "SCAN COMPLETE", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show($"No endpoints found.\n\nTotal requests: {_totalProcessed:N0}\nTime: {_stopwatch.Elapsed:hh\\:mm\\:ss}",
                        "SCAN COMPLETE", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (OperationCanceledException)
            {
                _stopwatch.Stop();
                _updateTimer.Stop();
                Log(">>> ═══════════════════════════════════════════════════");
                Log(">>> OPERATION TERMINATED BY USER");
                Log($">>> REQUESTS COMPLETED: {_totalProcessed:N0}");
                Log($">>> ENDPOINTS FOUND: {_totalHits}");
                Log(">>> ═══════════════════════════════════════════════════");

                SaveResultsToDatabase();
            }
            catch (Exception ex)
            {
                _stopwatch.Stop();
                _updateTimer.Stop();
                Log($">>> CRITICAL ERROR: {ex.Message}");
            }
            finally
            {
                _isFuzzing = false;
                _activeThreads = 0;

                StartBtn.Content = "START SCAN";
                StartBtn.Background = new SolidColorBrush(Color.FromRgb(90, 0, 0));
                StartBtn.BorderBrush = new SolidColorBrush(Color.FromRgb(139, 0, 0));

                EngineStatus.Text = "COMPLETE";
                EngineStatus.Foreground = new SolidColorBrush(Color.FromRgb(0, 255, 65));
            }
        }

        private async Task ProcessWordFast(string baseUrl, string word, SemaphoreSlim semaphore)
        {
            await semaphore.WaitAsync(_cts.Token);
            Interlocked.Increment(ref _activeThreads);

            try
            {
                await FastProbeEndpoint(baseUrl, word);
            }
            finally
            {
                semaphore.Release();
                Interlocked.Decrement(ref _activeThreads);
                Interlocked.Increment(ref _totalProcessed);
            }
        }

        private async Task FastProbeEndpoint(string baseUrl, string path)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                Dispatcher.Invoke(() =>
                {
                    Log($"◢ PROBING: /{path}");
                });

                string fullUrl = baseUrl + path.TrimStart('/');

                using (var request = new HttpRequestMessage(HttpMethod.Get, fullUrl))
                using (var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, _cts.Token))
                {
                    stopwatch.Stop();

                    int statusCode = (int)response.StatusCode;

                    if (statusCode >= 200 && statusCode < 400 || statusCode == 401 || statusCode == 403)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        long contentLength = content.Length;

                        bool isReal404 = false;
                        if (statusCode == 200)
                        {
                            var lowerContent = content.ToLower();
                            if (lowerContent.Contains("404") &&
                                (lowerContent.Contains("not found") || lowerContent.Contains("page not found")) &&
                                contentLength < 2000)
                            {
                                isReal404 = true;
                            }
                        }

                        if (!isReal404)
                        {
                            int hits = Interlocked.Increment(ref _totalHits);

                            string length = contentLength > 1024
                                ? $"{(contentLength / 1024.0):F1} KB"
                                : $"{contentLength} bytes";

                            var result = new FuzzResult
                            {
                                Status = statusCode.ToString(),
                                Method = "GET",
                                Path = "/" + path,
                                Length = length,
                                ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                                Confidence = CalculateConfidence(content, statusCode)
                            };

                            Dispatcher.Invoke(() =>
                            {
                                _results.Add(result);
                                HitCounter.Text = hits.ToString();

                                SaveResultToDatabase(result, fullUrl, contentLength, stopwatch.ElapsedMilliseconds);

                                if (statusCode >= 200 && statusCode < 300)
                                {
                                    Log($"◢ [200] FOUND: /{path} ({length})");
                                }
                                else if (statusCode >= 300 && statusCode < 400)
                                {
                                    Log($"◢ [3XX] REDIRECT: /{path}");
                                }
                                else if (statusCode == 401)
                                {
                                    Log($"◢ [401] AUTH REQUIRED: /{path}");
                                }
                                else if (statusCode == 403)
                                {
                                    Log($"◢ [403] FORBIDDEN: /{path}");
                                }
                            });
                        }
                    }
                }

                foreach (var ext in COMMON_EXTENSIONS.Take(3))
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    if (!string.IsNullOrEmpty(ext) && !path.EndsWith(ext))
                    {
                        await ProbeExtension(baseUrl, path + ext);
                    }
                }
            }
            catch (TaskCanceledException)
            {
                
            }
            catch (HttpRequestException)
            {
                
            }
            catch
            {
                
            }
        }

        private async Task ProbeExtension(string baseUrl, string testPath)
        {
            try
            {
                string fullUrl = baseUrl + testPath.TrimStart('/');
                var stopwatch = Stopwatch.StartNew();

                using (var request = new HttpRequestMessage(HttpMethod.Get, fullUrl))
                using (var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, _cts.Token))
                {
                    stopwatch.Stop();

                    int statusCode = (int)response.StatusCode;

                    if (statusCode >= 200 && statusCode < 400 || statusCode == 401 || statusCode == 403)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        long contentLength = content.Length;

                        bool isReal404 = false;
                        if (statusCode == 200)
                        {
                            var lowerContent = content.ToLower();
                            if (lowerContent.Contains("404") &&
                                (lowerContent.Contains("not found") || lowerContent.Contains("page not found")) &&
                                contentLength < 2000)
                            {
                                isReal404 = true;
                            }
                        }

                        if (!isReal404)
                        {
                            int hits = Interlocked.Increment(ref _totalHits);

                            string length = contentLength > 1024
                                ? $"{(contentLength / 1024.0):F1} KB"
                                : $"{contentLength} bytes";

                            var result = new FuzzResult
                            {
                                Status = statusCode.ToString(),
                                Method = "GET",
                                Path = "/" + testPath,
                                Length = length,
                                ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                                Confidence = CalculateConfidence(content, statusCode)
                            };

                            Dispatcher.Invoke(() =>
                            {
                                _results.Add(result);
                                HitCounter.Text = _totalHits.ToString();

                                SaveResultToDatabase(result, fullUrl, contentLength, stopwatch.ElapsedMilliseconds);

                                if (statusCode >= 200 && statusCode < 300)
                                {
                                    Log($"◢ [200] FOUND: /{testPath} ({length})");
                                }
                            });
                        }
                    }
                }
            }
            catch
            {
                
            }
        }

        private void SaveResultToDatabase(FuzzResult result, string url, long contentLength, long responseTime)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand(
                    "INSERT INTO directories (scan_id, url, path, status_code, content_length, response_time_ms) " +
                    "VALUES (@scanId, @url, @path, @status, @length, @time)", conn);

                cmd.Parameters.AddWithValue("@scanId", _scanId);
                cmd.Parameters.AddWithValue("@url", url);
                cmd.Parameters.AddWithValue("@path", result.Path);
                cmd.Parameters.AddWithValue("@status", Convert.ToInt32(result.Status));
                cmd.Parameters.AddWithValue("@length", contentLength);
                cmd.Parameters.AddWithValue("@time", responseTime);

                cmd.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving to database: {ex.Message}");
            }
        }

        private void SaveResultsToDatabase()
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand(
                    "UPDATE scans SET end_time = @endTime, scan_duration = @duration WHERE id = @scanId", conn);

                cmd.Parameters.AddWithValue("@endTime", DateTime.Now);
                cmd.Parameters.AddWithValue("@duration", _stopwatch.Elapsed.TotalSeconds);
                cmd.Parameters.AddWithValue("@scanId", _scanId);

                cmd.ExecuteNonQuery();

                Log($">>> RESULTS SAVED TO DATABASE (Scan ID: {_scanId})");
            }
            catch (Exception ex)
            {
                Log($">>> ERROR SAVING TO DATABASE: {ex.Message}");
            }
        }

        private int CalculateConfidence(string content, int statusCode)
        {
            int confidence = 70;

            if (statusCode == 200) confidence += 20;
            if (statusCode == 403 || statusCode == 401) confidence += 15;

            if (content.Length > 500) confidence += 10;
            if (content.Length > 2000) confidence += 5;

            if (content.Contains("<html") && content.Contains("<body>"))
                confidence += 5;

            if (content.Contains("div") || content.Contains("class="))
                confidence += 5;

            return Math.Min(95, confidence);
        }

        private void Export_Click(object sender, RoutedEventArgs e)
        {
            if (_results.Count == 0)
            {
                MessageBox.Show("No results to export.", "INFO", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "Text File (*.txt)|*.txt|CSV File (*.csv)|*.csv|JSON File (*.json)|*.json",
                    FileName = $"directory_scan_{_target}_{DateTime.Now:yyyyMMdd_HHmmss}"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    if (saveDialog.FileName.EndsWith(".json"))
                    {
                        var jsonBuilder = new StringBuilder();
                        jsonBuilder.AppendLine("[");
                        for (int i = 0; i < _results.Count; i++)
                        {
                            var result = _results[i];
                            jsonBuilder.AppendLine($"  {{");
                            jsonBuilder.AppendLine($"    \"status\": \"{result.Status}\",");
                            jsonBuilder.AppendLine($"    \"method\": \"{result.Method}\",");
                            jsonBuilder.AppendLine($"    \"path\": \"{result.Path}\",");
                            jsonBuilder.AppendLine($"    \"size\": \"{result.Length}\",");
                            jsonBuilder.AppendLine($"    \"time\": \"{result.ResponseTime}\",");
                            jsonBuilder.AppendLine($"    \"confidence\": {result.Confidence}");
                            jsonBuilder.AppendLine($"  }}" + (i < _results.Count - 1 ? "," : ""));
                        }
                        jsonBuilder.AppendLine("]");
                        File.WriteAllText(saveDialog.FileName, jsonBuilder.ToString());
                    }
                    else if (saveDialog.FileName.EndsWith(".csv"))
                    {
                        var sb = new StringBuilder();
                        sb.AppendLine("Status,Method,Path,Size,ResponseTime,Confidence");
                        foreach (var result in _results)
                        {
                            sb.AppendLine($"{result.Status},{result.Method},{result.Path.Replace(",", ";")},{result.Length},{result.ResponseTime},{result.Confidence}");
                        }
                        File.WriteAllText(saveDialog.FileName, sb.ToString());
                    }
                    else
                    {
                        var sb = new StringBuilder();
                        sb.AppendLine("DIRECTORY SCAN RESULTS");
                        sb.AppendLine($"Target: {TargetUrl.Text}");
                        sb.AppendLine($"Scan Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        sb.AppendLine($"Scan ID: {_scanId}");
                        sb.AppendLine($"Endpoints Found: {_results.Count}");
                        sb.AppendLine($"Total Requests: {_totalProcessed:N0}");
                        sb.AppendLine($"Scan Speed: {_totalProcessed / Math.Max(1, _stopwatch.Elapsed.TotalSeconds):F1} req/sec");
                        sb.AppendLine($"Elapsed Time: {_stopwatch.Elapsed:hh\\:mm\\:ss}");
                        sb.AppendLine(new string('=', 80));
                        sb.AppendLine();

                        foreach (var result in _results)
                        {
                            string statusIcon = result.Status == "200" ? "✅" :
                                              result.Status == "403" ? "🔒" :
                                              result.Status == "401" ? "🔐" : "↪️";

                            sb.AppendLine($"{statusIcon} [{result.Status}] {result.Method} {result.Path}");
                            sb.AppendLine($"  Size: {result.Length} | Time: {result.ResponseTime} | Confidence: {result.Confidence}%");
                            sb.AppendLine();
                        }

                        File.WriteAllText(saveDialog.FileName, sb.ToString());
                    }

                    Log($">>> RESULTS EXPORTED: {Path.GetFileName(saveDialog.FileName)}");
                    MessageBox.Show($"Results exported successfully!\n\nFile: {saveDialog.FileName}",
                        "EXPORT COMPLETE", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Log($">>> EXPORT ERROR: {ex.Message}");
                MessageBox.Show($"Failed to export results: {ex.Message}", "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public class FuzzResult
    {
        public string Status { get; set; }
        public string Method { get; set; }
        public string Path { get; set; }
        public string Length { get; set; }
        public string ResponseTime { get; set; }
        public int Confidence { get; set; }
    }
}
