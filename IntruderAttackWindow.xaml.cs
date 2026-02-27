using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ReconSuite
{
    public class StatusCodeToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is string statusCode)
            {
                if (statusCode.StartsWith("2")) return "#00FF41";
                if (statusCode.StartsWith("3")) return "#FFA500";
                if (statusCode.StartsWith("4")) return "#FF3131";
                if (statusCode.StartsWith("5")) return "#9B59B6";
                if (statusCode == "ERR") return "#FF3131";
            }
            return "#888888";
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public partial class IntruderAttackWindow : Window
    {
        public class AttackConfig
        {
            public string AttackType { get; set; }
            public string Template { get; set; }
            public string[] Payloads { get; set; }
            public string TargetUrl { get; set; }
            public int Threads { get; set; } = 15;
            public int Delay { get; set; } = 100;
            public bool FollowRedirects { get; set; } = true;
            public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        }

        public class AttackResult
        {
            public int RequestNumber { get; set; }
            public string Payload { get; set; }
            public string StatusCode { get; set; }
            public string StatusColor => GetStatusColor();
            public string ResponseTime { get; set; }
            public string Length { get; set; }
            public string ErrorMessage { get; set; }
            public string ErrorColor => string.IsNullOrEmpty(ErrorMessage) ? "#888888" : "#FF3131";
            public string FullRequest { get; set; }
            public string FullResponse { get; set; }
            public string TargetUrl { get; set; }
            public DateTime Timestamp { get; set; }
            public string RedirectLocation { get; set; }
            public string ContentType { get; set; }
            public bool IsRedirect => StatusCode.StartsWith("3");

            private string GetStatusColor()
            {
                if (StatusCode.StartsWith("2")) return "#00FF41";
                if (StatusCode.StartsWith("3")) return "#FFA500";
                if (StatusCode.StartsWith("4")) return "#FF3131";
                if (StatusCode.StartsWith("5")) return "#9B59B6";
                return "#888888";
            }
        }

        private AttackConfig _config;
        private CancellationTokenSource _cts;
        private bool _isRunning = false;
        private bool _isPaused = false;
        private int _completedRequests = 0;
        private int _successCount = 0;
        private int _errorCount = 0;
        private DateTime _startTime;
        private ObservableCollection<AttackResult> _results;
        private ObservableCollection<AttackResult> _filteredResults;
        private HttpClient _httpClient;
        private Stopwatch _stopwatch;
        private DispatcherTimer _statsTimer;

        private bool _show200 = true;
        private bool _show300 = true;
        private bool _show400 = true;
        private bool _show500 = true;
        private bool _showErrors = true;

        public IntruderAttackWindow(AttackConfig config)
        {
            try
            {
                InitializeComponent();
                _config = config;

                _results = new ObservableCollection<AttackResult>();
                _filteredResults = new ObservableCollection<AttackResult>();

                ResultsGrid.ItemsSource = _filteredResults;

                InitializeHttpClient();
                SetupTimers();

                Loaded += async (s, e) => await StartAttackAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to initialize attack window: {ex.Message}\n\n{ex.StackTrace}",
                    "Initialization Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Close();
            }
        }

        private string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }

        private void SetupTimers()
        {
            _statsTimer = new DispatcherTimer();
            _statsTimer.Interval = TimeSpan.FromMilliseconds(500);
            _statsTimer.Tick += UpdateStats;
            _stopwatch = new Stopwatch();
        }

        private void InitializeHttpClient()
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    UseProxy = false,
                    AllowAutoRedirect = _config.FollowRedirects,
                    AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
                };

                _httpClient = new HttpClient(handler)
                {
                    Timeout = TimeSpan.FromSeconds(30)
                };

                _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
                _httpClient.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");

                if (_config.Headers != null)
                {
                    foreach (var header in _config.Headers)
                    {
                        if (!string.IsNullOrEmpty(header.Key) && !string.IsNullOrEmpty(header.Value))
                        {
                            try
                            {
                                _httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to initialize HTTP client: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        private async Task StartAttackAsync()
        {
            if (_config == null)
            {
                MessageBox.Show("Attack configuration is null", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (_config.Payloads == null || _config.Payloads.Length == 0)
            {
                MessageBox.Show("No payloads configured", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(_config.TargetUrl))
            {
                MessageBox.Show("Target URL is not configured", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _cts = new CancellationTokenSource();
            _isRunning = true;
            _startTime = DateTime.Now;
            _stopwatch.Start();
            _statsTimer.Start();

            StatusText.Text = "Attack running...";
            PauseResumeBtn.IsEnabled = true;
            StopBtn.IsEnabled = true;

            try
            {
                await RunAttackAsync();
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "Attack cancelled by user";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show($"Attack failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _isRunning = false;
                _stopwatch.Stop();
                _statsTimer.Stop();

                PauseResumeBtn.Content = "⏸ PAUSE";
                PauseResumeBtn.IsEnabled = false;
                StopBtn.Content = "✓ DONE";

                StatusText.Text = $"Attack completed - {_completedRequests} requests processed";

                ShowAttackSummary();
            }
        }

        private async Task RunAttackAsync()
        {
            int totalPayloads = _config.Payloads.Length;
            var semaphore = new SemaphoreSlim(_config.Threads);
            var tasks = new List<Task>();

            for (int i = 0; i < totalPayloads; i++)
            {
                if (_cts.Token.IsCancellationRequested)
                    break;

                while (_isPaused && !_cts.Token.IsCancellationRequested)
                {
                    await Task.Delay(100);
                }

                await semaphore.WaitAsync(_cts.Token);

                int requestNum = i + 1;
                string payload = _config.Payloads[i];

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var result = await SendRequestAsync(requestNum, payload, _cts.Token);

                        await Dispatcher.InvokeAsync(() =>
                        {
                            try
                            {
                                _results.Add(result);

                                ApplyFilters();

                                _completedRequests++;
                                if (result.StatusCode.StartsWith("2"))
                                    _successCount++;
                                else if (!string.IsNullOrEmpty(result.ErrorMessage) || result.StatusCode == "ERR")
                                    _errorCount++;

                                CompletedText.Text = _completedRequests.ToString();
                                SuccessText.Text = _successCount.ToString();
                                ErrorsText.Text = _errorCount.ToString();
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"UI update error: {ex.Message}");
                            }
                        });
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Request {requestNum} failed: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, _cts.Token));

                if (_config.Delay > 0)
                {
                    await Task.Delay(_config.Delay, _cts.Token);
                }
            }

            await Task.WhenAll(tasks);
        }

        private async Task<AttackResult> SendRequestAsync(int requestNumber, string payload, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            string fullRequest = "";

            try
            {
                var (request, requestText) = BuildRequestFromTemplate(payload);
                fullRequest = requestText;

                using (var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                {
                    stopwatch.Stop();

                    string responseBody = await response.Content.ReadAsStringAsync();

                    var responseBuilder = new StringBuilder();
                    responseBuilder.AppendLine($"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}");

                    foreach (var header in response.Headers)
                        responseBuilder.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");

                    if (response.Content != null)
                    {
                        foreach (var header in response.Content.Headers)
                            responseBuilder.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");

                        responseBuilder.AppendLine();
                        responseBuilder.Append(responseBody);
                    }

                    string fullResponse = responseBuilder.ToString();

                    string redirectLocation = "";
                    if (response.StatusCode >= System.Net.HttpStatusCode.MovedPermanently &&
                        response.StatusCode <= System.Net.HttpStatusCode.PermanentRedirect)
                    {
                        if (response.Headers.Location != null)
                        {
                            redirectLocation = response.Headers.Location.ToString();
                        }
                    }

                    string contentType = "";
                    if (response.Content?.Headers?.ContentType != null)
                    {
                        contentType = response.Content.Headers.ContentType.MediaType;
                    }

                    long contentLength = response.Content?.Headers?.ContentLength ?? 0;
                    if (contentLength == 0) contentLength = responseBody.Length;

                    return new AttackResult
                    {
                        RequestNumber = requestNumber,
                        Payload = payload,
                        StatusCode = ((int)response.StatusCode).ToString(),
                        ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                        Length = FormatBytes(contentLength),
                        ErrorMessage = redirectLocation,
                        FullRequest = fullRequest,
                        FullResponse = fullResponse,
                        TargetUrl = request.RequestUri?.ToString() ?? "Unknown",
                        Timestamp = DateTime.Now,
                        RedirectLocation = redirectLocation,
                        ContentType = contentType
                    };
                }
            }
            catch (HttpRequestException httpEx)
            {
                stopwatch.Stop();

                return new AttackResult
                {
                    RequestNumber = requestNumber,
                    Payload = payload,
                    StatusCode = "ERR",
                    ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                    Length = "0 B",
                    ErrorMessage = $"HTTP Error: {httpEx.Message}",
                    FullRequest = fullRequest,
                    FullResponse = $"HTTP REQUEST ERROR: {httpEx.Message}",
                    TargetUrl = "",
                    Timestamp = DateTime.Now
                };
            }
            catch (TaskCanceledException)
            {
                stopwatch.Stop();

                return new AttackResult
                {
                    RequestNumber = requestNumber,
                    Payload = payload,
                    StatusCode = "ERR",
                    ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                    Length = "0 B",
                    ErrorMessage = "Request timeout",
                    FullRequest = fullRequest,
                    FullResponse = "REQUEST TIMEOUT",
                    TargetUrl = "",
                    Timestamp = DateTime.Now
                };
            }
            catch (Exception ex)
            {
                stopwatch.Stop();

                return new AttackResult
                {
                    RequestNumber = requestNumber,
                    Payload = payload,
                    StatusCode = "ERR",
                    ResponseTime = $"{stopwatch.ElapsedMilliseconds}ms",
                    Length = "0 B",
                    ErrorMessage = ex.Message,
                    FullRequest = fullRequest,
                    FullResponse = $"ERROR: {ex.Message}",
                    TargetUrl = "",
                    Timestamp = DateTime.Now
                };
            }
        }

        private (HttpRequestMessage request, string requestText) BuildRequestFromTemplate(string payload)
        {
            if (string.IsNullOrEmpty(_config.Template))
                throw new Exception("Template is empty");

            var template = _config.Template;
            var markerRegex = new Regex(@"§([^§]*)§");

            string processedTemplate = markerRegex.Replace(template, payload);

            var lines = processedTemplate.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            if (lines.Length < 2)
                throw new Exception("Invalid request template");

            var requestLine = lines[0].Split(' ');
            if (requestLine.Length < 3)
                throw new Exception("Invalid request line");

            string method = requestLine[0];
            string finalUrl = _config.TargetUrl;

            var request = new HttpRequestMessage(new HttpMethod(method), finalUrl);

            bool inHeaders = true;
            var bodyBuilder = new StringBuilder();

            for (int i = 1; i < lines.Length; i++)
            {
                if (string.IsNullOrWhiteSpace(lines[i]))
                {
                    inHeaders = false;
                    continue;
                }

                if (inHeaders)
                {
                    var colonIndex = lines[i].IndexOf(':');
                    if (colonIndex > 0)
                    {
                        string headerName = lines[i].Substring(0, colonIndex).Trim();
                        string headerValue = lines[i].Substring(colonIndex + 1).Trim();

                        if (headerName.Equals("Host", StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (!IsRestrictedHeader(headerName))
                        {
                            try
                            {
                                request.Headers.TryAddWithoutValidation(headerName, headerValue);
                            }
                            catch { }
                        }
                    }
                }
                else
                {
                    bodyBuilder.AppendLine(lines[i]);
                }
            }

            string body = bodyBuilder.ToString().Trim();
            if (!string.IsNullOrEmpty(body))
            {
                request.Content = new StringContent(body, Encoding.UTF8);
            }

            return (request, processedTemplate);
        }

        private bool IsRestrictedHeader(string headerName)
        {
            string[] restricted = {
                "Host", "Connection", "Content-Length",
                "Transfer-Encoding", "Upgrade", "Expect"
            };

            return restricted.Any(h => h.Equals(headerName, StringComparison.OrdinalIgnoreCase));
        }

        private void UpdateStats(object sender, EventArgs e)
        {
            try
            {
                if (!_isRunning) return;

                double progress = _config.Payloads.Length > 0 ?
                    (_completedRequests * 100.0 / _config.Payloads.Length) : 0;

                ProgressBar.Value = progress;
                ProgressText.Text = $"{progress:F1}%";

                if (_stopwatch.IsRunning && _stopwatch.Elapsed.TotalSeconds > 0)
                {
                    double rps = _completedRequests / _stopwatch.Elapsed.TotalSeconds;
                    ReqPerSecText.Text = $"{rps:F1}";
                }

                ElapsedTimeText.Text = _stopwatch.Elapsed.ToString(@"hh\:mm\:ss");

                if (_isPaused)
                    StatusText.Text = "PAUSED";
                else
                    StatusText.Text = $"Running... ({_completedRequests}/{_config.Payloads.Length})";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Stats update error: {ex.Message}");
            }
        }

        private string FormatBytes(long bytes)
        {
            try
            {
                string[] suffixes = { "B", "KB", "MB", "GB" };
                int suffixIndex = 0;
                double size = bytes;

                while (size >= 1024 && suffixIndex < suffixes.Length - 1)
                {
                    size /= 1024;
                    suffixIndex++;
                }

                return $"{size:0.##} {suffixes[suffixIndex]}";
            }
            catch
            {
                return "0 B";
            }
        }

        private void PauseResumeBtn_Click(object sender, RoutedEventArgs e)
        {
            _isPaused = !_isPaused;
            PauseResumeBtn.Content = _isPaused ? "▶ RESUME" : "⏸ PAUSE";
            StatusText.Text = _isPaused ? "PAUSED" : "RUNNING";
        }

        private void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            _isRunning = false;
        }

        private void ViewDetailsBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Button btn && btn.Tag is AttackResult result)
                {
                    RequestPreview.Text = result.FullRequest ?? "";
                    ResponsePreview.Text = result.FullResponse ?? "";
                    ResponseInfoText.Text = $"Status: {result.StatusCode} | Time: {result.ResponseTime} | Size: {result.Length}";

                    if (result.IsRedirect && !string.IsNullOrEmpty(result.RedirectLocation))
                    {
                        ResponseInfoText.Text += $" | Redirect: {result.RedirectLocation}";
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error viewing details: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyRequestBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Button btn && btn.Tag is AttackResult result)
                {
                    Clipboard.SetText(result.FullRequest ?? "");
                    StatusText.Text = $"Copied request #{result.RequestNumber} to clipboard";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying request: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ResendBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is Button btn && btn.Tag is AttackResult result)
                {
                    var newResult = await SendRequestAsync(result.RequestNumber, result.Payload, CancellationToken.None);

                    int index = _results.IndexOf(result);
                    if (index >= 0)
                    {
                        _results[index] = newResult;
                        ApplyFilters();
                    }

                    StatusText.Text = $"Re-tested request #{result.RequestNumber}";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error re-testing: {ex.Message}";
            }
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_results == null || _results.Count == 0)
                {
                    MessageBox.Show("No results to export", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var dialog = new SaveFileDialog
                {
                    Filter = "CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|HTML Report (*.html)|*.html",
                    FileName = $"intruder_attack_{DateTime.Now:yyyyMMdd_HHmmss}",
                    DefaultExt = ".csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    if (dialog.FileName.EndsWith(".csv"))
                    {
                        ExportToCsv(dialog.FileName);
                    }
                    else if (dialog.FileName.EndsWith(".json"))
                    {
                        ExportToJson(dialog.FileName);
                    }
                    else if (dialog.FileName.EndsWith(".html"))
                    {
                        ExportToHtml(dialog.FileName);
                    }

                    MessageBox.Show($"Results exported successfully to:\n{dialog.FileName}",
                        "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportToCsv(string filePath)
        {
            try
            {
                using (var writer = new StreamWriter(filePath))
                {
                    writer.WriteLine("RequestNumber,Payload,StatusCode,ResponseTime,Length,ErrorMessage,RedirectLocation,Timestamp");

                    foreach (var result in _results)
                    {
                        writer.WriteLine($"{result.RequestNumber},\"{EscapeCsv(result.Payload)}\",{result.StatusCode},{result.ResponseTime},{result.Length},\"{EscapeCsv(result.ErrorMessage)}\",\"{EscapeCsv(result.RedirectLocation)}\",{result.Timestamp:yyyy-MM-dd HH:mm:ss}");
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"CSV export error: {ex.Message}", ex);
            }
        }

        private string EscapeCsv(string text)
        {
            if (text == null) return "";
            return text.Replace("\"", "\"\"");
        }

        private void ExportToJson(string filePath)
        {
            try
            {
                var exportData = new
                {
                    AttackConfig = _config,
                    Results = _results.ToList(),
                    Summary = new
                    {
                        TotalRequests = _completedRequests,
                        SuccessCount = _successCount,
                        ErrorCount = _errorCount,
                        ElapsedTime = _stopwatch.Elapsed.ToString(),
                        AverageTimePerRequest = _completedRequests > 0 ? _stopwatch.Elapsed.TotalMilliseconds / _completedRequests : 0
                    }
                };

                string json = JsonConvert.SerializeObject(exportData, Formatting.Indented);
                File.WriteAllText(filePath, json);
            }
            catch (Exception ex)
            {
                throw new Exception($"JSON export error: {ex.Message}", ex);
            }
        }

        private void ExportToHtml(string filePath)
        {
            try
            {
                var html = new StringBuilder();
                html.AppendLine("<!DOCTYPE html>");
                html.AppendLine("<html>");
                html.AppendLine("<head>");
                html.AppendLine("<title>Vrax Intruder Attack Report</title>");
                html.AppendLine("<style>");
                html.AppendLine("body { font-family: Consolas, monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }");
                html.AppendLine("h1 { color: #00ff41; border-bottom: 2px solid #00ff41; padding-bottom: 10px; }");
                html.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 20px; }");
                html.AppendLine("th { background: #050505; color: #00ff41; padding: 12px; border: 1px solid #00ff41; text-align: left; }");
                html.AppendLine("td { padding: 10px; border: 1px solid #333; }");
                html.AppendLine(".status-2xx { color: #00ff41; font-weight: bold; }");
                html.AppendLine(".status-3xx { color: #ffa500; font-weight: bold; }");
                html.AppendLine(".status-4xx { color: #ff3131; font-weight: bold; }");
                html.AppendLine(".status-5xx { color: #9b59b6; font-weight: bold; }");
                html.AppendLine(".status-err { color: #ff3131; font-weight: bold; }");
                html.AppendLine("</style>");
                html.AppendLine("</head>");
                html.AppendLine("<body>");

                html.AppendLine($"<h1>⚔ Vrax Intruder Attack Report</h1>");
                html.AppendLine($"<p><strong>Generated:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
                html.AppendLine($"<p><strong>Target:</strong> {_config.TargetUrl}</p>");
                html.AppendLine($"<p><strong>Attack Type:</strong> {_config.AttackType}</p>");
                html.AppendLine($"<p><strong>Payloads:</strong> {_config.Payloads.Length}</p>");
                html.AppendLine($"<p><strong>Completed:</strong> {_completedRequests}</p>");
                html.AppendLine($"<p><strong>Success (2xx):</strong> {_successCount}</p>");
                html.AppendLine($"<p><strong>Errors:</strong> {_errorCount}</p>");
                html.AppendLine($"<p><strong>Elapsed Time:</strong> {_stopwatch.Elapsed.ToString(@"hh\:mm\:ss")}</p>");

                html.AppendLine("<table>");
                html.AppendLine("<tr><th>#</th><th>Payload</th><th>Status</th><th>Time</th><th>Size</th><th>Notes</th></tr>");

                foreach (var result in _results)
                {
                    string statusClass = "";
                    if (result.StatusCode.StartsWith("2")) statusClass = "status-2xx";
                    else if (result.StatusCode.StartsWith("3")) statusClass = "status-3xx";
                    else if (result.StatusCode.StartsWith("4")) statusClass = "status-4xx";
                    else if (result.StatusCode.StartsWith("5")) statusClass = "status-5xx";
                    else statusClass = "status-err";

                    html.AppendLine($"<tr>");
                    html.AppendLine($"<td>{result.RequestNumber}</td>");
                    html.AppendLine($"<td>{result.Payload}</td>");
                    html.AppendLine($"<td class='{statusClass}'>{result.StatusCode}</td>");
                    html.AppendLine($"<td>{result.ResponseTime}</td>");
                    html.AppendLine($"<td>{result.Length}</td>");
                    html.AppendLine($"<td>{result.ErrorMessage}</td>");
                    html.AppendLine("</tr>");
                }

                html.AppendLine("</table>");
                html.AppendLine("</body>");
                html.AppendLine("</html>");

                File.WriteAllText(filePath, html.ToString());
            }
            catch (Exception ex)
            {
                throw new Exception($"HTML export error: {ex.Message}", ex);
            }
        }

        private void ClearBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (MessageBox.Show("Clear all attack results?", "Confirm Clear",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    _results?.Clear();
                    _filteredResults?.Clear();
                    RequestPreview.Clear();
                    ResponsePreview.Clear();
                    StatusText.Text = "Results cleared";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error clearing results: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BeautifyJsonBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string response = ResponsePreview.Text;

                if (string.IsNullOrEmpty(response))
                {
                    StatusText.Text = "No response to format";
                    return;
                }

                int jsonStart = response.IndexOf('{');
                if (jsonStart == -1) jsonStart = response.IndexOf('[');

                if (jsonStart >= 0)
                {
                    string beforeJson = response.Substring(0, jsonStart);
                    string jsonPart = response.Substring(jsonStart);

                    try
                    {
                        var parsed = JToken.Parse(jsonPart);
                        string beautified = parsed.ToString(Formatting.Indented);
                        ResponsePreview.Text = beforeJson + beautified;
                        StatusText.Text = "JSON formatted";
                    }
                    catch (JsonException)
                    {
                        StatusText.Text = "Invalid JSON format";
                    }
                }
                else
                {
                    StatusText.Text = "No JSON found in response";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Format error: {ex.Message}";
            }
        }

        private void BeautifyHtmlBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string response = ResponsePreview.Text;

                if (string.IsNullOrEmpty(response))
                {
                    StatusText.Text = "No response to format";
                    return;
                }

                if (response.Contains("<html") || response.Contains("<!DOCTYPE"))
                {
                    response = response
                        .Replace("><", ">\n<")
                        .Replace("/>", "/>\n")
                        .Replace("</", "\n</")
                        .Replace("\r", "");

                    ResponsePreview.Text = response;
                    StatusText.Text = "HTML formatted";
                }
                else
                {
                    StatusText.Text = "No HTML found in response";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Format error: {ex.Message}";
            }
        }

        private void CopyRequestPreview_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(RequestPreview.Text))
                {
                    Clipboard.SetText(RequestPreview.Text);
                    StatusText.Text = "Request copied to clipboard";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying request: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyResponsePreview_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!string.IsNullOrEmpty(ResponsePreview.Text))
                {
                    Clipboard.SetText(ResponsePreview.Text);
                    StatusText.Text = "Response copied to clipboard";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying response: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                if (ResultsGrid.SelectedItem is AttackResult result)
                {
                    RequestPreview.Text = result.FullRequest ?? "";
                    ResponsePreview.Text = result.FullResponse ?? "";
                    ResponseInfoText.Text = $"Status: {result.StatusCode} | Time: {result.ResponseTime} | Size: {result.Length}";

                    if (result.IsRedirect && !string.IsNullOrEmpty(result.RedirectLocation))
                    {
                        ResponseInfoText.Text += $" | Redirect: {result.RedirectLocation}";
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Selection changed error: {ex.Message}");
            }
        }

        private void ResultsGrid_LoadingRow(object sender, DataGridRowEventArgs e)
        {
            try
            {
                if (e.Row.Item is AttackResult result)
                {
                    if (result.StatusCode.StartsWith("2"))
                        e.Row.Background = new SolidColorBrush(Color.FromArgb(20, 0, 255, 65));
                    else if (result.StatusCode.StartsWith("3"))
                        e.Row.Background = new SolidColorBrush(Color.FromArgb(20, 255, 165, 0));
                    else if (result.StatusCode.StartsWith("4"))
                        e.Row.Background = new SolidColorBrush(Color.FromArgb(20, 255, 49, 49));
                    else if (result.StatusCode.StartsWith("5"))
                        e.Row.Background = new SolidColorBrush(Color.FromArgb(20, 155, 89, 182));
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Row loading error: {ex.Message}");
            }
        }

        private void ShowAttackSummary()
        {
            try
            {
                int redirectCount = _results?.Count(r => r.StatusCode.StartsWith("3")) ?? 0;
                int clientErrorCount = _results?.Count(r => r.StatusCode.StartsWith("4")) ?? 0;
                int serverErrorCount = _results?.Count(r => r.StatusCode.StartsWith("5")) ?? 0;

                string summary = $"⚔ ATTACK COMPLETE!\n\n" +
                               $"Total Payloads: {_config.Payloads.Length}\n" +
                               $"Processed: {_completedRequests}\n" +
                               $"Success (2xx): {_successCount}\n" +
                               $"Redirects (3xx): {redirectCount}\n" +
                               $"Client Errors (4xx): {clientErrorCount}\n" +
                               $"Server Errors (5xx): {serverErrorCount}\n" +
                               $"Other Errors: {_errorCount}\n" +
                               $"Elapsed Time: {_stopwatch.Elapsed.ToString(@"hh\:mm\:ss")}\n" +
                               $"Average RPS: {(_completedRequests / Math.Max(_stopwatch.Elapsed.TotalSeconds, 1)):F1}";

                MessageBox.Show(summary, "Attack Summary", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error showing summary: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                var glowEffect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = Color.FromRgb(0, 255, 65),
                    BlurRadius = 25,
                    ShadowDepth = 0,
                    Opacity = 0.6
                };

                var header = this.FindName("AttackInfoText") as TextBlock;
                if (header != null)
                {
                    header.Effect = glowEffect;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Window loaded error: {ex.Message}");
            }
        }

        private void Filter_Changed(object sender, RoutedEventArgs e)
        {
            try
            {
                if (sender is CheckBox checkBox)
                {
                    string content = checkBox.Content.ToString();

                    if (content.Contains("200")) _show200 = checkBox.IsChecked == true;
                    else if (content.Contains("3xx")) _show300 = checkBox.IsChecked == true;
                    else if (content.Contains("4xx")) _show400 = checkBox.IsChecked == true;
                    else if (content.Contains("5xx")) _show500 = checkBox.IsChecked == true;
                    else if (content.Contains("ERRORS")) _showErrors = checkBox.IsChecked == true;

                    ApplyFilters();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Filter changed error: {ex.Message}");
            }
        }

        private void ApplyFilters()
        {
            try
            {
                if (_filteredResults == null || _results == null)
                    return;

                _filteredResults.Clear();

                foreach (var result in _results)
                {
                    if (ShouldShowResult(result))
                    {
                        _filteredResults.Add(result);
                    }
                }

                ResultsGrid.Items.Refresh();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Apply filters error: {ex.Message}");
            }
        }

        private bool ShouldShowResult(AttackResult result)
        {
            if (result == null) return false;

            if (result.StatusCode.StartsWith("2") && !_show200) return false;
            if (result.StatusCode.StartsWith("3") && !_show300) return false;
            if (result.StatusCode.StartsWith("4") && !_show400) return false;
            if (result.StatusCode.StartsWith("5") && !_show500) return false;
            if (result.StatusCode == "ERR" && !_showErrors) return false;

            return true;
        }
    }
}