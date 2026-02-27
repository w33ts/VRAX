using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using System.Windows.Controls;

namespace VRAX
{
    public partial class VanguardScanner : Window
    {
        private ProductionScannerEngine _engine;
        private CancellationTokenSource _cancellationTokenSource;
        private int _totalRequests = 0;
        private DispatcherTimer _statsTimer;
        private bool _userAuthorizedScan = false;
        private DateTime? _authorizationTimestamp = null;
        private string _authorizationUser = "";

        public VanguardScanner()
        {
            InitializeComponent(); 

            InitializeEngine();
            SetupDataBindings();
            StartStatsTimer();
        }



        private void InitializeEngine()
        {
            var config = new ScannerConfiguration
            {
                TlsValidationMode = TlsValidationMode.Strict,
                ScopeEnforcement = ScopeEnforcement.Strict,
                RateLimitRequestsPerSecond = 10,
                MaxConcurrentRequests = 5,
                RequestBudget = 10000,
                EnableOutOfBandTesting = false,
                EnableBlindInjectionTesting = false,
                EnableCloudMetadataTesting = false,
                EnableAuthenticationTesting = false,
                EnableComponentAnalysis = true,
                EnableCryptographicTesting = true,
                EnableSecurityHeaderAnalysis = true
            };

            _engine = new ProductionScannerEngine(config);
            _engine.RequestLogged += OnRequestLogged;
            _engine.VulnerabilityFound += OnVulnerabilityFound;
            _engine.ProgressUpdated += OnProgressUpdated;
            _engine.LogMessage += OnLogMessage;
            _engine.StatsUpdated += OnStatsUpdated;
            _engine.ScopeViolationDetected += OnScopeViolationDetected;
            _engine.ServerInstabilityDetected += OnServerInstabilityDetected;
            _engine.ScanAuthorizationRequired += OnScanAuthorizationRequired;
        }

        private void SetupDataBindings()
        {
            BindingOperations.EnableCollectionSynchronization(_engine.RequestLogs, _engine.RequestLogs);
            BindingOperations.EnableCollectionSynchronization(_engine.Vulnerabilities, _engine.Vulnerabilities);
            BindingOperations.EnableCollectionSynchronization(_engine.InjectionFindings, _engine.InjectionFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.XssFindings, _engine.XssFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.AccessControlFindings, _engine.AccessControlFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.SsrfFindings, _engine.SsrfFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.MisconfigFindings, _engine.MisconfigFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.CryptoFindings, _engine.CryptoFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.ComponentFindings, _engine.ComponentFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.DesignFindings, _engine.DesignFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.IntegrityFindings, _engine.IntegrityFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.LoggingFindings, _engine.LoggingFindings);
            BindingOperations.EnableCollectionSynchronization(_engine.AuthFindings, _engine.AuthFindings);

            RequestsGrid.ItemsSource = _engine.RequestLogs;
            VulnGrid.ItemsSource = _engine.Vulnerabilities;
            InjectionList.ItemsSource = _engine.InjectionFindings;
            XssList.ItemsSource = _engine.XssFindings;
            AccessControlList.ItemsSource = _engine.AccessControlFindings;
            SsrfList.ItemsSource = _engine.SsrfFindings;
            MisconfigList.ItemsSource = _engine.MisconfigFindings;
            CryptoList.ItemsSource = _engine.CryptoFindings;
            ComponentsList.ItemsSource = _engine.ComponentFindings;
            DesignList.ItemsSource = _engine.DesignFindings;
            IntegrityList.ItemsSource = _engine.IntegrityFindings;
            LoggingList.ItemsSource = _engine.LoggingFindings;
            IdentificationList.ItemsSource = _engine.AuthFindings;
        }

        private void StartStatsTimer()
        {
            _statsTimer = new DispatcherTimer();
            _statsTimer.Interval = TimeSpan.FromSeconds(2);
            _statsTimer.Tick += (s, e) => UpdateRealTimeStats();
            _statsTimer.Start();
        }

        private void UpdateRealTimeStats()
        {
            if (_engine != null)
            {
                Dispatcher.Invoke(() =>
                {
                    var stats = _engine.RealTimeStats;
                    StatusText.Text = $"🔒 {stats.TotalRequests} REQS | {stats.VulnerabilitiesFound} VULNS | {stats.RequestsPerSecond:0.0}/s | {stats.ScopeViolations} BLOCKED";
                    if (stats.ServerHealthStatus != ServerHealthStatus.Normal)
                    {
                        StatusText.Text += $" | ⚠️ {stats.ServerHealthStatus}";
                    }
                });
            }
        }

        private async void StartScanBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!_userAuthorizedScan)
                {
                    var authDialog = new SimpleAuthorizationDialog();
                    if (authDialog.ShowDialog() == true)
                    {
                        _userAuthorizedScan = true;
                        _authorizationTimestamp = DateTime.Now;
                        _authorizationUser = authDialog.UserName;
                        _engine.SetAuthorizationRecord(_authorizationUser, _authorizationTimestamp.Value);
                    }
                    else
                    {
                        Log("❌ Scan authorization required. Scan cancelled.");
                        return;
                    }
                }

                var targetUrl = TargetUrl.Text.Trim();
                if (string.IsNullOrEmpty(targetUrl) || !Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri))
                {
                    Log("❌ Invalid target URL. Please enter a valid URL (e.g., https://example.com)");
                    return;
                }

                var scopeDialog = new SimpleScopeDialog(uri);
                if (scopeDialog.ShowDialog() == true)
                {
                    _engine.SetScanScope(scopeDialog.AllowedDomains, scopeDialog.AllowedCidrs);
                }
                else
                {
                    Log("❌ Scope configuration required. Scan cancelled.");
                    return;
                }

                Log($"🚀 Starting enterprise security scan against: {targetUrl}");
                Log($"📋 Scope: {string.Join(", ", _engine.CurrentScope.Domains)}");
                Log($"🔐 TLS Mode: {_engine.Configuration.TlsValidationMode}");
                Log($"👤 Authorized by: {_authorizationUser} at {_authorizationTimestamp:yyyy-MM-dd HH:mm:ss}");

                StatusText.Text = "INITIALIZING...";
                StartScanBtn.IsEnabled = false;
                StopScanBtn.IsEnabled = true;
                OverallProgress.Value = 0;
                _totalRequests = 0;

                _engine.ClearResults();

                _cancellationTokenSource = new CancellationTokenSource();
                await _engine.StartProductionScanAsync(targetUrl, _cancellationTokenSource.Token);
            }
            catch (Exception ex)
            {
                Log($"💥 Scan initialization failed: {ex.Message}");
                StartScanBtn.IsEnabled = true;
                StopScanBtn.IsEnabled = false;
            }
        }

        private void StopScanBtn_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            StatusText.Text = "STOPPED";
            StartScanBtn.IsEnabled = true;
            StopScanBtn.IsEnabled = false;
            Log("🛑 Scan terminated by user");
        }

        private void OnScopeViolationDetected(object sender, ScopeViolation violation)
        {
            Dispatcher.Invoke(() =>
            {
                Log($"🚫 SCOPE VIOLATION: {violation.RequestedUrl} - {violation.Reason}");


            });
        }

        private void OnServerInstabilityDetected(object sender, ServerHealthStatus status)
        {
            Dispatcher.Invoke(() =>
            {
                Log($"⚠️ SERVER HEALTH: {status} - Rate limiting adjusted");
                if (status == ServerHealthStatus.Critical)
                {
                    Log("🛑 Auto-pausing scan due to critical server instability");
                    StopScanBtn_Click(null, null);
                }
            });
        }

        private void OnScanAuthorizationRequired(object sender, EventArgs e)
        {
            Dispatcher.Invoke(() =>
            {
                var result = MessageBox.Show("Additional authorization required for sensitive tests. Continue?", "Authorization Required", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    _engine.ContinueWithAuthorization();
                }
                else
                {
                    _engine.SkipSensitiveTests();
                }
            });
        }

        private void OnRequestLogged(object sender, RequestLogEntry entry)
        {
            Dispatcher.Invoke(() =>
            {
                _totalRequests++;
                _engine.RequestLogs.Add(entry);
            });
        }

        private void OnVulnerabilityFound(object sender, Vulnerability vulnerability)
        {
            Dispatcher.Invoke(() =>
            {
                if (vulnerability.Confidence < _engine.Configuration.MinimumConfidenceThreshold)
                {
                    Log($"🔍 Low confidence finding filtered: {vulnerability.Type} ({vulnerability.Confidence}%)");
                    return;
                }

                _engine.Vulnerabilities.Add(vulnerability);
                FoundCount.Text = _engine.Vulnerabilities.Count.ToString();

                switch (vulnerability.OWASPCategory)
                {
                    case "A01:2021-Broken Access Control":
                        _engine.AccessControlFindings.Add(vulnerability);
                        break;
                    case "A03:2021-Injection":
                        _engine.InjectionFindings.Add(vulnerability);
                        break;
                    case "A07:2021-XSS":
                        _engine.XssFindings.Add(vulnerability);
                        break;
                    case "A10:2021-SSRF":
                        _engine.SsrfFindings.Add(vulnerability);
                        break;
                    case "A05:2021-Security Misconfiguration":
                        _engine.MisconfigFindings.Add(vulnerability);
                        break;
                    case "A02:2021-Cryptographic Failures":
                        _engine.CryptoFindings.Add(vulnerability);
                        break;
                    case "A06:2021-Vulnerable Components":
                        _engine.ComponentFindings.Add(vulnerability);
                        break;
                    case "A04:2021-Insecure Design":
                        _engine.DesignFindings.Add(vulnerability);
                        break;
                    case "A08:2021-Software and Data Integrity":
                        _engine.IntegrityFindings.Add(vulnerability);
                        break;
                    case "A09:2021-Security Logging":
                        _engine.LoggingFindings.Add(vulnerability);
                        break;
                    case "A07:2021-Identification and Authentication Failures":
                        _engine.AuthFindings.Add(vulnerability);
                        break;
                }

                Log($"🔴 VULNERABILITY: {vulnerability.Type} | {vulnerability.Severity} ({vulnerability.Confidence}%) | {vulnerability.Url}");
            });
        }

        private void OnProgressUpdated(object sender, ProgressUpdate progress)
        {
            Dispatcher.Invoke(() =>
            {
                OverallProgress.Value = progress.Percentage;
                ProgressText.Text = $"{progress.Percentage}% - {progress.Status}";
            });
        }

        private void OnStatsUpdated(object sender, ScanStatistics stats)
        {
            Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"🔒 {stats.TotalRequests} REQS | {stats.VulnerabilitiesFound} VULNS | {stats.RequestsPerSecond:0.0}/s | {stats.ScopeViolations} BLOCKED";
            });
        }

        private void OnLogMessage(object sender, string message)
        {
            Log(message);
        }

        private void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogConsole.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\n");
                LogConsole.ScrollToEnd();
            });
        }

        private void ExportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_engine.Vulnerabilities.Count == 0)
                {
                    var result = MessageBox.Show("No vulnerabilities found. Generate report anyway?", "No Findings", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (result != MessageBoxResult.Yes) return;
                }

                var reportDialog = new SimpleReportDialog();
                if (reportDialog.ShowDialog() == true)
                {
                    var report = _engine.GenerateEnterpriseReport(reportDialog.IncludeExecutiveSummary, reportDialog.IncludeTechnicalDetails, reportDialog.IncludeScanMetadata);
                    var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    var fileName = $"enterprise_security_report_{timestamp}.json";

                    File.WriteAllText(fileName, report.JsonReport);
                    Log($"📁 JSON report exported: {Path.GetFullPath(fileName)}");

                    if (reportDialog.GenerateHtmlReport)
                    {
                        var htmlReport = _engine.GenerateHtmlReport(reportDialog.IncludeExecutiveSummary);
                        var htmlFileName = fileName.Replace(".json", ".html");
                        File.WriteAllText(htmlFileName, htmlReport);
                        Log($"📊 HTML report generated: {htmlFileName}");

                        if (reportDialog.OpenAfterGeneration)
                        {
                            System.Diagnostics.Process.Start(new ProcessStartInfo
                            {
                                FileName = htmlFileName,
                                UseShellExecute = true
                            });
                        }
                    }

                    if (reportDialog.GenerateCoverageMatrix)
                    {
                        var coverage = _engine.GenerateCoverageMatrix();
                        var coverageFileName = fileName.Replace(".json", "_coverage.md");
                        File.WriteAllText(coverageFileName, coverage);
                        Log($"📈 Coverage matrix generated: {coverageFileName}");
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"❌ Export failed: {ex.Message}");
            }
        }

        private void SettingsBtn_Click(object sender, RoutedEventArgs e)
        {
            var settings = new SimpleSettingsDialog(_engine.Configuration);
            if (settings.ShowDialog() == true)
            {
                _engine.UpdateConfiguration(settings.Configuration);
                Log($"⚙️ Configuration updated: TLS={settings.Configuration.TlsValidationMode}, RateLimit={settings.Configuration.RateLimitRequestsPerSecond}/s");
            }
        }

        private void ViewCoverageMatrix_Click(object sender, RoutedEventArgs e)
        {
            var coverage = _engine.GenerateCoverageMatrix();
            var dialog = new SimpleTextDialog("Scanner Coverage Matrix", coverage);
            dialog.ShowDialog();
        }

        private void ViewAuthorization_Click(object sender, RoutedEventArgs e)
        {
            if (_authorizationTimestamp.HasValue)
            {
                MessageBox.Show($"Scan authorized by: {_authorizationUser}\nTimestamp: {_authorizationTimestamp:yyyy-MM-dd HH:mm:ss.fff}\nScope: {string.Join(", ", _engine.CurrentScope?.Domains?.ToList() ?? new List<string>())}", "Authorization Record", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("No authorization record found.", "Authorization Record", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void RequestsGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (RequestsGrid.SelectedItem is RequestLogEntry entry)
            {
                Dispatcher.Invoke(() =>
                {
                    RequestDetails.Text = entry.RequestDetails;
                    ResponseDetails.Text = entry.ResponseDetails;
                });
            }
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void CloseBtn_Click(object sender, RoutedEventArgs e) => Close();
        private void ClearLogsBtn_Click(object sender, RoutedEventArgs e) => LogConsole.Clear();
        private void CopyLogsBtn_Click(object sender, RoutedEventArgs e) => Clipboard.SetText(LogConsole.Text);
    }

    public class SimpleAuthorizationDialog : Window
    {
        public string UserName { get; set; } = "Security Analyst";
        private TextBox UserNameBox;
        private CheckBox AgreeCheck;
        private Button OkButton;
        private Button CancelButton;

        public SimpleAuthorizationDialog()
        {
            Width = 600;
            Height = 400;
            Title = "Scan Authorization";
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var stack = new StackPanel { Margin = new Thickness(20) };

            var warning = new TextBlock
            {
                Text = "⚠️ LEGAL WARNING\nYou must have explicit written authorization to scan the target system.\nUnauthorized scanning is illegal and unethical.",
                Foreground = System.Windows.Media.Brushes.Red,
                FontWeight = FontWeights.Bold,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(warning);

            var nameLabel = new TextBlock { Text = "Your Name:", Margin = new Thickness(0, 10, 0, 5) };
            stack.Children.Add(nameLabel);

            UserNameBox = new TextBox { Text = UserName, Margin = new Thickness(0, 0, 0, 10) };
            stack.Children.Add(UserNameBox);

            AgreeCheck = new CheckBox
            {
                Content = "I have explicit authorization to scan the target system",
                Margin = new Thickness(0, 10, 0, 20)
            };
            stack.Children.Add(AgreeCheck);

            var buttonStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            OkButton = new Button { Content = "Authorize", IsEnabled = false, Width = 80, Margin = new Thickness(5) };
            OkButton.Click += (s, e) => { DialogResult = true; Close(); };
            buttonStack.Children.Add(OkButton);

            CancelButton = new Button { Content = "Cancel", Width = 80, Margin = new Thickness(5) };
            CancelButton.Click += (s, e) => { DialogResult = false; Close(); };
            buttonStack.Children.Add(CancelButton);

            AgreeCheck.Checked += (s, e) => OkButton.IsEnabled = true;
            AgreeCheck.Unchecked += (s, e) => OkButton.IsEnabled = false;

            stack.Children.Add(buttonStack);
            Content = stack;
        }
    }

    public class SimpleScopeDialog : Window
    {
        public List<string> AllowedDomains { get; set; } = new List<string>();
        public List<string> AllowedCidrs { get; set; } = new List<string>();
        private Uri BaseUri;
        private TextBox DomainBox;
        private TextBox CidrBox;

        public SimpleScopeDialog(Uri baseUri)
        {
            BaseUri = baseUri;
            Width = 500;
            Height = 400;
            Title = "Scan Scope Configuration";
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var stack = new StackPanel { Margin = new Thickness(20) };

            var warning = new TextBlock
            {
                Text = "Configure the scanning scope. The scanner will only test URLs within this scope.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(warning);

            var domainLabel = new TextBlock { Text = "Allowed Domains (comma-separated):", Margin = new Thickness(0, 10, 0, 5) };
            stack.Children.Add(domainLabel);

            DomainBox = new TextBox
            {
                Text = baseUri.Host,
                Height = 60,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(DomainBox);

            var cidrLabel = new TextBlock { Text = "Allowed CIDR Ranges (optional, comma-separated):", Margin = new Thickness(0, 10, 0, 5) };
            stack.Children.Add(cidrLabel);

            CidrBox = new TextBox
            {
                Height = 40,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 20)
            };
            stack.Children.Add(CidrBox);

            var buttonStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var okButton = new Button { Content = "OK", Width = 80, Margin = new Thickness(5) };
            okButton.Click += (s, e) =>
            {
                AllowedDomains = DomainBox.Text.Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(d => d.Trim())
                    .Where(d => !string.IsNullOrEmpty(d))
                    .ToList();

                AllowedCidrs = CidrBox.Text.Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(c => c.Trim())
                    .Where(c => !string.IsNullOrEmpty(c))
                    .ToList();

                DialogResult = true;
                Close();
            };
            buttonStack.Children.Add(okButton);

            var cancelButton = new Button { Content = "Cancel", Width = 80, Margin = new Thickness(5) };
            cancelButton.Click += (s, e) => { DialogResult = false; Close(); };
            buttonStack.Children.Add(cancelButton);

            stack.Children.Add(buttonStack);
            Content = stack;
        }
    }

    public class SimpleReportDialog : Window
    {
        public bool IncludeExecutiveSummary { get; set; } = true;
        public bool IncludeTechnicalDetails { get; set; } = true;
        public bool IncludeScanMetadata { get; set; } = true;
        public bool GenerateHtmlReport { get; set; } = true;
        public bool GenerateCoverageMatrix { get; set; } = true;
        public bool OpenAfterGeneration { get; set; } = true;

        private CheckBox ExecSummaryCheck;
        private CheckBox TechDetailsCheck;
        private CheckBox MetadataCheck;
        private CheckBox HtmlCheck;
        private CheckBox CoverageCheck;
        private CheckBox OpenCheck;

        public SimpleReportDialog()
        {
            Width = 400;
            Height = 350;
            Title = "Report Configuration";
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var stack = new StackPanel { Margin = new Thickness(20) };

            var label = new TextBlock
            {
                Text = "Select report options:",
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(label);

            ExecSummaryCheck = new CheckBox
            {
                Content = "Include Executive Summary",
                IsChecked = IncludeExecutiveSummary,
                Margin = new Thickness(0, 5, 0, 5)
            };
            ExecSummaryCheck.Checked += (s, e) => IncludeExecutiveSummary = true;
            ExecSummaryCheck.Unchecked += (s, e) => IncludeExecutiveSummary = false;
            stack.Children.Add(ExecSummaryCheck);

            TechDetailsCheck = new CheckBox
            {
                Content = "Include Technical Details",
                IsChecked = IncludeTechnicalDetails,
                Margin = new Thickness(0, 5, 0, 5)
            };
            TechDetailsCheck.Checked += (s, e) => IncludeTechnicalDetails = true;
            TechDetailsCheck.Unchecked += (s, e) => IncludeTechnicalDetails = false;
            stack.Children.Add(TechDetailsCheck);

            MetadataCheck = new CheckBox
            {
                Content = "Include Scan Metadata",
                IsChecked = IncludeScanMetadata,
                Margin = new Thickness(0, 5, 0, 5)
            };
            MetadataCheck.Checked += (s, e) => IncludeScanMetadata = true;
            MetadataCheck.Unchecked += (s, e) => IncludeScanMetadata = false;
            stack.Children.Add(MetadataCheck);

            HtmlCheck = new CheckBox
            {
                Content = "Generate HTML Report",
                IsChecked = GenerateHtmlReport,
                Margin = new Thickness(0, 5, 0, 5)
            };
            HtmlCheck.Checked += (s, e) => GenerateHtmlReport = true;
            HtmlCheck.Unchecked += (s, e) => GenerateHtmlReport = false;
            stack.Children.Add(HtmlCheck);

            CoverageCheck = new CheckBox
            {
                Content = "Generate Coverage Matrix",
                IsChecked = GenerateCoverageMatrix,
                Margin = new Thickness(0, 5, 0, 5)
            };
            CoverageCheck.Checked += (s, e) => GenerateCoverageMatrix = true;
            CoverageCheck.Unchecked += (s, e) => GenerateCoverageMatrix = false;
            stack.Children.Add(CoverageCheck);

            OpenCheck = new CheckBox
            {
                Content = "Open Report After Generation",
                IsChecked = OpenAfterGeneration,
                Margin = new Thickness(0, 5, 0, 20)
            };
            OpenCheck.Checked += (s, e) => OpenAfterGeneration = true;
            OpenCheck.Unchecked += (s, e) => OpenAfterGeneration = false;
            stack.Children.Add(OpenCheck);

            var buttonStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var okButton = new Button { Content = "Generate", Width = 80, Margin = new Thickness(5) };
            okButton.Click += (s, e) => { DialogResult = true; Close(); };
            buttonStack.Children.Add(okButton);

            var cancelButton = new Button { Content = "Cancel", Width = 80, Margin = new Thickness(5) };
            cancelButton.Click += (s, e) => { DialogResult = false; Close(); };
            buttonStack.Children.Add(cancelButton);

            stack.Children.Add(buttonStack);
            Content = stack;
        }
    }

    public class SimpleSettingsDialog : Window
    {
        public ScannerConfiguration Configuration { get; set; }
        private ComboBox TlsModeCombo;
        private TextBox RateLimitBox;
        private TextBox MaxConcurrentBox;
        private TextBox RequestBudgetBox;
        private TextBox ConfidenceBox;

        public SimpleSettingsDialog(ScannerConfiguration config)
        {
            Configuration = new ScannerConfiguration
            {
                TlsValidationMode = config.TlsValidationMode,
                RateLimitRequestsPerSecond = config.RateLimitRequestsPerSecond,
                MaxConcurrentRequests = config.MaxConcurrentRequests,
                RequestBudget = config.RequestBudget,
                MinimumConfidenceThreshold = config.MinimumConfidenceThreshold
            };

            Width = 400;
            Height = 350;
            Title = "Scanner Settings";
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var stack = new StackPanel { Margin = new Thickness(20) };

            var tlsLabel = new TextBlock { Text = "TLS Validation Mode:", Margin = new Thickness(0, 0, 0, 5) };
            stack.Children.Add(tlsLabel);

            TlsModeCombo = new ComboBox
            {
                ItemsSource = new[] { "Strict", "Pinned", "Insecure" },
                SelectedItem = Configuration.TlsValidationMode.ToString(),
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(TlsModeCombo);

            var rateLimitLabel = new TextBlock { Text = "Rate Limit (requests/second):", Margin = new Thickness(0, 0, 0, 5) };
            stack.Children.Add(rateLimitLabel);

            RateLimitBox = new TextBox
            {
                Text = Configuration.RateLimitRequestsPerSecond.ToString(),
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(RateLimitBox);

            var concurrentLabel = new TextBlock { Text = "Max Concurrent Requests:", Margin = new Thickness(0, 0, 0, 5) };
            stack.Children.Add(concurrentLabel);

            MaxConcurrentBox = new TextBox
            {
                Text = Configuration.MaxConcurrentRequests.ToString(),
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(MaxConcurrentBox);

            var budgetLabel = new TextBlock { Text = "Request Budget:", Margin = new Thickness(0, 0, 0, 5) };
            stack.Children.Add(budgetLabel);

            RequestBudgetBox = new TextBox
            {
                Text = Configuration.RequestBudget.ToString(),
                Margin = new Thickness(0, 0, 0, 10)
            };
            stack.Children.Add(RequestBudgetBox);

            var confidenceLabel = new TextBlock { Text = "Minimum Confidence Threshold (%):", Margin = new Thickness(0, 0, 0, 5) };
            stack.Children.Add(confidenceLabel);

            ConfidenceBox = new TextBox
            {
                Text = Configuration.MinimumConfidenceThreshold.ToString(),
                Margin = new Thickness(0, 0, 0, 20)
            };
            stack.Children.Add(ConfidenceBox);

            var buttonStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var okButton = new Button { Content = "Save", Width = 80, Margin = new Thickness(5) };
            okButton.Click += (s, e) =>
            {
                if (Enum.TryParse<TlsValidationMode>(TlsModeCombo.SelectedItem.ToString(), out var tlsMode))
                    Configuration.TlsValidationMode = tlsMode;

                if (int.TryParse(RateLimitBox.Text, out var rateLimit))
                    Configuration.RateLimitRequestsPerSecond = rateLimit;

                if (int.TryParse(MaxConcurrentBox.Text, out var maxConcurrent))
                    Configuration.MaxConcurrentRequests = maxConcurrent;

                if (int.TryParse(RequestBudgetBox.Text, out var budget))
                    Configuration.RequestBudget = budget;

                if (int.TryParse(ConfidenceBox.Text, out var confidence))
                    Configuration.MinimumConfidenceThreshold = confidence;

                DialogResult = true;
                Close();
            };
            buttonStack.Children.Add(okButton);

            var cancelButton = new Button { Content = "Cancel", Width = 80, Margin = new Thickness(5) };
            cancelButton.Click += (s, e) => { DialogResult = false; Close(); };
            buttonStack.Children.Add(cancelButton);

            stack.Children.Add(buttonStack);
            Content = stack;
        }
    }

    public class SimpleTextDialog : Window
    {
        public SimpleTextDialog(string title, string content)
        {
            Width = 600;
            Height = 400;
            Title = title;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;

            var stack = new StackPanel();

            var textBox = new TextBox
            {
                Text = content,
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 12,
                IsReadOnly = true,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                TextWrapping = TextWrapping.NoWrap
            };

            var closeButton = new Button
            {
                Content = "Close",
                Width = 80,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(10)
            };
            closeButton.Click += (s, e) => Close();

            stack.Children.Add(textBox);
            stack.Children.Add(closeButton);
            Content = stack;
        }
    }

    public class ProductionScannerEngine
    {
        public event EventHandler<RequestLogEntry> RequestLogged;
        public event EventHandler<Vulnerability> VulnerabilityFound;
        public event EventHandler<ProgressUpdate> ProgressUpdated;
        public event EventHandler<string> LogMessage;
        public event EventHandler<ScanStatistics> StatsUpdated;
        public event EventHandler<ScopeViolation> ScopeViolationDetected;
        public event EventHandler<ServerHealthStatus> ServerInstabilityDetected;
        public event EventHandler ScanAuthorizationRequired;

        public ObservableCollection<RequestLogEntry> RequestLogs { get; } = new ObservableCollection<RequestLogEntry>();
        public ObservableCollection<Vulnerability> Vulnerabilities { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> InjectionFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> XssFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> AccessControlFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> SsrfFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> MisconfigFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> CryptoFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> ComponentFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> DesignFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> IntegrityFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> LoggingFindings { get; } = new ObservableCollection<Vulnerability>();
        public ObservableCollection<Vulnerability> AuthFindings { get; } = new ObservableCollection<Vulnerability>();

        public ScannerConfiguration Configuration { get; private set; }
        public ScanScope CurrentScope { get; private set; }
        public ScanStatistics RealTimeStats { get; private set; } = new ScanStatistics();

        private HttpClient _httpClient;
        private HttpClientHandler _httpHandler;
        private ProductionCrawler _crawler;
        private ProductionSqlInjectionTester _sqlTester;
        private ProductionXssTester _xssTester;
        private ProductionAccessControlTester _accessControlTester;
        private ProductionSsrfTester _ssrfTester;
        private ProductionSecurityHeadersTester _headersTester;
        private ProductionCryptographicTester _cryptoTester;
        private ProductionComponentTester _componentTester;
        private ProductionDesignTester _designTester;
        private ProductionIntegrityTester _integrityTester;
        private ProductionLoggingTester _loggingTester;
        private ProductionAuthTester _authTester;

        private ConcurrentDictionary<string, ProductionBaselineResponse> _baselines = new ConcurrentDictionary<string, ProductionBaselineResponse>();
        private SemaphoreSlim _requestSemaphore;
        private RateLimiter _rateLimiter;
        private CancellationTokenSource _currentScanCancellation;
        private Stopwatch _scanStopwatch = new Stopwatch();
        private int _lastRequestCount = 0;
        private DateTime _lastStatsUpdate = DateTime.Now;
        private ServerHealthMonitor _serverHealthMonitor;
        private AuthorizationRecord _authorization;
        private bool _sensitiveTestsAuthorized = false;

        public ProductionScannerEngine(ScannerConfiguration config)
        {
            Configuration = config ?? new ScannerConfiguration();
            CurrentScope = new ScanScope();

            InitializeHttpClient();
            InitializeTesters();

            _requestSemaphore = new SemaphoreSlim(Configuration.MaxConcurrentRequests, Configuration.MaxConcurrentRequests);
            _rateLimiter = new RateLimiter(Configuration.RateLimitRequestsPerSecond);
            _serverHealthMonitor = new ServerHealthMonitor();
            _serverHealthMonitor.HealthStatusChanged += OnServerHealthStatusChanged;
        }

        private void InitializeHttpClient()
        {
            _httpHandler = new HttpClientHandler
            {
                UseCookies = true,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.All,
                MaxConnectionsPerServer = Configuration.MaxConcurrentRequests * 2,
                UseProxy = false,
                ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation
            };

            switch (Configuration.TlsValidationMode)
            {
                case TlsValidationMode.Strict:
                    _httpHandler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    break;
                case TlsValidationMode.Pinned:
                    _httpHandler.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    break;
                case TlsValidationMode.Insecure:
                    _httpHandler.SslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13;
                    break;
            }

            _httpClient = new HttpClient(_httpHandler);
            _httpClient.Timeout = TimeSpan.FromSeconds(Configuration.RequestTimeoutSeconds);
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("EnterpriseSecurityScanner/1.0 (Security Assessment)");
            _httpClient.DefaultRequestHeaders.Add("X-Scanner", "EnterpriseSecurityScanner");
            _httpClient.DefaultRequestHeaders.Add("X-Scan-ID", Guid.NewGuid().ToString());
        }

        private bool ServerCertificateCustomValidation(HttpRequestMessage request, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
        {
            if (Configuration.TlsValidationMode == TlsValidationMode.Insecure)
            {
                Log($"⚠️ INSECURE MODE: Certificate validation disabled for {request.RequestUri.Host}");
                return true;
            }

            if (errors == SslPolicyErrors.None)
                return true;

            if (Configuration.TlsValidationMode == TlsValidationMode.Pinned)
            {
                var certHash = cert.GetCertHashString();
                if (Configuration.PinnedCertificates.Contains(certHash))
                {
                    Log($"🔐 Certificate pinned: {certHash}");
                    return true;
                }
            }

            Log($"❌ TLS Certificate error for {request.RequestUri.Host}: {errors}");
            return false;
        }

        private void InitializeTesters()
        {
            _crawler = new ProductionCrawler(_httpClient, Configuration);
            _sqlTester = new ProductionSqlInjectionTester(Configuration);
            _xssTester = new ProductionXssTester(Configuration);
            _accessControlTester = new ProductionAccessControlTester(Configuration);
            _ssrfTester = new ProductionSsrfTester(Configuration);
            _headersTester = new ProductionSecurityHeadersTester(Configuration);
            _cryptoTester = new ProductionCryptographicTester(Configuration);
            _componentTester = new ProductionComponentTester(Configuration);
            _designTester = new ProductionDesignTester(Configuration);
            _integrityTester = new ProductionIntegrityTester(Configuration);
            _loggingTester = new ProductionLoggingTester(Configuration);
            _authTester = new ProductionAuthTester(Configuration);
        }

        public void SetScanScope(List<string> allowedDomains, List<string> allowedCidrs)
        {
            CurrentScope = new ScanScope
            {
                Domains = new HashSet<string>(allowedDomains ?? new List<string>()),
                AllowedCidrs = new List<string>(allowedCidrs ?? new List<string>()),
                AllowIpLiterals = allowedCidrs?.Count > 0
            };
            Log($"📋 Scope set: {string.Join(", ", CurrentScope.Domains)}");
        }

        public void SetAuthorizationRecord(string user, DateTime timestamp)
        {
            _authorization = new AuthorizationRecord
            {
                User = user,
                Timestamp = timestamp,
                Scope = CurrentScope?.Domains?.ToList() ?? new List<string>()
            };
        }

        public void UpdateConfiguration(ScannerConfiguration config)
        {
            Configuration = config;
            InitializeHttpClient();
            InitializeTesters();
            _requestSemaphore = new SemaphoreSlim(Configuration.MaxConcurrentRequests, Configuration.MaxConcurrentRequests);
            _rateLimiter = new RateLimiter(Configuration.RateLimitRequestsPerSecond);
        }

        public void ClearResults()
        {
            RequestLogs.Clear();
            Vulnerabilities.Clear();
            InjectionFindings.Clear();
            XssFindings.Clear();
            AccessControlFindings.Clear();
            SsrfFindings.Clear();
            MisconfigFindings.Clear();
            CryptoFindings.Clear();
            ComponentFindings.Clear();
            DesignFindings.Clear();
            IntegrityFindings.Clear();
            LoggingFindings.Clear();
            AuthFindings.Clear();
            _baselines.Clear();
            _serverHealthMonitor.Reset();
            _sensitiveTestsAuthorized = false;
        }

        public async Task StartProductionScanAsync(string baseUrl, CancellationToken cancellationToken)
        {
            _currentScanCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _scanStopwatch.Start();
            _serverHealthMonitor.StartMonitoring();

            try
            {
                ValidateScanAuthorization();
                ValidateTargetScope(baseUrl);

                await UpdateProgress(0, "Initializing scan...");

                var scanContext = new ScanContext
                {
                    BaseUrl = baseUrl,
                    Authorization = _authorization,
                    Configuration = Configuration,
                    Scope = CurrentScope,
                    CancellationToken = _currentScanCancellation.Token
                };

                await ExecuteScanPhases(scanContext);

                _scanStopwatch.Stop();
                await UpdateProgress(100, "Scan complete");

                GenerateScanSummary();
                LogScanCompletion();
            }
            catch (OperationCanceledException)
            {
                Log("🛑 Scan cancelled");
            }
            catch (ScopeViolationException ex)
            {
                Log($"🚫 Scan terminated: {ex.Message}");
            }
            catch (UnauthorizedScanException ex)
            {
                Log($"🔒 Scan terminated: {ex.Message}");
            }
            catch (Exception ex)
            {
                Log($"❌ Scan error: {ex.Message}");
            }
            finally
            {
                _currentScanCancellation?.Dispose();
                _serverHealthMonitor.StopMonitoring();
                UpdateStatistics();
            }
        }

        private async Task ExecuteScanPhases(ScanContext context)
        {
            var phases = new List<ScanPhase>
            {
                new ScanPhase { Name = "Discovery", Weight = 10, Action = PhaseDiscovery },
                new ScanPhase { Name = "Baseline Analysis", Weight = 10, Action = PhaseBaselineAnalysis },
                new ScanPhase { Name = "Security Headers", Weight = 5, Action = PhaseSecurityHeaders },
                new ScanPhase { Name = "Cryptographic Testing", Weight = 10, Action = PhaseCryptographicTesting },
                new ScanPhase { Name = "Component Analysis", Weight = 10, Action = PhaseComponentAnalysis },
                new ScanPhase { Name = "Injection Testing", Weight = 15, Action = PhaseInjectionTesting },
                new ScanPhase { Name = "Access Control Testing", Weight = 15, Action = PhaseAccessControlTesting },
                new ScanPhase { Name = "Design Analysis", Weight = 10, Action = PhaseDesignAnalysis },
                new ScanPhase { Name = "Logging Analysis", Weight = 5, Action = PhaseLoggingAnalysis },
                new ScanPhase { Name = "Integrity Analysis", Weight = 5, Action = PhaseIntegrityAnalysis },
                new ScanPhase { Name = "Authentication Analysis", Weight = 5, Action = PhaseAuthenticationAnalysis }
            };

            int completedWeight = 0;
            int totalWeight = phases.Sum(p => p.Weight);

            foreach (var phase in phases)
            {
                if (context.CancellationToken.IsCancellationRequested)
                    break;

                if (phase.RequiresSensitiveAuthorization && !_sensitiveTestsAuthorized)
                {
                    ScanAuthorizationRequired?.Invoke(this, EventArgs.Empty);
                    if (!_sensitiveTestsAuthorized)
                    {
                        Log($"⏭️ Skipping {phase.Name} - not authorized");
                        completedWeight += phase.Weight;
                        continue;
                    }
                }

                await UpdateProgress((int)(100 * completedWeight / totalWeight), $"Phase: {phase.Name}");

                try
                {
                    await phase.Action(context);
                }
                catch (Exception ex)
                {
                    Log($"⚠️ Phase {phase.Name} failed: {ex.Message}");
                }

                completedWeight += phase.Weight;
            }
        }

        private async Task PhaseDiscovery(ScanContext context)
        {
            await UpdateProgress(0, "Discovering endpoints...");
            var endpoints = await _crawler.DiscoverEndpointsAsync(context.BaseUrl, context.CancellationToken);
            Log($"📡 Discovered {endpoints.Count} endpoints within scope");
            context.Endpoints = endpoints;
        }

        private async Task PhaseBaselineAnalysis(ScanContext context)
        {
            await UpdateProgress(10, "Establishing baselines...");
            await EstablishBaselines(context.Endpoints, context.CancellationToken);
        }

        private async Task PhaseSecurityHeaders(ScanContext context)
        {
            if (!Configuration.EnableSecurityHeaderAnalysis)
                return;

            await UpdateProgress(20, "Testing security headers...");
            foreach (var endpoint in context.Endpoints)
            {
                if (context.CancellationToken.IsCancellationRequested)
                    break;

                await TestSecurityHeaders(endpoint, context.CancellationToken);
                await _rateLimiter.WaitAsync(context.CancellationToken);
            }
        }

        private async Task PhaseCryptographicTesting(ScanContext context)
        {
            if (!Configuration.EnableCryptographicTesting)
                return;

            await UpdateProgress(30, "Testing cryptographic security...");
            await TestCryptographicSecurity(context.BaseUrl, context.CancellationToken);
        }

        private async Task PhaseComponentAnalysis(ScanContext context)
        {
            if (!Configuration.EnableComponentAnalysis)
                return;

            await UpdateProgress(40, "Analyzing components...");
            await TestComponents(context.Endpoints, context.CancellationToken);
        }

        private async Task PhaseInjectionTesting(ScanContext context)
        {
            await UpdateProgress(50, "Testing injection vulnerabilities...");

            var injectionTasks = new List<Task>();
            foreach (var endpoint in context.Endpoints)
            {
                if (context.CancellationToken.IsCancellationRequested)
                    break;

                injectionTasks.Add(TestSqlInjection(endpoint, context.CancellationToken));
                injectionTasks.Add(TestXss(endpoint, context.CancellationToken));
                injectionTasks.Add(TestCommandInjection(endpoint, context.CancellationToken));

                if (injectionTasks.Count >= Configuration.MaxConcurrentRequests)
                {
                    await Task.WhenAll(injectionTasks);
                    injectionTasks.Clear();
                    await _rateLimiter.WaitAsync(context.CancellationToken);
                }
            }

            if (injectionTasks.Count > 0)
                await Task.WhenAll(injectionTasks);
        }

        private async Task PhaseAccessControlTesting(ScanContext context)
        {
            if (!_sensitiveTestsAuthorized && Configuration.RequireAuthorizationForSensitiveTests)
            {
                Log("⏭️ Skipping access control testing - requires authorization");
                return;
            }

            await UpdateProgress(65, "Testing access control...");

            foreach (var endpoint in context.Endpoints)
            {
                if (context.CancellationToken.IsCancellationRequested)
                    break;

                await TestAccessControl(endpoint, context.CancellationToken);
                await TestIdor(endpoint, context.CancellationToken);
                await TestPathTraversal(endpoint, context.CancellationToken);
                await _rateLimiter.WaitAsync(context.CancellationToken);
            }
        }

        private async Task PhaseDesignAnalysis(ScanContext context)
        {
            await UpdateProgress(75, "Analyzing design patterns...");
            await TestDesignPatterns(context.Endpoints, context.CancellationToken);
        }

        private async Task PhaseLoggingAnalysis(ScanContext context)
        {
            await UpdateProgress(80, "Analyzing logging...");
            await TestLogging(context.Endpoints, context.CancellationToken);
        }

        private async Task PhaseIntegrityAnalysis(ScanContext context)
        {
            await UpdateProgress(85, "Testing integrity controls...");
            await TestIntegrity(context.Endpoints, context.CancellationToken);
        }

        private async Task PhaseAuthenticationAnalysis(ScanContext context)
        {
            if (!Configuration.EnableAuthenticationTesting)
                return;

            if (!_sensitiveTestsAuthorized && Configuration.RequireAuthorizationForSensitiveTests)
            {
                Log("⏭️ Skipping authentication testing - requires authorization");
                return;
            }

            await UpdateProgress(90, "Testing authentication...");
            await TestAuthentication(context.Endpoints, context.CancellationToken);
        }

        private void ValidateScanAuthorization()
        {
            if (_authorization == null)
                throw new UnauthorizedScanException("Scan authorization required");

            if ((DateTime.Now - _authorization.Timestamp).TotalHours > 24)
                throw new UnauthorizedScanException("Authorization expired (24 hour limit)");

            Log($"✅ Scan authorized by {_authorization.User} at {_authorization.Timestamp:HH:mm:ss}");
        }

        private void ValidateTargetScope(string url)
        {
            if (!CurrentScope.IsUrlInScope(url))
                throw new ScopeViolationException($"Target URL {url} not in scan scope");

            Log($"✅ Target URL {url} validated against scope");
        }

        private async Task EstablishBaselines(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            int completed = 0;
            int total = endpoints.Count;

            foreach (var endpoint in endpoints)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    await _requestSemaphore.WaitAsync(cancellationToken);
                    await _rateLimiter.WaitAsync(cancellationToken);

                    var response = await SendRequestAsync(endpoint, cancellationToken);

                    if (!CurrentScope.IsUrlInScope(response.Url))
                    {
                        ScopeViolationDetected?.Invoke(this, new ScopeViolation
                        {
                            RequestedUrl = response.Url,
                            Reason = "URL outside configured scope",
                            Timestamp = DateTime.Now
                        });
                        continue;
                    }

                    _baselines[endpoint.Url] = new ProductionBaselineResponse
                    {
                        StatusCode = response.StatusCode,
                        BodyHash = ComputeHash(response.Body),
                        Body = response.Body,
                        BodyLength = response.Body?.Length ?? 0,
                        ResponseTime = response.ResponseTime,
                        Headers = response.Headers.ToDictionary(h => h.Key, h => string.Join("; ", h.Value)),
                        ContentType = response.ContentType
                    };

                    LogRequest(response, "BASELINE");
                    _serverHealthMonitor.RecordResponse(response);

                    completed++;
                    if (completed % 10 == 0)
                    {
                        await UpdateProgress(10 + (int)(10 * completed / total), $"Baselines: {completed}/{total}");
                    }
                }
                catch (Exception ex)
                {
                    Log($"⚠️ Baseline failed for {endpoint.Url}: {ex.Message}");
                }
                finally
                {
                    _requestSemaphore.Release();
                }
            }
        }

        private async Task TestSqlInjection(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            if (!endpoint.HasParameters) return;

            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            foreach (var param in endpoint.Parameters)
            {
                if (!_sqlTester.IsRelevantParameter(param.Key)) continue;

                foreach (var testCase in _sqlTester.GetTestCases())
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        await _requestSemaphore.WaitAsync(cancellationToken);
                        await _rateLimiter.WaitAsync(cancellationToken);

                        var testEndpoint = endpoint.Clone();
                        testEndpoint.Parameters[param.Key] = testCase.Payload;

                        var response = await SendRequestAsync(testEndpoint, cancellationToken);
                        LogRequest(response, "SQLi");

                        var detectionResult = _sqlTester.DetectVulnerability(response, baseline, testCase);

                        if (detectionResult.IsVulnerable)
                        {
                            ReportVulnerability(detectionResult);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠️ SQLi test error for {endpoint.Url}: {ex.Message}");
                    }
                    finally
                    {
                        _requestSemaphore.Release();
                    }
                }
            }
        }

        private async Task TestXss(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            if (!endpoint.HasParameters) return;

            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            foreach (var param in endpoint.Parameters)
            {
                if (!_xssTester.IsRelevantParameter(param.Key)) continue;

                foreach (var testCase in _xssTester.GetTestCases())
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        await _requestSemaphore.WaitAsync(cancellationToken);
                        await _rateLimiter.WaitAsync(cancellationToken);

                        var testEndpoint = endpoint.Clone();
                        testEndpoint.Parameters[param.Key] = testCase.Payload;

                        var response = await SendRequestAsync(testEndpoint, cancellationToken);
                        LogRequest(response, "XSS");

                        var detectionResult = _xssTester.DetectVulnerability(response, baseline, testCase);

                        if (detectionResult.IsVulnerable)
                        {
                            ReportVulnerability(detectionResult);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠️ XSS test error for {endpoint.Url}: {ex.Message}");
                    }
                    finally
                    {
                        _requestSemaphore.Release();
                    }
                }
            }
        }

        private async Task TestAccessControl(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            foreach (var testCase in _accessControlTester.GetTestCases(endpoint))
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    await _requestSemaphore.WaitAsync(cancellationToken);
                    await _rateLimiter.WaitAsync(cancellationToken);

                    var response = await SendRequestAsync(testCase.TestEndpoint, cancellationToken);
                    LogRequest(response, "ACCESS_CONTROL");

                    var detectionResult = _accessControlTester.DetectVulnerability(response, baseline, testCase);

                    if (detectionResult.IsVulnerable)
                    {
                        ReportVulnerability(detectionResult);
                    }
                }
                catch (Exception ex)
                {
                    Log($"⚠️ Access control test error for {endpoint.Url}: {ex.Message}");
                }
                finally
                {
                    _requestSemaphore.Release();
                }
            }
        }

        private async Task TestIdor(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            var testCases = _accessControlTester.GenerateIdorTestCases(endpoint);

            foreach (var testCase in testCases)
            {
                if (cancellationToken.IsCancellationRequested) break;

                try
                {
                    await _requestSemaphore.WaitAsync(cancellationToken);
                    await _rateLimiter.WaitAsync(cancellationToken);

                    var response = await SendRequestAsync(testCase.TestEndpoint, cancellationToken);
                    LogRequest(response, "IDOR");

                    var detectionResult = _accessControlTester.DetectIdorVulnerability(response, baseline, testCase);

                    if (detectionResult.IsVulnerable)
                    {
                        ReportVulnerability(detectionResult);
                    }
                }
                catch (Exception ex)
                {
                    Log($"⚠️ IDOR test error for {endpoint.Url}: {ex.Message}");
                }
                finally
                {
                    _requestSemaphore.Release();
                }
            }
        }

        private async Task TestCommandInjection(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            if (!endpoint.HasParameters) return;

            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            foreach (var param in endpoint.Parameters)
            {
                var testCases = _sqlTester.GetCommandInjectionTestCases();

                foreach (var testCase in testCases)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        await _requestSemaphore.WaitAsync(cancellationToken);
                        await _rateLimiter.WaitAsync(cancellationToken);

                        var testEndpoint = endpoint.Clone();
                        testEndpoint.Parameters[param.Key] = testCase.Payload;

                        var response = await SendRequestAsync(testEndpoint, cancellationToken);
                        LogRequest(response, "CMD_INJECTION");

                        var detectionResult = _sqlTester.DetectCommandInjection(response, baseline, testCase);

                        if (detectionResult.IsVulnerable)
                        {
                            ReportVulnerability(detectionResult);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠️ Command injection test error for {endpoint.Url}: {ex.Message}");
                    }
                    finally
                    {
                        _requestSemaphore.Release();
                    }
                }
            }
        }

        private async Task TestPathTraversal(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            if (!endpoint.HasParameters) return;

            var baseline = _baselines.GetValueOrDefault(endpoint.Url);
            if (baseline == null) return;

            var testCases = _accessControlTester.GetPathTraversalTestCases();

            foreach (var param in endpoint.Parameters)
            {
                foreach (var testCase in testCases)
                {
                    if (cancellationToken.IsCancellationRequested) break;

                    try
                    {
                        await _requestSemaphore.WaitAsync(cancellationToken);
                        await _rateLimiter.WaitAsync(cancellationToken);

                        var testEndpoint = endpoint.Clone();
                        testEndpoint.Parameters[param.Key] = testCase.Payload;

                        var response = await SendRequestAsync(testEndpoint, cancellationToken);
                        LogRequest(response, "PATH_TRAVERSAL");

                        var detectionResult = _accessControlTester.DetectPathTraversal(response, baseline, testCase);

                        if (detectionResult.IsVulnerable)
                        {
                            ReportVulnerability(detectionResult);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"⚠️ Path traversal test error for {endpoint.Url}: {ex.Message}");
                    }
                    finally
                    {
                        _requestSemaphore.Release();
                    }
                }
            }
        }

        private async Task TestSecurityHeaders(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            try
            {
                await _requestSemaphore.WaitAsync(cancellationToken);
                await _rateLimiter.WaitAsync(cancellationToken);

                var response = await SendRequestAsync(endpoint, cancellationToken);

                var securityIssues = _headersTester.AnalyzeSecurityHeaders(response);
                foreach (var issue in securityIssues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A05:2021-Security Misconfiguration",
                                Type = issue.Type,
                                Severity = issue.Severity,
                                Confidence = issue.Confidence,
                                Url = endpoint.Url,
                                Parameter = "headers",
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore(issue.Severity, issue.Confidence),
                                CWE = GetCweForIssue(issue.Type),
                                Impact = GetImpactForIssue(issue.Type),
                                Remediation = GetRemediationForIssue(issue.Type)
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Security headers test error for {endpoint.Url}: {ex.Message}");
            }
            finally
            {
                _requestSemaphore.Release();
            }
        }

        private async Task TestCryptographicSecurity(string baseUrl, CancellationToken cancellationToken)
        {
            try
            {
                var issues = await _cryptoTester.TestCryptographicSecurity(baseUrl, cancellationToken);
                foreach (var issue in issues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A02:2021-Cryptographic Failures",
                                Type = issue.Type,
                                Severity = issue.Severity,
                                Confidence = issue.Confidence,
                                Url = baseUrl,
                                Parameter = "crypto",
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore(issue.Severity, issue.Confidence),
                                CWE = GetCweForIssue(issue.Type),
                                Impact = GetImpactForIssue(issue.Type),
                                Remediation = GetRemediationForIssue(issue.Type)
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Cryptographic test error: {ex.Message}");
            }
        }

        private async Task TestComponents(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            try
            {
                var issues = await _componentTester.AnalyzeComponents(endpoints, cancellationToken);
                foreach (var issue in issues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A06:2021-Vulnerable Components",
                                Type = issue.Type,
                                Severity = issue.Severity,
                                Confidence = issue.Confidence,
                                Url = issue.Url,
                                Parameter = "component",
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore(issue.Severity, issue.Confidence),
                                CWE = GetCweForIssue(issue.Type),
                                Impact = GetImpactForIssue(issue.Type),
                                Remediation = GetRemediationForIssue(issue.Type)
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Component test error: {ex.Message}");
            }
        }

        private async Task TestDesignPatterns(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            try
            {
                var issues = await _designTester.AnalyzeDesignPatterns(endpoints, cancellationToken);
                foreach (var issue in issues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A04:2021-Insecure Design",
                                Type = issue.Type,
                                Severity = "MEDIUM",
                                Confidence = issue.Confidence,
                                Url = issue.Url,
                                Parameter = issue.Parameter,
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore("MEDIUM", issue.Confidence),
                                CWE = "CWE-250",
                                Impact = "Potential business logic bypass or abuse",
                                Remediation = "Review and strengthen business logic controls",
                                Note = "Automated design weakness indicator - requires manual validation"
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Design analysis error: {ex.Message}");
            }
        }

        private async Task TestLogging(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            try
            {
                var issues = await _loggingTester.AnalyzeLogging(endpoints, cancellationToken);
                foreach (var issue in issues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A09:2021-Security Logging",
                                Type = issue.Type,
                                Severity = "LOW",
                                Confidence = issue.Confidence,
                                Url = issue.Url,
                                Parameter = issue.Parameter,
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore("LOW", issue.Confidence),
                                CWE = "CWE-778",
                                Impact = "Reduced security observability and incident response capability",
                                Remediation = "Implement comprehensive security logging and monitoring",
                                Note = "Logging and monitoring observability gap"
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Logging analysis error: {ex.Message}");
            }
        }

        private async Task TestIntegrity(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            try
            {
                var issues = await _integrityTester.AnalyzeIntegrity(endpoints, cancellationToken);
                foreach (var issue in issues)
                {
                    if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                    {
                        ReportVulnerability(new VulnerabilityDetectionResult
                        {
                            IsVulnerable = true,
                            Vulnerability = new Vulnerability
                            {
                                OWASPCategory = "A08:2021-Software and Data Integrity",
                                Type = issue.Type,
                                Severity = issue.Severity,
                                Confidence = issue.Confidence,
                                Url = issue.Url,
                                Parameter = issue.Parameter,
                                Evidence = issue.Details,
                                Timestamp = DateTime.Now,
                                RiskScore = CalculateRiskScore(issue.Severity, issue.Confidence),
                                CWE = GetCweForIssue(issue.Type),
                                Impact = GetImpactForIssue(issue.Type),
                                Remediation = GetRemediationForIssue(issue.Type)
                            }
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Integrity analysis error: {ex.Message}");
            }
        }

        private async Task TestAuthentication(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            try
            {
                var authEndpoints = endpoints.Where(e =>
                    e.Url.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                    e.Url.Contains("signin", StringComparison.OrdinalIgnoreCase) ||
                    e.Url.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                    e.Url.Contains("password", StringComparison.OrdinalIgnoreCase)).ToList();

                foreach (var endpoint in authEndpoints)
                {
                    var issues = await _authTester.TestAuthentication(endpoint, cancellationToken);
                    foreach (var issue in issues)
                    {
                        if (issue.Confidence >= Configuration.MinimumConfidenceThreshold)
                        {
                            ReportVulnerability(new VulnerabilityDetectionResult
                            {
                                IsVulnerable = true,
                                Vulnerability = new Vulnerability
                                {
                                    OWASPCategory = "A07:2021-Identification and Authentication Failures",
                                    Type = issue.Type,
                                    Severity = issue.Severity,
                                    Confidence = issue.Confidence,
                                    Url = endpoint.Url,
                                    Parameter = issue.Parameter,
                                    Evidence = issue.Details,
                                    Timestamp = DateTime.Now,
                                    RiskScore = CalculateRiskScore(issue.Severity, issue.Confidence),
                                    CWE = GetCweForIssue(issue.Type),
                                    Impact = GetImpactForIssue(issue.Type),
                                    Remediation = GetRemediationForIssue(issue.Type)
                                }
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"⚠️ Authentication test error: {ex.Message}");
            }
        }

        private async Task<ProductionHttpResponse> SendRequestAsync(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            string requestDetails = "";
            string responseDetails = "";

            try
            {
                if (!CurrentScope.IsUrlInScope(endpoint.Url))
                {
                    throw new ScopeViolationException($"URL {endpoint.Url} outside scan scope");
                }

                if (RequestLogs.Count >= Configuration.RequestBudget)
                {
                    throw new RequestBudgetExceededException($"Request budget ({Configuration.RequestBudget}) exceeded");
                }

                HttpRequestMessage request = endpoint.Method.ToUpper() switch
                {
                    "GET" => new HttpRequestMessage(HttpMethod.Get, BuildUrlWithParams(endpoint)),
                    "POST" => new HttpRequestMessage(HttpMethod.Post, endpoint.Url)
                    {
                        Content = new FormUrlEncodedContent(endpoint.Parameters)
                    },
                    "PUT" => new HttpRequestMessage(HttpMethod.Put, endpoint.Url)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(endpoint.Parameters), Encoding.UTF8, "application/json")
                    },
                    "DELETE" => new HttpRequestMessage(HttpMethod.Delete, BuildUrlWithParams(endpoint)),
                    _ => new HttpRequestMessage(new HttpMethod(endpoint.Method), endpoint.Url)
                };

                request.Headers.Add("X-Scan-ID", Guid.NewGuid().ToString());
                request.Headers.Add("X-Scan-Timestamp", DateTime.UtcNow.ToString("O"));

                requestDetails = $"{request.Method} {request.RequestUri}\n";
                foreach (var header in request.Headers)
                {
                    requestDetails += $"{header.Key}: {string.Join(", ", header.Value)}\n";
                }
                if (request.Content != null)
                {
                    requestDetails += $"\n{await request.Content.ReadAsStringAsync(cancellationToken)}";
                }

                var response = await _httpClient.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);

                stopwatch.Stop();

                responseDetails = $"HTTP/1.1 {(int)response.StatusCode} {response.ReasonPhrase}\n";
                foreach (var header in response.Headers)
                {
                    responseDetails += $"{header.Key}: {string.Join(", ", header.Value)}\n";
                }
                foreach (var header in response.Content.Headers)
                {
                    responseDetails += $"{header.Key}: {string.Join(", ", header.Value)}\n";
                }
                responseDetails += $"\n{body}";

                return new ProductionHttpResponse
                {
                    Url = endpoint.Url,
                    StatusCode = (int)response.StatusCode,
                    Body = body,
                    Headers = response.Headers,
                    ResponseTime = stopwatch.ElapsedMilliseconds,
                    RequestDetails = requestDetails,
                    ResponseDetails = responseDetails,
                    ContentType = response.Content.Headers.ContentType?.MediaType
                };
            }
            catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (ScopeViolationException ex)
            {
                stopwatch.Stop();
                ScopeViolationDetected?.Invoke(this, new ScopeViolation
                {
                    RequestedUrl = endpoint.Url,
                    Reason = ex.Message,
                    Timestamp = DateTime.Now
                });
                throw;
            }
            catch (RequestBudgetExceededException ex)
            {
                stopwatch.Stop();
                Log($"💰 {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return new ProductionHttpResponse
                {
                    Url = endpoint.Url,
                    StatusCode = 0,
                    Body = ex.Message,
                    ResponseTime = stopwatch.ElapsedMilliseconds,
                    RequestDetails = requestDetails,
                    ResponseDetails = ex.ToString(),
                    ContentType = "text/plain"
                };
            }
        }

        private string BuildUrlWithParams(ProductionEndpoint endpoint)
        {
            if (!endpoint.HasParameters) return endpoint.Url;

            var uriBuilder = new UriBuilder(endpoint.Url);
            var query = string.Join("&", endpoint.Parameters
                .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

            if (uriBuilder.Query.Length > 1)
                uriBuilder.Query = uriBuilder.Query.Substring(1) + "&" + query;
            else
                uriBuilder.Query = query;

            return uriBuilder.ToString();
        }

        private void LogRequest(ProductionHttpResponse response, string category)
        {
            var entry = new RequestLogEntry
            {
                Id = RequestLogs.Count + 1,
                Timestamp = DateTime.Now,
                Method = response.RequestDetails?.Split(' ')[0] ?? "GET",
                Category = category,
                Url = response.Url.Length > 80 ? response.Url.Substring(0, 80) + "..." : response.Url,
                Payload = ExtractPayloadFromResponse(response),
                StatusCode = response.StatusCode,
                Size = response.Body?.Length ?? 0,
                ResponseTime = response.ResponseTime / 1000.0,
                Result = GetResultFromResponse(response),
                RequestDetails = response.RequestDetails,
                ResponseDetails = response.ResponseDetails
            };

            RequestLogged?.Invoke(this, entry);
            UpdateStatistics();
            _serverHealthMonitor.RecordResponse(response);
        }

        private string ExtractPayloadFromResponse(ProductionHttpResponse response)
        {
            try
            {
                if (response.RequestDetails.Contains("?"))
                {
                    var queryStart = response.RequestDetails.IndexOf('?');
                    var query = response.RequestDetails.Substring(queryStart);
                    return query.Length > 40 ? query.Substring(0, 40) + "..." : query;
                }
                return response.Url.Contains("?") ? response.Url.Split('?')[1] : "N/A";
            }
            catch
            {
                return "N/A";
            }
        }

        private string GetResultFromResponse(ProductionHttpResponse response)
        {
            if (response.StatusCode >= 200 && response.StatusCode < 300)
                return "SAFE";
            else if (response.StatusCode >= 400 && response.StatusCode < 500)
                return "CLIENT_ERROR";
            else if (response.StatusCode >= 500)
                return "SERVER_ERROR";
            else
                return "UNKNOWN";
        }

        private void ReportVulnerability(VulnerabilityDetectionResult result)
        {
            if (!result.IsVulnerable) return;

            var vuln = result.Vulnerability;

            var existing = Vulnerabilities.FirstOrDefault(v =>
                v.Url == vuln.Url &&
                v.Parameter == vuln.Parameter &&
                v.Type == vuln.Type &&
                Math.Abs(v.Confidence - vuln.Confidence) < 10);

            if (existing != null) return;

            VulnerabilityFound?.Invoke(this, vuln);
        }

        private int CalculateRiskScore(string severity, int confidence)
        {
            var severityScore = severity switch
            {
                "CRITICAL" => 100,
                "HIGH" => 75,
                "MEDIUM" => 50,
                "LOW" => 25,
                _ => 10
            };

            return (int)(severityScore * (confidence / 100.0));
        }

        private string GetCweForIssue(string issueType)
        {
            return issueType switch
            {
                var t when t.Contains("SQL") => "CWE-89",
                var t when t.Contains("XSS") => "CWE-79",
                var t when t.Contains("IDOR") => "CWE-639",
                var t when t.Contains("SSRF") => "CWE-918",
                var t when t.Contains("Command") => "CWE-78",
                var t when t.Contains("Path") => "CWE-22",
                var t when t.Contains("TLS") => "CWE-326",
                var t when t.Contains("Cookie") => "CWE-614",
                var t when t.Contains("Header") => "CWE-693",
                var t when t.Contains("Component") => "CWE-1104",
                _ => "CWE-000"
            };
        }

        private string GetImpactForIssue(string issueType)
        {
            return issueType switch
            {
                var t when t.Contains("SQL") => "Data breach, authentication bypass, data manipulation",
                var t when t.Contains("XSS") => "Session hijacking, credential theft, defacement",
                var t when t.Contains("IDOR") => "Unauthorized data access, privilege escalation",
                var t when t.Contains("SSRF") => "Internal network access, cloud metadata exposure",
                var t when t.Contains("Command") => "Remote code execution, server compromise",
                var t when t.Contains("Path") => "Sensitive file disclosure, directory traversal",
                var t when t.Contains("TLS") => "Man-in-the-middle attacks, data interception",
                var t when t.Contains("Cookie") => "Session hijacking, CSRF attacks",
                var t when t.Contains("Header") => "Information disclosure, security control bypass",
                var t when t.Contains("Component") => "Known vulnerability exploitation, supply chain attacks",
                _ => "Security control weakness"
            };
        }

        private string GetRemediationForIssue(string issueType)
        {
            return issueType switch
            {
                var t when t.Contains("SQL") => "Use parameterized queries, stored procedures, ORM with built-in protection",
                var t when t.Contains("XSS") => "Implement Content Security Policy, output encoding, input validation",
                var t when t.Contains("IDOR") => "Implement proper access control checks, use UUIDs, validate ownership",
                var t when t.Contains("SSRF") => "Implement URL allowlisting, network segmentation, disable dangerous protocols",
                var t when t.Contains("Command") => "Use parameterized APIs, avoid system() calls, implement input validation",
                var t when t.Contains("Path") => "Implement path validation, use chroot/jail, normalize paths",
                var t when t.Contains("TLS") => "Upgrade to TLS 1.2+, use strong cipher suites, implement HSTS",
                var t when t.Contains("Cookie") => "Set Secure, HttpOnly, SameSite attributes, use proper scope",
                var t when t.Contains("Header") => "Implement security headers (CSP, HSTS, X-Frame-Options, etc.)",
                var t when t.Contains("Component") => "Update to latest secure versions, monitor for vulnerabilities",
                _ => "Review and implement security best practices"
            };
        }

        private async Task UpdateProgress(int percentage, string status)
        {
            ProgressUpdated?.Invoke(this, new ProgressUpdate { Percentage = percentage, Status = status });
            await Task.Delay(10);
        }

        private void UpdateStatistics()
        {
            var now = DateTime.Now;
            var elapsed = (now - _lastStatsUpdate).TotalSeconds;

            if (elapsed >= 1.0)
            {
                var requestsDelta = RequestLogs.Count - _lastRequestCount;
                var requestsPerSecond = requestsDelta / elapsed;

                RealTimeStats = new ScanStatistics
                {
                    TotalRequests = RequestLogs.Count,
                    VulnerabilitiesFound = Vulnerabilities.Count,
                    RequestsPerSecond = requestsPerSecond,
                    ElapsedTime = _scanStopwatch.Elapsed,
                    AverageResponseTime = RequestLogs.Any() ? RequestLogs.Average(r => r.ResponseTime) : 0,
                    ScopeViolations = RealTimeStats?.ScopeViolations ?? 0,
                    ServerHealthStatus = _serverHealthMonitor.CurrentStatus
                };

                StatsUpdated?.Invoke(this, RealTimeStats);

                _lastRequestCount = RequestLogs.Count;
                _lastStatsUpdate = now;
            }
        }

        private void OnServerHealthStatusChanged(object sender, ServerHealthStatus status)
        {
            RealTimeStats.ServerHealthStatus = status;
            ServerInstabilityDetected?.Invoke(this, status);

            if (status == ServerHealthStatus.Critical)
            {
                _rateLimiter.SetRateLimit(1);
            }
            else if (status == ServerHealthStatus.Unstable)
            {
                _rateLimiter.SetRateLimit(Configuration.RateLimitRequestsPerSecond / 2);
            }
            else
            {
                _rateLimiter.SetRateLimit(Configuration.RateLimitRequestsPerSecond);
            }
        }

        public void ContinueWithAuthorization()
        {
            _sensitiveTestsAuthorized = true;
            Log("✅ Sensitive tests authorized to proceed");
        }

        public void SkipSensitiveTests()
        {
            _sensitiveTestsAuthorized = false;
            Log("⏭️ Sensitive tests skipped as requested");
        }

        private void GenerateScanSummary()
        {
            var criticalCount = Vulnerabilities.Count(v => v.Severity == "CRITICAL");
            var highCount = Vulnerabilities.Count(v => v.Severity == "HIGH");
            var mediumCount = Vulnerabilities.Count(v => v.Severity == "MEDIUM");
            var lowCount = Vulnerabilities.Count(v => v.Severity == "LOW");

            var totalRisk = Vulnerabilities.Sum(v => v.RiskScore);
            var avgConfidence = Vulnerabilities.Any() ? Vulnerabilities.Average(v => v.Confidence) : 0;

            Log($"\n📊 ENTERPRISE SCAN SUMMARY:");
            Log($"   🎯 Total Findings: {Vulnerabilities.Count}");
            Log($"   💀 CRITICAL: {criticalCount}");
            Log($"   🔥 HIGH: {highCount}");
            Log($"   ⚠️ MEDIUM: {mediumCount}");
            Log($"   📝 LOW: {lowCount}");
            Log($"   📈 Average Confidence: {avgConfidence:F1}%");
            Log($"   🎲 Total Risk Score: {totalRisk}");
            Log($"   ⏱️ Scan Duration: {_scanStopwatch.Elapsed.TotalMinutes:0.0} minutes");
            Log($"   📨 Total Requests: {RequestLogs.Count}");
            Log($"   🚫 Scope Violations: {RealTimeStats.ScopeViolations}");
            Log($"   🩺 Server Health: {_serverHealthMonitor.CurrentStatus}");
        }

        private void LogScanCompletion()
        {
            Log($"\n✅ ENTERPRISE SCAN COMPLETE");
            Log($"   Scanner Version: 2.0.0");
            Log($"   TLS Mode: {Configuration.TlsValidationMode}");
            Log($"   Scope: {string.Join(", ", CurrentScope.Domains)}");
            Log($"   Authorized by: {_authorization?.User ?? "Unknown"}");
            Log($"   Authorization Time: {_authorization?.Timestamp:yyyy-MM-dd HH:mm:ss}");
            Log($"\n⚠️ IMPORTANT: Automated scanning has limitations:");
            Log($"   - Does not replace manual penetration testing");
            Log($"   - Limited to detectable patterns");
            Log($"   - Business logic flaws may be missed");
            Log($"   - Always validate findings manually");
        }

        private string ComputeHash(string text)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;
            using var sha256 = SHA256.Create();
            return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(text)));
        }

        public EnterpriseScanReportResult GenerateEnterpriseReport(bool includeExecutiveSummary, bool includeTechnicalDetails, bool includeScanMetadata)
        {
            var report = new EnterpriseScanReport
            {
                Metadata = new ScanMetadata
                {
                    ScannerVersion = "2.0.0",
                    ScannerHash = ComputeHash(typeof(ProductionScannerEngine).AssemblyQualifiedName),
                    ScanId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    ScanDuration = _scanStopwatch.Elapsed,
                    TargetScope = CurrentScope.Domains.ToList(),
                    TlsValidationMode = Configuration.TlsValidationMode.ToString(),
                    AuthorizationRecord = _authorization
                },
                Statistics = new EnterpriseReportStatistics
                {
                    TotalRequests = RequestLogs.Count,
                    TotalFindings = Vulnerabilities.Count,
                    CriticalCount = Vulnerabilities.Count(v => v.Severity == "CRITICAL"),
                    HighCount = Vulnerabilities.Count(v => v.Severity == "HIGH"),
                    MediumCount = Vulnerabilities.Count(v => v.Severity == "MEDIUM"),
                    LowCount = Vulnerabilities.Count(v => v.Severity == "LOW"),
                    AverageConfidence = Vulnerabilities.Any() ? Vulnerabilities.Average(v => v.Confidence) : 0,
                    TotalRiskScore = Vulnerabilities.Sum(v => v.RiskScore),
                    ScopeViolations = RealTimeStats.ScopeViolations,
                    ServerHealthStatus = _serverHealthMonitor.CurrentStatus.ToString()
                },
                Findings = includeTechnicalDetails ? Vulnerabilities.ToList() : new List<Vulnerability>(),
                ExecutiveSummary = includeExecutiveSummary ? GenerateExecutiveSummary() : null,
                Recommendations = GenerateRecommendations(),
                Limitations = GenerateLimitations(),
                CoverageMatrix = GenerateCoverageMatrixDetails()
            };

            var jsonReport = JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            return new EnterpriseScanReportResult
            {
                Report = report,
                JsonReport = jsonReport,
                Timestamp = DateTime.UtcNow
            };
        }

        private ExecutiveSummary GenerateExecutiveSummary()
        {
            var criticalFindings = Vulnerabilities.Where(v => v.Severity == "CRITICAL").ToList();
            var highFindings = Vulnerabilities.Where(v => v.Severity == "HIGH").ToList();

            return new ExecutiveSummary
            {
                BusinessRiskLevel = CalculateBusinessRiskLevel(),
                TopRisks = criticalFindings.Take(5).Select(v => new RiskItem
                {
                    Type = v.Type,
                    Severity = v.Severity,
                    Impact = v.Impact,
                    Url = v.Url
                }).ToList(),
                AssetExposure = CalculateAssetExposure(),
                RiskHeatmap = GenerateRiskHeatmap(),
                TimeToRemediate = CalculateTimeToRemediate(),
                ComplianceGaps = IdentifyComplianceGaps()
            };
        }

        private string CalculateBusinessRiskLevel()
        {
            var criticalCount = Vulnerabilities.Count(v => v.Severity == "CRITICAL");
            var highCount = Vulnerabilities.Count(v => v.Severity == "HIGH");
            var totalRisk = Vulnerabilities.Sum(v => v.RiskScore);

            if (criticalCount > 3 || totalRisk > 500) return "CRITICAL";
            if (criticalCount > 0 || highCount > 5 || totalRisk > 200) return "HIGH";
            if (highCount > 0 || totalRisk > 50) return "MEDIUM";
            return "LOW";
        }

        private AssetExposure CalculateAssetExposure()
        {
            var exposedEndpoints = RequestLogs.Select(r => r.Url).Distinct().Count();
            var authEndpoints = RequestLogs.Count(r => r.Url.Contains("login") || r.Url.Contains("auth"));
            var adminEndpoints = RequestLogs.Count(r => r.Url.Contains("admin") || r.Url.Contains("manage"));

            return new AssetExposure
            {
                TotalEndpoints = exposedEndpoints,
                AuthenticationEndpoints = authEndpoints,
                AdministrativeEndpoints = adminEndpoints,
                DataInputPoints = RequestLogs.Count(r => r.Category.Contains("POST") || r.Category.Contains("PUT")),
                ExternalDependencies = _componentTester.GetDiscoveredComponents().Count
            };
        }

        private RiskHeatmap GenerateRiskHeatmap()
        {
            var heatmap = new RiskHeatmap
            {
                OWASP01 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A01")),
                OWASP02 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A02")),
                OWASP03 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A03")),
                OWASP04 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A04")),
                OWASP05 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A05")),
                OWASP06 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A06")),
                OWASP07 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A07")),
                OWASP08 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A08")),
                OWASP09 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A09")),
                OWASP10 = Vulnerabilities.Count(v => v.OWASPCategory.Contains("A10"))
            };

            heatmap.HighestRiskCategory = heatmap.GetHighestRiskCategory();
            return heatmap;
        }

        private TimeSpan CalculateTimeToRemediate()
        {
            var criticalCount = Vulnerabilities.Count(v => v.Severity == "CRITICAL");
            var highCount = Vulnerabilities.Count(v => v.Severity == "HIGH");

            var totalHours = criticalCount * 8 + highCount * 4;
            return TimeSpan.FromHours(totalHours);
        }

        private List<string> IdentifyComplianceGaps()
        {
            var gaps = new List<string>();

            if (Vulnerabilities.Any(v => v.OWASPCategory.Contains("A02")))
                gaps.Add("Cryptographic controls (PCI DSS 3.2.1, NIST 800-53 SC-13)");

            if (Vulnerabilities.Any(v => v.OWASPCategory.Contains("A01")))
                gaps.Add("Access control (ISO 27001 A.9, NIST 800-53 AC-3)");

            if (Vulnerabilities.Any(v => v.OWASPCategory.Contains("A03") || v.OWASPCategory.Contains("A07")))
                gaps.Add("Input validation (OWASP ASVS V5, PCI DSS 6.5)");

            if (Vulnerabilities.Any(v => v.OWASPCategory.Contains("A09")))
                gaps.Add("Logging and monitoring (ISO 27001 A.12, NIST 800-53 AU-6)");

            return gaps;
        }

        private List<Recommendation> GenerateRecommendations()
        {
            var recommendations = new List<Recommendation>();

            if (Vulnerabilities.Any(v => v.Type.Contains("SQL Injection")))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "CRITICAL",
                    Category = "A03: Injection",
                    Description = "Implement parameterized queries or use an ORM with built-in SQL injection protection",
                    Timeline = "Immediate",
                    Effort = "Medium",
                    BusinessImpact = "Prevents data breaches and authentication bypass"
                });
            }

            if (Vulnerabilities.Any(v => v.Type.Contains("XSS")))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "HIGH",
                    Category = "A07: XSS",
                    Description = "Implement Content Security Policy (CSP) and ensure all user input is properly encoded",
                    Timeline = "1-2 weeks",
                    Effort = "Medium",
                    BusinessImpact = "Prevents session hijacking and client-side attacks"
                });
            }

            if (Vulnerabilities.Any(v => v.Type.Contains("IDOR")))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "HIGH",
                    Category = "A01: Broken Access Control",
                    Description = "Implement proper access control checks and consider using UUIDs instead of sequential IDs",
                    Timeline = "2-4 weeks",
                    Effort = "High",
                    BusinessImpact = "Prevents unauthorized data access and privilege escalation"
                });
            }

            if (Vulnerabilities.Any(v => v.OWASPCategory == "A02:2021-Cryptographic Failures"))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "HIGH",
                    Category = "A02: Cryptographic Failures",
                    Description = "Upgrade to TLS 1.2+, use strong cipher suites, and implement HSTS",
                    Timeline = "2-4 weeks",
                    Effort = "Medium",
                    BusinessImpact = "Prevents man-in-the-middle attacks and data interception"
                });
            }

            if (Vulnerabilities.Any(v => v.OWASPCategory == "A05:2021-Security Misconfiguration"))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "MEDIUM",
                    Category = "A05: Security Misconfiguration",
                    Description = "Harden security headers and remove unnecessary information disclosure",
                    Timeline = "1-2 weeks",
                    Effort = "Low",
                    BusinessImpact = "Reduces attack surface and information leakage"
                });
            }

            if (Vulnerabilities.Any(v => v.OWASPCategory == "A06:2021-Vulnerable Components"))
            {
                recommendations.Add(new Recommendation
                {
                    Priority = "MEDIUM",
                    Category = "A06: Vulnerable Components",
                    Description = "Establish component inventory and vulnerability management process",
                    Timeline = "4-8 weeks",
                    Effort = "High",
                    BusinessImpact = "Prevents known vulnerability exploitation and supply chain attacks"
                });
            }

            return recommendations;
        }

        private ScannerLimitations GenerateLimitations()
        {
            return new ScannerLimitations
            {
                AutomatedCoverage = "70-80% of detectable patterns",
                ManualTestingRequired = "Business logic, authorization logic, complex workflows",
                FalsePositiveRate = "5-15% depending on application complexity",
                BlindSpots = new List<string>
                {
                    "Stored XSS requiring specific user interaction",
                    "Complex business logic bypasses",
                    "Multi-step authentication bypass",
                    "Race conditions",
                    "DOM-based vulnerabilities requiring JavaScript execution",
                    "Client-side logic flaws"
                },
                Assumptions = new List<string>
                {
                    "Standard HTTP/HTTPS protocols",
                    "HTML/JSON/XML response formats",
                    "Stateless or session-based authentication",
                    "RESTful or traditional web architecture"
                }
            };
        }

        private CoverageMatrix GenerateCoverageMatrixDetails()
        {
            return new CoverageMatrix
            {
                OWASP01 = new CoverageLevel { Automated = "High", Notes = "IDOR, path traversal, method tampering" },
                OWASP02 = new CoverageLevel { Automated = "High", Notes = "TLS, certificates, cookies, headers" },
                OWASP03 = new CoverageLevel { Automated = "High", Notes = "SQLi, command injection, NoSQL (basic)" },
                OWASP04 = new CoverageLevel { Automated = "Low", Notes = "Design pattern indicators only" },
                OWASP05 = new CoverageLevel { Automated = "Medium", Notes = "Headers, configurations, defaults" },
                OWASP06 = new CoverageLevel { Automated = "Medium", Notes = "Version detection, known CVE mapping" },
                OWASP07 = new CoverageLevel { Automated = "High", Notes = "Reflected XSS, basic auth weaknesses" },
                OWASP08 = new CoverageLevel { Automated = "Low", Notes = "Basic integrity check indicators" },
                OWASP09 = new CoverageLevel { Automated = "Low", Notes = "Logging header and error message analysis" },
                OWASP10 = new CoverageLevel { Automated = "Medium", Notes = "SSRF with response analysis" }
            };
        }

        public string GenerateHtmlReport(bool includeExecutiveSummary)
        {
            var criticalCount = Vulnerabilities.Count(v => v.Severity == "CRITICAL");
            var highCount = Vulnerabilities.Count(v => v.Severity == "HIGH");
            var totalRisk = Vulnerabilities.Sum(v => v.RiskScore);
            var businessRisk = CalculateBusinessRiskLevel();

            var coverageMatrix = GenerateCoverageMatrixDetails();

            return $@"<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Security Assessment Report</title>
    <meta charset='UTF-8'>
    <style>
        body {{ 
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; 
            margin: 0;
            padding: 0;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{ 
            background: linear-gradient(135deg, #1a237e 0%, #283593 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }}
        
        .disclaimer {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
            font-size: 14px;
        }}
        
        .risk-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 8px;
        }}
        
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #fd7e14; color: white; }}
        .risk-medium {{ background: #ffc107; color: #212529; }}
        .risk-low {{ background: #28a745; color: white; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .stat-card .value {{
            font-size: 32px;
            font-weight: 700;
            margin: 10px 0;
        }}
        
        .coverage-matrix {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin: 30px 0;
        }}
        
        .coverage-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        .coverage-table th,
        .coverage-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        
        .coverage-table th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        
        .vulnerability-list {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin: 30px 0;
        }}
        
        .vulnerability-item {{
            padding: 20px;
            margin: 10px 0;
            border-left: 4px solid;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        
        .vulnerability-critical {{ border-left-color: #dc3545; }}
        .vulnerability-high {{ border-left-color: #fd7e14; }}
        .vulnerability-medium {{ border-left-color: #ffc107; }}
        .vulnerability-low {{ border-left-color: #28a745; }}
        
        .recommendations {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin: 30px 0;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class='header'>
        <div class='header-content'>
            <h1>🔒 Enterprise Security Assessment Report</h1>
            <p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss} UTC</p>
            <p>Scan Duration: {_scanStopwatch.Elapsed.TotalMinutes:0.0} minutes</p>
            <p>Target Scope: {string.Join(", ", CurrentScope.Domains)}</p>
        </div>
    </div>
    
    <div class='container'>
        <div class='disclaimer'>
            <strong>⚠️ IMPORTANT DISCLAIMER:</strong> This report is generated by an automated security scanner. 
            It does not replace manual penetration testing or code review. Findings should be validated manually. 
            Automated scanning has inherent limitations and may produce false positives or miss certain vulnerabilities.
        </div>
        
        {(includeExecutiveSummary ? $@"
        <div class='stats-grid'>
            <div class='stat-card'>
                <h3>Business Risk Level</h3>
                <div class='value'><span class='risk-badge risk-{businessRisk.ToLower()}'>{businessRisk}</span></div>
            </div>
            <div class='stat-card'>
                <h3>Total Findings</h3>
                <div class='value'>{Vulnerabilities.Count}</div>
            </div>
            <div class='stat-card'>
                <h3>Critical Findings</h3>
                <div class='value'>{criticalCount}</div>
            </div>
            <div class='stat-card'>
                <h3>Total Risk Score</h3>
                <div class='value'>{totalRisk}</div>
            </div>
        </div>
        
        <div class='coverage-matrix'>
            <h2>📊 Scanner Coverage Matrix</h2>
            <p>This shows what the automated scanner can and cannot detect reliably:</p>
            
            <table class='coverage-table'>
                <tr>
                    <th>OWASP Category</th>
                    <th>Automated Coverage</th>
                    <th>Notes</th>
                </tr>
                <tr>
                    <td>A01: Broken Access Control</td>
                    <td>{coverageMatrix.OWASP01.Automated}</td>
                    <td>{coverageMatrix.OWASP01.Notes}</td>
                </tr>
                <tr>
                    <td>A02: Cryptographic Failures</td>
                    <td>{coverageMatrix.OWASP02.Automated}</td>
                    <td>{coverageMatrix.OWASP02.Notes}</td>
                </tr>
                <tr>
                    <td>A03: Injection</td>
                    <td>{coverageMatrix.OWASP03.Automated}</td>
                    <td>{coverageMatrix.OWASP03.Notes}</td>
                </tr>
                <tr>
                    <td>A04: Insecure Design</td>
                    <td>{coverageMatrix.OWASP04.Automated}</td>
                    <td>{coverageMatrix.OWASP04.Notes}</td>
                </tr>
                <tr>
                    <td>A05: Security Misconfiguration</td>
                    <td>{coverageMatrix.OWASP05.Automated}</td>
                    <td>{coverageMatrix.OWASP05.Notes}</td>
                </tr>
                <tr>
                    <td>A06: Vulnerable Components</td>
                    <td>{coverageMatrix.OWASP06.Automated}</td>
                    <td>{coverageMatrix.OWASP06.Notes}</td>
                </tr>
                <tr>
                    <td>A07: Identification & Auth Failures</td>
                    <td>{coverageMatrix.OWASP07.Automated}</td>
                    <td>{coverageMatrix.OWASP07.Notes}</td>
                </tr>
                <tr>
                    <td>A08: Software & Data Integrity</td>
                    <td>{coverageMatrix.OWASP08.Automated}</td>
                    <td>{coverageMatrix.OWASP08.Notes}</td>
                </tr>
                <tr>
                    <td>A09: Security Logging & Monitoring</td>
                    <td>{coverageMatrix.OWASP09.Automated}</td>
                    <td>{coverageMatrix.OWASP09.Notes}</td>
                </tr>
                <tr>
                    <td>A10: Server-Side Request Forgery</td>
                    <td>{coverageMatrix.OWASP10.Automated}</td>
                    <td>{coverageMatrix.OWASP10.Notes}</td>
                </tr>
            </table>
        </div>
        " : "")}
        
        <div class='vulnerability-list'>
            <h2>🚨 Critical & High Severity Findings</h2>
            {string.Join("", Vulnerabilities
                .Where(v => v.Severity == "CRITICAL" || v.Severity == "HIGH")
                .OrderByDescending(v => v.RiskScore)
                .Select(v => $@"
                <div class='vulnerability-item vulnerability-{v.Severity.ToLower()}'>
                    <h3>{v.Type} <span style='float: right;'>Confidence: {v.Confidence}%</span></h3>
                    <p><strong>URL:</strong> {v.Url}</p>
                    <p><strong>Parameter:</strong> {v.Parameter}</p>
                    <p><strong>Evidence:</strong> {WebUtility.HtmlEncode(v.Evidence)}</p>
                    <p><strong>CWE:</strong> {v.CWE}</p>
                    <p><strong>Impact:</strong> {v.Impact}</p>
                    <p><strong>Remediation:</strong> {v.Remediation}</p>
                    {(string.IsNullOrEmpty(v.Note) ? "" : $"<p><strong>Note:</strong> {v.Note}</p>")}
                </div>
                "))}
        </div>
        
        <div class='recommendations'>
            <h2>✅ Recommended Actions</h2>
            <ol>
            {string.Join("", GenerateRecommendations().Select(r => $@"
                <li>
                    <strong>{r.Priority} - {r.Category}:</strong> {r.Description}
                    <br><small>Timeline: {r.Timeline} | Effort: {r.Effort} | Impact: {r.BusinessImpact}</small>
                </li>
            "))}
            </ol>
        </div>
        
        <div class='footer'>
            <p>Report generated by Enterprise Security Scanner v2.0.0</p>
            <p>Scan ID: {Guid.NewGuid().ToString().Substring(0, 8)}</p>
            <p>Authorized by: {_authorization?.User ?? "Unknown"} at {_authorization?.Timestamp:yyyy-MM-dd HH:mm:ss}</p>
            <p>© {DateTime.Now.Year} Enterprise Security Services. Confidential.</p>
        </div>
    </div>
</body>
</html>";
        }

        public string GenerateCoverageMatrix()
        {
            var matrix = GenerateCoverageMatrixDetails();

            return $@"# Enterprise Security Scanner - Coverage Matrix
Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}

## Automated Detection Capabilities

### ✅ High Coverage (80-90% detectable)
- **A01: Broken Access Control**
  - IDOR detection via sequential ID testing
  - Path traversal via directory traversal attempts
  - Method tampering (GET → POST → PUT)
  - Horizontal privilege escalation indicators

- **A02: Cryptographic Failures**
  - TLS/SSL configuration analysis
  - Certificate validation and expiration
  - Cookie security attributes (Secure, HttpOnly, SameSite)
  - Missing security headers (HSTS, etc.)

- **A03: Injection**
  - SQL injection via error-based and time-based detection
  - Command injection via OS command patterns
  - Basic NoSQL injection patterns
  - LDAP injection indicators

- **A07: Cross-Site Scripting (XSS)**
  - Reflected XSS via payload reflection analysis
  - Basic stored XSS indicators
  - DOM XSS via parameter analysis

### ⚠️ Medium Coverage (50-70% detectable)
- **A05: Security Misconfiguration**
  - Default credentials and installations
  - Directory listing enabled
  - Debug/error messages exposed
  - Unnecessary HTTP methods

- **A06: Vulnerable Components**
  - Version detection via banners and signatures
  - Known CVE matching via offline database
  - Outdated library detection

- **A10: Server-Side Request Forgery (SSRF)**
  - Internal endpoint access attempts
  - Cloud metadata service probing
  - Basic SSRF via response analysis

### 📝 Low Coverage (20-40% detectable)
- **A04: Insecure Design**
  - Rate limiting absence indicators
  - Predictable resource identifiers
  - Missing abuse protections (basic)

- **A08: Software and Data Integrity**
  - Unsigned update mechanisms
  - Insecure deserialization patterns (basic)
  - Client-side trust issues

- **A09: Security Logging & Monitoring**
  - Missing security event indicators
  - Error disclosure patterns
  - Logging header analysis

## 🔍 Manual Testing Required
The following require manual security testing:

- Business logic vulnerabilities
- Complex authorization bypass
- Multi-step attack chains
- Race conditions
- DOM-based XSS requiring specific user interaction
- Stored XSS with complex payload requirements
- Authentication bypass requiring specific sequences
- Configuration issues in non-standard deployments

## 📊 Detection Methodology
1. **Baseline Establishment**: Normal response patterns
2. **Control Requests**: Valid requests for comparison
3. **Test Payloads**: Security-focused test inputs
4. **Response Analysis**: Delta analysis from baseline
5. **Confidence Scoring**: Multi-factor confidence calculation
6. **False Positive Reduction**: Heuristic filtering

## ⚠️ Limitations & Assumptions
- Assumes standard web architecture
- Limited to HTTP/HTTPS protocols
- Requires service availability during scan
- May not detect complex, multi-vector attacks
- Business logic flaws often require manual testing

## 🎯 Recommended Usage
1. **Initial Assessment**: Broad coverage for common vulnerabilities
2. **Continuous Scanning**: Regular checks for new issues
3. **Pre-Deployment**: Final security check before production
4. **Compliance**: Supporting evidence for security controls
5. **Education**: Developer awareness of common vulnerabilities

**Note**: This tool supplements but does not replace manual penetration testing.";
        }

        private void Log(string message) => LogMessage?.Invoke(this, message);
    }

    public class ScannerConfiguration
    {
        public TlsValidationMode TlsValidationMode { get; set; } = TlsValidationMode.Strict;
        public ScopeEnforcement ScopeEnforcement { get; set; } = ScopeEnforcement.Strict;
        public int RateLimitRequestsPerSecond { get; set; } = 10;
        public int MaxConcurrentRequests { get; set; } = 5;
        public int RequestBudget { get; set; } = 10000;
        public int RequestTimeoutSeconds { get; set; } = 30;
        public int MinimumConfidenceThreshold { get; set; } = 70;
        public bool EnableOutOfBandTesting { get; set; } = false;
        public bool EnableBlindInjectionTesting { get; set; } = false;
        public bool EnableCloudMetadataTesting { get; set; } = false;
        public bool EnableAuthenticationTesting { get; set; } = false;
        public bool EnableComponentAnalysis { get; set; } = true;
        public bool EnableCryptographicTesting { get; set; } = true;
        public bool EnableSecurityHeaderAnalysis { get; set; } = true;
        public bool RequireAuthorizationForSensitiveTests { get; set; } = true;
        public HashSet<string> PinnedCertificates { get; set; } = new HashSet<string>();
    }

    public enum TlsValidationMode
    {
        Strict,
        Pinned,
        Insecure
    }

    public enum ScopeEnforcement
    {
        Strict,
        Permissive,
        None
    }

    public enum ServerHealthStatus
    {
        Normal,
        Unstable,
        Critical,
        Degraded
    }

    public class ScanScope
    {
        public HashSet<string> Domains { get; set; } = new HashSet<string>();
        public List<string> AllowedCidrs { get; set; } = new List<string>();
        public bool AllowIpLiterals { get; set; } = false;

        public bool IsUrlInScope(string url)
        {
            try
            {
                var uri = new Uri(url);

                if (!AllowIpLiterals && IsIpAddress(uri.Host))
                    return false;

                if (Domains.Contains(uri.Host))
                    return true;

                if (Domains.Any(domain => uri.Host.EndsWith($".{domain}")))
                    return true;

                if (AllowedCidrs.Any() && IsIpAddress(uri.Host))
                {
                    var ip = IPAddress.Parse(uri.Host);
                    return AllowedCidrs.Any(cidr => IsInCidrRange(ip, cidr));
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool IsIpAddress(string host)
        {
            return IPAddress.TryParse(host, out _);
        }

        private bool IsInCidrRange(IPAddress ip, string cidr)
        {
            try
            {
                var parts = cidr.Split('/');
                var rangeIp = IPAddress.Parse(parts[0]);
                var prefixLength = int.Parse(parts[1]);

                if (rangeIp.AddressFamily != ip.AddressFamily)
                    return false;

                var rangeBytes = rangeIp.GetAddressBytes();
                var ipBytes = ip.GetAddressBytes();

                if (prefixLength == 0)
                    return true;

                var fullBytes = prefixLength / 8;
                var remainingBits = prefixLength % 8;

                for (int i = 0; i < fullBytes; i++)
                {
                    if (rangeBytes[i] != ipBytes[i])
                        return false;
                }

                if (remainingBits > 0)
                {
                    var mask = (byte)(0xFF << (8 - remainingBits));
                    return (rangeBytes[fullBytes] & mask) == (ipBytes[fullBytes] & mask);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public class AuthorizationRecord
    {
        public string User { get; set; }
        public DateTime Timestamp { get; set; }
        public List<string> Scope { get; set; }
    }

    public class RateLimiter
    {
        private SemaphoreSlim _semaphore;
        private int _requestsPerSecond;
        private DateTime _lastRequestTime = DateTime.MinValue;
        private object _lock = new object();

        public RateLimiter(int requestsPerSecond)
        {
            _requestsPerSecond = requestsPerSecond;
            _semaphore = new SemaphoreSlim(1, 1);
        }

        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                var now = DateTime.Now;
                var timeSinceLastRequest = now - _lastRequestTime;
                var minimumDelay = TimeSpan.FromSeconds(1.0 / _requestsPerSecond);

                if (timeSinceLastRequest < minimumDelay)
                {
                    var delayNeeded = minimumDelay - timeSinceLastRequest;
                    await Task.Delay(delayNeeded, cancellationToken);
                }

                _lastRequestTime = DateTime.Now;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public void SetRateLimit(int requestsPerSecond)
        {
            _requestsPerSecond = requestsPerSecond;
        }
    }

    public class ServerHealthMonitor
    {
        private ConcurrentQueue<ProductionHttpResponse> _recentResponses = new ConcurrentQueue<ProductionHttpResponse>();
        private Timer _monitoringTimer;
        private ServerHealthStatus _currentStatus = ServerHealthStatus.Normal;
        private object _statusLock = new object();

        public event EventHandler<ServerHealthStatus> HealthStatusChanged;

        public ServerHealthStatus CurrentStatus
        {
            get { lock (_statusLock) return _currentStatus; }
            private set { lock (_statusLock) _currentStatus = value; }
        }

        public void StartMonitoring()
        {
            _monitoringTimer = new Timer(MonitorHealth, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));
        }

        public void StopMonitoring()
        {
            _monitoringTimer?.Dispose();
        }

        public void RecordResponse(ProductionHttpResponse response)
        {
            _recentResponses.Enqueue(response);
            while (_recentResponses.Count > 100)
                _recentResponses.TryDequeue(out _);
        }

        private void MonitorHealth(object state)
        {
            var responses = _recentResponses.ToArray();
            if (responses.Length < 10) return;

            var recent = responses.TakeLast(20).ToArray();

            var errorRate = recent.Count(r => r.StatusCode >= 500) / (double)recent.Length;
            var timeoutRate = recent.Count(r => r.StatusCode == 0 || r.ResponseTime > 10000) / (double)recent.Length;
            var avgResponseTime = recent.Where(r => r.StatusCode != 0).Average(r => r.ResponseTime);

            var newStatus = ServerHealthStatus.Normal;

            if (errorRate > 0.3 || timeoutRate > 0.5)
                newStatus = ServerHealthStatus.Critical;
            else if (errorRate > 0.1 || timeoutRate > 0.2 || avgResponseTime > 5000)
                newStatus = ServerHealthStatus.Unstable;
            else if (errorRate > 0.05 || avgResponseTime > 2000)
                newStatus = ServerHealthStatus.Degraded;

            if (newStatus != CurrentStatus)
            {
                CurrentStatus = newStatus;
                HealthStatusChanged?.Invoke(this, newStatus);
            }
        }

        public void Reset()
        {
            _recentResponses.Clear();
            CurrentStatus = ServerHealthStatus.Normal;
        }
    }

    public class ScopeViolation
    {
        public string RequestedUrl { get; set; }
        public string Reason { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ScanContext
    {
        public string BaseUrl { get; set; }
        public AuthorizationRecord Authorization { get; set; }
        public ScannerConfiguration Configuration { get; set; }
        public ScanScope Scope { get; set; }
        public CancellationToken CancellationToken { get; set; }
        public List<ProductionEndpoint> Endpoints { get; set; } = new List<ProductionEndpoint>();
    }

    public class ScanPhase
    {
        public string Name { get; set; }
        public int Weight { get; set; }
        public bool RequiresSensitiveAuthorization { get; set; }
        public Func<ScanContext, Task> Action { get; set; }
    }

    public class UnauthorizedScanException : Exception
    {
        public UnauthorizedScanException(string message) : base(message) { }
    }

    public class ScopeViolationException : Exception
    {
        public ScopeViolationException(string message) : base(message) { }
    }

    public class RequestBudgetExceededException : Exception
    {
        public RequestBudgetExceededException(string message) : base(message) { }
    }

    public class VulnerabilityDetectionResult
    {
        public bool IsVulnerable { get; set; }
        public Vulnerability Vulnerability { get; set; }
        public string EvidenceDetails { get; set; }
        public int Confidence { get; set; }
    }

    public class RequestLogEntry
    {
        public int Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string Method { get; set; }
        public string Category { get; set; }
        public string Url { get; set; }
        public string Payload { get; set; }
        public int StatusCode { get; set; }
        public int Size { get; set; }
        public double ResponseTime { get; set; }
        public string Result { get; set; }
        public string RequestDetails { get; set; }
        public string ResponseDetails { get; set; }
    }

    public class Vulnerability
    {
        public string OWASPCategory { get; set; }
        public string Type { get; set; }
        public string Severity { get; set; }
        public int Confidence { get; set; }
        public string Url { get; set; }
        public string Parameter { get; set; }
        public string Evidence { get; set; }
        public DateTime Timestamp { get; set; }
        public int RiskScore { get; set; }
        public string CWE { get; set; }
        public string Impact { get; set; }
        public string Remediation { get; set; }
        public string Note { get; set; }
    }

    public class ProgressUpdate
    {
        public int Percentage { get; set; }
        public string Status { get; set; }
    }

    public class ScanStatistics
    {
        public int TotalRequests { get; set; }
        public int VulnerabilitiesFound { get; set; }
        public double RequestsPerSecond { get; set; }
        public TimeSpan ElapsedTime { get; set; }
        public double AverageResponseTime { get; set; }
        public int ScopeViolations { get; set; }
        public ServerHealthStatus ServerHealthStatus { get; set; } = ServerHealthStatus.Normal;
    }

    public class ProductionHttpResponse
    {
        public string Url { get; set; }
        public int StatusCode { get; set; }
        public string Body { get; set; }
        public IEnumerable<KeyValuePair<string, IEnumerable<string>>> Headers { get; set; }
        public long ResponseTime { get; set; }
        public string RequestDetails { get; set; }
        public string ResponseDetails { get; set; }
        public string ContentType { get; set; }
        public int BodyLength => Body?.Length ?? 0;
    }

    public class ProductionEndpoint
    {
        public string Url { get; set; }
        public string Method { get; set; }
        public Dictionary<string, string> Parameters { get; set; }
        public bool HasParameters => Parameters?.Count > 0;

        public ProductionEndpoint(string url, string method, Dictionary<string, string> parameters = null)
        {
            Url = url;
            Method = method;
            Parameters = parameters ?? new Dictionary<string, string>();
        }

        public ProductionEndpoint Clone()
        {
            return new ProductionEndpoint(Url, Method, new Dictionary<string, string>(Parameters));
        }
    }

    public class ProductionBaselineResponse
    {
        public int StatusCode { get; set; }
        public string BodyHash { get; set; }
        public string Body { get; set; }
        public int BodyLength { get; set; }
        public long ResponseTime { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public string ContentType { get; set; }
    }

    public class EnterpriseScanReport
    {
        public ScanMetadata Metadata { get; set; }
        public EnterpriseReportStatistics Statistics { get; set; }
        public List<Vulnerability> Findings { get; set; }
        public ExecutiveSummary ExecutiveSummary { get; set; }
        public List<Recommendation> Recommendations { get; set; }
        public ScannerLimitations Limitations { get; set; }
        public CoverageMatrix CoverageMatrix { get; set; }
        public string JsonReport { get; set; }
    }

    public class EnterpriseScanReportResult
    {
        public EnterpriseScanReport Report { get; set; }
        public string JsonReport { get; set; }
        public DateTime Timestamp { get; set; }
    }

    public class ScanMetadata
    {
        public string ScannerVersion { get; set; }
        public string ScannerHash { get; set; }
        public string ScanId { get; set; }
        public DateTime Timestamp { get; set; }
        public TimeSpan ScanDuration { get; set; }
        public List<string> TargetScope { get; set; }
        public string TlsValidationMode { get; set; }
        public AuthorizationRecord AuthorizationRecord { get; set; }
    }

    public class EnterpriseReportStatistics
    {
        public int TotalRequests { get; set; }
        public int TotalFindings { get; set; }
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public double AverageConfidence { get; set; }
        public int TotalRiskScore { get; set; }
        public int ScopeViolations { get; set; }
        public string ServerHealthStatus { get; set; }
    }

    public class ExecutiveSummary
    {
        public string BusinessRiskLevel { get; set; }
        public List<RiskItem> TopRisks { get; set; }
        public AssetExposure AssetExposure { get; set; }
        public RiskHeatmap RiskHeatmap { get; set; }
        public TimeSpan TimeToRemediate { get; set; }
        public List<string> ComplianceGaps { get; set; }
    }

    public class RiskItem
    {
        public string Type { get; set; }
        public string Severity { get; set; }
        public string Impact { get; set; }
        public string Url { get; set; }
    }

    public class AssetExposure
    {
        public int TotalEndpoints { get; set; }
        public int AuthenticationEndpoints { get; set; }
        public int AdministrativeEndpoints { get; set; }
        public int DataInputPoints { get; set; }
        public int ExternalDependencies { get; set; }
    }

    public class RiskHeatmap
    {
        public int OWASP01 { get; set; }
        public int OWASP02 { get; set; }
        public int OWASP03 { get; set; }
        public int OWASP04 { get; set; }
        public int OWASP05 { get; set; }
        public int OWASP06 { get; set; }
        public int OWASP07 { get; set; }
        public int OWASP08 { get; set; }
        public int OWASP09 { get; set; }
        public int OWASP10 { get; set; }
        public string HighestRiskCategory { get; set; }

        public string GetHighestRiskCategory()
        {
            var values = new Dictionary<string, int>
            {
                ["A01"] = OWASP01,
                ["A02"] = OWASP02,
                ["A03"] = OWASP03,
                ["A04"] = OWASP04,
                ["A05"] = OWASP05,
                ["A06"] = OWASP06,
                ["A07"] = OWASP07,
                ["A08"] = OWASP08,
                ["A09"] = OWASP09,
                ["A10"] = OWASP10
            };

            return values.OrderByDescending(v => v.Value).First().Key;
        }
    }

    public class Recommendation
    {
        public string Priority { get; set; }
        public string Category { get; set; }
        public string Description { get; set; }
        public string Timeline { get; set; }
        public string Effort { get; set; }
        public string BusinessImpact { get; set; }
    }

    public class ScannerLimitations
    {
        public string AutomatedCoverage { get; set; }
        public string ManualTestingRequired { get; set; }
        public string FalsePositiveRate { get; set; }
        public List<string> BlindSpots { get; set; }
        public List<string> Assumptions { get; set; }
    }

    public class CoverageMatrix
    {
        public CoverageLevel OWASP01 { get; set; }
        public CoverageLevel OWASP02 { get; set; }
        public CoverageLevel OWASP03 { get; set; }
        public CoverageLevel OWASP04 { get; set; }
        public CoverageLevel OWASP05 { get; set; }
        public CoverageLevel OWASP06 { get; set; }
        public CoverageLevel OWASP07 { get; set; }
        public CoverageLevel OWASP08 { get; set; }
        public CoverageLevel OWASP09 { get; set; }
        public CoverageLevel OWASP10 { get; set; }
    }

    public class CoverageLevel
    {
        public string Automated { get; set; }
        public string Notes { get; set; }
    }

    public class ProductionCrawler
    {
        private readonly HttpClient _httpClient;
        private readonly ScannerConfiguration _config;
        private readonly HashSet<string> _visitedUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly string[] _commonPaths = new[]
        {
            "/admin", "/administrator", "/wp-admin", "/login", "/signin",
            "/register", "/signup", "/logout", "/api", "/api/v1", "/api/v2",
            "/rest", "/graphql", "/swagger", "/swagger-ui", "/docs",
            "/documentation", "/robots.txt", "/sitemap.xml", "/.git/config",
            "/.env", "/config.json", "/phpinfo.php", "/info.php", "/test",
            "/debug", "/health", "/status", "/metrics", "/actuator/health"
        };

        public ProductionCrawler(HttpClient httpClient, ScannerConfiguration config)
        {
            _httpClient = httpClient;
            _config = config;
        }

        public async Task<List<ProductionEndpoint>> DiscoverEndpointsAsync(string baseUrl, CancellationToken cancellationToken)
        {
            var endpoints = new List<ProductionEndpoint>();
            var baseUri = new Uri(baseUrl);

            await CrawlPage(baseUrl, endpoints, cancellationToken, 0, 2);

            var commonPathTasks = _commonPaths.Select(path =>
                CrawlPage(baseUri.Scheme + "://" + baseUri.Host + path, endpoints, cancellationToken, 0, 1));

            await Task.WhenAll(commonPathTasks);

            return endpoints.DistinctBy(e => e.Url).ToList();
        }

        private async Task CrawlPage(string url, List<ProductionEndpoint> endpoints, CancellationToken cancellationToken, int depth, int maxDepth)
        {
            if (depth >= maxDepth || _visitedUrls.Contains(url) || cancellationToken.IsCancellationRequested)
                return;

            _visitedUrls.Add(url);

            try
            {
                var response = await _httpClient.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) return;

                var html = await response.Content.ReadAsStringAsync(cancellationToken);

                endpoints.Add(new ProductionEndpoint(url, "GET"));

                ExtractLinks(html, url, endpoints);
                ExtractForms(html, url, endpoints);
                ExtractApiEndpoints(html, url, endpoints);

                await CrawlDiscoveredLinks(endpoints, cancellationToken, depth + 1, maxDepth);
            }
            catch
            {
            }
        }

        private void ExtractLinks(string html, string baseUrl, List<ProductionEndpoint> endpoints)
        {
            var patterns = new[]
            {
                @"href=[""']([^""'#?]+)[""']",
                @"src=[""']([^""'#?]+)[""']",
                @"action=[""']([^""'#?]+)[""']"
            };

            foreach (var pattern in patterns)
            {
                foreach (Match match in Regex.Matches(html, pattern, RegexOptions.IgnoreCase))
                {
                    var link = match.Groups[1].Value;
                    var absoluteUrl = MakeAbsolute(baseUrl, link);

                    if (IsSameDomain(baseUrl, absoluteUrl))
                    {
                        endpoints.Add(new ProductionEndpoint(absoluteUrl, "GET"));
                    }
                }
            }
        }

        private void ExtractForms(string html, string baseUrl, List<ProductionEndpoint> endpoints)
        {
            var formPattern = @"<form[^>]*action=[""']([^""']*)[""'][^>]*method=[""']([^""']*)[""'][^>]*>(.*?)</form>";
            foreach (Match match in Regex.Matches(html, formPattern, RegexOptions.IgnoreCase | RegexOptions.Singleline))
            {
                var action = match.Groups[1].Value;
                var method = match.Groups[2].Value.ToUpper();
                var formContent = match.Groups[3].Value;

                if (string.IsNullOrEmpty(action) || action == "#")
                    action = baseUrl;

                var absoluteUrl = MakeAbsolute(baseUrl, action);
                var parameters = ExtractFormParameters(formContent);

                endpoints.Add(new ProductionEndpoint(absoluteUrl, method, parameters));
            }
        }

        private void ExtractApiEndpoints(string html, string baseUrl, List<ProductionEndpoint> endpoints)
        {
            var apiPatterns = new[]
            {
                @"['""](/api/[^'""]+)['""]",
                @"['""](/v[0-9]/[^'""]+)['""]",
                @"fetch\(['""]([^'""]+)['""]",
                @"\.ajax\([^)]*url:['""]([^'""]+)['""]"
            };

            foreach (var pattern in apiPatterns)
            {
                foreach (Match match in Regex.Matches(html, pattern, RegexOptions.IgnoreCase))
                {
                    var endpointPath = match.Groups[1].Value;
                    var absoluteUrl = MakeAbsolute(baseUrl, endpointPath);

                    endpoints.Add(new ProductionEndpoint(absoluteUrl, "GET"));
                    endpoints.Add(new ProductionEndpoint(absoluteUrl, "POST"));
                }
            }
        }

        private async Task CrawlDiscoveredLinks(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken, int depth, int maxDepth)
        {
            var newEndpoints = endpoints.Where(e => !_visitedUrls.Contains(e.Url)).ToList();
            var crawlTasks = new List<Task>();

            foreach (var endpoint in newEndpoints.Take(10))
            {
                crawlTasks.Add(CrawlPage(endpoint.Url, endpoints, cancellationToken, depth, maxDepth));
            }

            await Task.WhenAll(crawlTasks);
        }

        private Dictionary<string, string> ExtractFormParameters(string formHtml)
        {
            var parameters = new Dictionary<string, string>();

            var inputPattern = @"<input[^>]*name=[""']([^""']*)[""'][^>]*value=[""']([^""']*)[""'][^>]*>";
            foreach (Match match in Regex.Matches(formHtml, inputPattern, RegexOptions.IgnoreCase))
            {
                parameters[match.Groups[1].Value] = match.Groups[2].Value;
            }

            if (parameters.Count == 0)
            {
                parameters["test"] = "test";
            }

            return parameters;
        }

        private string MakeAbsolute(string baseUrl, string relativeUrl)
        {
            try
            {
                if (Uri.TryCreate(new Uri(baseUrl), relativeUrl, out var absoluteUri))
                    return absoluteUri.ToString();
                return relativeUrl;
            }
            catch
            {
                return relativeUrl;
            }
        }

        private bool IsSameDomain(string baseUrl, string target)
        {
            try
            {
                var baseHost = new Uri(baseUrl).Host;
                var targetHost = new Uri(target).Host;
                return baseHost == targetHost || targetHost.EndsWith($".{baseHost}");
            }
            catch
            {
                return false;
            }
        }
    }

    public class ProductionSqlInjectionTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionSqlInjectionTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public List<SqlInjectionTestCase> GetTestCases()
        {
            return new List<SqlInjectionTestCase>
            {
                new SqlInjectionTestCase
                {
                    Payload = "'",
                    Type = "Error-based",
                    Description = "Single quote to trigger SQL errors"
                },
                new SqlInjectionTestCase
                {
                    Payload = "' OR '1'='1",
                    Type = "Boolean-based",
                    Description = "Basic boolean-based injection"
                },
                new SqlInjectionTestCase
                {
                    Payload = "' UNION SELECT NULL--",
                    Type = "Union-based",
                    Description = "Union-based injection test"
                },
                new SqlInjectionTestCase
                {
                    Payload = "' OR SLEEP(5)--",
                    Type = "Time-based",
                    Description = "Time-based blind injection"
                }
            };
        }

        public List<InjectionTestCase> GetCommandInjectionTestCases()
        {
            return new List<InjectionTestCase>
            {
                new InjectionTestCase
                {
                    Payload = "; ls",
                    Type = "Command Injection",
                    Description = "Basic command injection test"
                },
                new InjectionTestCase
                {
                    Payload = "| cat /etc/passwd",
                    Type = "Command Injection",
                    Description = "Pipe-based command injection"
                },
                new InjectionTestCase
                {
                    Payload = "`id`",
                    Type = "Command Injection",
                    Description = "Backtick command injection"
                }
            };
        }

        public bool IsRelevantParameter(string parameterName)
        {
            var relevantParams = new[]
            {
                "id", "user", "username", "email", "search", "q",
                "order", "sort", "filter", "category", "product"
            };

            return relevantParams.Any(p => parameterName.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        public VulnerabilityDetectionResult DetectVulnerability(ProductionHttpResponse response, ProductionBaselineResponse baseline, SqlInjectionTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            var sqlErrors = new[]
            {
                "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
                "Microsoft SQL Server", "ODBC Driver", "SQL command not properly ended",
                "You have an error in your SQL syntax", "Warning: mysql",
                "SQLSTATE[", "syntax error", "MySQL server", "MariaDB"
            };

            if (sqlErrors.Any(error => response.Body.Contains(error, StringComparison.OrdinalIgnoreCase)))
            {
                result.IsVulnerable = true;
                result.Confidence = 85;
                result.EvidenceDetails = $"SQL error found in response: {sqlErrors.First(error => response.Body.Contains(error, StringComparison.OrdinalIgnoreCase))}";
            }

            if (testCase.Type == "Time-based" && testCase.Payload.Contains("SLEEP"))
            {
                if (response.ResponseTime > baseline.ResponseTime + 4000)
                {
                    result.IsVulnerable = true;
                    result.Confidence = 75;
                    result.EvidenceDetails = $"Time delay detected: {response.ResponseTime}ms vs baseline {baseline.ResponseTime}ms";
                }
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A03:2021-Injection",
                    Type = "SQL Injection",
                    Severity = result.Confidence >= 80 ? "CRITICAL" : "HIGH",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = ExtractParameterFromUrl(response.Url),
                    Evidence = $"{testCase.Type}: {testCase.Payload} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore(result.Confidence >= 80 ? "CRITICAL" : "HIGH", result.Confidence),
                    CWE = "CWE-89",
                    Impact = "Data breach, authentication bypass, data manipulation",
                    Remediation = "Use parameterized queries, stored procedures, ORM with built-in protection"
                };
            }

            return result;
        }

        public VulnerabilityDetectionResult DetectCommandInjection(ProductionHttpResponse response, ProductionBaselineResponse baseline, InjectionTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            if (response.Body.Contains("root:x:0:0:") ||
                response.Body.Contains("uid=") ||
                response.Body.Contains("total ") ||
                response.Body.Contains("Directory of") ||
                response.Body.Contains("Volume in drive"))
            {
                result.IsVulnerable = true;
                result.Confidence = 90;
                result.EvidenceDetails = "Command output found in response";
            }

            if (response.Body.Contains("sh:") ||
                response.Body.Contains("bash:") ||
                response.Body.Contains("cmd.exe") ||
                response.Body.Contains("Command not found"))
            {
                result.IsVulnerable = true;
                result.Confidence = 75;
                result.EvidenceDetails = "Command error found in response";
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A03:2021-Injection",
                    Type = "Command Injection",
                    Severity = "CRITICAL",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = ExtractParameterFromUrl(response.Url),
                    Evidence = $"{testCase.Type}: {testCase.Payload} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore("CRITICAL", result.Confidence),
                    CWE = "CWE-78",
                    Impact = "Remote code execution, server compromise",
                    Remediation = "Use parameterized APIs, avoid system() calls, implement input validation"
                };
            }

            return result;
        }

        private string ExtractParameterFromUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var query = uri.Query.TrimStart('?');
                var parameters = query.Split('&');
                return parameters.Length > 0 ? parameters[0].Split('=')[0] : "unknown";
            }
            catch
            {
                return "unknown";
            }
        }

        private int CalculateRiskScore(string severity, int confidence)
        {
            var severityScore = severity switch
            {
                "CRITICAL" => 100,
                "HIGH" => 75,
                "MEDIUM" => 50,
                "LOW" => 25,
                _ => 10
            };

            return (int)(severityScore * (confidence / 100.0));
        }
    }

    public class SqlInjectionTestCase
    {
        public string Payload { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class InjectionTestCase
    {
        public string Payload { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class ProductionXssTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionXssTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public List<XssTestCase> GetTestCases()
        {
            return new List<XssTestCase>
            {
                new XssTestCase
                {
                    Payload = "<script>alert('XSS')</script>",
                    Type = "Basic XSS",
                    Description = "Basic script tag injection"
                },
                new XssTestCase
                {
                    Payload = "<img src=x onerror=alert('XSS')>",
                    Type = "Event Handler",
                    Description = "Image with error event handler"
                },
                new XssTestCase
                {
                    Payload = "<svg onload=alert('XSS')>",
                    Type = "SVG XSS",
                    Description = "SVG with load event handler"
                },
                new XssTestCase
                {
                    Payload = "\" onmouseover=\"alert('XSS')",
                    Type = "Attribute Escape",
                    Description = "Attribute escape with event handler"
                }
            };
        }

        public bool IsRelevantParameter(string parameterName)
        {
            var relevantParams = new[]
            {
                "name", "title", "description", "comment", "message",
                "content", "body", "text", "search", "q",
                "url", "link", "redirect", "return", "ref"
            };

            return relevantParams.Any(p => parameterName.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        public VulnerabilityDetectionResult DetectVulnerability(ProductionHttpResponse response, ProductionBaselineResponse baseline, XssTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            var escapedPayload = WebUtility.HtmlEncode(testCase.Payload);

            if (response.Body.Contains(testCase.Payload) && !response.Body.Contains(escapedPayload))
            {
                result.IsVulnerable = true;
                result.Confidence = 85;
                result.EvidenceDetails = "Payload reflected unescaped";
            }
            else if (testCase.Payload.Contains("<script>") && response.Body.Contains("alert('XSS')"))
            {
                result.IsVulnerable = true;
                result.Confidence = 90;
                result.EvidenceDetails = "Script execution detected";
            }
            else if ((testCase.Payload.Contains("onerror=") || testCase.Payload.Contains("onload=")) &&
                     response.Body.Contains(testCase.Payload.Split('=')[0]))
            {
                result.IsVulnerable = true;
                result.Confidence = 80;
                result.EvidenceDetails = "Event handler reflected";
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A07:2021-XSS",
                    Type = "Cross-Site Scripting",
                    Severity = "HIGH",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = ExtractParameterFromUrl(response.Url),
                    Evidence = $"{testCase.Type}: {testCase.Payload} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore("HIGH", result.Confidence),
                    CWE = "CWE-79",
                    Impact = "Session hijacking, credential theft, defacement",
                    Remediation = "Implement Content Security Policy, output encoding, input validation"
                };
            }

            return result;
        }

        private string ExtractParameterFromUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var query = uri.Query.TrimStart('?');
                var parameters = query.Split('&');
                return parameters.Length > 0 ? parameters[0].Split('=')[0] : "unknown";
            }
            catch
            {
                return "unknown";
            }
        }

        private int CalculateRiskScore(string severity, int confidence)
        {
            var severityScore = severity switch
            {
                "CRITICAL" => 100,
                "HIGH" => 75,
                "MEDIUM" => 50,
                "LOW" => 25,
                _ => 10
            };

            return (int)(severityScore * (confidence / 100.0));
        }
    }

    public class XssTestCase
    {
        public string Payload { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class ProductionAccessControlTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionAccessControlTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public List<AccessControlTestCase> GetTestCases(ProductionEndpoint endpoint)
        {
            var testCases = new List<AccessControlTestCase>();

            testCases.Add(new AccessControlTestCase
            {
                TestEndpoint = new ProductionEndpoint(endpoint.Url, "POST", endpoint.Parameters),
                Type = "Method Tampering",
                Description = "GET to POST method change"
            });

            testCases.Add(new AccessControlTestCase
            {
                TestEndpoint = new ProductionEndpoint(endpoint.Url, "PUT", endpoint.Parameters),
                Type = "Method Tampering",
                Description = "GET to PUT method change"
            });

            testCases.Add(new AccessControlTestCase
            {
                TestEndpoint = new ProductionEndpoint(endpoint.Url, "DELETE", endpoint.Parameters),
                Type = "Method Tampering",
                Description = "GET to DELETE method change"
            });

            return testCases;
        }

        public List<IdorTestCase> GenerateIdorTestCases(ProductionEndpoint endpoint)
        {
            var testCases = new List<IdorTestCase>();

            var numericPatterns = new[]
            {
                @"/(\d+)(/|$|\.)",
                @"id=(\d+)",
                @"user=(\d+)",
                @"uid=(\d+)",
                @"order=(\d+)"
            };

            foreach (var pattern in numericPatterns)
            {
                foreach (Match match in Regex.Matches(endpoint.Url, pattern, RegexOptions.IgnoreCase))
                {
                    if (int.TryParse(match.Groups[1].Value, out int originalId))
                    {
                        var testIds = GenerateTestIds(originalId);

                        foreach (var testId in testIds)
                        {
                            var testUrl = endpoint.Url.Replace(match.Groups[1].Value, testId.ToString());
                            testCases.Add(new IdorTestCase
                            {
                                OriginalEndpoint = endpoint,
                                TestEndpoint = new ProductionEndpoint(testUrl, endpoint.Method, endpoint.Parameters),
                                OriginalId = originalId,
                                TestId = testId,
                                Type = "IDOR",
                                Description = $"ID change: {originalId} → {testId}"
                            });
                        }
                    }
                }
            }

            return testCases;
        }

        public List<PathTraversalTestCase> GetPathTraversalTestCases()
        {
            return new List<PathTraversalTestCase>
            {
                new PathTraversalTestCase
                {
                    Payload = "../../../etc/passwd",
                    Type = "Path Traversal",
                    Description = "Unix directory traversal"
                },
                new PathTraversalTestCase
                {
                    Payload = "..\\..\\..\\windows\\win.ini",
                    Type = "Path Traversal",
                    Description = "Windows directory traversal"
                },
                new PathTraversalTestCase
                {
                    Payload = "%2e%2e%2fetc%2fpasswd",
                    Type = "Path Traversal",
                    Description = "URL encoded traversal"
                }
            };
        }

        private IEnumerable<int> GenerateTestIds(int originalId)
        {
            return new[]
            {
                originalId + 1,
                originalId - 1,
                1,
                0,
                -1,
                999999
            };
        }

        public VulnerabilityDetectionResult DetectVulnerability(ProductionHttpResponse response, ProductionBaselineResponse baseline, AccessControlTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            if (response.StatusCode == 200 && baseline.StatusCode == 403)
            {
                result.IsVulnerable = true;
                result.Confidence = 85;
                result.EvidenceDetails = $"Method tampering successful: {baseline.StatusCode} → {response.StatusCode}";
            }
            else if (response.StatusCode == 200 && baseline.StatusCode == 401)
            {
                result.IsVulnerable = true;
                result.Confidence = 80;
                result.EvidenceDetails = $"Authentication bypass: {baseline.StatusCode} → {response.StatusCode}";
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A01:2021-Broken Access Control",
                    Type = testCase.Type,
                    Severity = "HIGH",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = "method",
                    Evidence = $"{testCase.Description} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore("HIGH", result.Confidence),
                    CWE = "CWE-285",
                    Impact = "Unauthorized access, privilege escalation",
                    Remediation = "Implement proper access control checks, validate user permissions"
                };
            }

            return result;
        }

        public VulnerabilityDetectionResult DetectIdorVulnerability(ProductionHttpResponse response, ProductionBaselineResponse baseline, IdorTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            if (response.StatusCode == 200 && baseline.StatusCode == 403)
            {
                result.IsVulnerable = true;
                result.Confidence = 90;
                result.EvidenceDetails = $"IDOR detected: Access to ID {testCase.TestId} when only {testCase.OriginalId} should be accessible";
            }
            else if (response.StatusCode == 200 && baseline.StatusCode == 404)
            {
                result.IsVulnerable = true;
                result.Confidence = 85;
                result.EvidenceDetails = $"IDOR detected: Resource exists for ID {testCase.TestId} when it shouldn't";
            }
            else if (Math.Abs(response.BodyLength - baseline.BodyLength) > 200 && response.StatusCode == 200)
            {
                result.IsVulnerable = true;
                result.Confidence = 75;
                result.EvidenceDetails = $"Content difference detected for ID {testCase.TestId}";
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A01:2021-Broken Access Control",
                    Type = "Insecure Direct Object Reference (IDOR)",
                    Severity = "HIGH",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = "id",
                    Evidence = $"{testCase.Description} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore("HIGH", result.Confidence),
                    CWE = "CWE-639",
                    Impact = "Unauthorized data access, information disclosure",
                    Remediation = "Implement proper access control checks, use UUIDs instead of sequential IDs"
                };
            }

            return result;
        }

        public VulnerabilityDetectionResult DetectPathTraversal(ProductionHttpResponse response, ProductionBaselineResponse baseline, PathTraversalTestCase testCase)
        {
            var result = new VulnerabilityDetectionResult
            {
                IsVulnerable = false,
                Confidence = 50
            };

            if (response.Body.Contains("root:x:0:0:") ||
                response.Body.Contains("[extensions]") ||
                response.Body.Contains("[boot loader]") ||
                response.Body.Contains("Directory of") ||
                response.Body.Contains("Volume in drive"))
            {
                result.IsVulnerable = true;
                result.Confidence = 95;
                result.EvidenceDetails = "Sensitive file contents found in response";
            }

            if (result.IsVulnerable)
            {
                result.Vulnerability = new Vulnerability
                {
                    OWASPCategory = "A01:2021-Broken Access Control",
                    Type = "Path Traversal",
                    Severity = "HIGH",
                    Confidence = result.Confidence,
                    Url = response.Url,
                    Parameter = ExtractParameterFromUrl(response.Url),
                    Evidence = $"{testCase.Type}: {testCase.Payload} | {result.EvidenceDetails}",
                    Timestamp = DateTime.Now,
                    RiskScore = CalculateRiskScore("HIGH", result.Confidence),
                    CWE = "CWE-22",
                    Impact = "Sensitive file disclosure, directory traversal",
                    Remediation = "Implement path validation, use chroot/jail, normalize paths"
                };
            }

            return result;
        }

        private string ExtractParameterFromUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var query = uri.Query.TrimStart('?');
                var parameters = query.Split('&');
                return parameters.Length > 0 ? parameters[0].Split('=')[0] : "unknown";
            }
            catch
            {
                return "unknown";
            }
        }

        private int CalculateRiskScore(string severity, int confidence)
        {
            var severityScore = severity switch
            {
                "CRITICAL" => 100,
                "HIGH" => 75,
                "MEDIUM" => 50,
                "LOW" => 25,
                _ => 10
            };

            return (int)(severityScore * (confidence / 100.0));
        }
    }

    public class AccessControlTestCase
    {
        public ProductionEndpoint TestEndpoint { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class IdorTestCase
    {
        public ProductionEndpoint OriginalEndpoint { get; set; }
        public ProductionEndpoint TestEndpoint { get; set; }
        public int OriginalId { get; set; }
        public int TestId { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class PathTraversalTestCase
    {
        public string Payload { get; set; }
        public string Type { get; set; }
        public string Description { get; set; }
    }

    public class ProductionSecurityHeadersTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionSecurityHeadersTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class SecurityHeaderIssue
        {
            public string Type { get; set; }
            public string Severity { get; set; }
            public int Confidence { get; set; }
            public string Details { get; set; }
        }

        public List<SecurityHeaderIssue> AnalyzeSecurityHeaders(ProductionHttpResponse response)
        {
            var issues = new List<SecurityHeaderIssue>();
            var headers = response.Headers.ToDictionary(
                h => h.Key,
                h => string.Join("; ", h.Value),
                StringComparer.OrdinalIgnoreCase
            );

            CheckMissingHeaders(headers, issues);
            CheckWeakHeaderValues(headers, issues);
            CheckCookieSecurity(headers, response.Url, issues);

            return issues;
        }

        private void CheckMissingHeaders(Dictionary<string, string> headers, List<SecurityHeaderIssue> issues)
        {
            var requiredHeaders = new Dictionary<string, string>
            {
                ["X-Content-Type-Options"] = "nosniff",
                ["X-Frame-Options"] = "DENY or SAMEORIGIN",
                ["Content-Security-Policy"] = "Various directives",
                ["Strict-Transport-Security"] = "max-age=31536000"
            };

            foreach (var required in requiredHeaders)
            {
                if (!headers.ContainsKey(required.Key))
                {
                    issues.Add(new SecurityHeaderIssue
                    {
                        Type = $"Missing Security Header: {required.Key}",
                        Severity = "MEDIUM",
                        Confidence = 90,
                        Details = $"Missing header: {required.Key} (Recommended: {required.Value})"
                    });
                }
            }
        }

        private void CheckWeakHeaderValues(Dictionary<string, string> headers, List<SecurityHeaderIssue> issues)
        {
            if (headers.ContainsKey("X-Frame-Options") &&
                headers["X-Frame-Options"].ToUpper() == "ALLOWALL")
            {
                issues.Add(new SecurityHeaderIssue
                {
                    Type = "Weak X-Frame-Options",
                    Severity = "HIGH",
                    Confidence = 95,
                    Details = "X-Frame-Options set to ALLOWALL allows clickjacking attacks"
                });
            }

            if (headers.ContainsKey("Content-Security-Policy") &&
                headers["Content-Security-Policy"].Contains("unsafe-inline"))
            {
                issues.Add(new SecurityHeaderIssue
                {
                    Type = "Weak Content Security Policy",
                    Severity = "MEDIUM",
                    Confidence = 80,
                    Details = "CSP contains unsafe-inline directive which reduces protection against XSS"
                });
            }
        }

        private void CheckCookieSecurity(Dictionary<string, string> headers, string url, List<SecurityHeaderIssue> issues)
        {
            if (headers.ContainsKey("Set-Cookie"))
            {
                var cookies = headers["Set-Cookie"];

                if (!cookies.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new SecurityHeaderIssue
                    {
                        Type = "Insecure Cookie - Missing HttpOnly",
                        Severity = "MEDIUM",
                        Confidence = 85,
                        Details = "Cookies missing HttpOnly flag - accessible via JavaScript"
                    });
                }

                if (!cookies.Contains("Secure", StringComparison.OrdinalIgnoreCase) && url.StartsWith("https://"))
                {
                    issues.Add(new SecurityHeaderIssue
                    {
                        Type = "Insecure Cookie - Missing Secure",
                        Severity = "MEDIUM",
                        Confidence = 90,
                        Details = "HTTPS cookies missing Secure flag - transmitted over HTTP"
                    });
                }

                if (!cookies.Contains("SameSite", StringComparison.OrdinalIgnoreCase))
                {
                    issues.Add(new SecurityHeaderIssue
                    {
                        Type = "Insecure Cookie - Missing SameSite",
                        Severity = "LOW",
                        Confidence = 80,
                        Details = "Cookies missing SameSite attribute - vulnerable to CSRF"
                    });
                }
            }
        }
    }

    public class ProductionCryptographicTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionCryptographicTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class CryptoIssue
        {
            public string Type { get; set; }
            public string Severity { get; set; }
            public int Confidence { get; set; }
            public string Details { get; set; }
        }

        public async Task<List<CryptoIssue>> TestCryptographicSecurity(string url, CancellationToken cancellationToken)
        {
            var issues = new List<CryptoIssue>();

            try
            {
                var uri = new Uri(url);

                if (uri.Scheme == "https")
                {
                    await TestSslTls(uri, issues, cancellationToken);
                    await CheckHttpAvailability(uri, issues, cancellationToken);
                    await CheckMixedContent(uri, issues, cancellationToken);
                }
                else
                {
                    issues.Add(new CryptoIssue
                    {
                        Type = "HTTP Used Instead of HTTPS",
                        Severity = "HIGH",
                        Confidence = 100,
                        Details = "Application uses HTTP instead of HTTPS - data transmitted in cleartext"
                    });
                }
            }
            catch (Exception ex)
            {
                issues.Add(new CryptoIssue
                {
                    Type = "Cryptographic Testing Error",
                    Severity = "LOW",
                    Confidence = 100,
                    Details = $"Failed to test cryptographic security: {ex.Message}"
                });
            }

            return issues;
        }

        private async Task TestSslTls(Uri uri, List<CryptoIssue> issues, CancellationToken cancellationToken)
        {
            try
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
                    {
                        if (sslPolicyErrors != SslPolicyErrors.None)
                        {
                            issues.Add(new CryptoIssue
                            {
                                Type = "Invalid SSL Certificate",
                                Severity = "HIGH",
                                Confidence = 100,
                                Details = $"SSL certificate error: {sslPolicyErrors}"
                            });
                        }

                        if (cert != null && cert.NotAfter < DateTime.Now)
                        {
                            issues.Add(new CryptoIssue
                            {
                                Type = "Expired SSL Certificate",
                                Severity = "HIGH",
                                Confidence = 100,
                                Details = $"Certificate expired on {cert.NotAfter:yyyy-MM-dd}"
                            });
                        }

                        if (cert != null && cert.SignatureAlgorithm != null)
                        {
                            if (cert.SignatureAlgorithm.Value.Contains("sha1", StringComparison.OrdinalIgnoreCase))
                            {
                                issues.Add(new CryptoIssue
                                {
                                    Type = "Weak Certificate Algorithm",
                                    Severity = "MEDIUM",
                                    Confidence = 90,
                                    Details = $"Certificate uses weak algorithm: {cert.SignatureAlgorithm.Value}"
                                });
                            }
                        }

                        return true;
                    },
                    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                };

                using var client = new HttpClient(handler);
                await client.GetAsync(uri, cancellationToken);
            }
            catch (Exception ex)
            {
                issues.Add(new CryptoIssue
                {
                    Type = "SSL/TLS Connection Error",
                    Severity = "MEDIUM",
                    Confidence = 80,
                    Details = $"Failed to establish secure connection: {ex.Message}"
                });
            }
        }

        private async Task CheckHttpAvailability(Uri httpsUri, List<CryptoIssue> issues, CancellationToken cancellationToken)
        {
            var httpUri = new UriBuilder(httpsUri) { Scheme = "http", Port = 80 }.Uri;

            try
            {
                using var client = new HttpClient();
                var response = await client.GetAsync(httpUri, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    issues.Add(new CryptoIssue
                    {
                        Type = "HTTP Available",
                        Severity = "HIGH",
                        Confidence = 100,
                        Details = "HTTP version of the site is accessible - should redirect to HTTPS or be disabled"
                    });
                }
            }
            catch
            {
            }
        }

        private async Task CheckMixedContent(Uri uri, List<CryptoIssue> issues, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new HttpClient();
                var response = await client.GetAsync(uri, cancellationToken);
                var html = await response.Content.ReadAsStringAsync(cancellationToken);

                var httpResources = new[]
                {
                    @"src=""http://",
                    @"href=""http://",
                    @"url\(http://",
                    @"action=""http://"
                };

                foreach (var pattern in httpResources)
                {
                    if (Regex.IsMatch(html, pattern, RegexOptions.IgnoreCase))
                    {
                        issues.Add(new CryptoIssue
                        {
                            Type = "Mixed Content",
                            Severity = "MEDIUM",
                            Confidence = 90,
                            Details = "HTTPS page contains HTTP resources (mixed content)"
                        });
                        break;
                    }
                }
            }
            catch
            {
            }
        }
    }

    public class ProductionComponentTester
    {
        private readonly ScannerConfiguration _config;
        private readonly List<DiscoveredComponent> _components = new List<DiscoveredComponent>();

        public ProductionComponentTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class ComponentIssue
        {
            public string Type { get; set; }
            public string Severity { get; set; }
            public int Confidence { get; set; }
            public string Url { get; set; }
            public string Details { get; set; }
        }

        public class DiscoveredComponent
        {
            public string Name { get; set; }
            public string Version { get; set; }
            public string Source { get; set; }
            public DateTime Detected { get; set; }
        }

        public async Task<List<ComponentIssue>> AnalyzeComponents(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            var issues = new List<ComponentIssue>();

            var vulnerableComponents = new[]
            {
                new { Name = "jQuery", VersionPattern = @"jquery[.-](\d+\.\d+\.\d+)", MinSafeVersion = "3.0.0" },
                new { Name = "Bootstrap", VersionPattern = @"bootstrap[.-](\d+\.\d+\.\d+)", MinSafeVersion = "4.0.0" },
                new { Name = "AngularJS", VersionPattern = @"angular[.-](\d+\.\d+\.\d+)", MinSafeVersion = "1.8.0" }
            };

            foreach (var endpoint in endpoints.Take(5))
            {
                try
                {
                    using var client = new HttpClient();
                    var response = await client.GetAsync(endpoint.Url, cancellationToken);
                    var html = await response.Content.ReadAsStringAsync(cancellationToken);

                    foreach (var component in vulnerableComponents)
                    {
                        var match = Regex.Match(html, component.VersionPattern, RegexOptions.IgnoreCase);
                        if (match.Success)
                        {
                            var version = match.Groups[1].Value;
                            _components.Add(new DiscoveredComponent
                            {
                                Name = component.Name,
                                Version = version,
                                Source = endpoint.Url,
                                Detected = DateTime.Now
                            });

                            if (IsVersionVulnerable(version, component.MinSafeVersion))
                            {
                                issues.Add(new ComponentIssue
                                {
                                    Type = $"Vulnerable {component.Name} Version",
                                    Severity = "MEDIUM",
                                    Confidence = 85,
                                    Url = endpoint.Url,
                                    Details = $"{component.Name} version {version} detected (minimum safe version: {component.MinSafeVersion})"
                                });
                            }
                        }
                    }

                    CheckForVulnerableLibraries(html, endpoint.Url, issues);
                    CheckExposedVersions(html, endpoint.Url, issues);
                }
                catch
                {
                }
            }

            return issues;
        }

        public List<DiscoveredComponent> GetDiscoveredComponents()
        {
            return _components;
        }

        private bool IsVersionVulnerable(string currentVersion, string minSafeVersion)
        {
            try
            {
                var current = new Version(currentVersion);
                var minSafe = new Version(minSafeVersion);
                return current < minSafe;
            }
            catch
            {
                return false;
            }
        }

        private void CheckForVulnerableLibraries(string html, string url, List<ComponentIssue> issues)
        {
            var vulnerableLibraries = new[]
            {
                new { Name = "Log4j", Pattern = @"log4j", CVE = "CVE-2021-44228" },
                new { Name = "Apache Struts", Pattern = @"struts", CVE = "CVE-2017-5638" },
                new { Name = "Spring Framework", Pattern = @"spring[.-]framework", CVE = "CVE-2022-22965" }
            };

            foreach (var lib in vulnerableLibraries)
            {
                if (Regex.IsMatch(html, lib.Pattern, RegexOptions.IgnoreCase))
                {
                    issues.Add(new ComponentIssue
                    {
                        Type = $"Potentially Vulnerable {lib.Name}",
                        Severity = "HIGH",
                        Confidence = 75,
                        Url = url,
                        Details = $"{lib.Name} detected - Check for {lib.CVE}"
                    });
                }
            }
        }

        private void CheckExposedVersions(string html, string url, List<ComponentIssue> issues)
        {
            var versionPatterns = new[]
            {
                @"<!--.*?Version:?\s*(\d+\.\d+\.\d+).*?-->",
                @"<meta.*?content=""(\d+\.\d+\.\d+)"".*?>",
                @"Powered by.*?(\d+\.\d+\.\d+)"
            };

            foreach (var pattern in versionPatterns)
            {
                var matches = Regex.Matches(html, pattern, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    if (match.Groups.Count > 1)
                    {
                        issues.Add(new ComponentIssue
                        {
                            Type = "Exposed Version Information",
                            Severity = "LOW",
                            Confidence = 95,
                            Url = url,
                            Details = $"Version information exposed: {match.Groups[1].Value}"
                        });
                    }
                }
            }
        }
    }

    public class ProductionDesignTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionDesignTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class DesignIssue
        {
            public string Type { get; set; }
            public string Parameter { get; set; }
            public int Confidence { get; set; }
            public string Url { get; set; }
            public string Details { get; set; }
        }

        public async Task<List<DesignIssue>> AnalyzeDesignPatterns(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            var issues = new List<DesignIssue>();

            foreach (var endpoint in endpoints)
            {
                CheckPredictableIds(endpoint, issues);
                CheckMissingRateLimiting(endpoint, issues);
                CheckBusinessLogicIndicators(endpoint, issues);
            }

            return issues;
        }

        private void CheckPredictableIds(ProductionEndpoint endpoint, List<DesignIssue> issues)
        {
            var idPatterns = new[]
            {
                @"/(\d+)(/|$|\.)",
                @"id=(\d+)",
                @"user=(\d+)"
            };

            foreach (var pattern in idPatterns)
            {
                if (Regex.IsMatch(endpoint.Url, pattern, RegexOptions.IgnoreCase))
                {
                    issues.Add(new DesignIssue
                    {
                        Type = "Predictable Resource Identifier",
                        Parameter = "id",
                        Confidence = 70,
                        Url = endpoint.Url,
                        Details = "Sequential numeric IDs detected - may enable IDOR attacks"
                    });
                }
            }
        }

        private void CheckMissingRateLimiting(ProductionEndpoint endpoint, List<DesignIssue> issues)
        {
            if (endpoint.Url.Contains("login") || endpoint.Url.Contains("password") || endpoint.Url.Contains("auth"))
            {
                issues.Add(new DesignIssue
                {
                    Type = "Missing Rate Limiting Indicators",
                    Parameter = "authentication",
                    Confidence = 60,
                    Url = endpoint.Url,
                    Details = "Authentication endpoint without obvious rate limiting controls"
                });
            }
        }

        private void CheckBusinessLogicIndicators(ProductionEndpoint endpoint, List<DesignIssue> issues)
        {
            if (endpoint.Method == "GET" && endpoint.HasParameters &&
                endpoint.Parameters.Any(p => p.Key.Contains("price") || p.Key.Contains("amount") || p.Key.Contains("quantity")))
            {
                issues.Add(new DesignIssue
                {
                    Type = "Business Logic Parameter in URL",
                    Parameter = endpoint.Parameters.First(p => p.Key.Contains("price") || p.Key.Contains("amount") || p.Key.Contains("quantity")).Key,
                    Confidence = 65,
                    Url = endpoint.Url,
                    Details = "Business logic parameters in URL may be tampered with"
                });
            }
        }
    }

    public class ProductionIntegrityTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionIntegrityTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class IntegrityIssue
        {
            public string Type { get; set; }
            public string Severity { get; set; }
            public int Confidence { get; set; }
            public string Url { get; set; }
            public string Parameter { get; set; }
            public string Details { get; set; }
        }

        public async Task<List<IntegrityIssue>> AnalyzeIntegrity(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            var issues = new List<IntegrityIssue>();

            foreach (var endpoint in endpoints)
            {
                CheckInsecureDeserialization(endpoint, issues);
                CheckClientSideTrust(endpoint, issues);
            }

            return issues;
        }

        private void CheckInsecureDeserialization(ProductionEndpoint endpoint, List<IntegrityIssue> issues)
        {
            if (endpoint.Url.Contains(".ashx") || endpoint.Url.Contains(".asmx") ||
                endpoint.Url.Contains("remoting") || endpoint.Url.Contains("serialize"))
            {
                issues.Add(new IntegrityIssue
                {
                    Type = "Potential Insecure Deserialization Endpoint",
                    Severity = "HIGH",
                    Confidence = 70,
                    Url = endpoint.Url,
                    Parameter = "N/A",
                    Details = "Endpoint suggests serialization/deserialization functionality"
                });
            }
        }

        private void CheckClientSideTrust(ProductionEndpoint endpoint, List<IntegrityIssue> issues)
        {
            if (endpoint.Parameters.Any(p => p.Key.Contains("token") || p.Key.Contains("signature") || p.Key.Contains("nonce")) &&
                endpoint.Method == "GET")
            {
                issues.Add(new IntegrityIssue
                {
                    Type = "Security Token in URL",
                    Severity = "MEDIUM",
                    Confidence = 75,
                    Url = endpoint.Url,
                    Parameter = endpoint.Parameters.First(p => p.Key.Contains("token") || p.Key.Contains("signature") || p.Key.Contains("nonce")).Key,
                    Details = "Security tokens in URLs may be logged or leaked"
                });
            }
        }
    }

    public class ProductionLoggingTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionLoggingTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class LoggingIssue
        {
            public string Type { get; set; }
            public string Parameter { get; set; }
            public int Confidence { get; set; }
            public string Url { get; set; }
            public string Details { get; set; }
        }

        public async Task<List<LoggingIssue>> AnalyzeLogging(List<ProductionEndpoint> endpoints, CancellationToken cancellationToken)
        {
            var issues = new List<LoggingIssue>();

            foreach (var endpoint in endpoints)
            {
                await CheckErrorMessages(endpoint, issues, cancellationToken);
                CheckMissingCorrelation(endpoint, issues);
            }

            return issues;
        }

        private async Task CheckErrorMessages(ProductionEndpoint endpoint, List<LoggingIssue> issues, CancellationToken cancellationToken)
        {
            try
            {
                using var client = new HttpClient();
                var invalidEndpoint = endpoint.Clone();
                invalidEndpoint.Parameters["test"] = Guid.NewGuid().ToString();

                var response = await client.GetAsync(BuildInvalidUrl(invalidEndpoint), cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);

                if (body.Contains("Stack trace") || body.Contains("at ") || body.Contains("Exception:") ||
                    body.Contains("Microsoft") || body.Contains("Java.") || body.Contains("python"))
                {
                    issues.Add(new LoggingIssue
                    {
                        Type = "Stack Trace Exposure",
                        Parameter = "error",
                        Confidence = 90,
                        Url = endpoint.Url,
                        Details = "Stack traces exposed in error responses"
                    });
                }

                if (body.Contains("SQL") || body.Contains("database") || body.Contains("query"))
                {
                    issues.Add(new LoggingIssue
                    {
                        Type = "Database Error Exposure",
                        Parameter = "error",
                        Confidence = 85,
                        Url = endpoint.Url,
                        Details = "Database errors exposed to users"
                    });
                }
            }
            catch
            {
            }
        }

        private void CheckMissingCorrelation(ProductionEndpoint endpoint, List<LoggingIssue> issues)
        {
            if (endpoint.Url.Contains("error") || endpoint.Url.Contains("fail") || endpoint.Url.Contains("exception"))
            {
                issues.Add(new LoggingIssue
                {
                    Type = "Missing Correlation IDs",
                    Parameter = "logging",
                    Confidence = 60,
                    Url = endpoint.Url,
                    Details = "Error endpoints without obvious correlation/tracking IDs"
                });
            }
        }

        private string BuildInvalidUrl(ProductionEndpoint endpoint)
        {
            if (!endpoint.HasParameters) return endpoint.Url;

            var uriBuilder = new UriBuilder(endpoint.Url);
            var query = string.Join("&", endpoint.Parameters
                .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

            if (uriBuilder.Query.Length > 1)
                uriBuilder.Query = uriBuilder.Query.Substring(1) + "&" + query;
            else
                uriBuilder.Query = query;

            return uriBuilder.ToString();
        }
    }

    public class ProductionAuthTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionAuthTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public class AuthIssue
        {
            public string Type { get; set; }
            public string Severity { get; set; }
            public int Confidence { get; set; }
            public string Parameter { get; set; }
            public string Details { get; set; }
        }

        public async Task<List<AuthIssue>> TestAuthentication(ProductionEndpoint endpoint, CancellationToken cancellationToken)
        {
            var issues = new List<AuthIssue>();

            await TestDefaultCredentials(endpoint, issues, cancellationToken);
            await TestWeakPasswordPolicy(endpoint, issues, cancellationToken);
            await TestAccountEnumeration(endpoint, issues, cancellationToken);

            return issues;
        }

        private async Task TestDefaultCredentials(ProductionEndpoint endpoint, List<AuthIssue> issues, CancellationToken cancellationToken)
        {
            var defaultCredentials = new[]
            {
                new { Username = "admin", Password = "admin" },
                new { Username = "admin", Password = "password" },
                new { Username = "administrator", Password = "administrator" }
            };

            foreach (var creds in defaultCredentials.Take(2))
            {
                try
                {
                    var testEndpoint = endpoint.Clone();
                    if (testEndpoint.Parameters.ContainsKey("username"))
                        testEndpoint.Parameters["username"] = creds.Username;
                    if (testEndpoint.Parameters.ContainsKey("password"))
                        testEndpoint.Parameters["password"] = creds.Password;

                    using var client = new HttpClient();
                    var request = new HttpRequestMessage(HttpMethod.Post, testEndpoint.Url)
                    {
                        Content = new FormUrlEncodedContent(testEndpoint.Parameters)
                    };

                    var response = await client.SendAsync(request, cancellationToken);
                    var body = await response.Content.ReadAsStringAsync(cancellationToken);

                    if (body.Contains("Welcome") || body.Contains("Dashboard") ||
                        body.Contains("Logout") || response.Headers.Contains("Set-Cookie"))
                    {
                        issues.Add(new AuthIssue
                        {
                            Type = "Default Credentials",
                            Severity = "HIGH",
                            Confidence = 90,
                            Parameter = "credentials",
                            Details = $"Default credentials work: {creds.Username}/{creds.Password}"
                        });
                        break;
                    }
                }
                catch
                {
                }
            }
        }

        private async Task TestWeakPasswordPolicy(ProductionEndpoint endpoint, List<AuthIssue> issues, CancellationToken cancellationToken)
        {
            try
            {
                var testEndpoint = endpoint.Clone();
                if (testEndpoint.Parameters.ContainsKey("password"))
                    testEndpoint.Parameters["password"] = "123456";

                using var client = new HttpClient();
                var request = new HttpRequestMessage(HttpMethod.Post, testEndpoint.Url)
                {
                    Content = new FormUrlEncodedContent(testEndpoint.Parameters)
                };

                var response = await client.SendAsync(request, cancellationToken);
                var body = await response.Content.ReadAsStringAsync(cancellationToken);

                if (!body.Contains("weak") && !body.Contains("strong") &&
                    !body.Contains("minimum") && response.IsSuccessStatusCode)
                {
                    issues.Add(new AuthIssue
                    {
                        Type = "Weak Password Policy",
                        Severity = "MEDIUM",
                        Confidence = 75,
                        Parameter = "password",
                        Details = "No password complexity requirements detected"
                    });
                }
            }
            catch
            {
            }
        }

        private async Task TestAccountEnumeration(ProductionEndpoint endpoint, List<AuthIssue> issues, CancellationToken cancellationToken)
        {
            try
            {
                var existingUserResponse = "";
                var nonExistingUserResponse = "";

                var testUsers = new[] { "admin", "nonexistentuser12345" };

                foreach (var username in testUsers)
                {
                    var testEndpoint = endpoint.Clone();
                    if (testEndpoint.Parameters.ContainsKey("username"))
                        testEndpoint.Parameters["username"] = username;
                    if (testEndpoint.Parameters.ContainsKey("password"))
                        testEndpoint.Parameters["password"] = "wrongpassword";

                    using var client = new HttpClient();
                    var request = new HttpRequestMessage(HttpMethod.Post, testEndpoint.Url)
                    {
                        Content = new FormUrlEncodedContent(testEndpoint.Parameters)
                    };

                    var response = await client.SendAsync(request, cancellationToken);
                    var body = await response.Content.ReadAsStringAsync(cancellationToken);

                    if (username.Contains("nonexistent"))
                        nonExistingUserResponse = body;
                    else
                        existingUserResponse = body;
                }

                if (!string.IsNullOrEmpty(existingUserResponse) && !string.IsNullOrEmpty(nonExistingUserResponse) &&
                    existingUserResponse != nonExistingUserResponse)
                {
                    issues.Add(new AuthIssue
                    {
                        Type = "Account Enumeration",
                        Severity = "MEDIUM",
                        Confidence = 85,
                        Parameter = "username",
                        Details = "Different error messages reveal valid usernames"
                    });
                }
            }
            catch
            {
            }
        }
    }

    public class ProductionSsrfTester
    {
        private readonly ScannerConfiguration _config;

        public ProductionSsrfTester(ScannerConfiguration config)
        {
            _config = config;
        }

        public bool IsHighProbabilityParameter(string parameterName)
        {
            var highProbParams = new[]
            {
                "url", "link", "image", "src", "file",
                "load", "import", "export", "fetch",
                "redirect", "return", "callback", "proxy"
            };

            return highProbParams.Any(p => parameterName.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        public IEnumerable<string> GetPayloads()
        {
            return new[]
            {
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost",
                "http://127.0.0.1",
                "file:///etc/passwd"
            };
        }

        public bool IsVulnerable(ProductionHttpResponse response)
        {
            var awsIndicators = new[]
            {
                "instance-id", "ami-id", "hostname", "public-keys",
                "security-groups", "iam/", "meta-data", "user-data"
            };

            if (awsIndicators.Any(indicator =>
                response.Body.Contains(indicator, StringComparison.OrdinalIgnoreCase)))
                return true;

            if (response.Body.Contains("root:x:0:0:") ||
                response.Body.Contains("[extensions]") ||
                response.Body.Contains("[boot loader]"))
                return true;

            return false;
        }
    }
}

public class TextBox : System.Windows.Controls.TextBox { }
public class ProgressBar : System.Windows.Controls.ProgressBar { }
public class Button : System.Windows.Controls.Button { }
public class DataGrid : System.Windows.Controls.DataGrid { }
public class ListBox : System.Windows.Controls.ListBox { }
public class TextBlock : System.Windows.Controls.TextBlock { }
public class CheckBox : System.Windows.Controls.CheckBox { }
public class ComboBox : System.Windows.Controls.ComboBox { }
public class StackPanel : System.Windows.Controls.StackPanel { }
public class ScrollBarVisibility
{
    public static System.Windows.Controls.ScrollBarVisibility Auto = System.Windows.Controls.ScrollBarVisibility.Auto;

    public static System.Windows.Controls.ScrollBarVisibility Disabled { get; internal set; }
}
