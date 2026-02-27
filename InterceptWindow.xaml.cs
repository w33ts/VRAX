using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace ReconSuite
{
    public class BoolToHttpsConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value is bool isHttps && isHttps ? "HTTPS" : "HTTP";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class HttpTransaction
    {
        public int Id { get; set; }
        public string Method { get; set; }
        public string Host { get; set; }
        public string Url { get; set; }
        public string Status { get; set; }
        public string Size { get; set; }
        public string RequestHeaders { get; set; }
        public string ResponseHeaders { get; set; }
        public DateTime Timestamp { get; set; }
        public bool IsHttps { get; set; }
        public long ResponseTime { get; set; }
        public string RequestBody { get; set; }
        public string ResponseBody { get; set; }
        public string FullRequest { get; set; }
        public string FullResponse { get; set; }
        public byte[] RawRequest { get; set; }
        public byte[] RawResponse { get; set; }
    }

    public class InterceptContext
    {
        public HttpTransaction Transaction { get; set; }
        public byte[] RequestData { get; set; }
        public byte[] ResponseData { get; set; }
        public TaskCompletionSource<InterceptDecision> DecisionSource { get; set; }
        public bool IsResponse { get; set; }
        public bool IsHttps { get; set; }
        public string Host { get; set; }
    }

    public class InterceptDecision
    {
        public InterceptAction Action { get; set; }
        public byte[] ModifiedData { get; set; }
    }

    public enum InterceptAction
    {
        Forward,
        Drop,
        Modified
    }

    public class HttpRequestInfo
    {
        public string Method { get; set; }
        public string Path { get; set; }
        public string Host { get; set; }
        public string HttpVersion { get; set; }
        public string FullUrl { get; set; }
        public bool IsHttps { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Body { get; set; }
        public byte[] RawData { get; set; }
        public int ContentLength { get; set; }
        public bool HasBody { get; set; }
    }

    public class RepeaterSession
    {
        public string Name { get; set; }
        public string Url { get; set; }
        public string Request { get; set; }
        public string Response { get; set; }
        public DateTime LastModified { get; set; }
        public long ResponseTime { get; set; }
        public int StatusCode { get; set; }
        public string StatusText { get; set; }
    }

    public class IntruderAttackConfig
    {
        public string AttackType { get; set; }
        public string Template { get; set; }
        public string[] Payloads { get; set; }
        public string TargetUrl { get; set; }
        public int Threads { get; set; }
        public int Delay { get; set; }
        public bool FollowRedirects { get; set; }
        public Dictionary<string, string> Headers { get; set; }
        public bool AutoStart { get; set; }
        public int MaxRetries { get; set; }
        public int Timeout { get; set; }
        public bool UseCookies { get; set; }
        public string CookieJar { get; set; }
    }

    public class IntruderResult
    {
        public int RequestId { get; set; }
        public string Payload { get; set; }
        public int StatusCode { get; set; }
        public long ResponseTime { get; set; }
        public string ResponseLength { get; set; }
        public string ResponsePreview { get; set; }
        public string Error { get; set; }
        public bool Success { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public string Cookies { get; set; }
    }

    public class ProxySettings
    {
        public bool EnableSSLInterception { get; set; } = true;
        public bool TrustSelfSignedCerts { get; set; } = true;
        public int MaxConnections { get; set; } = 100;
        public int BufferSize { get; set; } = 8192;
        public int TimeoutSeconds { get; set; } = 30;
        public bool LogRequests { get; set; } = true;
        public bool LogResponses { get; set; } = false;
        public bool AutoStartProxy { get; set; } = false;
        public bool BypassLocalhost { get; set; } = false;
    }

    public partial class InterceptWindow : Window
    {
        private TcpListener _proxyListener;
        private bool _isProxyRunning = false;
        private bool _isInterceptEnabled = false;
        private bool _isInterceptResponseEnabled = true;
        private CancellationTokenSource _proxyServerCts;
        private int _requestIdCounter = 0;
        private DispatcherTimer _uptimeTimer;
        private DateTime _proxyStartTime;

        private const string CERT_PASSWORD = "VRAX-Proxy-2024-Secure!";
        private const string CA_CERT_SUBJECT = "CN=VRAX Proxy CA, O=VRAX Security, C=US";
        private const string CA_CERT_FRIENDLY_NAME = "VRAX Proxy Root Certificate Authority";

        private readonly object _syncLock = new object();
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _hostLocks = new ConcurrentDictionary<string, SemaphoreSlim>();

        private readonly BlockingCollection<InterceptContext> _interceptQueue = new BlockingCollection<InterceptContext>();
        private InterceptContext _currentInterceptedRequest;
        private Task _interceptProcessorTask;
        private CancellationTokenSource _interceptProcessorCts;

        private X509Certificate2 _rootCaCertificate;
        private readonly ConcurrentDictionary<string, X509Certificate2> _serverCertificateCache = new ConcurrentDictionary<string, X509Certificate2>();

        public ObservableCollection<HttpTransaction> RequestHistory { get; set; } = new ObservableCollection<HttpTransaction>();
        public ObservableCollection<RepeaterSession> RepeaterSessions { get; set; } = new ObservableCollection<RepeaterSession>();
        private int _repeaterSessionCounter = 0;

        private long _totalRequestsProcessed = 0;
        private long _totalBytesTransferred = 0;
        private readonly HttpClient _httpClient;
        private HttpClient _repeaterHttpClient;
        private HttpClientHandler _repeaterHandler;

        private CancellationTokenSource _intruderAttackCts;
        private bool _isAttackRunning = false;
        private ObservableCollection<IntruderResult> _intruderResults = new ObservableCollection<IntruderResult>();

        private bool _sslInterceptionEnabled = true;
        private int _maxHistorySize = 5000;
        private bool _autoStartIntercept = false;
        private bool _followRedirects = false;
        private int _proxyTimeout = 30000;
        private ProxySettings _settings = new ProxySettings();

        private string _currentRepeaterSessionName = "Session-1";
        private int _repeaterHistoryIndex = -1;
        private List<RepeaterSession> _repeaterHistory = new List<RepeaterSession>();
        private CookieContainer _repeaterCookies = new CookieContainer();

        private List<Task> _activeConnections = new List<Task>();
        private readonly object _connectionsLock = new object();

        private string _certificatesPath;
        private bool _isCertificateInstalled = false;
        private bool _isCertificateGenerated = false;
        private TextBlock _connectionCountText;

        public InterceptWindow()
        {
            InitializeComponent();

            _connectionCountText = new TextBlock
            {
                Name = "ConnectionCount",
                Text = "Connections: 0",
                Foreground = new SolidColorBrush(Color.FromRgb(204, 102, 102)),
                Margin = new Thickness(24, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };

            _certificatesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "certificates");
            Directory.CreateDirectory(_certificatesPath);

            var handler = new HttpClientHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                UseCookies = false
            };

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(45)
            };

            _repeaterHandler = new HttpClientHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                UseCookies = true,
                CookieContainer = _repeaterCookies
            };

            _repeaterHttpClient = new HttpClient(_repeaterHandler)
            {
                Timeout = TimeSpan.FromSeconds(90)
            };

            InitializeApplication();
        }

        private void InitializeApplication()
        {
            HistoryGrid.ItemsSource = RequestHistory;
            _proxyStartTime = DateTime.Now;

            _uptimeTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _uptimeTimer.Tick += UpdateUptimeAndStats;
            _uptimeTimer.Start();

            UpdateProxyUiState();

            LogInfo("╔═══════════════════════════════════════════════════════════╗");
            LogInfo("║     VRAX INTERCEPT ENGINE v3.0 - INITIALIZED             ║");
            LogInfo("║     Advanced HTTP/HTTPS Proxy • Complete Web Toolkit     ║");
            LogInfo("╚═══════════════════════════════════════════════════════════╝");

            Task.Run(() => InitializeCertificateSystem());
            StartInterceptProcessor();

            RepeaterSessionManager();
            InitializeRepeater();

            LoadSettings();
            CheckCertificateInstallation();
        }

        private void UpdateUptimeAndStats(object sender, EventArgs e)
        {
            try
            {
                var uptime = DateTime.Now - _proxyStartTime;
                UptimeDisplay.Text = uptime.ToString(@"hh\:mm\:ss");

                var process = Process.GetCurrentProcess();
                var memoryMB = process.WorkingSet64 / (1024.0 * 1024.0);
                MemoryUsage.Text = $"{memoryMB:F1} MB";

                if (_isProxyRunning)
                {
                    StatusMessage.Text = $"Proxy active: {_totalRequestsProcessed} requests, {FormatBytes(_totalBytesTransferred)}";
                    _connectionCountText.Text = $"Connections: {_activeConnections.Count}";
                }
            }
            catch { }
        }

        private void UpdateProxyUiState()
        {
            try
            {
                Dispatcher.Invoke(() =>
                {
                    StartProxyBtn.IsEnabled = !_isProxyRunning;
                    StopProxyBtn.IsEnabled = _isProxyRunning;
                    ProxyStatus.Fill = _isProxyRunning ? Brushes.LimeGreen : Brushes.Red;

                    ProxyStatusText.Text = _isProxyRunning ?
                        $"PROXY: ONLINE @ {ProxyHost.Text}:{ProxyPort.Text}" :
                        "PROXY: OFFLINE";
                    ProxyStatusText.Foreground = _isProxyRunning ? Brushes.LimeGreen : Brushes.Red;

                    InterceptOnOffBtn.Content = _isInterceptEnabled ? "🟢 INTERCEPT ON" : "🔴 INTERCEPT OFF";
                    InterceptOnOffBtn.BorderBrush = _isInterceptEnabled ? Brushes.LimeGreen : Brushes.Red;
                    InterceptOnOffBtn.Foreground = _isInterceptEnabled ? Brushes.LimeGreen : Brushes.Red;

                    InterceptStatus.Text = _isInterceptEnabled ?
                        "◢ INTERCEPTION: ACTIVE" :
                        "◢ INTERCEPTION: INACTIVE";
                    InterceptStatus.Foreground = _isInterceptEnabled ? Brushes.LimeGreen : Brushes.Red;

                    CertStatus.Text = _isCertificateInstalled ? "✓ INSTALLED" : "⚠ NOT INSTALLED";
                    CertStatus.Foreground = _isCertificateInstalled ? Brushes.LimeGreen : Brushes.Orange;

                    if (_isCertificateGenerated && !_isCertificateInstalled)
                    {
                        CertStatus.Text = "⚠ GENERATED (NOT INSTALLED)";
                        CertStatus.Foreground = Brushes.Yellow;
                    }

                    if (!_isInterceptEnabled)
                    {
                        ForwardBtn.IsEnabled = false;
                        DropBtn.IsEnabled = false;
                        ModifyBtn.IsEnabled = false;
                    }
                });
            }
            catch { }
        }

        private void InitializeCertificateSystem()
        {
            try
            {
                string certPath = Path.Combine(_certificatesPath, "vrax_ca.pfx");
                string cerPath = Path.Combine(_certificatesPath, "vrax_ca.cer");

                LogInfo("Initializing certificate system...");

                if (File.Exists(certPath))
                {
                    LogInfo("Found existing certificate, loading...");
                    try
                    {
                        _rootCaCertificate = new X509Certificate2(
                            certPath,
                            CERT_PASSWORD,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
                        );

                        if (!_rootCaCertificate.HasPrivateKey)
                        {
                            LogWarning("Certificate missing private key, generating new one");
                            GenerateRootCertificate();
                        }
                        else if (DateTime.Now > _rootCaCertificate.NotAfter.AddDays(-30))
                        {
                            LogWarning("Certificate expiring soon, generating new one");
                            GenerateRootCertificate();
                        }
                        else
                        {
                            _isCertificateGenerated = true;
                            LogSuccess($"✓ Loaded existing certificate (Valid: {_rootCaCertificate.NotBefore:yyyy-MM-dd} to {_rootCaCertificate.NotAfter:yyyy-MM-dd})");
                        }
                    }
                    catch (CryptographicException ex)
                    {
                        LogWarning($"Failed to load existing certificate: {ex.Message}. Generating new one.");
                        GenerateRootCertificate();
                    }
                }
                else
                {
                    LogInfo("No existing certificate found, generating new one...");
                    GenerateRootCertificate();
                }

                Dispatcher.Invoke(() =>
                {
                    if (_rootCaCertificate != null && _rootCaCertificate.HasPrivateKey)
                    {
                        SslStatus.Text = "✅ READY";
                        SslStatus.Foreground = Brushes.LimeGreen;
                        LogSuccess("Root CA certificate ready for SSL interception");

                        CheckCertificateInstallation();
                    }
                    else
                    {
                        SslStatus.Text = "❌ ERROR";
                        SslStatus.Foreground = Brushes.Red;
                        LogError("Certificate initialization failed");
                    }
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    LogError($"Certificate initialization failed: {ex.Message}");
                    SslStatus.Text = "❌ ERROR";
                    SslStatus.Foreground = Brushes.Red;
                });
            }
        }

        private void GenerateRootCertificate()
        {
            try
            {
                LogInfo("Generating new Root CA certificate...");

                var keyFlags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet;

                using (var rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest(
                        CA_CERT_SUBJECT,
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1
                    );

                    request.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(true, false, 0, true)
                    );

                    request.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                            true
                        )
                    );

                    request.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.1"),
                                new Oid("1.3.6.1.5.5.7.3.2")
                            },
                            false
                        )
                    );

                    var subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(
                        request.PublicKey,
                        false
                    );
                    request.CertificateExtensions.Add(subjectKeyIdentifier);

                    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
                    var notAfter = notBefore.AddYears(5);

                    var certificate = request.CreateSelfSigned(notBefore, notAfter);

                    _rootCaCertificate = new X509Certificate2(
                        certificate.Export(X509ContentType.Pfx, CERT_PASSWORD),
                        CERT_PASSWORD,
                        keyFlags
                    );

                    _rootCaCertificate.FriendlyName = CA_CERT_FRIENDLY_NAME;

                    string certPath = Path.Combine(_certificatesPath, "vrax_ca.pfx");
                    string cerPath = Path.Combine(_certificatesPath, "vrax_ca.cer");

                    File.WriteAllBytes(certPath, _rootCaCertificate.Export(X509ContentType.Pfx, CERT_PASSWORD));
                    File.WriteAllBytes(cerPath, _rootCaCertificate.Export(X509ContentType.Cert));

                    _isCertificateGenerated = true;

                    LogSuccess($"✓ Generated new Root CA certificate (Valid: {notBefore:yyyy-MM-dd} to {notAfter:yyyy-MM-dd})");
                    LogInfo($"Certificate saved to: {certPath}");
                    LogInfo($"Public key saved to: {cerPath}");

                    Dispatcher.Invoke(() =>
                    {
                        var result = MessageBox.Show(
                            "✓ Root CA certificate generated successfully!\n\n" +
                            "For HTTPS interception to work without browser warnings:\n" +
                            "1. Install the certificate as Trusted Root CA\n" +
                            "2. Restart your browser\n" +
                            "3. Clear SSL state\n\n" +
                            "Would you like to install the certificate now?",
                            "Certificate Generated",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Information
                        );

                        if (result == MessageBoxResult.Yes)
                        {
                            InstallCertificate();
                        }
                        else
                        {
                            ShowCertificateInstructions();
                        }

                        UpdateProxyUiState();
                    });
                }
            }
            catch (CryptographicException cryptoEx)
            {
                LogError($"Cryptographic error generating certificate: {cryptoEx.Message}");

                try
                {
                    LogInfo("Trying alternative certificate generation method...");
                    GenerateRootCertificateAlternative();
                }
                catch (Exception ex)
                {
                    LogError($"Alternative method also failed: {ex.Message}");
                    _isCertificateGenerated = false;

                    Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show(
                            $"Failed to generate certificate:\n\n{cryptoEx.Message}\n\n" +
                            "Try running the application as Administrator.",
                            "Certificate Error",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error
                        );
                    });
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to generate Root CA certificate: {ex.Message}");
                _isCertificateGenerated = false;

                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(
                        $"Failed to generate certificate:\n\n{ex.Message}",
                        "Certificate Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error
                    );
                });
            }
        }

        private void GenerateRootCertificateAlternative()
        {
            try
            {
                using (var rsa = RSA.Create(2048))
                {
                    var request = new CertificateRequest(
                        CA_CERT_SUBJECT,
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1
                    );

                    request.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(true, false, 0, true)
                    );

                    request.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                            true
                        )
                    );

                    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
                    var notAfter = notBefore.AddYears(2);

                    var certificate = request.CreateSelfSigned(notBefore, notAfter);

                    var pfxData = certificate.Export(X509ContentType.Pfx, CERT_PASSWORD);
                    _rootCaCertificate = new X509Certificate2(pfxData, CERT_PASSWORD,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                    _rootCaCertificate.FriendlyName = CA_CERT_FRIENDLY_NAME;

                    string certPath = Path.Combine(_certificatesPath, "vrax_ca.pfx");
                    string cerPath = Path.Combine(_certificatesPath, "vrax_ca.cer");

                    File.WriteAllBytes(certPath, pfxData);
                    File.WriteAllBytes(cerPath, _rootCaCertificate.Export(X509ContentType.Cert));

                    _isCertificateGenerated = true;

                    LogSuccess($"✓ Generated certificate (Alternative method)");
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Alternative method failed: {ex.Message}", ex);
            }
        }

        private void ShowCertificateInstructions()
        {
            Dispatcher.Invoke(() =>
            {
                MessageBox.Show(
                    "Manual Certificate Installation:\n\n" +
                    "1. Open certificates folder in File Explorer\n" +
                    "2. Double-click 'vrax_ca.cer'\n" +
                    "3. Click 'Install Certificate'\n" +
                    "4. Select 'Current User'\n" +
                    "5. Place certificate in 'Trusted Root Certification Authorities'\n" +
                    "6. Restart browser and clear SSL cache\n\n" +
                    "Path: " + _certificatesPath,
                    "Installation Instructions",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            });
        }

        private void CheckCertificateInstallation()
        {
            try
            {
                if (_rootCaCertificate == null)
                {
                    _isCertificateInstalled = false;
                    return;
                }

                using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadOnly);

                    var certs = store.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        _rootCaCertificate.Thumbprint,
                        false
                    );

                    if (certs.Count == 0)
                    {
                        certs = store.Certificates.Find(
                            X509FindType.FindBySubjectName,
                            "VRAX Proxy CA",
                            false
                        );
                    }

                    _isCertificateInstalled = certs.Count > 0;

                    if (_isCertificateInstalled)
                    {
                        var installedCert = certs[0];
                        LogSuccess($"✓ Certificate found in store (Valid: {installedCert.NotBefore:yyyy-MM-dd} to {installedCert.NotAfter:yyyy-MM-dd})");
                    }

                    store.Close();
                }

                Dispatcher.Invoke(() =>
                {
                    CertStatus.Text = _isCertificateInstalled ? "✓ INSTALLED" : "⚠ NOT INSTALLED";
                    CertStatus.Foreground = _isCertificateInstalled ? Brushes.LimeGreen : Brushes.Orange;

                    if (!_isCertificateInstalled && _isCertificateGenerated)
                    {
                        StatusMessage.Text = "WARNING: Certificate not installed. HTTPS sites will show security warnings.";
                    }
                    else if (_isCertificateInstalled)
                    {
                        StatusMessage.Text = "✓ Certificate installed. HTTPS interception ready.";
                    }
                });
            }
            catch (Exception ex)
            {
                LogError($"Certificate check failed: {ex.Message}");
                _isCertificateInstalled = false;
            }
        }

        private void InstallCertificate()
        {
            try
            {
                if (_rootCaCertificate == null)
                {
                    MessageBox.Show("Certificate not available. Please generate one first.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                LogInfo("Installing certificate to Trusted Root store...");

                using (var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);

                    var existingCerts = store.Certificates.Find(
                        X509FindType.FindBySubjectName,
                        "VRAX Proxy CA",
                        false
                    );

                    foreach (var cert in existingCerts)
                    {
                        LogInfo($"Removing existing certificate: {cert.Thumbprint}");
                        store.Remove(cert);
                    }

                    store.Add(_rootCaCertificate);
                    store.Close();
                }

                _isCertificateInstalled = true;

                Dispatcher.Invoke(() =>
                {
                    CertStatus.Text = "✓ INSTALLED";
                    CertStatus.Foreground = Brushes.LimeGreen;

                    MessageBox.Show(
                        "✓ Certificate installed successfully!\n\n" +
                        "Important next steps:\n" +
                        "1. Restart your browser completely\n" +
                        "2. Clear SSL state (browser settings)\n" +
                        "3. For Chrome: Visit chrome://restart\n" +
                        "4. For Firefox: Clear SSL Session Cache\n\n" +
                        "After restart, HTTPS sites should work without warnings.",
                        "Installation Complete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );

                    LogSuccess("Root CA certificate installed successfully");
                    StatusMessage.Text = "✓ Certificate installed. Please restart browser.";
                    UpdateProxyUiState();
                });
            }
            catch (UnauthorizedAccessException)
            {
                LogError("Access denied. Try running as administrator.");
                MessageBox.Show(
                    "Access denied. Please run VRAX as Administrator to install certificate.",
                    "Permission Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
            catch (CryptographicException cryptoEx)
            {
                LogError($"Cryptographic error during installation: {cryptoEx.Message}");
                MessageBox.Show(
                    $"Cryptographic error:\n\n{cryptoEx.Message}\n\n" +
                    "Try running as Administrator or install manually from certificates folder.",
                    "Installation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
            catch (Exception ex)
            {
                LogError($"Certificate installation failed: {ex.Message}");
                MessageBox.Show(
                    $"Installation failed:\n\n{ex.Message}\n\n" +
                    "You can manually install the certificate from the certificates folder.",
                    "Installation Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

        private X509Certificate2 GenerateServerCertificate(string hostname)
        {
            if (_rootCaCertificate == null || !_rootCaCertificate.HasPrivateKey)
            {
                throw new InvalidOperationException("Root CA certificate not available");
            }

            var cacheKey = hostname.ToLower();
            if (_serverCertificateCache.TryGetValue(cacheKey, out var cachedCert))
            {
                if (DateTime.Now < cachedCert.NotAfter && DateTime.Now > cachedCert.NotBefore)
                {
                    return cachedCert;
                }
                _serverCertificateCache.TryRemove(cacheKey, out _);
            }

            var hostLock = _hostLocks.GetOrAdd(cacheKey, new SemaphoreSlim(1, 1));
            hostLock.Wait();

            try
            {
                if (_serverCertificateCache.TryGetValue(cacheKey, out cachedCert))
                {
                    return cachedCert;
                }

                using (var rsa = RSA.Create(2048))
                {
                    var distinguishedName = $"CN={hostname}";

                    var request = new CertificateRequest(
                        distinguishedName,
                        rsa,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1
                    );

                    if (!hostname.Equals("localhost", StringComparison.OrdinalIgnoreCase))
                    {
                        var sanBuilder = new SubjectAlternativeNameBuilder();
                        sanBuilder.AddDnsName(hostname);

                        if (!hostname.Contains("*"))
                        {
                            sanBuilder.AddDnsName($"*.{hostname}");
                        }

                        request.CertificateExtensions.Add(sanBuilder.Build());
                    }

                    request.CertificateExtensions.Add(
                        new X509BasicConstraintsExtension(false, false, 0, false)
                    );

                    request.CertificateExtensions.Add(
                        new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                            true
                        )
                    );

                    request.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            new OidCollection {
                                new Oid("1.3.6.1.5.5.7.3.1")
                            },
                            false
                        )
                    );

                    var skiExtension = new X509SubjectKeyIdentifierExtension(
                        request.PublicKey,
                        X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                        false
                    );
                    request.CertificateExtensions.Add(skiExtension);

                    var serialNumber = new byte[16];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serialNumber);
                    }
                    serialNumber[0] = 0x40;

                    var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
                    var notAfter = notBefore.AddDays(365);

                    var serverCert = request.Create(
                        _rootCaCertificate,
                        notBefore,
                        notAfter,
                        serialNumber
                    );

                    var certWithKey = serverCert.CopyWithPrivateKey(rsa);

                    var exportable = new X509Certificate2(
                        certWithKey.Export(X509ContentType.Pfx),
                        (string)null,
                        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
                    );

                    exportable.FriendlyName = $"VRAX Proxy: {hostname}";

                    _serverCertificateCache[cacheKey] = exportable;

                    LogInfo($"Generated server certificate for: {hostname}");
                    return exportable;
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to generate server certificate for {hostname}: {ex.Message}");
                throw;
            }
            finally
            {
                hostLock.Release();
            }
        }

        private async void StartProxy_Click(object sender, RoutedEventArgs e)
        {
            if (_isProxyRunning)
            {
                MessageBox.Show("Proxy is already running!", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                string host = ProxyHost.Text.Trim();
                if (string.IsNullOrWhiteSpace(host))
                    host = "127.0.0.1";

                if (!int.TryParse(ProxyPort.Text.Trim(), out int port) || port < 1 || port > 65535)
                {
                    MessageBox.Show("Invalid port number! Use 1-65535.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (port < 1024 && !IsAdministrator())
                {
                    var result = MessageBox.Show(
                        "Ports below 1024 require administrator privileges.\n\n" +
                        "Would you like to use a different port?",
                        "Port Warning",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning
                    );

                    if (result == MessageBoxResult.Yes)
                    {
                        ProxyPort.Text = "8080";
                        port = 8080;
                    }
                    else
                    {
                        return;
                    }
                }

                if (!_isCertificateGenerated)
                {
                    var result = MessageBox.Show(
                        "Certificate not generated. HTTPS interception won't work.\n\n" +
                        "Generate certificate now?",
                        "Certificate Required",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning
                    );

                    if (result == MessageBoxResult.Yes)
                    {
                        Task.Run(() => GenerateRootCertificate()).Wait(15000);

                        if (!_isCertificateGenerated)
                        {
                            MessageBox.Show("Certificate generation failed or timed out.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                }

                if (!_isCertificateInstalled && _sslInterceptionEnabled)
                {
                    var result = MessageBox.Show(
                        "Root certificate is not installed. HTTPS sites will show security warnings.\n\n" +
                        "Would you like to install the certificate now?",
                        "Certificate Warning",
                        MessageBoxButton.YesNoCancel,
                        MessageBoxImage.Warning
                    );

                    if (result == MessageBoxResult.Cancel)
                        return;

                    if (result == MessageBoxResult.Yes)
                    {
                        InstallCertificate();

                        if (!_isCertificateInstalled)
                        {
                            MessageBox.Show("Certificate not installed. HTTPS will show warnings.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                }

                _proxyServerCts = new CancellationTokenSource();

                IPAddress ipAddress;
                if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                    host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
                {
                    ipAddress = IPAddress.Loopback;
                }
                else if (host.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase))
                {
                    ipAddress = IPAddress.Any;
                }
                else
                {
                    ipAddress = IPAddress.Parse(host);
                }

                _proxyListener = new TcpListener(ipAddress, port);
                _proxyListener.Start(500);

                _isProxyRunning = true;
                _proxyStartTime = DateTime.Now;
                UpdateProxyUiState();

                LogSuccess($"✓ Proxy server started on {host}:{port}");
                LogInfo($"Configure your browser to use proxy: {host}:{port}");

                if (_sslInterceptionEnabled)
                {
                    if (_isCertificateInstalled)
                    {
                        LogSuccess("✓ SSL Interception: ENABLED (Certificate installed)");
                    }
                    else if (_isCertificateGenerated)
                    {
                        LogWarning("⚠ SSL Interception: ENABLED (Certificate NOT installed - browsers will show warnings)");
                    }
                    else
                    {
                        LogError("✗ SSL Interception: DISABLED (Certificate not generated)");
                    }
                }
                else
                {
                    LogInfo("✓ SSL Interception: DISABLED (HTTPS will pass through)");
                }

                _ = Task.Run(() => AcceptClientConnections(_proxyServerCts.Token), _proxyServerCts.Token);
            }
            catch (SocketException sex)
            {
                if (sex.SocketErrorCode == SocketError.AddressAlreadyInUse)
                {
                    MessageBox.Show($"Port {ProxyPort.Text} is already in use!", "Port Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    LogError($"Port {ProxyPort.Text} already in use");
                }
                else
                {
                    MessageBox.Show($"Socket error: {sex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    LogError($"Socket error: {sex.Message}");
                }
                _isProxyRunning = false;
                UpdateProxyUiState();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to start proxy:\n\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LogError($"Failed to start proxy: {ex.Message}");
                _isProxyRunning = false;
                UpdateProxyUiState();
            }
        }

        private bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void StopProxy_Click(object sender, RoutedEventArgs e)
        {
            if (!_isProxyRunning)
                return;

            try
            {
                _proxyServerCts?.Cancel();
                _proxyListener?.Stop();
                _isProxyRunning = false;

                lock (_connectionsLock)
                {
                    foreach (var connection in _activeConnections)
                    {
                        try
                        {
                            if (!connection.IsCompleted)
                            {
                                Task.Delay(100).Wait();
                            }
                        }
                        catch { }
                    }
                    _activeConnections.Clear();
                    _connectionCountText.Text = "Connections: 0";
                }

                if (_isInterceptEnabled)
                {
                    ToggleIntercept_Click(null, null);
                }

                UpdateProxyUiState();
                LogInfo("✓ Proxy server stopped");
            }
            catch (Exception ex)
            {
                LogError($"Error stopping proxy: {ex.Message}");
            }
        }

        private async Task AcceptClientConnections(CancellationToken cancellationToken)
        {
            LogInfo("Listening for client connections...");

            while (!cancellationToken.IsCancellationRequested && _isProxyRunning)
            {
                try
                {
                    var client = await _proxyListener.AcceptTcpClientAsync();
                    client.ReceiveTimeout = 30000;
                    client.SendTimeout = 30000;
                    client.NoDelay = true;

                    var connectionTask = Task.Run(() => HandleClientConnection(client, cancellationToken), cancellationToken);

                    lock (_connectionsLock)
                    {
                        _activeConnections.Add(connectionTask);
                        _connectionCountText.Text = $"Connections: {_activeConnections.Count}";
                        connectionTask.ContinueWith(t =>
                        {
                            lock (_connectionsLock)
                            {
                                _activeConnections.Remove(connectionTask);
                                _connectionCountText.Text = $"Connections: {_activeConnections.Count}";
                            }
                        }, cancellationToken);
                    }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException sex) when (sex.SocketErrorCode == SocketError.Interrupted)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        LogError($"Error accepting client: {ex.Message}");
                    }
                }
            }

            LogInfo("Stopped accepting connections");
        }

        private async Task HandleClientConnection(TcpClient client, CancellationToken cancellationToken)
        {
            string clientInfo = null;

            try
            {
                var remoteEndpoint = client.Client.RemoteEndPoint as IPEndPoint;
                clientInfo = $"{remoteEndpoint?.Address}:{remoteEndpoint?.Port}";

                using (client)
                using (var clientStream = client.GetStream())
                {
                    var buffer = new byte[4096];
                    var bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                    if (bytesRead == 0)
                        return;

                    string requestPreview = Encoding.ASCII.GetString(buffer, 0, Math.Min(bytesRead, 512));

                    if (requestPreview.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                    {
                        await HandleHttpsConnect(client, clientStream, buffer, bytesRead, cancellationToken);
                    }
                    else
                    {
                        await HandleHttpRequest(clientStream, buffer, bytesRead, null, false, cancellationToken);
                    }
                }
            }
            catch (IOException ioEx)
            {
                LogDebug($"Client {clientInfo} disconnected: {ioEx.Message}");
            }
            catch (SocketException sockEx)
            {
                LogDebug($"Socket error for client {clientInfo}: {sockEx.Message}");
            }
            catch (Exception ex)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    LogError($"Client {clientInfo} handler error: {ex.Message}");
                }
            }
        }

        private async Task HandleHttpsConnect(TcpClient client, NetworkStream clientStream, byte[] initialBuffer, int initialBytes, CancellationToken cancellationToken)
        {
            string targetHost = null;
            int targetPort = 443;

            try
            {
                string requestText = Encoding.ASCII.GetString(initialBuffer, 0, initialBytes);
                var lines = requestText.Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);

                if (lines.Length == 0)
                    return;

                var connectParts = lines[0].Split(' ');
                if (connectParts.Length < 2)
                    return;

                string hostAndPort = connectParts[1];
                var hostParts = hostAndPort.Split(':');
                targetHost = hostParts[0].Trim();

                if (hostParts.Length > 1 && int.TryParse(hostParts[1], out int port))
                    targetPort = port;

                if (targetHost.Contains(":"))
                {
                    targetHost = targetHost.Split(':')[0];
                }

                LogInfo($"HTTPS CONNECT: {targetHost}:{targetPort}");

                byte[] connectResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: VRAX-Proxy/3.0\r\n\r\n");
                await clientStream.WriteAsync(connectResponse, 0, connectResponse.Length, cancellationToken);
                await clientStream.FlushAsync(cancellationToken);

                if (_sslInterceptionEnabled && _rootCaCertificate != null && _rootCaCertificate.HasPrivateKey)
                {
                    await PerformSslInterception(clientStream, targetHost, targetPort, cancellationToken);
                }
                else
                {
                    await TunnelConnection(clientStream, targetHost, targetPort, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                LogError($"HTTPS CONNECT error for {targetHost}:{targetPort}: {ex.Message}");
            }
        }

        private async Task PerformSslInterception(NetworkStream clientStream, string targetHost, int targetPort, CancellationToken cancellationToken)
        {
            SslStream clientSslStream = null;

            try
            {
                var serverCertificate = GenerateServerCertificate(targetHost);

                clientSslStream = new SslStream(
                    clientStream,
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (sender, cert, chain, errors) =>
                    {
                        return true;
                    }
                );

                var sslOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption
                };

                await clientSslStream.AuthenticateAsServerAsync(sslOptions, cancellationToken);

                if (clientSslStream.IsAuthenticated && clientSslStream.IsEncrypted)
                {
                    LogSuccess($"SSL handshake completed for: {targetHost} (Protocol: {clientSslStream.SslProtocol})");
                }
                else
                {
                    LogWarning($"SSL handshake incomplete for: {targetHost}");
                    return;
                }

                var buffer = new byte[8192];
                var bytesRead = await clientSslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                if (bytesRead == 0)
                    return;

                await HandleHttpRequest(clientSslStream, buffer, bytesRead, targetHost, true, cancellationToken);
            }
            catch (AuthenticationException authEx)
            {
                LogError($"SSL authentication failed for {targetHost}: {authEx.Message}");
            }
            catch (IOException ioEx)
            {
                LogDebug($"SSL stream closed for {targetHost}: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                LogError($"SSL interception error for {targetHost}: {ex.Message}");
            }
            finally
            {
                try
                {
                    clientSslStream?.Close();
                    clientSslStream?.Dispose();
                }
                catch { }
            }
        }

        private async Task TunnelConnection(NetworkStream clientStream, string targetHost, int targetPort, CancellationToken cancellationToken)
        {
            using (var targetClient = new TcpClient())
            {
                try
                {
                    await targetClient.ConnectAsync(targetHost, targetPort);
                    using (var targetStream = targetClient.GetStream())
                    {
                        var clientToServer = Task.Run(async () =>
                        {
                            var buffer = new byte[8192];
                            int bytesRead;
                            try
                            {
                                while ((bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                                {
                                    await targetStream.WriteAsync(buffer, 0, bytesRead, cancellationToken);
                                }
                            }
                            catch { }
                        }, cancellationToken);

                        var serverToClient = Task.Run(async () =>
                        {
                            var buffer = new byte[8192];
                            int bytesRead;
                            try
                            {
                                while ((bytesRead = await targetStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                                {
                                    await clientStream.WriteAsync(buffer, 0, bytesRead, cancellationToken);
                                }
                            }
                            catch { }
                        }, cancellationToken);

                        await Task.WhenAny(clientToServer, serverToClient);
                    }
                }
                catch (Exception ex)
                {
                    LogDebug($"Tunnel error for {targetHost}:{targetPort}: {ex.Message}");
                }
            }
        }

        private async Task<byte[]> ReadCompleteHttpRequest(Stream stream, byte[] initialBuffer, int initialBytes, CancellationToken cancellationToken)
        {
            using (var ms = new MemoryStream())
            {
                ms.Write(initialBuffer, 0, initialBytes);

                string headerText = Encoding.ASCII.GetString(ms.ToArray());
                int headerEndIndex = headerText.IndexOf("\r\n\r\n", StringComparison.Ordinal);

                while (headerEndIndex == -1)
                {
                    var buffer = new byte[4096];
                    int read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                    if (read == 0)
                        break;

                    ms.Write(buffer, 0, read);
                    headerText = Encoding.ASCII.GetString(ms.ToArray());
                    headerEndIndex = headerText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                }

                if (headerEndIndex == -1)
                    return ms.ToArray();

                var contentLengthMatch = Regex.Match(headerText, @"Content-Length:\s*(\d+)", RegexOptions.IgnoreCase);

                if (contentLengthMatch.Success && int.TryParse(contentLengthMatch.Groups[1].Value, out int contentLength) && contentLength > 0)
                {
                    int headerLength = headerEndIndex + 4;
                    int bodyBytesReceived = (int)ms.Length - headerLength;
                    int remainingBytes = contentLength - bodyBytesReceived;

                    if (remainingBytes > 0)
                    {
                        var buffer = new byte[Math.Min(65536, remainingBytes)];

                        while (remainingBytes > 0 && !cancellationToken.IsCancellationRequested)
                        {
                            int toRead = Math.Min(buffer.Length, remainingBytes);
                            int read = await stream.ReadAsync(buffer, 0, toRead, cancellationToken);

                            if (read == 0)
                                break;

                            ms.Write(buffer, 0, read);
                            remainingBytes -= read;
                        }
                    }
                }
                else if (headerText.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
                {
                    await ReadChunkedBody(stream, ms, cancellationToken);
                }

                return ms.ToArray();
            }
        }

        private async Task ReadChunkedBody(Stream stream, MemoryStream ms, CancellationToken cancellationToken)
        {
            var buffer = new byte[4096];
            var decoder = Encoding.ASCII.GetDecoder();
            var chunkSizeBuffer = new StringBuilder();

            try
            {
                while (true)
                {
                    chunkSizeBuffer.Clear();
                    char currentChar;
                    byte[] singleByte = new byte[1];

                    while (true)
                    {
                        int bytesRead = await stream.ReadAsync(singleByte, 0, 1, cancellationToken);
                        if (bytesRead == 0) return;

                        char[] chars = new char[1];
                        decoder.Convert(singleByte, 0, 1, chars, 0, 1, false, out _, out _, out _);
                        currentChar = chars[0];

                        if (currentChar == '\r')
                        {
                            await stream.ReadAsync(singleByte, 0, 1, cancellationToken);
                            break;
                        }

                        if (char.IsDigit(currentChar) || (currentChar >= 'a' && currentChar <= 'f') || (currentChar >= 'A' && currentChar <= 'F'))
                        {
                            chunkSizeBuffer.Append(currentChar);
                        }
                    }

                    if (chunkSizeBuffer.Length == 0) break;

                    int chunkSize = Convert.ToInt32(chunkSizeBuffer.ToString(), 16);
                    if (chunkSize == 0) break;

                    int totalRead = 0;
                    while (totalRead < chunkSize)
                    {
                        int toRead = Math.Min(buffer.Length, chunkSize - totalRead);
                        int bytesRead = await stream.ReadAsync(buffer, 0, toRead, cancellationToken);
                        if (bytesRead == 0) break;

                        ms.Write(buffer, 0, bytesRead);
                        totalRead += bytesRead;
                    }

                    await stream.ReadAsync(buffer, 0, 2, cancellationToken);
                }

                await stream.ReadAsync(buffer, 0, 2, cancellationToken);
            }
            catch { }
        }

        private HttpRequestInfo ParseHttpRequest(string requestText, string forcedHost, bool isHttps)
        {
            try
            {
                var lines = requestText.Split(new[] { "\r\n" }, StringSplitOptions.None);

                if (lines.Length == 0)
                    return null;

                var requestLineParts = lines[0].Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);

                if (requestLineParts.Length < 3)
                    return null;

                string method = requestLineParts[0];
                string pathOrUrl = requestLineParts[1];
                string httpVersion = requestLineParts[2];

                string host = forcedHost;

                if (string.IsNullOrEmpty(host))
                {
                    for (int i = 1; i < lines.Length; i++)
                    {
                        if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                        {
                            host = lines[i].Substring(5).Trim();
                            break;
                        }
                    }
                }

                if (string.IsNullOrEmpty(host))
                    return null;

                string path = pathOrUrl;
                string fullUrl;

                if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    fullUrl = pathOrUrl;
                    var uri = new Uri(fullUrl);
                    path = uri.PathAndQuery;
                    host = uri.Host;
                    isHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    path = pathOrUrl;
                    fullUrl = $"{(isHttps ? "https" : "http")}://{host}{path}";
                }

                var headers = new Dictionary<string, string>();
                bool inHeaders = true;
                StringBuilder bodyBuilder = new StringBuilder();
                int contentLength = 0;

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

                            headers[headerName] = headerValue;

                            if (headerName.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                            {
                                if (int.TryParse(headerValue, out int cl))
                                {
                                    contentLength = cl;
                                }
                            }
                        }
                    }
                    else
                    {
                        bodyBuilder.AppendLine(lines[i]);
                    }
                }

                string body = bodyBuilder.ToString().Trim();

                return new HttpRequestInfo
                {
                    Method = method,
                    Path = path,
                    Host = host,
                    HttpVersion = httpVersion,
                    FullUrl = fullUrl,
                    IsHttps = isHttps,
                    Headers = headers,
                    Body = body,
                    ContentLength = contentLength,
                    HasBody = !string.IsNullOrEmpty(body) || contentLength > 0
                };
            }
            catch (Exception ex)
            {
                LogError($"Failed to parse request: {ex.Message}");
                return null;
            }
        }

        private async Task HandleHttpRequest(
            Stream clientStream,
            byte[] initialBuffer,
            int initialBytes,
            string forcedHost,
            bool isHttps,
            CancellationToken cancellationToken)
        {
            HttpTransaction transaction = null;

            try
            {
                var fullRequestData = await ReadCompleteHttpRequest(clientStream, initialBuffer, initialBytes, cancellationToken);

                if (fullRequestData == null || fullRequestData.Length == 0)
                    return;

                string requestText = Encoding.UTF8.GetString(fullRequestData);

                var requestInfo = ParseHttpRequest(requestText, forcedHost, isHttps);

                if (requestInfo == null)
                {
                    LogWarning("Failed to parse HTTP request");
                    return;
                }

                transaction = new HttpTransaction
                {
                    Id = Interlocked.Increment(ref _requestIdCounter),
                    Method = requestInfo.Method,
                    Host = requestInfo.Host,
                    Url = requestInfo.FullUrl,
                    RequestHeaders = requestText,
                    Timestamp = DateTime.Now,
                    IsHttps = isHttps,
                    Status = "...",
                    Size = FormatBytes(fullRequestData.Length),
                    ResponseTime = 0,
                    FullRequest = requestText,
                    RawRequest = fullRequestData
                };

                Interlocked.Increment(ref _totalRequestsProcessed);
                LogRequest($"#{transaction.Id} {transaction.Method} {transaction.Host}{requestInfo.Path}");

                if (_isInterceptEnabled)
                {
                    var interceptDecision = await InterceptRequest(transaction, fullRequestData, false, cancellationToken);

                    if (interceptDecision.Action == InterceptAction.Drop)
                    {
                        transaction.Status = "DROPPED";
                        transaction.ResponseHeaders = "Request dropped by user";
                        AddTransactionToHistory(transaction);
                        return;
                    }

                    if (interceptDecision.Action == InterceptAction.Modified && interceptDecision.ModifiedData != null)
                    {
                        fullRequestData = interceptDecision.ModifiedData;
                        requestText = Encoding.UTF8.GetString(fullRequestData);
                        requestInfo = ParseHttpRequest(requestText, forcedHost, isHttps);
                        transaction.RequestHeaders = requestText;
                        transaction.FullRequest = requestText;
                        transaction.RawRequest = fullRequestData;
                    }
                }

                await ForwardRequestToServer(transaction, requestInfo, requestText, clientStream, isHttps, cancellationToken);
            }
            catch (Exception ex)
            {
                if (transaction != null)
                {
                    transaction.Status = "ERROR";
                    transaction.ResponseHeaders = $"Error: {ex.Message}";
                    AddTransactionToHistory(transaction);
                }

                if (!cancellationToken.IsCancellationRequested)
                {
                    LogError($"Request handling error: {ex.Message}");
                    await SendErrorResponse(clientStream, 502, "Bad Gateway", ex.Message);
                }
            }
        }

        private async Task ForwardRequestToServer(
            HttpTransaction transaction,
            HttpRequestInfo requestInfo,
            string requestText,
            Stream clientStream,
            bool isHttps,
            CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();

            try
            {
                Uri targetUri;
                try
                {
                    targetUri = new Uri(requestInfo.FullUrl);
                }
                catch (UriFormatException)
                {
                    targetUri = new Uri($"{(isHttps ? "https" : "http")}://{requestInfo.Host}{requestInfo.Path}");
                }

                var request = new HttpRequestMessage(new HttpMethod(requestInfo.Method), targetUri);

                var lines = requestText.Split(new[] { "\r\n" }, StringSplitOptions.None);
                bool inHeaders = true;
                StringBuilder bodyBuilder = new StringBuilder();

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

                            if (!IsRestrictedHeader(headerName))
                            {
                                try
                                {
                                    if (headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (request.Content == null)
                                        {
                                            request.Content = new StringContent("", Encoding.UTF8, headerValue);
                                        }
                                    }
                                    else if (headerName.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
                                    {
                                        request.Headers.TryAddWithoutValidation("User-Agent", headerValue);
                                    }
                                    else if (headerName.Equals("Accept", StringComparison.OrdinalIgnoreCase))
                                    {
                                        request.Headers.Accept.ParseAdd(headerValue);
                                    }
                                    else if (headerName.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase))
                                    {
                                        request.Headers.AcceptEncoding.ParseAdd(headerValue);
                                    }
                                    else if (headerName.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                                    {
                                        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                                            headerValue.Split(' ')[0],
                                            headerValue.Substring(headerValue.IndexOf(' ') + 1)
                                        );
                                    }
                                    else
                                    {
                                        request.Headers.TryAddWithoutValidation(headerName, headerValue);
                                    }
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
                if (!string.IsNullOrEmpty(body) && request.Content == null)
                {
                    request.Content = new StringContent(body, Encoding.UTF8);
                }

                using (var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                {
                    stopwatch.Stop();

                    var responseBuilder = new StringBuilder();
                    responseBuilder.AppendLine($"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}");

                    foreach (var header in response.Headers)
                    {
                        foreach (var value in header.Value)
                        {
                            responseBuilder.AppendLine($"{header.Key}: {value}");
                        }
                    }

                    if (response.Content != null)
                    {
                        foreach (var header in response.Content.Headers)
                        {
                            foreach (var value in header.Value)
                            {
                                responseBuilder.AppendLine($"{header.Key}: {value}");
                            }
                        }

                        responseBuilder.AppendLine();
                    }

                    byte[] responseBody = null;
                    string responseBodyText = "";

                    if (response.Content != null)
                    {
                        responseBody = await response.Content.ReadAsByteArrayAsync();
                        responseBodyText = await response.Content.ReadAsStringAsync();
                    }

                    string responseHeaders = responseBuilder.ToString();
                    byte[] responseHeaderBytes = Encoding.UTF8.GetBytes(responseHeaders);

                    var fullResponseData = new byte[responseHeaderBytes.Length + (responseBody?.Length ?? 0)];
                    Buffer.BlockCopy(responseHeaderBytes, 0, fullResponseData, 0, responseHeaderBytes.Length);

                    if (responseBody != null && responseBody.Length > 0)
                    {
                        Buffer.BlockCopy(responseBody, 0, fullResponseData, responseHeaderBytes.Length, responseBody.Length);
                    }

                    if (_isInterceptEnabled && _isInterceptResponseEnabled)
                    {
                        var interceptDecision = await InterceptRequest(transaction, fullResponseData, true, cancellationToken);

                        if (interceptDecision.Action == InterceptAction.Drop)
                        {
                            transaction.Status = "RESPONSE DROPPED";
                            transaction.ResponseHeaders = "Response dropped by user";
                            AddTransactionToHistory(transaction);
                            return;
                        }

                        if (interceptDecision.Action == InterceptAction.Modified && interceptDecision.ModifiedData != null)
                        {
                            fullResponseData = interceptDecision.ModifiedData;
                        }

                        await clientStream.WriteAsync(fullResponseData, 0, fullResponseData.Length, cancellationToken);
                    }
                    else
                    {
                        await clientStream.WriteAsync(fullResponseData, 0, fullResponseData.Length, cancellationToken);
                    }

                    await clientStream.FlushAsync(cancellationToken);

                    transaction.Status = ((int)response.StatusCode).ToString();
                    transaction.ResponseTime = stopwatch.ElapsedMilliseconds;

                    long responseSize = fullResponseData.Length;
                    transaction.Size = FormatBytes(responseSize);
                    Interlocked.Add(ref _totalBytesTransferred, responseSize);

                    transaction.ResponseHeaders = responseHeaders + responseBodyText;
                    transaction.FullResponse = responseHeaders + responseBodyText;
                    transaction.RawResponse = fullResponseData;

                    AddTransactionToHistory(transaction);

                    LogSuccess($"#{transaction.Id} → {transaction.Status} ({transaction.ResponseTime}ms, {transaction.Size})");
                }
            }
            catch (TaskCanceledException)
            {
                transaction.Status = "TIMEOUT";
                transaction.ResponseHeaders = "Request timed out";
                transaction.ResponseTime = stopwatch.ElapsedMilliseconds;
                AddTransactionToHistory(transaction);
                LogWarning($"#{transaction.Id} timed out");
            }
            catch (HttpRequestException httpEx)
            {
                stopwatch.Stop();
                transaction.Status = "HTTP ERROR";
                transaction.ResponseHeaders = $"HTTP Error: {httpEx.Message}";
                transaction.ResponseTime = stopwatch.ElapsedMilliseconds;
                AddTransactionToHistory(transaction);

                LogError($"#{transaction.Id} HTTP error: {httpEx.Message}");
                await SendErrorResponse(clientStream, 502, "Bad Gateway", $"Proxy error: {httpEx.Message}");
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                transaction.Status = "ERROR";
                transaction.ResponseHeaders = $"Error: {ex.Message}";
                transaction.ResponseTime = stopwatch.ElapsedMilliseconds;
                AddTransactionToHistory(transaction);

                LogError($"#{transaction.Id} failed: {ex.Message}");
                await SendErrorResponse(clientStream, 502, "Bad Gateway", $"Proxy error: {ex.Message}");
            }
        }

        private bool IsRestrictedHeader(string headerName)
        {
            string[] restricted = {
                "Host", "Connection", "Proxy-Connection", "Transfer-Encoding",
                "Upgrade", "Expect", "Keep-Alive", "Proxy-Authorization",
                "TE", "Trailer"
            };

            return restricted.Any(h => h.Equals(headerName, StringComparison.OrdinalIgnoreCase));
        }

        private async Task SendErrorResponse(Stream clientStream, int statusCode, string statusText, string message)
        {
            try
            {
                string errorResponse = $"HTTP/1.1 {statusCode} {statusText}\r\n" +
                                      "Content-Type: text/plain; charset=utf-8\r\n" +
                                      "Connection: close\r\n" +
                                      $"Content-Length: {Encoding.UTF8.GetByteCount(message)}\r\n" +
                                      "\r\n" +
                                      message;

                byte[] errorBytes = Encoding.UTF8.GetBytes(errorResponse);
                await clientStream.WriteAsync(errorBytes, 0, errorBytes.Length);
                await clientStream.FlushAsync();
            }
            catch { }
        }

        private void StartInterceptProcessor()
        {
            _interceptProcessorCts = new CancellationTokenSource();

            _interceptProcessorTask = Task.Run(async () =>
            {
                try
                {
                    foreach (var context in _interceptQueue.GetConsumingEnumerable(_interceptProcessorCts.Token))
                    {
                        await Dispatcher.InvokeAsync(() =>
                        {
                            try
                            {
                                _currentInterceptedRequest = context;

                                if (context.IsResponse)
                                {
                                    RequestEditor.Text = context.Transaction.FullRequest;
                                    ResponseViewer.Text = Encoding.UTF8.GetString(context.ResponseData);
                                    CurrentRequestInfo.Text = $"#{context.Transaction.Id} RESPONSE ({context.Transaction.Method} {context.Transaction.Host})";
                                }
                                else
                                {
                                    RequestEditor.Text = Encoding.UTF8.GetString(context.RequestData);
                                    ResponseViewer.Text = "";
                                    CurrentRequestInfo.Text = $"#{context.Transaction.Id} {context.Transaction.Method} {context.Transaction.Host}";
                                }

                                ForwardBtn.IsEnabled = true;
                                DropBtn.IsEnabled = true;
                                ModifyBtn.IsEnabled = true;
                                InterceptOnOffBtn.IsEnabled = false;

                                InterceptStatus.Text = context.IsResponse ?
                                    "◢ INTERCEPTION: RESPONSE HELD" :
                                    "◢ INTERCEPTION: REQUEST HELD";
                                InterceptStatus.Foreground = Brushes.Orange;

                                LogInfo($"⚡ Intercepted: #{context.Transaction.Id} {context.Transaction.Method} {context.Transaction.Host}");
                            }
                            catch (Exception ex)
                            {
                                LogError($"UI update error: {ex.Message}");
                            }
                        });
                    }
                }
                catch (OperationCanceledException) { }
            }, _interceptProcessorCts.Token);
        }

        private async Task<InterceptDecision> InterceptRequest(HttpTransaction transaction, byte[] data, bool isResponse, CancellationToken cancellationToken)
        {
            var context = new InterceptContext
            {
                Transaction = transaction,
                RequestData = isResponse ? null : data,
                ResponseData = isResponse ? data : null,
                IsResponse = isResponse,
                DecisionSource = new TaskCompletionSource<InterceptDecision>()
            };

            _interceptQueue.Add(context);

            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeoutCts.CancelAfter(TimeSpan.FromMinutes(2));

                try
                {
                    return await context.DecisionSource.Task.WaitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException)
                {
                    return new InterceptDecision { Action = InterceptAction.Forward };
                }
            }
        }

        private void ToggleIntercept_Click(object sender, RoutedEventArgs e)
        {
            _isInterceptEnabled = !_isInterceptEnabled;
            _isInterceptResponseEnabled = _isInterceptEnabled;

            if (_isInterceptEnabled)
            {
                LogSuccess("✓ Interception ENABLED - All requests and responses will be intercepted");
            }
            else
            {
                LogInfo("✓ Interception DISABLED");

                if (_currentInterceptedRequest != null)
                {
                    _currentInterceptedRequest.DecisionSource?.TrySetResult(new InterceptDecision { Action = InterceptAction.Forward });
                    _currentInterceptedRequest = null;
                }

                while (_interceptQueue.TryTake(out var context))
                {
                    context.DecisionSource?.TrySetResult(new InterceptDecision { Action = InterceptAction.Forward });
                }

                ClearInterceptUi();
            }

            UpdateProxyUiState();
        }

        private void Forward_Click(object sender, RoutedEventArgs e)
        {
            if (_currentInterceptedRequest == null)
                return;

            try
            {
                byte[] modifiedData;

                if (_currentInterceptedRequest.IsResponse)
                {
                    string currentText = ResponseViewer.Text;
                    modifiedData = Encoding.UTF8.GetBytes(currentText);
                    LogInfo($"→ Forwarded modified response #{_currentInterceptedRequest.Transaction.Id}");
                }
                else
                {
                    string currentText = RequestEditor.Text;
                    modifiedData = Encoding.UTF8.GetBytes(currentText);
                    LogInfo($"→ Forwarded modified request #{_currentInterceptedRequest.Transaction.Id}");
                }

                _currentInterceptedRequest.DecisionSource.TrySetResult(new InterceptDecision
                {
                    Action = InterceptAction.Modified,
                    ModifiedData = modifiedData
                });

                _currentInterceptedRequest = null;
                ClearInterceptUi();
            }
            catch (Exception ex)
            {
                LogError($"Forward error: {ex.Message}");
            }
        }

        private void Modify_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Request/Response can be modified directly in the editor.\n\nMake your changes and click FORWARD to send the modified version.", "Modify Request", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void Drop_Click(object sender, RoutedEventArgs e)
        {
            if (_currentInterceptedRequest == null)
                return;

            try
            {
                _currentInterceptedRequest.DecisionSource.TrySetResult(new InterceptDecision { Action = InterceptAction.Drop });
                LogWarning($"✗ Dropped #{_currentInterceptedRequest.Transaction.Id}");

                _currentInterceptedRequest = null;
                ClearInterceptUi();
            }
            catch (Exception ex)
            {
                LogError($"Drop error: {ex.Message}");
            }
        }

        private void ClearInterceptUi()
        {
            Dispatcher.Invoke(() =>
            {
                ForwardBtn.IsEnabled = false;
                DropBtn.IsEnabled = false;
                ModifyBtn.IsEnabled = false;
                InterceptOnOffBtn.IsEnabled = true;
                CurrentRequestInfo.Text = "Waiting for next request...";
                InterceptStatus.Text = _isInterceptEnabled ? "◢ INTERCEPTION: ACTIVE" : "◢ INTERCEPTION: INACTIVE";
                InterceptStatus.Foreground = _isInterceptEnabled ? Brushes.LimeGreen : Brushes.Red;
            });
        }

        private void RequestEditor_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void AddTransactionToHistory(HttpTransaction transaction)
        {
            Dispatcher.Invoke(() =>
            {
                RequestHistory.Insert(0, transaction);

                while (RequestHistory.Count > _maxHistorySize)
                {
                    RequestHistory.RemoveAt(RequestHistory.Count - 1);
                }

                RequestCount.Text = RequestHistory.Count.ToString();
            });
        }

        private void HistoryGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                RequestEditor.Text = transaction.FullRequest ?? "";
                ResponseViewer.Text = transaction.FullResponse ?? "No response data available";
            }
        }

        private void SendToRepeater_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                string url = transaction.Url;

                if (string.IsNullOrEmpty(url) || !Uri.IsWellFormedUriString(url, UriKind.Absolute))
                {
                    url = $"{(transaction.IsHttps ? "https" : "http")}://{transaction.Host}";
                }

                RepeaterUrl.Text = url;
                RepeaterRequest.Text = transaction.FullRequest;

                var tabControl = FindVisualChild<TabControl>(this);
                if (tabControl != null && tabControl.Items.Count > 1)
                {
                    tabControl.SelectedIndex = 1;
                }

                SaveRepeaterSession();

                LogSuccess($"✓ Sent to Repeater: {transaction.Method} {transaction.Host}");
            }
        }

        private void SendToIntruder_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                IntruderTemplate.Text = transaction.FullRequest;

                var tabControl = FindVisualChild<TabControl>(this);
                if (tabControl != null && tabControl.Items.Count > 2)
                {
                    tabControl.SelectedIndex = 2;
                }

                LogSuccess($"✓ Sent to Intruder: {transaction.Method} {transaction.Host}");
            }
        }

        private void CopyUrl_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                try
                {
                    string url = transaction.Url;
                    if (string.IsNullOrEmpty(url))
                    {
                        url = $"{(transaction.IsHttps ? "https" : "http")}://{transaction.Host}";
                    }

                    Clipboard.SetText(url);
                    LogSuccess("✓ URL copied to clipboard");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy URL: {ex.Message}");
                }
            }
        }

        private void SaveRequest_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                try
                {
                    var saveDialog = new SaveFileDialog
                    {
                        Filter = "HTTP Request (*.http)|*.http|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                        FileName = $"request_{transaction.Id}_{transaction.Method}_{SanitizeFileName(transaction.Host)}.http",
                        InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
                    };

                    if (saveDialog.ShowDialog() == true)
                    {
                        File.WriteAllText(saveDialog.FileName, transaction.FullRequest);
                        LogSuccess($"✓ Request saved to: {Path.GetFileName(saveDialog.FileName)}");
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Failed to save request: {ex.Message}");
                }
            }
        }

        private void DeleteHistory_Click(object sender, RoutedEventArgs e)
        {
            if (HistoryGrid.SelectedItem is HttpTransaction transaction)
            {
                RequestHistory.Remove(transaction);
                RequestCount.Text = RequestHistory.Count.ToString();
                LogInfo($"✓ Deleted request #{transaction.Id}");
            }
        }

        private void FilterBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string filter = FilterBox.Text?.ToLower() ?? "";

            if (string.IsNullOrWhiteSpace(filter))
            {
                HistoryGrid.ItemsSource = RequestHistory;
            }
            else
            {
                var filteredList = RequestHistory.Where(t =>
                    (t.Host?.ToLower().Contains(filter) ?? false) ||
                    (t.Method?.ToLower().Contains(filter) ?? false) ||
                    (t.Url?.ToLower().Contains(filter) ?? false) ||
                    (t.Status?.ToLower().Contains(filter) ?? false) ||
                    (t.FullRequest?.ToLower().Contains(filter) ?? false)
                ).ToList();

                HistoryGrid.ItemsSource = filteredList;
            }
        }

        private void ClearHistory_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to clear all request history?",
                "Confirm Clear History",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question
            );

            if (result == MessageBoxResult.Yes)
            {
                RequestHistory.Clear();
                RequestCount.Text = "0";
                RequestEditor.Text = "";
                ResponseViewer.Text = "";
                LogInfo("✓ Request history cleared");
            }
        }

        private void InitializeRepeater()
        {
            _currentRepeaterSessionName = $"Session-{++_repeaterSessionCounter}";
            _repeaterHistory.Clear();
            _repeaterHistoryIndex = -1;

            RepeaterUrl.Text = "https://example.com";
            RepeaterRequest.Text = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: VRAX-Repeater/3.0\r\nAccept: */*\r\n\r\n";
        }

        private void RepeaterSessionManager()
        {
            Dispatcher.Invoke(() =>
            {
                if (!RepeaterSessions.Any(s => s.Name == _currentRepeaterSessionName))
                {
                    RepeaterSessions.Add(new RepeaterSession
                    {
                        Name = _currentRepeaterSessionName,
                        Url = "https://example.com",
                        Request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        Response = "",
                        LastModified = DateTime.Now
                    });
                }
            });
        }

        private void SaveRepeaterSession()
        {
            var session = RepeaterSessions.FirstOrDefault(s => s.Name == _currentRepeaterSessionName);
            if (session != null)
            {
                session.Url = RepeaterUrl.Text;
                session.Request = RepeaterRequest.Text;
                session.Response = RepeaterResponse.Text;
                session.LastModified = DateTime.Now;
                session.StatusCode = GetStatusCodeFromResponse(RepeaterResponse.Text);
                session.StatusText = GetStatusTextFromResponse(RepeaterResponse.Text);

                if (long.TryParse(RepeaterResponseTime.Text?.Replace("ms", ""), out long time))
                {
                    session.ResponseTime = time;
                }
            }
        }

        private int GetStatusCodeFromResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
                return 0;

            var firstLine = response.Split('\n').FirstOrDefault();
            if (firstLine == null)
                return 0;

            var parts = firstLine.Split(' ');
            if (parts.Length >= 2 && int.TryParse(parts[1], out int statusCode))
                return statusCode;

            return 0;
        }

        private string GetStatusTextFromResponse(string response)
        {
            if (string.IsNullOrEmpty(response))
                return "";

            var firstLine = response.Split('\n').FirstOrDefault();
            if (firstLine == null)
                return "";

            var parts = firstLine.Split(' ', 3);
            if (parts.Length >= 3)
                return parts[2].Trim();

            return "";
        }

        private void AddToRepeaterHistory()
        {
            var session = new RepeaterSession
            {
                Name = $"History-{DateTime.Now:HHmmss}",
                Url = RepeaterUrl.Text,
                Request = RepeaterRequest.Text,
                Response = RepeaterResponse.Text,
                ResponseTime = long.TryParse(RepeaterResponseTime.Text?.Replace("ms", ""), out long time) ? time : 0,
                StatusCode = GetStatusCodeFromResponse(RepeaterResponse.Text),
                StatusText = GetStatusTextFromResponse(RepeaterResponse.Text),
                LastModified = DateTime.Now
            };

            _repeaterHistory.Add(session);
            _repeaterHistoryIndex = _repeaterHistory.Count - 1;
        }

        private async void RepeaterSend_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string url = RepeaterUrl.Text?.Trim();
                string requestText = RepeaterRequest.Text?.Trim();

                if (string.IsNullOrWhiteSpace(url))
                {
                    MessageBox.Show("Please enter a target URL", "Missing URL", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(requestText))
                {
                    MessageBox.Show("Please enter a request", "Missing Request", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
                {
                    MessageBox.Show("Invalid URL format. Please enter a complete URL including http:// or https://", "Invalid URL", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                LogInfo($"→ Sending request to {url}...");
                RepeaterStatus.Text = "Sending...";
                RepeaterSendBtn.IsEnabled = false;

                var lines = requestText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
                if (lines.Length == 0)
                {
                    MessageBox.Show("Invalid request format", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    RepeaterSendBtn.IsEnabled = true;
                    return;
                }

                var requestLineParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (requestLineParts.Length < 2)
                {
                    MessageBox.Show("Invalid request line format", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    RepeaterSendBtn.IsEnabled = true;
                    return;
                }

                string method = requestLineParts[0].ToUpper();
                string path = requestLineParts[1];

                if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    url = path;
                    uri = new Uri(url);
                }

                var request = new HttpRequestMessage(new HttpMethod(method), uri);

                bool inHeaders = true;
                StringBuilder bodyBuilder = new StringBuilder();
                string contentType = null;
                bool hasHostHeader = false;

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
                            {
                                hasHostHeader = true;
                                request.Headers.Host = headerValue;
                            }
                            else if (headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                            {
                                contentType = headerValue;
                            }
                            else if (!IsRestrictedHeader(headerName))
                            {
                                try
                                {
                                    request.Headers.TryAddWithoutValidation(headerName, headerValue);
                                }
                                catch (Exception headerEx)
                                {
                                    LogWarning($"Failed to add header '{headerName}': {headerEx.Message}");
                                }
                            }
                        }
                    }
                    else
                    {
                        bodyBuilder.AppendLine(lines[i]);
                    }
                }

                if (!hasHostHeader)
                {
                    request.Headers.Host = uri.Host;
                }

                string body = bodyBuilder.ToString().Trim();
                if (!string.IsNullOrEmpty(body))
                {
                    if (contentType != null)
                    {
                        request.Content = new StringContent(body, Encoding.UTF8, contentType.Split(';')[0]);
                    }
                    else
                    {
                        request.Content = new StringContent(body, Encoding.UTF8);
                    }
                }

                var stopwatch = Stopwatch.StartNew();

                try
                {
                    using (var response = await _repeaterHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead))
                    {
                        stopwatch.Stop();

                        var responseBuilder = new StringBuilder();
                        responseBuilder.AppendLine($"HTTP/{response.Version} {(int)response.StatusCode} {response.ReasonPhrase}");

                        foreach (var header in response.Headers)
                        {
                            foreach (var value in header.Value)
                            {
                                responseBuilder.AppendLine($"{header.Key}: {value}");
                            }
                        }

                        if (response.Content != null)
                        {
                            foreach (var header in response.Content.Headers)
                            {
                                foreach (var value in header.Value)
                                {
                                    responseBuilder.AppendLine($"{header.Key}: {value}");
                                }
                            }

                            responseBuilder.AppendLine();

                            string responseBody = await response.Content.ReadAsStringAsync();
                            responseBuilder.Append(responseBody);
                        }

                        RepeaterResponse.Text = responseBuilder.ToString();
                        RepeaterResponseTime.Text = $"{stopwatch.ElapsedMilliseconds}ms";

                        SaveRepeaterSession();
                        AddToRepeaterHistory();

                        LogSuccess($"✓ Response: {(int)response.StatusCode} {response.ReasonPhrase} ({stopwatch.ElapsedMilliseconds}ms)");
                        RepeaterStatus.Text = "Ready";
                    }
                }
                catch (TaskCanceledException)
                {
                    RepeaterResponse.Text = "ERROR: Request timed out after 90 seconds";
                    RepeaterResponseTime.Text = "TIMEOUT";
                    LogError("Repeater request timed out");
                    RepeaterStatus.Text = "Timeout";
                }
                catch (HttpRequestException httpEx)
                {
                    RepeaterResponse.Text = $"HTTP ERROR:\n\n{httpEx.Message}";
                    if (httpEx.InnerException != null)
                    {
                        RepeaterResponse.Text += $"\n\nInner Exception: {httpEx.InnerException.Message}";
                    }
                    RepeaterResponseTime.Text = "ERROR";
                    LogError($"Repeater HTTP error: {httpEx.Message}");
                    RepeaterStatus.Text = "Error";
                }
                catch (Exception ex)
                {
                    RepeaterResponse.Text = $"ERROR:\n\n{ex.Message}";
                    RepeaterResponseTime.Text = "ERROR";
                    LogError($"Repeater error: {ex.Message}");
                    RepeaterStatus.Text = "Error";
                }
            }
            catch (Exception ex)
            {
                RepeaterResponse.Text = $"FATAL ERROR:\n\n{ex.Message}\n\n{ex.StackTrace}";
                RepeaterResponseTime.Text = "ERROR";
                LogError($"Repeater fatal error: {ex.Message}");
                RepeaterStatus.Text = "Error";
            }
            finally
            {
                RepeaterSendBtn.IsEnabled = true;
            }
        }

        private void StartAttack_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string template = IntruderTemplate.Text?.Trim();
                string payloadsText = IntruderPayloads.Text?.Trim();

                if (string.IsNullOrWhiteSpace(template))
                {
                    MessageBox.Show("Please provide a request template", "Missing Template",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrWhiteSpace(payloadsText))
                {
                    MessageBox.Show("Please provide payloads", "Missing Payloads",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var payloads = payloadsText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList();

                if (payloads.Count == 0)
                {
                    MessageBox.Show("No valid payloads found", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var markerRegex = new Regex(@"§([^§]*)§");
                var matches = markerRegex.Matches(template);

                if (matches.Count == 0)
                {
                    MessageBox.Show("No payload markers (§) found in template", "Warning",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                string targetUrl = RepeaterUrl.Text?.Trim();

                if (string.IsNullOrEmpty(targetUrl))
                {
                    var lines = template.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    if (lines.Length > 0)
                    {
                        var requestLineParts = lines[0].Split(' ');
                        if (requestLineParts.Length > 1)
                        {
                            string pathOrUrl = requestLineParts[1].Trim();

                            if (pathOrUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                pathOrUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                            {
                                targetUrl = pathOrUrl;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(targetUrl))
                {
                    var inputDialog = new InputDialogWindow(
                        "Target URL Required",
                        "Please enter the target URL for the attack:",
                        "https://example.com"
                    );

                    if (inputDialog.ShowDialog() == true)
                    {
                        targetUrl = inputDialog.Answer;
                    }
                    else
                    {
                        return;
                    }
                }

                var config = new IntruderAttackConfig
                {
                    AttackType = (AttackTypeCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Sniper",
                    Template = template,
                    Payloads = payloads.ToArray(),
                    TargetUrl = targetUrl,
                    Threads = 5,
                    Delay = 100,
                    FollowRedirects = false,
                    Headers = new Dictionary<string, string>(),
                    AutoStart = true,
                    MaxRetries = 2,
                    Timeout = 30000,
                    UseCookies = true,
                    CookieJar = ""
                };

                LaunchIntruderAttack(config);
            }
            catch (UriFormatException ex)
            {
                MessageBox.Show($"Invalid URL format: {ex.Message}\n\nPlease check your target URL.",
                    "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                LogError($"Failed to start attack: {ex.Message}");
                MessageBox.Show($"Error preparing attack:\n{ex.Message}",
                    "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LaunchIntruderAttack(IntruderAttackConfig config)
        {
            _intruderAttackCts = new CancellationTokenSource();
            _isAttackRunning = true;
            _intruderResults.Clear();
            IntruderResults.Text = "";

            Dispatcher.Invoke(() =>
            {
                StopAttackBtn.IsEnabled = true;
                StartAttackBtn.IsEnabled = false;
                AttackProgress.Value = 0;
                AttackProgressText.Text = "0/0";
            });

            LogSuccess($"⚔ Intruder attack launched: {config.Payloads.Length} payloads against {config.TargetUrl}");

            _ = Task.Run(async () =>
            {
                try
                {
                    int completed = 0;
                    object lockObj = new object();
                    var tasks = new List<Task>();

                    for (int i = 0; i < config.Payloads.Length; i += config.Threads)
                    {
                        var batch = config.Payloads.Skip(i).Take(config.Threads).ToArray();

                        foreach (var payload in batch)
                        {
                            if (_intruderAttackCts.Token.IsCancellationRequested)
                                break;

                            var task = Task.Run(async () =>
                            {
                                try
                                {
                                    var result = await ExecuteIntruderRequest(config, payload, completed + 1);

                                    lock (lockObj)
                                    {
                                        _intruderResults.Add(result);
                                        completed++;

                                        Dispatcher.Invoke(() =>
                                        {
                                            AttackProgress.Value = (double)completed / config.Payloads.Length * 100;
                                            AttackProgressText.Text = $"{completed}/{config.Payloads.Length}";

                                            StringBuilder resultsText = new StringBuilder();
                                            var recentResults = _intruderResults.OrderByDescending(r => r.RequestId).Take(50).OrderBy(r => r.RequestId);

                                            foreach (var res in recentResults)
                                            {
                                                string statusColor = res.StatusCode >= 200 && res.StatusCode < 300 ? "✓" :
                                                                    res.StatusCode >= 400 && res.StatusCode < 500 ? "⚠" :
                                                                    res.StatusCode >= 500 ? "✗" : "→";

                                                resultsText.AppendLine($"[{res.RequestId:0000}] {statusColor} {res.StatusCode} | {res.ResponseTime}ms | {res.ResponseLength} | {res.Payload}");
                                                if (!string.IsNullOrEmpty(res.Error))
                                                {
                                                    resultsText.AppendLine($"     ERROR: {res.Error}");
                                                }
                                            }
                                            IntruderResults.Text = resultsText.ToString();
                                        });
                                    }

                                    if (config.Delay > 0)
                                    {
                                        await Task.Delay(config.Delay, _intruderAttackCts.Token);
                                    }
                                }
                                catch (OperationCanceledException)
                                {
                                }
                                catch (Exception ex)
                                {
                                    lock (lockObj)
                                    {
                                        completed++;
                                    }
                                    LogError($"Attack task error: {ex.Message}");
                                }
                            });

                            tasks.Add(task);
                        }

                        await Task.WhenAll(tasks);
                        tasks.Clear();
                    }
                }
                catch (OperationCanceledException)
                {
                    LogInfo("Attack cancelled by user");
                }
                catch (Exception ex)
                {
                    LogError($"Attack error: {ex.Message}");
                }
                finally
                {
                    Dispatcher.Invoke(() =>
                    {
                        StopAttackBtn.IsEnabled = false;
                        StartAttackBtn.IsEnabled = true;
                        _isAttackRunning = false;

                        LogSuccess($"Attack completed: {_intruderResults.Count(r => r.Success)} successful, {_intruderResults.Count(r => !r.Success)} failed");
                    });
                }
            });
        }

        private async Task<IntruderResult> ExecuteIntruderRequest(IntruderAttackConfig config, string payload, int requestId)
        {
            var result = new IntruderResult
            {
                RequestId = requestId,
                Payload = payload,
                Success = false
            };

            try
            {
                var stopwatch = Stopwatch.StartNew();

                string requestText = config.Template;
                var markerRegex = new Regex(@"§([^§]*)§");
                requestText = markerRegex.Replace(requestText, payload);

                var lines = requestText.Split(new[] { "\r\n" }, StringSplitOptions.None);
                if (lines.Length == 0)
                {
                    result.Error = "Invalid request format";
                    return result;
                }

                var requestLineParts = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (requestLineParts.Length < 2)
                {
                    result.Error = "Invalid request line";
                    return result;
                }

                string method = requestLineParts[0].ToUpper();
                string path = requestLineParts[1];

                Uri targetUri;
                if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    targetUri = new Uri(path);
                }
                else
                {
                    targetUri = new Uri(config.TargetUrl);
                }

                var request = new HttpRequestMessage(new HttpMethod(method), targetUri);

                bool inHeaders = true;
                StringBuilder bodyBuilder = new StringBuilder();
                string contentType = null;

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
                            {
                                request.Headers.Host = headerValue;
                            }
                            else if (headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                            {
                                contentType = headerValue;
                            }
                            else if (!IsRestrictedHeader(headerName))
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
                    if (contentType != null)
                    {
                        request.Content = new StringContent(body, Encoding.UTF8, contentType.Split(';')[0]);
                    }
                    else
                    {
                        request.Content = new StringContent(body, Encoding.UTF8);
                    }
                }

                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(_intruderAttackCts.Token))
                {
                    cts.CancelAfter(config.Timeout);

                    using (var response = await _httpClient.SendAsync(request, cts.Token))
                    {
                        stopwatch.Stop();

                        result.StatusCode = (int)response.StatusCode;
                        result.ResponseTime = stopwatch.ElapsedMilliseconds;
                        result.Success = true;

                        foreach (var header in response.Headers)
                        {
                            result.Headers[header.Key] = string.Join(", ", header.Value);
                        }

                        if (response.Content != null)
                        {
                            var responseBody = await response.Content.ReadAsStringAsync();
                            result.ResponseLength = $"{responseBody.Length} chars";
                            result.ResponsePreview = responseBody.Length > 100 ? responseBody.Substring(0, 100) + "..." : responseBody;
                        }
                    }
                }
            }
            catch (TaskCanceledException)
            {
                result.Error = "Timeout";
            }
            catch (HttpRequestException httpEx)
            {
                result.Error = $"HTTP Error: {httpEx.Message}";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }

            return result;
        }

        private void StopAttack_Click(object sender, RoutedEventArgs e)
        {
            _intruderAttackCts?.Cancel();
            Dispatcher.Invoke(() =>
            {
                StopAttackBtn.IsEnabled = false;
                StartAttackBtn.IsEnabled = true;
            });
            LogInfo("Intruder attack stopped");
        }

        private void ClearMarkers_Click(object sender, RoutedEventArgs e)
        {
            IntruderTemplate.Text = IntruderTemplate.Text?.Replace("§", "");
            LogInfo("Payload markers cleared");
        }

        private void LoadPayloads_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|Wordlists (*.lst)|*.lst|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                Title = "Load Payload Wordlist"
            };

            if (openDialog.ShowDialog() == true)
            {
                try
                {
                    string[] payloads = File.ReadAllLines(openDialog.FileName);
                    payloads = payloads.Where(p => !string.IsNullOrWhiteSpace(p) && !p.StartsWith("#")).ToArray();

                    IntruderPayloads.Text = string.Join("\n", payloads);
                    PayloadCount.Text = $"{payloads.Length} payloads";
                    LogSuccess($"Loaded {payloads.Length} payloads from {Path.GetFileName(openDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to load payloads: {ex.Message}");
                }
            }
        }

        private void Base64Decode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                if (input.Contains(" "))
                {
                    input = input.Replace(" ", "");
                }

                if (input.Length % 4 != 0)
                {
                    input = input.PadRight(input.Length + (4 - input.Length % 4), '=');
                }

                byte[] bytes = Convert.FromBase64String(input);
                DecoderOutput.Text = Encoding.UTF8.GetString(bytes);
                LogSuccess("Base64 decoded successfully");
            }
            catch (FormatException)
            {
                try
                {
                    byte[] bytes = Convert.FromBase64String(DecoderInput.Text);
                    DecoderOutput.Text = BitConverter.ToString(bytes).Replace("-", " ");
                    LogSuccess("Base64 decoded to hex");
                }
                catch (Exception ex)
                {
                    LogError($"Base64 decode error: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Base64 decode error: {ex.Message}");
            }
        }

        private void Base64Encode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                DecoderOutput.Text = Convert.ToBase64String(bytes);
                LogSuccess("Base64 encoded successfully");
            }
            catch (Exception ex)
            {
                LogError($"Base64 encode error: {ex.Message}");
            }
        }

        private void UrlDecode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                DecoderOutput.Text = Uri.UnescapeDataString(input);
                LogSuccess("URL decoded successfully");
            }
            catch (Exception ex)
            {
                LogError($"URL decode error: {ex.Message}");
            }
        }

        private void UrlEncode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                DecoderOutput.Text = Uri.EscapeDataString(input);
                LogSuccess("URL encoded successfully");
            }
            catch (Exception ex)
            {
                LogError($"URL encode error: {ex.Message}");
            }
        }

        private void HtmlDecode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                DecoderOutput.Text = WebUtility.HtmlDecode(input);
                LogSuccess("HTML decoded successfully");
            }
            catch (Exception ex)
            {
                LogError($"HTML decode error: {ex.Message}");
            }
        }

        private void HtmlEncode_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = DecoderInput.Text;
                DecoderOutput.Text = WebUtility.HtmlEncode(input);
                LogSuccess("HTML encoded successfully");
            }
            catch (Exception ex)
            {
                LogError($"HTML encode error: {ex.Message}");
            }
        }

        private void SwapDecoderText_Click(object sender, RoutedEventArgs e)
        {
            string temp = DecoderInput.Text;
            DecoderInput.Text = DecoderOutput.Text;
            DecoderOutput.Text = temp;
            LogInfo("Swapped decoder input/output");
        }

        private void LoadCompare1_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|HTTP Files (*.http)|*.http|All Files (*.*)|*.*"
            };

            if (openDialog.ShowDialog() == true)
            {
                try
                {
                    CompareText1.Text = File.ReadAllText(openDialog.FileName);
                    LogInfo($"Loaded first file: {Path.GetFileName(openDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to load file: {ex.Message}");
                }
            }
        }

        private void LoadCompare2_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|HTTP Files (*.http)|*.http|All Files (*.*)|*.*"
            };

            if (openDialog.ShowDialog() == true)
            {
                try
                {
                    CompareText2.Text = File.ReadAllText(openDialog.FileName);
                    LogInfo($"Loaded second file: {Path.GetFileName(openDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to load file: {ex.Message}");
                }
            }
        }

        private void CompareTexts_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string text1 = CompareText1.Text;
                string text2 = CompareText2.Text;

                if (string.IsNullOrEmpty(text1) || string.IsNullOrEmpty(text2))
                {
                    MessageBox.Show("Please load text into both boxes", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (text1 == text2)
                {
                    MessageBox.Show("Texts are identical!", "Comparison Result", MessageBoxButton.OK, MessageBoxImage.Information);
                    LogInfo("Text comparison: IDENTICAL");
                }
                else
                {
                    int differences = CountDifferences(text1, text2);
                    double similarity = (1.0 - (double)differences / Math.Max(text1.Length, text2.Length)) * 100;

                    MessageBox.Show($"Texts differ by {differences} characters.\nSimilarity: {similarity:F2}%", "Comparison Result", MessageBoxButton.OK, MessageBoxImage.Information);
                    LogInfo($"Text comparison: DIFFERENT ({differences} differences, {similarity:F2}% similar)");
                }
            }
            catch (Exception ex)
            {
                LogError($"Comparison error: {ex.Message}");
            }
        }

        private int CountDifferences(string text1, string text2)
        {
            int minLength = Math.Min(text1.Length, text2.Length);
            int differences = Math.Abs(text1.Length - text2.Length);

            for (int i = 0; i < minLength; i++)
            {
                if (text1[i] != text2[i])
                    differences++;
            }

            return differences;
        }

        private T FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T result)
                    return result;

                var descendant = FindVisualChild<T>(child);
                if (descendant != null)
                    return descendant;
            }
            return null;
        }

        private string SanitizeFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return "unknown";

            char[] invalidChars = Path.GetInvalidFileNameChars();
            foreach (char c in invalidChars)
            {
                fileName = fileName.Replace(c.ToString(), "_");
            }
            return fileName.Length > 50 ? fileName.Substring(0, 50) : fileName;
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

            return $"{size:0.##} {suffixes[suffixIndex]}";
        }

        private void LogInfo(string message)
        {
            Debug.WriteLine($"[INFO] {DateTime.Now:HH:mm:ss} {message}");
            UpdateStatusMessage(message);
        }

        private void LogSuccess(string message)
        {
            Debug.WriteLine($"[SUCCESS] {DateTime.Now:HH:mm:ss} {message}");
            UpdateStatusMessage($"✓ {message}");
        }

        private void LogWarning(string message)
        {
            Debug.WriteLine($"[WARNING] {DateTime.Now:HH:mm:ss} {message}");
            UpdateStatusMessage($"⚠ {message}");
        }

        private void LogError(string message)
        {
            Debug.WriteLine($"[ERROR] {DateTime.Now:HH:mm:ss} {message}");
            UpdateStatusMessage($"✗ {message}");
        }

        private void LogDebug(string message)
        {
            Debug.WriteLine($"[DEBUG] {DateTime.Now:HH:mm:ss} {message}");
        }

        private void LogRequest(string message)
        {
            Debug.WriteLine($"[REQUEST] {DateTime.Now:HH:mm:ss} {message}");
        }

        private void UpdateStatusMessage(string message)
        {
            Dispatcher.InvokeAsync(() =>
            {
                StatusMessage.Text = message.Length > 100 ? message.Substring(0, 100) + "..." : message;
            });
        }

        private void CopyRequest_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(RequestEditor.Text))
            {
                try
                {
                    Clipboard.SetText(RequestEditor.Text);
                    LogSuccess("Request copied to clipboard");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy request: {ex.Message}");
                }
            }
        }

        private void LoadRequest_Click(object sender, RoutedEventArgs e)
        {
            var openDialog = new OpenFileDialog
            {
                Filter = "HTTP Files (*.http;*.txt)|*.http;*.txt|All Files (*.*)|*.*",
                Title = "Load HTTP Request"
            };

            if (openDialog.ShowDialog() == true)
            {
                try
                {
                    RequestEditor.Text = File.ReadAllText(openDialog.FileName);
                    LogSuccess($"Request loaded from {Path.GetFileName(openDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to load request: {ex.Message}");
                }
            }
        }

        private void SaveCurrentRequest_Click(object sender, RoutedEventArgs e)
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = "HTTP Request (*.http)|*.http|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"request_{DateTime.Now:yyyyMMddHHmmss}.http",
                Title = "Save HTTP Request"
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(saveDialog.FileName, RequestEditor.Text);
                    LogSuccess($"Request saved to {Path.GetFileName(saveDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to save request: {ex.Message}");
                }
            }
        }

        private void CopyResponse_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(ResponseViewer.Text))
            {
                try
                {
                    Clipboard.SetText(ResponseViewer.Text);
                    LogSuccess("Response copied to clipboard");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to copy response: {ex.Message}");
                }
            }
        }

        private void SaveResponse_Click(object sender, RoutedEventArgs e)
        {
            var saveDialog = new SaveFileDialog
            {
                Filter = "HTTP Response (*.http)|*.http|Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"response_{DateTime.Now:yyyyMMddHHmmss}.http",
                Title = "Save HTTP Response"
            };

            if (saveDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(saveDialog.FileName, ResponseViewer.Text);
                    LogSuccess($"Response saved to {Path.GetFileName(saveDialog.FileName)}");
                }
                catch (Exception ex)
                {
                    LogError($"Failed to save response: {ex.Message}");
                }
            }
        }

        private void BeautifyResponse_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string response = ResponseViewer.Text;

                if (string.IsNullOrWhiteSpace(response))
                {
                    MessageBox.Show("No response to beautify", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
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
                        ResponseViewer.Text = beforeJson + beautified;
                        LogSuccess("JSON beautified successfully");
                        return;
                    }
                    catch (JsonException)
                    {
                    }
                }

                if (response.Contains("<html") || response.Contains("<!DOCTYPE"))
                {
                    response = System.Text.RegularExpressions.Regex.Replace(response, "><", ">\n<");
                    response = System.Text.RegularExpressions.Regex.Replace(response, "/>", "/>\n");
                    response = System.Text.RegularExpressions.Regex.Replace(response, "</", "\n</");

                    ResponseViewer.Text = response;
                    LogSuccess("HTML formatted");
                    return;
                }

                if (response.Contains("\"") && response.Contains(":"))
                {
                    try
                    {
                        response = System.Text.RegularExpressions.Regex.Replace(response, "\"([^\"]*)\":", "\"$1\": ");
                        ResponseViewer.Text = response;
                        LogSuccess("Simple JSON formatting applied");
                        return;
                    }
                    catch { }
                }

                MessageBox.Show("No JSON or HTML found to beautify", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                LogError($"Beautify error: {ex.Message}");
            }
        }

        private void Settings_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new SettingsWindow(_settings, this);
            settingsWindow.Owner = this;
            settingsWindow.ShowDialog();

            if (settingsWindow.DialogResult == true)
            {
                ApplySettings(settingsWindow.Settings);
                SaveSettings();
            }
        }

        private void ApplySettings(ProxySettings settings)
        {
            _settings = settings;
            _sslInterceptionEnabled = settings.EnableSSLInterception;

            _httpClient.Timeout = TimeSpan.FromSeconds(settings.TimeoutSeconds);
            _repeaterHttpClient.Timeout = TimeSpan.FromSeconds(settings.TimeoutSeconds * 2);

            LogInfo("Settings applied");
        }

        private void LoadSettings()
        {
            try
            {
                string settingsPath = Path.Combine(_certificatesPath, "vrax_settings.json");
                if (File.Exists(settingsPath))
                {
                    string json = File.ReadAllText(settingsPath);
                    _settings = JsonConvert.DeserializeObject<ProxySettings>(json) ?? new ProxySettings();
                    ApplySettings(_settings);

                    Dispatcher.Invoke(() =>
                    {
                        if (!string.IsNullOrEmpty(_settings.EnableSSLInterception.ToString()))
                            _sslInterceptionEnabled = _settings.EnableSSLInterception;
                    });

                    LogInfo("Settings loaded from file");
                }
            }
            catch (Exception ex)
            {
                LogError($"Failed to load settings: {ex.Message}");
            }
        }

        private void SaveSettings()
        {
            try
            {
                string settingsPath = Path.Combine(_certificatesPath, "vrax_settings.json");
                string json = JsonConvert.SerializeObject(_settings, Formatting.Indented);
                File.WriteAllText(settingsPath, json);
                LogInfo("Settings saved to file");
            }
            catch (Exception ex)
            {
                LogError($"Failed to save settings: {ex.Message}");
            }
        }

        private void ExportCert_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_rootCaCertificate == null)
                {
                    MessageBox.Show("No certificate available. Please generate a certificate first.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var saveDialog = new SaveFileDialog
                {
                    Filter = "Certificate (*.cer)|*.cer|PFX Certificate (*.pfx)|*.pfx|All Files (*.*)|*.*",
                    FileName = "VRAX_Proxy_CA.cer",
                    Title = "Export CA Certificate",
                    InitialDirectory = _certificatesPath
                };

                if (saveDialog.ShowDialog() == true)
                {
                    if (saveDialog.FileName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
                    {
                        byte[] pfxData = _rootCaCertificate.Export(X509ContentType.Pfx, CERT_PASSWORD);
                        File.WriteAllBytes(saveDialog.FileName, pfxData);

                        MessageBox.Show(
                            $"✓ PFX certificate exported successfully!\n\n" +
                            $"Password: {CERT_PASSWORD}\n\n" +
                            $"Save this password to import the certificate elsewhere.",
                            "Export Complete",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information
                        );
                    }
                    else
                    {
                        byte[] certData = _rootCaCertificate.Export(X509ContentType.Cert);
                        File.WriteAllBytes(saveDialog.FileName, certData);

                        MessageBox.Show(
                            "✓ Certificate exported successfully!\n\n" +
                            "You can import this .cer file into browsers or systems as a Trusted Root CA.",
                            "Export Complete",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information
                        );
                    }

                    LogSuccess($"Certificate exported to {Path.GetFileName(saveDialog.FileName)}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LogError($"Certificate export error: {ex.Message}");
            }
        }

        private void InstallCertificate_Click(object sender, RoutedEventArgs e)
        {
            InstallCertificate();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (_isProxyRunning)
            {
                var result = MessageBox.Show(
                    "Proxy is still running. Stop proxy and exit?",
                    "Confirm Exit",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question
                );

                if (result == MessageBoxResult.Yes)
                {
                    StopProxy_Click(null, null);
                }
                else if (result == MessageBoxResult.Cancel)
                {
                    e.Cancel = true;
                    return;
                }
            }

            _uptimeTimer?.Stop();

            _proxyServerCts?.Cancel();
            _interceptProcessorCts?.Cancel();
            _intruderAttackCts?.Cancel();

            try
            {
                _httpClient?.Dispose();
                _repeaterHttpClient?.Dispose();
                _repeaterHandler?.Dispose();
            }
            catch { }

            try
            {
                _proxyServerCts?.Dispose();
                _interceptProcessorCts?.Dispose();
                _intruderAttackCts?.Dispose();
            }
            catch { }

            foreach (var lockObj in _hostLocks.Values)
            {
                try { lockObj.Dispose(); } catch { }
            }

            SaveSettings();

            LogInfo("VRAX Intercept shutting down...");
            base.OnClosing(e);
        }

        public class InputDialogWindow : Window
        {
            public string Answer { get; private set; }

            public InputDialogWindow(string title, string prompt, string defaultValue = "")
            {
                Title = title;
                Width = 500;
                Height = 200;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                Background = new SolidColorBrush(Color.FromRgb(10, 10, 10));
                BorderBrush = new SolidColorBrush(Color.FromRgb(139, 0, 0));
                BorderThickness = new Thickness(2);
                ResizeMode = ResizeMode.NoResize;

                var stackPanel = new StackPanel { Margin = new Thickness(20) };

                var promptText = new TextBlock
                {
                    Text = prompt,
                    Foreground = Brushes.White,
                    Margin = new Thickness(0, 0, 0, 20),
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 12
                };
                stackPanel.Children.Add(promptText);

                var textBox = new TextBox
                {
                    Text = defaultValue,
                    Foreground = Brushes.White,
                    Background = new SolidColorBrush(Color.FromRgb(30, 30, 30)),
                    BorderBrush = new SolidColorBrush(Color.FromRgb(69, 0, 0)),
                    BorderThickness = new Thickness(1),
                    Height = 30,
                    Margin = new Thickness(0, 0, 0, 20),
                    FontSize = 12,
                    Padding = new Thickness(5)
                };
                stackPanel.Children.Add(textBox);

                var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };

                var okButton = new Button
                {
                    Content = "OK",
                    Width = 100,
                    Height = 30,
                    Margin = new Thickness(0, 0, 10, 0),
                    Background = new SolidColorBrush(Color.FromRgb(139, 0, 0)),
                    Foreground = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(69, 0, 0)),
                    FontWeight = FontWeights.Bold,
                    Cursor = Cursors.Hand
                };

                okButton.Click += (s, e) =>
                {
                    Answer = textBox.Text;
                    DialogResult = true;
                    Close();
                };

                var cancelButton = new Button
                {
                    Content = "Cancel",
                    Width = 100,
                    Height = 30,
                    Background = new SolidColorBrush(Color.FromRgb(50, 50, 50)),
                    Foreground = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                    FontWeight = FontWeights.Bold,
                    Cursor = Cursors.Hand
                };

                cancelButton.Click += (s, e) =>
                {
                    DialogResult = false;
                    Close();
                };

                buttonPanel.Children.Add(okButton);
                buttonPanel.Children.Add(cancelButton);
                stackPanel.Children.Add(buttonPanel);

                Content = stackPanel;

                textBox.Focus();
                textBox.SelectAll();
            }
        }

        public class SettingsWindow : Window
        {
            public ProxySettings Settings { get; private set; }

            public SettingsWindow(ProxySettings currentSettings, Window owner)
            {
                Settings = JsonConvert.DeserializeObject<ProxySettings>(JsonConvert.SerializeObject(currentSettings));
                Owner = owner;

                InitializeComponent();
            }

            private void InitializeComponent()
            {
                Title = "VRAX Proxy Settings";
                Width = 600;
                Height = 500;
                WindowStartupLocation = WindowStartupLocation.CenterOwner;
                Background = new SolidColorBrush(Color.FromRgb(10, 10, 10));
                BorderBrush = new SolidColorBrush(Color.FromRgb(139, 0, 0));
                BorderThickness = new Thickness(2);
                ResizeMode = ResizeMode.NoResize;

                var scrollViewer = new ScrollViewer
                {
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
                };

                var stackPanel = new StackPanel { Margin = new Thickness(20) };

                var titleText = new TextBlock
                {
                    Text = "VRAX PROXY SETTINGS",
                    Foreground = new SolidColorBrush(Color.FromRgb(204, 102, 102)),
                    FontSize = 18,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 20),
                    HorizontalAlignment = HorizontalAlignment.Center
                };
                stackPanel.Children.Add(titleText);

                AddSettingCheckbox(stackPanel, "Enable SSL Interception", Settings.EnableSSLInterception,
                    (isChecked) => Settings.EnableSSLInterception = isChecked);

                AddSettingCheckbox(stackPanel, "Trust Self-Signed Certificates", Settings.TrustSelfSignedCerts,
                    (isChecked) => Settings.TrustSelfSignedCerts = isChecked);

                AddSettingCheckbox(stackPanel, "Log All Requests", Settings.LogRequests,
                    (isChecked) => Settings.LogRequests = isChecked);

                AddSettingCheckbox(stackPanel, "Log All Responses", Settings.LogResponses,
                    (isChecked) => Settings.LogResponses = isChecked);

                AddSettingCheckbox(stackPanel, "Auto Start Proxy", Settings.AutoStartProxy,
                    (isChecked) => Settings.AutoStartProxy = isChecked);

                AddSettingCheckbox(stackPanel, "Bypass Localhost", Settings.BypassLocalhost,
                    (isChecked) => Settings.BypassLocalhost = isChecked);

                AddSettingNumeric(stackPanel, "Max Connections", Settings.MaxConnections, 1, 1000,
                    (value) => Settings.MaxConnections = value);

                AddSettingNumeric(stackPanel, "Buffer Size (KB)", Settings.BufferSize / 1024, 1, 64,
                    (value) => Settings.BufferSize = value * 1024);

                AddSettingNumeric(stackPanel, "Timeout (seconds)", Settings.TimeoutSeconds, 1, 300,
                    (value) => Settings.TimeoutSeconds = value);

                var buttonPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    Margin = new Thickness(0, 30, 0, 0)
                };

                var saveButton = new Button
                {
                    Content = "SAVE SETTINGS",
                    Width = 150,
                    Height = 40,
                    Margin = new Thickness(0, 0, 20, 0),
                    Background = new SolidColorBrush(Color.FromRgb(139, 0, 0)),
                    Foreground = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(69, 0, 0)),
                    FontWeight = FontWeights.Bold,
                    Cursor = Cursors.Hand
                };

                saveButton.Click += (s, e) =>
                {
                    DialogResult = true;
                    Close();
                };

                var cancelButton = new Button
                {
                    Content = "CANCEL",
                    Width = 150,
                    Height = 40,
                    Background = new SolidColorBrush(Color.FromRgb(50, 50, 50)),
                    Foreground = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                    FontWeight = FontWeights.Bold,
                    Cursor = Cursors.Hand
                };

                cancelButton.Click += (s, e) =>
                {
                    DialogResult = false;
                    Close();
                };

                buttonPanel.Children.Add(saveButton);
                buttonPanel.Children.Add(cancelButton);
                stackPanel.Children.Add(buttonPanel);

                scrollViewer.Content = stackPanel;
                Content = scrollViewer;
            }

            private void AddSettingCheckbox(StackPanel panel, string label, bool currentValue, Action<bool> setter)
            {
                var grid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300, GridUnitType.Pixel) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200, GridUnitType.Pixel) });

                var labelText = new TextBlock
                {
                    Text = label,
                    Foreground = Brushes.White,
                    VerticalAlignment = VerticalAlignment.Center,
                    FontSize = 12
                };
                Grid.SetColumn(labelText, 0);
                grid.Children.Add(labelText);

                var checkbox = new CheckBox
                {
                    IsChecked = currentValue,
                    VerticalAlignment = VerticalAlignment.Center,
                    HorizontalAlignment = HorizontalAlignment.Left
                };

                checkbox.Checked += (s, e) => setter(true);
                checkbox.Unchecked += (s, e) => setter(false);

                Grid.SetColumn(checkbox, 1);
                grid.Children.Add(checkbox);

                panel.Children.Add(grid);
            }

            private void AddSettingNumeric(StackPanel panel, string label, int currentValue, int min, int max, Action<int> setter)
            {
                var grid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300, GridUnitType.Pixel) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200, GridUnitType.Pixel) });

                var labelText = new TextBlock
                {
                    Text = label,
                    Foreground = Brushes.White,
                    VerticalAlignment = VerticalAlignment.Center,
                    FontSize = 12
                };
                Grid.SetColumn(labelText, 0);
                grid.Children.Add(labelText);

                var textBox = new TextBox
                {
                    Text = currentValue.ToString(),
                    Width = 100,
                    Height = 25,
                    VerticalAlignment = VerticalAlignment.Center,
                    HorizontalAlignment = HorizontalAlignment.Left,
                    Background = new SolidColorBrush(Color.FromRgb(30, 30, 30)),
                    Foreground = Brushes.White,
                    BorderBrush = new SolidColorBrush(Color.FromRgb(69, 0, 0))
                };

                textBox.LostFocus += (s, e) =>
                {
                    if (int.TryParse(textBox.Text, out int value))
                    {
                        value = Math.Max(min, Math.Min(max, value));
                        textBox.Text = value.ToString();
                        setter(value);
                    }
                    else
                    {
                        textBox.Text = currentValue.ToString();
                    }
                };

                Grid.SetColumn(textBox, 1);
                grid.Children.Add(textBox);

                panel.Children.Add(grid);
            }
        }
    }
}