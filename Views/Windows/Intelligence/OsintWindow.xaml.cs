using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Diagnostics;

namespace VRAX
{
    public partial class OsintWindow : Window
    {
        public ObservableCollection<OsintResult> AllResults { get; set; } = new ObservableCollection<OsintResult>();
        public ObservableCollection<OsintResult> CriticalResults { get; set; } = new ObservableCollection<OsintResult>();
        public ObservableCollection<OsintResult> WebResults { get; set; } = new ObservableCollection<OsintResult>();
        public ObservableCollection<OsintResult> IdentityResults { get; set; } = new ObservableCollection<OsintResult>();
        public ObservableCollection<OsintResult> LeakedCredentials { get; set; } = new ObservableCollection<OsintResult>();

        private static readonly HttpClient _httpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        })
        {
            Timeout = TimeSpan.FromSeconds(25)
        };

        private CancellationTokenSource _cts;
        private DateTime _scanStartTime;
        private System.Windows.Threading.DispatcherTimer _timer;
        private string _currentMode = "website";
        private int _completedTasks = 0;
        private int _totalTasks = 0;
        private readonly Random _random = new Random();

        private static readonly string[] USER_AGENTS = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        };

        private static readonly Dictionary<string, CountryInfo> _countryCodes = new()
        {
            ["+1"] = new CountryInfo("United States/Canada", "US", "North America"),
            ["+44"] = new CountryInfo("United Kingdom", "GB", "Europe"),
            ["+964"] = new CountryInfo("Iraq", "IQ", "Middle East"),
            ["+966"] = new CountryInfo("Saudi Arabia", "SA", "Middle East"),
            ["+971"] = new CountryInfo("United Arab Emirates", "AE", "Middle East"),
            ["+20"] = new CountryInfo("Egypt", "EG", "Africa"),
            ["+33"] = new CountryInfo("France", "FR", "Europe"),
            ["+49"] = new CountryInfo("Germany", "DE", "Europe"),
            ["+7"] = new CountryInfo("Russia", "RU", "Europe/Asia"),
            ["+81"] = new CountryInfo("Japan", "JP", "Asia"),
            ["+86"] = new CountryInfo("China", "CN", "Asia"),
            ["+91"] = new CountryInfo("India", "IN", "Asia"),
            ["+92"] = new CountryInfo("Pakistan", "PK", "Asia"),
            ["+61"] = new CountryInfo("Australia", "AU", "Oceania"),
            ["+55"] = new CountryInfo("Brazil", "BR", "South America")
        };

        private static readonly Dictionary<string, string> _usAreaCodes = new()
        {
            ["212"] = "Manhattan, New York City, NY",
            ["310"] = "Los Angeles, CA",
            ["312"] = "Chicago, IL",
            ["415"] = "San Francisco, CA",
            ["202"] = "Washington, D.C.",
            ["305"] = "Miami, FL",
            ["404"] = "Atlanta, GA",
            ["617"] = "Boston, MA",
            ["702"] = "Las Vegas, NV",
            ["214"] = "Dallas, TX",
            ["303"] = "Denver, CO",
            ["206"] = "Seattle, WA",
            ["713"] = "Houston, TX",
            ["602"] = "Phoenix, AZ",
            ["215"] = "Philadelphia, PA"
        };

        private static readonly string[] _commonSubdomains = {
            "www", "mail", "ftp", "admin", "api", "blog", "shop", "store",
            "dev", "test", "staging", "portal", "app", "mobile", "cdn",
            "static", "vpn", "webmail", "smtp", "pop", "imap", "ns1", "ns2"
        };

        private static readonly Dictionary<string, List<string>> _googleDorks = new()
        {
            ["sensitive_files"] = new List<string>
            {
                "filetype:pdf \"confidential\"",
                "filetype:xls \"username\" \"password\"",
                "filetype:sql \"INSERT INTO\" \"password\"",
                "filetype:env DB_PASSWORD",
                "filetype:log \"password\"",
                "filetype:bak",
                "filetype:conf",
                "filetype:config",
                "inurl:wp-config.php",
                "inurl:config.php.bak"
            },
            ["vulnerable_apps"] = new List<string>
            {
                "intitle:\"Welcome to JBoss\"",
                "intitle:\"WebLogic Server Administration Console\"",
                "inurl:8080 intitle:\"Dashboard\"",
                "inurl:phpMyAdmin intitle:phpMyAdmin"
            },
            ["login_panels"] = new List<string>
            {
                "intitle:\"Login\" inurl:admin",
                "intitle:\"Admin Login\"",
                "inurl:/admin/login.php",
                "inurl:/wp-admin",
                "inurl:/administrator"
            },
            ["cameras"] = new List<string>
            {
                "intitle:\"Live View / - AXIS\"",
                "intitle:\"Network Camera\"",
                "intitle:\"Webcam 7\"",
                "inurl:/view/view.shtml"
            },
            ["database_exposure"] = new List<string>
            {
                "ext:sql intext:\"-- phpMyAdmin SQL Dump\"",
                "ext:sql intext:\"INSERT INTO\" -git",
                "ext:sql \"DROP TABLE\""
            },
            ["password_files"] = new List<string>
            {
                "filetype:txt \"password\"",
                "filetype:csv \"username,password\"",
                "filetype:ini \"mysql\"",
                "filetype:log \"Failed password\""
            },
            ["network_devices"] = new List<string>
            {
                "intitle:\"RouterOS router configuration page\"",
                "intitle:\"TP-LINK Wireless Router\"",
                "intitle:\"Cisco Router\""
            },
            ["email_lists"] = new List<string>
            {
                "filetype:xls email OR contact",
                "filetype:csv contact OR email",
                "filetype:txt \"@gmail.com\""
            }
        };

        private static readonly Dictionary<string, string> _socialPlatforms = new()
        {
            ["Facebook"] = "https://facebook.com/{0}",
            ["Instagram"] = "https://instagram.com/{0}",
            ["Twitter/X"] = "https://twitter.com/{0}",
            ["LinkedIn"] = "https://linkedin.com/in/{0}",
            ["GitHub"] = "https://github.com/{0}",
            ["Reddit"] = "https://reddit.com/user/{0}",
            ["TikTok"] = "https://tiktok.com/@{0}",
            ["YouTube"] = "https://youtube.com/@{0}",
            ["Pinterest"] = "https://pinterest.com/{0}",
            ["Snapchat"] = "https://snapchat.com/add/{0}",
            ["Twitch"] = "https://twitch.tv/{0}",
            ["Telegram"] = "https://t.me/{0}",
            ["Tumblr"] = "https://{0}.tumblr.com",
            ["Medium"] = "https://medium.com/@{0}",
            ["DeviantArt"] = "https://deviantart.com/{0}",
            ["SoundCloud"] = "https://soundcloud.com/{0}",
            ["Spotify"] = "https://open.spotify.com/user/{0}",
            ["Steam"] = "https://steamcommunity.com/id/{0}",
            ["Roblox"] = "https://roblox.com/user.aspx?username={0}"
        };

        private static readonly Dictionary<string, string> _datingSites = new()
        {
            ["Tinder"] = "Search on Tinder for {0}",
            ["Bumble"] = "Search on Bumble for {0}",
            ["Hinge"] = "Search on Hinge for {0}",
            ["OkCupid"] = "https://okcupid.com/profile/{0}",
            ["Badoo"] = "https://badoo.com/en/{0}"
        };

        private static readonly Dictionary<string, string> _breachSites = new()
        {
            ["HaveIBeenPwned"] = "https://haveibeenpwned.com/account/{0}",
            ["DeHashed"] = "https://dehashed.com/search?query={0}",
            ["LeakCheck"] = "https://leakcheck.io/search?query={0}",
            ["BreachDirectory"] = "https://breachdirectory.org/?email={0}",
            ["IntelX"] = "https://intelx.io/?s={0}"
        };

        private static readonly Dictionary<string, List<string>> _commonRecoveryQuestions = new()
        {
            ["pet"] = new List<string> { "What is your pet's name?", "What was your first pet's name?" },
            ["school"] = new List<string> { "What elementary school did you attend?", "What high school did you attend?" },
            ["mother"] = new List<string> { "What is your mother's maiden name?" },
            ["birth"] = new List<string> { "What city were you born in?" },
            ["car"] = new List<string> { "What was your first car?" }
        };

        private static readonly List<string> _commonPasswords = new()
        {
            "password", "123456", "12345678", "1234", "qwerty", "12345", "dragon",
            "baseball", "football", "letmein", "monkey", "abc123", "mustang", "michael",
            "shadow", "master", "jennifer", "111111", "jordan", "superman", "harley",
            "fuckme", "hunter", "fuckyou", "trustno1", "ranger", "buster", "thomas",
            "tigger", "robert", "soccer", "fuck", "batman", "test", "pass", "killer",
            "hockey", "george", "charlie", "andrew", "michelle", "love", "sunshine",
            "jessica", "asshole", "pepper", "daniel", "access", "123456789", "654321",
            "joshua", "maggie", "starwars", "silver", "william", "dallas", "yankees",
            "123123", "ashley", "666666", "hello", "amanda", "orange", "biteme", "freedom"
        };

        private static readonly Dictionary<string, string> _publicDataSources = new()
        {
            ["FamilySearch"] = "https://familysearch.org/search/record/results?q.givenName={0}&q.surname={1}",
            ["Ancestry"] = "https://ancestry.com/search/?name={0}_{1}",
            ["MyHeritage"] = "https://myheritage.com/research?qname={0}%20{1}",
            ["Whitepages"] = "https://whitepages.com/name/{0}-{1}",
            ["Spokeo"] = "https://spokeo.com/{0}-{1}",
            ["PeekYou"] = "https://peekyou.com/{0}_{1}",
            ["Pipl"] = "https://pipl.com/search/?q={0}+{1}"
        };

        public OsintWindow()
        {
            InitializeComponent();

            OsintGrid.ItemsSource = AllResults;
            CriticalGrid.ItemsSource = CriticalResults;
            WebGrid.ItemsSource = WebResults;
            IdentityGrid.ItemsSource = IdentityResults;

            ConfigureHttpClient();

            _timer = new System.Windows.Threading.DispatcherTimer();
            _timer.Interval = TimeSpan.FromSeconds(1);
            _timer.Tick += Timer_Tick;

            UpdateUIForMode("website");

            Log("╔═══════════════════════════════════════════════════════════╗", "HEADER");
            Log("║  VRAX OSINT // ELITE CYBERSECURITY RECON v3.0        ║", "HEADER");
            Log("║  Advanced Intelligence Gathering Platform                 ║", "HEADER");
            Log("╚═══════════════════════════════════════════════════════════╝", "HEADER");
            Log("⚡ System initialized. Ready for target acquisition.", "SUCCESS");
        }

        private void ConfigureHttpClient()
        {
            _httpClient.DefaultRequestHeaders.Clear();
            SetRandomUserAgent();
            _httpClient.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
            _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
            _httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
            _httpClient.DefaultRequestHeaders.Add("DNT", "1");
            _httpClient.DefaultRequestHeaders.Add("Connection", "keep-alive");
        }

        private void SetRandomUserAgent()
        {
            _httpClient.DefaultRequestHeaders.Remove("User-Agent");
            _httpClient.DefaultRequestHeaders.Add("User-Agent", USER_AGENTS[_random.Next(USER_AGENTS.Length)]);
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            if (TimeElapsed != null)
            {
                var elapsed = DateTime.Now - _scanStartTime;
                TimeElapsed.Text = elapsed.ToString(@"hh\:mm\:ss");
            }
        }

        private void TargetMode_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            if (TargetMode != null && TargetMode.SelectedItem is System.Windows.Controls.ComboBoxItem selectedItem)
            {
                _currentMode = selectedItem.Content.ToString().ToLower().Contains("website") ? "website" :
                              selectedItem.Content.ToString().ToLower().Contains("person") ? "person" :
                              selectedItem.Content.ToString().ToLower().Contains("email") ? "email" :
                              selectedItem.Content.ToString().ToLower().Contains("phone") ? "phone" :
                              selectedItem.Content.ToString().ToLower().Contains("username") ? "username" : "website";
                UpdateUIForMode(_currentMode);
            }
        }

        private void UpdateUIForMode(string mode)
        {
            if (TargetHint == null || SearchQuery == null) return;

            switch (mode)
            {
                case "website":
                    TargetHint.Text = "Enter domain (e.g., example.com)";
                    SearchQuery.Text = "example.com";
                    break;
                case "person":
                    TargetHint.Text = "Enter full name (e.g., John Smith)";
                    SearchQuery.Text = "John Doe";
                    break;
                case "email":
                    TargetHint.Text = "Enter email address (e.g., user@example.com)";
                    SearchQuery.Text = "test@example.com";
                    break;
                case "phone":
                    TargetHint.Text = "Enter phone number with country code (e.g., +9647712345678)";
                    SearchQuery.Text = "+9647712345678";
                    break;
                case "username":
                    TargetHint.Text = "Enter username (e.g., johndoe123)";
                    SearchQuery.Text = "johndoe";
                    break;
            }
        }

        private async void StartOsint_Click(object sender, RoutedEventArgs e)
        {
            string target = SearchQuery.Text.Trim();
            if (string.IsNullOrWhiteSpace(target))
            {
                MessageBox.Show("Please enter a target!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            ClearAllResults();

            _cts = new CancellationTokenSource();
            _scanStartTime = DateTime.Now;
            _timer.Start();
            BtnStop.IsEnabled = true;
            BtnStop.Content = "ABORT SCAN";

            StatusText.Text = $"Scanning {target}...";

            Log($"╔═══════════════════════════════════════════════════════════╗", "HEADER");
            Log($"║  VRAX OSINT - ADVANCED SCAN INITIATED                 ║", "HEADER");
            Log($"╚═══════════════════════════════════════════════════════════╝", "HEADER");
            Log($"🎯 TARGET: {target}", "INFO");
            Log($"🔧 MODE: {_currentMode.ToUpper()}", "INFO");
            Log($"⏱ STARTED: {_scanStartTime:HH:mm:ss}", "INFO");
            Log($"🔐 OPERATOR: {Environment.UserName}", "INFO");
            Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "SEPARATOR");

            try
            {
                var tasks = GetScanTasks(target);
                _totalTasks = tasks.Count;

                await ExecuteTasksWithProgress(tasks);

                Log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "SEPARATOR");
                Log($"✅ ADVANCED SCAN COMPLETE", "SUCCESS");
                Log($"📊 Total Intelligence Items: {AllResults.Count}", "SUCCESS");
                Log($"🔴 Critical Findings: {CriticalResults.Count}", "SUCCESS");
                Log($"🌐 Web Intelligence: {WebResults.Count}", "SUCCESS");
                Log($"👤 Identity Data: {IdentityResults.Count}", "SUCCESS");
                Log($"🔑 Leaked Credentials: {LeakedCredentials.Count}", "SUCCESS");
                Log($"⏱ Duration: {(DateTime.Now - _scanStartTime).TotalSeconds:F1}s", "SUCCESS");

                StatusText.Text = $"Complete - {AllResults.Count} intelligence items";
                UpdateStatistics();

                if (AllResults.Count > 0)
                {
                    var message = $"VRAX OSINT SCAN COMPLETE\n\n" +
                                  $"• Total Intelligence Items: {AllResults.Count}\n" +
                                  $"• Critical Security Findings: {CriticalResults.Count}\n" +
                                  $"• Web Infrastructure Data: {WebResults.Count}\n" +
                                  $"• Identity Intelligence: {IdentityResults.Count}\n" +
                                  $"• Leaked Credentials Found: {LeakedCredentials.Count}\n" +
                                  $"• Operation Duration: {(DateTime.Now - _scanStartTime).TotalSeconds:F1}s\n\n" +
                                  $"Results ready for analysis.";

                    if (LeakedCredentials.Count > 0)
                    {
                        message += "\n\n⚠ WARNING: Leaked credentials detected!";
                    }

                    MessageBox.Show(message, "VRAX OSINT - SCAN COMPLETE",
                        MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (OperationCanceledException)
            {
                Log($"⏸ SCAN ABORTED BY OPERATOR", "WARNING");
                StatusText.Text = "Scan aborted";
            }
            catch (Exception ex)
            {
                Log($"❌ SCAN FAILED: {ex.Message}", "ERROR");
                StatusText.Text = "Scan failed";
                MessageBox.Show($"Scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                _timer.Stop();
                BtnStop.IsEnabled = false;
                BtnStop.Content = "ABORT SCAN";
            }
        }

        private List<Task> GetScanTasks(string target)
        {
            var tasks = new List<Task>();

            tasks.Add(RunGoogleDorks(target, _currentMode));

            switch (_currentMode)
            {
                case "website":
                    tasks.Add(EnhancedWebsiteScan(target));
                    tasks.Add(CheckWebsiteBreaches(target));
                    tasks.Add(FindSubdomainsAdvanced(target));
                    tasks.Add(CheckWebsiteSecurity(target));
                    tasks.Add(FindTechnologies(target));
                    tasks.Add(CheckSSLDetails(target));
                    tasks.Add(ExtractMetadata(target));
                    break;

                case "person":
                    tasks.Add(EnhancedPersonScan(target));
                    tasks.Add(CheckPersonBreaches(target));
                    tasks.Add(FindSocialMediaForPerson(target));
                    tasks.Add(GenerateRecoveryQuestions(target));
                    tasks.Add(FindPublicRecords(target));
                    tasks.Add(CheckDatingProfiles(target));
                    tasks.Add(FindRelatives(target));
                    tasks.Add(FindCourtRecords(target));
                    tasks.Add(FindPropertyRecords(target));
                    break;

                case "email":
                    tasks.Add(EnhancedEmailScan(target));
                    tasks.Add(CheckEmailBreaches(target));
                    tasks.Add(FindEmailOnSocialMedia(target));
                    tasks.Add(FindAssociatedAccounts(target));
                    tasks.Add(CheckEmailReputationAdvanced(target));
                    tasks.Add(FindPasswordHints(target));
                    tasks.Add(CheckPastebinForEmail(target));
                    tasks.Add(FindEmailHistory(target));
                    tasks.Add(SearchEmailOnline(target));
                    tasks.Add(GenerateRelatedAccounts(target));
                    tasks.Add(GenerateInvestigationLinksForEmail(target));
                    tasks.Add(CheckGravatar(target));
                    tasks.Add(CheckDisposableEmail(target));
                    break;

                case "phone":
                    tasks.Add(EnhancedPhoneScan(target));
                    tasks.Add(CheckPhoneBreaches(target));
                    tasks.Add(FindPhoneOnSocialMedia(target));
                    tasks.Add(FindPhoneOwner(target));
                    tasks.Add(CheckPhoneCarrierDetails(target));
                    tasks.Add(FindPhoneLocation(target));
                    tasks.Add(CheckPhoneReputation(target));
                    tasks.Add(FindAssociatedEmails(target));
                    break;

                case "username":
                    tasks.Add(EnhancedUsernameScan(target));
                    tasks.Add(CheckUsernameBreaches(target));
                    tasks.Add(FindUsernameOnAllPlatforms(target));
                    tasks.Add(FindEmailFromUsername(target));
                    tasks.Add(FindRealNameFromUsername(target));
                    tasks.Add(FindUsernameHistory(target));
                    tasks.Add(CheckUsernameOnPastebin(target));
                    break;
            }

            return tasks;
        }

        private async Task ExecuteTasksWithProgress(List<Task> tasks)
        {
            var taskList = tasks.ToList();

            foreach (var task in taskList)
            {
                if (_cts.Token.IsCancellationRequested)
                    break;

                try
                {
                    await task;
                    _completedTasks++;
                }
                catch (Exception ex)
                {
                    Log($"⚠ Task failed: {ex.Message}", "WARNING");
                }
            }
        }

        private async Task RunGoogleDorks(string target, string mode)
        {
            try
            {
                Log($"🔍 Running Advanced Google Dorks for {target}", "HEADER");

                string dorkTarget = mode switch
                {
                    "website" => $"site:{target}",
                    "person" => $"\"{target}\"",
                    "email" => target,
                    "phone" => target,
                    "username" => $"\"{target}\"",
                    _ => target
                };

                Log("📁 Checking for sensitive files...", "INFO");
                foreach (var dork in _googleDorks["sensitive_files"].Take(5))
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    string searchQuery = $"{dork} {dorkTarget}";
                    string googleUrl = $"https://www.google.com/search?q={Uri.EscapeDataString(searchQuery)}";
                    AddResult("DORK", "Sensitive Files", googleUrl, "INFO");
                    await Task.Delay(100);
                }

                Log("🔐 Searching for login panels...", "INFO");
                foreach (var dork in _googleDorks["login_panels"].Take(5))
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    string searchQuery = $"{dork} {dorkTarget}";
                    string googleUrl = $"https://www.google.com/search?q={Uri.EscapeDataString(searchQuery)}";
                    AddResult("DORK", "Login Panels", googleUrl, "INFO");
                    await Task.Delay(100);
                }

                Log("⚠️ Looking for vulnerable applications...", "INFO");
                foreach (var dork in _googleDorks["vulnerable_apps"].Take(5))
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    string searchQuery = $"{dork} {dorkTarget}";
                    string googleUrl = $"https://www.google.com/search?q={Uri.EscapeDataString(searchQuery)}";
                    AddResult("DORK", "Vulnerable Apps", googleUrl, "WARNING");
                    await Task.Delay(100);
                }

                Log("🔑 Searching for exposed passwords...", "INFO");
                foreach (var dork in _googleDorks["password_files"].Take(5))
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    string searchQuery = $"{dork} {dorkTarget}";
                    string googleUrl = $"https://www.google.com/search?q={Uri.EscapeDataString(searchQuery)}";
                    AddResult("DORK", "Password Exposure", googleUrl, "CRITICAL");
                    await Task.Delay(100);
                }

                Log("✅ Google dorking completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Google dorking failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckWebsiteBreaches(string domain)
        {
            try
            {
                Log($"🔑 Checking {domain} for known breaches...", "HEADER");

                string hibpUrl = $"https://haveibeenpwned.com/domain/{domain}";
                AddResult("BREACH", "Domain Check", hibpUrl, "INFO");

                string ffMonitor = $"https://monitor.firefox.com/scan?domain={domain}";
                AddResult("BREACH", "Firefox Monitor", ffMonitor, "INFO");

                var possibleBreaches = new[]
                {
                    "Collection #1", "Collection #2", "Anti Public Combo List",
                    "Exploit.in", "COMB", "We Leak Info DB"
                };

                foreach (var breach in possibleBreaches.Take(3))
                {
                    AddResult("BREACH", "Possible Breach", $"{domain} may appear in {breach}", "WARNING");
                }

                Log("✅ Breach check completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Breach check failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckEmailBreaches(string email)
        {
            try
            {
                Log($"🔑 Checking {email} for known breaches...", "HEADER");

                string hibpUrl = $"https://haveibeenpwned.com/account/{Uri.EscapeDataString(email)}";
                AddResult("BREACH", "HaveIBeenPwned", hibpUrl, "CRITICAL");

                string dehashedUrl = $"https://dehashed.com/search?query={Uri.EscapeDataString(email)}";
                AddResult("BREACH", "DeHashed", dehashedUrl, "CRITICAL");

                string leakCheckUrl = $"https://leakcheck.io/search?query={Uri.EscapeDataString(email)}";
                AddResult("BREACH", "LeakCheck", leakCheckUrl, "CRITICAL");

                string breachDirUrl = $"https://breachdirectory.org/?email={Uri.EscapeDataString(email)}";
                AddResult("BREACH", "BreachDirectory", breachDirUrl, "CRITICAL");

                var commonBreaches = new[]
                {
                    "Adobe", "LinkedIn", "MySpace", "Dropbox", "Tumblr",
                    "Zynga", "Bitly", "Disqus", "Imgur"
                };

                foreach (var breach in commonBreaches.Take(5))
                {
                    AddResult("BREACH", "Possible Breach", $"{email} may be in {breach} breach", "WARNING");
                }

                Log("✅ Email breach check completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Email breach check failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckPhoneBreaches(string phone)
        {
            try
            {
                Log($"🔑 Checking {phone} for known breaches...", "HEADER");

                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var breachUrls = new[]
                {
                    $"https://dehashed.com/search?query={cleanPhone}",
                    $"https://leakcheck.io/search?query={cleanPhone}",
                    $"https://breachdirectory.org/?phone={cleanPhone}"
                };

                foreach (var url in breachUrls)
                {
                    AddResult("BREACH", "Phone Check", url, "CRITICAL");
                }

                Log("✅ Phone breach check completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Phone breach check failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckUsernameBreaches(string username)
        {
            try
            {
                Log($"🔑 Checking {username} for known breaches...", "HEADER");

                var breachUrls = new[]
                {
                    $"https://dehashed.com/search?query={username}",
                    $"https://leakcheck.io/search?query={username}",
                    $"https://breachdirectory.org/?username={username}"
                };

                foreach (var url in breachUrls)
                {
                    AddResult("BREACH", "Username Check", url, "CRITICAL");
                }

                Log("🔐 Generating password guesses for credential stuffing...", "INFO");

                var commonPasswords = new[]
                {
                    username + "123", username + "!", username + "@", username + "123456",
                    username + "password", "password" + username, "Pass@" + username
                };

                foreach (var password in commonPasswords)
                {
                    AddResult("PASSWORD", "Possible Password", password, "WARNING");
                }

                Log("✅ Username breach check completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Username breach check failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckPersonBreaches(string name)
        {
            try
            {
                Log($"🔑 Checking {name} for known breaches...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    var searchQueries = new[]
                    {
                        $"https://dehashed.com/search?query={firstName}+{lastName}",
                        $"https://leakcheck.io/search?query={firstName}+{lastName}",
                        $"https://breachdirectory.org/?name={firstName}+{lastName}"
                    };

                    foreach (var query in searchQueries)
                    {
                        AddResult("BREACH", "Person Check", query, "CRITICAL");
                    }
                }

                Log("✅ Person breach check completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Person breach check failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckPastebinForEmail(string email)
        {
            try
            {
                var searchUrl = $"https://psbdmp.ws/api/search/{Uri.EscapeDataString(email)}";
                AddResult("PASTEBIN", "Search", searchUrl, "INFO");

                var pasteSites = new[]
                {
                    $"https://pastebin.com/search?q={Uri.EscapeDataString(email)}",
                    $"https://paste.ee/search?q={Uri.EscapeDataString(email)}"
                };

                foreach (var site in pasteSites)
                {
                    AddResult("PASTEBIN", "Check", site, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckUsernameOnPastebin(string username)
        {
            try
            {
                var searchUrl = $"https://psbdmp.ws/api/search/{username}";
                AddResult("PASTEBIN", "Username Search", searchUrl, "INFO");
            }
            catch { }
        }

        private async Task FindSocialMediaForPerson(string name)
        {
            try
            {
                Log($"🌐 Searching social media for {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0].ToLower();
                    var lastName = nameParts[^1].ToLower();
                    var fullName = $"{firstName}{lastName}".Replace(" ", "");

                    var usernameVariations = new[]
                    {
                        firstName + lastName,
                        firstName + "." + lastName,
                        firstName + "_" + lastName,
                        firstName + "-" + lastName,
                        fullName + "123",
                        fullName + "_"
                    };

                    foreach (var platform in _socialPlatforms)
                    {
                        foreach (var variation in usernameVariations.Take(3))
                        {
                            var profileUrl = string.Format(platform.Value, variation);
                            AddResult("SOCIAL", platform.Key, profileUrl, "INFO");
                        }
                    }

                    var fbSearch = $"https://www.facebook.com/search/people/?q={firstName}%20{lastName}";
                    AddResult("SOCIAL", "Facebook Search", fbSearch, "INFO");

                    var liSearch = $"https://www.linkedin.com/search/results/people/?keywords={firstName}%20{lastName}";
                    AddResult("SOCIAL", "LinkedIn Search", liSearch, "INFO");
                }
            }
            catch { }
        }

        private async Task FindUsernameOnAllPlatforms(string username)
        {
            try
            {
                Log($"🌐 Checking username {username} across all platforms...", "HEADER");

                foreach (var platform in _socialPlatforms)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    var profileUrl = string.Format(platform.Value, username);
                    AddResult("USERNAME", platform.Key, profileUrl, "INFO");
                    await Task.Delay(50);
                }
            }
            catch { }
        }

        private async Task CheckDatingProfiles(string name)
        {
            try
            {
                Log($"❤️ Checking dating sites for {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    foreach (var site in _datingSites)
                    {
                        var searchUrl = string.Format(site.Value, firstName, lastName);
                        AddResult("DATING", site.Key, searchUrl, "WARNING");
                    }

                    AddResult("DATING", "Tinder", "Check Tinder app manually", "WARNING");
                }
            }
            catch { }
        }

        private async Task FindEmailOnSocialMedia(string email)
        {
            try
            {
                var username = email.Split('@')[0];

                foreach (var platform in _socialPlatforms.Take(10))
                {
                    var profileUrl = string.Format(platform.Value, username);
                    AddResult("SOCIAL", $"Email on {platform.Key}", profileUrl, "INFO");
                }
            }
            catch { }
        }

        private async Task FindPhoneOnSocialMedia(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var phoneSearches = new[]
                {
                    $"https://www.facebook.com/search/people/?q={cleanPhone}",
                    $"https://www.google.com/search?q={cleanPhone}+facebook",
                    $"https://www.google.com/search?q={cleanPhone}+twitter",
                    $"https://www.truecaller.com/search/{cleanPhone}"
                };

                foreach (var search in phoneSearches)
                {
                    AddResult("SOCIAL", "Phone Search", search, "INFO");
                }
            }
            catch { }
        }

        private async Task FindAssociatedAccounts(string email)
        {
            try
            {
                var username = email.Split('@')[0];

                var services = new[]
                {
                    "GitHub", "Twitter", "Instagram", "Reddit", "Medium",
                    "Disqus", "Gravatar", "Keybase", "About.me"
                };

                foreach (var service in services)
                {
                    AddResult("ASSOCIATED", service, $"Check if {username} exists on {service}", "INFO");
                }

                var similarPatterns = new[]
                {
                    username + "@gmail.com",
                    username + "@yahoo.com",
                    username + "@outlook.com"
                };

                foreach (var pattern in similarPatterns.Where(p => p != email))
                {
                    AddResult("ASSOCIATED", "Similar Email", pattern, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateRecoveryQuestions(string name)
        {
            try
            {
                Log($"🔐 Generating possible password recovery answers for {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    var recoveryInfo = new Dictionary<string, string>
                    {
                        ["Mother's Maiden Name"] = $"Try {lastName} or variations",
                        ["First Pet"] = $"Check for common pet names: Max, Bella, Charlie, Luna",
                        ["Birth City"] = $"Search for {name}'s birthplace",
                        ["First School"] = $"Search for elementary schools near {lastName} family",
                        ["First Car"] = $"Common cars: Honda Civic, Toyota Corolla, Ford Focus"
                    };

                    foreach (var item in recoveryInfo)
                    {
                        AddResult("RECOVERY", item.Key, item.Value, "INFO");
                    }
                }

                Log("📝 Common security questions to target:", "INFO");
                foreach (var question in _commonRecoveryQuestions.Values.SelectMany(q => q).Take(5))
                {
                    AddResult("QUESTIONS", "Security Question", question, "INFO");
                }
            }
            catch { }
        }

        private async Task FindPasswordHints(string email)
        {
            try
            {
                var username = email.Split('@')[0];

                var possiblePasswords = new List<string>();

                possiblePasswords.AddRange(_commonPasswords.Take(20));

                possiblePasswords.Add(username);
                possiblePasswords.Add(username + "123");
                possiblePasswords.Add(username + "!");
                possiblePasswords.Add(username + "@");
                possiblePasswords.Add(username + "2023");
                possiblePasswords.Add(username + "2024");
                possiblePasswords.Add(char.ToUpper(username[0]) + username.Substring(1) + "123");

                for (int year = 1990; year <= 2024; year++)
                {
                    if (year % 5 == 0)
                    {
                        possiblePasswords.Add(year.ToString());
                        possiblePasswords.Add("Password" + year);
                        possiblePasswords.Add("Pass" + year + "!");
                    }
                }

                foreach (var password in possiblePasswords.Take(30))
                {
                    AddResult("PASSWORD", "Possible Password", password, "WARNING");
                }

                AddResult("PASSWORD", "Check Leaks", $"https://dehashed.com/search?query={email}", "CRITICAL");
            }
            catch { }
        }

        private async Task CheckPhoneCarrierDetails(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1") && digits.Length == 11)
                {
                    var npa = digits.Substring(1, 3);
                    var nxx = digits.Substring(4, 3);

                    var carrierInfo = new Dictionary<string, string>
                    {
                        ["Verizon"] = $"NXX {nxx} may be Verizon",
                        ["AT&T"] = $"NXX {nxx} may be AT&T",
                        ["T-Mobile"] = $"NXX {nxx} may be T-Mobile",
                        ["Sprint"] = $"NXX {nxx} may be Sprint (now T-Mobile)"
                    };

                    foreach (var carrier in carrierInfo)
                    {
                        AddResult("CARRIER", carrier.Key, carrier.Value, "INFO");
                    }

                    AddResult("CARRIER", "Porting", $"Check if number was ported from another carrier", "INFO");
                }
                else if (digits.StartsWith("964") && digits.Length >= 12)
                {
                    var prefix = digits.Substring(3, 3);
                    var operatorInfo = GetIraqiOperator(prefix);
                    AddResult("CARRIER", "Iraq Operator", operatorInfo, "INFO");
                }
            }
            catch { }
        }

        private async Task FindPhoneLocation(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1") && digits.Length == 11)
                {
                    var areaCode = digits.Substring(1, 3);
                    if (_usAreaCodes.TryGetValue(areaCode, out var location))
                    {
                        AddResult("LOCATION", "Area", location, "INFO");
                    }

                    AddResult("LOCATION", "Cell Tower", $"Check OpenCellID for nearest towers", "INFO");
                }
                else if (digits.StartsWith("964"))
                {
                    AddResult("LOCATION", "Country", "Iraq", "INFO");

                    var governorates = new[] { "Baghdad", "Basra", "Mosul", "Erbil", "Sulaymaniyah", "Kirkuk" };
                    AddResult("LOCATION", "Possible Governorates", string.Join(", ", governorates), "INFO");
                }
            }
            catch { }
        }

        private async Task FindPhoneOwner(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var lookupServices = new[]
                {
                    $"https://www.truecaller.com/search/{cleanPhone}",
                    $"https://www.spydialer.com/default.aspx?phone={cleanPhone}",
                    $"https://www.whitepages.com/phone/{cleanPhone}",
                    $"https://www.zabasearch.com/phone/{cleanPhone}"
                };

                foreach (var service in lookupServices)
                {
                    AddResult("OWNER", "Phone Lookup", service, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckPhoneReputation(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var reputationChecks = new[]
                {
                    $"https://800notes.com/Phone.aspx/{cleanPhone}",
                    $"https://www.whocallsme.com/Phone-Number/{cleanPhone}",
                    $"https://www.shouldianswer.com/phone/{cleanPhone}"
                };

                foreach (var check in reputationChecks)
                {
                    AddResult("REPUTATION", "Phone Reputation", check, "INFO");
                }
            }
            catch { }
        }

        private async Task FindAssociatedEmails(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var searchQueries = new[]
                {
                    $"https://www.google.com/search?q={cleanPhone}+email",
                    $"https://www.google.com/search?q=\"{cleanPhone}\"+AND+email"
                };

                foreach (var query in searchQueries)
                {
                    AddResult("ASSOCIATED", "Email Search", query, "INFO");
                }
            }
            catch { }
        }

        private async Task FindPublicRecords(string name)
        {
            try
            {
                Log($"📋 Searching public records for {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    foreach (var source in _publicDataSources)
                    {
                        var searchUrl = string.Format(source.Value, firstName, lastName);
                        AddResult("RECORDS", source.Key, searchUrl, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task FindRelatives(string name)
        {
            try
            {
                Log($"👨‍👩‍👧 Searching for relatives of {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    var relativeSearches = new[]
                    {
                        $"https://www.familysearch.org/search/record/results?q.givenName={firstName}&q.surname={lastName}",
                        $"https://www.ancestry.com/search/?name={firstName}_{lastName}",
                        $"https://www.myheritage.com/research?qname={firstName}+{lastName}"
                    };

                    foreach (var search in relativeSearches)
                    {
                        AddResult("RELATIVES", "Family Search", search, "INFO");
                    }

                    var potentialRelatives = new[]
                    {
                        $"Spouse of {firstName} {lastName}",
                        $"Children of {firstName} {lastName}",
                        $"Parents of {firstName} {lastName}",
                        $"Siblings of {firstName} {lastName}"
                    };

                    foreach (var relative in potentialRelatives)
                    {
                        AddResult("RELATIVES", "Look for", relative, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task FindCourtRecords(string name)
        {
            try
            {
                Log($"⚖️ Checking court records for {name}...", "HEADER");

                var encodedName = Uri.EscapeDataString(name);

                var courtSearches = new[]
                {
                    $"https://www.courtlistener.com/search/?q={encodedName}",
                    $"https://www.justia.com/search?q={encodedName}",
                    $"https://pacer.uscourts.gov/search?q={encodedName}",
                    $"https://www.google.com/search?q={encodedName}+court+case"
                };

                foreach (var search in courtSearches)
                {
                    AddResult("COURT", "Records", search, "WARNING");
                }
            }
            catch { }
        }

        private async Task FindPropertyRecords(string name)
        {
            try
            {
                Log($"🏠 Checking property records for {name}...", "HEADER");

                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    var propertySearches = new[]
                    {
                        $"https://www.zillow.com/search/query/?q={firstName}+{lastName}",
                        $"https://www.realtor.com/search?q={firstName}+{lastName}",
                        $"https://www.redfin.com/search?q={firstName}+{lastName}",
                        $"https://www.google.com/search?q={firstName}+{lastName}+property+records"
                    };

                    foreach (var search in propertySearches)
                    {
                        AddResult("PROPERTY", "Records", search, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task FindEmailFromUsername(string username)
        {
            try
            {
                var possibleEmails = new[]
                {
                    $"{username}@gmail.com",
                    $"{username}@yahoo.com",
                    $"{username}@outlook.com",
                    $"{username}@hotmail.com",
                    $"{username}@protonmail.com",
                    $"{username}@icloud.com"
                };

                foreach (var email in possibleEmails)
                {
                    AddResult("EMAIL", "Possible", email, "INFO");
                }
            }
            catch { }
        }

        private async Task FindRealNameFromUsername(string username)
        {
            try
            {
                var namePatterns = new[]
                {
                    @"^([a-z]+)([0-9]+)$",
                    @"^([a-z]+)[._-]?([a-z]+)[0-9]*$",
                    @"^([a-z])[._-]?([a-z]+)[0-9]*$"
                };

                foreach (var pattern in namePatterns)
                {
                    var match = Regex.Match(username, pattern, RegexOptions.IgnoreCase);
                    if (match.Success && match.Groups.Count >= 2)
                    {
                        for (int i = 1; i < match.Groups.Count; i++)
                        {
                            if (!string.IsNullOrEmpty(match.Groups[i].Value) && match.Groups[i].Value.Length > 2)
                            {
                                AddResult("REALNAME", "Possible Name Part", match.Groups[i].Value, "INFO");
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private async Task FindUsernameHistory(string username)
        {
            try
            {
                var archiveSearches = new[]
                {
                    $"https://web.archive.org/web/*/{username}",
                    $"https://archive.is/*/{username}",
                    $"https://www.google.com/search?q={username}+site:archive.org"
                };

                foreach (var search in archiveSearches)
                {
                    AddResult("HISTORY", "Username Archive", search, "INFO");
                }
            }
            catch { }
        }

        private async Task SearchEmailOnline(string email)
        {
            try
            {
                var encodedEmail = Uri.EscapeDataString(email);

                var searchLinks = new Dictionary<string, string>
                {
                    ["Google"] = $"https://www.google.com/search?q=\"{encodedEmail}\"",
                    ["Bing"] = $"https://www.bing.com/search?q=\"{encodedEmail}\"",
                    ["GitHub"] = $"https://github.com/search?q={encodedEmail}&type=code"
                };

                foreach (var search in searchLinks)
                {
                    AddResult("SEARCH", search.Key, search.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateRelatedAccounts(string email)
        {
            try
            {
                var username = email.Split('@')[0];

                var services = new Dictionary<string, string>
                {
                    ["Outlook"] = $"https://outlook.live.com/owa/?path=/mail/search&q=from:{email}",
                    ["ProtonMail"] = $"Mail service with privacy focus",
                    ["Gmail"] = $"Google's email service"
                };

                foreach (var service in services)
                {
                    AddResult("SERVICE", service.Key, service.Value, "INFO");
                }

                AddResult("RELATED", "Username Search", $"Search for username: {username}", "INFO");
            }
            catch { }
        }

        private async Task GenerateInvestigationLinksForEmail(string email)
        {
            try
            {
                var encodedEmail = Uri.EscapeDataString(email);

                var investigationTools = new Dictionary<string, string>
                {
                    ["Have I Been Pwned"] = $"https://haveibeenpwned.com/account/{encodedEmail}",
                    ["DeHashed"] = $"https://dehashed.com/search?query={encodedEmail}",
                    ["Hunter.io"] = $"https://hunter.io/verify?email={encodedEmail}"
                };

                foreach (var tool in investigationTools)
                {
                    AddResult("INVESTIGATE", tool.Key, tool.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckGravatar(string email)
        {
            try
            {
                var hash = ComputeMd5Hash(email.Trim().ToLower());
                var gravatarUrl = $"https://gravatar.com/avatar/{hash}";

                AddResult("GRAVATAR", "Image", gravatarUrl, "INFO");
                AddResult("GRAVATAR", "Profile", $"https://gravatar.com/{hash}", "INFO");
            }
            catch { }
        }

        private async Task CheckDisposableEmail(string email)
        {
            try
            {
                var domain = email.Split('@')[1].ToLower();
                var disposableDomains = new HashSet<string>
                {
                    "mailinator.com", "tempmail.com", "guerrillamail.com",
                    "10minutemail.com", "throwawaymail.com", "yopmail.com",
                    "temp-mail.org", "fakeinbox.com", "maildrop.cc"
                };

                if (disposableDomains.Contains(domain))
                {
                    AddResult("SECURITY", "⚠ Warning", "Disposable/temporary email", "WARNING");
                }
                else if (domain.Contains("temp") || domain.Contains("fake"))
                {
                    AddResult("SECURITY", "Suspicious", "Email domain looks temporary", "WARNING");
                }
                else
                {
                    AddResult("SECURITY", "Status", "Permanent email domain", "SUCCESS");
                }
            }
            catch { }
        }

        private async Task FindEmailHistory(string email)
        {
            try
            {
                var archiveChecks = new[]
                {
                    $"https://web.archive.org/web/*/{email}",
                    $"https://archive.is/*/{email}",
                    $"https://www.google.com/search?q={Uri.EscapeDataString(email)}+site:archive.org"
                };

                foreach (var check in archiveChecks)
                {
                    AddResult("HISTORY", "Archive Search", check, "INFO");
                }
            }
            catch { }
        }

        private async Task EnhancedWebsiteScan(string domain)
        {
            try
            {
                domain = CleanDomain(domain);

                Log($"🌐 PHASE 1: Basic Reconnaissance for {domain}", "HEADER");
                await Task.WhenAll(
                    PerformDnsLookup(domain),
                    CheckHttpProtocols(domain),
                    GetIpAddress(domain)
                );

                Log($"🔒 PHASE 2: Security Analysis", "HEADER");
                await Task.WhenAll(
                    CheckSslCertificate(domain),
                    AnalyzeSecurityHeaders(domain),
                    CheckCommonVulnerabilities(domain),
                    PortScanQuick(domain)
                );

                Log($"📊 PHASE 3: Intelligence Gathering", "HEADER");
                await Task.WhenAll(
                    FindSubdomains(domain),
                    CheckTechnologyStack(domain),
                    LookupWhois(domain),
                    GetGeolocation(domain)
                );

                Log($"✅ Website scan completed for {domain}", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Website scan failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckWebsiteSecurity(string domain)
        {
            try
            {
                Log($"🛡️ Performing security audit for {domain}...", "HEADER");

                var securityChecks = new[]
                {
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options"
                };

                var response = await _httpClient.GetAsync($"https://{domain}", _cts.Token);

                int securityScore = 0;
                foreach (var header in securityChecks)
                {
                    if (response.Headers.Contains(header))
                    {
                        securityScore++;
                        AddResult("SECURITY", $"✓ {header}", "Present", "SUCCESS");
                    }
                    else
                    {
                        AddResult("SECURITY", $"✗ {header}", "Missing", "WARNING");
                    }
                }

                var scorePercent = (securityScore / (double)securityChecks.Length) * 100;
                AddResult("SECURITY", "Security Score", $"{scorePercent:F0}% ({securityScore}/{securityChecks.Length})",
                    scorePercent >= 70 ? "SUCCESS" : "WARNING");
            }
            catch { }
        }

        private async Task FindSubdomainsAdvanced(string domain)
        {
            try
            {
                Log($"🔍 Advanced subdomain enumeration for {domain}...", "HEADER");

                var subdomains = new List<string>();
                var commonPrefixes = new[] { "dev", "staging", "test", "admin", "api", "mail", "ftp", "vpn", "secure" };

                foreach (var prefix in commonPrefixes)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    var testDomain = $"{prefix}.{domain}";
                    try
                    {
                        var addresses = await Dns.GetHostAddressesAsync(testDomain);
                        if (addresses.Length > 0)
                        {
                            subdomains.Add(testDomain);
                            AddResult("SUBDOMAIN", "Found", testDomain, "SUCCESS");
                        }
                    }
                    catch { }

                    await Task.Delay(50);
                }

                if (subdomains.Count > 0)
                {
                    AddResult("SUBDOMAIN", "Total", $"Found {subdomains.Count} subdomains", "INFO");
                }
            }
            catch { }
        }

        private async Task FindTechnologies(string domain)
        {
            try
            {
                Log($"🔧 Identifying technologies used by {domain}...", "HEADER");

                var response = await _httpClient.GetAsync($"https://{domain}", _cts.Token);
                var html = await response.Content.ReadAsStringAsync();

                if (response.Headers.TryGetValues("Server", out var serverValues))
                {
                    var server = string.Join(", ", serverValues);
                    AddResult("TECH", "Web Server", server, "INFO");

                    if (server.Contains("Apache/2.2") || server.Contains("Apache/2.0"))
                    {
                        AddResult("VULNERABILITY", "⚠ Old Apache", "Version may have known vulnerabilities", "WARNING");
                    }
                }

                var techPatterns = new Dictionary<string, string>
                {
                    { @"wp-content|wp-includes", "WordPress" },
                    { @"Joomla!", "Joomla" },
                    { @"Drupal.settings", "Drupal" },
                    { @"Magento", "Magento" },
                    { @"Shopify", "Shopify" },
                    { @"Bootstrap", "Bootstrap" },
                    { @"jQuery", "jQuery" },
                    { @"React|react-dom", "React" },
                    { @"Angular|ng-app", "Angular" },
                    { @"Vue|vue.js", "Vue.js" },
                    { @"Laravel", "Laravel" },
                    { @"ASP.NET|__VIEWSTATE", "ASP.NET" },
                    { @"nginx", "Nginx" },
                    { @"apache", "Apache" }
                };

                foreach (var pattern in techPatterns)
                {
                    if (Regex.IsMatch(html, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        AddResult("TECH", "Framework/CMS", pattern.Value, "INFO");
                    }
                }

                if (html.Contains("google-analytics") || html.Contains("gtag.js"))
                {
                    AddResult("ANALYTICS", "Google Analytics", "Detected", "INFO");
                }

                Log("✅ Technology identification complete", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Technology identification failed: {ex.Message}", "ERROR");
            }
        }

        private async Task CheckSSLDetails(string domain)
        {
            try
            {
                Log($"🔐 Analyzing SSL/TLS configuration for {domain}...", "HEADER");

                using var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                    {
                        if (cert != null)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                AddResult("SSL", "Issuer", cert.Issuer, "INFO");
                                AddResult("SSL", "Subject", cert.Subject, "INFO");
                                AddResult("SSL", "Valid From", cert.NotBefore.ToString("yyyy-MM-dd"), "INFO");
                                AddResult("SSL", "Valid Until", cert.NotAfter.ToString("yyyy-MM-dd"), "INFO");

                                var daysLeft = (cert.NotAfter - DateTime.Now).Days;
                                var status = daysLeft switch
                                {
                                    < 0 => "EXPIRED",
                                    < 7 => "CRITICAL",
                                    < 30 => "WARNING",
                                    _ => "GOOD"
                                };

                                AddResult("SSL", "Days Until Expiry", $"{daysLeft} days", status);
                            });
                        }
                        return true;
                    }
                };

                using var client = new HttpClient(handler);
                await client.GetAsync($"https://{domain}", _cts.Token);

                AddResult("SSL", "SSL Labs Test", $"https://www.ssllabs.com/ssltest/analyze.html?d={domain}", "INFO");

                Log("✅ SSL analysis complete", "SUCCESS");
            }
            catch
            {
                AddResult("SSL", "Status", "SSL certificate check failed", "WARNING");
            }
        }

        private async Task ExtractMetadata(string domain)
        {
            try
            {
                Log($"📄 Extracting metadata from {domain}...", "HEADER");

                var response = await _httpClient.GetAsync($"https://{domain}", _cts.Token);
                var html = await response.Content.ReadAsStringAsync();

                var metaPatterns = new Dictionary<string, string>
                {
                    { @"<meta name=""description"" content=""([^""]*)""", "Description" },
                    { @"<meta name=""keywords"" content=""([^""]*)""", "Keywords" },
                    { @"<meta name=""author"" content=""([^""]*)""", "Author" },
                    { @"<meta name=""generator"" content=""([^""]*)""", "Generator" },
                    { @"<meta property=""og:title"" content=""([^""]*)""", "OG Title" }
                };

                foreach (var pattern in metaPatterns)
                {
                    var match = Regex.Match(html, pattern.Key, RegexOptions.IgnoreCase);
                    if (match.Success && match.Groups.Count > 1)
                    {
                        AddResult("META", pattern.Value, match.Groups[1].Value, "INFO");
                    }
                }

                var commentPattern = @"<!--(.*?)-->";
                var comments = Regex.Matches(html, commentPattern, RegexOptions.Singleline)
                    .Cast<Match>()
                    .Select(m => m.Groups[1].Value.Trim())
                    .Where(c => !string.IsNullOrWhiteSpace(c) && c.Length < 200)
                    .Take(3)
                    .ToList();

                foreach (var comment in comments)
                {
                    if (comment.Contains("TODO") || comment.Contains("FIXME"))
                    {
                        AddResult("COMMENTS", "⚠ Developer Note", comment, "WARNING");
                    }
                }

                Log("✅ Metadata extraction complete", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Metadata extraction failed: {ex.Message}", "ERROR");
            }
        }

        private async Task EnhancedPersonScan(string name)
        {
            try
            {
                Log($"👤 PERSON INTELLIGENCE: {name}", "HEADER");

                await Task.WhenAll(
                    GeneratePersonProfiles(name),
                    SearchPersonOnline(name)
                );

                await Task.WhenAll(
                    GenerateContactPatterns(name),
                    CheckProfessionalProfiles(name)
                );

                await Task.WhenAll(
                    CheckSocialMediaPresence(name),
                    GenerateInvestigationLinks(name)
                );

                Log($"✅ Person intelligence completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Person scan failed: {ex.Message}", "ERROR");
            }
        }

        private async Task GeneratePersonProfiles(string name)
        {
            try
            {
                var nameParts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];

                    AddResult("PROFILE", "Full Name", name, "INFO");
                    AddResult("PROFILE", "First Name", firstName, "INFO");
                    AddResult("PROFILE", "Last Name", lastName, "INFO");

                    if (nameParts.Length > 2)
                    {
                        AddResult("PROFILE", "Middle Name", string.Join(" ", nameParts[1..^1]), "INFO");
                    }

                    AddResult("PROFILE", "Initials", $"{firstName[0]}{lastName[0]}", "INFO");
                }
            }
            catch { }
        }

        private async Task SearchPersonOnline(string name)
        {
            try
            {
                var encodedName = Uri.EscapeDataString(name);

                var searchEngines = new Dictionary<string, string>
                {
                    ["Google"] = $"https://www.google.com/search?q=\"{encodedName}\"",
                    ["Bing"] = $"https://www.bing.com/search?q=\"{encodedName}\"",
                    ["DuckDuckGo"] = $"https://duckduckgo.com/?q=\"{encodedName}\""
                };

                foreach (var engine in searchEngines)
                {
                    AddResult("SEARCH", engine.Key, engine.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateContactPatterns(string name)
        {
            try
            {
                var nameParts = name.ToLower().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (nameParts.Length >= 2)
                {
                    var firstName = nameParts[0];
                    var lastName = nameParts[^1];
                    var firstInitial = firstName[0].ToString();

                    var patterns = new[]
                    {
                        $"{firstName}.{lastName}@company.com",
                        $"{firstName}{lastName}@company.com",
                        $"{firstInitial}{lastName}@company.com",
                        $"{firstName}_{lastName}@company.com",
                        $"{lastName}.{firstName}@company.com"
                    };

                    foreach (var pattern in patterns)
                    {
                        AddResult("PATTERN", "Email Pattern", pattern, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task CheckProfessionalProfiles(string name)
        {
            try
            {
                var encodedName = Uri.EscapeDataString(name);

                var professionalSites = new Dictionary<string, string>
                {
                    ["LinkedIn"] = $"https://www.linkedin.com/search/results/people/?keywords={encodedName}",
                    ["GitHub"] = $"https://github.com/search?q={encodedName}&type=users",
                    ["Google Scholar"] = $"https://scholar.google.com/scholar?q={encodedName}"
                };

                foreach (var site in professionalSites)
                {
                    AddResult("PROFESSIONAL", site.Key, site.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckSocialMediaPresence(string name)
        {
            try
            {
                var encodedName = Uri.EscapeDataString(name);

                var socialMedia = new Dictionary<string, string>
                {
                    ["Twitter"] = $"https://twitter.com/search?q={encodedName}",
                    ["Facebook"] = $"https://www.facebook.com/search/people/?q={encodedName}",
                    ["Instagram"] = $"https://www.instagram.com/explore/tags/{encodedName.Replace(" ", "")}",
                    ["TikTok"] = $"https://www.tiktok.com/search?q={encodedName}"
                };

                foreach (var platform in socialMedia)
                {
                    AddResult("SOCIAL", platform.Key, platform.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateInvestigationLinks(string name)
        {
            try
            {
                var encodedName = Uri.EscapeDataString($"\"{name}\"");

                var investigationTools = new Dictionary<string, string>
                {
                    ["Pipl"] = $"https://pipl.com/search/?q={encodedName}",
                    ["Spokeo"] = $"https://www.spokeo.com/{encodedName}",
                    ["Whitepages"] = $"https://www.whitepages.com/name/{encodedName}"
                };

                foreach (var tool in investigationTools)
                {
                    AddResult("INVESTIGATE", tool.Key, tool.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task EnhancedEmailScan(string email)
        {
            try
            {
                Log($"📧 EMAIL INTELLIGENCE: {email}", "HEADER");

                await Task.WhenAll(
                    ValidateEmailComprehensive(email),
                    AnalyzeEmailPattern(email),
                    CheckEmailDomain(email)
                );

                await Task.WhenAll(
                    SearchEmailOnline(email),
                    CheckGravatar(email),
                    GenerateRelatedAccounts(email)
                );

                await Task.WhenAll(
                    CheckDisposableEmail(email),
                    CheckEmailReputationAdvanced(email),
                    GenerateInvestigationLinksForEmail(email)
                );

                Log($"✅ Email intelligence completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Email scan failed: {ex.Message}", "ERROR");
            }
        }

        private async Task ValidateEmailComprehensive(string email)
        {
            try
            {
                var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
                if (emailRegex.IsMatch(email))
                {
                    AddResult("VALIDATION", "Format", "✓ Valid email format", "SUCCESS");

                    var parts = email.Split('@');
                    AddResult("VALIDATION", "Username", parts[0], "INFO");
                    AddResult("VALIDATION", "Domain", parts[1], "INFO");
                }
                else
                {
                    AddResult("VALIDATION", "Format", "✗ Invalid email format", "ERROR");
                }
            }
            catch { }
        }

        private async Task AnalyzeEmailPattern(string email)
        {
            try
            {
                var localPart = email.Split('@')[0];

                if (localPart.Contains('.'))
                {
                    AddResult("PATTERN", "Type", "Corporate (first.last)", "INFO");
                }
                else if (localPart.Contains('_'))
                {
                    AddResult("PATTERN", "Type", "Underscore format", "INFO");
                }
                else if (Regex.IsMatch(localPart, @"^\d"))
                {
                    AddResult("PATTERN", "Type", "Numeric prefix", "INFO");
                }
                else
                {
                    AddResult("PATTERN", "Type", "Simple format", "INFO");
                }
            }
            catch { }
        }

        private async Task CheckEmailDomain(string email)
        {
            try
            {
                var domain = email.Split('@')[1];

                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(domain);
                    if (addresses.Length > 0)
                    {
                        AddResult("DOMAIN", "Status", "✓ Domain exists", "SUCCESS");
                    }
                }
                catch
                {
                    AddResult("DOMAIN", "Status", "✗ Domain not found", "WARNING");
                }
            }
            catch { }
        }

        private async Task CheckEmailReputationAdvanced(string email)
        {
            try
            {
                var domain = email.Split('@')[1].ToLower();

                var freeProviders = new HashSet<string>
                {
                    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                    "aol.com", "icloud.com", "protonmail.com"
                };

                if (freeProviders.Contains(domain))
                {
                    AddResult("REPUTATION", "Type", "Free email provider", "INFO");
                }
                else if (domain.Contains("edu"))
                {
                    AddResult("REPUTATION", "Type", "Educational institution", "INFO");
                }
                else if (domain.Contains("gov"))
                {
                    AddResult("REPUTATION", "Type", "Government email", "INFO");
                }
                else
                {
                    AddResult("REPUTATION", "Type", "Corporate email", "INFO");
                }
            }
            catch { }
        }

        private async Task EnhancedPhoneScan(string phone)
        {
            try
            {
                Log($"📱 PHONE INTELLIGENCE: {phone}", "HEADER");

                await Task.WhenAll(
                    ValidateAndParsePhone(phone),
                    IdentifyPhoneType(phone)
                );

                await Task.WhenAll(
                    AnalyzePhoneNumber(phone),
                    GeolocatePhoneNumber(phone),
                    CheckCarrierInformation(phone)
                );

                await Task.WhenAll(
                    GenerateSearchLinks(phone),
                    GenerateInvestigationLinksForPhone(phone)
                );

                if (phone.Contains("+964"))
                {
                    await AnalyzeIraqiNumber(phone);
                }

                Log($"✅ Phone intelligence completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Phone scan failed: {ex.Message}", "ERROR");
            }
        }

        private async Task ValidateAndParsePhone(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                AddResult("PHONE", "Original", phone, "INFO");
                AddResult("PHONE", "Digits Only", digits, "INFO");
                AddResult("PHONE", "Length", $"{digits.Length} digits", "INFO");

                foreach (var countryCode in _countryCodes.Keys.OrderByDescending(k => k.Length))
                {
                    if (digits.StartsWith(countryCode.TrimStart('+')))
                    {
                        var country = _countryCodes[countryCode];
                        AddResult("PHONE", "Country", $"{country.Name} ({country.Code})", "SUCCESS");
                        AddResult("PHONE", "Region", country.Region, "INFO");
                        break;
                    }
                }
            }
            catch { }
        }

        private async Task IdentifyPhoneType(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1") && digits.Length == 11)
                {
                    var areaCode = digits.Substring(1, 3);
                    var tollFreeCodes = new[] { "800", "833", "844", "855", "866", "877", "888" };

                    if (tollFreeCodes.Contains(areaCode))
                    {
                        AddResult("PHONE", "Type", "Toll-Free Number", "INFO");
                    }
                }
                else if (digits.StartsWith("964") && digits.Length >= 12)
                {
                    AddResult("PHONE", "Type", "Iraqi Mobile Number", "INFO");
                }
            }
            catch { }
        }

        private async Task AnalyzePhoneNumber(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1") && digits.Length == 11)
                {
                    var formatted = $"({digits.Substring(1, 3)}) {digits.Substring(4, 3)}-{digits.Substring(7, 4)}";
                    AddResult("FORMAT", "US Format", formatted, "INFO");
                }
                else if (digits.StartsWith("964") && digits.Length >= 12)
                {
                    var mobile = digits.Substring(3);
                    if (mobile.Length == 10)
                    {
                        var formatted = $"+964 {mobile.Substring(0, 3)} {mobile.Substring(3, 3)} {mobile.Substring(6)}";
                        AddResult("FORMAT", "Iraqi Format", formatted, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task GeolocatePhoneNumber(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1") && digits.Length == 11)
                {
                    var areaCode = digits.Substring(1, 3);
                    if (_usAreaCodes.TryGetValue(areaCode, out var location))
                    {
                        AddResult("LOCATION", "Location", location, "INFO");
                    }
                }
                else if (digits.StartsWith("964") && digits.Length >= 12)
                {
                    var mobile = digits.Substring(3);
                    if (mobile.Length >= 3)
                    {
                        var prefix = mobile.Substring(0, 3);
                        var operatorInfo = GetIraqiOperator(prefix);
                        AddResult("LOCATION", "Iraq Region", operatorInfo, "INFO");
                    }
                }
            }
            catch { }
        }

        private string GetIraqiOperator(string prefix)
        {
            var operators = new Dictionary<string, string>
            {
                ["770"] = "Zain Iraq - Baghdad",
                ["771"] = "Zain Iraq",
                ["772"] = "Zain Iraq - North",
                ["775"] = "Asia Cell",
                ["776"] = "Asia Cell",
                ["778"] = "Korek Telecom",
                ["779"] = "Korek Telecom",
                ["780"] = "Zain Iraq Special"
            };

            return operators.TryGetValue(prefix, out var op) ? op : "Unknown Iraqi operator";
        }

        private async Task CheckCarrierInformation(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("1"))
                {
                    AddResult("CARRIER", "Lookup", $"Check: carrierlookup.com/{digits}", "INFO");
                }
                else if (digits.StartsWith("964"))
                {
                    AddResult("CARRIER", "Iraq Operators", "Main: Zain, Asia Cell, Korek", "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateSearchLinks(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());
                var encodedPhone = Uri.EscapeDataString(phone);

                var searchLinks = new Dictionary<string, string>
                {
                    ["Google"] = $"https://www.google.com/search?q=\"{encodedPhone}\"",
                    ["TrueCaller"] = $"https://www.truecaller.com/search/{cleanPhone}",
                    ["WhitePages"] = $"https://www.whitepages.com/phone/{cleanPhone}"
                };

                foreach (var search in searchLinks)
                {
                    AddResult("SEARCH", search.Key, search.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateInvestigationLinksForPhone(string phone)
        {
            try
            {
                var cleanPhone = new string(phone.Where(char.IsDigit).ToArray());

                var investigationTools = new Dictionary<string, string>
                {
                    ["NumVerify"] = $"https://numverify.com/validate/{cleanPhone}",
                    ["WhatsApp Check"] = $"Check if {cleanPhone} is on WhatsApp",
                    ["Telegram Check"] = $"Check if {cleanPhone} is on Telegram"
                };

                foreach (var tool in investigationTools)
                {
                    AddResult("INVESTIGATE", tool.Key, tool.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task AnalyzeIraqiNumber(string phone)
        {
            try
            {
                var digits = new string(phone.Where(char.IsDigit).ToArray());

                if (digits.StartsWith("964"))
                {
                    AddResult("IRAQ", "Country Code", "+964 Iraq", "SUCCESS");

                    var mobile = digits.Substring(3);
                    if (mobile.Length == 10)
                    {
                        AddResult("IRAQ", "Format", "Correct Iraqi mobile length", "SUCCESS");

                        var prefix = mobile.Substring(0, 3);
                        AddResult("IRAQ", "Operator Prefix", prefix, "INFO");

                        var operatorInfo = GetIraqiOperator(prefix);
                        if (operatorInfo != "Unknown Iraqi operator")
                        {
                            AddResult("IRAQ", "Mobile Operator", operatorInfo, "SUCCESS");
                        }
                    }

                    AddResult("IRAQ", "Emergency", "Police: 104, Ambulance: 122", "INFO");
                }
            }
            catch { }
        }

        private async Task EnhancedUsernameScan(string username)
        {
            try
            {
                Log($"👤 USERNAME INTELLIGENCE: {username}", "HEADER");

                await Task.WhenAll(
                    AnalyzeUsernamePattern(username),
                    GenerateVariations(username)
                );

                await Task.WhenAll(
                    CheckGitHubProfile(username),
                    CheckRedditProfile(username),
                    CheckSocialMedia(username)
                );

                await Task.WhenAll(
                    SearchUsernameOnline(username),
                    CheckUsernameAvailability(username),
                    GenerateInvestigationLinksForUsername(username)
                );

                Log($"✅ Username intelligence completed", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"❌ Username scan failed: {ex.Message}", "ERROR");
            }
        }

        private async Task AnalyzeUsernamePattern(string username)
        {
            try
            {
                AddResult("ANALYSIS", "Username", username, "INFO");
                AddResult("ANALYSIS", "Length", $"{username.Length} characters", "INFO");

                if (Regex.IsMatch(username, @"^\d"))
                {
                    AddResult("ANALYSIS", "Pattern", "Starts with number", "INFO");
                }

                if (username.Contains('_'))
                {
                    AddResult("ANALYSIS", "Pattern", "Contains underscore", "INFO");
                }

                if (username.Contains('.'))
                {
                    AddResult("ANALYSIS", "Pattern", "Contains dot", "INFO");
                }

                if (Regex.IsMatch(username, @"\d+$"))
                {
                    AddResult("ANALYSIS", "Pattern", "Ends with numbers", "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateVariations(string username)
        {
            try
            {
                var variations = new List<string>
                {
                    username,
                    $"{username}123",
                    $"{username}_{DateTime.Now.Year % 100}",
                    $"{username}official",
                    $"the{username}",
                    $"{username}real",
                    $"{username}1",
                    $"{username}_"
                };

                foreach (var variation in variations.Take(5))
                {
                    AddResult("VARIATION", "Possible", variation, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckGitHubProfile(string username)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get,
                    $"https://api.github.com/users/{Uri.EscapeDataString(username)}");
                request.Headers.Add("User-Agent", "VRAX-OSINT");

                var response = await _httpClient.SendAsync(request, _cts.Token);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var data = JObject.Parse(json);

                    AddResult("GITHUB", "✓ Profile Found", username, "SUCCESS");
                    AddResult("GITHUB", "Name", data["name"]?.ToString() ?? "Not set", "INFO");
                    AddResult("GITHUB", "Repositories", data["public_repos"]?.ToString() ?? "0", "INFO");
                    AddResult("GITHUB", "URL", data["html_url"]?.ToString(), "INFO");
                }
                else
                {
                    AddResult("GITHUB", "Status", "Profile not found", "INFO");
                }
            }
            catch { }
        }

        private async Task CheckRedditProfile(string username)
        {
            try
            {
                var response = await _httpClient.GetAsync(
                    $"https://www.reddit.com/user/{Uri.EscapeDataString(username)}/about.json", _cts.Token);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    if (!json.Contains("\"error\": 404"))
                    {
                        AddResult("REDDIT", "✓ Profile Found", username, "SUCCESS");
                        AddResult("REDDIT", "URL", $"https://reddit.com/user/{username}", "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task CheckSocialMedia(string username)
        {
            try
            {
                var socialPlatforms = new Dictionary<string, string>
                {
                    ["Twitter"] = $"https://twitter.com/{username}",
                    ["Instagram"] = $"https://instagram.com/{username}",
                    ["Facebook"] = $"https://facebook.com/{username}",
                    ["TikTok"] = $"https://tiktok.com/@{username}",
                    ["YouTube"] = $"https://youtube.com/@{username}",
                    ["Twitch"] = $"https://twitch.tv/{username}"
                };

                foreach (var platform in socialPlatforms)
                {
                    AddResult("SOCIAL", platform.Key, platform.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task SearchUsernameOnline(string username)
        {
            try
            {
                var encodedUsername = Uri.EscapeDataString(username);

                var searchLinks = new Dictionary<string, string>
                {
                    ["Google"] = $"https://www.google.com/search?q=\"{encodedUsername}\"",
                    ["Bing"] = $"https://www.bing.com/search?q=\"{encodedUsername}\"",
                    ["GitHub Code"] = $"https://github.com/search?q={encodedUsername}&type=code"
                };

                foreach (var search in searchLinks)
                {
                    AddResult("SEARCH", search.Key, search.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task CheckUsernameAvailability(string username)
        {
            try
            {
                var availabilityTools = new Dictionary<string, string>
                {
                    ["Namechk"] = $"https://namechk.com/{username}",
                    ["KnowEm"] = $"https://knowem.com/checkusernames.php?u={username}"
                };

                foreach (var tool in availabilityTools)
                {
                    AddResult("AVAILABILITY", tool.Key, tool.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task GenerateInvestigationLinksForUsername(string username)
        {
            try
            {
                var encodedUsername = Uri.EscapeDataString(username);

                var investigationTools = new Dictionary<string, string>
                {
                    ["WhatsMyName"] = $"Web app: whatsmyname.app",
                    ["Social Searcher"] = $"https://www.social-searcher.com/search-users/?q={encodedUsername}",
                    ["UserSearch"] = $"https://usersearch.org/results_normal.php?URL_username={encodedUsername}"
                };

                foreach (var tool in investigationTools)
                {
                    AddResult("INVESTIGATE", tool.Key, tool.Value, "INFO");
                }
            }
            catch { }
        }

        private async Task PerformDnsLookup(string domain)
        {
            try
            {
                Log($"🌐 DNS Analysis: {domain}", "INFO");

                var hostEntry = await Dns.GetHostEntryAsync(domain);
                AddResult("DNS", "Hostname", hostEntry.HostName, "SUCCESS");

                foreach (var address in hostEntry.AddressList)
                {
                    string type = address.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
                    AddResult("DNS", type, address.ToString(), "INFO");
                }

                try
                {
                    string[] mxRecords = await GetMxRecordsViaDns(domain);
                    foreach (var mx in mxRecords.Take(3))
                    {
                        AddResult("DNS", "MX Record", mx, "INFO");
                    }
                }
                catch { }

                Log($"✓ DNS analysis complete", "SUCCESS");
            }
            catch (Exception ex)
            {
                Log($"⚠ DNS lookup failed: {ex.Message}", "WARNING");
            }
        }

        private async Task<string[]> GetMxRecordsViaDns(string domain)
        {
            var tasks = new List<Task<string>>();

            for (int i = 0; i < 3; i++)
            {
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get,
                            $"http://dig.jsondns.org/IN/{domain}/MX");
                        var response = await _httpClient.SendAsync(request);
                        var json = await response.Content.ReadAsStringAsync();
                        var data = JObject.Parse(json);

                        if (data["answer"] is JArray answers)
                        {
                            return string.Join(", ", answers.Select(a => a["rdata"]?.ToString()).Where(r => r != null));
                        }
                    }
                    catch { }
                    return null;
                }));
            }

            var results = await Task.WhenAll(tasks);
            return results.Where(r => !string.IsNullOrEmpty(r)).ToArray();
        }

        private async Task CheckHttpProtocols(string domain)
        {
            try
            {
                Log($"📡 Checking HTTP protocols...", "INFO");

                var protocols = new[] { "https", "http" };
                foreach (var protocol in protocols)
                {
                    try
                    {
                        var url = $"{protocol}://{domain}";
                        var response = await _httpClient.GetAsync(url, _cts.Token);

                        AddResult("HTTP", $"{protocol.ToUpper()} Status",
                            $"{(int)response.StatusCode} {response.ReasonPhrase}", "SUCCESS");

                        if (response.Headers.TryGetValues("Server", out var server))
                        {
                            AddResult("HTTP", "Web Server", string.Join(", ", server), "INFO");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task GetIpAddress(string domain)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                if (addresses.Length > 0)
                {
                    AddResult("IP", "Primary IP", addresses[0].ToString(), "INFO");
                }
            }
            catch { }
        }

        private async Task CheckSslCertificate(string domain)
        {
            try
            {
                using var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                    {
                        if (cert != null)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                AddResult("SSL", "Issuer", cert.Issuer, "INFO");
                                AddResult("SSL", "Valid Until", cert.NotAfter.ToString("yyyy-MM-dd"), "INFO");

                                var daysLeft = (cert.NotAfter - DateTime.Now).Days;
                                if (daysLeft < 30)
                                {
                                    AddResult("SSL", "⚠ WARNING", $"Expires in {daysLeft} days", "WARNING");
                                }
                            });
                        }
                        return true;
                    }
                };

                using var client = new HttpClient(handler);
                await client.GetAsync($"https://{domain}", _cts.Token);

                Log($"✓ SSL certificate check complete", "SUCCESS");
            }
            catch
            {
                AddResult("SSL", "Status", "No SSL certificate or HTTPS not available", "WARNING");
            }
        }

        private async Task AnalyzeSecurityHeaders(string domain)
        {
            try
            {
                var response = await _httpClient.GetAsync($"https://{domain}", _cts.Token);

                var securityChecks = new Dictionary<string, Action<string>>
                {
                    ["Strict-Transport-Security"] = v => AddResult("Security", "HSTS", "Enabled", "SUCCESS"),
                    ["X-Frame-Options"] = v => AddResult("Security", "Clickjacking", "Protected", "SUCCESS"),
                    ["X-Content-Type-Options"] = v => AddResult("Security", "MIME Sniffing", "Blocked", "SUCCESS")
                };

                int secureHeaders = 0;
                foreach (var check in securityChecks)
                {
                    if (response.Headers.Contains(check.Key))
                    {
                        check.Value("");
                        secureHeaders++;
                    }
                    else
                    {
                        AddResult("Security", $"Missing", check.Key, "WARNING");
                    }
                }
            }
            catch { }
        }

        private async Task CheckCommonVulnerabilities(string domain)
        {
            try
            {
                var vulnerablePaths = new[]
                {
                    "/.env", "/wp-config.php", "/config.php", "/.git/config",
                    "/phpinfo.php", "/test.php", "/admin.php", "/backup.zip"
                };

                foreach (var path in vulnerablePaths)
                {
                    try
                    {
                        var response = await _httpClient.GetAsync($"https://{domain}{path}", _cts.Token);
                        if (response.IsSuccessStatusCode)
                        {
                            AddResult("VULNERABILITY", "⚠ EXPOSED", $"{path} is publicly accessible", "CRITICAL");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task PortScanQuick(string domain)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

                if (ip != null)
                {
                    var criticalPorts = new[] { 22, 23, 21, 25, 3389, 5900, 8080 };

                    foreach (var port in criticalPorts)
                    {
                        try
                        {
                            using var client = new TcpClient();
                            var task = client.ConnectAsync(ip.ToString(), port);

                            if (await Task.WhenAny(task, Task.Delay(1000)) == task && client.Connected)
                            {
                                AddResult("PORT", $"{port} OPEN", GetPortService(port), "WARNING");
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private string GetPortService(int port)
        {
            return port switch
            {
                22 => "SSH",
                23 => "Telnet",
                21 => "FTP",
                25 => "SMTP",
                3389 => "RDP",
                5900 => "VNC",
                8080 => "HTTP Proxy",
                _ => "Unknown"
            };
        }

        private async Task FindSubdomains(string domain)
        {
            try
            {
                int found = 0;
                foreach (var sub in _commonSubdomains.Take(10))
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    var fullDomain = $"{sub}.{domain}";
                    try
                    {
                        var addresses = await Dns.GetHostAddressesAsync(fullDomain);
                        if (addresses.Length > 0)
                        {
                            found++;
                            AddResult("SUBDOMAIN", "Found", fullDomain, "SUCCESS");
                        }
                    }
                    catch { }
                }

                if (found > 0)
                {
                    AddResult("SUBDOMAIN", "Total", $"Found {found} subdomains", "INFO");
                }
            }
            catch { }
        }

        private async Task CheckTechnologyStack(string domain)
        {
            try
            {
                var response = await _httpClient.GetAsync($"https://{domain}", _cts.Token);
                var html = await response.Content.ReadAsStringAsync();

                var techPatterns = new Dictionary<string, string>
                {
                    { @"wp-content|wp-includes", "WordPress" },
                    { @"Joomla!", "Joomla" },
                    { @"Drupal.settings", "Drupal" },
                    { @"React|react-dom", "React" },
                    { @"angular|ng-", "Angular" },
                    { @"vue\.js|Vue\.", "Vue.js" },
                    { @"jQuery|jquery", "jQuery" },
                    { @"bootstrap", "Bootstrap" },
                    { @"laravel", "Laravel" },
                    { @".net|asp.net", "ASP.NET" },
                    { @"nginx", "Nginx" },
                    { @"apache", "Apache" }
                };

                foreach (var pattern in techPatterns)
                {
                    if (Regex.IsMatch(html, pattern.Key, RegexOptions.IgnoreCase))
                    {
                        AddResult("TECH", "Detected", pattern.Value, "INFO");
                    }
                }
            }
            catch { }
        }

        private async Task LookupWhois(string domain)
        {
            try
            {
                AddResult("WHOIS", "Lookup", $"Check: whois.domaintools.com/{domain}", "INFO");
                AddResult("WHOIS", "Lookup", $"Check: whois.com/whois/{domain}", "INFO");
            }
            catch { }
        }

        private async Task GetGeolocation(string domain)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain);
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

                if (ip != null)
                {
                    AddResult("GEO", "IP", ip.ToString(), "INFO");
                    AddResult("GEO", "Lookup", $"Check: ip-api.com/#{ip}", "INFO");
                }
            }
            catch { }
        }

        private void StopScan_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            Log("⏸ SCAN STOPPED BY OPERATOR", "WARNING");
            StatusText.Text = "Scan stopped";
            BtnStop.IsEnabled = false;
        }

        private void ExportResults_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var filename = $"vrax_osint_{timestamp}.json";

                var exportData = AllResults.Select(r => new
                {
                    Severity = r.Severity,
                    Category = r.Category,
                    Source = r.Source,
                    Data = r.Data,
                    Timestamp = r.Timestamp,
                    VisitURL = ExtractUrlFromResult(r)
                }).ToList();

                var json = JsonConvert.SerializeObject(exportData, Formatting.Indented);
                File.WriteAllText(filename, json);

                Log($"💾 Intelligence exported to {filename}", "SUCCESS");
                MessageBox.Show($"Intelligence Data Exported:\n{Path.GetFullPath(filename)}",
                    "VRAX - EXPORT COMPLETE", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Log($"❌ Export failed: {ex.Message}", "ERROR");
                MessageBox.Show($"Export failed: {ex.Message}", "ERROR",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RefreshGrid_Click(object sender, RoutedEventArgs e)
        {
            Log("🔄 Refreshing intelligence dashboard...", "INFO");
            UpdateStatistics();
        }

        private void VisitResult_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button button && button.Tag is OsintResult result)
            {
                try
                {
                    var url = ExtractUrlFromResult(result);
                    if (!string.IsNullOrEmpty(url))
                    {
                        if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                        {
                            url = "https://" + url;
                        }

                        Log($"🌐 Opening: {url}", "INFO");

                        Process.Start(new ProcessStartInfo
                        {
                            FileName = url,
                            UseShellExecute = true
                        });
                    }
                    else
                    {
                        var searchQuery = Uri.EscapeDataString($"{result.Source} {result.Data}");
                        var searchUrl = $"https://www.google.com/search?q={searchQuery}";

                        Log($"🔍 Searching: {result.Source} {result.Data}", "INFO");

                        Process.Start(new ProcessStartInfo
                        {
                            FileName = searchUrl,
                            UseShellExecute = true
                        });
                    }
                }
                catch (Exception ex)
                {
                    Log($"❌ Failed to open: {ex.Message}", "ERROR");
                    MessageBox.Show($"Failed to open link:\n{ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string ExtractUrlFromResult(OsintResult result)
        {
            var urlPattern = @"(https?://[^\s]+|www\.[^\s]+\.[^\s]+)";
            var match = Regex.Match(result.Data, urlPattern);
            if (match.Success)
            {
                return match.Value;
            }

            match = Regex.Match(result.Source, urlPattern);
            if (match.Success)
            {
                return match.Value;
            }

            switch (result.Category)
            {
                case "GITHUB" when result.Source == "URL":
                    return result.Data;
                case "SOCIAL":
                case "PROFESSIONAL":
                case "SEARCH":
                case "INVESTIGATE":
                case "DORK":
                case "BREACH":
                    return result.Data;
                case "WHOIS" when result.Source == "Lookup":
                    if (result.Data.Contains("whois."))
                        return ExtractUrlFromText(result.Data);
                    break;
                case "GEO" when result.Source == "Lookup":
                    if (result.Data.Contains("ip-api.com"))
                        return ExtractUrlFromText(result.Data);
                    break;
            }

            return null;
        }

        private string ExtractUrlFromText(string text)
        {
            var patterns = new[]
            {
                @"https?://[^\s]+",
                @"www\.[^\s]+\.[^\s]+"
            };

            foreach (var pattern in patterns)
            {
                var match = Regex.Match(text, pattern);
                if (match.Success)
                {
                    var url = match.Value;
                    if (!url.StartsWith("http"))
                        url = "https://" + url;
                    return url;
                }
            }

            return null;
        }

        private void AddResult(string category, string source, string data, string severity)
        {
            Dispatcher.Invoke(() =>
            {
                var result = new OsintResult
                {
                    Category = category,
                    Source = source,
                    Data = data,
                    Severity = severity,
                    Timestamp = DateTime.Now.ToString("HH:mm:ss")
                };

                AllResults.Add(result);
                ResultCount.Text = $"Intelligence Items: {AllResults.Count}";

                if (severity == "CRITICAL" || severity == "WARNING")
                    CriticalResults.Add(result);

                if (category.Contains("DNS") || category.Contains("HTTP") || category.Contains("SSL") ||
                    category.Contains("PORT") || category.Contains("Security") || category.Contains("TECH") ||
                    category.Contains("VULNERABILITY") || category.Contains("SUBDOMAIN") ||
                    category.Contains("WHOIS") || category.Contains("GEO") || category.Contains("IP") ||
                    category.Contains("DORK") || category.Contains("FILE") || category.Contains("META") ||
                    category.Contains("COMMENTS"))
                    WebResults.Add(result);

                if (category.Contains("EMAIL") || category.Contains("PHONE") || category.Contains("SOCIAL") ||
                    category.Contains("USERNAME") || category.Contains("GITHUB") || category.Contains("REDDIT") ||
                    category.Contains("PROFILE") || category.Contains("PERSON") || category.Contains("PATTERN") ||
                    category.Contains("PROFESSIONAL") || category.Contains("VALIDATION") ||
                    category.Contains("REPUTATION") || category.Contains("ANALYSIS") || category.Contains("VARIATION") ||
                    category.Contains("BREACH") || category.Contains("RECOVERY") || category.Contains("QUESTIONS") ||
                    category.Contains("PASSWORD") || category.Contains("RELATIVES") || category.Contains("COURT") ||
                    category.Contains("PROPERTY") || category.Contains("RECORDS") || category.Contains("HISTORY") ||
                    category.Contains("DATING") || category.Contains("ASSOCIATED") || category.Contains("CARRIER") ||
                    category.Contains("LOCATION") || category.Contains("OWNER") || category.Contains("IRAQ") ||
                    category.Contains("CHECKER") || category.Contains("PASTEBIN") || category.Contains("GRAVATAR") ||
                    category.Contains("SERVICE"))
                    IdentityResults.Add(result);

                if (category == "BREACH" || category == "PASSWORD" ||
                    (severity == "CRITICAL" && (data.Contains("leak") || data.Contains("breach") || data.Contains("password"))))
                    LeakedCredentials.Add(result);
            });
        }

        private void Log(string message, string type = "INFO")
        {
            Dispatcher.Invoke(() =>
            {
                var timestamp = DateTime.Now.ToString("HH:mm:ss");
                var prefix = type switch
                {
                    "ERROR" => "❌",
                    "WARNING" => "⚠",
                    "SUCCESS" => "✓",
                    "CRITICAL" => "🚨",
                    "HEADER" => "═",
                    "SEPARATOR" => "━",
                    _ => "•"
                };

                LogText.Text += $"[{timestamp}] {prefix} {message}\n";

                if (LogScroll != null)
                    LogScroll.ScrollToEnd();
            });
        }

        private void UpdateStatistics()
        {
            Dispatcher.Invoke(() =>
            {
                var stats = new StringBuilder();
                stats.AppendLine("📊 CYBERSECURITY INTELLIGENCE REPORT\n");
                stats.AppendLine("═══════════════════════════════════════\n");
                stats.AppendLine($"Total Intelligence Items: {AllResults.Count}");
                stats.AppendLine($"Critical Security Findings: {CriticalResults.Count}");
                stats.AppendLine($"Web Infrastructure Data: {WebResults.Count}");
                stats.AppendLine($"Identity Intelligence: {IdentityResults.Count}");
                stats.AppendLine($"Leaked Credentials: {LeakedCredentials.Count}\n");

                var categories = AllResults
                    .GroupBy(r => r.Category)
                    .Select(g => new { Category = g.Key, Count = g.Count() })
                    .OrderByDescending(x => x.Count)
                    .Take(8);

                stats.AppendLine("Intelligence Categories:\n");
                foreach (var cat in categories)
                {
                    stats.AppendLine($"  • {cat.Category}: {cat.Count}");
                }

                stats.AppendLine($"\n═══════════════════════════════════════");
                stats.AppendLine($"Scan Mode: {_currentMode.ToUpper()}");
                stats.AppendLine($"Operator: {Environment.UserName}");
                stats.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                stats.AppendLine($"Duration: {(DateTime.Now - _scanStartTime).TotalSeconds:F1}s");

                StatsText.Text = stats.ToString();
            });
        }

        private string ComputeMd5Hash(string input)
        {
            using var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input.Trim().ToLower()));
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private string CleanDomain(string domain)
        {
            domain = domain.Replace("https://", "").Replace("http://", "").Split('/')[0].Trim();
            return domain;
        }

        private void ClearAllResults()
        {
            Dispatcher.Invoke(() =>
            {
                AllResults.Clear();
                CriticalResults.Clear();
                WebResults.Clear();
                IdentityResults.Clear();
                LeakedCredentials.Clear();

                ResultCount.Text = "Intelligence Items: 0";

                _completedTasks = 0;
                _totalTasks = 0;
            });
        }
    }

    public class OsintResult
    {
        public string Severity { get; set; }
        public string Category { get; set; }
        public string Source { get; set; }
        public string Data { get; set; }
        public string Timestamp { get; set; }
    }

    public class CountryInfo
    {
        public string Name { get; }
        public string Code { get; }
        public string Region { get; }

        public CountryInfo(string name, string code, string region)
        {
            Name = name;
            Code = code;
            Region = region;
        }
    }
}
