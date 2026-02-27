using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace ReconSuite
{
    public partial class IntelWindow : Window
    {
        private readonly string connStr = "Data Source=recon.db;Version=3;";
        private Point lastMousePosition;
        private bool isDragging = false;
        private double zoomLevel = 1.0;
        private const double MIN_ZOOM = 0.1;
        private const double MAX_ZOOM = 8.0;
        private const double ZOOM_FACTOR = 1.2;
        private DispatcherTimer animationTimer;
        private DispatcherTimer elapsedTimer;
        private DateTime startTime;
        private double ringAngle = 0;
        private List<UIElement> createdNodes = new List<UIElement>();
        private List<UIElement> createdLinks = new List<UIElement>();
        private ScaleTransform scaleTransform;
        private TranslateTransform translateTransform;
        private TransformGroup transformGroup;
        private bool isInitialized = false;
        private double centerX = 2000;
        private double centerY = 2000;
        private long currentScanId = -1;

        public IntelWindow(string target = "")
        {
            InitializeComponent();
            InitializeTransforms();
            InitializeEventHandlers();
            InitializeDatabase();
            InitializeTimers();
            SetupCanvas();

            Loaded += (s, e) =>
            {
                StartAnimations();
                LoadTargets();
                if (!string.IsNullOrEmpty(target))
                {
                    TargetSelector.SelectedItem = target;
                    LoadTargetData(target);
                }
                isInitialized = true;
                CenterView();
            };
        }

        private void InitializeTransforms()
        {
            scaleTransform = new ScaleTransform(zoomLevel, zoomLevel);
            translateTransform = new TranslateTransform();
            transformGroup = new TransformGroup();
            transformGroup.Children.Add(scaleTransform);
            transformGroup.Children.Add(translateTransform);
            MapCanvas.RenderTransform = transformGroup;
        }

        private void InitializeEventHandlers()
        {
            MapCanvas.MouseWheel += MapCanvas_MouseWheel;
            MapCanvas.MouseLeftButtonDown += MapCanvas_MouseLeftButtonDown;
            MapCanvas.MouseLeftButtonUp += MapCanvas_MouseLeftButtonUp;
            MapCanvas.MouseMove += MapCanvas_MouseMove;
            ResetViewBtn.Click += ResetView_Click;
            ZoomInBtn.Click += ZoomIn_Click;
            ZoomOutBtn.Click += ZoomOut_Click;
            ClearMapBtn.Click += ClearMap_Click;
            GenerateReportBtn.Click += GenerateReport_Click;
            ExportVisualizationBtn.Click += ExportVisualization_Click;
            CloseBtn.Click += Close_Click;
            TargetSelector.SelectionChanged += TargetSelector_SelectionChanged;
        }

        private void InitializeDatabase()
        {
            try
            {
                if (!File.Exists("recon.db"))
                {
                    CreateDatabaseSchema();
                    InsertSampleData();
                }
                else
                {
                    DbStatus.Text = "CONNECTED";
                }
            }
            catch (Exception ex)
            {
                DbStatus.Text = "ERROR";
                LogMessage($">> DATABASE ERROR: {ex.Message}");
            }
        }

        private void CreateDatabaseSchema()
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                string sql = @"
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        ip_address TEXT,
                        start_time DATETIME NOT NULL,
                        end_time DATETIME,
                        scan_duration REAL,
                        status TEXT DEFAULT 'completed',
                        hostname TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        port INTEGER NOT NULL,
                        service TEXT,
                        status TEXT NOT NULL,
                        banner TEXT,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS technologies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        technology TEXT NOT NULL,
                        confidence INTEGER DEFAULT 1,
                        version TEXT,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS security_issues (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        issue_type TEXT NOT NULL,
                        severity TEXT,
                        description TEXT,
                        recommendation TEXT,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS geolocation (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        country TEXT,
                        city TEXT,
                        region TEXT,
                        isp TEXT,
                        timezone TEXT,
                        latitude REAL,
                        longitude REAL,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS network_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        ping_time_ms INTEGER,
                        hop_count INTEGER,
                        network_type TEXT,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    
                    CREATE TABLE IF NOT EXISTS http_response (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        status_code INTEGER,
                        server_header TEXT,
                        content_type TEXT,
                        has_ssl BOOLEAN DEFAULT 0,
                        protocol TEXT,
                        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );";

                using var cmd = new SQLiteCommand(sql, conn);
                cmd.ExecuteNonQuery();

                DbStatus.Text = "CONNECTED";
                LogMessage(">> DATABASE SCHEMA CREATED");
            }
            catch (Exception ex)
            {
                LogMessage($">> ERROR CREATING DATABASE: {ex.Message}");
            }
        }

        private void InsertSampleData()
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("INSERT INTO scans (target, ip_address, start_time, status, hostname) VALUES ('example.com', '93.184.216.34', @start, 'completed', 'example.com'); SELECT last_insert_rowid();", conn);
                cmd.Parameters.AddWithValue("@start", DateTime.Now);
                var scanId = Convert.ToInt64(cmd.ExecuteScalar());

                var ports = new[] {
                    new { Port = 80, Service = "HTTP" },
                    new { Port = 443, Service = "HTTPS" },
                    new { Port = 22, Service = "SSH" },
                    new { Port = 21, Service = "FTP" },
                    new { Port = 25, Service = "SMTP" }
                };

                foreach (var port in ports)
                {
                    using var portCmd = new SQLiteCommand("INSERT INTO ports (scan_id, port, service, status) VALUES (@scanId, @port, @service, 'open')", conn);
                    portCmd.Parameters.AddWithValue("@scanId", scanId);
                    portCmd.Parameters.AddWithValue("@port", port.Port);
                    portCmd.Parameters.AddWithValue("@service", port.Service);
                    portCmd.ExecuteNonQuery();
                }

                var technologies = new[] { "Apache", "PHP", "MySQL", "WordPress", "jQuery" };
                foreach (var tech in technologies)
                {
                    using var techCmd = new SQLiteCommand("INSERT INTO technologies (scan_id, technology) VALUES (@scanId, @tech)", conn);
                    techCmd.Parameters.AddWithValue("@scanId", scanId);
                    techCmd.Parameters.AddWithValue("@tech", tech);
                    techCmd.ExecuteNonQuery();
                }

                using var geoCmd = new SQLiteCommand("INSERT INTO geolocation (scan_id, country, city, region, isp, timezone) VALUES (@scanId, 'United States', 'New York', 'NY', 'Cloudflare', 'America/New_York')", conn);
                geoCmd.Parameters.AddWithValue("@scanId", scanId);
                geoCmd.ExecuteNonQuery();

                var issues = new[] {
                    new { Description = "Missing security header: X-Frame-Options", Severity = "Medium" },
                    new { Description = "No SSL/TLS encryption (HTTP only)", Severity = "High" }
                };

                foreach (var issue in issues)
                {
                    using var issueCmd = new SQLiteCommand("INSERT INTO security_issues (scan_id, issue_type, severity, description) VALUES (@scanId, 'Security Issue', @severity, @desc)", conn);
                    issueCmd.Parameters.AddWithValue("@scanId", scanId);
                    issueCmd.Parameters.AddWithValue("@severity", issue.Severity);
                    issueCmd.Parameters.AddWithValue("@desc", issue.Description);
                    issueCmd.ExecuteNonQuery();
                }

                using var netCmd = new SQLiteCommand("INSERT INTO network_info (scan_id, ping_time_ms, hop_count, network_type) VALUES (@scanId, 45, 12, 'IPv4')", conn);
                netCmd.Parameters.AddWithValue("@scanId", scanId);
                netCmd.ExecuteNonQuery();

                using var httpCmd = new SQLiteCommand("INSERT INTO http_response (scan_id, status_code, server_header, content_type, has_ssl) VALUES (@scanId, 200, 'Apache/2.4.41', 'text/html', 1)", conn);
                httpCmd.Parameters.AddWithValue("@scanId", scanId);
                httpCmd.ExecuteNonQuery();

                LogMessage(">> SAMPLE DATA INSERTED");
            }
            catch (Exception ex)
            {
                LogMessage($">> ERROR INSERTING SAMPLE DATA: {ex.Message}");
            }
        }

        private void InitializeTimers()
        {
            animationTimer = new DispatcherTimer();
            animationTimer.Interval = TimeSpan.FromMilliseconds(60);
            animationTimer.Tick += AnimationTimer_Tick;

            elapsedTimer = new DispatcherTimer();
            elapsedTimer.Interval = TimeSpan.FromSeconds(1);
            elapsedTimer.Tick += ElapsedTimer_Tick;
            startTime = DateTime.Now;
        }

        private void SetupCanvas()
        {
            GridCanvas.Children.Clear();
            for (int x = 0; x <= 4000; x += 100)
            {
                var line = new Line
                {
                    X1 = x,
                    Y1 = 0,
                    X2 = x,
                    Y2 = 4000,
                    Stroke = new SolidColorBrush(Color.FromArgb(30, 0, 255, 65)),
                    StrokeThickness = 0.5
                };
                GridCanvas.Children.Add(line);
            }

            for (int y = 0; y <= 4000; y += 100)
            {
                var line = new Line
                {
                    X1 = 0,
                    Y1 = y,
                    X2 = 4000,
                    Y2 = y,
                    Stroke = new SolidColorBrush(Color.FromArgb(30, 0, 255, 65)),
                    StrokeThickness = 0.5
                };
                GridCanvas.Children.Add(line);
            }
        }

        private void StartAnimations()
        {
            animationTimer.Start();
            elapsedTimer.Start();
            StatusText.Text = "ACTIVE";
        }

        private void AnimationTimer_Tick(object sender, EventArgs e)
        {
            ringAngle += 0.5;
            if (ringAngle >= 360) ringAngle = 0;

            var outerTransform = new RotateTransform(ringAngle, 2000, 2000);
            OuterRing.RenderTransform = outerTransform;

            var midTransform = new RotateTransform(-ringAngle * 0.7, 2000, 2000);
            MidRing.RenderTransform = midTransform;

            var innerTransform = new RotateTransform(ringAngle * 0.5, 2000, 2000);
            InnerRing.RenderTransform = innerTransform;

            double pulse = Math.Sin(DateTime.Now.TimeOfDay.TotalSeconds * 2) * 0.05 + 1;
            CenterNode.RenderTransform = new ScaleTransform(pulse, pulse, 100, 100);
        }

        private void ElapsedTimer_Tick(object sender, EventArgs e)
        {
            var elapsed = DateTime.Now - startTime;
            TimeElapsed.Text = elapsed.ToString(@"hh\:mm\:ss");
        }

        private void LoadTargets()
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT DISTINCT target FROM scans ORDER BY target", conn);
                using var reader = cmd.ExecuteReader();

                TargetSelector.Items.Clear();

                while (reader.Read())
                {
                    string target = reader["target"].ToString();
                    if (!TargetSelector.Items.Contains(target))
                    {
                        TargetSelector.Items.Add(target);
                    }
                }

                LogMessage($">> LOADED {TargetSelector.Items.Count} TARGETS");
            }
            catch (Exception ex)
            {
                LogMessage($">> ERROR LOADING TARGETS: {ex.Message}");
            }
        }

        private void TargetSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TargetSelector.SelectedItem != null)
            {
                string target = TargetSelector.SelectedItem.ToString();
                LoadTargetData(target);
            }
        }

        private void LoadTargetData(string targetName)
        {
            try
            {
                ClearVisualization();
                StatusText.Text = "PROCESSING";
                LogMessage($">> LOADING DATA FOR: {targetName.ToUpper()}");

                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var scanCmd = new SQLiteCommand("SELECT id, ip_address, hostname FROM scans WHERE target = @target ORDER BY id DESC LIMIT 1", conn);
                scanCmd.Parameters.AddWithValue("@target", targetName);

                using var scanReader = scanCmd.ExecuteReader();
                if (!scanReader.Read())
                {
                    LogMessage($">> NO DATA FOUND FOR '{targetName}'");
                    StatusText.Text = "NO DATA";
                    return;
                }

                currentScanId = Convert.ToInt64(scanReader["id"]);
                string targetIp = scanReader["ip_address"]?.ToString() ?? "Unknown";
                string hostname = scanReader["hostname"]?.ToString() ?? targetName;

                CenterText.Text = targetName.ToUpper();
                CenterSubtext.Text = $"{targetIp}\n{hostname}";

                LoadAndVisualizeData(currentScanId);

                NodeCount.Text = createdNodes.Count.ToString();
                StatusText.Text = "VISUALIZED";
                LogMessage($">> VISUALIZATION COMPLETE - {createdNodes.Count} NODES CREATED");
            }
            catch (Exception ex)
            {
                LogMessage($">> ERROR: {ex.Message}");
                StatusText.Text = "ERROR";
            }
        }

        private void LoadAndVisualizeData(long scanId)
        {
            VisualizePorts(scanId);
            VisualizeTechnologies(scanId);
            VisualizeSecurityIssues(scanId);
            VisualizeGeolocation(scanId);
            VisualizeNetworkInfo(scanId);
            VisualizeHttpResponse(scanId);
        }

        private void VisualizePorts(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT port, service FROM ports WHERE scan_id = @scanId AND status = 'open' ORDER BY port", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                var ports = new List<(int Port, string Service)>();

                while (reader.Read())
                {
                    ports.Add((Convert.ToInt32(reader["port"]), reader["service"]?.ToString() ?? "Unknown"));
                }

                if (ports.Count == 0)
                {
                    LogMessage(">> NO OPEN PORTS");
                    return;
                }

                double radius = 400;
                double angleStep = 360.0 / ports.Count;

                for (int i = 0; i < ports.Count; i++)
                {
                    double angle = i * angleStep * Math.PI / 180.0;
                    double x = centerX + radius * Math.Cos(angle);
                    double y = centerY + radius * Math.Sin(angle);

                    CreateNode(x, y, $"PORT {ports[i].Port}", ports[i].Service, "#00AAFF");
                    CreateLink(centerX, centerY, x, y, "#00AAFF");
                }

                LogMessage($">> VISUALIZED {ports.Count} PORTS");
            }
            catch (Exception ex)
            {
                LogMessage($">> PORTS ERROR: {ex.Message}");
            }
        }

        private void VisualizeTechnologies(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT technology FROM technologies WHERE scan_id = @scanId ORDER BY technology", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                var technologies = new List<string>();

                while (reader.Read())
                {
                    technologies.Add(reader["technology"].ToString());
                }

                if (technologies.Count == 0) return;

                double radius = 600;
                double angleStep = 360.0 / technologies.Count;

                for (int i = 0; i < technologies.Count; i++)
                {
                    double angle = i * angleStep * Math.PI / 180.0;
                    double x = centerX + radius * Math.Cos(angle);
                    double y = centerY + radius * Math.Sin(angle);

                    CreateNode(x, y, technologies[i].ToUpper(), "Technology", "#FFD700");
                    if (i % 2 == 0)
                    {
                        CreateLink(centerX, centerY, x, y, "#FFD700");
                    }
                }

                LogMessage($">> VISUALIZED {technologies.Count} TECHNOLOGIES");
            }
            catch (Exception ex)
            {
                LogMessage($">> TECHNOLOGIES ERROR: {ex.Message}");
            }
        }

        private void VisualizeSecurityIssues(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT description, severity FROM security_issues WHERE scan_id = @scanId ORDER BY severity DESC", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                var issues = new List<(string Description, string Severity)>();

                while (reader.Read())
                {
                    issues.Add((reader["description"].ToString(), reader["severity"]?.ToString() ?? "Medium"));
                }

                if (issues.Count == 0) return;

                double radius = 800;
                double angleStep = 360.0 / issues.Count;

                for (int i = 0; i < issues.Count; i++)
                {
                    double angle = i * angleStep * Math.PI / 180.0;
                    double x = centerX + radius * Math.Cos(angle);
                    double y = centerY + radius * Math.Sin(angle);

                    string desc = issues[i].Description;
                    string displayName = desc.Length > 15 ? desc.Substring(0, 12) + "..." : desc;
                    string severity = issues[i].Severity;
                    string color = severity == "High" ? "#FF3131" : severity == "Medium" ? "#FFA500" : "#FFFF00";

                    CreateNode(x, y, displayName, severity, color);
                    CreateLink(centerX, centerY, x, y, color);
                }

                LogMessage($">> VISUALIZED {issues.Count} SECURITY ISSUES");
            }
            catch (Exception ex)
            {
                LogMessage($">> SECURITY ERROR: {ex.Message}");
            }
        }

        private void VisualizeGeolocation(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT country, city, region, isp FROM geolocation WHERE scan_id = @scanId LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string country = reader["country"]?.ToString() ?? "Unknown";
                    string city = reader["city"]?.ToString() ?? "Unknown";
                    string region = reader["region"]?.ToString() ?? "Unknown";
                    string isp = reader["isp"]?.ToString() ?? "Unknown";

                    double x = centerX + 1000 * Math.Cos(45 * Math.PI / 180.0);
                    double y = centerY + 1000 * Math.Sin(45 * Math.PI / 180.0);

                    CreateNode(x, y, "GEOLOCATION", $"{city}, {country}", "#00FF00");
                    CreateLink(centerX, centerY, x, y, "#00FF00");

                    LogMessage($">> VISUALIZED GEOLOCATION");
                }
            }
            catch (Exception ex)
            {
                LogMessage($">> GEO ERROR: {ex.Message}");
            }
        }

        private void VisualizeNetworkInfo(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT ping_time_ms, hop_count, network_type FROM network_info WHERE scan_id = @scanId LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    long pingTime = reader["ping_time_ms"] != DBNull.Value ? Convert.ToInt64(reader["ping_time_ms"]) : 0;
                    int hopCount = reader["hop_count"] != DBNull.Value ? Convert.ToInt32(reader["hop_count"]) : 0;
                    string networkType = reader["network_type"]?.ToString() ?? "IPv4";

                    double x = centerX + 1000 * Math.Cos(135 * Math.PI / 180.0);
                    double y = centerY + 1000 * Math.Sin(135 * Math.PI / 180.0);

                    CreateNode(x, y, "NETWORK", $"Ping: {pingTime}ms\nHops: {hopCount}", "#9370DB");
                    CreateLink(centerX, centerY, x, y, "#9370DB");

                    LogMessage($">> VISUALIZED NETWORK INFO");
                }
            }
            catch (Exception ex)
            {
                LogMessage($">> NETWORK ERROR: {ex.Message}");
            }
        }

        private void VisualizeHttpResponse(long scanId)
        {
            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var cmd = new SQLiteCommand("SELECT status_code, server_header, content_type, has_ssl FROM http_response WHERE scan_id = @scanId LIMIT 1", conn);
                cmd.Parameters.AddWithValue("@scanId", scanId);

                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    int statusCode = reader["status_code"] != DBNull.Value ? Convert.ToInt32(reader["status_code"]) : 0;
                    string server = reader["server_header"]?.ToString() ?? "Unknown";
                    string contentType = reader["content_type"]?.ToString() ?? "Unknown";
                    bool hasSSL = Convert.ToBoolean(reader["has_ssl"]);

                    double x = centerX + 1000 * Math.Cos(225 * Math.PI / 180.0);
                    double y = centerY + 1000 * Math.Sin(225 * Math.PI / 180.0);

                    CreateNode(x, y, "HTTP", $"Status: {statusCode}\nServer: {server}", "#FF69B4");
                    CreateLink(centerX, centerY, x, y, "#FF69B4");

                    LogMessage($">> VISUALIZED HTTP INFO");
                }
            }
            catch (Exception ex)
            {
                LogMessage($">> HTTP ERROR: {ex.Message}");
            }
        }

        private void CreateNode(double x, double y, string title, string subtitle, string colorHex)
        {
            var color = (Color)ColorConverter.ConvertFromString(colorHex);
            var brush = new SolidColorBrush(color);

            var node = new Border
            {
                Width = 160,
                Height = 160,
                Background = new SolidColorBrush(Color.FromArgb(40, color.R, color.G, color.B)),
                BorderBrush = brush,
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(10),
                Cursor = Cursors.Hand
            };

            var content = new StackPanel();

            var titleText = new TextBlock
            {
                Text = title,
                Foreground = brush,
                FontSize = 13,
                FontWeight = FontWeights.Bold,
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                HorizontalAlignment = HorizontalAlignment.Center
            };

            var subtitleText = new TextBlock
            {
                Text = subtitle,
                Foreground = new SolidColorBrush(Color.FromArgb(180, color.R, color.G, color.B)),
                FontSize = 10,
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 5, 0, 0)
            };

            content.Children.Add(titleText);
            content.Children.Add(subtitleText);
            node.Child = content;

            Canvas.SetLeft(node, x - node.Width / 2);
            Canvas.SetTop(node, y - node.Height / 2);

            node.MouseEnter += (s, e) =>
            {
                node.BorderThickness = new Thickness(3);
                node.Background = new SolidColorBrush(Color.FromArgb(80, color.R, color.G, color.B));
                node.Effect = new DropShadowEffect
                {
                    Color = color,
                    BlurRadius = 25,
                    ShadowDepth = 0,
                    Opacity = 0.9
                };
            };

            node.MouseLeave += (s, e) =>
            {
                node.BorderThickness = new Thickness(2);
                node.Background = new SolidColorBrush(Color.FromArgb(40, color.R, color.G, color.B));
                node.Effect = null;
            };

            node.MouseLeftButtonDown += (s, e) =>
            {
                LogMessage($">> SELECTED: {title}");
            };

            NodesCanvas.Children.Add(node);
            createdNodes.Add(node);
        }

        private void CreateLink(double x1, double y1, double x2, double y2, string colorHex)
        {
            var color = (Color)ColorConverter.ConvertFromString(colorHex);
            var brush = new SolidColorBrush(Color.FromArgb(120, color.R, color.G, color.B));

            var link = new Line
            {
                X1 = x1,
                Y1 = y1,
                X2 = x2,
                Y2 = y2,
                Stroke = brush,
                StrokeThickness = 2,
                StrokeDashArray = new DoubleCollection { 4, 3 },
                Opacity = 0.6
            };

            LinksCanvas.Children.Add(link);
            createdLinks.Add(link);
        }

        private void ClearVisualization()
        {
            foreach (var node in createdNodes)
            {
                NodesCanvas.Children.Remove(node);
            }

            foreach (var link in createdLinks)
            {
                LinksCanvas.Children.Remove(link);
            }

            createdNodes.Clear();
            createdLinks.Clear();

            NodeCount.Text = "0";
            NeuralLog.Text = "";
        }

        private void LogMessage(string message)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            Dispatcher.BeginInvoke(() =>
            {
                NeuralLog.Text += $"[{timestamp}] {message}\n";
                LogScroller.ScrollToEnd();
            });
        }

        private void MapCanvas_MouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (!isInitialized) return;

            var mousePos = e.GetPosition(MapCanvas);
            double zoomFactor = e.Delta > 0 ? ZOOM_FACTOR : 1 / ZOOM_FACTOR;
            double newZoom = zoomLevel * zoomFactor;

            if (newZoom >= MIN_ZOOM && newZoom <= MAX_ZOOM)
            {
                double scale = zoomFactor;

                double offsetX = (mousePos.X - translateTransform.X) * (scale - 1);
                double offsetY = (mousePos.Y - translateTransform.Y) * (scale - 1);

                translateTransform.X -= offsetX;
                translateTransform.Y -= offsetY;

                scaleTransform.ScaleX *= scale;
                scaleTransform.ScaleY *= scale;

                zoomLevel = newZoom;
            }

            e.Handled = true;
        }

        private void MapCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (!isInitialized) return;

            lastMousePosition = e.GetPosition(MainScrollViewer);
            isDragging = true;
            MapCanvas.CaptureMouse();
            MapCanvas.Cursor = Cursors.ScrollAll;
            e.Handled = true;
        }

        private void MapCanvas_MouseMove(object sender, MouseEventArgs e)
        {
            if (!isInitialized || !isDragging) return;

            var currentPosition = e.GetPosition(MainScrollViewer);
            var delta = currentPosition - lastMousePosition;

            translateTransform.X += delta.X;
            translateTransform.Y += delta.Y;

            lastMousePosition = currentPosition;
            e.Handled = true;
        }

        private void MapCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (!isInitialized) return;

            isDragging = false;
            MapCanvas.ReleaseMouseCapture();
            MapCanvas.Cursor = Cursors.Arrow;
            e.Handled = true;
        }

        private void ResetView_Click(object sender, RoutedEventArgs e)
        {
            ResetView();
        }

        private void ResetView()
        {
            zoomLevel = 1.0;
            scaleTransform.ScaleX = 1.0;
            scaleTransform.ScaleY = 1.0;
            translateTransform.X = 0;
            translateTransform.Y = 0;
            CenterView();
        }

        private void CenterView()
        {
            Dispatcher.BeginInvoke(() =>
            {
                MainScrollViewer.ScrollToHorizontalOffset(1800);
                MainScrollViewer.ScrollToVerticalOffset(1800);
            });
        }

        private void ZoomIn_Click(object sender, RoutedEventArgs e)
        {
            if (zoomLevel < MAX_ZOOM)
            {
                zoomLevel *= ZOOM_FACTOR;
                scaleTransform.ScaleX = zoomLevel;
                scaleTransform.ScaleY = zoomLevel;
            }
        }

        private void ZoomOut_Click(object sender, RoutedEventArgs e)
        {
            if (zoomLevel > MIN_ZOOM)
            {
                zoomLevel /= ZOOM_FACTOR;
                scaleTransform.ScaleX = zoomLevel;
                scaleTransform.ScaleY = zoomLevel;
            }
        }

        private void ClearMap_Click(object sender, RoutedEventArgs e)
        {
            ClearVisualization();
            CenterText.Text = "TARGET";
            CenterSubtext.Text = "Select a target";
        }

        private void GenerateReport_Click(object sender, RoutedEventArgs e)
        {
            if (TargetSelector.SelectedItem == null)
            {
                MessageBox.Show("Please select a target first", "No Target Selected",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string target = TargetSelector.SelectedItem.ToString();
            string report = GenerateTargetReport(target);

            var saveDialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"report_{target}_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveDialog.FileName, report);
                LogMessage($">> REPORT SAVED: {saveDialog.FileName}");
                MessageBox.Show("Report generated successfully!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private string GenerateTargetReport(string target)
        {
            var report = new StringBuilder();
            report.AppendLine("=== VRAX INTELLIGENCE REPORT ===");
            report.AppendLine($"Target: {target}");
            report.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine();

            try
            {
                using var conn = new SQLiteConnection(connStr);
                conn.Open();

                using var scanCmd = new SQLiteCommand("SELECT * FROM scans WHERE target = @target ORDER BY id DESC LIMIT 1", conn);
                scanCmd.Parameters.AddWithValue("@target", target);

                using var scanReader = scanCmd.ExecuteReader();
                if (scanReader.Read())
                {
                    report.AppendLine("Scan Information:");
                    report.AppendLine($"- IP Address: {scanReader["ip_address"]}");
                    report.AppendLine($"- Hostname: {scanReader["hostname"]}");
                    report.AppendLine($"- Status: {scanReader["status"]}");
                    report.AppendLine($"- Started: {Convert.ToDateTime(scanReader["start_time"]):yyyy-MM-dd HH:mm:ss}");
                    report.AppendLine();

                    long scanId = Convert.ToInt64(scanReader["id"]);

                    using var portsCmd = new SQLiteCommand("SELECT port, service FROM ports WHERE scan_id = @scanId AND status = 'open' ORDER BY port", conn);
                    portsCmd.Parameters.AddWithValue("@scanId", scanId);

                    using var portsReader = portsCmd.ExecuteReader();
                    report.AppendLine("Open Ports:");
                    while (portsReader.Read())
                    {
                        report.AppendLine($"- {portsReader["port"]}: {portsReader["service"]}");
                    }
                    report.AppendLine();

                    using var techCmd = new SQLiteCommand("SELECT technology FROM technologies WHERE scan_id = @scanId ORDER BY technology", conn);
                    techCmd.Parameters.AddWithValue("@scanId", scanId);

                    using var techReader = techCmd.ExecuteReader();
                    report.AppendLine("Technologies:");
                    while (techReader.Read())
                    {
                        report.AppendLine($"- {techReader["technology"]}");
                    }
                }
            }
            catch (Exception ex)
            {
                report.AppendLine($"Error: {ex.Message}");
            }

            return report.ToString();
        }

        private void ExportVisualization_Click(object sender, RoutedEventArgs e)
        {
            if (TargetSelector.SelectedItem == null)
            {
                MessageBox.Show("Please select a target first", "No Target",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var saveDialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                FileName = $"visualization_{TargetSelector.SelectedItem}_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };

            if (saveDialog.ShowDialog() == true)
            {
                string report = GenerateTargetReport(TargetSelector.SelectedItem.ToString());
                File.WriteAllText(saveDialog.FileName, report);
                LogMessage($">> VISUALIZATION DATA SAVED");
                MessageBox.Show("Data exported successfully!", "Success",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            animationTimer?.Stop();
            elapsedTimer?.Stop();
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            animationTimer?.Stop();
            elapsedTimer?.Stop();
            base.OnClosing(e);
        }
    }
}