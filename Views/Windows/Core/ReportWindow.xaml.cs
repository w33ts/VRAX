using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace VRAX
{
    public partial class ReportWindow : Window, INotifyPropertyChanged
    {
        private ObservableCollection<Finding> findings = new ObservableCollection<Finding>();
        private ObservableCollection<Finding> filteredFindings = new ObservableCollection<Finding>();
        private Finding selectedFinding;
        private ObservableCollection<EvidenceItem> evidence = new ObservableCollection<EvidenceItem>();
        private string filterSeverity = "ALL";
        private string filterStatus = "ALL";
        private string filterModule = "ALL";
        private readonly string dbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "findings.json");
        private readonly string evidenceDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "evidence");

        public ObservableCollection<Finding> Findings
        {
            get => findings;
            set { findings = value; OnPropertyChanged(); }
        }

        public ObservableCollection<Finding> FilteredFindings
        {
            get => filteredFindings;
            set { filteredFindings = value; OnPropertyChanged(); }
        }

        public Finding SelectedFinding
        {
            get => selectedFinding;
            set { selectedFinding = value; OnPropertyChanged(); LoadFinding(value); }
        }

        public ObservableCollection<EvidenceItem> Evidence
        {
            get => evidence;
            set { evidence = value; OnPropertyChanged(); }
        }

        public ReportWindow()
        {
            InitializeComponent();
            DataContext = this;

            if (!Directory.Exists(evidenceDir))
                Directory.CreateDirectory(evidenceDir);

            LoadData();
            SetupEvents();
            NewFinding();
            UpdateStatus();
        }

        private void SetupEvents()
        {
            GenerateReportBtn.Click += (s, e) => GenerateReport();
            ExportHtmlBtn.Click += (s, e) => ExportHtml();
            SyncFindingsBtn.Click += (s, e) => { LoadData(); UpdateStatus(); };
            ApplyFilterBtn.Click += (s, e) => ApplyFilters();
            FindingsList.SelectionChanged += (s, e) => SelectedFinding = FindingsList.SelectedItem as Finding;
            AddEvidenceBtn.Click += (s, e) => AddEvidence();
            SaveFindingBtn.Click += (s, e) => SaveFinding();
            NewFindingBtn.Click += (s, e) => NewFinding();
            DeleteFindingBtn.Click += (s, e) => DeleteFinding();
        }

        private void LoadData()
        {
            try
            {
                if (File.Exists(dbPath))
                {
                    string json = File.ReadAllText(dbPath);
                    var list = JsonSerializer.Deserialize<List<FindingSerializable>>(json);
                    Findings = new ObservableCollection<Finding>(list.Select(f => f.ToFinding(evidenceDir)));
                }
                else
                {
                    Findings = new ObservableCollection<Finding>();
                }
                ApplyFilters();
                UpdateStatus();
            }
            catch
            {
                Findings = new ObservableCollection<Finding>();
            }
        }

        private void SaveData()
        {
            try
            {
                var list = Findings.Select(f => FindingSerializable.FromFinding(f)).ToList();
                string json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(dbPath, json);
                UpdateStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Save failed: {ex.Message}");
            }
        }

        private void ApplyFilters()
        {
            filterSeverity = FilterSeverity.Text.ToUpper();
            filterStatus = FilterStatus.Text.ToUpper();
            filterModule = FilterModule.Text.ToUpper();

            var query = Findings.AsEnumerable();

            if (filterSeverity != "ALL")
                query = query.Where(f => f.Severity.ToUpper().Contains(filterSeverity));

            if (filterStatus != "ALL")
                query = query.Where(f => f.Status.ToUpper().Contains(filterStatus));

            if (filterModule != "ALL")
                query = query.Where(f => f.Module.ToUpper().Contains(filterModule));

            FilteredFindings = new ObservableCollection<Finding>(query);
            FindingsList.ItemsSource = FilteredFindings;
            FindingCount.Text = $"FINDINGS: {Findings.Count} | SHOWING: {FilteredFindings.Count}";
        }

        private void LoadFinding(Finding f)
        {
            if (f == null) return;

            FindingTitle.Text = f.Title;
            SeverityInput.Text = f.Severity;
            CvssInput.Text = f.CVSS.ToString("F1");
            StatusInput.Text = f.Status;
            AssignedInput.Text = f.AssignedTo;
            ModuleInput.Text = f.Module;
            TargetInput.Text = f.Target;
            OwaspInput.Text = f.Owasp;
            DescriptionInput.Text = f.Description;
            RemediationInput.Text = f.Remediation;
            Evidence = new ObservableCollection<EvidenceItem>(f.EvidenceItems ?? new List<EvidenceItem>());
            EvidenceList.ItemsSource = Evidence;
        }

        private void NewFinding()
        {
            SelectedFinding = new Finding
            {
                Id = Guid.NewGuid().ToString(),
                Title = "NEW FINDING",
                Severity = "MEDIUM",
                Status = "OPEN",
                CVSS = 5.0,
                AssignedTo = "analyst",
                Module = "MANUAL",
                Target = "https://",
                Owasp = "A01:2021-Broken Access Control",
                Description = "DESCRIBE THE VULNERABILITY",
                Remediation = "PROVIDE REMEDIATION",
                EvidenceItems = new List<EvidenceItem>(),
                Created = DateTime.Now,
                Modified = DateTime.Now
            };
            Evidence.Clear();
        }

        private void SaveFinding()
        {
            if (SelectedFinding == null) return;

            SelectedFinding.Title = FindingTitle.Text;
            SelectedFinding.Severity = SeverityInput.Text;
            SelectedFinding.CVSS = double.TryParse(CvssInput.Text, out var cvss) ? cvss : 5.0;
            SelectedFinding.Status = StatusInput.Text;
            SelectedFinding.AssignedTo = AssignedInput.Text;
            SelectedFinding.Module = ModuleInput.Text;
            SelectedFinding.Target = TargetInput.Text;
            SelectedFinding.Owasp = OwaspInput.Text;
            SelectedFinding.Description = DescriptionInput.Text;
            SelectedFinding.Remediation = RemediationInput.Text;
            SelectedFinding.EvidenceItems = Evidence.ToList();
            SelectedFinding.Modified = DateTime.Now;

            var existing = Findings.FirstOrDefault(f => f.Id == SelectedFinding.Id);
            if (existing == null)
                Findings.Add(SelectedFinding);

            SaveData();
            ApplyFilters();
            StatusText.Text = "SAVED";
            BottomStatus.Text = $"Saved: {SelectedFinding.Title}";
        }

        private void DeleteFinding()
        {
            if (SelectedFinding == null) return;

            var result = MessageBox.Show($"Delete '{SelectedFinding.Title}'?", "Confirm", MessageBoxButton.YesNo);
            if (result == MessageBoxResult.Yes)
            {
                Findings.Remove(SelectedFinding);
                SaveData();
                ApplyFilters();
                NewFinding();
                StatusText.Text = "DELETED";
            }
        }

        private void AddEvidence()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Multiselect = true,
                Filter = "All Files (*.*)|*.*"
            };

            if (dialog.ShowDialog() == true)
            {
                foreach (string file in dialog.FileNames)
                {
                    try
                    {
                        string fileName = $"{Guid.NewGuid():N}_{Path.GetFileName(file)}";
                        string destPath = Path.Combine(evidenceDir, fileName);
                        File.Copy(file, destPath);

                        Evidence.Add(new EvidenceItem
                        {
                            FileName = fileName,
                            OriginalName = Path.GetFileName(file),
                            FilePath = destPath,
                            IsImage = new[] { ".png", ".jpg", ".jpeg", ".gif", ".bmp" }
                                .Contains(Path.GetExtension(file).ToLower()),
                            AddedDate = DateTime.Now
                        });
                    }
                    catch { }
                }
                SaveFinding();
            }
        }

        private void GenerateReport()
        {
            try
            {
                StatusText.Text = "GENERATING...";

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    FileName = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html",
                    Filter = "HTML Files|*.html"
                };

                if (dialog.ShowDialog() == true)
                {
                    string reportDir = Path.GetDirectoryName(dialog.FileName);
                    string evidenceReportDir = Path.Combine(reportDir, "evidence");

                    if (Directory.Exists(evidenceReportDir))
                        Directory.Delete(evidenceReportDir, true);

                    Directory.CreateDirectory(evidenceReportDir);

                    if (Directory.Exists(evidenceDir))
                    {
                        foreach (string file in Directory.GetFiles(evidenceDir))
                        {
                            string fileName = Path.GetFileName(file);
                            string destPath = Path.Combine(evidenceReportDir, fileName);
                            File.Copy(file, destPath, true);
                        }
                    }

                    string html = BuildHtmlReport();
                    File.WriteAllText(dialog.FileName, html);

                    StatusText.Text = "COMPLETE";
                    BottomStatus.Text = $"Report saved: {Path.GetFileName(dialog.FileName)}";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Report failed: {ex.Message}");
                StatusText.Text = "FAILED";
            }
        }

        private void ExportHtml()
        {
            try
            {
                string html = BuildHtmlReport();

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    FileName = $"export_{DateTime.Now:yyyyMMdd_HHmmss}.html",
                    Filter = "HTML Files|*.html"
                };

                if (dialog.ShowDialog() == true)
                {
                    File.WriteAllText(dialog.FileName, html);
                    StatusText.Text = "EXPORTED";
                    BottomStatus.Text = $"Exported: {Path.GetFileName(dialog.FileName)}";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}");
            }
        }

        private string BuildHtmlReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head>");
            sb.AppendLine("<meta charset='UTF-8'><title>VRAX REPORT</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',monospace;margin:40px}");
            sb.AppendLine(".header{background:#121212;padding:30px;border-left:5px solid #8b0000;margin-bottom:30px}");
            sb.AppendLine(".finding{background:#1a1a1a;padding:25px;margin:25px 0;border:1px solid #333}");
            sb.AppendLine(".critical{border-left:5px solid #ff0000}");
            sb.AppendLine(".high{border-left:5px solid #ff4444}");
            sb.AppendLine(".medium{border-left:5px solid #ff8800}");
            sb.AppendLine(".low{border-left:5px solid #ffff00}");
            sb.AppendLine(".info{border-left:5px solid #00ffff}");
            sb.AppendLine("h1{color:#8b0000}");
            sb.AppendLine("h2{color:#cc6666}");
            sb.AppendLine(".badge{background:#8b0000;padding:5px 15px;border-radius:20px;display:inline-block;margin-right:10px}");
            sb.AppendLine(".evidence{max-width:600px;margin:15px 0;border:2px solid #444}");
            sb.AppendLine("</style></head><body>");

            sb.AppendLine("<div class='header'>");
            sb.AppendLine("<h1>VRAX // SECURITY REPORT</h1>");
            sb.AppendLine($"<p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm}</p>");
            sb.AppendLine($"<p>Total Findings: {Findings.Count}</p>");
            sb.AppendLine("</div>");

            int num = 1;
            foreach (var f in Findings.OrderByDescending(f => GetSeverityValue(f.Severity)))
            {
                sb.AppendLine($"<div class='finding {f.Severity.ToLower()}'>");
                sb.AppendLine($"<h2>FINDING {num++}: {f.Title}</h2>");
                sb.AppendLine($"<span class='badge'>{f.Severity}</span>");
                sb.AppendLine($"<span style='margin-left:20px'><strong>CVSS:</strong> {f.CVSS:F1}</span>");
                sb.AppendLine($"<p><strong>Target:</strong> {f.Target}</p>");
                sb.AppendLine($"<p><strong>Module:</strong> {f.Module}</p>");
                sb.AppendLine($"<p><strong>OWASP:</strong> {f.Owasp}</p>");
                sb.AppendLine($"<h3>Description</h3><p>{f.Description.Replace("\n", "<br>")}</p>");
                sb.AppendLine($"<h3>Remediation</h3><p>{f.Remediation.Replace("\n", "<br>")}</p>");

                if (f.EvidenceItems != null && f.EvidenceItems.Any())
                {
                    sb.AppendLine("<h3>Evidence</h3>");
                    foreach (var e in f.EvidenceItems)
                    {
                        if (e.IsImage)
                            sb.AppendLine($"<img src='evidence/{e.FileName}' class='evidence'/><br>");
                        else
                            sb.AppendLine($"<p>📎 {e.OriginalName}</p>");
                    }
                }
                sb.AppendLine("</div>");
            }

            sb.AppendLine("<div style='margin-top:50px;padding:20px;background:#121212;font-size:12px;color:#888'>");
            sb.AppendLine("CONFIDENTIAL - VRAX SECURITY SUITE</div>");
            sb.AppendLine("</body></html>");

            return sb.ToString();
        }

        private int GetSeverityValue(string s)
        {
            return s switch
            {
                "CRITICAL" => 5,
                "HIGH" => 4,
                "MEDIUM" => 3,
                "LOW" => 2,
                "INFO" => 1,
                _ => 0
            };
        }

        private void UpdateStatus()
        {
            StatusText.Text = "READY";
            BottomStatus.Text = "READY";
            DbStatus.Text = $"DATABASE: {(File.Exists(dbPath) ? "READY" : "NEW")}";
            FindingCount.Text = $"FINDINGS: {Findings.Count}";
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }

    public class Finding : INotifyPropertyChanged
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; }
        public double CVSS { get; set; }
        public string AssignedTo { get; set; }
        public string Module { get; set; }
        public string Target { get; set; }
        public string Owasp { get; set; }
        public string Description { get; set; }
        public string Remediation { get; set; }
        public List<EvidenceItem> EvidenceItems { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }

        public Brush SeverityColor
        {
            get
            {
                return Severity switch
                {
                    "CRITICAL" => new SolidColorBrush(Colors.Red),
                    "HIGH" => new SolidColorBrush(Color.FromRgb(255, 68, 68)),
                    "MEDIUM" => new SolidColorBrush(Colors.Orange),
                    "LOW" => new SolidColorBrush(Colors.Yellow),
                    "INFO" => new SolidColorBrush(Colors.Cyan),
                    _ => new SolidColorBrush(Colors.Gray)
                };
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public class EvidenceItem
    {
        public string FileName { get; set; }
        public string OriginalName { get; set; }
        public string FilePath { get; set; }
        public bool IsImage { get; set; }
        public DateTime AddedDate { get; set; }
        public string DisplayName => $"{OriginalName} ({AddedDate:HH:mm})";
    }

    public class FindingSerializable
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; }
        public double CVSS { get; set; }
        public string AssignedTo { get; set; }
        public string Module { get; set; }
        public string Target { get; set; }
        public string Owasp { get; set; }
        public string Description { get; set; }
        public string Remediation { get; set; }
        public List<string> EvidenceFiles { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }

        public static FindingSerializable FromFinding(Finding f)
        {
            return new FindingSerializable
            {
                Id = f.Id,
                Title = f.Title,
                Severity = f.Severity,
                Status = f.Status,
                CVSS = f.CVSS,
                AssignedTo = f.AssignedTo,
                Module = f.Module,
                Target = f.Target,
                Owasp = f.Owasp,
                Description = f.Description,
                Remediation = f.Remediation,
                EvidenceFiles = f.EvidenceItems?.Select(e => e.FileName).ToList() ?? new List<string>(),
                Created = f.Created,
                Modified = f.Modified
            };
        }

        public Finding ToFinding(string evidenceDir)
        {
            var items = new List<EvidenceItem>();
            if (EvidenceFiles != null)
            {
                foreach (string file in EvidenceFiles)
                {
                    string path = Path.Combine(evidenceDir, file);
                    if (File.Exists(path))
                    {
                        items.Add(new EvidenceItem
                        {
                            FileName = file,
                            OriginalName = file.Substring(file.IndexOf('_') + 1),
                            FilePath = path,
                            IsImage = new[] { ".png", ".jpg", ".jpeg", ".gif", ".bmp" }
                                .Contains(Path.GetExtension(file).ToLower()),
                            AddedDate = File.GetCreationTime(path)
                        });
                    }
                }
            }

            return new Finding
            {
                Id = Id,
                Title = Title,
                Severity = Severity,
                Status = Status,
                CVSS = CVSS,
                AssignedTo = AssignedTo,
                Module = Module,
                Target = Target,
                Owasp = Owasp,
                Description = Description,
                Remediation = Remediation,
                EvidenceItems = items,
                Created = Created,
                Modified = Modified
            };
        }
    }
}
