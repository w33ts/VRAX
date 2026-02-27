using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ReconSuite
{
    public partial class ForensicsWindow : Window
    {
        private byte[] fileData;
        private string currentFilePath;
        private int bytesPerLine = 16;
        private bool isUpdating = false;
        private List<int> searchResults = new List<int>();
        private int currentSearchIndex = -1;
        private Dictionary<string, string> exifData = new Dictionary<string, string>();
        private Dictionary<string, string> fileMetadata = new Dictionary<string, string>();
        private List<string> ipAddresses = new List<string>();
        private List<string> domains = new List<string>();
        private List<string> urls = new List<string>();
        private List<string> emails = new List<string>();
        private List<string> filePaths = new List<string>();
        private HttpClient httpClient = new HttpClient();

        public ForensicsWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            BytesPerLineCombo.SelectionChanged += BytesPerLineCombo_SelectionChanged;
            ClearAllData();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            httpClient?.Dispose();
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.F5)
            {
                RefreshAnalysis();
            }
            else if (e.Key == Key.F2)
            {
                SaveFileBtn_Click(null, null);
            }
            else if (e.Key == Key.F3 && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                GoToBtn_Click(null, null);
            }
        }

        private void ClearAllData()
        {
            fileData = null;
            currentFilePath = null;
            FileNameText.Text = "None";
            FileSizeText.Text = "0 bytes";
            FileTypeText.Text = "Unknown";
            MimeTypeText.Text = "Unknown";
            MagicBytesText.Text = "None";
            FileExtensionText.Text = "None";
            CreatedText.Text = "Unknown";
            ModifiedText.Text = "Unknown";
            AccessedText.Text = "Unknown";
            MD5Text.Text = "None";
            SHA1Text.Text = "None";
            SHA256Text.Text = "None";
            SHA512Text.Text = "None";
            CRC32Text.Text = "None";
            EntropyText.Text = "0.0 bits/byte";
            EntropyBar.Value = 0;
            IPCountText.Text = "0";
            DomainCountText.Text = "0";
            URLCountText.Text = "0";
            EmailCountText.Text = "0";
            PathCountText.Text = "0";

            HexViewBox.Text = "";
            AsciiView.Text = "";
            OffsetNumbers.Text = "";
            StringsOutputBox.Text = "";

            exifData.Clear();
            fileMetadata.Clear();
            ipAddresses.Clear();
            domains.Clear();
            urls.Clear();
            emails.Clear();
            filePaths.Clear();

            UpdateExifDisplay();
            UpdateFileMetadataDisplay();
            UpdateIOCDisplays();
            

            StatusText.Text = "READY";
            StatusLed.Fill = Brushes.Green;
        }

        private void RefreshAnalysis()
        {
            if (fileData != null)
            {
                AnalyzeFile();
                StatusText.Text = "REFRESHED";
                StatusLed.Fill = Brushes.Green;
            }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshAnalysis();
        }

        private async void OpenFileBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "All Files (*.*)|*.*|Images|*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.tiff;*.webp|Audio|*.mp3;*.wav;*.flac;*.aac;*.ogg;*.m4a|Video|*.mp4;*.avi;*.mkv;*.mov;*.wmv;*.flv|Documents|*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.txt|Executables|*.exe;*.dll;*.so;*.dylib|Archives|*.zip;*.rar;*.7z;*.tar;*.gz|Disk Images|*.iso;*.img;*.vhd;*.vmdk",
                Title = "Select File for Forensic Analysis"
            };

            if (dialog.ShowDialog() == true)
            {
                LoadFile(dialog.FileName);
            }
        }

        private async void LoadFromURLBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new InputDialog("Enter URL:", "Load from URL");
            if (dialog.ShowDialog() == true)
            {
                try
                {
                    StatusText.Text = "DOWNLOADING...";
                    StatusLed.Fill = Brushes.Yellow;

                    string url = dialog.Answer;
                    byte[] data = await httpClient.GetByteArrayAsync(url);

                    fileData = data;
                    currentFilePath = url;

                    FileNameText.Text = GetFileNameFromUrl(url);
                    FileSizeText.Text = GetFileSizeString(fileData.Length);

                    AnalyzeFile();

                    StatusText.Text = "DOWNLOADED";
                    StatusLed.Fill = Brushes.Green;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error downloading file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    StatusText.Text = "ERROR";
                    StatusLed.Fill = Brushes.Red;
                }
            }
        }

        private string GetFileNameFromUrl(string url)
        {
            try
            {
                Uri uri = new Uri(url);
                string fileName = Path.GetFileName(uri.LocalPath);
                if (string.IsNullOrEmpty(fileName))
                {
                    fileName = "downloaded_file";
                }
                return fileName;
            }
            catch
            {
                return "downloaded_file";
            }
        }

        private void CompareFilesBtn_Click(object sender, RoutedEventArgs e)
        {
            if (fileData == null)
            {
                MessageBox.Show("Load a file first", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var dialog = new OpenFileDialog
            {
                Title = "Select File to Compare"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    byte[] otherData = File.ReadAllBytes(dialog.FileName);

                    StringBuilder comparison = new StringBuilder();
                    comparison.AppendLine($"=== FILE COMPARISON ===");
                    comparison.AppendLine($"Current: {Path.GetFileName(currentFilePath)} ({fileData.Length} bytes)");
                    comparison.AppendLine($"Other: {Path.GetFileName(dialog.FileName)} ({otherData.Length} bytes)");
                    comparison.AppendLine();

                    if (fileData.Length == otherData.Length)
                    {
                        int differences = 0;
                        for (int i = 0; i < fileData.Length; i++)
                        {
                            if (fileData[i] != otherData[i])
                            {
                                differences++;
                                if (differences <= 10)
                                {
                                    comparison.AppendLine($"Difference at offset 0x{i:X8}: 0x{fileData[i]:X2} vs 0x{otherData[i]:X2}");
                                }
                            }
                        }

                        comparison.AppendLine($"Total differences: {differences} bytes");

                        if (differences == 0)
                        {
                            comparison.AppendLine("Files are IDENTICAL");
                        }
                    }
                    else
                    {
                        comparison.AppendLine("Files are DIFFERENT sizes - cannot compare byte-for-byte");
                    }

                    MessageBox.Show(comparison.ToString(), "Comparison Results", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error comparing files: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void LoadFile(string path)
        {
            try
            {
                StatusText.Text = "LOADING...";
                StatusLed.Fill = Brushes.Yellow;

                currentFilePath = path;
                fileData = File.ReadAllBytes(path);

                FileNameText.Text = Path.GetFileName(path);
                FileSizeText.Text = GetFileSizeString(fileData.Length);
                FileExtensionText.Text = Path.GetExtension(path).ToLower();

                AnalyzeFile();

                StatusText.Text = "LOADED";
                StatusLed.Fill = Brushes.Green;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusText.Text = "ERROR";
                StatusLed.Fill = Brushes.Red;
            }
        }

        private void AnalyzeFile()
        {
            if (fileData == null) return;

            DetectFileType();
            GetTimestamps();
            ComputeHashes();
            CalculateEntropy();
            ExtractIOCs();
            ExtractExifData();
            ExtractFileMetadata();
            UpdateHexView();
        }

        private void DetectFileType()
        {
            if (fileData.Length < 8) return;

            byte[] magic = fileData.Take(8).ToArray();
            string hexMagic = BitConverter.ToString(magic).Replace("-", " ");
            string asciiMagic = "";
            foreach (byte b in magic)
            {
                asciiMagic += (b >= 32 && b <= 126) ? (char)b : '.';
            }
            MagicBytesText.Text = $"{hexMagic} ({asciiMagic})";

            string type = "Unknown";
            string mime = "application/octet-stream";

            if (magic[0] == 0xFF && magic[1] == 0xD8) { type = "JPEG Image"; mime = "image/jpeg"; }
            else if (magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E && magic[3] == 0x47) { type = "PNG Image"; mime = "image/png"; }
            else if (magic[0] == 0x47 && magic[1] == 0x49 && magic[2] == 0x46) { type = "GIF Image"; mime = "image/gif"; }
            else if (magic[0] == 0x42 && magic[1] == 0x4D) { type = "BMP Image"; mime = "image/bmp"; }
            else if (magic[0] == 0x49 && magic[1] == 0x49 && magic[2] == 0x2A && magic[3] == 0x00) { type = "TIFF Image (LE)"; mime = "image/tiff"; }
            else if (magic[0] == 0x4D && magic[1] == 0x4D && magic[2] == 0x00 && magic[3] == 0x2A) { type = "TIFF Image (BE)"; mime = "image/tiff"; }
            else if (magic[0] == 0x52 && magic[1] == 0x49 && magic[2] == 0x46 && magic[3] == 0x46) { type = "WEBP/RIFF"; mime = "image/webp"; }
            else if (magic[0] == 0x49 && magic[1] == 0x44 && magic[2] == 0x33) { type = "MP3 Audio (ID3)"; mime = "audio/mpeg"; }
            else if (magic[0] == 0xFF && magic[1] == 0xFB) { type = "MP3 Audio"; mime = "audio/mpeg"; }
            else if (magic[0] == 0x52 && magic[1] == 0x49 && magic[2] == 0x46 && magic[3] == 0x46) { type = "WAV Audio"; mime = "audio/wav"; }
            else if (magic[0] == 0x66 && magic[1] == 0x4C && magic[2] == 0x61 && magic[3] == 0x43) { type = "FLAC Audio"; mime = "audio/flac"; }
            else if (magic[0] == 0x4F && magic[1] == 0x67 && magic[2] == 0x67 && magic[3] == 0x53) { type = "OGG Audio"; mime = "audio/ogg"; }
            else if (magic[0] == 0x00 && magic[1] == 0x00 && magic[2] == 0x00 && magic[3] == 0x18 && magic[4] == 0x66 && magic[5] == 0x74 && magic[6] == 0x79 && magic[7] == 0x70) { type = "MP4 Video"; mime = "video/mp4"; }
            else if (magic[0] == 0x1A && magic[1] == 0x45 && magic[2] == 0xDF && magic[3] == 0xA3) { type = "MKV Video"; mime = "video/x-matroska"; }
            else if (magic[0] == 0x52 && magic[1] == 0x49 && magic[2] == 0x46 && magic[3] == 0x46) { type = "AVI Video"; mime = "video/avi"; }
            else if (magic[0] == 0x25 && magic[1] == 0x50 && magic[2] == 0x44 && magic[3] == 0x46) { type = "PDF Document"; mime = "application/pdf"; }
            else if (magic[0] == 0xD0 && magic[1] == 0xCF && magic[2] == 0x11 && magic[3] == 0xE0) { type = "DOC File (Old)"; mime = "application/msword"; }
            else if (magic[0] == 0x50 && magic[1] == 0x4B && magic[2] == 0x03 && magic[3] == 0x04)
            {
                if (FileExtensionText.Text == ".docx" || FileExtensionText.Text == ".xlsx" || FileExtensionText.Text == ".pptx")
                    type = "Office Open XML";
                else if (FileExtensionText.Text == ".zip")
                    type = "ZIP Archive";
                else
                    type = "ZIP/PK Archive";
                mime = "application/zip";
            }
            else if (magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46) { type = "ELF Executable"; mime = "application/x-executable"; }
            else if (magic[0] == 0x4D && magic[1] == 0x5A) { type = "DOS/Windows Executable"; mime = "application/x-dosexec"; }
            else if (magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE) { type = "Java Class File"; mime = "application/java-vm"; }
            else if (Encoding.ASCII.GetString(magic.Take(3).ToArray()) == "CWS") { type = "SWF File (Compressed)"; mime = "application/x-shockwave-flash"; }
            else if (Encoding.ASCII.GetString(magic.Take(3).ToArray()) == "FWS") { type = "SWF File"; mime = "application/x-shockwave-flash"; }

            FileTypeText.Text = type;
            MimeTypeText.Text = mime;
        }

        private void GetTimestamps()
        {
            if (string.IsNullOrEmpty(currentFilePath) || !File.Exists(currentFilePath)) return;

            try
            {
                FileInfo info = new FileInfo(currentFilePath);
                CreatedText.Text = info.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
                ModifiedText.Text = info.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
                AccessedText.Text = info.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch { }
        }

        private void ComputeHashes()
        {
            if (fileData == null) return;

            using (MD5 md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(fileData);
                MD5Text.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }

            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(fileData);
                SHA1Text.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(fileData);
                SHA256Text.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }

            using (SHA512 sha512 = SHA512.Create())
            {
                byte[] hash = sha512.ComputeHash(fileData);
                SHA512Text.Text = BitConverter.ToString(hash).Replace("-", "").ToLower();
            }

            CRC32Text.Text = ComputeCRC32(fileData).ToString("X8").ToLower();
        }

        private uint ComputeCRC32(byte[] data)
        {
            uint[] table = new uint[256];
            uint polynomial = 0xEDB88320;

            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 8; j > 0; j--)
                {
                    if ((crc & 1) == 1)
                        crc = (crc >> 1) ^ polynomial;
                    else
                        crc >>= 1;
                }
                table[i] = crc;
            }

            uint result = 0xFFFFFFFF;
            foreach (byte b in data)
            {
                result = table[(result ^ b) & 0xFF] ^ (result >> 8);
            }
            return result ^ 0xFFFFFFFF;
        }

        private void CalculateEntropy()
        {
            if (fileData == null || fileData.Length == 0) return;

            int[] frequencies = new int[256];
            foreach (byte b in fileData)
            {
                frequencies[b]++;
            }

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double p = (double)frequencies[i] / fileData.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            EntropyText.Text = $"{entropy:F3} bits/byte";
            EntropyBar.Value = (entropy / 8.0) * 100;

            if (entropy > 7.5)
                EntropyBar.Foreground = Brushes.Red;
            else if (entropy > 6.5)
                EntropyBar.Foreground = Brushes.Orange;
            else if (entropy > 5.0)
                EntropyBar.Foreground = Brushes.Yellow;
            else
                EntropyBar.Foreground = Brushes.Green;
        }

        

        private void ExtractIOCs()
        {
            if (fileData == null) return;

            string text = Encoding.ASCII.GetString(fileData);

            ipAddresses.Clear();
            domains.Clear();
            urls.Clear();
            emails.Clear();
            filePaths.Clear();

            MatchCollection ipMatches = Regex.Matches(text, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            foreach (Match match in ipMatches)
            {
                string ip = match.Value;
                if (IsValidIP(ip) && !ipAddresses.Contains(ip))
                {
                    ipAddresses.Add(ip);
                }
            }

            MatchCollection domainMatches = Regex.Matches(text, @"\b[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\b");
            foreach (Match match in domainMatches)
            {
                string domain = match.Value;
                if (!domain.Contains(".") || domain.Contains("example") || domain.Contains("localhost")) continue;
                if (!domains.Contains(domain) && domain.Length > 3)
                {
                    domains.Add(domain);
                }
            }

            MatchCollection urlMatches = Regex.Matches(text, @"(https?://|ftp://|file://)[^\s<>""']+");
            foreach (Match match in urlMatches)
            {
                string url = match.Value;
                if (!urls.Contains(url) && url.Length > 10)
                {
                    urls.Add(url);
                }
            }

            MatchCollection emailMatches = Regex.Matches(text, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b");
            foreach (Match match in emailMatches)
            {
                string email = match.Value;
                if (!emails.Contains(email) && email.Length > 5)
                {
                    emails.Add(email);
                }
            }

            MatchCollection winPathMatches = Regex.Matches(text, @"[A-Za-z]:\\(?:[^\\<>:""|?*\r\n]+\\)*[^\\<>:""|?*\r\n]*");
            foreach (Match match in winPathMatches)
            {
                string path = match.Value;
                if (!filePaths.Contains(path) && path.Length > 5)
                {
                    filePaths.Add(path);
                }
            }

            MatchCollection unixPathMatches = Regex.Matches(text, @"(?:/[\w\.-]+)+/?");
            foreach (Match match in unixPathMatches)
            {
                string path = match.Value;
                if (path.Length > 5 && !filePaths.Contains(path) && !path.Contains("//") && !path.Contains("/./"))
                {
                    filePaths.Add(path);
                }
            }

            IPCountText.Text = ipAddresses.Count.ToString();
            DomainCountText.Text = domains.Count.ToString();
            URLCountText.Text = urls.Count.ToString();
            EmailCountText.Text = emails.Count.ToString();
            PathCountText.Text = filePaths.Count.ToString();

            UpdateIOCDisplays();
        }

        private bool IsValidIP(string ip)
        {
            string[] parts = ip.Split('.');
            if (parts.Length != 4) return false;

            foreach (string part in parts)
            {
                if (!int.TryParse(part, out int num)) return false;
                if (num < 0 || num > 255) return false;
            }
            return true;
        }

        private void ExtractExifData()
        {
            exifData.Clear();

            if (fileData == null) return;

            if (FileTypeText.Text.Contains("JPEG") || FileTypeText.Text.Contains("JPG"))
            {
                for (int i = 0; i < fileData.Length - 4; i++)
                {
                    if (fileData[i] == 0xFF && fileData[i + 1] == 0xE1)
                    {
                        int length = (fileData[i + 2] << 8) | fileData[i + 3];
                        if (i + length < fileData.Length)
                        {
                            string exifHeader = Encoding.ASCII.GetString(fileData, i + 4, 4);
                            if (exifHeader == "Exif")
                            {
                                exifData["EXIF Header Found"] = $"At offset 0x{i:X} (length: {length})";
                                break;
                            }
                        }
                    }
                }
            }

            string text = Encoding.ASCII.GetString(fileData);
            string[] commonTags = { "Author", "Copyright", "Software", "Description", "Title", "Subject", "Keywords", "Producer", "Creator", "CreationDate", "ModDate", "Artist", "Make", "Model", "DateTime", "GPS" };

            foreach (string tag in commonTags)
            {
                Match match = Regex.Match(text, $@"{tag}[:\s]+([^\r\n]{0,100})", RegexOptions.IgnoreCase);
                if (match.Success && !exifData.ContainsKey(tag))
                {
                    string value = match.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(value) && value.Length > 2)
                    {
                        exifData[tag] = value;
                    }
                }
            }

            UpdateExifDisplay();
        }

        private void ExtractFileMetadata()
        {
            fileMetadata.Clear();

            if (fileData == null) return;

            fileMetadata["File Size"] = GetFileSizeString(fileData.Length);
            fileMetadata["Total Bytes"] = fileData.Length.ToString("N0");
            fileMetadata["File Type"] = FileTypeText.Text;
            fileMetadata["MIME Type"] = MimeTypeText.Text;
            fileMetadata["Magic Bytes"] = MagicBytesText.Text;
            fileMetadata["Entropy"] = EntropyText.Text;
            fileMetadata["MD5"] = MD5Text.Text;
            fileMetadata["SHA1"] = SHA1Text.Text;
            fileMetadata["SHA256"] = SHA256Text.Text;

            UpdateFileMetadataDisplay();
        }

        private void UpdateExifDisplay()
        {
            ExifItemsControl.Items.Clear();
            foreach (var item in exifData)
            {
                Border border = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(20, 51, 153, 255)),
                    Padding = new Thickness(8),
                    Margin = new Thickness(0, 0, 0, 2),
                    CornerRadius = new CornerRadius(3)
                };

                Grid grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(120) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                TextBlock keyBlock = new TextBlock
                {
                    Text = item.Key,
                    Foreground = Brushes.Cyan,
                    FontWeight = FontWeights.Bold,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(keyBlock, 0);

                TextBlock valueBlock = new TextBlock
                {
                    Text = item.Value,
                    Foreground = Brushes.White,
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(5, 0, 0, 0)
                };
                Grid.SetColumn(valueBlock, 1);

                grid.Children.Add(keyBlock);
                grid.Children.Add(valueBlock);
                border.Child = grid;

                ExifItemsControl.Items.Add(border);
            }

            if (exifData.Count == 0)
            {
                Border border = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(20, 100, 100, 100)),
                    Padding = new Thickness(8),
                    Margin = new Thickness(0, 0, 0, 2),
                    CornerRadius = new CornerRadius(3)
                };

                TextBlock textBlock = new TextBlock
                {
                    Text = "No EXIF data found",
                    Foreground = Brushes.Gray,
                    FontSize = 11
                };

                border.Child = textBlock;
                ExifItemsControl.Items.Add(border);
            }
        }

        private void UpdateFileMetadataDisplay()
        {
            FileMetadataItemsControl.Items.Clear();
            foreach (var item in fileMetadata)
            {
                Border border = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(20, 255, 153, 51)),
                    Padding = new Thickness(8),
                    Margin = new Thickness(0, 0, 0, 2),
                    CornerRadius = new CornerRadius(3)
                };

                Grid grid = new Grid();
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                TextBlock keyBlock = new TextBlock
                {
                    Text = item.Key,
                    Foreground = Brushes.Orange,
                    FontWeight = FontWeights.Bold,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                Grid.SetColumn(keyBlock, 0);

                TextBlock valueBlock = new TextBlock
                {
                    Text = item.Value,
                    Foreground = Brushes.White,
                    FontSize = 11,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(5, 0, 0, 0)
                };
                Grid.SetColumn(valueBlock, 1);

                grid.Children.Add(keyBlock);
                grid.Children.Add(valueBlock);
                border.Child = grid;

                FileMetadataItemsControl.Items.Add(border);
            }
        }

        private void UpdateIOCDisplays()
        {
            IPAddressesList.Items.Clear();
            foreach (string ip in ipAddresses.Take(100))
            {
                IPAddressesList.Items.Add(ip);
            }

            DomainsList.Items.Clear();
            foreach (string domain in domains.Take(100))
            {
                DomainsList.Items.Add(domain);
            }

            URLsList.Items.Clear();
            foreach (string url in urls.Take(100))
            {
                URLsList.Items.Add(url);
            }

            EmailsList.Items.Clear();
            foreach (string email in emails.Take(100))
            {
                EmailsList.Items.Add(email);
            }

            FilePathsList.Items.Clear();
            foreach (string path in filePaths.Take(100))
            {
                FilePathsList.Items.Add(path);
            }
        }

        private string GetFileSizeString(int bytes)
        {
            if (bytes < 1024) return $"{bytes} bytes";
            if (bytes < 1048576) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1073741824) return $"{bytes / 1048576.0:F2} MB";
            return $"{bytes / 1073741824.0:F2} GB";
        }

        private void UpdateHexView()
        {
            if (fileData == null || isUpdating) return;

            isUpdating = true;

            try
            {
                bytesPerLine = int.Parse(((ComboBoxItem)BytesPerLineCombo.SelectedItem).Content.ToString());

                StringBuilder hexBuilder = new StringBuilder();
                StringBuilder asciiBuilder = new StringBuilder();
                StringBuilder offsetBuilder = new StringBuilder();

                int totalLines = (fileData.Length + bytesPerLine - 1) / bytesPerLine;
                TotalBytesText.Text = fileData.Length.ToString();

                for (int line = 0; line < totalLines; line++)
                {
                    int offset = line * bytesPerLine;
                    int bytesInLine = Math.Min(bytesPerLine, fileData.Length - offset);

                    offsetBuilder.AppendLine($"{offset:X8}");

                    for (int i = 0; i < bytesInLine; i++)
                    {
                        hexBuilder.Append($"{fileData[offset + i]:X2} ");
                    }

                    if (bytesInLine < bytesPerLine)
                    {
                        for (int i = 0; i < (bytesPerLine - bytesInLine); i++)
                        {
                            hexBuilder.Append("   ");
                        }
                    }

                    hexBuilder.AppendLine();

                    for (int i = 0; i < bytesInLine; i++)
                    {
                        byte b = fileData[offset + i];
                        char c = (b >= 32 && b <= 126) ? (char)b : '.';
                        asciiBuilder.Append(c);
                    }
                    asciiBuilder.AppendLine();
                }

                OffsetNumbers.Text = offsetBuilder.ToString();
                HexViewBox.Text = hexBuilder.ToString();
                AsciiView.Text = asciiBuilder.ToString();
            }
            finally
            {
                isUpdating = false;
            }
        }

        private void HexScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (OffsetScroll != null && AsciiScroll != null)
            {
                OffsetScroll.ScrollToVerticalOffset(e.VerticalOffset);
                AsciiScroll.ScrollToVerticalOffset(e.VerticalOffset);
            }
        }

        private void HexViewBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (isUpdating || fileData == null) return;

            string hex = HexViewBox.Text.Replace(" ", "").Replace("\r", "").Replace("\n", "");
            if (hex.Length % 2 == 0)
            {
                try
                {
                    byte[] newData = new byte[hex.Length / 2];
                    for (int i = 0; i < newData.Length; i++)
                    {
                        newData[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                    }
                    fileData = newData;
                    ComputeHashes();
                    CalculateEntropy();
                    FileSizeText.Text = GetFileSizeString(fileData.Length);
                    TotalBytesText.Text = fileData.Length.ToString();
                }
                catch { }
            }
        }

        private void HexViewBox_SelectionChanged(object sender, RoutedEventArgs e)
        {
            int caretIndex = HexViewBox.CaretIndex;
            int offset = (caretIndex / (bytesPerLine * 3)) * bytesPerLine + (caretIndex % (bytesPerLine * 3)) / 3;

            if (offset < fileData?.Length)
            {
                CurrentOffsetText.Text = $"0x{offset:X}";
            }

            int selectionLength = HexViewBox.SelectionLength;
            SelectedBytesText.Text = (selectionLength / 3).ToString();
        }

        private void BytesPerLineCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateHexView();
        }

        private void SaveFileBtn_Click(object sender, RoutedEventArgs e)
        {
            if (fileData == null) return;

            try
            {
                File.WriteAllBytes(currentFilePath, fileData);
                StatusText.Text = "SAVED";
                StatusLed.Fill = Brushes.Green;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveAsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (fileData == null) return;

            var dialog = new SaveFileDialog
            {
                Filter = "All Files (*.*)|*.*",
                FileName = Path.GetFileName(currentFilePath)
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(dialog.FileName, fileData);
                    currentFilePath = dialog.FileName;
                    FileNameText.Text = Path.GetFileName(currentFilePath);
                    StatusText.Text = "SAVED";
                    StatusLed.Fill = Brushes.Green;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void GoToBtn_Click(object sender, RoutedEventArgs e)
        {
            string input = GoToOffsetInput.Text.Trim();
            if (string.IsNullOrEmpty(input) || fileData == null) return;

            try
            {
                int offset;
                if (input.StartsWith("0x"))
                {
                    offset = Convert.ToInt32(input.Substring(2), 16);
                }
                else
                {
                    offset = int.Parse(input);
                }

                if (offset >= 0 && offset < fileData.Length)
                {
                    int line = offset / bytesPerLine;
                    int col = (offset % bytesPerLine) * 3;
                    int position = line * (bytesPerLine * 3 + 2) + col;

                    HexViewBox.Focus();
                    HexViewBox.Select(position, 1);
                    HexScroll.ScrollToVerticalOffset(line * 19);
                }
            }
            catch { }
        }

        private void CopyHexBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(HexViewBox.Text)) return;
            Clipboard.SetText(HexViewBox.Text);
            StatusText.Text = "COPIED";
        }

        private void CopyTextBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(AsciiView.Text)) return;
            Clipboard.SetText(AsciiView.Text);
            StatusText.Text = "COPIED";
        }

        private void ExtractStringsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (fileData == null) return;

            StringBuilder strings = new StringBuilder();
            StringBuilder current = new StringBuilder();

            for (int i = 0; i < fileData.Length; i++)
            {
                if (fileData[i] >= 32 && fileData[i] <= 126)
                {
                    current.Append((char)fileData[i]);
                }
                else
                {
                    if (current.Length >= 4)
                    {
                        strings.AppendLine(current.ToString());
                    }
                    current.Clear();
                }
            }

            if (current.Length >= 4)
            {
                strings.AppendLine(current.ToString());
            }

            StringsOutputBox.Text = strings.ToString();
        }

        private void CopyStringsBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(StringsOutputBox.Text))
            {
                Clipboard.SetText(StringsOutputBox.Text);
                StatusText.Text = "COPIED";
            }
        }

        private void ExportMetadataBtn_Click(object sender, RoutedEventArgs e)
        {
            if (fileData == null) return;

            var dialog = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                FileName = Path.GetFileNameWithoutExtension(currentFilePath) + "_metadata.txt"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    sb.AppendLine($"=== METADATA REPORT ===");
                    sb.AppendLine($"File: {Path.GetFileName(currentFilePath)}");
                    sb.AppendLine($"Analyzed: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    sb.AppendLine();

                    sb.AppendLine("--- FILE INFO ---");
                    foreach (var item in fileMetadata)
                    {
                        sb.AppendLine($"{item.Key}: {item.Value}");
                    }

                    sb.AppendLine();
                    sb.AppendLine("--- EXIF DATA ---");
                    foreach (var item in exifData)
                    {
                        sb.AppendLine($"{item.Key}: {item.Value}");
                    }

                    sb.AppendLine();
                    sb.AppendLine("--- INDICATORS OF COMPROMISE ---");
                    sb.AppendLine($"IP Addresses ({ipAddresses.Count}):");
                    foreach (string ip in ipAddresses) sb.AppendLine($"  {ip}");
                    sb.AppendLine($"Domains ({domains.Count}):");
                    foreach (string domain in domains) sb.AppendLine($"  {domain}");
                    sb.AppendLine($"URLs ({urls.Count}):");
                    foreach (string url in urls) sb.AppendLine($"  {url}");
                    sb.AppendLine($"Emails ({emails.Count}):");
                    foreach (string email in emails) sb.AppendLine($"  {email}");

                    File.WriteAllText(dialog.FileName, sb.ToString());
                    MessageBox.Show($"Metadata exported to {dialog.FileName}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error exporting: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }

    public class EntropyBlock
    {
        public double Value { get; set; }
        public SolidColorBrush Color { get; set; }
        public string Block { get; set; }
    }

    public class EntropyToHeightConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return (double)value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class InputDialog : Window
    {
        private TextBox inputBox;

        public string Answer { get; private set; }

        public InputDialog(string prompt, string title)
        {
            Title = title;
            Width = 400;
            Height = 180;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(Color.FromRgb(10, 10, 10));
            Foreground = Brushes.White;
            ResizeMode = ResizeMode.NoResize;

            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.Margin = new Thickness(20);

            var promptBlock = new TextBlock
            {
                Text = prompt,
                Foreground = Brushes.White,
                Margin = new Thickness(0, 0, 0, 10)
            };
            Grid.SetRow(promptBlock, 0);

            inputBox = new TextBox
            {
                Background = new SolidColorBrush(Color.FromRgb(18, 18, 18)),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(51, 51, 51)),
                Padding = new Thickness(8),
                Margin = new Thickness(0, 0, 0, 10)
            };
            Grid.SetRow(inputBox, 1);

            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

            var okButton = new Button
            {
                Content = "OK",
                Width = 80,
                Height = 30,
                Margin = new Thickness(0, 0, 10, 0),
                Background = new SolidColorBrush(Color.FromRgb(139, 0, 0)),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(51, 51, 51)),
                Cursor = Cursors.Hand
            };
            okButton.Click += (s, e) => { Answer = inputBox.Text; DialogResult = true; };

            var cancelButton = new Button
            {
                Content = "Cancel",
                Width = 80,
                Height = 30,
                Background = new SolidColorBrush(Color.FromRgb(18, 18, 18)),
                Foreground = Brushes.White,
                BorderBrush = new SolidColorBrush(Color.FromRgb(51, 51, 51)),
                Cursor = Cursors.Hand
            };
            cancelButton.Click += (s, e) => { Answer = null; DialogResult = false; };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            Grid.SetRow(buttonPanel, 2);

            grid.Children.Add(promptBlock);
            grid.Children.Add(inputBox);
            grid.Children.Add(buttonPanel);

            Content = grid;

            inputBox.KeyDown += (s, e) => { if (e.Key == Key.Enter) { Answer = inputBox.Text; DialogResult = true; } };
        }
    }
}