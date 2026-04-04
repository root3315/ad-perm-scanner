using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace AdPermScanner;

/// <summary>
/// Main entry point for the Active Directory Permission Scanner.
/// Provides command-line interface for scanning and auditing AD permissions.
/// </summary>
public class Program
{
    private static int Main(string[] args)
    {
        var rootCommand = CreateRootCommand();
        return rootCommand.Invoke(args);
    }

    private static RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand("Active Directory Permission Scanner - Audit and analyze AD permissions and access controls");

        var domainOption = new Option<string>(
            aliases: new[] { "--domain", "-d" },
            description: "Active Directory domain name to scan (e.g., contoso.com). Uses current domain if not specified."
        );

        var ldapPathOption = new Option<string>(
            aliases: new[] { "--ldap-path", "-l" },
            description: "Specific LDAP path to scan (e.g., LDAP://OU=Users,DC=contoso,DC=com)"
        );

        var usernameOption = new Option<string>(
            aliases: new[] { "--username", "-u" },
            description: "Username for authentication (optional, uses current credentials if not specified)"
        );

        var passwordOption = new Option<string>(
            aliases: new[] { "--password", "-p" },
            description: "Password for authentication (optional)"
        );

        var outputOption = new Option<string>(
            aliases: new[] { "--output", "-o" },
            description: "Output file path for the report"
        );

        var formatOption = new Option<ReportFormat>(
            aliases: new[] { "--format", "-f" },
            getDefaultValue: () => ReportFormat.Text,
            description: "Output format: Text, Json, Csv, Html"
        );

        var filterOption = new Option<string>(
            aliases: new[] { "--filter" },
            description: "Custom LDAP filter for object selection"
        );

        var timeoutOption = new Option<int>(
            aliases: new[] { "--timeout", "-t" },
            getDefaultValue: () => 30,
            description: "Timeout in seconds for the entire scan operation (default: 30)"
        );

        var pageSizeOption = new Option<int>(
            aliases: new[] { "--page-size" },
            getDefaultValue: () => 1000,
            description: "Page size for LDAP queries"
        );

        var includeInheritedOption = new Option<bool>(
            aliases: new[] { "--include-inherited", "-i" },
            getDefaultValue: () => true,
            description: "Include inherited permissions in the scan"
        );

        var verboseOption = new Option<bool>(
            aliases: new[] { "--verbose", "-v" },
            getDefaultValue: () => false,
            description: "Enable verbose output"
        );

        var listOnlyOption = new Option<bool>(
            aliases: new[] { "--list-only" },
            getDefaultValue: () => false,
            description: "Only list objects without detailed permission analysis"
        );

        var highRiskOnlyOption = new Option<bool>(
            aliases: new[] { "--high-risk-only" },
            getDefaultValue: () => false,
            description: "Show only objects with high-risk permissions"
        );

        var maxRetriesOption = new Option<int>(
            aliases: new[] { "--max-retries" },
            getDefaultValue: () => 3,
            description: "Maximum number of retry attempts for LDAP operations"
        );

        var retryDelayOption = new Option<int>(
            aliases: new[] { "--retry-delay" },
            getDefaultValue: () => 1000,
            description: "Initial delay between retries in milliseconds (doubles each retry)"
        );

        rootCommand.AddOption(domainOption);
        rootCommand.AddOption(ldapPathOption);
        rootCommand.AddOption(usernameOption);
        rootCommand.AddOption(passwordOption);
        rootCommand.AddOption(outputOption);
        rootCommand.AddOption(formatOption);
        rootCommand.AddOption(filterOption);
        rootCommand.AddOption(timeoutOption);
        rootCommand.AddOption(pageSizeOption);
        rootCommand.AddOption(includeInheritedOption);
        rootCommand.AddOption(verboseOption);
        rootCommand.AddOption(listOnlyOption);
        rootCommand.AddOption(highRiskOnlyOption);
        rootCommand.AddOption(maxRetriesOption);
        rootCommand.AddOption(retryDelayOption);

        rootCommand.SetHandler(async (invocationContext) =>
        {
            var options = new ScannerOptions
            {
                DomainName = invocationContext.ParseResult.GetValueForOption(domainOption) ?? string.Empty,
                LdapPath = invocationContext.ParseResult.GetValueForOption(ldapPathOption),
                Username = invocationContext.ParseResult.GetValueForOption(usernameOption),
                Password = invocationContext.ParseResult.GetValueForOption(passwordOption),
                TimeoutSeconds = invocationContext.ParseResult.GetValueForOption(timeoutOption),
                PageSize = invocationContext.ParseResult.GetValueForOption(pageSizeOption),
                IncludeInheritedPermissions = invocationContext.ParseResult.GetValueForOption(includeInheritedOption),
                SearchFilter = invocationContext.ParseResult.GetValueForOption(filterOption),
                VerboseOutput = invocationContext.ParseResult.GetValueForOption(verboseOption),
                MaxRetries = invocationContext.ParseResult.GetValueForOption(maxRetriesOption),
                RetryDelayMilliseconds = invocationContext.ParseResult.GetValueForOption(retryDelayOption)
            };

            var outputPath = invocationContext.ParseResult.GetValueForOption(outputOption);
            var format = invocationContext.ParseResult.GetValueForOption(formatOption);
            var listOnly = invocationContext.ParseResult.GetValueForOption(listOnlyOption);
            var highRiskOnly = invocationContext.ParseResult.GetValueForOption(highRiskOnlyOption);

            await RunScanAsync(options, outputPath, format, listOnly, highRiskOnly);
        });

        return rootCommand;
    }

    private static async Task RunScanAsync(
        ScannerOptions options,
        string? outputPath,
        ReportFormat format,
        bool listOnly,
        bool highRiskOnly)
    {
        PrintBanner();
        PrintConfiguration(options);

        Console.WriteLine("Initializing scan...");
        Console.WriteLine();

        using var scanner = new AdScanner(options);
        
        ScanResult result;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
            result = await scanner.ScanAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine($"Scan timed out after {options.TimeoutSeconds} seconds.");
            Environment.Exit(1);
            return;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Scan failed: {ex.Message}");
            if (options.VerboseOutput)
            {
                Console.WriteLine($"Details: {ex.StackTrace}");
            }
            Environment.Exit(1);
            return;
        }

        if (!result.IsSuccess)
        {
            Console.WriteLine($"Scan completed with errors: {result.ErrorMessage}");
            Environment.Exit(1);
            return;
        }

        DisplayResults(result, listOnly, highRiskOnly);

        if (!string.IsNullOrEmpty(outputPath))
        {
            try
            {
                var generator = new ReportGenerator(result, format);
                generator.SaveToFile(outputPath);
                Console.WriteLine();
                Console.WriteLine($"Report saved to: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save report: {ex.Message}");
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Scan completed in {result.Duration.TotalSeconds:F2} seconds");
        Console.WriteLine($"Objects scanned: {result.TotalObjectsScanned}");
        Console.WriteLine($"Permissions found: {result.TotalPermissionsFound}");
        Console.WriteLine($"Critical: {result.CriticalFindings} | High: {result.HighFindings} | Medium: {result.MediumFindings} | Low: {result.LowFindings}");
    }

    private static void PrintBanner()
    {
        Console.WriteLine();
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║     Active Directory Permission Scanner v1.0.0               ║");
        Console.WriteLine("║     Audit and analyze AD permissions and access controls     ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();
    }

    private static void PrintConfiguration(ScannerOptions options)
    {
        Console.WriteLine("Configuration:");
        Console.WriteLine($"  Domain:        {string.IsNullOrEmpty(options.DomainName) ? "(current)" : options.DomainName}");
        Console.WriteLine($"  LDAP Path:     {options.LdapPath ?? "(root)"}");
        Console.WriteLine($"  Timeout:       {options.TimeoutSeconds}s");
        Console.WriteLine($"  Page Size:     {options.PageSize}");
        Console.WriteLine($"  Include Inherited: {options.IncludeInheritedPermissions}");
        Console.WriteLine($"  Verbose:       {options.VerboseOutput}");
        Console.WriteLine($"  Max Retries:   {options.MaxRetries}");
        Console.WriteLine($"  Retry Delay:   {options.RetryDelayMilliseconds}ms");
        if (!string.IsNullOrEmpty(options.SearchFilter))
        {
            Console.WriteLine($"  Filter:        {options.SearchFilter}");
        }
        Console.WriteLine();
    }

    private static void DisplayResults(ScanResult result, bool listOnly, bool highRiskOnly)
    {
        var objectsToDisplay = result.Objects;

        if (highRiskOnly)
        {
            objectsToDisplay = result.GetObjectsWithHighRiskPermissions().ToList();
        }

        if (listOnly)
        {
            Console.WriteLine("Scanned Objects:");
            Console.WriteLine(new string('-', 80));
            
            foreach (var obj in objectsToDisplay)
            {
                Console.WriteLine($"  [{obj.ObjectType,-15}] {obj.DistinguishedName}");
            }
            
            return;
        }

        Console.WriteLine(new string('=', 80));
        Console.WriteLine("SCAN RESULTS");
        Console.WriteLine(new string('=', 80));
        Console.WriteLine();

        var criticalObjects = result.GetObjectsBySeverity(PermissionSeverity.Critical).ToList();
        var highObjects = result.GetObjectsBySeverity(PermissionSeverity.High).ToList();
        var mediumObjects = result.GetObjectsBySeverity(PermissionSeverity.Medium).ToList();

        if (criticalObjects.Count > 0)
        {
            Console.WriteLine("CRITICAL FINDINGS:");
            Console.WriteLine(new string('-', 40));
            foreach (var obj in criticalObjects.Take(10))
            {
                Console.WriteLine($"  ! {obj.DistinguishedName}");
                Console.WriteLine($"    Type: {obj.ObjectType} | Permissions: {obj.PermissionCount}");
                foreach (var perm in obj.HighRiskPermissions.Take(3))
                {
                    Console.WriteLine($"      - {perm.IdentityReference}: {perm.ActiveDirectoryRights}");
                }
            }
            Console.WriteLine();
        }

        if (highObjects.Count > 0)
        {
            Console.WriteLine("HIGH SEVERITY FINDINGS:");
            Console.WriteLine(new string('-', 40));
            foreach (var obj in highObjects.Take(10))
            {
                Console.WriteLine($"  ! {obj.DistinguishedName}");
                Console.WriteLine($"    Type: {obj.ObjectType} | Permissions: {obj.PermissionCount}");
            }
            Console.WriteLine();
        }

        if (mediumObjects.Count > 0)
        {
            Console.WriteLine("MEDIUM SEVERITY FINDINGS:");
            Console.WriteLine(new string('-', 40));
            foreach (var obj in mediumObjects.Take(10))
            {
                Console.WriteLine($"  ~ {obj.DistinguishedName}");
                Console.WriteLine($"    Type: {obj.ObjectType} | Permissions: {obj.PermissionCount}");
            }
            Console.WriteLine();
        }

        var objectsByType = objectsToDisplay.GroupBy(o => o.ObjectType)
            .OrderByDescending(g => g.Count());

        Console.WriteLine("OBJECTS BY TYPE:");
        Console.WriteLine(new string('-', 40));
        foreach (var group in objectsByType)
        {
            Console.WriteLine($"  {group.Key,-20} {group.Count(),5} objects");
        }
        Console.WriteLine();

        Console.WriteLine("TOP 10 OBJECTS BY PERMISSION COUNT:");
        Console.WriteLine(new string('-', 40));
        var topObjects = objectsToDisplay
            .OrderByDescending(o => o.PermissionCount)
            .Take(10);

        foreach (var obj in topObjects)
        {
            Console.WriteLine($"  {obj.PermissionCount,4}  {obj.DistinguishedName}");
        }
    }

    public static void PrintUsage()
    {
        Console.WriteLine(@"
Active Directory Permission Scanner

USAGE:
  ad-perm-scanner [OPTIONS]

OPTIONS:
  -d, --domain <domain>        Active Directory domain to scan
  -l, --ldap-path <path>       Specific LDAP path to scan
  -u, --username <user>        Username for authentication
  -p, --password <pass>        Password for authentication
  -o, --output <file>          Output file for report
  -f, --format <format>        Output format: Text, Json, Csv, Html
  -t, --timeout <seconds>      Scan timeout in seconds (default: 30)
  --page-size <size>           LDAP query page size (default: 1000)
  -i, --include-inherited      Include inherited permissions
  -v, --verbose                Enable verbose output
  --list-only                  List objects without detailed analysis
  --high-risk-only             Show only high-risk permission objects
  --filter <ldap-filter>       Custom LDAP filter
  --max-retries <count>        Maximum retry attempts for LDAP operations (default: 3)
  --retry-delay <ms>           Initial retry delay in milliseconds (default: 1000)

EXAMPLES:
  ad-perm-scanner
  ad-perm-scanner -d contoso.com -o report.txt
  ad-perm-scanner -l ""LDAP://OU=Users,DC=contoso,DC=com"" -f Json -o report.json
  ad-perm-scanner --high-risk-only -f Html -o findings.html
  ad-perm-scanner --filter ""(objectClass=user)"" --verbose
");
    }
}
