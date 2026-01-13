using System.Text;
using System.Text.Json;

namespace AdPermScanner;

/// <summary>
/// Supported output formats for scan reports.
/// </summary>
public enum ReportFormat
{
    Text,
    Json,
    Csv,
    Html
}

/// <summary>
/// Generates reports from AD permission scan results.
/// </summary>
public class ReportGenerator
{
    private readonly ScanResult _result;
    private readonly ReportFormat _format;

    public ReportGenerator(ScanResult result, ReportFormat format = ReportFormat.Text)
    {
        _result = result ?? throw new ArgumentNullException(nameof(result));
        _format = format;
    }

    public string Generate()
    {
        return _format switch
        {
            ReportFormat.Json => GenerateJsonReport(),
            ReportFormat.Csv => GenerateCsvReport(),
            ReportFormat.Html => GenerateHtmlReport(),
            _ => GenerateTextReport()
        };
    }

    public void SaveToFile(string filePath)
    {
        var content = Generate();
        var directory = Path.GetDirectoryName(filePath);
        
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(filePath, content);
    }

    private string GenerateTextReport()
    {
        var sb = new StringBuilder();
        
        sb.AppendLine("=".PadRight(80, '='));
        sb.AppendLine("ACTIVE DIRECTORY PERMISSION SCAN REPORT");
        sb.AppendLine("=".PadRight(80, '='));
        sb.AppendLine();
        sb.AppendLine($"Scan Target:      {_result.ScanTarget}");
        sb.AppendLine($"Scan Started:     {_result.ScanStartTime:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine($"Scan Completed:   {_result.ScanEndTime:yyyy-MM-dd HH:mm:ss UTC}");
        sb.AppendLine($"Duration:         {_result.Duration.TotalSeconds:F2} seconds");
        sb.AppendLine();

        if (!_result.IsSuccess)
        {
            sb.AppendLine($"ERROR: {_result.ErrorMessage}");
            return sb.ToString();
        }

        sb.AppendLine("-".PadRight(80, '-'));
        sb.AppendLine("SUMMARY");
        sb.AppendLine("-".PadRight(80, '-'));
        sb.AppendLine($"Total Objects Scanned:    {_result.TotalObjectsScanned}");
        sb.AppendLine($"Total Permissions Found:  {_result.TotalPermissionsFound}");
        sb.AppendLine();
        sb.AppendLine("Findings by Severity:");
        sb.AppendLine($"  Critical:  {_result.CriticalFindings}");
        sb.AppendLine($"  High:      {_result.HighFindings}");
        sb.AppendLine($"  Medium:    {_result.MediumFindings}");
        sb.AppendLine($"  Low:       {_result.LowFindings}");
        sb.AppendLine();

        var highRiskObjects = _result.GetObjectsWithHighRiskPermissions().ToList();
        if (highRiskObjects.Count > 0)
        {
            sb.AppendLine("-".PadRight(80, '-));
            sb.AppendLine("HIGH-RISK PERMISSIONS");
            sb.AppendLine("-".PadRight(80, '-));
            
            foreach (var obj in highRiskObjects.Take(20))
            {
                sb.AppendLine();
                sb.AppendLine($"Object: {obj.DistinguishedName}");
                sb.AppendLine($"  Type: {obj.ObjectType} | Severity: {obj.GetSeverity()}");
                
                foreach (var perm in obj.HighRiskPermissions.Take(5))
                {
                    sb.AppendLine($"  - {perm.IdentityReference}: {perm.AccessControlType} - {FormatRights(perm.ActiveDirectoryRights)}");
                }

                if (obj.HighRiskPermissions.Count() > 5)
                {
                    sb.AppendLine($"  ... and {obj.HighRiskPermissions.Count() - 5} more");
                }
            }

            if (highRiskObjects.Count > 20)
            {
                sb.AppendLine();
                sb.AppendLine($"... and {highRiskObjects.Count - 20} more objects with high-risk permissions");
            }
            sb.AppendLine();
        }

        sb.AppendLine("-".PadRight(80, '-));
        sb.AppendLine("OBJECTS BY TYPE");
        sb.AppendLine("-".PadRight(80, '-));

        var byType = _result.Objects.GroupBy(o => o.ObjectType)
            .OrderByDescending(g => g.Count());

        foreach (var group in byType)
        {
            sb.AppendLine($"{group.Key}: {group.Count()} objects");
        }
        sb.AppendLine();

        sb.AppendLine("-".PadRight(80, '-));
        sb.AppendLine("TOP 10 OBJECTS BY PERMISSION COUNT");
        sb.AppendLine("-".PadRight(80, '-));

        var topObjects = _result.Objects
            .OrderByDescending(o => o.PermissionCount)
            .Take(10);

        foreach (var obj in topObjects)
        {
            sb.AppendLine($"{obj.PermissionCount,4} permissions - {obj.DistinguishedName}");
        }
        sb.AppendLine();

        sb.AppendLine("=".PadRight(80, '='));
        sb.AppendLine("END OF REPORT");
        sb.AppendLine("=".PadRight(80, '='));

        return sb.ToString();
    }

    private string GenerateJsonReport()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        var reportData = new
        {
            reportInfo = new
            {
                scanTarget = _result.ScanTarget,
                scanStartTime = _result.ScanStartTime.ToString("o"),
                scanEndTime = _result.ScanEndTime.ToString("o"),
                durationSeconds = _result.Duration.TotalSeconds,
                isSuccess = _result.IsSuccess,
                errorMessage = _result.ErrorMessage
            },
            summary = new
            {
                totalObjectsScanned = _result.TotalObjectsScanned,
                totalPermissionsFound = _result.TotalPermissionsFound,
                criticalFindings = _result.CriticalFindings,
                highFindings = _result.HighFindings,
                mediumFindings = _result.MediumFindings,
                lowFindings = _result.LowFindings
            },
            objects = _result.Objects.Select(o => new
            {
                distinguishedName = o.DistinguishedName,
                name = o.Name,
                samAccountName = o.SamAccountName,
                objectType = o.ObjectType.ToString(),
                objectClass = o.ObjectClass,
                severity = o.GetSeverity().ToString(),
                permissionCount = o.PermissionCount,
                highRiskPermissionCount = o.HighRiskPermissions.Count(),
                isEnabled = o.IsEnabled,
                whenCreated = o.WhenCreated?.ToString("o"),
                whenChanged = o.WhenChanged?.ToString("o"),
                memberOf = o.MemberOf,
                permissions = o.Permissions.Select(p => new
                {
                    identityReference = p.IdentityReference,
                    activeDirectoryRights = p.ActiveDirectoryRights.ToString(),
                    accessControlType = p.AccessControlType.ToString(),
                    inheritanceType = p.InheritanceType.ToString(),
                    isInherited = p.IsInherited,
                    objectTypeName = p.ObjectTypeName
                })
            })
        };

        return JsonSerializer.Serialize(reportData, options);
    }

    private string GenerateCsvReport()
    {
        var sb = new StringBuilder();
        
        sb.AppendLine("DistinguishedName,Name,SamAccountName,ObjectType,Severity,PermissionCount,HighRiskCount,IsEnabled,IdentityReference,AccessControlType,Rights,IsInherited");

        foreach (var obj in _result.Objects)
        {
            var baseFields = EscapeCsvField(obj.DistinguishedName) + "," +
                            EscapeCsvField(obj.Name) + "," +
                            EscapeCsvField(obj.SamAccountName ?? "") + "," +
                            obj.ObjectType + "," +
                            obj.GetSeverity() + "," +
                            obj.PermissionCount + "," +
                            obj.HighRiskPermissions.Count() + "," +
                            obj.IsEnabled;

            if (obj.Permissions.Count == 0)
            {
                sb.AppendLine($"{baseFields},,,,,");
            }
            else
            {
                foreach (var perm in obj.Permissions)
                {
                    sb.AppendLine($"{baseFields}," +
                                 $"{EscapeCsvField(perm.IdentityReference)}," +
                                 $"{perm.AccessControlType}," +
                                 $"{EscapeCsvField(FormatRights(perm.ActiveDirectoryRights))}," +
                                 $"{perm.IsInherited}");
                }
            }
        }

        return sb.ToString();
    }

    private string GenerateHtmlReport()
    {
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("    <meta charset=\"UTF-8\">");
        sb.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        sb.AppendLine("    <title>AD Permission Scan Report</title>");
        sb.AppendLine("    <style>");
        sb.AppendLine("        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }");
        sb.AppendLine("        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }");
        sb.AppendLine("        h1 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }");
        sb.AppendLine("        h2 { color: #555; margin-top: 30px; }");
        sb.AppendLine("        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }");
        sb.AppendLine("        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }");
        sb.AppendLine("        .stat-value { font-size: 2em; font-weight: bold; color: #0078d4; }");
        sb.AppendLine("        .stat-label { color: #666; font-size: 0.9em; }");
        sb.AppendLine("        .critical { color: #dc3545; }");
        sb.AppendLine("        .high { color: #fd7e14; }");
        sb.AppendLine("        .medium { color: #ffc107; }");
        sb.AppendLine("        .low { color: #28a745; }");
        sb.AppendLine("        table { width: 100%; border-collapse: collapse; margin: 15px 0; }");
        sb.AppendLine("        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }");
        sb.AppendLine("        th { background: #0078d4; color: white; }");
        sb.AppendLine("        tr:hover { background: #f5f5f5; }");
        sb.AppendLine("        .severity-badge { padding: 3px 8px; border-radius: 3px; font-size: 0.85em; color: white; }");
        sb.AppendLine("        .severity-critical { background: #dc3545; }");
        sb.AppendLine("        .severity-high { background: #fd7e14; }");
        sb.AppendLine("        .severity-medium { background: #ffc107; color: #333; }");
        sb.AppendLine("        .severity-low { background: #28a745; }");
        sb.AppendLine("        .meta-info { color: #666; font-size: 0.9em; margin-bottom: 20px; }");
        sb.AppendLine("    </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("    <div class=\"container\">");
        sb.AppendLine($"        <h1>Active Directory Permission Scan Report</h1>");
        sb.AppendLine($"        <div class=\"meta-info\">");
        sb.AppendLine($"            <p><strong>Target:</strong> {EscapeHtml(_result.ScanTarget)}</p>");
        sb.AppendLine($"            <p><strong>Scan Time:</strong> {_result.ScanStartTime:yyyy-MM-dd HH:mm:ss} UTC (Duration: {_result.Duration.TotalSeconds:F2}s)</p>");
        sb.AppendLine($"        </div>");

        if (!_result.IsSuccess)
        {
            sb.AppendLine($"        <div style=\"background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px;\">");
            sb.AppendLine($"            <strong>Error:</strong> {EscapeHtml(_result.ErrorMessage ?? "Unknown error")}");
            sb.AppendLine($"        </div>");
        }
        else
        {
            sb.AppendLine("        <div class=\"summary\">");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value\">{_result.TotalObjectsScanned}</div><div class=\"stat-label\">Objects Scanned</div></div>");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value\">{_result.TotalPermissionsFound}</div><div class=\"stat-label\">Total Permissions</div></div>");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value critical\">{_result.CriticalFindings}</div><div class=\"stat-label\">Critical</div></div>");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value high\">{_result.HighFindings}</div><div class=\"stat-label\">High</div></div>");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value medium\">{_result.MediumFindings}</div><div class=\"stat-label\">Medium</div></div>");
            sb.AppendLine($"            <div class=\"stat-card\"><div class=\"stat-value low\">{_result.LowFindings}</div><div class=\"stat-label\">Low</div></div>");
            sb.AppendLine("        </div>");

            var highRiskObjects = _result.GetObjectsWithHighRiskPermissions().ToList();
            if (highRiskObjects.Count > 0)
            {
                sb.AppendLine("        <h2>High-Risk Permissions</h2>");
                sb.AppendLine("        <table>");
                sb.AppendLine("            <thead><tr><th>Object</th><th>Type</th><th>Principal</th><th>Rights</th></tr></thead>");
                sb.AppendLine("            <tbody>");

                foreach (var obj in highRiskObjects.Take(50))
                {
                    foreach (var perm in obj.HighRiskPermissions.Take(3))
                    {
                        sb.AppendLine($"                <tr>");
                        sb.AppendLine($"                    <td>{EscapeHtml(obj.Name)}</td>");
                        sb.AppendLine($"                    <td>{obj.ObjectType}</td>");
                        sb.AppendLine($"                    <td>{EscapeHtml(perm.IdentityReference)}</td>");
                        sb.AppendLine($"                    <td>{EscapeHtml(FormatRights(perm.ActiveDirectoryRights))}</td>");
                        sb.AppendLine($"                </tr>");
                    }
                }

                sb.AppendLine("            </tbody>");
                sb.AppendLine("        </table>");
            }

            sb.AppendLine("        <h2>All Scanned Objects</h2>");
            sb.AppendLine("        <table>");
            sb.AppendLine("            <thead><tr><th>Name</th><th>Type</th><th>Severity</th><th>Permissions</th><th>High-Risk</th></tr></thead>");
            sb.AppendLine("            <tbody>");

            foreach (var obj in _result.Objects)
            {
                var severityClass = obj.GetSeverity().ToString().ToLower();
                sb.AppendLine($"                <tr>");
                sb.AppendLine($"                    <td title=\"{EscapeHtml(obj.DistinguishedName)}\">{EscapeHtml(obj.Name)}</td>");
                sb.AppendLine($"                    <td>{obj.ObjectType}</td>");
                sb.AppendLine($"                    <td><span class=\"severity-badge severity-{severityClass}\">{obj.GetSeverity()}</span></td>");
                sb.AppendLine($"                    <td>{obj.PermissionCount}</td>");
                sb.AppendLine($"                    <td>{obj.HighRiskPermissions.Count()}</td>");
                sb.AppendLine($"                </tr>");
            }

            sb.AppendLine("            </tbody>");
            sb.AppendLine("        </table>");
        }

        sb.AppendLine("    </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    private static string FormatRights(ActiveDirectoryRights rights)
    {
        var rightList = new List<string>();

        if (rights.HasFlag(ActiveDirectoryRights.GenericAll)) rightList.Add("GenericAll");
        if (rights.HasFlag(ActiveDirectoryRights.GenericWrite)) rightList.Add("GenericWrite");
        if (rights.HasFlag(ActiveDirectoryRights.WriteOwner)) rightList.Add("WriteOwner");
        if (rights.HasFlag(ActiveDirectoryRights.WriteDacl)) rightList.Add("WriteDacl");
        if (rights.HasFlag(ActiveDirectoryRights.Delete)) rightList.Add("Delete");
        if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight)) rightList.Add("ExtendedRight");

        return rightList.Count > 0 ? string.Join(", ", rightList) : rights.ToString();
    }

    private static string EscapeCsvField(string field)
    {
        if (string.IsNullOrEmpty(field)) return string.Empty;
        if (field.Contains(",") || field.Contains("\"") || field.Contains("\n"))
        {
            return $"\"{field.Replace("\"", "\"\"")}\"";
        }
        return field;
    }

    private static string EscapeHtml(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;");
    }
}
