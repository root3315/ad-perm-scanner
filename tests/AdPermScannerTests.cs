using System.Security.AccessControl;
using AdPermScanner;
using Xunit;

namespace AdPermScanner.Tests;

/// <summary>
/// Unit tests for AdPermission model classes.
/// </summary>
public class AdPermissionTests
{
    [Fact]
    public void AdPermissionEntry_ToString_ReturnsFormattedString()
    {
        var entry = new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\User",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
            AccessControlType = AccessControlType.Allow,
            InheritanceType = ActiveDirectorySecurityInheritance.All
        };

        var result = entry.ToString();

        Assert.Contains("DOMAIN\\User", result);
        Assert.Contains("Allow", result);
        Assert.Contains("GenericAll", result);
    }

    [Fact]
    public void AdPermissionEntry_FormatRights_MultipleRights()
    {
        var entry = new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\Group",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericWrite | ActiveDirectoryRights.Delete,
            AccessControlType = AccessControlType.Allow,
            InheritanceType = ActiveDirectorySecurityInheritance.None
        };

        var result = entry.ToString();

        Assert.Contains("GenericWrite", result);
        Assert.Contains("Delete", result);
    }

    [Fact]
    public void ScannedAdObject_HighRiskPermissions_IdentifiesCorrectly()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=User,DC=domain,DC=com",
            Name = "TestUser",
            ObjectType = AdObjectType.User
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\Admins",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
            AccessControlType = AccessControlType.Allow,
            IsInherited = false
        });

        var highRisk = obj.HighRiskPermissions.ToList();

        Assert.Single(highRisk);
        Assert.Equal("DOMAIN\\Admins", highRisk[0].IdentityReference);
    }

    [Fact]
    public void ScannedAdObject_GetSeverity_CriticalForGenericAll()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=Object,DC=domain,DC=com",
            Name = "TestObject",
            ObjectType = AdObjectType.Container
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\User",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
            AccessControlType = AccessControlType.Allow,
            IsInherited = false
        });

        var severity = obj.GetSeverity();

        Assert.Equal(PermissionSeverity.Critical, severity);
    }

    [Fact]
    public void ScannedAdObject_GetSeverity_HighForWriteDacl()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=Object,DC=domain,DC=com",
            Name = "TestObject",
            ObjectType = AdObjectType.Container
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\User",
            ActiveDirectoryRights = ActiveDirectoryRights.WriteDacl,
            AccessControlType = AccessControlType.Allow,
            IsInherited = true
        });

        var severity = obj.GetSeverity();

        Assert.Equal(PermissionSeverity.High, severity);
    }

    [Fact]
    public void ScannedAdObject_GetSeverity_MediumForGenericWrite()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=Object,DC=domain,DC=com",
            Name = "TestObject",
            ObjectType = AdObjectType.Container
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\User",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericWrite,
            AccessControlType = AccessControlType.Allow,
            IsInherited = true
        });

        var severity = obj.GetSeverity();

        Assert.Equal(PermissionSeverity.Medium, severity);
    }

    [Fact]
    public void ScannedAdObject_GetSeverity_LowForReadPermissions()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=Object,DC=domain,DC=com",
            Name = "TestObject",
            ObjectType = AdObjectType.Container
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\Users",
            ActiveDirectoryRights = ActiveDirectoryRights.ReadProperty,
            AccessControlType = AccessControlType.Allow,
            IsInherited = true
        });

        var severity = obj.GetSeverity();

        Assert.Equal(PermissionSeverity.Low, severity);
    }

    [Fact]
    public void ScannedAdObject_PermissionCount_ReturnsCorrectCount()
    {
        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=Object,DC=domain,DC=com",
            Name = "TestObject",
            ObjectType = AdObjectType.User
        };

        obj.Permissions.Add(new AdPermissionEntry { IdentityReference = "User1" });
        obj.Permissions.Add(new AdPermissionEntry { IdentityReference = "User2" });
        obj.Permissions.Add(new AdPermissionEntry { IdentityReference = "User3" });

        Assert.Equal(3, obj.PermissionCount);
    }
}

/// <summary>
/// Unit tests for ScanResult class.
/// </summary>
public class ScanResultTests
{
    [Fact]
    public void ScanResult_Duration_CalculatesCorrectly()
    {
        var result = new ScanResult
        {
            ScanStartTime = DateTime.UtcNow.AddSeconds(-30),
            ScanEndTime = DateTime.UtcNow
        };

        var duration = result.Duration;

        Assert.True(duration.TotalSeconds >= 29 && duration.TotalSeconds <= 31);
    }

    [Fact]
    public void ScanResult_TotalObjectsScanned_ReturnsCorrectCount()
    {
        var result = new ScanResult();
        result.Objects.Add(new ScannedAdObject { Name = "Object1" });
        result.Objects.Add(new ScannedAdObject { Name = "Object2" });
        result.Objects.Add(new ScannedAdObject { Name = "Object3" });

        Assert.Equal(3, result.TotalObjectsScanned);
    }

    [Fact]
    public void ScanResult_TotalPermissionsFound_SumsAllPermissions()
    {
        var result = new ScanResult();
        
        var obj1 = new ScannedAdObject();
        obj1.Permissions.Add(new AdPermissionEntry());
        obj1.Permissions.Add(new AdPermissionEntry());
        
        var obj2 = new ScannedAdObject();
        obj2.Permissions.Add(new AdPermissionEntry());
        
        result.Objects.Add(obj1);
        result.Objects.Add(obj2);

        Assert.Equal(3, result.TotalPermissionsFound);
    }

    [Fact]
    public void ScanResult_GetObjectsBySeverity_FiltersCorrectly()
    {
        var result = new ScanResult();

        var criticalObj = new ScannedAdObject();
        criticalObj.Permissions.Add(new AdPermissionEntry
        {
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
            IsInherited = false
        });

        var lowObj = new ScannedAdObject();
        lowObj.Permissions.Add(new AdPermissionEntry
        {
            ActiveDirectoryRights = ActiveDirectoryRights.ReadProperty
        });

        result.Objects.Add(criticalObj);
        result.Objects.Add(lowObj);

        var criticalObjects = result.GetObjectsBySeverity(PermissionSeverity.Critical).ToList();

        Assert.Single(criticalObjects);
        Assert.Contains(criticalObj, criticalObjects);
    }

    [Fact]
    public void ScanResult_GetObjectsWithHighRiskPermissions_FiltersCorrectly()
    {
        var result = new ScanResult();

        var highRiskObj = new ScannedAdObject();
        highRiskObj.Permissions.Add(new AdPermissionEntry
        {
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll
        });

        var lowRiskObj = new ScannedAdObject();
        lowRiskObj.Permissions.Add(new AdPermissionEntry
        {
            ActiveDirectoryRights = ActiveDirectoryRights.ReadProperty
        });

        result.Objects.Add(highRiskObj);
        result.Objects.Add(lowRiskObj);

        var highRiskObjects = result.GetObjectsWithHighRiskPermissions().ToList();

        Assert.Single(highRiskObjects);
        Assert.Contains(highRiskObj, highRiskObjects);
    }

    [Fact]
    public void ScanResult_CriticalFindings_CountsCorrectly()
    {
        var result = new ScanResult();

        for (int i = 0; i < 3; i++)
        {
            var obj = new ScannedAdObject();
            obj.Permissions.Add(new AdPermissionEntry
            {
                ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
                IsInherited = false
            });
            result.Objects.Add(obj);
        }

        var lowObj = new ScannedAdObject();
        lowObj.Permissions.Add(new AdPermissionEntry
        {
            ActiveDirectoryRights = ActiveDirectoryRights.ReadProperty
        });
        result.Objects.Add(lowObj);

        Assert.Equal(3, result.CriticalFindings);
    }
}

/// <summary>
/// Unit tests for ReportGenerator class.
/// </summary>
public class ReportGeneratorTests
{
    [Fact]
    public void ReportGenerator_GenerateTextReport_ContainsHeader()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Text);

        var report = generator.Generate();

        Assert.Contains("ACTIVE DIRECTORY PERMISSION SCAN REPORT", report);
        Assert.Contains("SUMMARY", report);
    }

    [Fact]
    public void ReportGenerator_GenerateTextReport_ContainsScanInfo()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Text);

        var report = generator.Generate();

        Assert.Contains("Scan Target:", report);
        Assert.Contains("Scan Started:", report);
        Assert.Contains("Duration:", report);
    }

    [Fact]
    public void ReportGenerator_GenerateJsonReport_ValidJson()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Json);

        var report = generator.Generate();

        Assert.StartsWith("{", report.Trim());
        Assert.EndsWith("}", report.Trim());
        Assert.Contains("\"scanTarget\"", report);
        Assert.Contains("\"objects\"", report);
    }

    [Fact]
    public void ReportGenerator_GenerateCsvReport_ContainsHeader()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Csv);

        var report = generator.Generate();

        Assert.StartsWith("DistinguishedName,Name,SamAccountName", report);
    }

    [Fact]
    public void ReportGenerator_GenerateHtmlReport_ValidHtml()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Html);

        var report = generator.Generate();

        Assert.Contains("<!DOCTYPE html>", report);
        Assert.Contains("<html", report);
        Assert.Contains("</html>", report);
        Assert.Contains("Active Directory Permission Scan Report", report);
    }

    [Fact]
    public void ReportGenerator_GenerateHtmlReport_ContainsStyles()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Html);

        var report = generator.Generate();

        Assert.Contains("<style>", report);
        Assert.Contains("severity-critical", report);
        Assert.Contains("severity-high", report);
    }

    [Fact]
    public void ReportGenerator_ErrorResult_ShowsErrorMessage()
    {
        var result = new ScanResult
        {
            ScanTarget = "test.local",
            ScanStartTime = DateTime.UtcNow,
            ScanEndTime = DateTime.UtcNow,
            IsSuccess = false,
            ErrorMessage = "Connection failed"
        };

        var generator = new ReportGenerator(result, ReportFormat.Text);
        var report = generator.Generate();

        Assert.Contains("ERROR:", report);
        Assert.Contains("Connection failed", report);
    }

    [Fact]
    public void ReportGenerator_SaveToFile_CreatesFile()
    {
        var result = CreateTestScanResult();
        var generator = new ReportGenerator(result, ReportFormat.Text);
        var tempPath = Path.Combine(Path.GetTempPath(), $"test-report-{Guid.NewGuid()}.txt");

        try
        {
            generator.SaveToFile(tempPath);

            Assert.True(File.Exists(tempPath));
            var content = File.ReadAllText(tempPath);
            Assert.Contains("ACTIVE DIRECTORY PERMISSION SCAN REPORT", content);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                File.Delete(tempPath);
            }
        }
    }

    private static ScanResult CreateTestScanResult()
    {
        var result = new ScanResult
        {
            ScanTarget = "test.local",
            ScanStartTime = DateTime.UtcNow.AddSeconds(-10),
            ScanEndTime = DateTime.UtcNow,
            IsSuccess = true
        };

        var obj = new ScannedAdObject
        {
            DistinguishedName = "CN=TestUser,OU=Users,DC=test,DC=local",
            Name = "TestUser",
            SamAccountName = "testuser",
            ObjectType = AdObjectType.User
        };

        obj.Permissions.Add(new AdPermissionEntry
        {
            IdentityReference = "DOMAIN\\Admins",
            ActiveDirectoryRights = ActiveDirectoryRights.GenericAll,
            AccessControlType = AccessControlType.Allow
        });

        result.Objects.Add(obj);

        return result;
    }
}

/// <summary>
/// Unit tests for ScannerOptions class.
/// </summary>
public class ScannerOptionsTests
{
    [Fact]
    public void ScannerOptions_DefaultValues_AreCorrect()
    {
        var options = new ScannerOptions();

        Assert.Equal(30, options.TimeoutSeconds);
        Assert.Equal(1000, options.PageSize);
        Assert.True(options.IncludeInheritedPermissions);
        Assert.True(options.ResolveGroupMemberships);
        Assert.False(options.VerboseOutput);
        Assert.Empty(options.DomainName);
    }

    [Fact]
    public void ScannerOptions_ObjectClassesToScan_ContainsDefaults()
    {
        var options = new ScannerOptions();

        Assert.Contains("user", options.ObjectClassesToScan);
        Assert.Contains("group", options.ObjectClassesToScan);
        Assert.Contains("computer", options.ObjectClassesToScan);
        Assert.Contains("organizationalUnit", options.ObjectClassesToScan);
    }

    [Fact]
    public void ScannerOptions_CustomValues_AreSetCorrectly()
    {
        var options = new ScannerOptions
        {
            DomainName = "contoso.com",
            TimeoutSeconds = 60,
            PageSize = 500,
            IncludeInheritedPermissions = false,
            VerboseOutput = true
        };

        Assert.Equal("contoso.com", options.DomainName);
        Assert.Equal(60, options.TimeoutSeconds);
        Assert.Equal(500, options.PageSize);
        Assert.False(options.IncludeInheritedPermissions);
        Assert.True(options.VerboseOutput);
    }
}

/// <summary>
/// Integration-style tests for the scanner workflow.
/// </summary>
public class ScannerWorkflowTests
{
    [Fact]
    public void AdScanner_WithOptions_CreatesSuccessfully()
    {
        var options = new ScannerOptions
        {
            DomainName = "test.local",
            TimeoutSeconds = 30
        };

        using var scanner = new AdScanner(options);

        Assert.NotNull(scanner);
    }

    [Fact]
    public void AdScanner_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AdScanner(null!));
    }

    [Fact]
    public async Task AdScanner_Scan_WithoutConnection_ReturnsFailedResult()
    {
        var options = new ScannerOptions
        {
            DomainName = "nonexistent.domain.invalid",
            TimeoutSeconds = 2
        };

        using var scanner = new AdScanner(options);
        var result = await scanner.ScanAsync(CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.ErrorMessage);
    }

    [Fact]
    public async Task AdScanner_Scan_WithShortTimeout_ReturnsTimeoutError()
    {
        var options = new ScannerOptions
        {
            DomainName = "nonexistent.domain.invalid",
            TimeoutSeconds = 1
        };

        using var scanner = new AdScanner(options);
        var result = await scanner.ScanAsync(CancellationToken.None);

        Assert.False(result.IsSuccess);
        Assert.Contains("timed out", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AdScanner_Scan_WithPreCancelledToken_ReturnsCancelledError()
    {
        var options = new ScannerOptions
        {
            DomainName = "test.local",
            TimeoutSeconds = 60
        };

        using var scanner = new AdScanner(options);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await scanner.ScanAsync(cts.Token);

        Assert.False(result.IsSuccess);
        Assert.Contains("cancelled", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScanResult_EmptyObjects_HasZeroCounts()
    {
        var result = new ScanResult
        {
            ScanTarget = "test",
            ScanStartTime = DateTime.UtcNow,
            ScanEndTime = DateTime.UtcNow
        };

        Assert.Equal(0, result.TotalObjectsScanned);
        Assert.Equal(0, result.TotalPermissionsFound);
        Assert.Equal(0, result.CriticalFindings);
        Assert.Equal(0, result.HighFindings);
    }
}

/// <summary>
/// Tests for timeout behavior in ScannerOptions.
/// </summary>
public class ScannerOptionsTimeoutTests
{
    [Fact]
    public void ScannerOptions_DefaultTimeout_Is30Seconds()
    {
        var options = new ScannerOptions();

        Assert.Equal(30, options.TimeoutSeconds);
    }

    [Fact]
    public void ScannerOptions_CustomTimeout_IsSetCorrectly()
    {
        var options = new ScannerOptions
        {
            TimeoutSeconds = 120
        };

        Assert.Equal(120, options.TimeoutSeconds);
    }

    [Fact]
    public void ScannerOptions_ZeroTimeout_IsAllowed()
    {
        var options = new ScannerOptions
        {
            TimeoutSeconds = 0
        };

        Assert.Equal(0, options.TimeoutSeconds);
    }
}
