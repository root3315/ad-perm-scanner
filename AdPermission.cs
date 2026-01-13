using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AdPermScanner;

/// <summary>
/// Represents the type of Active Directory object being scanned.
/// </summary>
public enum AdObjectType
{
    User,
    Group,
    Computer,
    OrganizationalUnit,
    Container,
    Unknown
}

/// <summary>
/// Represents the severity level of a permission finding.
/// </summary>
public enum PermissionSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Represents a single permission entry on an AD object.
/// </summary>
public class AdPermissionEntry
{
    public string IdentityReference { get; set; } = string.Empty;
    public ActiveDirectoryRights ActiveDirectoryRights { get; set; }
    public AccessControlType AccessControlType { get; set; }
    public ActiveDirectorySecurityInheritance InheritanceType { get; set; }
    public string? InheritedObjectType { get; set; }
    public string? ObjectTypeName { get; set; }
    public bool IsInherited { get; set; }
    public string? InheritancePath { get; set; }

    public override string ToString()
    {
        var rights = FormatRights(ActiveDirectoryRights);
        return $"{IdentityReference}: {AccessControlType} - {rights}";
    }

    private static string FormatRights(ActiveDirectoryRights rights)
    {
        var rightList = new List<string>();
        
        if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
            rightList.Add("GenericAll");
        if (rights.HasFlag(ActiveDirectoryRights.GenericWrite))
            rightList.Add("GenericWrite");
        if (rights.HasFlag(ActiveDirectoryRights.GenericRead))
            rightList.Add("GenericRead");
        if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
            rightList.Add("WriteOwner");
        if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
            rightList.Add("WriteDacl");
        if (rights.HasFlag(ActiveDirectoryRights.ExtendedRight))
            rightList.Add("ExtendedRight");
        if (rights.HasFlag(ActiveDirectoryRights.Delete))
            rightList.Add("Delete");
        if (rights.HasFlag(ActiveDirectoryRights.ReadControl))
            rightList.Add("ReadControl");
        if (rights.HasFlag(ActiveDirectoryRights.Synchronize))
            rightList.Add("Synchronize");
        if (rights.HasFlag(ActiveDirectoryRights.CreateChild))
            rightList.Add("CreateChild");
        if (rights.HasFlag(ActiveDirectoryRights.DeleteChild))
            rightList.Add("DeleteChild");
        if (rights.HasFlag(ActiveDirectoryRights.DeleteTree))
            rightList.Add("DeleteTree");
        if (rights.HasFlag(ActiveDirectoryRights.ListChildren))
            rightList.Add("ListChildren");
        if (rights.HasFlag(ActiveDirectoryRights.Self))
            rightList.Add("Self");
        if (rights.HasFlag(ActiveDirectoryRights.ReadProperty))
            rightList.Add("ReadProperty");
        if (rights.HasFlag(ActiveDirectoryRights.WriteProperty))
            rightList.Add("WriteProperty");

        return rightList.Count > 0 ? string.Join(", ", rightList) : "None";
    }
}

/// <summary>
/// Represents a scanned AD object with its permissions.
/// </summary>
public class ScannedAdObject
{
    public string DistinguishedName { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? SamAccountName { get; set; }
    public AdObjectType ObjectType { get; set; }
    public string? ObjectClass { get; set; }
    public List<AdPermissionEntry> Permissions { get; set; } = new();
    public List<string> MemberOf { get; set; } = new();
    public DateTime? WhenCreated { get; set; }
    public DateTime? WhenChanged { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Description { get; set; }
    public int PermissionCount => Permissions.Count;
    public IEnumerable<AdPermissionEntry> HighRiskPermissions =>
        Permissions.Where(p => IsHighRisk(p));

    private static bool IsHighRisk(AdPermissionEntry permission)
    {
        var highRiskRights = ActiveDirectoryRights.GenericAll |
                            ActiveDirectoryRights.GenericWrite |
                            ActiveDirectoryRights.WriteOwner |
                            ActiveDirectoryRights.WriteDacl |
                            ActiveDirectoryRights.Delete;

        return (permission.ActiveDirectoryRights & highRiskRights) != 0 ||
               permission.AccessControlType == AccessControlType.Deny;
    }

    public PermissionSeverity GetSeverity()
    {
        if (Permissions.Any(p => p.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll) &&
                                 !p.IsInherited))
            return PermissionSeverity.Critical;

        if (Permissions.Any(p => p.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl) ||
                                 p.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner)))
            return PermissionSeverity.High;

        if (Permissions.Any(p => p.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericWrite) ||
                                 p.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.Delete)))
            return PermissionSeverity.Medium;

        return PermissionSeverity.Low;
    }
}

/// <summary>
/// Represents the results of an AD permission scan.
/// </summary>
public class ScanResult
{
    public string ScanTarget { get; set; } = string.Empty;
    public DateTime ScanStartTime { get; set; }
    public DateTime ScanEndTime { get; set; }
    public TimeSpan Duration => ScanEndTime - ScanStartTime;
    public List<ScannedAdObject> Objects { get; set; } = new();
    public int TotalObjectsScanned => Objects.Count;
    public int TotalPermissionsFound => Objects.Sum(o => o.PermissionCount);
    public int CriticalFindings => Objects.Count(o => o.GetSeverity() == PermissionSeverity.Critical);
    public int HighFindings => Objects.Count(o => o.GetSeverity() == PermissionSeverity.High);
    public int MediumFindings => Objects.Count(o => o.GetSeverity() == PermissionSeverity.Medium);
    public int LowFindings => Objects.Count(o => o.GetSeverity() == PermissionSeverity.Low);
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }

    public IEnumerable<ScannedAdObject> GetObjectsBySeverity(PermissionSeverity severity)
    {
        return Objects.Where(o => o.GetSeverity() == severity);
    }

    public IEnumerable<ScannedAdObject> GetObjectsWithHighRiskPermissions()
    {
        return Objects.Where(o => o.HighRiskPermissions.Any());
    }
}
