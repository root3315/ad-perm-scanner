using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AdPermScanner;

/// <summary>
/// Configuration options for the AD permission scanner.
/// </summary>
public class ScannerOptions
{
    public string DomainName { get; set; } = string.Empty;
    public string? LdapPath { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
    public int TimeoutSeconds { get; set; } = 30;
    public int PageSize { get; set; } = 1000;
    public bool IncludeInheritedPermissions { get; set; } = true;
    public bool ResolveGroupMemberships { get; set; } = true;
    public List<string> ObjectClassesToScan { get; set; } = new() { "user", "group", "computer", "organizationalUnit" };
    public string? SearchFilter { get; set; }
    public bool VerboseOutput { get; set; } = false;
}

/// <summary>
/// Main scanner class for Active Directory permissions.
/// </summary>
public class AdScanner : IDisposable
{
    private readonly ScannerOptions _options;
    private DirectoryEntry? _rootEntry;
    private bool _disposed;
    private static readonly string[] CommonAttributes = new[]
    {
        "distinguishedName", "name", "sAMAccountName", "objectClass",
        "whenCreated", "whenChanged", "description", "member", "memberOf",
        "userAccountControl", "adminCount", "servicePrincipalName"
    };

    public AdScanner(ScannerOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task<ScanResult> ScanAsync(CancellationToken cancellationToken = default)
    {
        var result = new ScanResult
        {
            ScanTarget = string.IsNullOrEmpty(_options.DomainName) 
                ? _options.LdapPath ?? "Local" 
                : _options.DomainName,
            ScanStartTime = DateTime.UtcNow
        };

        try
        {
            _rootEntry = await GetRootDirectoryEntryAsync(cancellationToken);
            
            if (_rootEntry == null)
            {
                result.IsSuccess = false;
                result.ErrorMessage = "Failed to connect to Active Directory";
                result.ScanEndTime = DateTime.UtcNow;
                return result;
            }

            var objects = await ScanDirectoryObjectsAsync(_rootEntry, cancellationToken);
            result.Objects = objects;
            result.IsSuccess = true;
        }
        catch (Exception ex)
        {
            result.IsSuccess = false;
            result.ErrorMessage = ex.Message;
        }
        finally
        {
            result.ScanEndTime = DateTime.UtcNow;
        }

        return result;
    }

    public ScanResult Scan()
    {
        return ScanAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    private async Task<DirectoryEntry?> GetRootDirectoryEntryAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            if (!string.IsNullOrEmpty(_options.LdapPath))
            {
                return CreateDirectoryEntry(_options.LdapPath);
            }

            if (!string.IsNullOrEmpty(_options.DomainName))
            {
                var ldapPath = $"LDAP://{_options.DomainName}";
                return CreateDirectoryEntry(ldapPath);
            }

            var domain = Domain.GetCurrentDomain();
            return CreateDirectoryEntry($"LDAP://{domain.Name}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.WriteLine($"Warning: Could not get root directory entry: {ex.Message}");
            return null;
        }
    }

    private DirectoryEntry CreateDirectoryEntry(string path)
    {
        if (!string.IsNullOrEmpty(_options.Username) && !string.IsNullOrEmpty(_options.Password))
        {
            return new DirectoryEntry(path, _options.Username, _options.Password);
        }

        return new DirectoryEntry(path);
    }

    private async Task<List<ScannedAdObject>> ScanDirectoryObjectsAsync(
        DirectoryEntry rootEntry, 
        CancellationToken cancellationToken)
    {
        var scannedObjects = new List<ScannedAdObject>();
        
        try
        {
            using var searcher = CreateDirectorySearcher(rootEntry);
            searcher.PageSize = _options.PageSize;
            searcher.SearchScope = SearchScope.Subtree;
            searcher.SearchTimeout = _options.TimeoutSeconds;

            foreach (var property in CommonAttributes)
            {
                searcher.PropertiesToLoad.Add(property);
            }
            searcher.PropertiesToLoad.Add("ntSecurityDescriptor");

            if (!string.IsNullOrEmpty(_options.SearchFilter))
            {
                searcher.Filter = _options.SearchFilter;
            }
            else
            {
                searcher.Filter = BuildDefaultFilter();
            }

            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();

            using var results = searcher.FindAll();
            
            foreach (SearchResult result in results)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                try
                {
                    var scannedObject = ProcessSearchResult(result);
                    if (scannedObject != null)
                    {
                        scannedObjects.Add(scannedObject);
                    }
                }
                catch (Exception ex)
                {
                    if (_options.VerboseOutput)
                    {
                        Console.WriteLine($"Error processing object: {ex.Message}");
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (_options.VerboseOutput)
            {
                Console.WriteLine($"Search error: {ex.Message}");
            }
        }

        return scannedObjects;
    }

    private DirectorySearcher CreateDirectorySearcher(DirectoryEntry rootEntry)
    {
        var searcher = new DirectorySearcher(rootEntry);
        
        if (!string.IsNullOrEmpty(_options.Username) && !string.IsNullOrEmpty(_options.Password))
        {
            searcher.SearchClient = new DirectorySearcher(rootEntry)
            {
                AuthenticationType = AuthenticationTypes.Secure
            };
        }

        return searcher;
    }

    private string BuildDefaultFilter()
    {
        var classFilters = _options.ObjectClassesToScan
            .Select(c => $"(objectClass={c})")
            .ToList();

        if (classFilters.Count == 0)
        {
            return "(objectClass=*)";
        }

        if (classFilters.Count == 1)
        {
            return classFilters[0];
        }

        return $"(|{string.Join("", classFilters)})";
    }

    private ScannedAdObject? ProcessSearchResult(SearchResult result)
    {
        if (result.Properties["distinguishedName"].Count == 0)
            return null;

        var scannedObject = new ScannedAdObject
        {
            DistinguishedName = result.Properties["distinguishedName"][0]?.ToString() ?? string.Empty,
            Name = result.Properties["name"].Count > 0 
                ? result.Properties["name"][0]?.ToString() ?? string.Empty 
                : string.Empty,
            SamAccountName = result.Properties["sAMAccountName"].Count > 0
                ? result.Properties["sAMAccountName"][0]?.ToString()
                : null,
            ObjectClass = result.Properties["objectClass"].Count > 0
                ? result.Properties["objectClass"][result.Properties["objectClass"].Count - 1]?.ToString()
                : null,
            Description = result.Properties["description"].Count > 0
                ? result.Properties["description"][0]?.ToString()
                : null
        };

        scannedObject.ObjectType = DetermineObjectType(scannedObject.ObjectClass);
        scannedObject.WhenCreated = ParseDateTime(result.Properties["whenCreated"]);
        scannedObject.WhenChanged = ParseDateTime(result.Properties["whenChanged"]);
        scannedObject.IsEnabled = IsAccountEnabled(result);

        if (_options.ResolveGroupMemberships && 
            result.Properties["memberOf"].Count > 0)
        {
            foreach (var memberOf in result.Properties["memberOf"])
            {
                if (memberOf != null)
                {
                    scannedObject.MemberOf.Add(memberOf.ToString() ?? string.Empty);
                }
            }
        }

        var permissions = ExtractPermissions(result);
        scannedObject.Permissions = permissions;

        return scannedObject;
    }

    private AdObjectType DetermineObjectType(string? objectClass)
    {
        return objectClass?.ToLowerInvariant() switch
        {
            "user" => AdObjectType.User,
            "group" => AdObjectType.Group,
            "computer" => AdObjectType.Computer,
            "organizationalunit" => AdObjectType.OrganizationalUnit,
            "container" => AdObjectType.Container,
            _ => AdObjectType.Unknown
        };
    }

    private DateTime? ParseDateTime(PropertyValueCollection collection)
    {
        if (collection.Count == 0 || collection[0] == null)
            return null;

        if (DateTime.TryParse(collection[0]?.ToString(), out var result))
            return result;

        return null;
    }

    private bool IsAccountEnabled(SearchResult result)
    {
        if (result.Properties["userAccountControl"].Count == 0)
            return true;

        if (!int.TryParse(result.Properties["userAccountControl"][0]?.ToString(), out var uac))
            return true;

        const int AccountDisabled = 0x2;
        return (uac & AccountDisabled) == 0;
    }

    private List<AdPermissionEntry> ExtractPermissions(SearchResult result)
    {
        var permissions = new List<AdPermissionEntry>();

        try
        {
            using var entry = result.GetDirectoryEntry();
            var securityDescriptor = entry.Options.SecurityMasks;
            entry.Options.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner;

            var rawSecurity = entry.Properties["ntSecurityDescriptor"].Value as byte[];
            if (rawSecurity == null)
            {
                entry.Options.SecurityMasks = securityDescriptor;
                return permissions;
            }

            var adSecurity = new ActiveDirectorySecurity();
            adSecurity.SetSecurityDescriptorBinaryForm(rawSecurity);

            foreach (ActiveDirectoryAccessRule rule in adSecurity.GetAccessRules(
                true, _options.IncludeInheritedPermissions, typeof(NTAccount)))
            {
                var permission = new AdPermissionEntry
                {
                    IdentityReference = rule.IdentityReference?.Value ?? "Unknown",
                    ActiveDirectoryRights = rule.ActiveDirectoryRights,
                    AccessControlType = rule.AccessControlType,
                    InheritanceType = rule.InheritanceType,
                    InheritedObjectType = rule.InheritedObjectType?.ToString(),
                    ObjectTypeName = GetObjectTypeName(rule.ObjectType),
                    IsInherited = rule.IsInherited
                };

                permissions.Add(permission);
            }

            entry.Options.SecurityMasks = securityDescriptor;
        }
        catch (Exception ex)
        {
            if (_options.VerboseOutput)
            {
                Console.WriteLine($"Error extracting permissions: {ex.Message}");
            }
        }

        return permissions;
    }

    private string? GetObjectTypeName(Guid? guid)
    {
        if (guid == null || guid == Guid.Empty)
            return null;

        var wellKnownRights = new Dictionary<Guid, string>
        {
            { new Guid("00299570-246d-11d0-a768-00aa006e0529"), "User-Change-Password" },
            { new Guid("00299570-246d-11d0-a768-00aa006e0529"), "User-Force-Change-Password" },
            { new Guid("ab721a53-1e2f-11d0-9819-00aa0040529b"), "User-Account-Restrictions" },
            { new Guid("46a9b11d-60ae-405a-b7e8-ff8a58d456d2"), "Allowed-To-Authenticate" },
            { new Guid("91d67418-0135-4acc-8d79-c08e857cfbec"), "SAM-Logon" },
            { new Guid("c7407360-20bf-11d0-a768-00aa006e0529"), "Domain-Password" },
            { new Guid("5f202010-79a5-11d0-9020-08002b2cf4ee"), "General-Information" },
            { new Guid("bc0ac240-79a9-11d0-9020-08002b2cf4ee"), "Phone-And-Mail-Options" },
            { new Guid("a1990816-4298-11d1-ade2-00c04fd8d5cd"), "Web-Information" },
            { new Guid("77b5b886-944a-11d1-aebd-0000f80367c1"), "Personal-Information" },
            { new Guid("e45795b2-9455-11d1-aebd-0000f80367c1"), "User-Account-Picture" },
            { new Guid("e45795b3-9455-11d1-aebd-0000f80367c1"), "Other-Logon-Information" },
            { new Guid("59ba2f42-79a2-11d0-9020-00c04fc2d3cf"), "General-Information-Write" },
            { new Guid("4c164200-20c0-11d0-a768-00aa006e0529"), "User-Logon-Information" },
            { new Guid("5f202011-79a5-11d0-9020-08002b2cf4ee"), "Group-Membership" },
            { new Guid("bc0ac241-79a9-11d0-9020-08002b2cf4ee"), "Membership-Set" }
        };

        return wellKnownRights.TryGetValue(guid.Value, out var name) ? name : guid.ToString();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _rootEntry?.Dispose();
            }
            _disposed = true;
        }
    }
}
