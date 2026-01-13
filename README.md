# Active Directory Permission Scanner

A comprehensive .NET tool for scanning and auditing Active Directory permissions and access controls. This utility helps security teams identify potentially dangerous permission configurations, excessive privileges, and access control issues within Active Directory environments.

## Features

- **Permission Scanning**: Enumerate and analyze permissions on AD objects including users, groups, computers, and OUs
- **Risk Assessment**: Automatically classify findings by severity (Critical, High, Medium, Low)
- **Multiple Output Formats**: Generate reports in Text, JSON, CSV, or HTML formats
- **Flexible Filtering**: Use custom LDAP filters to target specific objects
- **High-Risk Detection**: Identify dangerous permissions like GenericAll, WriteDacl, WriteOwner
- **Inheritance Analysis**: Track inherited vs. explicit permissions
- **Configurable Options**: Adjust timeout, page size, and scan scope

## Requirements

- .NET 8.0 SDK or later
- Windows environment with Active Directory access
- Appropriate permissions to read AD security descriptors

## Installation

### Clone and Build

```bash
git clone <repository-url>
cd ad-perm-scanner
dotnet restore
dotnet build --configuration Release
```

### Install as Global Tool (Optional)

```bash
dotnet pack --configuration Release
dotnet tool install --global --add-source ./nupkg ad-perm-scanner
```

## Usage

### Basic Usage

Scan the current domain with default settings:

```bash
dotnet run
```

### Scan Specific Domain

```bash
dotnet run -- --domain contoso.com
```

### Scan Specific OU

```bash
dotnet run -- --ldap-path "LDAP://OU=Users,DC=contoso,DC=com"
```

### Generate HTML Report

```bash
dotnet run -- --domain contoso.com --format Html --output report.html
```

### Show Only High-Risk Findings

```bash
dotnet run -- --high-risk-only --verbose
```

### Use Custom LDAP Filter

```bash
dotnet run -- --filter "(objectClass=user)" --format Json --output users.json
```

### Full Example with Authentication

```bash
dotnet run -- \
  --domain contoso.com \
  --username admin@contoso.com \
  --password "SecurePassword123" \
  --output audit-report.json \
  --format Json \
  --timeout 60 \
  --verbose
```

## Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--domain` | `-d` | Active Directory domain to scan | Current domain |
| `--ldap-path` | `-l` | Specific LDAP path to scan | Domain root |
| `--username` | `-u` | Username for authentication | Current user |
| `--password` | `-p` | Password for authentication | - |
| `--output` | `-o` | Output file path for report | Console |
| `--format` | `-f` | Output format (Text/Json/Csv/Html) | Text |
| `--timeout` | `-t` | LDAP operation timeout (seconds) | 30 |
| `--page-size` | - | LDAP query page size | 1000 |
| `--include-inherited` | `-i` | Include inherited permissions | true |
| `--verbose` | `-v` | Enable verbose output | false |
| `--list-only` | - | List objects without details | false |
| `--high-risk-only` | - | Show only high-risk objects | false |
| `--filter` | - | Custom LDAP filter | Default |

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Program.cs                              │
│                    (CLI Entry Point)                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      AdScanner.cs                            │
│              (Core Scanning Logic)                           │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ DirectorySearch │  │ Permission      │                   │
│  │                 │  │ Extraction      │                   │
│  └─────────────────┘  └─────────────────┘                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    AdPermission.cs                           │
│                  (Data Models)                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ AdPermission │  │ ScannedAdObj │  │   ScanResult │       │
│  │    Entry     │  │     ect      │  │              │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   ReportGenerator.cs                         │
│               (Report Generation)                            │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐             │
│  │   Text     │  │    JSON    │  │    HTML    │             │
│  │  Report    │  │   Report   │  │   Report   │             │
│  └────────────┘  └────────────┘  └────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

### Scanning Process

1. **Connection**: Establishes connection to Active Directory using LDAP
2. **Discovery**: Searches for objects matching specified criteria
3. **Permission Extraction**: Reads security descriptors from each object
4. **Analysis**: Evaluates permissions for risk level
5. **Reporting**: Generates formatted output

### Permission Risk Levels

| Level | Criteria |
|-------|----------|
| **Critical** | Non-inherited GenericAll permissions |
| **High** | WriteDacl, WriteOwner permissions |
| **Medium** | GenericWrite, Delete permissions |
| **Low** | Read-only or standard permissions |

### High-Risk Permissions Detected

- `GenericAll` - Full control over object
- `GenericWrite` - Write access to all properties
- `WriteDacl` - Can modify object's ACL
- `WriteOwner` - Can take ownership of object
- `Delete` - Can delete the object
- `ExtendedRight` - Special extended rights (e.g., password reset)

## Output Examples

### Text Report Summary

```
================================================================================
ACTIVE DIRECTORY PERMISSION SCAN REPORT
================================================================================
Scan Target:      contoso.com
Scan Started:     2024-01-15 10:30:00 UTC
Scan Completed:   2024-01-15 10:30:45 UTC
Duration:         45.23 seconds

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
Total Objects Scanned:    1523
Total Permissions Found:  8947

Findings by Severity:
  Critical:  12
  High:      45
  Medium:    156
  Low:       1310
```

### JSON Report Structure

```json
{
  "reportInfo": {
    "scanTarget": "contoso.com",
    "scanStartTime": "2024-01-15T10:30:00Z",
    "durationSeconds": 45.23
  },
  "summary": {
    "totalObjectsScanned": 1523,
    "criticalFindings": 12
  },
  "objects": [...]
}
```

## Running Tests

```bash
cd tests
dotnet test
```

## Security Considerations

- Run with least privilege necessary for the scan
- Avoid storing passwords in command history
- Use secure channels (LDAPS) in production
- Review generated reports before sharing
- Consider running from a secured jump host

## Troubleshooting

### "Access Denied" Errors

Ensure the account running the scanner has:
- Read permissions on target objects
- Read permissions on security descriptors
- Network access to domain controllers

### Slow Scan Performance

- Reduce page size with `--page-size 500`
- Use specific LDAP filters to narrow scope
- Scan specific OUs instead of entire domain
- Increase timeout for large environments

### Connection Issues

- Verify domain name is correct
- Check network connectivity to domain controllers
- Ensure DNS resolution is working
- Try specifying explicit LDAP path

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `dotnet test`
5. Submit a pull request
