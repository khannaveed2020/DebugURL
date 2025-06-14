@{
    # Script module or binary module file associated with this manifest.
    RootModule = '.\DebugURL.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.5'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID = 'd5f0cb9d-a818-49ad-ae90-6b707fc22718'

    # Author of this module
    Author = 'Naveed Khan'

    # Company or vendor of this module
    CompanyName = 'Hogwarts'

    # Copyright statement for this module
    Copyright = '(c) 2025 Naveed Khan. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Advanced URL debugging and testing module with comprehensive network analysis capabilities. Features include DNS resolution, SSL/TLS certificate details, response headers, content preview, proxy support, custom timeout settings, certificate validation skip option, custom user agent setting, HTTP methods support, custom headers, and concurrent requests for performance testing.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell host required by this module
    PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'

    # Processor architecture (None, X86, Amd64) required by this module
    ProcessorArchitecture = 'None'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'DebugURL',
        'Get-DNSCache',
        'Debug-URLWithProxy',
        'Debug-URLWithTimeout',
        'Debug-URLWithMetrics',
        'Debug-URLWithLoad',
        'Debug-URLWithTLS',
        'Debug-URLWithCipher',
        'Debug-URLWithLogging',
        'Debug-URLWithUserAgent',
        'Debug-URLWithResponseAnalysis'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @()

    # DSC resources to export from this module
    DscResourcesToExport = @()

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'DebugURL.psm1',
        'DebugURL.psd1',
        'README.md',
        'LICENSE'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('URL', 'Debug', 'Network', 'Testing', 'DNS', 'Performance', 'SSL', 'TLS', 'HTTP', 'HTTPS')
            LicenseUri = 'https://github.com/khannaveed2020/DebugURL/blob/main/LICENSE'
            ProjectUri = 'https://github.com/khannaveed2020/DebugURL'
            ReleaseNotes = 'Fixed concurrent requests timing calculations in PowerShell 5.1'
            Prerelease = ''
            RequireLicenseAcceptance = $false
            ExternalModuleDependencies = @()
            IconUri = 'https://raw.githubusercontent.com/khannaveed2020/DebugURL/main/icon.png'
            ReadMeUri = 'https://github.com/khannaveed2020/DebugURL/blob/main/README.md'
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/khannaveed2020/DebugURL/issues'
} 
# SIG # Begin signature block
# MIIFbQYJKoZIhvcNAQcCoIIFXjCCBVoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULvhPb4s+R76LBvFovVZCggQX
# zXigggMPMIIDCzCCAfOgAwIBAgIQJgQwjqAm/LBKanySwwIfRTANBgkqhkiG9w0B
# AQsFADATMREwDwYDVQQDDAhEZWJ1Z1VSTDAeFw0yNTA2MTIxNDE1MzNaFw0zMDA2
# MTIxNDI1MzJaMBMxETAPBgNVBAMMCERlYnVnVVJMMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAoZruS/TeQPApPG5lBBVlSHYnCSP/c47EXkxMDVHSaNLO
# Wq/Z153KujL30uom6qnmIriiBvEB6DWDoNcAxUXshiHYy+zXyOwts4E3LGmJPthQ
# bcx+odgbXK0N+YAC4TtkrRudnPdA/3DQGVbZ1HqwnnHcIrwSDFgABCpoBFduPYtV
# 783soSXgudjrMwanrod47qnvDF9xbjVFwGhjCLicGzkjq/bnhmlv90X17EVBJj+1
# w3S4Yd3/0AyU9J4wRWb8PoA3QmceYVDltlEH6JQEkJzpZmtWIUzEstwp8yUDMbHL
# JMFMupeUHOpdL4MJYCWEdlfj6Rfn2XZAwCxxoYRL7QIDAQABo1swWTAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEwYDVR0RBAwwCoIIRGVidWdV
# UkwwHQYDVR0OBBYEFM5IJfifmZ+wCzA7yF6SIp+OD4i0MA0GCSqGSIb3DQEBCwUA
# A4IBAQAfxnq8hJcaou1urLS/x892gRIfE5kr4uZgWwTkR1v4562TgQbsI6FvwDj+
# 9f/kr5lKWQXnTQ0lKOBnR/5ipAY3e+Ed6mauno0RJKWUYQlueRykGEPd21YtaRVk
# 2dr8QOt1ZGxLeL07+Xv80tgdQo1BaznytzSGcoNH65QuNrB6A5O2T48eUk8dsLP8
# Xo3ktPLvnEDrzfxZwbB82kasXZ+peGq51iowaczC0RQuwKn1m0VnDa7tclDihPcb
# pzGtyZYgHcZW9AElFr3P8Zge+hJv8f1QwhZJh7E8yDNKty1i41Weut3dpYYpY2P9
# 30OVzYrx+YSO02WAzoWnazobrsdGMYIByDCCAcQCAQEwJzATMREwDwYDVQQDDAhE
# ZWJ1Z1VSTAIQJgQwjqAm/LBKanySwwIfRTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUUfHVsrTj
# DSA9q1DBAythPZUt5/MwDQYJKoZIhvcNAQEBBQAEggEAIa0ql9UXExzDbqD8wyi0
# VsUidtQOx2NEZjrP8LZeJYcIO7dpyRADMdmUvsxG9ZXjXhITlOp3ZnNvhrRuBwV3
# 3g+JRZjwuJi2rKGz4zIIBlJSeNgFwgMkt5iYor6hNT8bTp5+2eyLHeHreDBrGWHZ
# Gov3WMBDtu0Hn+5iH4GulLdk8ZNl0tPD8z5861H6/2PxfV1fCUhvn+GWm55Rjx4E
# bOtWwjxRb98GNwcsKYr16Fji11fVlBjV/5uAOtgQCUtLDUFDxxyB1mI0F3jvpVr/
# 3dpnbSRLPuG6v4imwtYEWDq8AcpsEIad1F0wuHpPdP2rPxIVlOeBISueigUyyAbw
# 4Q==
# SIG # End signature block
