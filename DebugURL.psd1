@{
    # Script module or binary module file associated with this manifest.
    RootModule = '.\DebugURL.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.6'

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
        'Test-MultipleStatusCodes'
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
            ReleaseNotes = 'Added FormData parameter support with automatic URL encoding and fixed concurrent requests with SkipCertCheck for both PowerShell 5.1 and 7+'
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