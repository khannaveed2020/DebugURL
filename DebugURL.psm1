# DebugURL PowerShell Module
# Author: Naveed Khan
# Version: 1.0.5
# Description: Advanced URL debugging and testing module with comprehensive network analysis capabilities
# License: MIT License
# GitHub: https://github.com/khannaveed2020/DebugURL

#region Module Documentation
<#
.SYNOPSIS
    Advanced URL debugging and testing module with comprehensive network analysis capabilities.

.DESCRIPTION
    The DebugURL module provides comprehensive URL testing and debugging capabilities, including:
    - DNS resolution details
    - Request header information
    - SSL/TLS certificate details
    - Response headers
    - Content preview
    - Proxy support
    - Custom timeout settings
    - Certificate validation skip option
    - Custom user agent setting
    - HTTP methods support
    - Custom headers
    - Concurrent requests for performance testing

.NOTES
    Version: 1.0.5
    Author: Naveed Khan
    License: MIT License
    GitHub: https://github.com/khannaveed2020/DebugURL

.EXAMPLE
    DebugURL -URL "https://example.com"
    Performs a basic GET request to example.com and displays detailed information.

.EXAMPLE
    DebugURL -URL "https://example.com" -ConcurrentRequests 5
    Performs 5 concurrent requests to example.com for performance testing.

.EXAMPLE
    DebugURL -URL "https://example.com" -SkipCertCheck
    Performs a request while skipping SSL certificate validation.

.LINK
    https://github.com/khannaveed2020/DebugURL
#>
#endregion

# Add error handling for module loading
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'

function Format-Size {
    param (
        [long]$Bytes
    )

    $sizes = @('B', 'KB', 'MB', 'GB')
    $index = 0
    $size = $Bytes

    while ($size -gt 1024 -and $index -lt $sizes.Count - 1) {
        $size = $size / 1024
        $index++
    }

    return "$([math]::Round($size, 2)) $($sizes[$index])"
}

function Get-ErrorClassification {
    param (
        [string]$ErrorMessage
    )

    $errorTypes = @{
        'timeout' = 'Connection Timeout'
        'dns' = 'DNS Resolution Error'
        'ssl' = 'SSL/TLS Error'
        'connection refused' = 'Connection Refused'
        'not found' = 'Resource Not Found'
        'unauthorized' = 'Authentication Required'
        'forbidden' = 'Access Forbidden'
    }

    foreach ($type in $errorTypes.Keys) {
        if ($ErrorMessage -match $type) {
            return $errorTypes[$type]
        }
    }

    return 'General Error'
}

function Get-ResponseAnalysis {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Response
    )

    $analysis = @{
        'ContentType' = $null
        'CharacterSet' = $null
        'IsCompressed' = $false
        'IsChunked' = $false
        'CacheControl' = $null
    }

    try {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            # PowerShell 7+ handling
            $analysis['ContentType'] = $Response.Headers['Content-Type']
            $analysis['CharacterSet'] = $Response.Headers['Character-Set']
            $analysis['IsCompressed'] = $Response.Headers['Content-Encoding'] -match 'gzip|deflate'
            $analysis['IsChunked'] = $Response.Headers['Transfer-Encoding'] -eq 'chunked'
            $analysis['CacheControl'] = $Response.Headers['Cache-Control']
        } else {
            # PowerShell 5.1 handling
            $analysis['ContentType'] = $Response.ContentType
            $analysis['CharacterSet'] = $Response.CharacterSet
            $analysis['IsCompressed'] = $Response.Headers['Content-Encoding'] -match 'gzip|deflate'
            $analysis['IsChunked'] = $Response.Headers['Transfer-Encoding'] -eq 'chunked'
            $analysis['CacheControl'] = $Response.Headers['Cache-Control']
        }
    } catch {
        Write-Debug "Error analyzing response: $($_.Exception.Message)"
    }

    return $analysis
}

function Get-HTTPStatusInfo {
    param (
        [int]$StatusCode
    )

    $statusInfo = @{
        'Category' = switch ($StatusCode) {
            { $_ -ge 100 -and $_ -lt 200 } { 'Informational' }
            { $_ -ge 200 -and $_ -lt 300 } { 'Success' }
            { $_ -ge 300 -and $_ -lt 400 } { 'Redirection' }
            { $_ -ge 400 -and $_ -lt 500 } { 'Client Error' }
            { $_ -ge 500 -and $_ -lt 600 } { 'Server Error' }
            default { 'Unknown' }
        }
        'Description' = switch ($StatusCode) {
            200 { 'OK - The request has succeeded' }
            201 { 'Created - The request has succeeded and a new resource has been created' }
            204 { 'No Content - The server successfully processed the request but returns no content' }
            301 { 'Moved Permanently - The requested resource has been permanently moved' }
            302 { 'Found - The requested resource has been temporarily moved' }
            304 { 'Not Modified - The resource has not been modified since the last request' }
            400 { 'Bad Request - The server cannot process the request due to client error' }
            401 { 'Unauthorized - Authentication is required' }
            403 { 'Forbidden - Server refuses to authorize the request' }
            404 { 'Not Found - The requested resource does not exist' }
            405 { 'Method Not Allowed - The HTTP method is not supported for this resource' }
            408 { 'Request Timeout - The server timed out waiting for the request' }
            409 { 'Conflict - The request conflicts with the current state of the server' }
            413 { 'Payload Too Large - The request entity is larger than the server is willing to process' }
            415 { 'Unsupported Media Type - The server does not support the media type of the request' }
            429 { 'Too Many Requests - Rate limit exceeded' }
            500 { 'Internal Server Error - Server encountered an unexpected condition' }
            501 { 'Not Implemented - The server does not support the functionality required' }
            502 { 'Bad Gateway - Server received an invalid response from upstream' }
            503 { 'Service Unavailable - Server is temporarily unable to handle the request' }
            504 { 'Gateway Timeout - Server did not receive a timely response from upstream' }
            505 { 'HTTP Version Not Supported - The server does not support the HTTP version used' }
            default { 'Unknown status code' }
        }
        'SuggestedAction' = switch ($StatusCode) {
            405 { 'Verify the HTTP method is supported by the endpoint and check API documentation' }
            { $_ -ge 400 -and $_ -lt 500 } { 'Check request parameters, authentication, and client configuration' }
            { $_ -ge 500 -and $_ -lt 600 } { 'Contact server administrator or try again later' }
            default { 'No specific action required' }
        }
    }

    return $statusInfo
}

function Get-SSLCertificate {
    <#
    .SYNOPSIS
        Retrieves SSL certificate information for a specified hostname and port.

    .DESCRIPTION
        Gets detailed SSL certificate information including TLS version, cipher algorithms, and certificate details.

    .PARAMETER Hostname
        The hostname to check the SSL certificate for.

    .PARAMETER Port
        The port number to connect to. Default is 443.

    .PARAMETER SkipValidation
        Whether to skip certificate validation. Default is false.

    .EXAMPLE
        Get-SSLCertificate -Hostname "example.com"
        Gets SSL certificate information for example.com on port 443.

    .EXAMPLE
        Get-SSLCertificate -Hostname "example.com" -Port 8443 -SkipValidation
        Gets SSL certificate information for example.com on port 8443, skipping validation.

    .OUTPUTS
        [hashtable] containing certificate details.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Hostname,

        [Parameter(Mandatory=$false)]
        [int]$Port = 443,

        [Parameter(Mandatory=$false)]
        [bool]$SkipValidation = $false
    )

    try {
        Write-Verbose "Connecting to $Hostname on port $Port"
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Hostname, $Port)

        Write-Verbose "Creating SSL stream"
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            {
                param($senderObj, $cert, $certChain, $errors)
                if ($SkipValidation) {
                    Write-Verbose "Skipping certificate validation"
                    return $true
                }
                return [System.Net.Security.SslPolicyErrors]::None -eq $errors
            }
        )

        Write-Verbose "Authenticating SSL stream"
        $sslStream.AuthenticateAsClient($Hostname)

        # Get the actual TLS version
        $tlsVersion = switch ($sslStream.SslProtocol) {
            'Tls' { 'TLS 1.0' }
            'Tls11' { 'TLS 1.1' }
            'Tls12' { 'TLS 1.2' }
            'Tls13' { 'TLS 1.3' }
            default { $sslStream.SslProtocol.ToString() }
        }

        Write-Verbose "TLS Version: $tlsVersion"
        return @{
            Certificate = $sslStream.RemoteCertificate
            TLSVersion = $tlsVersion
            CipherAlgorithm = $sslStream.CipherAlgorithm.ToString()
            HashAlgorithm = $sslStream.HashAlgorithm.ToString()
            KeyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm.ToString()
        }
    }
    catch {
        Write-Verbose "SSL Certificate Error: $($_.Exception.Message)"
        Write-Debug "Detailed error: $($_.Exception | ConvertTo-Json -Depth 10)"
        return $null
    }
    finally {
        if ($sslStream) {
            Write-Verbose "Disposing SSL stream"
            $sslStream.Dispose()
        }
        if ($tcpClient) {
            Write-Verbose "Disposing TCP client"
            $tcpClient.Dispose()
        }
    }
}

function Get-ResponseContent {
    param (
        [Parameter(Mandatory=$true)]
        [System.Net.WebResponse]$Response
    )

    try {
        $stream = $Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Format-ResponseTime {
    param (
        [double]$Seconds
    )

    if ($Seconds -lt 1) {
        return "$([math]::Round($Seconds * 1000, 2)) ms"
    }
    return "$([math]::Round($Seconds, 3)) seconds"
}

function DebugURL {
    <#
    .SYNOPSIS
        Performs comprehensive URL testing and debugging with detailed network analysis.

    .DESCRIPTION
        The DebugURL function provides detailed analysis of URL connectivity, including:
        - DNS resolution details
        - SSL/TLS certificate information
        - Request and response headers
        - HTTP status code analysis
        - Performance metrics
        - Concurrent request testing

    .PARAMETER URL
        The URL to test. This parameter is mandatory.

    .PARAMETER Method
        The HTTP method to use. Valid values are: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH.
        Default is GET.

    .PARAMETER Headers
        A hashtable of custom headers to include in the request.

    .PARAMETER Body
        The request body content.

    .PARAMETER SkipCertCheck
        Skip SSL certificate validation.

    .PARAMETER UserAgent
        Custom User-Agent string. Default is "DebugURL-PowerShell-Module/1.0".

    .PARAMETER Timeout
        Request timeout in seconds. Default is 30.

    .PARAMETER Proxy
        Proxy server URL.

    .PARAMETER ConcurrentRequests
        Number of concurrent requests for performance testing. Default is 1.

    .PARAMETER LogPath
        Path to save detailed logs of the debugging process.

    .EXAMPLE
        DebugURL -URL "https://example.com"
        Performs a basic GET request to example.com with detailed analysis.

    .EXAMPLE
        DebugURL -URL "https://api.example.com" -Method POST -Headers @{"Authorization"="Bearer token"}
        Performs a POST request with custom headers.

    .OUTPUTS
        None. Outputs detailed analysis to the console.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$URL,

        [Parameter(Mandatory=$false)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')]
        [string]$Method = 'GET',

        [Parameter(Mandatory=$false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory=$false)]
        [string]$Body,

        [Parameter(Mandatory=$false)]
        [switch]$SkipCertCheck,

        [Parameter(Mandatory=$false)]
        [string]$UserAgent = "DebugURL-PowerShell-Module/1.0",

        [Parameter(Mandatory=$false)]
        [int]$Timeout = 30,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,

        [Parameter(Mandatory=$false)]
        [int]$ConcurrentRequests = 1,

        [Parameter(Mandatory=$false)]
        [string]$LogPath
    )

    try {
        # Initialize timeline tracking and request start time
        $timeline = [ordered]@{
            'DNS Resolution' = 0
            'TCP Connection' = 0
            'SSL Handshake' = 0
            'Request Send' = 0
            'Response Wait' = 0
            'Total Time' = 0
        }

        $startTime = Get-Date
        $requestStartTime = $startTime  # Initialize requestStartTime here

        # Initialize logging if LogPath is provided
        $logStream = $null
        if ($LogPath) {
            try {
                # Create log directory if it doesn't exist
                $logDir = Split-Path -Path $LogPath -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }
                
                # Create log file with timestamp
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $logFile = Join-Path $LogPath "DebugURL_$timestamp.log"
                
                # Ensure the log file directory exists
                $logFileDir = Split-Path -Path $logFile -Parent
                if (-not (Test-Path $logFileDir)) {
                    New-Item -ItemType Directory -Path $logFileDir -Force | Out-Null
                }
                
                $logStream = [System.IO.StreamWriter]::new($logFile)
                
                # Write initial log information
                $logStream.WriteLine("DebugURL Log - Started at $(Get-Date)")
                $logStream.WriteLine("URL: $URL")
                $logStream.WriteLine("Method: $Method")
                
                # Convert headers to a serializable format
                $headerObj = @{}
                foreach ($key in $Headers.Keys) {
                    $headerObj[$key.ToString()] = $Headers[$key].ToString()
                }
                $logStream.WriteLine("Headers: $($headerObj | ConvertTo-Json -Compress)")
                
                $logStream.WriteLine("Timeout: $Timeout seconds")
                $logStream.WriteLine("SkipCertCheck: $SkipCertCheck")
                $logStream.WriteLine("UserAgent: $UserAgent")
                if ($Proxy) { $logStream.WriteLine("Proxy: $Proxy") }
                if ($Body) { $logStream.WriteLine("Body: $Body") }
                $logStream.WriteLine("ConcurrentRequests: $ConcurrentRequests")
                $logStream.WriteLine("----------------------------------------")
            }
            catch {
                Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
                Write-Debug "Log initialization error: $($_.Exception | ConvertTo-Json -Depth 3)"
            }
        }

        Write-Debug "Starting DebugURL function with URL: $URL"
        Write-Verbose "Initializing request with Method: $Method, Timeout: $Timeout seconds"

        # Parse URL
        $uri = [System.Uri]$URL
        Write-Debug "Parsed URL - Scheme: $($uri.Scheme), Host: $($uri.Host), Port: $($uri.Port)"
        if ($logStream) {
            $logStream.WriteLine("URL Details:")
            $logStream.WriteLine("  Scheme: $($uri.Scheme)")
            $logStream.WriteLine("  Host: $($uri.Host)")
            $logStream.WriteLine("  Port: $($uri.Port)")
            $logStream.WriteLine("  Path: $($uri.PathAndQuery)")
        }

        # DNS Resolution
        Write-Verbose "Performing DNS resolution for $($uri.Host)"
        $dnsStartTime = Get-Date
        try {
            $dnsResult = Resolve-DnsName -Name $uri.Host -ErrorAction Stop
            $dnsEndTime = Get-Date
            $timeline['DNS Resolution'] = ($dnsEndTime - $dnsStartTime).TotalSeconds
            if ($logStream) {
                $logStream.WriteLine("DNS Resolution Results:")
                # Convert DNS results to a serializable format
                $dnsObj = @{}
                foreach ($record in $dnsResult) {
                    $dnsObj[$record.Name] = @{
                        'Type' = $record.Type
                        'IPAddress' = $record.IPAddress
                        'TTL' = $record.TTL
                    }
                }
                $dnsJson = $dnsObj | ConvertTo-Json -Compress
                $logStream.WriteLine($dnsJson)
                $logStream.WriteLine("DNS Resolution Time: $($timeline['DNS Resolution']) seconds")
            }
            $dnsTable = $dnsResult | Format-Table Name, Type, IPAddress, QueryType, Section | Out-String
            Write-Output "==================== DNS Resolution ===================="
            Write-Output $dnsTable.TrimEnd()
            Write-Output ""
        }
        catch {
            $errorDetails = @{
                'Hostname' = $uri.Host
                'Error' = $_.Exception.Message
                'Type' = Get-ErrorClassification -ErrorMessage $_.Exception.Message
                'Timestamp' = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                'DNS_Servers' = (Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses
            }

            # Get relevant cache entries only if they exist and have data
            $cacheEntries = Get-DnsClientCache | Where-Object {
                $_.Entry -like "*$($uri.Host)*" -and 
                $_.Data -and 
                $_.Record -and 
                $_.TTL -gt 0
            } | Select-Object Entry, Record, Data, TTL

            # Update timeline
            $dnsEndTime = Get-Date
            $timeline['DNS Resolution'] = ($dnsEndTime - $dnsStartTime).TotalSeconds
            $timeline['Total Time'] = ($dnsEndTime - $startTime).TotalSeconds

            # Display detailed error information
            Write-Output "==================== DNS Resolution Error ===================="
            Write-Output "Hostname: $($errorDetails.Hostname)"
            Write-Output "Error Type: $($errorDetails.Type)"
            Write-Output "Error Message: $($errorDetails.Error)"
            Write-Output "Timestamp: $($errorDetails.Timestamp)"
            Write-Output ""
            Write-Output "DNS Configuration:"
            Write-Output "  Configured DNS Servers:"
            foreach ($server in $errorDetails.DNS_Servers) {
                Write-Output "    - $server"
            }
            Write-Output ""
            
            if ($cacheEntries) {
                Write-Output "Relevant DNS Cache Entries:"
                $cacheEntries | Format-Table Entry, Record, Data, TTL
            } else {
                Write-Output "No relevant entries found in local DNS cache."
            }
            Write-Output ""
            Write-Output "Troubleshooting Suggestions:"
            Write-Output "  1. Verify the hostname is spelled correctly"
            Write-Output "  2. Check your network connection"
            Write-Output "  3. Verify DNS server configuration"
            Write-Output "  4. Try using a different DNS server"
            Write-Output "  5. Check if the hostname is accessible from other devices"
            Write-Output ""

            # Display timeline only once
            Write-Output "=================== Request Timeline ==================="
            $timelineObj = New-Object PSObject -Property $timeline
            Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
            Write-Output ""

            if ($logStream) {
                $logStream.WriteLine("DNS Resolution Error:")
                $logStream.WriteLine("  Error: $($_.Exception.Message)")
                $logStream.WriteLine("  Type: $(Get-ErrorClassification -ErrorMessage $_.Exception.Message)")
                $logStream.WriteLine("  DNS Servers: $($errorDetails.DNS_Servers -join ', ')")
                if ($cacheEntries) {
                    $logStream.WriteLine("  Cache Entries: $($cacheEntries | ConvertTo-Json -Compress)")
                }
            }

            # Set a flag to indicate we've already handled the error
            $script:errorHandled = $true
            
            # Throw a more concise error without the redundant prefix
            throw "Unable to resolve hostname '$($uri.Host)'"
        }

        # Get SSL Certificate Info for HTTPS
        $actualTLSVersion = "N/A"
        $certInfo = $null
        if ($uri.Scheme -eq 'https') {
            $sslStartTime = Get-Date
            Write-Verbose "Retrieving SSL certificate information"
            try {
                $certInfo = Get-SSLCertificate -Hostname $uri.Host -Port $uri.Port -SkipValidation:$SkipCertCheck
                $sslEndTime = Get-Date
                $timeline['SSL Handshake'] = ($sslEndTime - $sslStartTime).TotalSeconds
                if ($certInfo) {
                    $actualTLSVersion = $certInfo.TLSVersion
                    Write-Debug "SSL Certificate Info - TLS Version: $actualTLSVersion, Cipher: $($certInfo.CipherAlgorithm)"
                }
            } catch {
                $errorDetails = @{
                    'Hostname' = $uri.Host
                    'Error' = $_.Exception.Message
                    'Type' = Get-ErrorClassification -ErrorMessage $_.Exception.Message
                }

                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    Write-Warning "SSL Certificate Error: Unable to retrieve certificate for '$($uri.Host)'"
                    Write-Debug ($errorDetails | ConvertTo-Json -Depth 3)
                } else {
                    Write-Warning "SSL Certificate Error: Unable to retrieve certificate for '$($uri.Host)'"
                    Write-Debug "Error Details: $($errorDetails | ConvertTo-Json -Depth 3)"
                }
            }
        }

        # Create Request Headers Output
        Write-Verbose "Preparing request headers"
        $requestHeaders = [ordered]@{
            'Host' = $uri.Host
            'Method' = $Method
            'Port' = $uri.Port
            'TLS Version' = if ($uri.Scheme -eq 'https') { $actualTLSVersion } else { "N/A (HTTP)" }
            'User-Agent' = $UserAgent
        }

        # Add custom headers
        foreach ($header in $Headers.GetEnumerator()) {
            Write-Debug "Adding custom header: $($header.Key) = $($header.Value)"
            $requestHeaders[$header.Key] = $header.Value
        }

        Write-Output "==================== Request Headers ==================="
        $requestHeadersObj = New-Object PSObject -Property $requestHeaders
        Write-Output ($requestHeadersObj | Format-List | Out-String).TrimEnd()
        Write-Output ""

        # Display SSL Certificate Info for HTTPS
        if ($uri.Scheme -eq 'https') {
            Write-Verbose "Displaying certificate details"
            Write-Output "================== Certificate Details ================="

            if ($certInfo) {
                $cert = $certInfo.Certificate
                Write-Debug "Certificate Details - Subject: $($cert.Subject), Expires: $($cert.GetExpirationDateString())"
                $certDetails = [ordered]@{
                    'Thumbprint' = $cert.GetCertHashString()
                    'Subject' = $cert.Subject
                    'Issuer' = $cert.Issuer
                    'NotAfter' = $cert.GetExpirationDateString()
                    'TLS Version' = $certInfo.TLSVersion
                    'Cipher Algorithm' = $certInfo.CipherAlgorithm
                    'Hash Algorithm' = $certInfo.HashAlgorithm
                    'Key Exchange Algorithm' = $certInfo.KeyExchangeAlgorithm
                }
                $certObj = New-Object PSObject -Property $certDetails
                Write-Output ($certObj | Format-List | Out-String).TrimEnd()
            }
            else {
                Write-Warning "Unable to retrieve certificate details"
            }
            Write-Output ""
        }

        # Handle concurrent requests
        if ($ConcurrentRequests -gt 1) {
            Write-Verbose "Processing $ConcurrentRequests concurrent requests"
            Write-Debug "Concurrent request parameters - URL: $URL, Method: $Method, Timeout: $Timeout"
            Write-Output "`n================== Concurrent Requests Summary =================="
            Write-Output "Concurrent Requests: $ConcurrentRequests"

            $jobs = @()
            $startTime = Get-Date

            # Create and start jobs
            for ($i = 1; $i -le $ConcurrentRequests; $i++) {
                Write-Debug "Starting job $i of $ConcurrentRequests"
                $jobScript = {
                    param($URL, $Method, $Headers, $UserAgent, $Timeout, $SkipCertCheck, $Proxy, $Body, $PSVersion)

                    $ErrorActionPreference = 'Stop'
                    $result = @{
                        Success = $false
                        Time = 0
                        Status = $null
                        Error = $null
                        Content = $null
                    }

                    try {
                        Write-Debug "Job: Preparing request parameters"
                        # Create a clean copy of headers without invalid characters
                        $cleanHeaders = @{}
                        foreach ($key in $Headers.Keys) {
                            if ($key -notmatch '[^a-zA-Z0-9\-]') {
                                $cleanHeaders[$key] = $Headers[$key]
                            }
                        }

                        $requestParams = @{
                            Uri = $URL
                            Method = $Method
                            Headers = $cleanHeaders
                            UserAgent = $UserAgent
                            TimeoutSec = $Timeout
                            ErrorAction = 'Stop'
                        }

                        if ($SkipCertCheck) {
                            Write-Debug "Job: Skipping certificate validation"
                            $requestParams['SkipCertificateCheck'] = $true
                        }

                        if ($Proxy) {
                            Write-Debug "Job: Using proxy: $Proxy"
                            $requestParams['Proxy'] = $Proxy
                        }

                        if ($Body) {
                            Write-Debug "Job: Adding request body"
                            $requestParams['Body'] = $Body
                        }

                        Write-Debug "Job: Sending request"
                        $jobStartTime = Get-Date
                        $response = Invoke-WebRequest @requestParams
                        $jobEndTime = Get-Date

                        $result.Success = $true
                        $result.Time = ($jobEndTime - $jobStartTime).TotalSeconds
                        $result.Status = $response.StatusCode
                        $result.Content = if ($response.Content) { $response.Content } else { "" }
                        Write-Debug "Job: Request completed successfully in $($result.Time) seconds"
                    }
                    catch {
                        Write-Debug "Job: Request failed with error: $($_.Exception.Message)"
                        $result.Error = $_.Exception.Message
                    }

                    return $result
                }

                $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $URL, $Method, $requestHeaders, $UserAgent, $Timeout, $SkipCertCheck, $Proxy, $Body, $PSVersionTable.PSVersion.Major
            }

            Write-Verbose "Waiting for all jobs to complete"
            $jobResults = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job

            # Process results
            $successCount = 0
            $totalTime = 0
            $requestNumber = 1

            foreach ($result in $jobResults) {
                if ($result.Success) {
                    $successCount++
                    $totalTime += $result.Time
                    Write-Output "Request $requestNumber`: Success, Time: $(Format-ResponseTime -Seconds $result.Time), Status: $($result.Status)"
                    Write-Debug "Request $requestNumber details - Time: $($result.Time)s, Status: $($result.Status)"
                }
                else {
                    Write-Output "Request $requestNumber`: Fail, Time: $(Format-ResponseTime -Seconds $result.Time), Status: N/A - $($result.Error)"
                    Write-Debug "Request $requestNumber failed - Error: $($result.Error)"
                }
                $requestNumber++
            }

            if ($successCount -gt 0) {
                $avgTime = $totalTime / $successCount
                # Create array of times from successful requests
                $successTimes = @()
                foreach ($result in $jobResults) {
                    if ($result.Success) {
                        $successTimes += $result.Time
                    }
                }
                # Calculate min and max manually
                $minTime = [double]::MaxValue
                $maxTime = [double]::MinValue
                foreach ($time in $successTimes) {
                    if ($time -lt $minTime) { $minTime = $time }
                    if ($time -gt $maxTime) { $maxTime = $time }
                }
                Write-Output "Response Time Statistics:"
                Write-Output "  Average: $(Format-ResponseTime -Seconds $avgTime)"
                Write-Output "  Minimum: $(Format-ResponseTime -Seconds $minTime)"
                Write-Output "  Maximum: $(Format-ResponseTime -Seconds $maxTime)"
                Write-Debug "Concurrent requests summary - Success: $successCount/$ConcurrentRequests, Avg Time: $avgTime s"
            }
            Write-Output "$successCount of $ConcurrentRequests requests succeeded."
            return
        } else {
            Write-Verbose "Processing single request"
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                Write-Debug "Using PowerShell 6+ request handling"
                $requestStartTime = Get-Date
                $webRequestParams = @{
                    Uri = $URL
                    Method = $Method
                    Headers = $Headers
                    UserAgent = $UserAgent
                    TimeoutSec = $Timeout
                    UseBasicParsing = $true
                    SkipCertificateCheck = $SkipCertCheck
                    ErrorAction = 'Stop'
                }
                if ($Proxy) {
                    Write-Debug "Adding proxy: $Proxy"
                    $webRequestParams['Proxy'] = $Proxy
                }
                if ($Body) {
                    Write-Debug "Adding request body"
                    $webRequestParams['Body'] = $Body
                }
                Write-Verbose "Sending request with parameters: $($webRequestParams | ConvertTo-Json)"
                try {
                    $tcpStartTime = Get-Date
                    $response = Invoke-WebRequest @webRequestParams
                    $tcpEndTime = Get-Date
                    $timeline['TCP Connection'] = ($tcpEndTime - $tcpStartTime).TotalSeconds
                    $timeline['Response Wait'] = ($tcpEndTime - $tcpStartTime).TotalSeconds
                }
                catch {
                    if ($_.Exception.Response) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        $statusInfo = Get-HTTPStatusInfo -StatusCode $statusCode

                        Write-Output "=================== HTTP Error Details ==================="
                        Write-Output "Status Code: $statusCode"
                        Write-Output "Category: $($statusInfo.Category)"
                        Write-Output "Description: $($statusInfo.Description)"
                        Write-Output "Suggested Action: $($statusInfo.SuggestedAction)"
                        Write-Output ""

                        # Get response headers if available
                        if ($_.Exception.Response) {
                            Write-Output "Response Headers:"
                            try {
                                if ($PSVersionTable.PSVersion.Major -ge 6) {
                                    $response = $_.Exception.Response
                                    $headers = @{}
                                    foreach ($header in $response.Headers.GetEnumerator()) {
                                        $headers[$header.Key] = $header.Value
                                    }
                                    foreach ($key in $headers.Keys) {
                                        Write-Output "  $key : $($headers[$key])"
                                    }
                                } else {
                                    $response = $_.Exception.Response
                                    $headers = @{}
                                    foreach ($key in $response.Headers.AllKeys) {
                                        $headers[$key] = $response.Headers[$key]
                                    }
                                    foreach ($key in $headers.Keys) {
                                        Write-Output "  $key : $($headers[$key])"
                                    }
                                }
                            }
                            catch {
                                Write-Debug "Error accessing response headers: $($_.Exception.Message)"
                                Write-Debug "Exception type: $($_.Exception.GetType().FullName)"
                                Write-Debug "Stack trace: $($_.ScriptStackTrace)"

                                # Try alternative method
                                try {
                                    $response = $_.Exception.Response
                                    Write-Output "  Status: $($response.StatusCode) $($response.StatusDescription)"
                                    Write-Output "  Content-Type: $($response.ContentType)"
                                    Write-Output "  Content-Length: $($response.ContentLength)"
                                    Write-Output "  Server: $($response.Server)"
                                    Write-Output "  Last-Modified: $($response.LastModified)"
                                }
                                catch {
                                    Write-Debug "Alternative header access also failed: $($_.Exception.Message)"
                                }
                            }
                            Write-Output ""
                        } else {
                            Write-Debug "No response object available"
                        }

                        # Update timeline before error
                        $requestEndTime = Get-Date
                        $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
                        $timeTaken = ($requestEndTime - $startTime).TotalSeconds
                        $timeline['Total Time'] = $timeTaken

                        # Display timeline before throwing the error
                        Write-Output "=================== Request Timeline ==================="
                        $timelineObj = New-Object PSObject -Property $timeline
                        Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
                        Write-Output ""

                        Write-Error "HTTP Error $statusCode - $($statusInfo.Description)" -ErrorAction Stop
                    }
                    else {
                        # Update timeline before error
                        $requestEndTime = Get-Date
                        $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
                        $timeTaken = ($requestEndTime - $startTime).TotalSeconds
                        $timeline['Total Time'] = $timeTaken

                        # Display timeline before throwing the error
                        Write-Output "=================== Request Timeline ==================="
                        $timelineObj = New-Object PSObject -Property $timeline
                        Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
                        Write-Output ""
                        
                        throw
                    }
                }
                $requestEndTime = Get-Date
                $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
                $timeTaken = ($requestEndTime - $startTime).TotalSeconds
                $timeline['Total Time'] = $timeTaken
                Write-Debug "Request completed in $timeTaken seconds"
            }
            else {
                Write-Debug "Using PowerShell 5.1 request handling"
                if ($SkipCertCheck) {
                    Write-Debug "Skipping certificate validation"
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                }
                $request = [System.Net.HttpWebRequest]::Create($URL)
                $request.Method = $Method
                $request.UserAgent = $UserAgent
                $request.Timeout = $Timeout * 1000
                $request.AllowAutoRedirect = $false

                Write-Debug "Setting up request headers"
                if ($Headers.ContainsKey('Content-Type')) { $request.ContentType = $Headers['Content-Type']; $Headers.Remove('Content-Type') }
                if ($Headers.ContainsKey('Accept')) { $request.Accept = $Headers['Accept']; $Headers.Remove('Accept') }
                if ($Headers.ContainsKey('User-Agent')) { $request.UserAgent = $Headers['User-Agent']; $Headers.Remove('User-Agent') }
                if ($Headers.ContainsKey('Referer')) { $request.Referer = $Headers['Referer']; $Headers.Remove('Referer') }
                # Note: If errors related to 'Cannot bind parameter Date' persist despite the robust parsing below,
                # consider checking the $PSDefaultParameterValues variable in your session or profile,
                # e.g., $PSDefaultParameterValues['*:Date'] or $PSDefaultParameterValues['DebugURL:Date'],
                # as it might be externally influencing parameter binding for 'Date' parameters.
                if ($Headers.ContainsKey('Date')) {
                    $dateHeaderValue = $Headers['Date']
                    $parsedDate = [datetime]::MinValue
                    $isValidDateTime = $false

                    if ($dateHeaderValue -is [string]) {
                        if ([datetime]::TryParseExact($dateHeaderValue, "R", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$parsedDate)) {
                            $isValidDateTime = $true
                        }
                        if (-not $isValidDateTime -and [datetime]::TryParse($dateHeaderValue, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$parsedDate)) {
                            $isValidDateTime = $true
                        }
                    }

                    if ($isValidDateTime) {
                        $request.Date = $parsedDate
                    } else {
                        Write-Warning "The value '$dateHeaderValue' for the 'Date' header is not a valid DateTime object and will not be set on the HttpWebRequest.Date property. It will be attempted to be sent as a string header if other mechanisms don't prevent it."
                    }
                    $Headers.Remove('Date') # Keep this line to prevent it from being added as a regular string header if we attempted to parse it for the .Date property.
                }
                if ($Headers.ContainsKey('Host')) { $request.Host = $Headers['Host']; $Headers.Remove('Host') }
                foreach ($header in $Headers.GetEnumerator()) {
                    Write-Debug "Adding header: $($header.Key) = $($header.Value)"
                    $request.Headers.Add($header.Key, $header.Value)
                }
                if ($Proxy) {
                    Write-Debug "Setting up proxy: $Proxy"
                    $request.Proxy = New-Object System.Net.WebProxy($Proxy)
                }
                if ($Body) {
                    Write-Debug "Adding request body"
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
                    $request.ContentLength = $bodyBytes.Length
                    $requestStream = $request.GetRequestStream()
                    $requestStream.Write($bodyBytes, 0, $bodyBytes.Length)
                    $requestStream.Close()
                }
                Write-Verbose "Sending request"
                $requestStartTime = Get-Date
                try {
                    $tcpStartTime = Get-Date
                    $response = $request.GetResponse()
                    $tcpEndTime = Get-Date
                    $timeline['TCP Connection'] = ($tcpEndTime - $tcpStartTime).TotalSeconds
                    $timeline['Response Wait'] = ($tcpEndTime - $tcpStartTime).TotalSeconds
                }
                catch [System.Net.WebException] {
                    if ($_.Exception.Response) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        $statusInfo = Get-HTTPStatusInfo -StatusCode $statusCode

                        Write-Output "=================== HTTP Error Details ==================="
                        Write-Output "Status Code: $statusCode"
                        Write-Output "Category: $($statusInfo.Category)"
                        Write-Output "Description: $($statusInfo.Description)"
                        Write-Output "Suggested Action: $($statusInfo.SuggestedAction)"
                        Write-Output ""

                        # Get response headers if available
                        if ($_.Exception.Response) {
                            Write-Output "Response Headers:"
                            try {
                                if ($PSVersionTable.PSVersion.Major -ge 6) {
                                    $response = $_.Exception.Response
                                    $headers = @{}
                                    foreach ($header in $response.Headers.GetEnumerator()) {
                                        $headers[$header.Key] = $header.Value
                                    }
                                    foreach ($key in $headers.Keys) {
                                        Write-Output "  $key : $($headers[$key])"
                                    }
                                } else {
                                    $response = $_.Exception.Response
                                    $headers = @{}
                                    foreach ($key in $response.Headers.AllKeys) {
                                        $headers[$key] = $response.Headers[$key]
                                    }
                                    foreach ($key in $headers.Keys) {
                                        Write-Output "  $key : $($headers[$key])"
                                    }
                                }
                            }
                            catch {
                                Write-Debug "Error accessing response headers: $($_.Exception.Message)"
                                Write-Debug "Exception type: $($_.Exception.GetType().FullName)"
                                Write-Debug "Stack trace: $($_.ScriptStackTrace)"

                                # Try alternative method
                                try {
                                    $response = $_.Exception.Response
                                    Write-Output "  Status: $($response.StatusCode) $($response.StatusDescription)"
                                    Write-Output "  Content-Type: $($response.ContentType)"
                                    Write-Output "  Content-Length: $($response.ContentLength)"
                                    Write-Output "  Server: $($response.Server)"
                                    Write-Output "  Last-Modified: $($response.LastModified)"
                                }
                                catch {
                                    Write-Debug "Alternative header access also failed: $($_.Exception.Message)"
                                }
                            }
                            Write-Output ""
                        } else {
                            Write-Debug "No response object available"
                        }

                        # Update timeline before error
                        $requestEndTime = Get-Date
                        $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
                        $timeTaken = ($requestEndTime - $startTime).TotalSeconds
                        $timeline['Total Time'] = $timeTaken

                        # Display timeline before throwing the error
                        Write-Output "=================== Request Timeline ==================="
                        $timelineObj = New-Object PSObject -Property $timeline
                        Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
                        Write-Output ""

                        Write-Error "HTTP Error $statusCode - $($statusInfo.Description)" -ErrorAction Stop
                    }
                    throw
                }
                $requestEndTime = Get-Date
                $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
                $timeTaken = ($requestEndTime - $startTime).TotalSeconds
                $timeline['Total Time'] = $timeTaken
                Write-Debug "Request completed in $timeTaken seconds"
            }

            # Response Headers
            Write-Output "=================== Response Headers ==================="
            Write-Debug "Processing response headers"

            # Get response analysis
            $responseAnalysis = if ($response) { Get-ResponseAnalysis -Response $response } else { @{} }

            # Calculate response size
            $responseSize = 0
            if ($response) {
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        # PowerShell 7+ handling
                        $responseSize = if ($response.RawContentLength -gt 0) {
                            $response.RawContentLength
                        } else {
                            [System.Text.Encoding]::UTF8.GetByteCount($response.Content)
                        }
                    } else {
                        # PowerShell 5.1 handling
                        $responseSize = if ($response.ContentLength -gt 0) {
                            $response.ContentLength
                        } else {
                            $content = Get-ResponseContent -Response $response
                            [System.Text.Encoding]::UTF8.GetByteCount($content)
                        }
                    }
                } catch {
                    Write-Debug "Error calculating response size: $($_.Exception.Message)"
                }
            }

            $responseHeaders = [ordered]@{
                'Request-URI' = if ($response -and $response.ResponseUri) { $response.ResponseUri.ToString() } else { $URL }
                'ResponseHeaders' = "Response Headers"
                'ResponseTime' = Format-ResponseTime -Seconds $timeTaken
                'ResponseSize' = Format-Size -Bytes $responseSize
                'ContentType' = $responseAnalysis.ContentType
                'CharacterSet' = $responseAnalysis.CharacterSet
                'IsCompressed' = $responseAnalysis.IsCompressed
                'IsChunked' = $responseAnalysis.IsChunked
                'CacheControl' = $responseAnalysis.CacheControl
            }

            if ($response) {
                try {
                    if ($PSVersionTable.PSVersion.Major -ge 6) {
                        Write-Debug "Processing PowerShell 7+ response"
                        $responseHeaders['StatusCode'] = $response.StatusCode
                        $responseHeaders['StatusDescription'] = $response.StatusDescription

                        # FUTURE ENHANCEMENT: The date parsing for response headers (Date, Expires, Last-Modified)
                        # could be made more robust by using [datetime]::TryParseExact with common HTTP date formats (e.g., "R")
                        # before falling back to [datetime]::TryParse, similar to how the request Date header is handled.
                        # This would improve accuracy in converting these headers to DateTime objects for display or further processing.
                        # Process response headers
                        if ($response.Headers) {
                            foreach ($header in $response.Headers.GetEnumerator()) {
                                Write-Debug "Response header: $($header.Key) = $($header.Value)"
                                $responseHeaders[$header.Key] = $header.Value
                            }
                        }

                        # Process content
                        $content = if ($response.Content) { $response.Content } else { "" }
                        if ($content) {
                            $responseHeaders['Content'] = $content.Substring(0, [Math]::Min(150, $content.Length))
                        } else {
                            $responseHeaders['Content'] = ""
                        }
                    } else {
                        Write-Debug "Processing PowerShell 5.1 response"
                        $responseHeaders['StatusCode'] = [int]$response.StatusCode
                        $responseHeaders['StatusDescription'] = $response.StatusDescription

                        # FUTURE ENHANCEMENT: The date parsing for response headers (Date, Expires, Last-Modified)
                        # could be made more robust by using [datetime]::TryParseExact with common HTTP date formats (e.g., "R")
                        # before falling back to [datetime]::TryParse, similar to how the request Date header is handled.
                        # This would improve accuracy in converting these headers to DateTime objects for display or further processing.
                        # Process response headers
                        if ($response.Headers) {
                            foreach ($key in $response.Headers.AllKeys) {
                                Write-Debug "Response header: $key = $($response.Headers[$key])"
                                $responseHeaders[$key] = $response.Headers[$key]
                            }
                        }

                        # Process content
                        try {
                            $content = Get-ResponseContent -Response $response
                            if ($content) {
                                $responseHeaders['Content'] = $content.Substring(0, [Math]::Min(150, $content.Length))
                            } else {
                                $responseHeaders['Content'] = ""
                            }
                        } catch {
                            Write-Debug "Error getting response content: $($_.Exception.Message)"
                            $responseHeaders['Content'] = ""
                        }
                    }
                } catch {
                    Write-Debug "Error processing response: $($_.Exception.Message)"
                    $responseHeaders['Error'] = $_.Exception.Message
                }
            }

            $responseObj = New-Object PSObject -Property $responseHeaders
            Write-Output ($responseObj | Format-List | Out-String).TrimEnd()
            Write-Output ""

            # Display Timeline
            Write-Output "=================== Request Timeline ==================="
            $timelineObj = New-Object PSObject -Property $timeline
            Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
            Write-Output ""
        }
    }
    catch {
        if ($logStream) {
            $logStream.WriteLine("Error Occurred:")
            $logStream.WriteLine("  Message: $($_.Exception.Message)")
            $logStream.WriteLine("  Type: $(Get-ErrorClassification -ErrorMessage $_.Exception.Message)")
            $logStream.WriteLine("  Stack Trace: $($_.ScriptStackTrace)")
        }

        # Only display timeline and error if not already handled
        if (-not $script:errorHandled) {
            # Update timeline before error
            $requestEndTime = Get-Date
            $timeline['Request Send'] = ($requestEndTime - $requestStartTime).TotalSeconds
            $timeTaken = ($requestEndTime - $startTime).TotalSeconds
            $timeline['Total Time'] = $timeTaken

            # Display timeline before throwing the error
            Write-Output "=================== Request Timeline ==================="
            $timelineObj = New-Object PSObject -Property $timeline
            Write-Output ($timelineObj | Format-List | Out-String).TrimEnd()
            Write-Output ""

            $errorDetails = @{
                'Hostname' = $uri.Host
                'Error' = $_.Exception.Message
                'Type' = Get-ErrorClassification -ErrorMessage $_.Exception.Message
            }

            Write-Error $_.Exception.Message
        }
        return
    } finally {
        if ($logStream) {
            $logStream.WriteLine("----------------------------------------")
            $logStream.WriteLine("DebugURL Log - Ended at $(Get-Date)")
            $logStream.Dispose()
        }
        # Cleanup any resources
        if ($response -and -not $PSVersionTable.PSVersion.Major -ge 6) {
            $response.Close()
        }
        if ($PSVersionTable.PSVersion.Major -lt 6 -and $SkipCertCheck) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
        }
        # Reset error handled flag
        $script:errorHandled = $false
    }
}

function Get-DNSCache {
    <#
    .SYNOPSIS
        Retrieves and displays the current DNS cache entries.

    .DESCRIPTION
        The Get-DNSCache function displays the contents of the local DNS cache,
        including hostnames, IP addresses, and record types. This is useful for
        troubleshooting DNS resolution issues and verifying cached entries.

    .EXAMPLE
        Get-DNSCache
        Displays all entries in the DNS cache.

    .EXAMPLE
        Get-DNSCache | Where-Object { $_.Name -like "*.example.com" }
        Filters DNS cache entries for a specific domain pattern.

    .OUTPUTS
        System.Object[]
        Returns an array of objects containing DNS cache entries with the following properties:
        - Name: The hostname
        - Type: The record type (A, AAAA, CNAME, etc.)
        - IPAddress: The resolved IP address
        - TTL: Time to live in seconds
    #>
    [CmdletBinding()]
    param()

    try {
        Write-Debug "Retrieving DNS cache entries"
        $dnsCache = Get-DnsClientCache
        if ($dnsCache) {
            Write-Output "==================== DNS Cache Entries ===================="
            $dnsCache | Format-Table Name, Type, IPAddress, TTL | Out-String
            Write-Debug "Successfully retrieved $($dnsCache.Count) DNS cache entries"
        } else {
            Write-Output "No entries found in DNS cache."
            Write-Debug "DNS cache is empty"
        }
    }
    catch {
        Write-Error "Failed to retrieve DNS cache: $($_.Exception.Message)"
        Write-Debug "Error retrieving DNS cache: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function DebugURL, Get-DNSCache
