# DebugURL PowerShell Module

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/DebugURL.svg)](https://www.powershellgallery.com/packages/DebugURL)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/DebugURL.svg)](https://www.powershellgallery.com/packages/DebugURL)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell Version](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://github.com/khannaveed2020/DebugURL)

A PowerShell module for comprehensive URL testing and debugging, with full support for both PowerShell 5.1 and PowerShell 7+.

## Version
1.0.5

## Description
The DebugURL module provides a powerful set of tools for testing and debugging URLs, including DNS resolution, SSL/TLS certificate analysis, request/response header inspection, and performance testing.

## Features

- ✅ DNS resolution details
- ✅ Request header information
- ✅ SSL/TLS certificate details
- ✅ Response headers (working on both PS 5.1 and 7+)
- ✅ Content preview
- ✅ Proxy support
- ✅ Custom timeout settings
- ✅ Certificate validation skip option
- ✅ Custom user agent setting
- ✅ HTTP methods (GET, POST, PUT, DELETE, etc.)
- ✅ Custom headers support
- ✅ Concurrent requests for performance testing
- ✅ Actual TLS version detection
- ✅ Detailed HTTP status code handling and analysis
- ✅ Comprehensive error reporting with suggested actions

## Installation

### From PowerShell Gallery
```powershell
Install-Module -Name DebugURL -Scope CurrentUser
```

### Manual Installation
1. Clone or download this repository
2. Copy the module folder to one of your PowerShell module directories:
   ```powershell
   $env:PSModulePath -split ';'
   ```
3. Import the module:
   ```powershell
   Import-Module DebugURL
   ```

## Usage Examples

### Basic GET Request
```powershell
DebugURL -URL "https://example.com"
```

### SSL Certificate Testing
```powershell
# Testing with invalid/expired certificates
DebugURL -URL "https://expired.badssl.com" -SkipCertCheck
```

### Testing Different HTTP Status Codes

The module provides detailed analysis of HTTP status codes, including error descriptions and suggested actions.

#### Testing 404 Not Found
```powershell
DebugURL -URL "http://httpbin.org/status/404"
```

**Sample Output:**
```
=================== HTTP Error Details ===================
Status Code: 404
Category: Client Error
Description: Not Found - The requested resource does not exist
Suggested Action: Check request parameters and client configuration

Response Headers:
  Server: nginx
  Date: [timestamp]
  Content-Type: text/html
  Content-Length: [size]
  Connection: close
```

#### Testing 500 Server Error
```powershell
DebugURL -URL "http://httpbin.org/status/500"
```

**Sample Output:**
```
=================== HTTP Error Details ===================
Status Code: 500
Category: Server Error
Description: Internal Server Error - Server encountered an unexpected condition
Suggested Action: Contact server administrator or try again later

Response Headers:
  Server: nginx
  Date: [timestamp]
  Content-Type: text/html
  Content-Length: [size]
  Connection: close
```

#### Testing Multiple Status Codes
```powershell
# Test various status codes
$statusCodes = @(200, 301, 400, 401, 403, 404, 500, 503)
foreach ($code in $statusCodes) {
    Write-Host "`nTesting Status Code: $code"
    DebugURL -URL "http://httpbin.org/status/$code"
}
```

**Key Features of Status Code Handling:**
- ✅ **Detailed Error Analysis**: Provides clear descriptions of each status code
- ✅ **Category Classification**: Groups status codes into categories (Client Error, Server Error, etc.)
- ✅ **Suggested Actions**: Offers guidance on how to resolve the issue
- ✅ **Response Headers**: Shows all available response headers
- ✅ **Cross-Version Support**: Works consistently in both PowerShell 5.1 and 7+
- ✅ **Comprehensive Error Information**: Includes status code, description, and headers

**Use Cases:**
- API endpoint testing
- Error handling verification
- Server response validation
- Client error simulation
- Server error testing
- HTTP status code documentation
- Troubleshooting web services

### HTTP Methods Testing

1. GET with Custom Headers
```powershell
DebugURL -URL "https://httpbin.org/headers" `
    -Headers @{
        "X-Custom-Header" = "test-value"
        "Authorization" = "Bearer test-token"
    }
```

2. POST with JSON Body
```powershell
$postBody = @{
    title = 'test title'
    body = 'test body'
    userId = 1
} | ConvertTo-Json

DebugURL -URL "https://httpbin.org/post" `
    -Method "POST" `
    -Headers @{"Content-Type" = "application/json"} `
    -Body $postBody
```

3. PUT Request
```powershell
$putBody = @{
    id = 1
    title = 'updated title'
    body = 'updated content'
} | ConvertTo-Json

DebugURL -URL "https://httpbin.org/put" `
    -Method "PUT" `
    -Headers @{"Content-Type" = "application/json"} `
    -Body $putBody
```

4. DELETE Request
```powershell
DebugURL -URL "https://httpbin.org/delete" `
    -Method "DELETE"
```

5. Form Data POST
```powershell
$formData = "field1=value1&field2=value2"
DebugURL -URL "https://httpbin.org/post" `
    -Method "POST" `
    -Headers @{"Content-Type" = "application/x-www-form-urlencoded"} `
    -Body $formData
```

### Advanced Usage

Custom Timeout and Headers:
```powershell
DebugURL -URL "https://api.example.com" `
    -Headers @{
        "Authorization" = "Bearer token"
        "X-Custom-Header" = "value"
    } `
    -Timeout 60
```

With Proxy:
```powershell
DebugURL -URL "https://example.com" `
    -Proxy "http://proxy.internal:8080"
```

Custom User Agent:
```powershell
DebugURL -URL "https://example.com" `
    -UserAgent "CustomApp/1.0"
```

### Concurrent Requests (Performance Testing)

The module supports concurrent requests for performance testing and load simulation. When using concurrent requests, the module will show DNS resolution, SSL certificate details, and then a summary of all parallel requests.

#### Basic Concurrent Requests
```powershell
# Test with 5 concurrent requests
DebugURL -URL "https://www.google.com" -ConcurrentRequests 5
```

**Sample Output:**
```
================== Concurrent Requests Summary ==================
Concurrent Requests: 5
Request 1: Success, Time: 0.420s, Status: 200
Request 2: Success, Time: 0.444s, Status: 200
Request 3: Success, Time: 0.391s, Status: 200
Request 4: Success, Time: 0.371s, Status: 200
Request 5: Success, Time: 0.376s, Status: 200
Average Response Time: 0.400 s
5 of 5 requests succeeded.
```

#### Concurrent Requests with SSL Issues
```powershell
# Test expired certificate handling with concurrent requests
DebugURL -URL "https://expired.badssl.com" -ConcurrentRequests 3
```

**Sample Output:**
```
================== Concurrent Requests Summary ==================
Concurrent Requests: 3
Request 1: Fail, Time: 0.983s, Status: N/A - The SSL connection could not be established
Request 2: Fail, Time: 0.931s, Status: N/A - The SSL connection could not be established  
Request 3: Fail, Time: 0.957s, Status: N/A - The SSL connection could not be established
Average Response Time: 0.957 s
0 of 3 requests succeeded.
```

#### Concurrent Requests with Certificate Skip
```powershell
# Test with certificate validation disabled
DebugURL -URL "https://expired.badssl.com" -ConcurrentRequests 3 -SkipCertCheck
```

#### Concurrent POST Requests
```powershell
# Performance test POST requests
$jsonBody = @{
    name = "Test User"
    email = "test@example.com"
} | ConvertTo-Json

DebugURL -URL "https://httpbin.org/post" `
    -Method "POST" `
    -Headers @{"Content-Type" = "application/json"} `
    -Body $jsonBody `
    -ConcurrentRequests 4
```

#### Concurrent Requests with Custom Headers
```powershell
# Load test API endpoint with authentication
DebugURL -URL "https://api.example.com/data" `
    -Headers @{
        "Authorization" = "Bearer your-token-here"
        "X-API-Version" = "v2"
    } `
    -ConcurrentRequests 10 `
    -Timeout 60
```

#### Performance Testing Different Endpoints
```powershell
# Test multiple concurrent requests to compare performance
DebugURL -URL "https://httpbin.org/delay/1" -ConcurrentRequests 5  # Should take ~1 second each
DebugURL -URL "https://httpbin.org/delay/2" -ConcurrentRequests 5  # Should take ~2 seconds each
```

**Key Features of Concurrent Requests:**
- ✅ **True Parallelism**: Uses PowerShell background jobs for genuine concurrent execution
- ✅ **Individual Timing**: Shows response time for each request
- ✅ **Success/Failure Tracking**: Displays detailed status for each request
- ✅ **Error Details**: Shows specific error messages for failed requests
- ✅ **Performance Metrics**: Calculates average response time
- ✅ **SSL Support**: Works with both valid and invalid certificates
- ✅ **Cross-Version**: Compatible with both PowerShell 5.1 and 7+

**Use Cases:**
- Load testing web services
- Performance benchmarking
- SSL certificate validation testing at scale
- API endpoint reliability testing
- Network latency analysis
- Server response time monitoring

## Parameters

- `URL` (Required): The URL to test
- `Method`: HTTP method (default: GET)
- `Headers`: Hashtable of custom headers
- `Body`: Request body content
- `SkipCertCheck`: Skip SSL certificate validation
- `Timeout`: Request timeout in seconds (default: 30)
- `Proxy`: Proxy server URL
- `UserAgent`: Custom User-Agent string
- `TLSVersion`: Specify TLS version
- `LogPath`: Path for detailed logging
- `ConcurrentRequests`: Number of concurrent requests (default: 1)

## Testing Status

✅ **All Core Tests Passed**

Verified functionality across:
- PowerShell 5.1
- PowerShell 7+

Test scenarios completed:
- ✅ Basic HTTP requests
- ✅ HTTPS with valid certificates
- ✅ HTTPS with invalid/expired certificates
- ✅ DNS resolution
- ✅ Header handling (request & response)
- ✅ SSL certificate information
- ✅ Cross-version compatibility
- ✅ Resource cleanup and error handling
- ✅ HTTP Methods (GET, POST, PUT, DELETE)
- ✅ Custom headers
- ✅ Request/Response body handling
- ✅ Form data submission
- ✅ Concurrent requests (performance testing)
- ✅ Actual TLS version detection
- ✅ Parallel job execution and cleanup
- ✅ Error handling in concurrent mode

Test APIs Used:
- httpbin.org (Primary testing)
- badssl.com (SSL/TLS testing)
- example.com (Basic connectivity)

## Contributing

This project is currently not accepting contributions. The codebase is maintained by the original author for specific use cases and requirements.

If you find any issues or have suggestions, please feel free to open an issue for discussion.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 