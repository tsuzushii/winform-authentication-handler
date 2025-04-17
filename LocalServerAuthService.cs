using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class FixedPortAuthService
    {
        private readonly AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 120000; // 2 minutes
        private const int FixedPort = 54321; // Fixed port - make sure this is whitelisted with your IDP
        private readonly Action<string> _statusCallback;
        private readonly bool _hideBrowser;

        public FixedPortAuthService(AuthConfig authConfig, Action<string> statusCallback = null, bool hideBrowser = false)
        {
            _authConfig = authConfig;
            _statusCallback = statusCallback ?? ((message) => { Debug.WriteLine(message); });
            _hideBrowser = hideBrowser;
        }

        public async Task<Dictionary<string, string>> AuthenticateAsync()
        {
            _statusCallback("Starting authentication process...");
            Debug.WriteLine("Starting fixed port authentication");

            // Create a fixed redirect URI using the specified port
            string fixedRedirectUri = $"http://localhost:{FixedPort}/callback";
            Debug.WriteLine("Fixed redirect URI: " + fixedRedirectUri);

            HttpListener httpListener = null;

            try
            {
                // Set up the HTTP listener for capturing the redirect
                httpListener = new HttpListener();
                httpListener.Prefixes.Add($"http://localhost:{FixedPort}/callback/");

                try
                {
                    httpListener.Start();
                    Debug.WriteLine("HTTP listener started on " + fixedRedirectUri);
                }
                catch (HttpListenerException ex)
                {
                    _statusCallback($"Error starting HTTP listener: {ex.Message}");
                    Debug.WriteLine("Error starting HTTP listener: " + ex.Message);

                    // Check for specific error codes
                    if (ex.ErrorCode == 5) // Access denied
                    {
                        throw new InvalidOperationException("Unable to start the HTTP listener. You may need to run as administrator or check your firewall settings.");
                    }
                    else if (ex.ErrorCode == 183) // Already in use
                    {
                        throw new InvalidOperationException($"Port {FixedPort} is already in use. Close any other applications that might be using this port and try again.");
                    }
                    throw;
                }

                // Generate state and nonce for security
                var state = IdentityModel.CryptoRandom.CreateUniqueId();
                var nonce = IdentityModel.CryptoRandom.CreateUniqueId();

                // Create the authentication URL with the fixed redirect URI
                _statusCallback("Preparing authentication URL...");
                var request = new IdentityModel.Client.RequestUrl(GetAuthorizeUrlBasedOnEnvironment());
                var url = request.CreateAuthorizeUrl(
                    clientId: _authConfig.ClientId,
                    responseType: "id_token token",
                    responseMode: "fragment",
                    redirectUri: fixedRedirectUri,
                    state: state,
                    nonce: nonce,
                    scope: _authConfig.Scope
                );

                Debug.WriteLine("Authentication URL: " + url);

                // Launch the browser with the authentication URL
                _statusCallback("Launching browser...");
                bool browserLaunched = false;

                if (_hideBrowser)
                {
                    // Try to launch browser in hidden mode
                    browserLaunched = LaunchHiddenBrowser(url);
                }

                // If hidden browser failed or wasn't requested, use normal browser
                if (!browserLaunched)
                {
                    browserLaunched = LaunchBrowser(url);
                }

                if (!browserLaunched)
                {
                    _statusCallback("Error: Failed to launch browser.");
                    throw new InvalidOperationException("Failed to launch browser. Please check if a browser is installed.");
                }

                Debug.WriteLine("Browser launched");

                // Create a cancellation token source for the timeout
                using (var cts = new CancellationTokenSource(AuthenticationTimeoutMilliseconds))
                {
                    _statusCallback("Waiting for authentication in browser...");

                    // Create a task that will complete when the HTTP request (redirect) is received
                    Task<HttpListenerContext> httpContextTask;

                    try
                    {
                        httpContextTask = httpListener.GetContextAsync();

                        // Wait for either the HTTP context or cancellation
                        await Task.WhenAny(httpContextTask, Task.Delay(Timeout.Infinite, cts.Token)).ConfigureAwait(false);

                        // Check if we timed out
                        if (cts.Token.IsCancellationRequested && !httpContextTask.IsCompleted)
                        {
                            _statusCallback("Authentication timed out. Please try again.");
                            throw new TimeoutException("Authentication timed out. Please try again.");
                        }
                    }
                    catch (TaskCanceledException)
                    {
                        _statusCallback("Authentication timed out. Please try again.");
                        throw new TimeoutException("Authentication timed out. Please try again.");
                    }

                    // Get the HTTP context from the completed task
                    _statusCallback("Processing authentication response...");
                    var context = httpContextTask.Result;
                    Debug.WriteLine("Received HTTP request: " + context.Request.Url);

                    // Extract the token from various possible sources
                    string fragment = ExtractFragment(context);

                    // Send a response to the browser to close the window
                    await SendResponseAsync(context);

                    // Ensure we have a fragment
                    if (string.IsNullOrEmpty(fragment))
                    {
                        _statusCallback("Error: No authentication token received.");
                        Debug.WriteLine("No fragment found in the callback URL");
                        throw new InvalidOperationException("No authentication token received. Please try again.");
                    }

                    // Parse the fragment to get the token
                    var tokenDict = ParseFragment(fragment);

                    // Check for error response
                    if (tokenDict.ContainsKey("error"))
                    {
                        string errorDescription = tokenDict.ContainsKey("error_description")
                            ? tokenDict["error_description"]
                            : "Unknown error";

                        _statusCallback($"Authentication error: {errorDescription}");
                        throw new InvalidOperationException($"Authentication error: {errorDescription}");
                    }

                    // Validate state parameter to prevent CSRF
                    if (!tokenDict.ContainsKey("state") || tokenDict["state"] != state)
                    {
                        _statusCallback("Error: Invalid state parameter.");
                        Debug.WriteLine("State validation failed");
                        throw new InvalidOperationException("Invalid state parameter. The authentication request may have been tampered with.");
                    }

                    // Check if we have an access token
                    if (!tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                    {
                        _statusCallback("Error: No access token received.");
                        Debug.WriteLine("No access token in the response");
                        throw new InvalidOperationException("No access token received. Authentication failed.");
                    }

                    _statusCallback("Authentication successful!");
                    Debug.WriteLine("Authentication successful");
                    return tokenDict;
                }
            }
            finally
            {
                // Clean up
                if (httpListener != null && httpListener.IsListening)
                {
                    httpListener.Stop();
                    Debug.WriteLine("HTTP listener stopped");
                }
            }
        }

        private string ExtractFragment(HttpListenerContext context)
        {
            // Check multiple places where the fragment might be

            // 1. First check if fragment is present in URL query (it may be passed as a query parameter)
            string fragment = null;
            var query = context.Request.QueryString;

            if (query["fragment"] != null)
            {
                fragment = "#" + query["fragment"];
                Debug.WriteLine("Found fragment in 'fragment' query parameter: " + fragment);
            }
            else if (query["#"] != null)
            {
                fragment = "#" + query["#"];
                Debug.WriteLine("Found fragment in '#' query parameter: " + fragment);
            }

            // 2. Check for custom parameter that might contain the token directly
            else if (query["access_token"] != null)
            {
                fragment = "#access_token=" + query["access_token"];

                // Add other parameters if they exist
                if (query["token_type"] != null)
                    fragment += "&token_type=" + query["token_type"];
                if (query["expires_in"] != null)
                    fragment += "&expires_in=" + query["expires_in"];
                if (query["state"] != null)
                    fragment += "&state=" + query["state"];

                Debug.WriteLine("Constructed fragment from query parameters");
            }

            // 3. Check if it's in the Referer header
            else if (context.Request.Headers["Referer"] != null)
            {
                string referer = context.Request.Headers["Referer"];
                if (!string.IsNullOrEmpty(referer))
                {
                    try
                    {
                        var refererUri = new Uri(referer);
                        fragment = refererUri.Fragment;
                        Debug.WriteLine("Found fragment in referer: " + fragment);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("Error parsing referer URI: " + ex.Message);
                    }
                }
            }

            // 4. Check if it's in the URL fragment
            if (string.IsNullOrEmpty(fragment))
            {
                fragment = context.Request.Url.Fragment;
                Debug.WriteLine("Using fragment from URL: " + fragment);
            }

            return fragment;
        }

        private static async Task SendResponseAsync(HttpListenerContext context)
        {
            string responseHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Complete</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f0f0f0; text-align: center; padding-top: 50px; }
        .container { background-color: white; max-width: 500px; margin: 0 auto; padding: 20px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; }
        p { color: #333; margin: 20px 0; }
        .success-icon { font-size: 48px; color: #107c10; margin: 20px 0; }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Authentication Successful</h1>
        <div class='success-icon'>&#10004;</div>
        <p>You have been successfully authenticated. You can close this window now.</p>
    </div>
    <script>
        // Close the window automatically after 1 second
        setTimeout(function() {
            window.close();
        }, 1000);
    </script>
</body>
</html>";

            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.ContentType = "text/html";

            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();
            Debug.WriteLine("Response sent to browser");
        }

        private Dictionary<string, string> ParseFragment(string fragment)
        {
            if (string.IsNullOrEmpty(fragment) || fragment.Length <= 1)
            {
                return new Dictionary<string, string>();
            }

            // Remove the leading # character
            fragment = fragment.TrimStart('#');

            // Split the fragment into key-value pairs
            var pairs = fragment.Split('&');

            // Parse each pair into a dictionary
            var result = new Dictionary<string, string>();
            foreach (var pair in pairs)
            {
                var keyValue = pair.Split('=');
                if (keyValue.Length == 2)
                {
                    result[keyValue[0]] = HttpUtility.UrlDecode(keyValue[1]);
                }
            }

            return result;
        }

        private bool LaunchHiddenBrowser(string url)
        {
            try
            {
                // Try to use Edge first for hidden mode
                string edgePath = GetEdgeBrowserExecutable();

                if (!string.IsNullOrEmpty(edgePath))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = edgePath,
                        Arguments = url,
                        WindowStyle = ProcessWindowStyle.Minimized,
                        CreateNoWindow = true,
                        UseShellExecute = true
                    };

                    Process.Start(psi);
                    return true;
                }

                // Try Chrome if Edge not available
                string chromePath = GetChromeBrowserExecutable();
                if (!string.IsNullOrEmpty(chromePath))
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = chromePath,
                        Arguments = url,
                        WindowStyle = ProcessWindowStyle.Minimized,
                        CreateNoWindow = true,
                        UseShellExecute = true
                    };

                    Process.Start(psi);
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error launching hidden browser: " + ex.Message);
                return false;
            }
        }

        private bool LaunchBrowser(string url)
        {
            try
            {
                // Try to use Microsoft Edge browser first
                string edgePath = GetEdgeBrowserExecutable();

                if (!string.IsNullOrEmpty(edgePath))
                {
                    Debug.WriteLine("Launching Microsoft Edge: " + edgePath);
                    Process.Start(edgePath, url);
                    return true;
                }

                // Fallback to Chrome if Edge is not available
                string chromePath = GetChromeBrowserExecutable();
                if (!string.IsNullOrEmpty(chromePath))
                {
                    Debug.WriteLine("Launching Google Chrome: " + chromePath);
                    Process.Start(chromePath, url);
                    return true;
                }

                // Fallback to the system default browser
                Debug.WriteLine("Launching default system browser");
                Process.Start(url);
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error launching browser: " + ex.Message);
                return false;
            }
        }

        private static string GetEdgeBrowserExecutable()
        {
            // Try to find Edge (Chromium-based) browser
            string[] possibleEdgePaths = new string[]
            {
                // Edge stable channel
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                    
                // Edge Beta channel
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
                    
                // Edge Dev channel
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge Dev", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge Dev", "Application", "msedge.exe")
            };

            foreach (string path in possibleEdgePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }

            // Try to find from registry
            string regPath = Registry.GetValue(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
                null,
                null
            ) as string;

            if (!string.IsNullOrEmpty(regPath) && File.Exists(regPath))
            {
                return regPath;
            }

            return string.Empty;
        }

        private static string GetChromeBrowserExecutable()
        {
            string chromePath = Registry.GetValue(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
                null,
                null
            ) as string;

            if (string.IsNullOrEmpty(chromePath))
            {
                chromePath = Registry.GetValue(
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe",
                    null,
                    null
                ) as string;
            }

            return chromePath ?? string.Empty;
        }

        private string GetAuthorizeUrlBasedOnEnvironment()
        {
            string environment = Fortis.FIBE.XN.Environment.SystemInfo.Current.SystemEnvironment;
            string authorizeUrl = "";

            switch (environment)
            {
                case MSAConstants.LocalEnvironmentIdentifier:
                case MSAConstants.DevEnvironmentIdentifier:
                    authorizeUrl = MSAConstants.AuthorizeUrlDev;
                    break;
                case MSAConstants.QualEnvironmentIdentifier:
                    authorizeUrl = MSAConstants.AuthorizeUrlQual;
                    break;
                case MSAConstants.AccEnvironmentIdentifier:
                    authorizeUrl = MSAConstants.AuthorizeUrlAcc;
                    break;
                case MSAConstants.ProdEnvironmentIdentifier:
                    authorizeUrl = MSAConstants.AuthorizeUrlProd;
                    break;
                default:
                    throw new InvalidOperationException("Invalid or unsupported environment.");
            }
            return authorizeUrl;
        }

        public ClaimsPrincipal CreateClaimsPrincipal(Dictionary<string, string> tokenDict)
        {
            var claims = new List<Claim>();

            // Add all token information as claims
            foreach (var pair in tokenDict)
            {
                claims.Add(new Claim(pair.Key, pair.Value));
            }

            // Process ID token if available
            if (tokenDict.ContainsKey(MSAConstants.IdTokenIdentifier))
            {
                var idToken = tokenDict[MSAConstants.IdTokenIdentifier];
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(idToken);

                // Add claims from ID token
                foreach (var claim in jwtToken.Claims)
                {
                    // Skip duplicate claims
                    bool isDuplicate = false;
                    foreach (var existingClaim in claims)
                    {
                        if (existingClaim.Type == claim.Type && existingClaim.Value == claim.Value)
                        {
                            isDuplicate = true;
                            break;
                        }
                    }

                    if (!isDuplicate)
                    {
                        claims.Add(new Claim(claim.Type, claim.Value));
                    }
                }

                // Create identity
                var identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier);

                // Set identity label if possible
                string givenName = null;
                string familyName = null;

                foreach (var claim in jwtToken.Claims)
                {
                    if (claim.Type == MSAConstants.GivenNameIdentifier)
                    {
                        givenName = claim.Value;
                    }
                    else if (claim.Type == MSAConstants.FamilyNameIdentifier)
                    {
                        familyName = claim.Value;
                    }
                }

                if (givenName != null && familyName != null)
                {
                    identity.Label = givenName + " " + familyName;
                }

                // Handle name claim
                string nameClaim = null;
                foreach (var claim in jwtToken.Claims)
                {
                    if (claim.Type == MSAConstants.NameIdentifier)
                    {
                        nameClaim = claim.Value;
                        break;
                    }
                }

                if (nameClaim != null)
                {
                    // Remove 'AG\' prefix if it exists
                    string cleanName = nameClaim.Replace("AG\\", "");
                    identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, cleanName));
                }

                return new ClaimsPrincipal(identity);
            }
            else
            {
                // Create basic identity if no ID token
                var identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier);
                return new ClaimsPrincipal(identity);
            }
        }
    }
}