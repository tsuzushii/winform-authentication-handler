
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
using IdentityModel.Client;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class FixedPortAuthService
    {
        private readonly AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 120000; // 2 minutes
        private const int FixedPort = 54321; // Fixed port - make sure this is whitelisted with your IDP
        private readonly Action<string> _statusCallback;
        private readonly bool _hideBrowser;
        private TaskCompletionSource<Dictionary<string, string>> _authCompletionSource;
        private CancellationTokenSource _cancellationTokenSource;

        public FixedPortAuthService(AuthConfig authConfig, Action<string> statusCallback = null, bool hideBrowser = false)
        {
            _authConfig = authConfig;
            _statusCallback = statusCallback ?? ((message) => { Debug.WriteLine(message); });
            _hideBrowser = hideBrowser;
            _authCompletionSource = new TaskCompletionSource<Dictionary<string, string>>();
            _cancellationTokenSource = new CancellationTokenSource();
        }

        // Improved AuthenticateAsync method with proper task waiting
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

                Debug.WriteLine("Browser launched, waiting for callback...");
                _statusCallback("Waiting for authentication in browser...");

                // Create a cancellation token with timeout
                using (var cts = new CancellationTokenSource(AuthenticationTimeoutMilliseconds))
                {
                    try
                    {
                        // Wait for the request with timeout
                        var context = await GetCallbackWithTokenAsync(httpListener, state, cts.Token);

                        // Extract the token
                        _statusCallback("Processing authentication response...");
                        string fragment = ExtractFragment(context);

                        // Send response to close browser
                        await SendResponseAsync(context);

                        if (string.IsNullOrEmpty(fragment))
                        {
                            _statusCallback("Error: No authentication token received.");
                            throw new InvalidOperationException("No authentication token received. Please try again.");
                        }

                        // Parse the fragment
                        var tokenDict = ParseFragment(fragment);

                        // Check for access token
                        if (!tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                        {
                            _statusCallback("Error: No access token in response.");
                            throw new InvalidOperationException("No access token received. Authentication failed.");
                        }

                        _statusCallback("Authentication successful!");
                        Debug.WriteLine("Authentication successful");
                        return tokenDict;
                    }
                    catch (OperationCanceledException)
                    {
                        _statusCallback("Authentication timed out.");
                        throw new TimeoutException("Authentication timed out. Please try again.");
                    }
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

        // Helper method to get callback with token
        private async Task<HttpListenerContext> GetCallbackWithTokenAsync(HttpListener listener, string expectedState, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                // Create a task that will complete when a request is received
                var contextTask = listener.GetContextAsync();

                // Wait for either the context or cancellation
                await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, cancellationToken));

                // If we were canceled, propagate the cancellation
                cancellationToken.ThrowIfCancellationRequested();

                // Get the context
                var context = await contextTask;

                // Check if this request contains valid state
                string fragment = ExtractFragment(context);
                if (!string.IsNullOrEmpty(fragment))
                {
                    var tokens = ParseFragment(fragment);
                    if (tokens.ContainsKey("state") && tokens["state"] == expectedState)
                    {
                        // This is the callback we're looking for
                        return context;
                    }
                }

                // If we reach here, it wasn't the right request, so continue listening
                await SendContinueResponseAsync(context);
            }

            throw new OperationCanceledException();
        }

        // Helper to send a response to invalid requests
        private async Task SendContinueResponseAsync(HttpListenerContext context)
        {
            string responseHtml = @"
        <!DOCTYPE html>
        <html>
        <head><title>Processing...</title></head>
        <body><p>Processing authentication, please wait...</p></body>
        </html>";

            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.ContentType = "text/html";

            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();
        }

       

        private string ExtractFragment(HttpListenerContext context)
        {
            // Enhanced fragment extraction to handle various scenarios

            // 1. Check the URL fragment directly
            string fragment = context.Request.Url.Fragment;
            if (!string.IsNullOrEmpty(fragment))
            {
                Debug.WriteLine("Found fragment in URL: " + fragment);
                return fragment;
            }

            // 2. Check for special query parameters that might contain the fragment
            var query = context.Request.QueryString;

            // Various ways browsers might encode the fragment
            if (query["fragment"] != null)
            {
                fragment = "#" + query["fragment"];
                Debug.WriteLine("Found fragment in 'fragment' query parameter: " + fragment);
                return fragment;
            }

            if (query["#"] != null)
            {
                fragment = "#" + query["#"];
                Debug.WriteLine("Found fragment in '#' query parameter: " + fragment);
                return fragment;
            }

            // 3. Check for access_token directly in query params
            if (query["access_token"] != null)
            {
                var sb = new StringBuilder("#access_token=");
                sb.Append(query["access_token"]);

                // Add other standard OAuth parameters if present
                if (query["token_type"] != null)
                    sb.Append("&token_type=").Append(query["token_type"]);
                if (query["expires_in"] != null)
                    sb.Append("&expires_in=").Append(query["expires_in"]);
                if (query["state"] != null)
                    sb.Append("&state=").Append(query["state"]);
                if (query["id_token"] != null)
                    sb.Append("&id_token=").Append(query["id_token"]);

                fragment = sb.ToString();
                Debug.WriteLine("Constructed fragment from query parameters: " + fragment);
                return fragment;
            }

            // 4. Check request headers for Referer which might contain the fragment
            string referer = context.Request.Headers["Referer"];
            if (!string.IsNullOrEmpty(referer))
            {
                try
                {
                    var refererUri = new Uri(referer);
                    if (!string.IsNullOrEmpty(refererUri.Fragment))
                    {
                        Debug.WriteLine("Found fragment in referer: " + refererUri.Fragment);
                        return refererUri.Fragment;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Error parsing referer URI: " + ex.Message);
                }
            }

            // 5. Try to parse the raw URL to find a fragment anywhere
            string rawUrl = context.Request.RawUrl;
            if (!string.IsNullOrEmpty(rawUrl))
            {
                int hashIndex = rawUrl.IndexOf('#');
                if (hashIndex >= 0)
                {
                    fragment = rawUrl.Substring(hashIndex);
                    Debug.WriteLine("Found fragment in raw URL: " + fragment);
                    return fragment;
                }
            }

            // 6. Check the post data if it's a POST request
            if (context.Request.HttpMethod == "POST")
            {
                try
                {
                    using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
                    {
                        string body = reader.ReadToEnd();
                        if (body.Contains("access_token="))
                        {
                            Debug.WriteLine("Found token in POST body: " + body);
                            return "#" + body;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Error reading POST data: " + ex.Message);
                }
            }

            Debug.WriteLine("No token found in the request");
            return string.Empty;
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
        // Send the token back if it's in the URL hash
        var hash = window.location.hash;
        if (hash) {
            // Try to pass the hash back to the server
            var xhr = new XMLHttpRequest();
            xhr.open('GET', '/callback?fragment=' + encodeURIComponent(hash.substring(1)), true);
            xhr.send();
        }
        
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

            Debug.WriteLine($"Parsed {result.Count} parameters from fragment");
            foreach (var key in result.Keys)
            {
                Debug.WriteLine($"  {key}: {(key == "access_token" ? "[TOKEN]" : result[key])}");
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
                        CreateNoWindow = false, // Must be false to allow window manipulation
                        UseShellExecute = true  // Must be true to allow window manipulation
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
                        CreateNoWindow = false,
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
            // Implementation unchanged
            string[] possibleEdgePaths = new string[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
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
            // Implementation unchanged
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
            // Implementation unchanged
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
            // Implementation unchanged
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
