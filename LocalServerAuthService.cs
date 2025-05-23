﻿
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
using Microsoft.Win32;
using IdentityModel.Client;
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class FixedPortAuthService
    {
        private readonly AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 120000; // 2 minutes
        private const int FixedPort = 54321; // Fixed port - make sure this is whitelisted with your IDP
        private readonly Action<string> _logMessage;
        private TaskCompletionSource<Dictionary<string, string>> _fragmentReceived;
        private string _state;
        private string _nonce;
        private Process _browserProcess;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _isAuthenticationSuccessful = false;
        private bool _isProcessingFragment = false;

        public FixedPortAuthService(AuthConfig authConfig, Action<string> statusCallback = null, bool hideBrowser = false)
        {
            _authConfig = authConfig ?? throw new ArgumentNullException(nameof(authConfig));
            _logMessage = statusCallback ?? ((message) => { Debug.WriteLine(message); });

            // Generate state and nonce for security
            _state = IdentityModel.CryptoRandom.CreateUniqueId();
            _nonce = IdentityModel.CryptoRandom.CreateUniqueId();
        }

        /// <summary>
        /// Authenticates the user using OAuth2 Implicit Flow
        /// </summary>
        /// <returns>Dictionary containing authentication tokens</returns>
        public async Task<Dictionary<string, string>> AuthenticateAsync()
        {
            _logMessage("Starting authentication process...");
            Debug.WriteLine("Starting fixed port authentication");
            _isAuthenticationSuccessful = false;
            _isProcessingFragment = false;

            _fragmentReceived = new TaskCompletionSource<Dictionary<string, string>>();
            _cancellationTokenSource = new CancellationTokenSource();

            //Create a fixed redirect URI using the specified port
            string redirectUri = $"http://localhost:{FixedPort}/callback";
            Debug.WriteLine($"Redirect URI: {redirectUri}");

            using (var httpListener = new HttpListener())
            {
                try
                {
                    //Set up the HTTP listener for capturing the redirect
                    httpListener.Prefixes.Add($"http://localhost:{FixedPort}/callback/");
                    httpListener.Prefixes.Add($"http://localhost:{FixedPort}/fragment/");

                    try
                    {
                        httpListener.Start();
                        _logMessage("Listener started successfully");
                    }
                    catch (HttpListenerException ex)
                    {
                        HandleListenerStartupError(ex);
                    }

                    //Create the authentication URL
                    string authUrl = BuildAuthorizationUrl(redirectUri);

                    //Launch browser and start HTTP listener
                    await LaunchBrowserAndListenForCallback(authUrl, httpListener);

                    //Return the token dictionary
                    return _fragmentReceived.Task.Result;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Authentication exception: {ex.Message}");
                    throw;
                }
                finally
                {
                    //Clean up
                    CleanupResources(httpListener);
                }
            }
        }

        private void HandleListenerStartupError(HttpListenerException ex)
        {
            _logMessage($"Error starting HTTP listener: {ex.Message}");

            if (ex.ErrorCode == 5) // Access denied
            {
                throw new InvalidOperationException(
                    "Unable to start the HTTP listener. You may need to run as administrator or check your firewall settings.",
                    ex);
            }
            else if (ex.ErrorCode == 183) // Already in use
            {
                throw new InvalidOperationException(
                    $"Port {FixedPort} is already in use. Close any other applications that might be using this port and try again.",
                    ex);
            }
            else
            {
                Debug.WriteLine("Issues with HTTP listener");
            }
        }

        private string BuildAuthorizationUrl(string redirectUri)
        {
            _logMessage("Preparing authentication URL...");

            var request = new RequestUrl(GetAuthorizeUrlBasedOnEnvironment());
            var url = request.CreateAuthorizeUrl(
                clientId: _authConfig.ClientId,
                responseType: "id_token token",
                responseMode: "fragment",
                redirectUri: redirectUri,
                state: _state,
                nonce: _nonce,
                scope: _authConfig.Scope
            );

            Debug.WriteLine($"Authentication URL: {url}");
            return url;
        }

        private async Task LaunchBrowserAndListenForCallback(string authUrl, HttpListener httpListener)
        {
            _logMessage("Launching browser...");

            // Launch browser
            if (!LaunchBrowser(authUrl))
            {
                _logMessage("Error: Failed to launch browser.");
                throw new InvalidOperationException("Failed to launch browser. Please check if a browser is installed.");
            }

            // Start listening in background
            var listenerTask = StartListenerTask(httpListener);

            // Set up timeout and wait for authentication
            using (var cts = new CancellationTokenSource(AuthenticationTimeoutMilliseconds))
            {
                _cancellationTokenSource = cts;

                _logMessage("Waiting for authentication in browser...");

                try
                {
                    var timeoutTask = Task.Delay(AuthenticationTimeoutMilliseconds, cts.Token);
                    var completedTask = await Task.WhenAny(_fragmentReceived.Task, timeoutTask);

                    if (completedTask == timeoutTask)
                    {
                        throw new TimeoutException("Authentication timed out. Please try again.");
                    }

                    // Get the fragment data and validate it
                    var tokenDict = await _fragmentReceived.Task;
                    ValidateAuthenticationResponse(tokenDict);

                    _logMessage("Authentication successful!");
                    _isAuthenticationSuccessful = true;
                }
                catch (TimeoutException)
                {
                    _logMessage("Authentication timed out. Please try again.");
                    _isAuthenticationSuccessful = false;
                    throw;
                }
                catch (Exception ex)
                {
                    _logMessage($"Authentication error: {ex.Message}");
                    _isAuthenticationSuccessful = false;
                    throw;
                }
            }
        }

        public void CancelAuthentication()
        {
            Debug.WriteLine("Authentication canceled by user");

            // Cancel the authentication task
            if (_cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested)
            {
                _cancellationTokenSource.Cancel();
            }

            // Use taskkill to terminate any browser processes we started
            if (_browserProcess != null)
            {
                try
                {
                    int processId = _browserProcess.Id;
                    KillProcessAndChildren(processId);
                    _browserProcess = null;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error killing browser process: {ex.Message}");
                }
            }

            // Make sure we also set any completion status if needed
            if (!_fragmentReceived.Task.IsCompleted)
            {
                _fragmentReceived.TrySetCanceled();
            }
        }

        private void KillProcessAndChildren(int pid)
        {
            try
            {
                Debug.WriteLine($"Using taskkill to terminate process tree for PID: {pid}");
                using (Process taskkill = new Process())
                {
                    taskkill.StartInfo.FileName = "taskkill.exe";
                    taskkill.StartInfo.Arguments = $"/F /T /PID {pid}";
                    taskkill.StartInfo.UseShellExecute = false;
                    taskkill.StartInfo.CreateNoWindow = true;
                    taskkill.Start();

                    // Wait for up to 2 seconds for the kill process to complete
                    taskkill.WaitForExit(2000);

                    Debug.WriteLine("Process tree termination completed");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error killing process tree: {ex.Message}");
            }
        }

        private Task StartListenerTask(HttpListener httpListener)
        {
            return Task.Run(async () => {
                try
                {
                    while (httpListener.IsListening)
                    {
                        try
                        {
                            var context = await httpListener.GetContextAsync();
                            await ProcessHttpRequestAsync(context);
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Error processing HTTP request: {ex.Message}");
                            // Continue listening for other requests
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Listener task error: {ex.Message}");
                    // Signal fragment completion with error if not already completed
                    if (!_fragmentReceived.Task.IsCompleted)
                    {
                        _fragmentReceived.TrySetException(ex);
                    }
                }
            });
        }

        private void ValidateAuthenticationResponse(Dictionary<string, string> tokenDict)
        {
            if (tokenDict == null)
            {
                _isAuthenticationSuccessful = false;
                throw new InvalidOperationException("No token data received");
            }

            if (tokenDict.ContainsKey("error"))
            {
                string errorDescription = tokenDict.ContainsKey("error_description")
                    ? tokenDict["error_description"]
                    : "Unknown error";

                _logMessage($"Authentication error: {errorDescription}");
                _isAuthenticationSuccessful = false;
                throw new InvalidOperationException($"Authentication error: {errorDescription}");
            }

            // Validate state parameter to prevent CSRF
            if (!tokenDict.ContainsKey("state") || tokenDict["state"] != _state)
            {
                _logMessage("Error: Invalid state parameter.");
                Debug.WriteLine("State validation failed");
                _isAuthenticationSuccessful = false;
                throw new InvalidOperationException("Invalid state parameter. The authentication request may have been tampered with.");
            }

            // Check if we have an access token
            if (!tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
            {
                _logMessage("Error: No access token received.");
                Debug.WriteLine("No access token in the response");
                _isAuthenticationSuccessful = false;
                throw new InvalidOperationException("No access token received. Authentication failed.");
            }

            // If we get here, authentication was successful
            _isAuthenticationSuccessful = true;
        }

        private void CleanupResources(HttpListener httpListener)
        {
            try
            {
                if (httpListener != null && httpListener.IsListening)
                {
                    httpListener.Stop();
                    Debug.WriteLine("HTTP listener stopped");
                }

                if (_cancellationTokenSource != null)
                {
                    _cancellationTokenSource.Dispose();
                    _cancellationTokenSource = null;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error stopping HTTP listener: {ex.Message}");
                // Just log, don't throw from cleanup
            }
        }

        private async Task ProcessHttpRequestAsync(HttpListenerContext context)
        {
            try
            {
                string path = context.Request.Url.AbsolutePath;
                Debug.WriteLine($"Received request to {path}");

                if (path.StartsWith("/callback"))
                {
                    await SendCallbackPageAsync(context);
                    _logMessage("Processing authentication callback");
                }
                else if (path.StartsWith("/fragment"))
                {
                    // Prevent multiple fragment processing
                    if (_isProcessingFragment)
                    {
                        Debug.WriteLine("Ignoring duplicate fragment processing request");
                        await SendFragmentProcessedResponseAsync(context);
                        return;
                    }

                    _isProcessingFragment = true;

                    if (context.Request.HttpMethod == "POST")
                    {
                        // Handle POST requests from the form
                        await ProcessFragmentPostDataAsync(context);
                    }
                    else
                    {
                        // Handle GET requests (old method)
                        await ProcessFragmentDataAsync(context);
                    }
                }
                else
                {
                    // Send 404 for unknown paths
                    await SendErrorResponseAsync(context, 404, "Not Found");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in ProcessHttpRequestAsync: {ex.Message}");

                try
                {
                    if (context.Response.OutputStream.CanWrite)
                    {
                        await SendErrorResponseAsync(context, 500, "Internal Server Error");
                    }
                }
                catch
                {
                    // Ignore errors in error handling
                }
            }
        }

        private async Task SendFragmentProcessedResponseAsync(HttpListenerContext context)
        {
            string responseHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Complete</title>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background-color: #f0f0f0; 
            text-align: center; 
            margin: 0; 
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container { 
            background-color: white; 
            max-width: 500px; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .success {
            color: #107C10;
            font-weight: bold;
        }
    </style>
    <script>
        window.onload = function() {
            setTimeout(function() {
                window.close();
            }, 1000);
        };
    </script>
</head>
<body>
    <div class='container'>
        <p class='success'>Authentication successful!</p>
        <p>You can close this window now.</p>
    </div>
</body>
</html>";

            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            context.Response.ContentLength64 = buffer.Length;
            context.Response.ContentType = "text/html";
            context.Response.StatusCode = 200;

            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();
        }

        private async Task ProcessFragmentPostDataAsync(HttpListenerContext context)
        {
            try
            {
                // Read POST data
                string fragmentData = "";
                using (var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding))
                {
                    string formData = await reader.ReadToEndAsync();
                    Debug.WriteLine($"Received POST fragment data: {formData}");

                    // Extract the fragment parameter
                    var formParts = formData.Split('&');
                    foreach (var part in formParts)
                    {
                        var keyValue = part.Split(new[] { '=' }, 2);
                        if (keyValue.Length == 2 && keyValue[0] == "fragment")
                        {
                            fragmentData = HttpUtility.UrlDecode(keyValue[1]);
                            break;
                        }
                    }
                }

                bool fragmentProcessed = false;

                if (!string.IsNullOrEmpty(fragmentData))
                {
                    // Parse the query parameters
                    Dictionary<string, string> parsedData = ParseQueryString(fragmentData);

                    // Signal that we've received the fragment data
                    if (parsedData.Count > 0)
                    {
                        fragmentProcessed = _fragmentReceived.TrySetResult(parsedData);
                        Debug.WriteLine($"Successfully parsed and processed fragment data: {fragmentProcessed}");
                        _logMessage("Authentication data received");
                    }
                    else
                    {
                        fragmentProcessed = _fragmentReceived.TrySetException(new InvalidOperationException("Empty fragment data"));
                        Debug.WriteLine($"Empty fragment data received: {fragmentProcessed}");
                        _logMessage("Error: Empty authentication data");
                    }
                }
                else
                {
                    fragmentProcessed = _fragmentReceived.TrySetException(new InvalidOperationException("No fragment data received"));
                    Debug.WriteLine($"No fragment data received: {fragmentProcessed}");
                    _logMessage("Error: No authentication data received");
                }

                // Send a clear success response
                await SendFragmentProcessedResponseAsync(context);
                Debug.WriteLine("Fragment data processing complete with success response");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in ProcessFragmentPostDataAsync: {ex.Message}");
                throw;
            }
        }

        private async Task SendErrorResponseAsync(HttpListenerContext context, int statusCode, string message)
        {
            context.Response.StatusCode = statusCode;
            byte[] buffer = Encoding.UTF8.GetBytes(message);
            context.Response.ContentLength64 = buffer.Length;
            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            context.Response.OutputStream.Close();
        }

        private async Task SendCallbackPageAsync(HttpListenerContext context)
        {
            try
            {
                // Create a page that will extract the fragment and send it back to us
                string callbackHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication</title>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background-color: #f0f0f0; 
            text-align: center; 
            margin: 0; 
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container { 
            background-color: white; 
            max-width: 500px; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 4px 12px rgba(0,0,0,0.15); 
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .spinner {
            border: 4px solid rgba(0, 120, 212, 0.1);
            border-radius: 50%;
            border-top: 4px solid #0078d4;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px 0;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        #status {
            font-weight: bold;
            margin: 10px 0;
        }
        .success { color: #107C10; }
        .error { color: #D83B01; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='spinner' id='spinner'></div>
        <p id='status'>Processing authentication...</p>
    </div>
    <script>
        // Extract the fragment data and send it back
        function processFragment() {
            var fragmentData = location.hash.substring(1);
            
            if (fragmentData) {
                document.getElementById('status').textContent = 'Authentication successful! Completing process...';
                
                try {
                    // Create a form submit approach instead of fetch
                    var form = document.createElement('form');
                    form.method = 'POST';
                    form.action = 'http://localhost:" + FixedPort + @"/fragment';
                    form.style.display = 'none';
                    
                    var input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'fragment';
                    input.value = fragmentData;
                    
                    form.appendChild(input);
                    document.body.appendChild(form);
                    
                    // Submit the form
                    form.submit();
                    
                    // Don't auto-close here, let the response page handle it
                } catch(e) {
                    console.error('Error sending data:', e);
                    document.getElementById('spinner').style.display = 'none';
                    document.getElementById('status').className = 'error';
                    document.getElementById('status').textContent = 'Error: ' + e.message + '. Please close this window and try again.';
                }
            } else {
                document.getElementById('spinner').style.display = 'none';
                document.getElementById('status').className = 'error';
                document.getElementById('status').textContent = 'No authentication data received. Please try again.';
            }
        }
        
        // Run when page loads
        window.onload = processFragment;
    </script>
</body>
</html>";
                byte[] buffer = Encoding.UTF8.GetBytes(callbackHtml);
                context.Response.ContentLength64 = buffer.Length;
                context.Response.ContentType = "text/html";
                await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                context.Response.OutputStream.Close();
                Debug.WriteLine("Sent callback page with fragment extraction script");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in SendCallbackPageAsync: {ex.Message}");
                throw;
            }
        }

        private async Task ProcessFragmentDataAsync(HttpListenerContext context)
        {
            try
            {
                // Parse query parameters to get the fragment data
                var query = context.Request.Url.Query;
                Debug.WriteLine($"Received fragment data: {query}");

                Dictionary<string, string> fragmentData = null;
                bool fragmentProcessed = false;

                if (!string.IsNullOrEmpty(query) && query.Length > 1)
                {
                    // Remove the leading ? character
                    query = query.Substring(1);

                    // Parse the query parameters
                    fragmentData = ParseQueryString(query);

                    // Signal that we've received the fragment data
                    if (fragmentData.Count > 0)
                    {
                        fragmentProcessed = _fragmentReceived.TrySetResult(fragmentData);
                        Debug.WriteLine($"Fragment processing success: {fragmentProcessed}");
                    }
                    else
                    {
                        fragmentProcessed = _fragmentReceived.TrySetException(new InvalidOperationException("Empty fragment data"));
                        Debug.WriteLine("Empty fragment data received");
                    }
                }
                else
                {
                    fragmentProcessed = _fragmentReceived.TrySetException(new InvalidOperationException("No fragment data received"));
                    Debug.WriteLine("No fragment data received");
                }

                // Send a clear success response
                await SendFragmentProcessedResponseAsync(context);
                Debug.WriteLine("Fragment data processing complete with success response");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in ProcessFragmentDataAsync: {ex.Message}");
                throw;
            }
        }

        private Dictionary<string, string> ParseQueryString(string query)
        {
            var pairs = query.Split('&');
            var fragmentData = new Dictionary<string, string>();

            foreach (var pair in pairs)
            {
                var keyValue = pair.Split(new char[] { '=' }, 2); // Split on first = only
                if (keyValue.Length == 2)
                {
                    fragmentData[keyValue[0]] = HttpUtility.UrlDecode(keyValue[1]);
                }
                else if (keyValue.Length == 1 && !string.IsNullOrEmpty(keyValue[0]))
                {
                    // Handle value-less parameters
                    fragmentData[keyValue[0]] = string.Empty;
                }
            }

            return fragmentData;
        }

        private bool LaunchBrowser(string url)
        {
            try
            {
                // Simply use the system's default browser to open the URL
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                };

                _browserProcess = Process.Start(psi);
                Debug.WriteLine($"Browser launched with URL: {url}");

                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error launching browser: {ex.Message}");
                return false;
            }
        }

        private string GetAuthorizeUrlBasedOnEnvironment()
        {
            string environment = Fortis.FIBE.XN.Environment.SystemInfo.Current.SystemEnvironment;

            switch (environment)
            {
                case MSAConstants.LocalEnvironmentIdentifier:
                case MSAConstants.DevEnvironmentIdentifier:
                    return MSAConstants.AuthorizeUrlDev;
                case MSAConstants.QualEnvironmentIdentifier:
                    return MSAConstants.AuthorizeUrlQual;
                case MSAConstants.AccEnvironmentIdentifier:
                    return MSAConstants.AuthorizeUrlAcc;
                case MSAConstants.ProdEnvironmentIdentifier:
                    return MSAConstants.AuthorizeUrlProd;
                default:
                    throw new InvalidOperationException($"Invalid or unsupported environment: {environment}");
            }
        }

        public ClaimsPrincipal CreateClaimsPrincipal(Dictionary<string, string> tokenDict)
        {
            if (tokenDict == null)
            {
                throw new ArgumentNullException(nameof(tokenDict));
            }

            var claims = new List<Claim>();

            // Add all token information as claims
            foreach (var pair in tokenDict)
            {
                claims.Add(new Claim(pair.Key, pair.Value));
            }

            // Process ID token if available
            if (tokenDict.ContainsKey(MSAConstants.IdTokenIdentifier))
            {
                ProcessIdTokenClaims(tokenDict[MSAConstants.IdTokenIdentifier], claims, out ClaimsIdentity identity);
                return new ClaimsPrincipal(identity);
            }
            else
            {
                // Create basic identity if no ID token
                var identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier);
                return new ClaimsPrincipal(identity);
            }
        }

        private void ProcessIdTokenClaims(string idToken, List<Claim> existingClaims, out ClaimsIdentity identity)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(idToken);

            // Add claims from ID token without duplicates
            foreach (var claim in jwtToken.Claims)
            {
                if (!existingClaims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                {
                    existingClaims.Add(new Claim(claim.Type, claim.Value));
                }
            }

            // Create identity
            identity = new ClaimsIdentity(existingClaims, MSAConstants.AuthenticationTypeIdentifier);

            // Extract user information
            string givenName = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.GivenNameIdentifier)?.Value;
            string familyName = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.FamilyNameIdentifier)?.Value;

            // Set identity label if possible
            if (!string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(familyName))
            {
                identity.Label = $"{givenName} {familyName}";
            }

            // Handle name claim
            string nameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(nameClaim))
            {
                // Remove 'AG\' prefix if it exists
                string cleanName = nameClaim.Replace("AG\\", "");
                identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, cleanName));
            }
        }
    }
}
