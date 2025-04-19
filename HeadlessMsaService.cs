
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Win32;
using PuppeteerSharp;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    /// <summary>
    /// Provides headless authentication using PuppeteerSharp and Edge browser
    /// </summary>
    public class HeadlessMsaService
    {
        private readonly AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 15000;
        private readonly Action<string> _logCallback;

        /// <summary>
        /// Initializes a new instance of the HeadlessMsaService
        /// </summary>
        /// <param name="authConfig">Authentication configuration</param>
        /// <param name="logCallback">Optional callback for logging messages</param>
        public HeadlessMsaService(AuthConfig authConfig, Action<string> logCallback = null)
        {
            _authConfig = authConfig ?? throw new ArgumentNullException(nameof(authConfig));
            _logCallback = logCallback ?? ((s) => Debug.WriteLine(s));
        }

        /// <summary>
        /// Authenticates the user silently using a headless browser
        /// </summary>
        /// <returns>Dictionary of token information</returns>
        public async Task<Dictionary<string, string>> AuthenticateAsync(CancellationToken cancellationToken = default)
        {
            _logCallback("Starting headless authentication...");

            Dictionary<string, string> tokenDict = new Dictionary<string, string>();
            string exceptionMessage = string.Empty;
            bool authenticationCompleted = false;
            IBrowser browser = null;
            IPage page = null;

            try
            {
                // Check for cancellation
                cancellationToken.ThrowIfCancellationRequested();

                // Create the authorization URL with your config
                string state = CryptoRandom.CreateUniqueId();
                string nonce = CryptoRandom.CreateUniqueId();

                RequestUrl requestUrl = new RequestUrl(GetAuthorizeUrlBasedOnEnvironment());
                string url = requestUrl.CreateAuthorizeUrl(
                    clientId: _authConfig.ClientId,
                    responseType: "id_token token",
                    responseMode: "fragment",
                    redirectUri: _authConfig.RedirectUri,
                    state: state,
                    nonce: nonce,
                    scope: _authConfig.Scope
                );

                _logCallback(string.Format("Using authorize URL: {0}", GetAuthorizeUrlBasedOnEnvironment()));
                _logCallback(string.Format("Authentication redirect URI: {0}", _authConfig.RedirectUri));

                LaunchOptions launchOptions = new LaunchOptions
                {
                    DumpIO = false,
                    Headless = true,
                    HeadlessMode = HeadlessMode.True,
                    DefaultViewport = new ViewPortOptions { Width = 1920, Height = 1080 },
                    Args = new string[]
                    {
                "--no-sandbox",
                "--disable-gpu",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-sync",
                "--disable-translate",
                "--disable-renderer-backgrounding",
                "--disable-backgrounding-occluded-windows",
                "--disable-breakpad",
                "--disable-extensions",
                "--disable-infobars",
                "--disable-background-timer-throttling"
                    }
                };

                string edgePath = GetEdgeBrowserExecutable();
                _logCallback(string.Format("Using browser at: {0}", edgePath));

                if (string.IsNullOrEmpty(edgePath))
                {
                    throw new UnauthorizedAccessException("Not able to authorize due to missing Edge executable path.");
                }

                launchOptions.ExecutablePath = edgePath;

                // Check for cancellation before launching browser
                cancellationToken.ThrowIfCancellationRequested();

                browser = await Puppeteer.LaunchAsync(launchOptions);
                _logCallback("Browser launched successfully");

                // Register cancellation callback to close browser
                cancellationToken.Register(async () =>
                {
                    _logCallback("Cancellation requested, closing browser...");
                    try
                    {
                        if (browser != null && !browser.IsClosed)
                        {
                            await browser.CloseAsync();
                        }
                    }
                    catch (Exception ex)
                    {
                        _logCallback($"Error closing browser on cancellation: {ex.Message}");
                    }
                });

                page = await browser.NewPageAsync();
                await page.SetCacheEnabledAsync(true);
                await page.SetRequestInterceptionAsync(true);

                // Optimize by blocking unnecessary resources
                page.Request += async (sender, e) =>
                {
                    if (e.Request.ResourceType == ResourceType.Image ||
                        e.Request.ResourceType == ResourceType.StyleSheet ||
                        e.Request.ResourceType == ResourceType.Font)
                    {
                        await e.Request.AbortAsync();
                    }
                    else
                    {
                        await e.Request.ContinueAsync();
                    }
                };

                // Monitor for authentication completion or errors
                browser.TargetChanged += async (sender, e) =>
                {
                    try
                    {
                        string targetUrl = e.Target.Url;
                        _logCallback(string.Format("Navigation detected: {0}", targetUrl));

                        if (targetUrl.StartsWith(_authConfig.RedirectUri))
                        {
                            // Handle successful authentication
                            string fragment = new Uri(targetUrl).Fragment;
                            if (!string.IsNullOrEmpty(fragment))
                            {
                                string[] pairs = fragment.Substring(1).Split('&');
                                foreach (string pair in pairs)
                                {
                                    string[] keyValue = pair.Split('=');
                                    if (keyValue.Length == 2)
                                    {
                                        tokenDict[keyValue[0]] = WebUtility.UrlDecode(keyValue[1]);
                                    }
                                }

                                // Validate state to prevent CSRF
                                string returnedState;
                                if (tokenDict.TryGetValue("state", out returnedState) && returnedState == state)
                                {
                                    _logCallback("Authentication successful - token received");
                                    authenticationCompleted = true;
                                }
                                else
                                {
                                    exceptionMessage = "State validation failed. Possible security issue.";
                                    _logCallback(exceptionMessage);
                                }
                            }
                        }
                        else if (targetUrl.Contains("/Error/"))
                        {
                            // Handle authentication errors
                            Match errorMatch = Regex.Match(targetUrl, @"/msa-idp/Error/([a-zA-Z0-9]+)");
                            if (errorMatch.Success)
                            {
                                string errorCode = errorMatch.Groups[1].Value;
                                string pageContent = string.Empty;

                                if (errorCode == "Sorry")
                                {
                                    IPage errorPage = await e.Target.PageAsync();
                                    if (errorPage != null)
                                    {
                                        await errorPage.WaitForSelectorAsync("body");
                                        pageContent = await errorPage.EvaluateExpressionAsync<string>("document.documentElement.innerText");
                                        pageContent = string.Format(" - Error page content: {0}", pageContent.Replace("\n\n", " - "));
                                    }
                                }

                                exceptionMessage = string.Format("Authentication failed with code {0}{1}", errorCode, pageContent);
                                _logCallback(exceptionMessage);
                                authenticationCompleted = true;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logCallback(string.Format("Error processing navigation: {0}", ex.Message));
                    }
                };

                // Navigate to authorization URL
                await page.GoToAsync(url);
                _logCallback("Navigated to authentication URL, waiting for completion...");

                // Wait for authentication to complete, cancellation, or timeout
                var timeoutCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(AuthenticationTimeoutMilliseconds));
                var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                try
                {
                    await Task.Run(async () =>
                    {
                        while (!authenticationCompleted && string.IsNullOrEmpty(exceptionMessage))
                        {
                            linkedCts.Token.ThrowIfCancellationRequested();
                            await Task.Delay(200, linkedCts.Token);
                        }
                    }, linkedCts.Token);
                }
                catch (OperationCanceledException)
                {
                    if (timeoutCts.IsCancellationRequested)
                    {
                        exceptionMessage = "Authentication timed out";
                        _logCallback("Authentication timed out");
                    }
                    else
                    {
                        _logCallback("Authentication canceled by user");
                        throw; // Rethrow the cancellation exception
                    }
                }
                finally
                {
                    timeoutCts.Dispose();
                    linkedCts.Dispose();
                }
            }
            catch (OperationCanceledException)
            {
                _logCallback("Authentication was canceled");
                throw; // Rethrow to notify caller of cancellation
            }
            catch (Exception ex)
            {
                exceptionMessage = string.Format("Authentication error: {0}", ex.Message);
                _logCallback(string.Format("Critical error during authentication: {0}", ex));
            }
            finally
            {
                // Clean up resources
                if (browser != null)
                {
                    try
                    {
                        await browser.CloseAsync();
                        await browser.DisposeAsync();
                    }
                    catch (Exception ex)
                    {
                        _logCallback($"Error disposing browser: {ex.Message}");
                    }
                }
            }

            // Handle authentication results
            if (!string.IsNullOrEmpty(exceptionMessage))
            {
                throw new UnauthorizedAccessException(exceptionMessage);
            }

            if (!tokenDict.ContainsKey("access_token"))
            {
                throw new UnauthorizedAccessException("No access token received");
            }

            return tokenDict;
        }

        /// <summary>
        /// Creates a ClaimsPrincipal from the token dictionary
        /// </summary>
        /// <param name="tokenDict">Dictionary containing token information</param>
        /// <returns>A ClaimsPrincipal with claims from the tokens</returns>
        public ClaimsPrincipal CreateClaimsPrincipal(Dictionary<string, string> tokenDict)
        {
            List<Claim> claims = new List<Claim>();

            // Add all token information as claims
            foreach (KeyValuePair<string, string> pair in tokenDict)
            {
                claims.Add(new Claim(pair.Key, pair.Value));
            }

            // Process ID token if available
            if (tokenDict.ContainsKey(MSAConstants.IdTokenIdentifier))
            {
                string idToken = tokenDict[MSAConstants.IdTokenIdentifier];
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = handler.ReadJwtToken(idToken);

                // Add claims from ID token without duplicates
                foreach (Claim claim in jwtToken.Claims)
                {
                    if (!claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                    {
                        claims.Add(new Claim(claim.Type, claim.Value));
                    }
                }

                // Create identity
                ClaimsIdentity identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier);

                // Extract user information
                string givenName = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.GivenNameIdentifier)?.Value;
                string familyName = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.FamilyNameIdentifier)?.Value;

                // Set identity label if possible
                if (!string.IsNullOrEmpty(givenName) && !string.IsNullOrEmpty(familyName))
                {
                    identity.Label = string.Format("{0} {1}", givenName, familyName);
                }

                // Handle name claim
                string nameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(nameClaim))
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
                ClaimsIdentity identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier);
                return new ClaimsPrincipal(identity);
            }
        }

        /// <summary>
        /// Gets the path to the Edge browser executable
        /// </summary>
        private static string GetEdgeBrowserExecutable()
        {
            string[] possibleEdgePaths = new string[]
            {
                // Edge stable channel
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge", "Application", "msedge.exe"),
                
                // Edge Beta channel
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge Beta", "Application", "msedge.exe"),
                
                // Edge Dev channel
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft", "Edge Dev", "Application", "msedge.exe"),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Microsoft", "Edge Dev", "Application", "msedge.exe")
            };

            foreach (string path in possibleEdgePaths)
            {
                if (System.IO.File.Exists(path))
                {
                    return path;
                }
            }

            // Try registry as fallback
            string regPath = Registry.GetValue(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
                null,
                null
            ) as string;

            if (!string.IsNullOrEmpty(regPath) && System.IO.File.Exists(regPath))
            {
                return regPath;
            }

            return string.Empty;
        }

        /// <summary>
        /// Gets the authorization URL based on the current environment
        /// </summary>
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
                    throw new InvalidOperationException(string.Format("Invalid or unsupported environment: {0}", environment));
            }
        }
    }
}
