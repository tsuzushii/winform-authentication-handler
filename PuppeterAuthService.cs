
using PuppeteerSharp;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Win32;
using IdentityModel.Client;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class PuppeteerAuthService
    {
        private readonly AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 30000;

        public PuppeteerAuthService(AuthConfig authConfig)
        {
            _authConfig = authConfig;
        }

        public async Task<Dictionary<string, string>> AuthenticateAsync()
        {
            string requestToken = string.Empty;
            string exceptionMessage = string.Empty;
            Dictionary<string, string> tokenDict = new Dictionary<string, string>();

            // Create a profile directory for persistent authentication
            var profilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AG.VC.Oidc.WinForms",
                "EdgeProfile");

            // Ensure directory exists
            if (!Directory.Exists(profilePath))
            {
                Directory.CreateDirectory(profilePath);
            }

            // Create authorization URL
            var url = GetFullAuthorizeUrl();
            Debug.WriteLine("Auth URL: " + url);

            // Configure options for Edge browser
            var launchOptions = new LaunchOptions
            {
                DumpIO = false,
                Headless = false,
                IgnoreDefaultArgs = true,
                Args = new string[]
                {
                    "--no-sandbox",
                    "--enable-automation",
                    "--disable-search-engine-choice-screen",
                    "--no-first-run",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--user-data-dir=" + profilePath,
                    "\"" + url + "\""  // Pass URL directly as argument
                }
            };

            // Find Edge executable
            var edgePath = GetEdgeBrowserExecutable();
            Debug.WriteLine("Using Edge browser at: " + edgePath);

            if (string.IsNullOrEmpty(edgePath))
            {
                Debug.WriteLine("Edge not found, falling back to Chrome or downloading browser...");
                var chromePath = GetChromeBrowserExecutable();

                if (!string.IsNullOrEmpty(chromePath))
                {
                    launchOptions.ExecutablePath = chromePath;
                }
                else
                {
                    await new BrowserFetcher().DownloadAsync();
                }
            }
            else
            {
                launchOptions.ExecutablePath = edgePath;

                // Add Edge-specific flags for better SSO support
                var edgeArgs = new List<string>(launchOptions.Args);
                edgeArgs.Add("--enable-features=msWebAuthenticationAPI,msSingleSignOnService");
                edgeArgs.Add("--auth-server-allowlist=*.microsoftonline.com,*.live.com,*.msauth.net,*.msftauth.net");
                launchOptions.Args = edgeArgs.ToArray();
            }

            try
            {
                Debug.WriteLine("Launching browser...");

                // Launch browser directly with the URL
                using (var browser = await Puppeteer.LaunchAsync(launchOptions))
                {
                    Debug.WriteLine("Browser launched successfully");

                    // Monitor target changes to capture the redirect
                    browser.TargetChanged += (sender, e) =>
                    {
                        var targetUrl = e.Target.Url;
                        Debug.WriteLine("Target URL changed: " + targetUrl);

                        if (targetUrl.StartsWith(_authConfig.RedirectUri))
                        {
                            Debug.WriteLine("Detected redirect to return URL");
                            // Extract token from fragment
                            var fragment = new Uri(targetUrl).Fragment;

                            if (!string.IsNullOrEmpty(fragment))
                            {
                                var pairs = fragment.Substring(1).Split('&');
                                tokenDict = pairs
                                    .Select(pair => pair.Split('='))
                                    .ToDictionary(
                                        keyValue => keyValue[0],
                                        keyValue => HttpUtility.UrlDecode(keyValue[1])
                                    );

                                // Get access token
                                if (tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                                {
                                    requestToken = tokenDict[MSAConstants.AccessTokenIdentifier];
                                    Debug.WriteLine("Token obtained successfully");
                                }
                            }
                        }
                        else if (targetUrl.Contains("/Error/") || targetUrl.Contains("error="))
                        {
                            Debug.WriteLine("Error detected in URL: " + targetUrl);

                            // Capture error information
                            var errorMatch = Regex.Match(targetUrl, @"/msa-idp/Error/([a-zA-Z0-9]+)");
                            if (errorMatch.Success)
                            {
                                var errorCode = errorMatch.Groups[1].Value;
                                exceptionMessage = "Authentication failed with code " + errorCode;
                            }
                            else
                            {
                                exceptionMessage = "Authentication failed";
                            }
                        }
                    };

                    // Wait for authentication to complete or timeout
                    Debug.WriteLine("Waiting for authentication to complete...");
                    var timeoutTask = Task.Delay(AuthenticationTimeoutMilliseconds);
                    var resultTask = Task.Run(async () =>
                    {
                        while (string.IsNullOrEmpty(requestToken) && string.IsNullOrEmpty(exceptionMessage))
                        {
                            await Task.Delay(200);
                        }
                    });

                    // Wait for either completion or timeout
                    await Task.WhenAny(timeoutTask, resultTask);

                    if (timeoutTask.IsCompleted && string.IsNullOrEmpty(requestToken) && string.IsNullOrEmpty(exceptionMessage))
                    {
                        Debug.WriteLine("Authentication timed out");
                    }

                    // Clean up browser
                    Debug.WriteLine("Closing browser");
                    await browser.CloseAsync();
                    await browser.DisposeAsync();
                }

                // Check if authentication was successful
                if (!string.IsNullOrEmpty(exceptionMessage))
                {
                    Debug.WriteLine("Authentication exception: " + exceptionMessage);
                    throw new UnauthorizedAccessException(exceptionMessage);
                }

                if (string.IsNullOrEmpty(requestToken))
                {
                    Debug.WriteLine("No token received");
                    throw new TimeoutException("Authentication timed out");
                }

                Debug.WriteLine("Authentication completed successfully");
                return tokenDict;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Authentication error: " + ex.Message);
                throw;
            }
        }

        public ClaimsPrincipal CreateClaimsPrincipal(Dictionary<string, string> tokenDict)
        {
            // Implementation remains the same
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

        private string GetFullAuthorizeUrl()
        {
            // Generate state and nonce for security
            var state = IdentityModel.CryptoRandom.CreateUniqueId();
            var nonce = IdentityModel.CryptoRandom.CreateUniqueId();

            var request = new IdentityModel.Client.RequestUrl(GetAuthorizeUrlBasedOnEnvironment());
            return request.CreateAuthorizeUrl(
                clientId: _authConfig.ClientId,
                responseType: "id_token token",
                responseMode: "fragment",
                redirectUri: _authConfig.RedirectUri,
                state: state,
                nonce: nonce,
                scope: _authConfig.Scope
            );
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
    }
}
