using IdentityModel;
using IdentityModel.Client;
using Fortis.FIBE.XN.Environment;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using CefSharp;
using CefSharp.WinForms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    internal partial class AuthForm : Form
    {
        private ChromiumWebBrowser browser;
        private readonly string _state;
        private readonly string _nonce;
        private AuthConfig _authConfig;
        private const int AuthenticationTimeoutMilliseconds = 15000;
        private const int RetryDelayMilliseconds = 2000;
        private const int MaxRetryAttempts = 4;
        private int currentRetryCount = 0;
        private System.Timers.Timer timeoutTimer;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthForm"/> class.
        /// </summary>
        /// <param name="config">The configuration settings for OIDC authentication.</param>
        public AuthForm(AuthConfig config)
        {
            InitializeComponent();
            this.StartPosition = FormStartPosition.CenterScreen;
            this.WindowState = FormWindowState.Minimized;
            this.Text = "Connecting to MSA...";
            this.Width = 400;
            this.Height = 300;
            // Generate state and nonce
            _state = CryptoRandom.CreateUniqueId();
            _nonce = CryptoRandom.CreateUniqueId();
            _authConfig = config;
            InitializeChromium(config);
        }

        private void InitializeChromium(AuthConfig config)
        {
            // Create Authorization URL
            var request = new RequestUrl(GetAuthorizeUrlBasedOnEnvironment());
            var url = request.CreateAuthorizeUrl(
                clientId: config.ClientId,
                responseType: "id_token token",
                responseMode: "fragment",
                redirectUri: config.RedirectUri,
                state: _state,
                nonce: _nonce,
                scope: config.Scope
            );
            Debug.WriteLine("AG.VC.Oidc.Winforms.AuthenticationHandler: Authentication Request Launched.");
            browser = new ChromiumWebBrowser(url);
            this.Controls.Add(browser);
            // Listen for Redirects
            browser.FrameLoadEnd += HandleFrameLoadEnd;
            StartTimeoutTimer();
        }
        private void StartTimeoutTimer()
        {
            timeoutTimer = new System.Timers.Timer(AuthenticationTimeoutMilliseconds);
            timeoutTimer.Elapsed += (sender, e) =>
            {
                timeoutTimer.Stop();
                HandleTimeout();
            };
            timeoutTimer.AutoReset = false;
            timeoutTimer.Start();
        }

        private async void HandleTimeout()
        {
            try
            {
                if (currentRetryCount < MaxRetryAttempts)
                {
                    currentRetryCount++;
                    Debug.WriteLine($"Timeout reached. Retrying authentication... Attempt {currentRetryCount} of {MaxRetryAttempts}");
                    await Task.Delay(RetryDelayMilliseconds);
                    this.Invoke((MethodInvoker)(() =>
                    {
                        InitializeChromium(_authConfig); // Retry the authentication process
                    }));
                }
                else
                {
                    Debug.WriteLine("Authentication failed after max retry attempts due to timeout.");
                    AuthenticationManager.RaiseTokenFailed("Authentication timed out.");
                    ReleaseResources();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Exception in HandleTimeout: {ex.Message}");
                AuthenticationManager.RaiseTokenFailed("An error occurred during authentication.");
                ReleaseResources();
            }
        }

        // The power of this approach lies in its ability to intercept the navigation within the embedded browser, 
        // thereby eliminating the need for the redirect_uri to resolve to an actual network location. 
        // This makes it a flexible and secure method for handling OAuth flows in fat client applications. 
        // It's a neat way to keep everything self-contained within the application while still adhering to OAuth standards.
        private void HandleFrameLoadEnd(object sender, FrameLoadEndEventArgs args)
        {
            Debug.WriteLine("AG.VC.Oidc.Winforms.AuthenticationHandler: Redirection occured.");
            if (args.Frame.IsMain)
            {
                var uri = new Uri(args.Url);
                if (uri.ToString().StartsWith(_authConfig.RedirectUri))
                {
                    timeoutTimer.Stop();
                    HandleAuthenticationSuccessState(uri);
                }
                else if (IsFailureUrl(uri))
                {
                    timeoutTimer.Stop();
                    this.Invoke((MethodInvoker)delegate
                    {
                        this.TopMost = true;
                        this.WindowState = FormWindowState.Normal;
                    });
                    AuthenticationManager.RaiseTokenFailed("Authentication failed: refer to the MSA authentication screen for more details.");
                }
            }
        }
        private bool IsFailureUrl(Uri uri)
        {
            // Parse the query string
            var queryParams = HttpUtility.ParseQueryString(uri.Query);

            // Check for explicit error parameters
            if (queryParams["errorId"] != null)
            {
                return true;
            }

            // Check for known error paths
            if (uri.AbsolutePath.Contains("/Error/Sorry"))
            {
                return true;
            }

            // Additional generic checks (if needed)
            if (uri.ToString().Contains("error") || uri.ToString().Contains("login_failure"))
            {
                return true;
            }

            // No failure detected
            return false;
        }
        private void HandleAuthenticationSuccessState(Uri uri)
        {
            var tokenDict = ParseFragment(uri.Fragment);
            SetClaimsPrincipal(tokenDict);
            ReleaseResources(1);
        }
        private Dictionary<string, string> ParseFragment(string fragment)
        {
            var pairs = fragment.Substring(1).Split('&');
            return pairs.Select(pair => pair.Split('='))
                        .ToDictionary(keyValue => keyValue[0], keyValue => WebUtility.UrlDecode(keyValue[1]));
        }
        private void ReleaseResources(double delay = 5)
        {
            this.Invoke((MethodInvoker)async delegate
            {
                await Task.Delay(TimeSpan.FromSeconds(delay));
                timeoutTimer?.Dispose();
                browser?.Dispose();
                // Close the AuthForm
                this.Dispose();
            });
        }
        private void SetClaimsPrincipal(Dictionary<string, string> tokenDict)
        {
            if (tokenDict.ContainsKey(MSAConstants.IdTokenIdentifier))
            {
                var token = tokenDict[MSAConstants.IdTokenIdentifier];
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);
                var claims = jwtToken.Claims.Select(claim => new Claim(claim.Type, claim.Value)).ToList();

                AddAccessTokenToClaims(tokenDict, claims);
                var identity = SetIdentity(claims);

                // Set the principal in AuthenticationManager
                AuthenticationManager.OidcAuthenticatedClaimsPrincipal = new ClaimsPrincipal(identity);

                // Raise the TokenReceived event through AuthenticationManager
                AuthenticationManager.RaiseTokenReceived(
                    tokenDict[MSAConstants.AccessTokenIdentifier],
                    AuthenticationManager.OidcAuthenticatedClaimsPrincipal
                );
            }
        }

        private ClaimsIdentity SetIdentity(List<Claim> claims)
        {
            var givenName = GetClaim(claims, MSAConstants.GivenNameIdentifier);
            var familyName = GetClaim(claims, MSAConstants.FamilyNameIdentifier);
            var identity = new ClaimsIdentity(claims, MSAConstants.AuthenticationTypeIdentifier, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            if (givenName != null && familyName != null)
            {
                identity.Label = $"{givenName} {familyName}";
            }
            var nameClaim = GetClaim(claims, MSAConstants.NameIdentifier);

            if (nameClaim != null)
            {
                // Remove 'AG\' prefix if it exists
                string cleanName = nameClaim.Replace("AG\\", "");

                // Add the modified claim to identity
                identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, cleanName));
            }
            return identity;
        }
        private void AddAccessTokenToClaims(Dictionary<string, string> tokenDict, List<Claim> claims)
        {
            // Add access_token to Claims
            if (tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
            {
                claims.Add(new Claim(MSAConstants.AccessTokenIdentifier, tokenDict[MSAConstants.AccessTokenIdentifier]));
            }
        }
        private string GetClaim(List<Claim> claims, string key)
        {
            return claims.FirstOrDefault(c => c.Type == key)?.Value;
        }
        private string GetAuthorizeUrlBasedOnEnvironment()
        {
            string environment = SystemInfo.Current.SystemEnvironment;
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
