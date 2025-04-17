using CefSharp;
using CefSharp.WinForms;
using Fortis.FIBE.XN.Environment;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    /// <summary>
    /// Manages OIDC authentication flow using CEF (Chromium Embedded Framework).
    /// Responsible for initializing the OIDC authentication process, managing token refresh, and storing the authenticated ClaimsPrincipal.
    /// </summary>
    public static class AuthenticationManager
    {
        /// <summary>
        /// Get ClaimsPrincipal that represents an MSA authenticated user via Oidc.
        /// </summary>
        /// <value>
        /// The ClaimsPrincipal that contains the identities and claims of the connected user.
        /// </value>
        /// <remarks>
        /// This property holds the authenticated user's claims and identities and is set upon a successful MSA oidc authentication.
        /// </remarks>
        public static ClaimsPrincipal OidcAuthenticatedClaimsPrincipal { get; set; }
        private static System.Timers.Timer refreshTimer;
        private static TimeSpan bufferTime;
        private static AuthForm _authForm;
        private static SynchronizationContext _uiContext;

        /// <summary>
        /// Event raised when authentication is successful and token is received.
        /// </summary>
        public static event EventHandler<TokenReceivedEventArgs> TokenReceived;

        /// <summary>
        /// Event raised when authentication failed and token fails to be received.
        /// </summary>
        public static event EventHandler<string> TokenFailed;

        /// <summary>
        /// Method to invoke the TokenReceived event.
        /// </summary>
        internal static void RaiseTokenReceived(string accessToken, ClaimsPrincipal claimsPrincipal)
        {
            TokenReceived?.Invoke(null, new TokenReceivedEventArgs
            {
                AccessToken = accessToken,
                ClaimsPrincipal = claimsPrincipal
            });
        }

        /// <summary>
        /// Method to invoke the TokenFailed event.
        /// </summary>
        internal static void RaiseTokenFailed(string reason)
        {
            TokenFailed?.Invoke(null, reason);
        }

        /// <summary>
        /// Initializes the authentication process using the provided configuration settings.
        /// </summary>
        /// <remarks>
        /// This method performs the following tasks:
        /// 1. Initializes the Chromium Embedded Framework (CEF) if not already initialized.
        /// 2. Opens an authentication form for user login.
        /// 3. Sets the authenticated principal if authentication is successful.
        /// 
        /// <para>Make sure you call this method to kick off the authentication flow.</para>
        /// </remarks>
        /// <param name="config">An instance of <see cref="AuthConfig"/> that contains authentication configuration settings like ClientId, Scope and RedirectUri.</param>
        /// <example>
        /// <code>
        /// AuthConfig config = new AuthConfig
        /// {
        ///     ClientId = "YourClientID",
        ///     Scope = "YourScope",
        ///     RedirectUri = "YourRedirectURI",
        /// };
        /// AuthenticationManager.Initialize(config);
        /// </code>
        /// </example>
        /// <exception cref="ArgumentNullException">Thrown when the provided <see cref="AuthConfig"/> is null.</exception>
        public static void Initialize(AuthConfig config)
        {
            _uiContext = SynchronizationContext.Current;

            // Initialize CEF with enhanced settings for Windows authentication
            if (!Cef.IsInitialized)
            {
                var settings = new CefSettings();

                // Essential settings for SSO
                settings.PersistSessionCookies = true;
                settings.PersistUserPreferences = true;

                // Create a cache path in the user's profile
                string cachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AG.VC.Oidc.WinForms.AuthenticationHandler",
                    "CefCache"
                );

                if (!Directory.Exists(cachePath))
                {
                    Directory.CreateDirectory(cachePath);
                }

                settings.CachePath = cachePath;

                // Add Microsoft domains to the whitelist for authentication
                settings.CefCommandLineArgs.Add("auth-server-whitelist",
                    "*.aginsurance.intranet,*.microsoftonline.com,*.microsoft.com");
                settings.CefCommandLineArgs.Add("auth-negotiate-delegate-whitelist",
                    "*.aginsurance.intranet,*.microsoftonline.com,*.microsoft.com");

                // Enable integrated authentication
                settings.CefCommandLineArgs.Add("enable-ntlm-v2", "1");
                settings.CefCommandLineArgs.Add("allow-universal-access-from-files", "1");

                // Disable same-origin policy to help with redirects
                settings.CefCommandLineArgs.Add("disable-web-security", "1");

                // Enhanced proxy handling (may help with corporate networks)
                settings.CefCommandLineArgs.Add("proxy-auto-detect", "1");

                // Enable all authentication schemes
                settings.CefCommandLineArgs.Add("auth-schemes", "basic,digest,ntlm,negotiate");

                Cef.Initialize(settings);

                LogUserInfo(); // Log user info for debugging
            }

            InitializeAndShowAuthForm(config);

            if (OidcAuthenticatedClaimsPrincipal?.Identity?.IsAuthenticated == true)
            {
                InitializeRefreshTokenTimer(config);
            }
        }

        private static void LogUserInfo()
        {
            try
            {
                using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    Debug.WriteLine($"Windows Identity: {identity.Name}");
                    Debug.WriteLine($"Authentication Type: {identity.AuthenticationType}");
                    Debug.WriteLine($"Is Authenticated: {identity.IsAuthenticated}");

                    foreach (var claim in identity.Claims)
                    {
                        Debug.WriteLine($"Claim: {claim.Type} = {claim.Value}");
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error getting Windows identity: {ex.Message}");
            }
        }

        private static void InitializeRefreshTokenTimer(AuthConfig config)
        {
            // Stop and release the previous timer if it exists
            if (refreshTimer != null)
            {
                refreshTimer.Stop();
                refreshTimer.Dispose();
            }
            refreshTimer = new System.Timers.Timer();
            bufferTime = TimeSpan.FromMinutes(MSAConstants.ExpiryBufferTimeInMinutes);

            // Get the token expiry time directly from the access_token
            var tokenExpiryTime = GetTokenExpiryTime();

            refreshTimer.Interval = (tokenExpiryTime - DateTime.UtcNow).TotalMilliseconds - bufferTime.TotalMilliseconds;
            refreshTimer.Elapsed += (sender, e) =>
            {
                //marshal execution of authForm initialization on ui thread
                _uiContext.Post(_ => InitializeAndShowAuthForm(config), null);
            };
            refreshTimer.Start();
        }

        private static void InitializeAndShowAuthForm(AuthConfig config, bool isOnTop = true, bool isMinimized = false)
        {
            if (_authForm != null)
            {
                _authForm.Dispose();
            }
            _authForm = new AuthForm(config);

            // Set form properties
            _authForm.TopMost = isOnTop;
            if (!isMinimized)
            {
                _authForm.WindowState = FormWindowState.Normal;
            }

            _authForm.Show();
        }

        private static DateTime GetTokenExpiryTime()
        {
            var claimsPrincipal = Thread.CurrentPrincipal as ClaimsPrincipal;
            var accessToken = claimsPrincipal?.Claims.FirstOrDefault(c => c.Type == MSAConstants.AccessTokenIdentifier)?.Value;

            if (string.IsNullOrEmpty(accessToken))
            {
                // TODO(Anas): Handle error => Token not found
                return DateTime.UtcNow.AddHours(1);
            }

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(accessToken);
            var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == MSAConstants.TokenExpiryIdentifier);

            if (expClaim != null && long.TryParse(expClaim.Value, out long expValue))
            {
                // Convert the Unix timestamp to DateTime
                return DateTimeOffset.FromUnixTimeSeconds(expValue).UtcDateTime;
            }
            else
            {
                //  TODO(Anas): Handle error=> Claim not found or could not be parsed
                return DateTime.UtcNow.AddHours(1);
            }
        }
    }
}
