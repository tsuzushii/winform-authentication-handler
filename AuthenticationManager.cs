
using System;
using System.Diagnostics;
using System.Drawing;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public static class AuthenticationManager
    {
        public static ClaimsPrincipal OidcAuthenticatedClaimsPrincipal { get; set; }
        private static System.Timers.Timer refreshTimer;
        private static TimeSpan bufferTime;
        private static SynchronizationContext _uiContext;
        private static bool _hideBrowser = true; // Set to true to hide the browser window

        public static event EventHandler<TokenReceivedEventArgs> TokenReceived;
        public static event EventHandler<string> TokenFailed;

        internal static void RaiseTokenReceived(string accessToken, ClaimsPrincipal claimsPrincipal)
        {
            if (TokenReceived != null)
            {
                TokenReceived(null, new TokenReceivedEventArgs
                {
                    AccessToken = accessToken,
                    ClaimsPrincipal = claimsPrincipal
                });
            }
        }

        internal static void RaiseTokenFailed(string reason)
        {
            if (TokenFailed != null)
            {
                TokenFailed(null, reason);
            }
        }

        public static void Initialize(AuthConfig config)
        {
            Debug.WriteLine("AuthenticationManager.Initialize() called");
            _uiContext = SynchronizationContext.Current;

            // Create a more detailed status form
            var statusForm = new Form
            {
                Text = "Authentication",
                Width = 400,
                Height = 150,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MaximizeBox = false,
                MinimizeBox = false,
                ControlBox = true,
                ShowIcon = true
            };

            var statusLabel = new Label
            {
                Text = "Initializing authentication...",
                AutoSize = false,
                Width = 360,
                Height = 60,
                Location = new Point(20, 20),
                TextAlign = ContentAlignment.MiddleLeft
            };

            var progressBar = new ProgressBar
            {
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 30,
                Height = 20,
                Width = 360,
                Location = new Point(20, 90)
            };

            statusForm.Controls.Add(statusLabel);
            statusForm.Controls.Add(progressBar);

            // Provide an action to update the status label
            Action<string> updateStatus = (status) =>
            {
                if (_uiContext != null)
                {
                    _uiContext.Post(state =>
                    {
                        statusLabel.Text = status;
                        Debug.WriteLine("Status update: " + status);
                    }, null);
                }
            };

            // Show the status form
            statusForm.Show();
            statusForm.BringToFront();
            statusForm.Activate();

            // Start authentication in background thread
            Task.Run(async () =>
            {
                try
                {
                    updateStatus("Starting authentication process...");

                    // Create and use the fixed port authentication service with status callback
                    var authService = new FixedPortAuthService(config, updateStatus, _hideBrowser);
                    var tokenDict = await authService.AuthenticateAsync();

                    // Process the authentication result on UI thread
                    _uiContext.Post(state =>
                    {
                        try
                        {
                            // Close the status form
                            statusForm.Close();

                            if (tokenDict != null && tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                            {
                                Debug.WriteLine("Authentication successful, creating claims principal");
                                OidcAuthenticatedClaimsPrincipal = authService.CreateClaimsPrincipal(tokenDict);
                                RaiseTokenReceived(tokenDict[MSAConstants.AccessTokenIdentifier], OidcAuthenticatedClaimsPrincipal);

                                // Setup token refresh
                                InitializeRefreshTokenTimer(config);
                            }
                            else
                            {
                                Debug.WriteLine("Authentication failed - no token dictionary or no access token");
                                RaiseTokenFailed("Failed to obtain access token");
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine("Error processing authentication result: " + ex.Message);
                            RaiseTokenFailed("Error processing authentication result: " + ex.Message);
                        }
                    }, null);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Authentication exception: " + ex.Message);
                    _uiContext.Post(state =>
                    {
                        statusForm.Close();

                        // Show a more user-friendly error message
                        MessageBox.Show(
                            "Authentication failed: " + ex.Message,
                            "Authentication Error",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );

                        RaiseTokenFailed("Authentication failed: " + ex.Message);
                    }, null);
                }
            });

            // Handle form closing
            statusForm.FormClosing += (sender, e) =>
            {
                // If it's not a normal close, cancel the authentication
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    Debug.WriteLine("User canceled authentication");
                    RaiseTokenFailed("Authentication was canceled by the user.");
                }
            };
        }

        private static void InitializeRefreshTokenTimer(AuthConfig config)
        {
            Debug.WriteLine("Setting up token refresh timer");

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

            var intervalMs = (tokenExpiryTime - DateTime.UtcNow).TotalMilliseconds - bufferTime.TotalMilliseconds;
            Debug.WriteLine($"Token expires at {tokenExpiryTime}, refreshing in {intervalMs / 1000} seconds");

            refreshTimer.Interval = intervalMs;
            refreshTimer.Elapsed += (sender, e) =>
            {
                Debug.WriteLine("Token refresh timer elapsed, re-authenticating");
                _uiContext.Post(state => Initialize(config), null);
            };
            refreshTimer.Start();
        }

        private static DateTime GetTokenExpiryTime()
        {
            if (OidcAuthenticatedClaimsPrincipal == null)
            {
                Debug.WriteLine("No authenticated principal, using default expiry time");
                return DateTime.UtcNow.AddHours(1);
            }

            string accessToken = null;
            foreach (var claim in OidcAuthenticatedClaimsPrincipal.Claims)
            {
                if (claim.Type == MSAConstants.AccessTokenIdentifier)
                {
                    accessToken = claim.Value;
                    break;
                }
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                Debug.WriteLine("No access token found in claims, using default expiry time");
                return DateTime.UtcNow.AddHours(1);
            }

            try
            {
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(accessToken);

                foreach (var claim in jwtToken.Claims)
                {
                    if (claim.Type == MSAConstants.TokenExpiryIdentifier)
                    {
                        long expValue;
                        if (long.TryParse(claim.Value, out expValue))
                        {
                            // Convert the Unix timestamp to DateTime
                            var expiryTime = DateTimeOffset.FromUnixTimeSeconds(expValue).UtcDateTime;
                            Debug.WriteLine("Token expiry time from claims: " + expiryTime);
                            return expiryTime;
                        }
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error parsing token expiry: " + ex.Message);
            }

            // Fallback if claim not found or could not be parsed
            Debug.WriteLine("Using default expiry time");
            return DateTime.UtcNow.AddHours(1);
        }
    }
}
