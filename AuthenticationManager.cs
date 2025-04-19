
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
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
        private static bool _hideBrowser = true; // Default to headless mode
        private static bool _useCustomProgressIndicator = true;
        private static Form _progressForm = null;
        private static TokenCacheService _tokenCache;
        private static AuthConfig _currentConfig;
        public static event EventHandler<TokenReceivedEventArgs> TokenReceived;
        public static event EventHandler<string> TokenFailed;

        static AuthenticationManager()
        {
            // Initialize token cache service
            _tokenCache = new TokenCacheService(message => Debug.WriteLine($"TokenCache: {message}"));
        }

        internal static void RaiseTokenReceived(string accessToken, ClaimsPrincipal claimsPrincipal)
        {
            TokenReceived?.Invoke(null, new TokenReceivedEventArgs
            {
                AccessToken = accessToken,
                ClaimsPrincipal = claimsPrincipal
            });
        }

        internal static void RaiseTokenFailed(string reason)
        {
            TokenFailed?.Invoke(null, reason);
        }

        public static void Initialize(AuthConfig config)
        {
            Debug.WriteLine("AuthenticationManager.Initialize() called");
            _currentConfig = config;
            // Ensure any existing progress form is closed and disposed
            CloseProgressForm();

            _uiContext = SynchronizationContext.Current ?? new SynchronizationContext();

            // Try to load token from cache first
            var environment = Fortis.FIBE.XN.Environment.SystemInfo.Current.SystemEnvironment;
            var cachedToken = _tokenCache.LoadToken(environment);

            if (!string.IsNullOrEmpty(cachedToken))
            {
                Debug.WriteLine("Found valid token in cache - using it instead of authenticating");
                // Create principal from cached token
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    var jwtToken = handler.ReadJwtToken(cachedToken);

                    // Build a token dictionary similar to what we'd get from authentication
                    var tokenDict = new Dictionary<string, string>
                    {
                        { MSAConstants.AccessTokenIdentifier, cachedToken }
                    };

                    // Add any claims from the token
                    foreach (var claim in jwtToken.Claims)
                    {
                        if (!tokenDict.ContainsKey(claim.Type))
                        {
                            tokenDict[claim.Type] = claim.Value;
                        }
                    }

                    // Create principal and raise the token event
                    var authService = new HeadlessMsaService(config);
                    OidcAuthenticatedClaimsPrincipal = authService.CreateClaimsPrincipal(tokenDict);

                    RaiseTokenReceived(cachedToken, OidcAuthenticatedClaimsPrincipal);

                    // Setup token refresh
                    InitializeRefreshTokenTimer(config);

                    return; // Skip authentication process
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error using cached token: {ex.Message}");
                    // Continue with authentication if there's an error with cached token
                }
            }

            if (_useCustomProgressIndicator && Application.OpenForms.Count > 0)
            {
                try
                {
                    // Create the progress form on the UI thread
                    var mainForm = Application.OpenForms[0];
                    if (mainForm != null && !mainForm.IsDisposed)
                    {
                        if (mainForm.InvokeRequired)
                        {
                            mainForm.Invoke((MethodInvoker)delegate
                            {
                                ShowProgressForm();
                            });
                        }
                        else
                        {
                            ShowProgressForm();
                        }

                        // Process Windows messages to ensure form is displayed
                        Application.DoEvents();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Error creating progress form: " + ex.Message);
                    _useCustomProgressIndicator = false;
                }
            }

            // Start authentication in background thread
            Task.Run(async () =>
            {
                try
                {
                    UpdateProgressStatus("Starting authentication process...");

                    // Only try headless authentication, no fallback
                    UpdateProgressStatus("Attempting silent authentication...");
                    var headlessService = new HeadlessMsaService(config,
                        message => UpdateProgressStatus($"Auth: {message}"));

                    Dictionary<string, string> tokenDict = null;

                    try
                    {
                        tokenDict = await headlessService.AuthenticateAsync();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Silent authentication failed: {ex.Message}");
                        UpdateProgressStatus("Authentication failed: " + ex.Message);

                        // No fallback to visible browser - simply report the error
                        await Task.Delay(1000); // Give user time to read the message
                        CloseProgressForm();

                        RaiseTokenFailed("Authentication failed: " + ex.Message);
                        return; // Exit the authentication process
                    }

                    // Process successful authentication
                    if (tokenDict != null && tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                    {
                        Debug.WriteLine("Silent authentication successful");
                        OidcAuthenticatedClaimsPrincipal = headlessService.CreateClaimsPrincipal(tokenDict);

                        // Cache the token
                        _tokenCache.SaveToken(environment, tokenDict[MSAConstants.AccessTokenIdentifier]);

                        UpdateProgressStatus("Authentication successful!");
                        await Task.Delay(500); // Brief pause to show success message

                        CloseProgressForm();
                        RaiseTokenReceived(tokenDict[MSAConstants.AccessTokenIdentifier], OidcAuthenticatedClaimsPrincipal);

                        // Setup token refresh
                        InitializeRefreshTokenTimer(config);
                        return;
                    }
                    else
                    {
                        // Handle case where we get a response but no token
                        Debug.WriteLine("Authentication failed - no token received");
                        UpdateProgressStatus("Authentication failed - no access token received");
                        await Task.Delay(1000);
                        CloseProgressForm();
                        RaiseTokenFailed("Failed to obtain access token");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Authentication exception: " + ex.Message);
                    UpdateProgressStatus("Authentication error: " + ex.Message);
                    ShowEnhancedErrorDialog("Authentication Error", ex.Message);
                    CloseProgressForm();
                    RaiseTokenFailed(ex.Message);
                    return;
                }
            });
        }

        private static void ShowProgressForm()
        {
            try
            {
                Debug.WriteLine("Creating progress form on UI thread");
                _progressForm = CreateProgressForm();
                _progressForm.Show();
                _progressForm.BringToFront();
                _progressForm.Update();
                Debug.WriteLine("Progress form created and shown");
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error creating progress form: " + ex.Message);
            }
        }

        private static Form CreateProgressForm()
        {
            var form = new Form
            {
                Text = "MSA Authentication",
                Width = 400,
                Height = 250,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MaximizeBox = false,
                MinimizeBox = false,
                ControlBox = true,
                ShowIcon = true,
                BackColor = Color.White,
                TopMost = true
            };

            // Create a container panel to help with centering
            var containerPanel = new Panel
            {
                Width = 360,
                Height = 210,
                Location = new Point(20, 10),
                BackColor = Color.White
            };
            form.Controls.Add(containerPanel);

            // Add a logo or icon at the top - centered
            var iconLabel = new Label
            {
                Text = "🔐",
                Font = new Font("Segoe UI", 36, FontStyle.Regular),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = Color.FromArgb(0, 120, 212), // Microsoft blue
            };
            // Calculate center position
            int iconX = (containerPanel.Width - iconLabel.PreferredWidth) / 2;
            iconLabel.Location = new Point(iconX, 10);
            containerPanel.Controls.Add(iconLabel);

            // Add a title - properly centered
            var titleLabel = new Label
            {
                Text = "Authenticating...",
                Font = new Font("Segoe UI Semibold", 14, FontStyle.Regular),
                AutoSize = false,
                Width = 360,
                Height = 30,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 80) // Positioned below icon
            };
            containerPanel.Controls.Add(titleLabel);

            // Add a status label - properly centered
            var statusLabel = new Label
            {
                Text = "Please wait while we authenticate your account",
                Font = new Font("Segoe UI", 9, FontStyle.Regular),
                AutoSize = false,
                Width = 360,
                Height = 20,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(0, 110), // Positioned below title
                Tag = "status" // Tag to find this label later
            };
            containerPanel.Controls.Add(statusLabel);

            // Add a nicer progress bar - properly centered
            var progressBar = new ProgressBar
            {
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 30,
                Height = 5,
                Width = 320,
                Location = new Point(20, 140) // Positioned below status
            };
            containerPanel.Controls.Add(progressBar);

            // Add a cancel button - properly centered
            var cancelButton = new Button
            {
                Text = "Cancel",
                Width = 100,
                Height = 30,
                FlatStyle = FlatStyle.System,
                UseVisualStyleBackColor = true
            };
            // Calculate center position
            int buttonX = (containerPanel.Width - cancelButton.Width) / 2;
            cancelButton.Location = new Point(buttonX, 165);
            cancelButton.Click += (sender, e) =>
            {
                form.Close();
                RaiseTokenFailed("Authentication was canceled by the user.");
            };
            containerPanel.Controls.Add(cancelButton);

            // Handle form closing
            form.FormClosing += (sender, e) =>
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    Debug.WriteLine("User canceled authentication");
                    RaiseTokenFailed("Authentication was canceled by the user.");
                }
            };

            return form;
        }

        private static void UpdateProgressStatus(string status)
        {
            Debug.WriteLine("Status update: " + status);

            if (_progressForm == null || _progressForm.IsDisposed)
            {
                Debug.WriteLine("Progress form is null or disposed when trying to update status");
                return;
            }

            try
            {
                Action updateAction = () =>
                {
                    try
                    {
                        if (!_progressForm.IsDisposed)
                        {
                            var statusControls = _progressForm.Controls.Find("status", true);
                            if (statusControls.Length > 0 && statusControls[0] is Label statusLabel)
                            {
                                statusLabel.Text = status;
                                _progressForm.Update(); // Force immediate UI update
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("Error updating status inner: " + ex.Message);
                    }
                };

                if (_progressForm.InvokeRequired)
                {
                    _progressForm.Invoke(updateAction);
                }
                else
                {
                    updateAction();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error updating status: " + ex.Message);
            }
        }

        private static void CloseProgressForm()
        {
            if (_progressForm == null)
            {
                return;
            }

            try
            {
                Form formToClose = _progressForm;
                _progressForm = null; // Clear the reference first to prevent reentrance issues

                Action closeAction = () =>
                {
                    try
                    {
                        if (!formToClose.IsDisposed)
                        {
                            Debug.WriteLine("Closing progress form");
                            formToClose.Hide();
                            formToClose.Close();
                            formToClose.Dispose();
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine("Error in close action: " + ex.Message);
                    }
                };

                if (formToClose.InvokeRequired)
                {
                    formToClose.Invoke(closeAction);
                }
                else
                {
                    closeAction();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error closing progress form: " + ex.Message);
            }
        }
        private static void ShowEnhancedErrorDialog(string title, string errorMessage)
        {
            try
            {
                // Extract relevant error information
                string errorCode = "Unknown error";
                string errorDetail = errorMessage;
                string correlationId = "N/A";

                // Parse the error message if it follows the expected format
                if (errorMessage.Contains("Error page content:"))
                {
                    // Try to extract error code
                    Match codeMatch = Regex.Match(errorMessage, @"code ([A-Za-z0-9]+)");
                    if (codeMatch.Success && codeMatch.Groups.Count > 1)
                    {
                        errorCode = codeMatch.Groups[1].Value;
                    }

                    // Try to extract correlation ID if present
                    Match correlationMatch = Regex.Match(errorMessage, @"Correlation :\s*([a-f0-9-]+)");
                    if (correlationMatch.Success && correlationMatch.Groups.Count > 1)
                    {
                        correlationId = correlationMatch.Groups[1].Value;
                    }

                    // Extract the detailed message
                    int contentIndex = errorMessage.IndexOf("Error page content:") + "Error page content:".Length;
                    if (contentIndex > 0 && contentIndex < errorMessage.Length)
                    {
                        string content = errorMessage.Substring(contentIndex).Trim();

                        // Further extract just the error message without correlation ID
                        int correlationIndex = content.IndexOf("- Session Correlation");
                        if (correlationIndex > 0)
                        {
                            content = content.Substring(0, correlationIndex).Trim();
                        }

                        errorDetail = content;
                    }
                }

                // Create a custom error form instead of using MessageBox
                using (Form errorForm = new Form())
                {
                    errorForm.Text = "Authentication Error";
                    errorForm.Size = new Size(500, 350);
                    errorForm.FormBorderStyle = FormBorderStyle.FixedDialog;
                    errorForm.StartPosition = FormStartPosition.CenterScreen;
                    errorForm.MaximizeBox = false;
                    errorForm.MinimizeBox = false;
                    errorForm.BackColor = Color.White;
                    errorForm.Font = new Font("Segoe UI", 9F);
                    errorForm.ShowIcon = true;
                    errorForm.ShowInTaskbar = true;

                    // Create the main container panel
                    Panel mainPanel = new Panel
                    {
                        Dock = DockStyle.Fill,
                        Padding = new Padding(20)
                    };
                    errorForm.Controls.Add(mainPanel);

                    // Header with warning icon
                    Label iconLabel = new Label
                    {
                        Text = "⚠️",
                        Font = new Font("Segoe UI", 36),
                        AutoSize = true,
                        ForeColor = Color.FromArgb(232, 17, 35), // Red
                        Location = new Point(20, 10)
                    };
                    mainPanel.Controls.Add(iconLabel);

                    // Title
                    Label titleLabel = new Label
                    {
                        Text = "Authentication Failed",
                        Font = new Font("Segoe UI", 16, FontStyle.Bold),
                        AutoSize = true,
                        Location = new Point(80, 20)
                    };
                    mainPanel.Controls.Add(titleLabel);

                    // Create a panel for the error details with a nice border
                    Panel detailsPanel = new Panel
                    {
                        Width = 440,
                        Height = 180,
                        Location = new Point(20, 70),
                        BorderStyle = BorderStyle.FixedSingle,
                        BackColor = Color.FromArgb(245, 245, 245) // Light gray background
                    };
                    mainPanel.Controls.Add(detailsPanel);
                    // Error message
                    Label messageLabel = new Label
                    {
                        Text = errorDetail,
                        Font = new Font("Segoe UI", 10),
                        Location = new Point(10, 10),
                        Size = new Size(420, 50),
                        ForeColor = Color.FromArgb(50, 50, 50)
                    };
                    detailsPanel.Controls.Add(messageLabel);

                    // Error code with label
                    Label codeLabel = new Label
                    {
                        Text = "Error Code:",
                        Font = new Font("Segoe UI", 9, FontStyle.Bold),
                        AutoSize = true,
                        Location = new Point(10, 70),
                        ForeColor = Color.FromArgb(50, 50, 50)
                    };
                    detailsPanel.Controls.Add(codeLabel);

                    Label codeValueLabel = new Label
                    {
                        Text = errorCode,
                        Font = new Font("Segoe UI", 9),
                        AutoSize = true,
                        Location = new Point(120, 70),
                        ForeColor = Color.FromArgb(50, 50, 50)
                    };
                    detailsPanel.Controls.Add(codeValueLabel);

                    // Correlation ID with label
                    Label correlationLabel = new Label
                    {
                        Text = "Correlation ID:",
                        Font = new Font("Segoe UI", 9, FontStyle.Bold),
                        AutoSize = true,
                        Location = new Point(10, 100),
                        ForeColor = Color.FromArgb(50, 50, 50)
                    };
                    detailsPanel.Controls.Add(correlationLabel);

                    Label correlationValueLabel = new Label
                    {
                        Text = correlationId,
                        Font = new Font("Segoe UI", 9),
                        AutoSize = true,
                        Location = new Point(120, 100),
                        Size = new Size(310, 40),
                        ForeColor = Color.FromArgb(50, 50, 50)
                    };
                    detailsPanel.Controls.Add(correlationValueLabel);

                    // Additional help text
                    Label helpLabel = new Label
                    {
                        Text = "Please contact IT support if this issue persists.",
                        Font = new Font("Segoe UI", 9, FontStyle.Italic),
                        AutoSize = true,
                        Location = new Point(10, 140),
                        ForeColor = Color.FromArgb(100, 100, 100)
                    };
                    detailsPanel.Controls.Add(helpLabel);

                    // OK button
                    Button okButton = new Button
                    {
                        Text = "OK",
                        Size = new Size(100, 35),
                        Location = new Point(360, 260),
                        BackColor = Color.FromArgb(0, 120, 212), // Blue
                        ForeColor = Color.White,
                        FlatStyle = FlatStyle.Flat,
                        Font = new Font("Segoe UI", 9, FontStyle.Bold)
                    };
                    okButton.FlatAppearance.BorderSize = 0;
                    okButton.Click += (s, e) => errorForm.Close();
                    mainPanel.Controls.Add(okButton);

                    // Try again button
                    Button retryButton = new Button
                    {
                        Text = "Try Again",
                        Size = new Size(100, 35),
                        Location = new Point(250, 260),
                        BackColor = Color.White,
                        ForeColor = Color.FromArgb(0, 120, 212),
                        FlatStyle = FlatStyle.Flat,
                        Font = new Font("Segoe UI", 9)
                    };
                    retryButton.FlatAppearance.BorderColor = Color.FromArgb(0, 120, 212);
                    retryButton.Click += (s, e) =>
                    {
                        errorForm.DialogResult = DialogResult.Retry;
                        errorForm.Close();
                    };
                    mainPanel.Controls.Add(retryButton);
                    // Show the form
                    if (Application.OpenForms.Count > 0 && Application.OpenForms[0] != null)
                    {
                        Application.OpenForms[0].Invoke((MethodInvoker)delegate {
                            DialogResult result = errorForm.ShowDialog();
                            if (result == DialogResult.Retry)
                            {
                                // Handle retry logic here if needed
                                ClearTokenCache();
                                Initialize(_currentConfig);
                            }
                        });
                    }
                    else
                    {
                        errorForm.ShowDialog();
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error showing enhanced error dialog: {ex.Message}");
                // Fall back to regular message box if something goes wrong
                MessageBox.Show(errorMessage, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
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

            try
            {
                // Get the token expiry time directly from the access_token
                var tokenExpiryTime = GetTokenExpiryTime();

                var intervalMs = (tokenExpiryTime - DateTime.UtcNow).TotalMilliseconds - bufferTime.TotalMilliseconds;

                // Ensure interval is at least 1 minute and not more than 24 hours
                intervalMs = Math.Max(60000, Math.Min(intervalMs, 86400000));

                Debug.WriteLine($"Token expires at {tokenExpiryTime}, refreshing in {intervalMs / 1000} seconds");

                refreshTimer.Interval = intervalMs;
                refreshTimer.Elapsed += (sender, e) =>
                {
                    Debug.WriteLine("Token refresh timer elapsed, re-authenticating");

                    // Initialize on UI thread if possible
                    if (Application.OpenForms.Count > 0 && Application.OpenForms[0] != null)
                    {
                        Application.OpenForms[0].Invoke((MethodInvoker)delegate {
                            Initialize(config);
                        });
                    }
                    else
                    {
                        Initialize(config);
                    }
                };
                refreshTimer.Start();
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error setting up refresh timer: " + ex.Message);
                // Set a default timer of 1 hour as fallback
                refreshTimer.Interval = 3600000;
                refreshTimer.Start();
            }
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
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(accessToken);

                foreach (var claim in jwtToken.Claims)
                {
                    if (claim.Type == MSAConstants.TokenExpiryIdentifier)
                    {
                        if (long.TryParse(claim.Value, out long expValue))
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
        /// <summary>
        /// Clears the authentication token cache and forces re-authentication on next attempt
        /// </summary>
        public static void ClearTokenCache()
        {
            Debug.WriteLine("Clearing token cache");

            // Get current environment
            string environment = Fortis.FIBE.XN.Environment.SystemInfo.Current.SystemEnvironment;

            // Clear token cache
            if (_tokenCache != null)
            {
                _tokenCache.DeleteToken(environment);
            }

            // Reset principal
            OidcAuthenticatedClaimsPrincipal = null;

            // Stop refresh timer
            if (refreshTimer != null)
            {
                refreshTimer.Stop();
                refreshTimer.Dispose();
                refreshTimer = null;
            }

            Debug.WriteLine("Token cache cleared");
        }
    }
}
