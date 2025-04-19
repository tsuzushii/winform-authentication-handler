
using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        private static CancellationTokenSource _authCancellationTokenSource;
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

            // Create a new cancellation token source
            if (_authCancellationTokenSource != null)
            {
                _authCancellationTokenSource.Dispose();
            }
            _authCancellationTokenSource = new CancellationTokenSource();

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
                    // Get cancellation token
                    var cancellationToken = _authCancellationTokenSource.Token;

                    UpdateProgressStatus("Starting authentication process...");

                    // Only try headless authentication, no fallback
                    UpdateProgressStatus("Attempting silent authentication...");
                    var headlessService = new HeadlessMsaService(config,
                        message => UpdateProgressStatus($"Auth: {message}"));

                    Dictionary<string, string> tokenDict = null;

                    // Check for cancellation
                    if (cancellationToken.IsCancellationRequested)
                    {
                        Debug.WriteLine("Authentication canceled before starting authentication");
                        return;
                    }

                    try
                    {
                        // Pass cancellation token to authentication method
                        tokenDict = await headlessService.AuthenticateAsync(cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        Debug.WriteLine("Authentication was canceled by user");
                        return;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Silent authentication failed: {ex.Message}");

                        // Update UI to show error instead of closing form
                        UpdateProgressStatus("Authentication failed: " + ex.Message, false, true);

                        // Raise the token failed event
                        RaiseTokenFailed("Authentication failed: " + ex.Message);

                        return; // Exit the authentication process but leave error form visible
                    }

                    // Check for cancellation again
                    if (cancellationToken.IsCancellationRequested)
                    {
                        Debug.WriteLine("Authentication canceled after authentication but before processing");
                        return;
                    }

                    // Process successful authentication
                    if (tokenDict != null && tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                    {
                        ProcessSuccessfulAuthentication(headlessService, tokenDict, environment);
                    }
                    else
                    {
                        // Handle case where we get a response but no token
                        Debug.WriteLine("Authentication failed - no token received");
                        UpdateProgressStatus("Authentication failed - no access token received", false, true);
                        RaiseTokenFailed("Failed to obtain access token");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Authentication exception: " + ex.Message);
                    UpdateProgressStatus("Authentication error: " + ex.Message, false, true);
                    RaiseTokenFailed(ex.Message);
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
                Width = 380,
                Height = 280, // Normal height when no error
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MaximizeBox = false,
                MinimizeBox = false,
                ControlBox = true,
                ShowIcon = true,
                BackColor = Color.White,
                TopMost = true,
                Padding = new Padding(0)
            };

            // Create a container panel with tighter margins
            var containerPanel = new Panel
            {
                Width = 360,
                Height = 260,
                Location = new Point(10, 10),
                BackColor = Color.White,
                Name = "containerPanel"
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
                Tag = "iconLabel",
                Name = "iconLabel"
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
                Location = new Point(0, 80), // Positioned below icon
                Tag = "titleLabel",
                Name = "titleLabel"
            };
            containerPanel.Controls.Add(titleLabel);

            // Add a status label - properly centered vertically between title and progress bar
            var statusLabel = new Label
            {
                Text = "Please wait while we authenticate your account",
                Font = new Font("Segoe UI", 9, FontStyle.Regular),
                AutoSize = false,
                Width = 360,
                Height = 30, // Made taller to accommodate text
                TextAlign = ContentAlignment.MiddleCenter, // Middle alignment for vertical centering
                Location = new Point(0, 120), // Better vertical position between title and progress bar
                Tag = "status",
                Name = "statusLabel"
            };
            containerPanel.Controls.Add(statusLabel);

            // Add a RichTextBox for log display (initially hidden)
            var logView = new RichTextBox
            {
                ReadOnly = true,
                BackColor = Color.Black,
                ForeColor = Color.White,
                Font = new Font("Consolas", 8.5F),
                Location = new Point(20, 120), // Same position as status label
                Size = new Size(320, 0), // Zero height initially
                BorderStyle = BorderStyle.FixedSingle,
                Tag = "logView",
                Name = "logView",
                Visible = false, // Initially hidden
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            containerPanel.Controls.Add(logView);

            // Initialize the log with some basic information
            AddLogEntry(logView, "INFO", "Authentication process started");
            AddLogEntry(logView, "INFO", "Using headless MS authentication");
            AddLogEntry(logView, "DEBUG", "Contacting authentication service...");

            // Add a nicer progress bar - properly centered
            var progressBar = new ProgressBar
            {
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 30,
                Height = 5,
                Width = 320,
                Location = new Point(20, 170), // Positioned below status
                Tag = "progressBar",
                Name = "progressBar"
            };
            containerPanel.Controls.Add(progressBar);

            // Add a cancel button - right below the progress bar with minimal gap
            var cancelButton = new Button
            {
                Text = "Cancel",
                Width = 100,
                Height = 30,
                FlatStyle = FlatStyle.System,
                UseVisualStyleBackColor = true,
                Tag = "cancelButton",
                Name = "cancelButton"
            };
            // Calculate center position
            int buttonX = (containerPanel.Width - cancelButton.Width) / 2;
            cancelButton.Location = new Point(buttonX, 190); // Minimal gap below progress bar
            cancelButton.Click += (sender, e) =>
            {
                // Cancel the authentication process
                if (_authCancellationTokenSource != null && !_authCancellationTokenSource.IsCancellationRequested)
                {
                    Debug.WriteLine("Cancellation requested by user button click");
                    _authCancellationTokenSource.Cancel();
                }

                form.Close();
                // Let FormClosing event handle the cancellation notification
            };
            containerPanel.Controls.Add(cancelButton);

            // Handle form closing
            form.FormClosing += (sender, e) =>
            {
                if (e.CloseReason == CloseReason.UserClosing)
                {
                    // Cancel the authentication process if it's still running
                    if (_authCancellationTokenSource != null && !_authCancellationTokenSource.IsCancellationRequested)
                    {
                        Debug.WriteLine("Cancellation requested by form closing");
                        _authCancellationTokenSource.Cancel();
                    }

                    // Only trigger user canceled if the tag is true (default) or not set
                    bool shouldTriggerCanceled = form.Tag == null || (bool)form.Tag;

                    if (shouldTriggerCanceled)
                    {
                        Debug.WriteLine("User canceled authentication");
                        RaiseTokenFailed("Authentication was canceled by the user.");
                    }
                    else
                    {
                        Debug.WriteLine("Form closing without triggering cancellation");
                    }
                }
            };

            return form;
        }


        // Helper method to show a detailed error log window


        private static void UpdateProgressStatus(string status, bool isSuccess = false, bool isError = false)
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
                            // Get the container panel
                            var containerPanel = _progressForm.Controls.OfType<Panel>().FirstOrDefault();
                            if (containerPanel == null)
                            {
                                Debug.WriteLine("Container panel not found");
                                return;
                            }

                            // Get references to controls
                            var statusLabel = containerPanel.Controls.OfType<Label>()
                                .FirstOrDefault(l => l.Tag?.ToString() == "status");

                            var iconLabel = containerPanel.Controls.OfType<Label>()
                                .FirstOrDefault(l => l.Tag?.ToString() == "iconLabel");

                            var titleLabel = containerPanel.Controls.OfType<Label>()
                                .FirstOrDefault(l => l.Tag?.ToString() == "titleLabel");

                            var progressBar = containerPanel.Controls.OfType<ProgressBar>()
                                .FirstOrDefault(p => p.Tag?.ToString() == "progressBar");

                            var cancelButton = containerPanel.Controls.OfType<Button>()
                                .FirstOrDefault(b => b.Tag?.ToString() == "cancelButton");

                            var logView = containerPanel.Controls.OfType<RichTextBox>()
                                .FirstOrDefault(r => r.Tag?.ToString() == "logView");

                            // Always log the message to the RichTextBox
                            if (logView != null)
                            {
                                string level = isError ? "ERROR" : isSuccess ? "SUCCESS" : "INFO";
                                AddLogEntry(logView, level, status);
                            }

                            // Update icon and title based on state
                            if (isSuccess || isError)
                            {
                                if (iconLabel != null)
                                {
                                    iconLabel.Text = isSuccess ? "✅" : isError ? "❌" : "🔐";
                                    iconLabel.ForeColor = isSuccess ? Color.ForestGreen :
                                                    isError ? Color.Crimson :
                                                    Color.FromArgb(0, 120, 212);
                                }

                                if (titleLabel != null)
                                {
                                    titleLabel.Text = isSuccess ? "Authentication Successful" :
                                                isError ? "Authentication Failed" : "Authenticating...";
                                }

                                // For error state, show log view and resize form
                                if (isError)
                                {
                                    // Update form for error display
                                    if (statusLabel != null)
                                        statusLabel.Visible = false; // Hide status label

                                    if (progressBar != null)
                                        progressBar.Visible = false; // Hide progress bar

                                    // Show log view
                                    if (logView != null)
                                    {
                                        logView.Size = new Size(320, 120); // Expand to full size
                                        logView.Location = new Point(20, 120); // Position below title
                                        logView.Visible = true; // Make visible
                                        logView.ScrollToCaret(); // Auto-scroll to latest entry
                                    }

                                    // Move button below log view
                                    if (cancelButton != null)
                                    {
                                        cancelButton.Text = "Close";
                                        cancelButton.Location = new Point(cancelButton.Location.X, 250);
                                    }

                                    // Resize form to fit everything
                                    if (_progressForm.Height < 350)
                                    {
                                        _progressForm.Height = 350;
                                        containerPanel.Height = 330;
                                    }
                                }
                                else if (isSuccess)
                                {
                                    // For success state, show checkmark and completed progress
                                    if (progressBar != null)
                                    {
                                        progressBar.Style = ProgressBarStyle.Continuous;
                                        progressBar.Value = 100;
                                    }

                                    if (statusLabel != null)
                                    {
                                        statusLabel.Text = "Authentication successful!";
                                    }
                                }
                            }
                            else
                            {
                                // Normal status update during authentication
                                if (statusLabel != null)
                                {
                                    statusLabel.Text = status;
                                }
                            }

                            _progressForm.Update(); // Force immediate UI update
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


        // Helper method to add debug log entries directly
        private static void AddLogEntry(RichTextBox logView, string level, string message)
        {
            if (logView == null || logView.IsDisposed)
                return;

            Color levelColor = Color.White;
            switch (level)
            {
                case "ERROR":
                    levelColor = Color.Red;
                    break;
                case "WARNING":
                    levelColor = Color.Yellow;
                    break;
                case "INFO":
                    levelColor = Color.LightGreen;
                    break;
                case "DEBUG":
                    levelColor = Color.LightBlue;
                    break;
            }

            try
            {
                Action action = () =>
                {
                    // Add timestamp (gray)
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    logView.SelectionStart = logView.TextLength;
                    logView.SelectionLength = 0;
                    logView.SelectionColor = Color.Gray;
                    logView.AppendText(timestamp + " ");

                    // Add level indicator (with appropriate color)
                    logView.SelectionStart = logView.TextLength;
                    logView.SelectionLength = 0;
                    logView.SelectionColor = levelColor;
                    logView.AppendText("[" + level + "] ");

                    // Add message (white)
                    logView.SelectionStart = logView.TextLength;
                    logView.SelectionLength = 0;
                    logView.SelectionColor = Color.White;
                    logView.AppendText(message + Environment.NewLine);

                    // Scroll to the end
                    logView.ScrollToCaret();
                };

                if (logView.InvokeRequired)
                    logView.Invoke(action);
                else
                    action();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error adding log entry: {ex.Message}");
            }
        }

        private static void CloseProgressForm(bool triggerUserCanceled = true)
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

                            // Set a flag to control whether FormClosing should trigger user canceled logic
                            formToClose.Tag = triggerUserCanceled;

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

        private static void ProcessSuccessfulAuthentication(HeadlessMsaService authService, Dictionary<string, string> tokenDict, string environment)
        {
            Debug.WriteLine("Silent authentication successful");
            OidcAuthenticatedClaimsPrincipal = authService.CreateClaimsPrincipal(tokenDict);

            // Cache the token
            _tokenCache.SaveToken(environment, tokenDict[MSAConstants.AccessTokenIdentifier]);

            UpdateProgressStatus("Authentication successful!", true); // Added success parameter

            // Setup token refresh
            InitializeRefreshTokenTimer(_currentConfig);

            // Raise token received event
            RaiseTokenReceived(tokenDict[MSAConstants.AccessTokenIdentifier], OidcAuthenticatedClaimsPrincipal);

            // Delay to show success message, then close form
            Task.Run(async () => {
                await Task.Delay(1500); // Brief pause to show success message
                CloseProgressForm(false); // false means don't trigger "user canceled"
            });
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
