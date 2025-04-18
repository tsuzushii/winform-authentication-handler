
using System;
using System.Collections.Generic;
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
        private static bool _useCustomProgressIndicator = true; // Set to true to use our custom progress indicator
        private static Form _progressForm = null; // Keep a static reference to the progress form

        public static event EventHandler<TokenReceivedEventArgs> TokenReceived;
        public static event EventHandler<string> TokenFailed;

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

            // Ensure any existing progress form is closed and disposed
            CloseProgressForm();

            _uiContext = SynchronizationContext.Current ?? new SynchronizationContext();

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
            else
            {
                Debug.WriteLine("Not showing progress indicator: UseCustomIndicator=" + _useCustomProgressIndicator +
                               ", OpenForms.Count=" + Application.OpenForms.Count);
            }

            // Start authentication in background thread
            Task.Run(async () =>
            {
                try
                {
                    UpdateProgressStatus("Starting authentication process...");

                    // Create and use the fixed port authentication service
                    var authService = new FixedPortAuthService(
                        config,
                        UpdateProgressStatus,
                        _hideBrowser);

                    var tokenDict = await authService.AuthenticateAsync();

                    // Process successful authentication
                    if (tokenDict != null && tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                    {
                        Debug.WriteLine("Authentication successful, creating claims principal");
                        OidcAuthenticatedClaimsPrincipal = authService.CreateClaimsPrincipal(tokenDict);

                        // Update status before closing
                        UpdateProgressStatus("Authentication successful!");

                        // Close the progress form
                        CloseProgressForm();

                        RaiseTokenReceived(tokenDict[MSAConstants.AccessTokenIdentifier], OidcAuthenticatedClaimsPrincipal);

                        // Setup token refresh
                        InitializeRefreshTokenTimer(config);
                    }
                    else
                    {
                        Debug.WriteLine("Authentication failed - no token dictionary or no access token");
                        UpdateProgressStatus("Authentication failed - no access token");

                        // Give UI time to update
                        await Task.Delay(1000);

                        CloseProgressForm();
                        RaiseTokenFailed("Failed to obtain access token");
                        ShowErrorMessage("Authentication Failed", "Failed to obtain access token");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Authentication exception: " + ex.Message);
                    UpdateProgressStatus("Authentication error: " + ex.Message);

                    // Give UI time to update
                    await Task.Delay(1000);

                    CloseProgressForm();
                    RaiseTokenFailed("Authentication failed: " + ex.Message);
                    ShowErrorMessage("Authentication Error", "Authentication failed: " + ex.Message);
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

        private static void ShowErrorMessage(string title, string message)
        {
            try
            {
                if (Application.OpenForms.Count > 0 && Application.OpenForms[0] != null)
                {
                    Application.OpenForms[0].Invoke((MethodInvoker)delegate {
                        MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    });
                }
                else
                {
                    Debug.WriteLine($"ERROR - {title}: {message}");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error showing message: {ex.Message}");
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
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
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
    }
}
