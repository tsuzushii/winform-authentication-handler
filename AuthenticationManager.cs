
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
                                    Debug.WriteLine("Error creating progress form from invoke: " + ex.Message);
                                }
                            });
                        }
                        else
                        {
                            Debug.WriteLine("Creating progress form directly");
                            _progressForm = CreateProgressForm();
                            _progressForm.Show();
                            _progressForm.BringToFront();
                            _progressForm.Update();
                            Debug.WriteLine("Progress form created and shown directly");
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
                        (status) => UpdateProgressStatus(status),
                        _hideBrowser);

                    var tokenDict = await authService.AuthenticateAsync();

                    // Process successful authentication
                    if (tokenDict != null && tokenDict.ContainsKey(MSAConstants.AccessTokenIdentifier))
                    {
                        Debug.WriteLine("Authentication successful, creating claims principal");
                        OidcAuthenticatedClaimsPrincipal = authService.CreateClaimsPrincipal(tokenDict);

                        // Update status before closing
                        UpdateProgressStatus("Authentication successful!");

                        // Give UI time to update
                        await Task.Delay(1000);

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

        private static Form CreateProgressForm()
        {
            var form = new Form
            {
                Text = "Authentication",
                Width = 400,
                Height = 220,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterScreen,
                MaximizeBox = false,
                MinimizeBox = false,
                ControlBox = true,
                ShowIcon = true,
                BackColor = Color.White,
                TopMost = true // Make sure it stays on top
            };

            // Add a logo or icon at the top
            var iconLabel = new Label
            {
                Text = "🔐",
                Font = new Font("Segoe UI", 36, FontStyle.Regular),
                AutoSize = true,
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = Color.FromArgb(0, 120, 212), // Microsoft blue
                Location = new Point(175, 20)
            };
            form.Controls.Add(iconLabel);

            // Add a title
            var titleLabel = new Label
            {
                Text = "Authenticating...",
                Font = new Font("Segoe UI Semibold", 14, FontStyle.Regular),
                AutoSize = false,
                Width = 360,
                Height = 30,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(20, 80)
            };
            form.Controls.Add(titleLabel);

            // Add a status label
            var statusLabel = new Label
            {
                Text = "Please wait while we authenticate your account",
                Font = new Font("Segoe UI", 9, FontStyle.Regular),
                AutoSize = false,
                Width = 360,
                Height = 20,
                TextAlign = ContentAlignment.MiddleCenter,
                Location = new Point(20, 110),
                Tag = "status" // We'll use this tag to find the label later
            };
            form.Controls.Add(statusLabel);

            // Add a nicer progress bar
            var progressBar = new ProgressBar
            {
                Style = ProgressBarStyle.Marquee,
                MarqueeAnimationSpeed = 30,
                Height = 5,
                Width = 360,
                Location = new Point(20, 140)
            };
            form.Controls.Add(progressBar);

            // Add a cancel button
            var cancelButton = new Button
            {
                Text = "Cancel",
                Width = 100,
                Height = 30,
                Location = new Point(150, 160),
                UseVisualStyleBackColor = true
            };
            cancelButton.Click += (sender, e) =>
            {
                form.Close();
                RaiseTokenFailed("Authentication was canceled by the user.");
            };
            form.Controls.Add(cancelButton);

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

            if (_progressForm != null)
            {
                try
                {
                    if (_progressForm.InvokeRequired)
                    {
                        _progressForm.Invoke((MethodInvoker)delegate {
                            try
                            {
                                if (!_progressForm.IsDisposed)
                                {
                                    var statusLabel = _progressForm.Controls.Find("status", true);
                                    if (statusLabel.Length > 0 && statusLabel[0] is Label)
                                    {
                                        ((Label)statusLabel[0]).Text = status;
                                        _progressForm.Update(); // Force immediate UI update
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine("Error updating status inner: " + ex.Message);
                            }
                        });
                    }
                    else if (!_progressForm.IsDisposed)
                    {
                        var statusLabel = _progressForm.Controls.Find("status", true);
                        if (statusLabel.Length > 0 && statusLabel[0] is Label)
                        {
                            ((Label)statusLabel[0]).Text = status;
                            _progressForm.Update(); // Force immediate UI update
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Error updating status: " + ex.Message);
                }
            }
            else
            {
                Debug.WriteLine("Progress form is null when trying to update status");
            }
        }

        private static void CloseProgressForm()
        {
            if (_progressForm != null)
            {
                try
                {
                    Form formToClose = _progressForm;
                    _progressForm = null; // Clear the reference first

                    if (formToClose.InvokeRequired)
                    {
                        formToClose.Invoke((MethodInvoker)delegate {
                            try
                            {
                                if (!formToClose.IsDisposed)
                                {
                                    Debug.WriteLine("Closing progress form via invoke");
                                    formToClose.Hide();
                                    formToClose.Close();
                                    formToClose.Dispose();
                                }
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine("Error closing progress form inner: " + ex.Message);
                            }
                        });
                    }
                    else if (!formToClose.IsDisposed)
                    {
                        Debug.WriteLine("Closing progress form directly");
                        formToClose.Hide();
                        formToClose.Close();
                        formToClose.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Error closing progress form: " + ex.Message);
                }
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
            // Rest of the method stays the same...
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
            // Method implementation remains the same...
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
