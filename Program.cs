
using System;
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Create and show the main form first - this is important for UI thread handling
            var mainForm = new EntryPointForm();
            mainForm.Show();

            // Subscribe to the TokenReceived event
            AuthenticationManager.TokenReceived += OnTokenReceived;

            // Subscribe to the TokenFailed event
            AuthenticationManager.TokenFailed += OnTokenFailed;

            // IMPORTANT: Update the redirect URI to match the fixed port used in FixedPortAuthService
            var config = new AuthConfig
            {
                ClientId = "rgvelod.aginsurance.intranet_phrgvelo",
                Scope = "openid financingfunds.domain.dev.ag.intranet roles profile",
                // Use a fixed port redirect URI that must be whitelisted with your IDP
                RedirectUri = "http://localhost:54321/callback",
            };

            // Initialize the authentication manager
            AuthenticationManager.Initialize(config);

            // Run the application with the main form
            Application.Run(mainForm);
        }

        private static void OnTokenReceived(object sender, TokenReceivedEventArgs args)
        {
            // Don't show a message box here - it's duplicative and can cause issues
            Console.WriteLine("Authentication successful: " + args.ClaimsPrincipal.Identity.Name);
        }

        private static void OnTokenFailed(object sender, string reason)
        {
            // Only show error if it's not a user cancellation
            if (!reason.Contains("canceled by the user"))
            {
                MessageBox.Show(
                    "Authentication failed: " + reason,
                    "Authentication Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }
    }
}
