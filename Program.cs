
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

            // Run the main form
            Application.Run(new EntryPointForm());
        }

        private static void OnTokenReceived(object sender, TokenReceivedEventArgs args)
        {
            MessageBox.Show(
                "Authentication successful!\nUser: " + args.ClaimsPrincipal.Identity.Name,
                "Authentication Success",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }

        private static void OnTokenFailed(object sender, string reason)
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
