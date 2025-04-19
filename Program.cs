
using System;
using System.Diagnostics;
using System.Drawing;
using System.Text.RegularExpressions;
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
            AuthenticationManager.ClearTokenCache();
            // Subscribe to the TokenReceived event
            AuthenticationManager.TokenReceived += OnTokenReceived;

            // Subscribe to the TokenFailed event
            AuthenticationManager.TokenFailed += OnTokenFailed;

            // IMPORTANT: Update the redirect URI to match the fixed port used in FixedPortAuthService
            var config = new AuthConfig
            {
                ClientId = "rgvelod.aginsurance.intranet_phrsgvelo",
                Scope = "openid financingfunds.domain.dev.ag.intranet roles profile",
                //RedirectUri = "http://localhost:54321/callback",
                RedirectUri = "https://rgvelod.aginsurance.intranet/",
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
            Console.WriteLine("Auth Failed");
        }
    }
}
