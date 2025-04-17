
using System;
using System.Windows.Forms;
using AG.VC.Oidc.WinForms.AuthenticationHandler;
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
            AuthenticationManager.TokenReceived += (sender, args) =>
            {
                MessageBox.Show($"Token received successfully! User: {args.ClaimsPrincipal.Identity.Name}", 
                    "Authentication Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Console.WriteLine($"Access Token: {args.AccessToken}");
            };

            // Subscribe to the TokenFailed event
            AuthenticationManager.TokenFailed += (sender, reason) =>
            {
                MessageBox.Show($"Authentication failed: {reason}", 
                    "Authentication Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            //AuthenticationManager.TokenReceived += OnTokenReceived;
            //var config = new AG.VC.Oidc.WinForms.AuthenticationHandler.AuthConfig
            var config = new AuthConfig
            {
                ClientId = "rgvelod.aginsurance.intranet_phrgvelo",
                Scope = "openid financingfunds.domain.dev.ag.intranet roles profile",
                RedirectUri = "https://rgvelod.aginsurance.intranet/",
                //ClientId = "bspfsscrptd.aginsurance.intranet_phbspfsscrpt",
                //Scope = "openid jxwwdocumentapid.aginsurance.intranet roles profile",
                //RedirectUri = "https://bspfsscrptd.aginsurance.intranet/"
            };
            //AG.VC.Oidc.WinForms.AuthenticationHandler.AuthenticationManager.Initialize(config);
            AuthenticationManager.Initialize(config);

            Application.Run(new EntryPointForm());

        }
    }
}
