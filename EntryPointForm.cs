using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public partial class EntryPointForm : Form
    {
        private readonly DocumentAPIService _documentAPIService;
        public EntryPointForm()
        {
            InitializeComponent();
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Load += (sender, args) => this.Activate();
            _documentAPIService = new DocumentAPIService();
        }
        private void btnShowUserInfo_Click(object sender, EventArgs e)
        {
            var claimsPrincipal = AuthenticationManager.OidcAuthenticatedClaimsPrincipal;

            if (claimsPrincipal?.Identity?.IsAuthenticated == true)
            {
                var accessToken = claimsPrincipal.Claims.FirstOrDefault(c => c.Type == "access_token")?.Value;
                var userName = claimsPrincipal.Identity.Name;

                MessageBox.Show($"User: {userName}\nAccess Token: {accessToken}",
                    "User Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("User is not authenticated.",
                    "Authentication Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        private async void button1_Click(object sender, EventArgs e)
        {
            var thread = System.Threading.Thread.CurrentPrincipal;
            string result = await new DocumentAPIService().SearchFinancingFunds(100, 0, new List<string> { "41032", "44030" }, null, null, null);
        }

        private async void button2_Click(object sender, EventArgs e)
        {
            try
            {
                // Assuming GetERmsDocuments is a method in the same class or accessible
                string response = await _documentAPIService.GetErmsDocuments("NCDMGERGER00", "EP000KTestSabrina");

                if (!string.IsNullOrEmpty(response))
                {
                    // Do something with the response, e.g., display it in a MessageBox
                    MessageBox.Show(response);
                }
                else
                {
                    // Handle error
                    MessageBox.Show("Failed to retrieve documents.");
                }
            }
            catch (Exception)
            {

                throw;
            }

        }
    }
}
