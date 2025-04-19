
using System.Windows.Forms;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    /// <summary>
    /// MSA Configuration settings for OIDC authentication.
    /// </summary>
    public class AuthConfig
    {
        /// <summary>
        /// Gets or sets the client ID.
        /// </summary>
        /// <value>
        /// MSA client_id.
        /// </value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the scope of the access request.
        /// </summary>
        /// <value>
        /// The scope parameter defines the access level that the application is requesting.
        /// </value>
        public string Scope { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI.
        /// </summary>
        /// <value>
        /// The URI to which MSA will redirect the embeded user-agent after authorization has been granted by the user.
        /// Since this is a FAT client, the navigation is captured before the redirect_uri network request resolves.
        /// To minimize the risk of network resolution, it is recommended to opt for a redirect_uri that doesn't exist.
        /// </value>
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets whether to show any UI during authentication.
        /// If false, authentication happens completely in the background with no progress dialog.
        /// The application should handle TokenReceived and TokenFailed events.
        /// </summary>
        public bool ShowAuthenticationUI { get; set; } = true;
    }
}
