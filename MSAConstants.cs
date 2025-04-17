using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class MSAConstants
    {
        public const int ExpiryBufferTimeInMinutes = 5;
        public const string AuthorizeUrlDev = "https://aulogind.aginsurance.intranet/PIAULOGIN/msa-idp/connect/authorize";
        public const string AuthorizeUrlQual = "https://auloginq.aginsurance.intranet/PIAULOGIN/msa-idp/connect/authorize";
        public const string AuthorizeUrlAcc = "https://aulogina.aginsurance.intranet/PIAULOGIN/msa-idp/connect/authorize";
        public const string AuthorizeUrlProd = "https://auloginp.aginsurance.intranet/PIAULOGIN/msa-idp/connect/authorize";

        public const string LocalEnvironmentIdentifier = "T000";
        public const string DevEnvironmentIdentifier = "D000";
        public const string QualEnvironmentIdentifier = "Q000";
        public const string AccEnvironmentIdentifier = "A000";
        public const string ProdEnvironmentIdentifier = "P000";

        public const string IdTokenIdentifier = "id_token";
        public const string AccessTokenIdentifier = "access_token";
        public const string AuthenticationTypeIdentifier = "OpenIDConnect";
        public const string NameIdentifier = "name";
        public const string GivenNameIdentifier = "given_name";
        public const string FamilyNameIdentifier = "family_name";
        public const string TokenExpiryIdentifier = "exp";
        public const string FailedAuthorizationPathIdentifier = "Sorry";

    }
}
