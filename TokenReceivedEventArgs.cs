using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class TokenReceivedEventArgs : EventArgs
    {
        public string AccessToken { get; set; }
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
    }

}
