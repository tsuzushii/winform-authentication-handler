using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class AuthorizedHttpClient
    {
        private HttpClient _client;

        public HttpClient Client
        {
            get
            {
                if (_client == null)
                {
                    _client = new HttpClient();
                    InitializeClient();
                }
                return _client;
            }
        }

        private void InitializeClient()
        {
            var token = AuthenticationManager.OidcAuthenticatedClaimsPrincipal.Claims
                        .FirstOrDefault(c => c.Type == "access_token")?.Value;
            if (token != null)
            {
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }
    }


}
