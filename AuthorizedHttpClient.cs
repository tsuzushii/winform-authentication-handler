
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    public class AuthorizedHttpClient : IDisposable
    {
        private HttpClient _client;
        private bool _disposed;

        public HttpClient Client
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException(nameof(AuthorizedHttpClient));
                }

                if (_client == null)
                {
                    _client = new HttpClient();
                    InitializeClient();
                }
                return _client;
            }
        }

        public AuthorizedHttpClient()
        {
            // Subscribe to the TokenReceived event to update the authorization header when a new token is received
            AuthenticationManager.TokenReceived += (sender, args) => UpdateAuthorizationHeader(args.AccessToken);
        }

        private void InitializeClient()
        {
            var token = AuthenticationManager.OidcAuthenticatedClaimsPrincipal?.Claims
                        .FirstOrDefault(c => c.Type == "access_token")?.Value;

            if (token != null)
            {
                UpdateAuthorizationHeader(token);
            }
        }

        private void UpdateAuthorizationHeader(string token)
        {
            if (_client != null && !string.IsNullOrEmpty(token))
            {
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _client?.Dispose();
                }

                _client = null;
                _disposed = true;
            }
        }

        ~AuthorizedHttpClient()
        {
            Dispose(false);
        }
    }
}