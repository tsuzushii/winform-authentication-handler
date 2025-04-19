
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WinForms_OAuth2ImplicitFlow_Prototype
{
    /// <summary>
    /// Provides secure token caching functionality using memory cache and protected storage
    /// </summary>
    public class TokenCacheService
    {
        private readonly IMemoryCache _memoryCache;
        private readonly Action<string> _logCallback;

        /// <summary>
        /// Initializes a new instance of the TokenCacheService
        /// </summary>
        /// <param name="logCallback">Optional callback for logging messages</param>
        public TokenCacheService(Action<string> logCallback = null)
        {
            _memoryCache = new MemoryCache(new MemoryCacheOptions());
            _logCallback = logCallback ?? ((s) => Debug.WriteLine(s));
        }

        /// <summary>
        /// Loads a token from cache for the specified environment
        /// </summary>
        /// <param name="environment">Environment identifier</param>
        /// <returns>The cached token if valid, or an empty string</returns>
        public string LoadToken(string environment)
        {
            _logCallback(string.Format("TokenCacheService - Loading token for environment: {0}", environment));

            // Try to get token from memory cache first
            string token;
            if (_memoryCache.TryGetValue(GetTokenKey(environment), out token))
            {
                _logCallback("Token found in memory cache");
                return token;
            }

            _logCallback("Token not in memory cache, checking file cache");

            // If not in memory, try to load from file
            string filePath = GetFilePath(environment);
            DataProtectionScope dataProtectionScope = DataProtectionScope.CurrentUser;

            try
            {
                if (File.Exists(filePath))
                {
                    _logCallback(string.Format("Token file exists at: {0}", filePath));
                    byte[] encryptedToken = File.ReadAllBytes(filePath);
                    byte[] tokenBytes = ProtectedData.Unprotect(encryptedToken, null, dataProtectionScope);
                    token = Encoding.UTF8.GetString(tokenBytes);

                    // Validate token expiry
                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    JwtSecurityToken jwtToken = handler.ReadJwtToken(token);
                    DateTime expirationDate = jwtToken.ValidTo;

                    if (expirationDate <= DateTime.UtcNow)
                    {
                        _logCallback("Token is expired");
                        return string.Empty;
                    }

                    // Cache the token in memory with expiration
                    _logCallback(string.Format("Token valid until: {0}", expirationDate));
                    _memoryCache.Set(GetTokenKey(environment), token, expirationDate);

                    return token;
                }
                else
                {
                    _logCallback("Token file does not exist");
                }
            }
            catch (Exception ex)
            {
                _logCallback(string.Format("Error loading token: {0}", ex.Message));
            }

            return string.Empty;
        }

        /// <summary>
        /// Saves a token to cache for the specified environment
        /// </summary>
        /// <param name="environment">Environment identifier</param>
        /// <param name="token">The token to cache</param>
        public void SaveToken(string environment, string token)
        {
            _logCallback(string.Format("TokenCacheService - Saving token for environment: {0}", environment));

            try
            {
                // Parse token to get expiration time
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = handler.ReadJwtToken(token);
                DateTime expirationDate = jwtToken.ValidTo;

                // Cache in memory
                _logCallback(string.Format("Setting token in memory cache with expiration: {0}", expirationDate));
                _memoryCache.Set(GetTokenKey(environment), token, expirationDate);

                // Cache to file
                string filePath = GetFilePath(environment);
                string directoryPath = Path.GetDirectoryName(filePath);

                if (!Directory.Exists(directoryPath))
                {
                    _logCallback(string.Format("Creating directory: {0}", directoryPath));
                    Directory.CreateDirectory(directoryPath);
                }

                // Encrypt and save token
                byte[] tokenBytes = Encoding.UTF8.GetBytes(token);
                byte[] encryptedToken = ProtectedData.Protect(tokenBytes, null, DataProtectionScope.CurrentUser);

                _logCallback(string.Format("Writing encrypted token to: {0}", filePath));
                File.WriteAllBytes(filePath, encryptedToken);
            }
            catch (Exception ex)
            {
                _logCallback(string.Format("Error saving token: {0}", ex.Message));
            }
        }

        /// <summary>
        /// Gets the key used for in-memory caching
        /// </summary>
        private static string GetTokenKey(string environment)
        {
            return string.Format("msaToken_{0}", environment.ToUpper());
        }

        /// <summary>
        /// Gets the file path for token storage
        /// </summary>
        private static string GetFilePath(string environment)
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                ".msaauth",
                environment.ToLower(),
                "token.dat");
        }

        /// <summary>
        /// Deletes the cached token for the specified environment
        /// </summary>
        /// <param name="environment">Environment identifier</param>
        /// <returns>True if cache was successfully deleted, false otherwise</returns>
        public bool DeleteToken(string environment)
        {
            _logCallback(string.Format("TokenCacheService - Deleting token for environment: {0}", environment));

            bool success = true;

            try
            {
                // Remove from memory cache
                _memoryCache.Remove(GetTokenKey(environment));

                // Delete token file if it exists
                string filePath = GetFilePath(environment);
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    _logCallback(string.Format("Deleted token file: {0}", filePath));
                }
            }
            catch (Exception ex)
            {
                _logCallback(string.Format("Error deleting token: {0}", ex.Message));
                success = false;
            }

            return success;
        }
    }
}
