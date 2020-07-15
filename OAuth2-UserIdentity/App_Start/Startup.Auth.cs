using System;
using System.Configuration;
using System.Globalization;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using OAuth2_UserIdentity.Models;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using System.Web.UI;
using System.Runtime.Caching;
using Microsoft.Owin.Security;

namespace OAuth2_UserIdentity
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864

        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The App Key is a credential used to authenticate the application to Azure AD.  Azure AD supports password and certificate credentials.
        // The Metadata Address is used by the application to retrieve the signing keys used by Azure AD.
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Authority is the sign-in URL of the tenant.
        // The Post Logout Redirect Uri is the URL where the user will be redirected after they sign out.
        //
        
        public static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        public static string clientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        public static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        public static string graphUserUrl = ConfigurationManager.AppSettings["ida:GraphUserUrl"];
        //private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        //public static readonly string Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
        public static readonly string Authority = $"{aadInstance}{tenant}/v2.0";

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        public static string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];

        public static string redirectUrl = "https://localhost:44323/";

        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: clientId,
            //    clientSecret: clientSecret);

            var msalClient = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithClientSecret(clientSecret)
                .WithAuthority(Authority)
                .WithRedirectUri(redirectUrl)
                .Build();

            var msalCache = new MSALPerUserMemoryTokenCache(msalClient.UserTokenCache);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions()
            {
                // todo: check authority --> do we need multitenant? or should we be single-tenant
                AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
                Authority = Authority,
                ClientId = clientId,
                ClientSecret = clientSecret,
                //ResponseType = "code",
                MetadataAddress = $"{Authority}/.well-known/openid-configuration",
                Scope = "openid profile offline_access User.Read",
                RedirectUri = redirectUrl,
                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    SecurityTokenValidated = x =>
                    {
                        // you can add your own custom or additional claims here to the user's principal 
                        
                        return Task.CompletedTask;
                    },
                    AuthorizationCodeReceived = async x =>
                    {
                        // redeeming authorization_code & storing it in a cache
                        var authCodeResult = msalClient.AcquireTokenByAuthorizationCode(new[] { "User.Read" }, x.Code);
                        var result = await authCodeResult.ExecuteAsync();
                        return;
                    }
                }
            });

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});
        }
    }

    /// <summary>
    /// An implementation of token cache for both Confidential and Public clients backed by MemoryCache.
    /// MemoryCache is useful in Api scenarios where there is no HttpContext to cache data.
    /// </summary>
    /// <seealso cref="https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/token-cache-serialization"/>
    public class MSALPerUserMemoryTokenCache
    {
        /// <summary>
        /// The backing MemoryCache instance
        /// </summary>
        internal readonly MemoryCache memoryCache = MemoryCache.Default;

        /// <summary>
        /// The duration till the tokens are kept in memory cache. In production, a higher value, upto 90 days is recommended.
        /// </summary>
        private readonly DateTimeOffset cacheDuration = DateTimeOffset.Now.AddHours(48);

        /// <summary>
        /// Initializes a new instance of the <see cref="MSALPerUserMemoryTokenCache"/> class.
        /// </summary>
        /// <param name="tokenCache">The client's instance of the token cache.</param>
        public MSALPerUserMemoryTokenCache(ITokenCache tokenCache)
        {
            Initialize(tokenCache);
        }

        /// <summary>Initializes the cache instance</summary>
        /// <param name="tokenCache">The ITokenCache passed through the constructor</param>
        /// <param name="user">The signed-in user for whom the cache needs to be established..</param>
        private void Initialize(ITokenCache tokenCache)
        {
            tokenCache.SetBeforeAccess(UserTokenCacheBeforeAccessNotification);
            tokenCache.SetAfterAccess(UserTokenCacheAfterAccessNotification);
            tokenCache.SetBeforeWrite(UserTokenCacheBeforeWriteNotification);
        }

        /// <summary>
        /// Triggered right after MSAL accessed the cache.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void UserTokenCacheAfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (args.HasStateChanged)
            {
                string cacheKey = args.SuggestedCacheKey ?? args.Account?.HomeAccountId?.Identifier;
                if (args.HasTokens)
                {
                    if (string.IsNullOrWhiteSpace(cacheKey))
                        return;

                    // Ideally, methods that load and persist should be thread safe.MemoryCache.Get() is thread safe.
                    memoryCache.Set(cacheKey, args.TokenCache.SerializeMsalV3(), cacheDuration);
                }
                else
                {
                    memoryCache.Remove(cacheKey);
                }
            }
        }

        /// <summary>
        /// Triggered right before MSAL needs to access the cache. Reload the cache from the persistence store in case it changed since the last access.
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void UserTokenCacheBeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            string cacheKey = args.SuggestedCacheKey ?? args.Account?.HomeAccountId?.Identifier;
            if (string.IsNullOrEmpty(cacheKey))
            {
                return;
            }

            byte[] tokenCacheBytes = (byte[])memoryCache.Get(cacheKey);
            args.TokenCache.DeserializeMsalV3(tokenCacheBytes, shouldClearExistingCache: true);
        }

        /// <summary>
        /// if you want to ensure that no concurrent write take place, use this notification to place a lock on the entry
        /// </summary>
        /// <param name="args">Contains parameters used by the MSAL call accessing the cache.</param>
        private void UserTokenCacheBeforeWriteNotification(TokenCacheNotificationArgs args)
        {
            // Since we are using a MemoryCache ,whose methods are threads safe, we need not to do anything in this handler.
        }
    }
}