//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

// The following using statements were added for this sample.
using System.Net.Http;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.IdentityModel.Selectors;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.Globalization;
using System.Configuration;
using Microsoft.IdentityModel.Protocols;

namespace TodoListService_ManualJwt
{
    public class WebApiApplication : HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            GlobalConfiguration.Configuration.MessageHandlers.Add(new TokenValidationHandler());
        }
    }

    internal class TokenValidationHandler : DelegatingHandler
    {
        //
        // The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        // The Tenant is the name of the tenant in which this application is registered.
        // The Authority is the sign-in URL of the tenant.
        // The Audience is the value the service expects to see in tokens that are addressed to it.
        //
        private static readonly string AadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static readonly string Tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static readonly string Audience = ConfigurationManager.AppSettings["ida:Audience"];
        private readonly string _authority = string.Format(CultureInfo.InvariantCulture, AadInstance, Tenant);

        private static string _issuer = string.Empty;
        private static IList<SecurityToken> _signingTokens;
        private static DateTime _stsMetadataRetrievalTime = DateTime.MinValue;
        private const string ScopeClaimType = "http://schemas.microsoft.com/identity/claims/scope";

        //
        // SendAsync checks that incoming requests have a valid access token, and sets the current user identity using that access token.
        //
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Get the jwt bearer token from the authorization header
            string jwtToken = null;
            var authHeader = request.Headers.Authorization;
            if (authHeader != null)
            {
                jwtToken = authHeader.Parameter;
            }

            if (jwtToken == null)
            {
                var response = BuildResponseErrorMessage(HttpStatusCode.Unauthorized);
                return response;
            }

            string issuer;
            ICollection<SecurityToken> signingTokens;

            try
            {
                // The issuer and signingTokens are cached for 24 hours. They are updated if any of the conditions in the if condition is true.            
                if (DateTime.UtcNow.Subtract(_stsMetadataRetrievalTime).TotalHours > 24
                    || string.IsNullOrEmpty(_issuer)
                    || _signingTokens == null)
                {
                    // Get tenant information that's used to validate incoming jwt tokens
                    string stsDiscoveryEndpoint = $"{_authority}/.well-known/openid-configuration";
                    var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint);
                    var config = await configManager.GetConfigurationAsync(cancellationToken);
                    _issuer = config.Issuer;
                    _signingTokens = config.SigningTokens.ToList();
                    
                    _stsMetadataRetrievalTime = DateTime.UtcNow;
                }

                issuer = _issuer;
                signingTokens = _signingTokens;
            }
            catch (Exception)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }

            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = Audience,
                ValidIssuer = issuer,
                IssuerSigningTokens = signingTokens,
                CertificateValidator = X509CertificateValidator.None
            };

            try
            {
                // Validate token.
                SecurityToken validatedToken;
                var claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out validatedToken);

                // Set the ClaimsPrincipal on the current thread.
                Thread.CurrentPrincipal = claimsPrincipal;

                // Set the ClaimsPrincipal on HttpContext.Current if the app is running in web hosted environment.
                if (HttpContext.Current != null)
                {
                    HttpContext.Current.User = claimsPrincipal;
                }

                // If the token is scoped, verify that required permission is set in the scope claim.
                if (ClaimsPrincipal.Current.FindFirst(ScopeClaimType) == null ||
                    ClaimsPrincipal.Current.FindFirst(ScopeClaimType).Value == "user_impersonation")
                    return await base.SendAsync(request, cancellationToken);
                var response = BuildResponseErrorMessage(HttpStatusCode.Forbidden);
                return response;
            }
            catch (SecurityTokenValidationException)
            {
                var response = BuildResponseErrorMessage(HttpStatusCode.Unauthorized);
                return response;
            }
            catch (Exception)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }
        }

        private HttpResponseMessage BuildResponseErrorMessage(HttpStatusCode statusCode)
        {
            var response = new HttpResponseMessage(statusCode);

            //
            // The Scheme should be "Bearer", authorization_uri should point to the tenant url and resource_id should point to the audience.
            //
            var authenticateHeader = new AuthenticationHeaderValue("Bearer", "authorization_uri=\"" + _authority + "\"" + "," + "resource_id=" + Audience);

            response.Headers.WwwAuthenticate.Add(authenticateHeader);

            return response;
        }
    }
}
