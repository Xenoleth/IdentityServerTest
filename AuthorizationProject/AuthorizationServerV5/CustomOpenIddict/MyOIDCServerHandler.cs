//using AspNet.Security.OpenIdConnect.Primitives;
//using AspNet.Security.OpenIdConnect.Server;
//using Microsoft.AspNetCore.Authentication;
//using Microsoft.Extensions.Logging;
//using Microsoft.Extensions.Options;
//using System;
//using System.Text.Encodings.Web;
//using System.Threading.Tasks;

//namespace AuthorizationServerV5.CustomOpenIddict
//{
//    public class MyOIDCServerHandler : OpenIdConnectServerHandler
//    {
//        public MyOIDCServerHandler(
//            IOptionsMonitor<OpenIdConnectServerOptions> options,
//            ILoggerFactory logger,
//            UrlEncoder encoder,
//            ISystemClock clock)
//           : base(options, logger, encoder, clock) { }

//        public override async Task<bool> InvokeAsync()
//        {
//            var notification = new MatchEndpointContext(Context, Options);

//            if (Options.AuthorizationEndpointPath.HasValue &&
//                Options.AuthorizationEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchAuthorizationEndpoint();
//            }

//            else if (Options.ConfigurationEndpointPath.HasValue &&
//                     Options.ConfigurationEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchConfigurationEndpoint();
//            }

//            else if (Options.CryptographyEndpointPath.HasValue &&
//                     Options.CryptographyEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchCryptographyEndpoint();
//            }

//            else if (Options.IntrospectionEndpointPath.HasValue &&
//                     Options.IntrospectionEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchIntrospectionEndpoint();
//            }

//            else if (Options.LogoutEndpointPath.HasValue &&
//                     Options.LogoutEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchLogoutEndpoint();
//            }

//            else if (Options.RevocationEndpointPath.HasValue &&
//                     Options.RevocationEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchRevocationEndpoint();
//            }

//            else if (Options.TokenEndpointPath.HasValue &&
//                     Options.TokenEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchTokenEndpoint();
//            }

//            else if (Options.UserinfoEndpointPath.HasValue &&
//                     Options.UserinfoEndpointPath.IsEquivalentTo(Request.Path))
//            {
//                notification.MatchUserinfoEndpoint();
//            }

//            await Options.Provider.MatchEndpoint(notification);

//            if (notification.HandledResponse)
//            {
//                Logger.LogDebug("The request was handled in user code.");

//                return true;
//            }

//            else if (notification.Skipped)
//            {
//                Logger.LogDebug("The default request handling was skipped from user code.");

//                return false;
//            }

//            // Reject non-HTTPS requests handled by ASOS if AllowInsecureHttp is not set to true.
//            if (!Options.AllowInsecureHttp && string.Equals(Request.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
//            {
//                // Return the native error page for endpoints involving the user participation.
//                if (notification.IsAuthorizationEndpoint || notification.IsLogoutEndpoint)
//                {
//                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
//                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
//                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

//                    return await SendNativePageAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "This server only accepts HTTPS requests."
//                    });
//                }

//                // Return a JSON error for endpoints that don't involve the user participation.
//                else if (notification.IsConfigurationEndpoint || notification.IsCryptographyEndpoint ||
//                         notification.IsIntrospectionEndpoint || notification.IsRevocationEndpoint ||
//                         notification.IsTokenEndpoint || notification.IsUserinfoEndpoint)
//                {
//                    Logger.LogWarning("The current request was rejected because the OpenID Connect server middleware " +
//                                      "has been configured to reject HTTP requests. To permanently disable the transport " +
//                                      "security requirement, set 'OpenIdConnectServerOptions.AllowInsecureHttp' to 'true'.");

//                    return await SendPayloadAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "This server only accepts HTTPS requests."
//                    });
//                }
//            }

//            if (notification.IsAuthorizationEndpoint)
//            {
//                return await InvokeAuthorizationEndpointAsync();
//            }

//            else if (notification.IsConfigurationEndpoint)
//            {
//                return await InvokeConfigurationEndpointAsync();
//            }

//            else if (notification.IsCryptographyEndpoint)
//            {
//                return await InvokeCryptographyEndpointAsync();
//            }

//            else if (notification.IsIntrospectionEndpoint)
//            {
//                return await InvokeIntrospectionEndpointAsync();
//            }

//            else if (notification.IsLogoutEndpoint)
//            {
//                return await InvokeLogoutEndpointAsync();
//            }

//            else if (notification.IsRevocationEndpoint)
//            {
//                return await InvokeRevocationEndpointAsync();
//            }

//            else if (notification.IsTokenEndpoint)
//            {
//                return await InvokeTokenEndpointAsync();
//            }

//            else if (notification.IsUserinfoEndpoint)
//            {
//                return await InvokeUserinfoEndpointAsync();
//            }

//            return false;
//        }
//    }
//}
