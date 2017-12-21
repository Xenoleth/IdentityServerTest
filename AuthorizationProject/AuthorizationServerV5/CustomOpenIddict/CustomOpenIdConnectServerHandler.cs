//using AspNet.Security.OpenIdConnect.Extensions;
//using AspNet.Security.OpenIdConnect.Primitives;
//using AspNet.Security.OpenIdConnect.Server;
//using Microsoft.AspNetCore.Authentication;
//using Microsoft.AspNetCore.WebUtilities;
//using Microsoft.Extensions.DependencyInjection;
//using Microsoft.Extensions.Logging;
//using Microsoft.Extensions.Options;
//using Microsoft.IdentityModel.Tokens;
//using Microsoft.Net.Http.Headers;
//using Newtonsoft.Json;
//using Newtonsoft.Json.Linq;
//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Security.Claims;
//using System.Text.Encodings.Web;
//using System.Threading.Tasks;

//namespace AuthorizationServerV5.CustomOpenIddict
//{
//    public class CustomOpenIdConnectServerHandler : AuthenticationHandler<OpenIdConnectServerOptions>,
//        IAuthenticationRequestHandler, IAuthenticationSignInHandler, IAuthenticationSignOutHandler
//    {
//        public CustomOpenIdConnectServerHandler(
//            IOptionsMonitor<OpenIdConnectServerOptions> options,
//            ILoggerFactory logger,
//            UrlEncoder encoder,
//            ISystemClock clock)
//            : base(options, logger, encoder, clock) { }

//        public virtual async Task<bool> HandleRequestAsync()
//        {
//            var notification = new MatchEndpointContext(Context, Scheme, Options);

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

//            await Provider.MatchEndpoint(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            // Reject non-HTTPS requests handled by ASOS if AllowInsecureHttp is not set to true.
//            if (!Options.AllowInsecureHttp && !Request.IsHttps)
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

//        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            if (request == null)
//            {
//                throw new InvalidOperationException("An identity cannot be extracted from this request.");
//            }

//            if (request.IsAuthorizationRequest() || request.IsLogoutRequest())
//            {
//                if (string.IsNullOrEmpty(request.IdTokenHint))
//                {
//                    return AuthenticateResult.NoResult();
//                }

//                var ticket = await DeserializeIdentityTokenAsync(request.IdTokenHint, request);
//                if (ticket == null)
//                {
//                    Logger.LogWarning("The identity token extracted from the 'id_token_hint' " +
//                                      "parameter was invalid or malformed and was ignored.");

//                    return AuthenticateResult.NoResult();
//                }

//                // Tickets are returned even if they
//                // are considered invalid (e.g expired).
//                return AuthenticateResult.Success(ticket);
//            }

//            else if (request.IsTokenRequest())
//            {
//                // Note: this method can be called from the ApplyTokenResponse event,
//                // which may be invoked for a missing authorization code/refresh token.
//                if (request.IsAuthorizationCodeGrantType())
//                {
//                    if (string.IsNullOrEmpty(request.Code))
//                    {
//                        return AuthenticateResult.NoResult();
//                    }

//                    var ticket = await DeserializeAuthorizationCodeAsync(request.Code, request);
//                    if (ticket == null)
//                    {
//                        Logger.LogWarning("The authorization code extracted from the " +
//                                          "token request was invalid and was ignored.");

//                        return AuthenticateResult.NoResult();
//                    }

//                    return AuthenticateResult.Success(ticket);
//                }

//                else if (request.IsRefreshTokenGrantType())
//                {
//                    if (string.IsNullOrEmpty(request.RefreshToken))
//                    {
//                        return AuthenticateResult.NoResult();
//                    }

//                    var ticket = await DeserializeRefreshTokenAsync(request.RefreshToken, request);
//                    if (ticket == null)
//                    {
//                        Logger.LogWarning("The refresh token extracted from the " +
//                                          "token request was invalid and was ignored.");

//                        return AuthenticateResult.NoResult();
//                    }

//                    return AuthenticateResult.Success(ticket);
//                }

//                return AuthenticateResult.NoResult();
//            }

//            throw new InvalidOperationException("An identity cannot be extracted from this request.");
//        }

//        public virtual Task SignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
//            => SignInAsync(new AuthenticationTicket(user, properties, Scheme.Name));

//        private async Task<bool> SignInAsync(AuthenticationTicket ticket)
//        {
//            // Extract the OpenID Connect request from the ASP.NET Core context.
//            // If it cannot be found or doesn't correspond to an authorization
//            // or a token request, throw an InvalidOperationException.
//            var request = Context.GetOpenIdConnectRequest();
//            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
//            {
//                throw new InvalidOperationException("An authorization or token response cannot be returned from this endpoint.");
//            }

//            // Note: if a response was already generated, throw an exception.
//            var response = Context.GetOpenIdConnectResponse();
//            if (response != null || Response.HasStarted)
//            {
//                throw new InvalidOperationException("A response has already been sent.");
//            }

//            if (string.IsNullOrEmpty(ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)))
//            {
//                throw new InvalidOperationException("The authentication ticket was rejected because " +
//                                                    "the mandatory subject claim was missing.");
//            }

//            Logger.LogTrace("A sign-in operation was triggered: {Claims} ; {Properties}.",
//                            ticket.Principal.Claims, ticket.Properties.Items);

//            // Prepare a new OpenID Connect response.
//            response = new OpenIdConnectResponse();

//            // Copy the confidentiality level associated with the request to the authentication ticket.
//            if (!ticket.HasProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel))
//            {
//                ticket.SetConfidentialityLevel(request.GetProperty<string>(OpenIdConnectConstants.Properties.ConfidentialityLevel));
//            }

//            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
//            // Note: the application is allowed to specify a different "scopes": in this case,
//            // don't replace the "scopes" property stored in the authentication ticket.
//            if (request.HasScope(OpenIdConnectConstants.Scopes.OpenId) && !ticket.HasScope())
//            {
//                ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId);
//            }

//            // When a "resources" property cannot be found in the ticket,
//            // infer it from the "audiences" property.
//            if (ticket.HasAudience() && !ticket.HasResource())
//            {
//                ticket.SetResources(ticket.GetAudiences());
//            }

//            // Add the validated client_id to the list of authorized presenters,
//            // unless the presenters were explicitly set by the developer.
//            var presenter = request.GetProperty<string>(OpenIdConnectConstants.Properties.ValidatedClientId);
//            if (!string.IsNullOrEmpty(presenter) && !ticket.HasPresenter())
//            {
//                ticket.SetPresenters(presenter);
//            }

//            var notification = new ProcessSigninResponseContext(Context, Scheme, Options, ticket, request, response);

//            if (request.IsAuthorizationRequest())
//            {
//                // By default, return an authorization code if a response type containing code was specified.
//                notification.IncludeAuthorizationCode = request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code);

//                // By default, return an access token if a response type containing token was specified.
//                notification.IncludeAccessToken = request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token);

//                // By default, prevent a refresh token from being returned as the OAuth2 specification
//                // explicitly disallows returning a refresh token from the authorization endpoint.
//                // See https://tools.ietf.org/html/rfc6749#section-4.2.2 for more information.
//                notification.IncludeRefreshToken = false;

//                // By default, return an identity token if a response type containing code
//                // was specified and if the openid scope was explicitly or implicitly granted.
//                notification.IncludeIdentityToken =
//                    request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
//                    ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
//            }

//            else
//            {
//                // By default, prevent an authorization code from being returned as this type of token
//                // cannot be issued from the token endpoint in the standard OAuth2/OpenID Connect flows.
//                notification.IncludeAuthorizationCode = false;

//                // By default, always return an access token.
//                notification.IncludeAccessToken = true;

//                // By default, only return a refresh token is the offline_access scope was granted and if
//                // sliding expiration is disabled or if the request is not a grant_type=refresh_token request.
//                notification.IncludeRefreshToken =
//                    ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
//                   (Options.UseSlidingExpiration || !request.IsRefreshTokenGrantType());

//                // By default, only return an identity token if the openid scope was granted.
//                notification.IncludeIdentityToken = ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
//            }

//            await Provider.ProcessSigninResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The sign-in response was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default sign-in handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                if (request.IsAuthorizationRequest())
//                {
//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = notification.ErrorDescription,
//                        ErrorUri = notification.ErrorUri
//                    });
//                }

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            // Flow the changes made to the ticket.
//            ticket = notification.Ticket;

//            // Ensure an authentication ticket has been provided or return
//            // an error code indicating that the request was rejected.
//            if (ticket == null)
//            {
//                Logger.LogError("The request was rejected because no authentication ticket was provided.");

//                if (request.IsAuthorizationRequest())
//                {
//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.AccessDenied,
//                        ErrorDescription = "The authorization was denied by the resource owner."
//                    });
//                }

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                    ErrorDescription = "The token request was rejected by the authorization server."
//                });
//            }

//            if (notification.IncludeAuthorizationCode)
//            {
//                // Make sure to create a copy of the authentication properties
//                // to avoid modifying the properties set on the original ticket.
//                var properties = ticket.Properties.Copy();

//                response.Code = await SerializeAuthorizationCodeAsync(ticket.Principal, properties, request, response);
//            }

//            if (notification.IncludeAccessToken)
//            {
//                // Make sure to create a copy of the authentication properties
//                // to avoid modifying the properties set on the original ticket.
//                var properties = ticket.Properties.Copy();

//                // When receiving a grant_type=refresh_token request, determine whether the client application
//                // requests a limited set of scopes/resources and replace the corresponding properties if necessary.
//                // Note: at this stage, request.GetResources() cannot return more items than the ones that were initially granted
//                // by the resource owner as the "resources" parameter is always validated when receiving the token request.
//                if (request.IsTokenRequest() && request.IsRefreshTokenGrantType())
//                {
//                    if (!string.IsNullOrEmpty(request.Resource))
//                    {
//                        Logger.LogDebug("The access token resources will be limited to the resources requested " +
//                                        "by the client application: {Resources}.", request.GetResources());

//                        // Replace the resources initially granted by the resources listed by the client
//                        // application in the token request. Note: request.GetResources() automatically
//                        // removes duplicate entries, so additional filtering is not necessary.
//                        properties.SetProperty(OpenIdConnectConstants.Properties.Resources,
//                            new JArray(request.GetResources()).ToString(Formatting.None));
//                    }

//                    if (!string.IsNullOrEmpty(request.Scope))
//                    {
//                        Logger.LogDebug("The access token scopes will be limited to the scopes requested " +
//                                        "by the client application: {Scopes}.", request.GetScopes());

//                        // Replace the scopes initially granted by the scopes listed by the client
//                        // application in the token request. Note: request.GetScopes() automatically
//                        // removes duplicate entries, so additional filtering is not necessary.
//                        properties.SetProperty(OpenIdConnectConstants.Properties.Scopes,
//                            new JArray(request.GetScopes()).ToString(Formatting.None));
//                    }
//                }

//                var resources = ticket.GetResources();
//                if (request.IsAuthorizationCodeGrantType() || !new HashSet<string>(resources).SetEquals(request.GetResources()))
//                {
//                    response.Resource = string.Join(" ", resources);
//                }

//                var scopes = ticket.GetScopes();
//                if (request.IsAuthorizationCodeGrantType() || !new HashSet<string>(scopes).SetEquals(request.GetScopes()))
//                {
//                    response.Scope = string.Join(" ", scopes);
//                }

//                response.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
//                response.AccessToken = await SerializeAccessTokenAsync(ticket.Principal, properties, request, response);

//                // properties.ExpiresUtc is automatically set by SerializeAccessTokenAsync but the end user
//                // is free to set a null value directly in the SerializeAccessToken event.
//                if (properties.ExpiresUtc.HasValue && properties.ExpiresUtc > Options.SystemClock.UtcNow)
//                {
//                    var lifetime = properties.ExpiresUtc.Value - Options.SystemClock.UtcNow;

//                    response.ExpiresIn = (long)(lifetime.TotalSeconds + .5);
//                }
//            }

//            if (notification.IncludeRefreshToken)
//            {
//                // Make sure to create a copy of the authentication properties
//                // to avoid modifying the properties set on the original ticket.
//                var properties = ticket.Properties.Copy();

//                response.RefreshToken = await SerializeRefreshTokenAsync(ticket.Principal, properties, request, response);
//            }

//            if (notification.IncludeIdentityToken)
//            {
//                // Make sure to create a copy of the authentication properties
//                // to avoid modifying the properties set on the original ticket.
//                var properties = ticket.Properties.Copy();

//                response.IdToken = await SerializeIdentityTokenAsync(ticket.Principal, properties, request, response);
//            }

//            if (request.IsAuthorizationRequest())
//            {
//                return await SendAuthorizationResponseAsync(response, ticket);
//            }

//            return await SendTokenResponseAsync(response, ticket);
//        }

//        public virtual Task SignOutAsync(AuthenticationProperties properties)
//            => HandleSignOutAsync(properties ?? new AuthenticationProperties());

//        private async Task<bool> HandleSignOutAsync(AuthenticationProperties properties)
//        {
//            // Extract the OpenID Connect request from the ASP.NET Core context.
//            // If it cannot be found or doesn't correspond to a logout request,
//            // throw an InvalidOperationException.
//            var request = Context.GetOpenIdConnectRequest();
//            if (request == null || !request.IsLogoutRequest())
//            {
//                throw new InvalidOperationException("A logout response cannot be returned from this endpoint.");
//            }

//            // Note: if a response was already generated, throw an exception.
//            var response = Context.GetOpenIdConnectResponse();
//            if (response != null || Response.HasStarted)
//            {
//                throw new InvalidOperationException("A response has already been sent.");
//            }

//            Logger.LogTrace("A log-out operation was triggered: {Properties}.", properties.Items);

//            // Prepare a new OpenID Connect response.
//            response = new OpenIdConnectResponse();

//            var notification = new ProcessSignoutResponseContext(Context, Scheme, Options, properties, request, response);
//            await Provider.ProcessSignoutResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The sign-out response was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default sign-out handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            return await SendLogoutResponseAsync(response);
//        }

//        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
//            => HandleUnauthorizedAsync(properties ?? new AuthenticationProperties());

//        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
//            => HandleUnauthorizedAsync(properties ?? new AuthenticationProperties());

//        private async Task<bool> HandleUnauthorizedAsync(AuthenticationProperties properties)
//        {
//            // Extract the OpenID Connect request from the ASP.NET Core context.
//            // If it cannot be found or doesn't correspond to an authorization
//            // or a token request, throw an InvalidOperationException.
//            var request = Context.GetOpenIdConnectRequest();
//            if (request == null || (!request.IsAuthorizationRequest() && !request.IsTokenRequest()))
//            {
//                throw new InvalidOperationException("An authorization or token response cannot be returned from this endpoint.");
//            }

//            // Note: if a response was already generated, throw an exception.
//            var response = Context.GetOpenIdConnectResponse();
//            if (response != null || Response.HasStarted)
//            {
//                throw new InvalidOperationException("A response has already been sent.");
//            }

//            // Prepare a new OpenID Connect response.
//            response = new OpenIdConnectResponse
//            {
//                Error = properties.GetProperty(OpenIdConnectConstants.Properties.Error),
//                ErrorDescription = properties.GetProperty(OpenIdConnectConstants.Properties.ErrorDescription),
//                ErrorUri = properties.GetProperty(OpenIdConnectConstants.Properties.ErrorUri)
//            };

//            // Remove the error/error_description/error_uri properties from the ticket.
//            properties.RemoveProperty(OpenIdConnectConstants.Properties.Error)
//                      .RemoveProperty(OpenIdConnectConstants.Properties.ErrorDescription)
//                      .RemoveProperty(OpenIdConnectConstants.Properties.ErrorUri);

//            if (string.IsNullOrEmpty(response.Error))
//            {
//                response.Error = request.IsAuthorizationRequest() ?
//                    OpenIdConnectConstants.Errors.AccessDenied :
//                    OpenIdConnectConstants.Errors.InvalidGrant;
//            }

//            if (string.IsNullOrEmpty(response.ErrorDescription))
//            {
//                response.ErrorDescription = request.IsAuthorizationRequest() ?
//                    "The authorization was denied by the resource owner." :
//                    "The token request was rejected by the authorization server.";
//            }

//            Logger.LogTrace("A challenge operation was triggered: {Properties}.", properties.Items);

//            var notification = new ProcessChallengeResponseContext(Context, Scheme, Options, properties, request, response);
//            await Provider.ProcessChallengeResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The challenge response was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default challenge handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                if (request.IsAuthorizationRequest())
//                {
//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = notification.ErrorDescription,
//                        ErrorUri = notification.ErrorUri
//                    });
//                }

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            // Flow the changes made to the properties.
//            properties = notification.Properties;

//            // Create a new ticket containing an empty identity and
//            // the authentication properties extracted from the context.
//            var ticket = new AuthenticationTicket(
//                new ClaimsPrincipal(new ClaimsIdentity()),
//                properties, Scheme.Name);

//            if (request.IsAuthorizationRequest())
//            {
//                return await SendAuthorizationResponseAsync(response, ticket);
//            }

//            return await SendTokenResponseAsync(response, ticket);
//        }

//        private async Task<bool> SendNativePageAsync(OpenIdConnectResponse response)
//        {
//            using (var buffer = new MemoryStream())
//            using (var writer = new StreamWriter(buffer))
//            {
//                foreach (var parameter in response.GetParameters())
//                {
//                    // Ignore null or empty parameters, including JSON
//                    // objects that can't be represented as strings.
//                    var value = (string)parameter.Value;
//                    if (string.IsNullOrEmpty(value))
//                    {
//                        continue;
//                    }

//                    writer.WriteLine("{0}:{1}", parameter.Key, value);
//                }

//                writer.Flush();

//                if (!string.IsNullOrEmpty(response.Error))
//                {
//                    Response.StatusCode = 400;
//                }

//                Response.ContentLength = buffer.Length;
//                Response.ContentType = "text/plain;charset=UTF-8";

//                Response.Headers[HeaderNames.CacheControl] = "no-cache";
//                Response.Headers[HeaderNames.Pragma] = "no-cache";
//                Response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

//                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
//                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

//                // Return true to stop processing the request.
//                return true;
//            }
//        }

//        private async Task<bool> SendPayloadAsync(OpenIdConnectResponse response)
//        {
//            using (var buffer = new MemoryStream())
//            using (var writer = new JsonTextWriter(new StreamWriter(buffer)))
//            {
//                var serializer = JsonSerializer.CreateDefault();
//                serializer.Serialize(writer, response);

//                writer.Flush();

//                if (!string.IsNullOrEmpty(response.Error))
//                {
//                    Response.StatusCode = 400;
//                }

//                Response.ContentLength = buffer.Length;
//                Response.ContentType = "application/json;charset=UTF-8";

//                switch (response.GetProperty<string>(OpenIdConnectConstants.Properties.MessageType))
//                {
//                    // Discovery, userinfo and introspection responses can be cached by the client
//                    // or the intermediate proxies. To allow the developer to set up his own response
//                    // caching policy, don't override the Cache-Control, Pragma and Expires headers.
//                    case OpenIdConnectConstants.MessageTypes.ConfigurationResponse:
//                    case OpenIdConnectConstants.MessageTypes.CryptographyResponse:
//                    case OpenIdConnectConstants.MessageTypes.IntrospectionResponse:
//                    case OpenIdConnectConstants.MessageTypes.UserinfoResponse:
//                        break;

//                    // Prevent the other responses from being cached.
//                    default:
//                        Response.Headers[HeaderNames.CacheControl] = "no-cache";
//                        Response.Headers[HeaderNames.Pragma] = "no-cache";
//                        Response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

//                        break;
//                }

//                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
//                await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

//                // Return true to stop processing the request.
//                return true;
//            }
//        }

//        private OpenIdConnectServerProvider Provider => (OpenIdConnectServerProvider)base.Events;

//        private async Task<bool> InvokeAuthorizationEndpointAsync()
//        {
//            OpenIdConnectRequest request;

//            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                request = new OpenIdConnectRequest(Request.Query);
//            }

//            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
//                if (string.IsNullOrEmpty(Request.ContentType))
//                {
//                    Logger.LogError("The authorization request was rejected because " +
//                                    "the mandatory 'Content-Type' header was missing.");

//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
//                    });
//                }

//                // May have media/type; charset=utf-8, allow partial match.
//                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//                {
//                    Logger.LogError("The authorization request was rejected because an invalid 'Content-Type' " +
//                                    "header was specified: {ContentType}.", Request.ContentType);

//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The specified 'Content-Type' header is not valid."
//                    });
//                }

//                request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
//            }

//            else
//            {
//                Logger.LogError("The authorization request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // Note: set the message type before invoking the ExtractAuthorizationRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.AuthorizationRequest);

//            // Store the authorization request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractAuthorizationRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractAuthorizationRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The authorization request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default authorization request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            // Store the original redirect_uri sent by the client application for later comparison.
//            request.SetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri, request.RedirectUri);

//            Logger.LogInformation("The authorization request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            // client_id is mandatory parameter and MUST cause an error when missing.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//            if (string.IsNullOrEmpty(request.ClientId))
//            {
//                Logger.LogError("The authorization request was rejected because " +
//                                "the mandatory 'client_id' parameter was missing.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'client_id' parameter is missing."
//                });
//            }

//            // While redirect_uri was not mandatory in OAuth2, this parameter
//            // is now declared as REQUIRED and MUST cause an error when missing.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//            // To keep AspNet.Security.OpenIdConnect.Server compatible with pure OAuth2 clients,
//            // an error is only returned if the request was made by an OpenID Connect client.
//            if (string.IsNullOrEmpty(request.RedirectUri) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId))
//            {
//                Logger.LogError("The authorization request was rejected because " +
//                                "the mandatory 'redirect_uri' parameter was missing.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'redirect_uri' parameter is missing."
//                });
//            }

//            if (!string.IsNullOrEmpty(request.RedirectUri))
//            {
//                // Note: when specified, redirect_uri MUST be an absolute URI.
//                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
//                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//                //
//                // Note: on Linux/macOS, "/path" URLs are treated as valid absolute file URLs.
//                // To ensure relative redirect_uris are correctly rejected on these platforms,
//                // an additional check using IsWellFormedOriginalString() is made here.
//                // See https://github.com/dotnet/corefx/issues/22098 for more information.
//                if (!Uri.TryCreate(request.RedirectUri, UriKind.Absolute, out Uri uri) || !uri.IsWellFormedOriginalString())
//                {
//                    Logger.LogError("The authorization request was rejected because the 'redirect_uri' parameter " +
//                                    "didn't correspond to a valid absolute URL: {RedirectUri}.", request.RedirectUri);

//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The 'redirect_uri' parameter must be a valid absolute URL."
//                    });
//                }

//                // Note: when specified, redirect_uri MUST NOT include a fragment component.
//                // See http://tools.ietf.org/html/rfc6749#section-3.1.2
//                // and http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//                if (!string.IsNullOrEmpty(uri.Fragment))
//                {
//                    Logger.LogError("The authorization request was rejected because the 'redirect_uri' " +
//                                    "contained a URL fragment: {RedirectUri}.", request.RedirectUri);

//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The 'redirect_uri' parameter must not include a fragment."
//                    });
//                }
//            }

//            // Reject requests missing the mandatory response_type parameter.
//            if (string.IsNullOrEmpty(request.ResponseType))
//            {
//                Logger.LogError("The authorization request was rejected because " +
//                                "the mandatory 'response_type' parameter was missing.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'response_type' parameter is missing."
//                });
//            }

//            // response_mode=query (explicit or not) and a response_type containing id_token
//            // or token are not considered as a safe combination and MUST be rejected.
//            // See http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Security
//            if (request.IsQueryResponseMode() && (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) ||
//                                                  request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Token)))
//            {
//                Logger.LogError("The authorization request was rejected because the 'response_type'/'response_mode' combination " +
//                                "was invalid: {ResponseType} ; {ResponseMode}.", request.ResponseType, request.ResponseMode);

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified 'response_type'/'response_mode' combination is invalid."
//                });
//            }

//            // Reject OpenID Connect implicit/hybrid requests missing the mandatory nonce parameter.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
//            // http://openid.net/specs/openid-connect-implicit-1_0.html#RequestParameters
//            // and http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken.
//            if (string.IsNullOrEmpty(request.Nonce) && request.HasScope(OpenIdConnectConstants.Scopes.OpenId) &&
//                                                      (request.IsImplicitFlow() || request.IsHybridFlow()))
//            {
//                Logger.LogError("The authorization request was rejected because the mandatory 'nonce' parameter was missing.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'nonce' parameter is missing."
//                });
//            }

//            // Reject requests containing the id_token response_type if no openid scope has been received.
//            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
//               !request.HasScope(OpenIdConnectConstants.Scopes.OpenId))
//            {
//                Logger.LogError("The authorization request was rejected because the 'openid' scope was missing.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'openid' scope is missing."
//                });
//            }

//            // Reject requests containing the id_token response_type if no asymmetric signing key has been registered.
//            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.IdToken) &&
//               !Options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
//            {
//                Logger.LogError("The authorization request was rejected because the 'id_token' response type could not be honored. " +
//                                "To fix this error, consider registering a X.509 signing certificate or an ephemeral signing key.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
//                    ErrorDescription = "The specified 'response_type' is not supported by this server."
//                });
//            }

//            // Reject requests containing the code response_type if the token endpoint has been disabled.
//            if (request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code) && !Options.TokenEndpointPath.HasValue)
//            {
//                Logger.LogError("The authorization request was rejected because the authorization code flow was disabled.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.UnsupportedResponseType,
//                    ErrorDescription = "The specified 'response_type' is not supported by this server."
//                });
//            }

//            // Reject requests specifying prompt=none with consent/login or select_account.
//            if (request.HasPrompt(OpenIdConnectConstants.Prompts.None) && (request.HasPrompt(OpenIdConnectConstants.Prompts.Consent) ||
//                                                                           request.HasPrompt(OpenIdConnectConstants.Prompts.Login) ||
//                                                                           request.HasPrompt(OpenIdConnectConstants.Prompts.SelectAccount)))
//            {
//                Logger.LogError("The authorization request was rejected because an invalid prompt parameter was specified.");

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified 'prompt' parameter is invalid."
//                });
//            }

//            if (!string.IsNullOrEmpty(request.CodeChallenge) || !string.IsNullOrEmpty(request.CodeChallengeMethod))
//            {
//                // When code_challenge or code_challenge_method is specified, ensure the response_type includes "code".
//                if (!request.HasResponseType(OpenIdConnectConstants.ResponseTypes.Code))
//                {
//                    Logger.LogError("The authorization request was rejected because the response type " +
//                                    "was not compatible with 'code_challenge'/'code_challenge_method'.");

//                    return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The 'code_challenge' and 'code_challenge_method' parameters " +
//                                           "can only be used with a response type containing 'code'."
//                    });
//                }

//                if (!string.IsNullOrEmpty(request.CodeChallengeMethod))
//                {
//                    // Ensure a code_challenge was specified if a code_challenge_method was used.
//                    if (string.IsNullOrEmpty(request.CodeChallenge))
//                    {
//                        Logger.LogError("The authorization request was rejected because the code_challenge was missing.");

//                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The 'code_challenge_method' parameter " +
//                                               "cannot be used without 'code_challenge'."
//                        });
//                    }

//                    // If a code_challenge_method was specified, ensure the algorithm is supported.
//                    if (request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Plain &&
//                        request.CodeChallengeMethod != OpenIdConnectConstants.CodeChallengeMethods.Sha256)
//                    {
//                        Logger.LogError("The authorization request was rejected because " +
//                                        "the specified code challenge was not supported.");

//                        return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The specified code_challenge_method is not supported."
//                        });
//                    }
//                }
//            }

//            var context = new ValidateAuthorizationRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateAuthorizationRequest(context);

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The authorization request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default authorization request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            // Store the validated client_id/redirect_uri as request properties.
//            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId)
//                   .SetProperty(OpenIdConnectConstants.Properties.ValidatedRedirectUri, context.RedirectUri);

//            Logger.LogInformation("The authorization request was successfully validated.");

//            var notification = new HandleAuthorizationRequestContext(Context, Scheme, Options, request);
//            await Provider.HandleAuthorizationRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The authorization request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default authorization request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The authorization request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendAuthorizationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            // If an authentication ticket was provided, stop processing
//            // the request and return an authorization response.
//            var ticket = notification.Ticket;
//            if (ticket == null)
//            {
//                return false;
//            }

//            return await SignInAsync(ticket);
//        }

//        private async Task<bool> SendAuthorizationResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.AuthorizationResponse);

//            // Note: as this stage, the request may be null (e.g if it couldn't be extracted from the HTTP request).
//            var notification = new ApplyAuthorizationResponseContext(Context, Scheme, Options, ticket, request, response)
//            {
//                RedirectUri = request?.GetProperty<string>(OpenIdConnectConstants.Properties.ValidatedRedirectUri),
//                ResponseMode = request?.ResponseMode
//            };

//            // If the response_mode parameter was not specified, try to infer it.
//            if (string.IsNullOrEmpty(notification.ResponseMode) && !string.IsNullOrEmpty(notification.RedirectUri))
//            {
//                notification.ResponseMode =
//                    request.IsFormPostResponseMode() ? OpenIdConnectConstants.ResponseModes.FormPost :
//                    request.IsFragmentResponseMode() ? OpenIdConnectConstants.ResponseModes.Fragment :
//                    request.IsQueryResponseMode() ? OpenIdConnectConstants.ResponseModes.Query : null;
//            }

//            await Provider.ApplyAuthorizationResponse(notification);


//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The authorization request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default authorization request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            // Directly display an error page if redirect_uri cannot be used to
//            // redirect the user agent back to the client application.
//            if (!string.IsNullOrEmpty(response.Error) && string.IsNullOrEmpty(notification.RedirectUri))
//            {
//                // Apply a 400 status code by default.
//                Response.StatusCode = 400;

//                if (Options.ApplicationCanDisplayErrors)
//                {
//                    // Return false to allow the rest of
//                    // the pipeline to handle the request.
//                    return false;
//                }

//                Logger.LogInformation("The authorization response was successfully returned " +
//                                      "as a plain-text document: {Response}.", response);

//                return await SendNativePageAsync(response);
//            }

//            // At this stage, throw an exception if the request was not properly extracted.
//            if (request == null)
//            {
//                throw new InvalidOperationException("The authorization response cannot be returned.");
//            }

//            // Attach the request state to the authorization response.
//            if (string.IsNullOrEmpty(response.State))
//            {
//                response.State = request.State;
//            }

//            // Create a new parameters dictionary holding the name/value pairs.
//            var parameters = new Dictionary<string, string>();

//            foreach (var parameter in response.GetParameters())
//            {
//                // Ignore null or empty parameters, including JSON
//                // objects that can't be represented as strings.
//                var value = (string)parameter.Value;
//                if (string.IsNullOrEmpty(value))
//                {
//                    continue;
//                }

//                parameters.Add(parameter.Key, value);
//            }

//            // Note: at this stage, the redirect_uri parameter MUST be trusted.
//            switch (notification.ResponseMode)
//            {
//                case OpenIdConnectConstants.ResponseModes.FormPost:
//                    {
//                        Logger.LogInformation("The authorization response was successfully returned to " +
//                                              "'{RedirectUri}' using the form post response mode: {Response}.",
//                                              notification.RedirectUri, response);

//                        using (var buffer = new MemoryStream())
//                        using (var writer = new StreamWriter(buffer))
//                        {
//                            writer.WriteLine("<!doctype html>");
//                            writer.WriteLine("<html>");
//                            writer.WriteLine("<body>");

//                            // While the redirect_uri parameter should be guarded against unknown values
//                            // by OpenIdConnectServerProvider.ValidateAuthorizationRequest,
//                            // it's still safer to encode it to avoid cross-site scripting attacks
//                            // if the authorization server has a relaxed policy concerning redirect URIs.
//                            writer.WriteLine($@"<form name=""form"" method=""post"" action=""{Options.HtmlEncoder.Encode(notification.RedirectUri)}"">");

//                            foreach (var parameter in parameters)
//                            {
//                                var key = Options.HtmlEncoder.Encode(parameter.Key);
//                                var value = Options.HtmlEncoder.Encode(parameter.Value);

//                                writer.WriteLine($@"<input type=""hidden"" name=""{key}"" value=""{value}"" />");
//                            }

//                            writer.WriteLine(@"<noscript>Click here to finish the authorization process: <input type=""submit"" /></noscript>");
//                            writer.WriteLine("</form>");
//                            writer.WriteLine("<script>document.form.submit();</script>");
//                            writer.WriteLine("</body>");
//                            writer.WriteLine("</html>");
//                            writer.Flush();

//                            Response.StatusCode = 200;
//                            Response.ContentLength = buffer.Length;
//                            Response.ContentType = "text/html;charset=UTF-8";

//                            Response.Headers["Cache-Control"] = "no-cache";
//                            Response.Headers["Pragma"] = "no-cache";
//                            Response.Headers["Expires"] = "-1";

//                            buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
//                            await buffer.CopyToAsync(Response.Body, 4096, Context.RequestAborted);

//                            return true;
//                        }
//                    }

//                case OpenIdConnectConstants.ResponseModes.Fragment:
//                    {
//                        Logger.LogInformation("The authorization response was successfully returned to " +
//                                              "'{RedirectUri}' using the fragment response mode: {Response}.",
//                                              notification.RedirectUri, response);

//                        var location = notification.RedirectUri;
//                        var appender = new OpenIdConnectServerHelpers.Appender(location, '#');

//                        foreach (var parameter in parameters)
//                        {
//                            appender.Append(parameter.Key, parameter.Value);
//                        }

//                        Response.Redirect(appender.ToString());
//                        return true;
//                    }

//                case OpenIdConnectConstants.ResponseModes.Query:
//                    {
//                        Logger.LogInformation("The authorization response was successfully returned to " +
//                                              "'{RedirectUri}' using the query response mode: {Response}.",
//                                              notification.RedirectUri, response);

//                        var location = QueryHelpers.AddQueryString(notification.RedirectUri, parameters);

//                        Response.Redirect(location);
//                        return true;
//                    }

//                default:
//                    {
//                        Logger.LogError("The authorization request was rejected because the 'response_mode' " +
//                                        "parameter was invalid: {ResponseMode}.", request.ResponseMode);

//                        return await SendNativePageAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The specified 'response_mode' parameter is not supported."
//                        });
//                    }
//            }
//        }

//        private async Task<bool> InvokeConfigurationEndpointAsync()
//        {
//            // Metadata requests must be made via GET.
//            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
//            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The configuration request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            var request = new OpenIdConnectRequest(Request.Query);

//            // Note: set the message type before invoking the ExtractConfigurationRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.ConfigurationRequest);

//            // Store the configuration request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractConfigurationRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractConfigurationRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The configuration request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default configuration request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The configuration request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The configuration request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            var context = new ValidateConfigurationRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateConfigurationRequest(context);

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The configuration request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default configuration request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The configuration request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            Logger.LogInformation("The configuration request was successfully validated.");

//            var notification = new HandleConfigurationRequestContext(Context, Scheme, Options, request)
//            {
//                Issuer = Context.GetIssuer(Options)
//            };

//            if (Options.AuthorizationEndpointPath.HasValue)
//            {
//                notification.AuthorizationEndpoint = notification.Issuer.AddPath(Options.AuthorizationEndpointPath);
//            }

//            if (Options.CryptographyEndpointPath.HasValue)
//            {
//                notification.CryptographyEndpoint = notification.Issuer.AddPath(Options.CryptographyEndpointPath);
//            }

//            if (Options.IntrospectionEndpointPath.HasValue)
//            {
//                notification.IntrospectionEndpoint = notification.Issuer.AddPath(Options.IntrospectionEndpointPath);

//                notification.IntrospectionEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
//                notification.IntrospectionEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
//            }

//            if (Options.LogoutEndpointPath.HasValue)
//            {
//                notification.LogoutEndpoint = notification.Issuer.AddPath(Options.LogoutEndpointPath);
//            }

//            if (Options.RevocationEndpointPath.HasValue)
//            {
//                notification.RevocationEndpoint = notification.Issuer.AddPath(Options.RevocationEndpointPath);

//                notification.RevocationEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
//                notification.RevocationEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
//            }

//            if (Options.TokenEndpointPath.HasValue)
//            {
//                notification.TokenEndpoint = notification.Issuer.AddPath(Options.TokenEndpointPath);

//                notification.TokenEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretBasic);
//                notification.TokenEndpointAuthenticationMethods.Add(
//                    OpenIdConnectConstants.ClientAuthenticationMethods.ClientSecretPost);
//            }

//            if (Options.UserinfoEndpointPath.HasValue)
//            {
//                notification.UserinfoEndpoint = notification.Issuer.AddPath(Options.UserinfoEndpointPath);
//            }

//            if (Options.AuthorizationEndpointPath.HasValue)
//            {
//                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit);

//                if (Options.TokenEndpointPath.HasValue)
//                {
//                    // Only expose the code grant type and the code challenge methods
//                    // if both the authorization and the token endpoints are enabled.
//                    notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);

//                    // Note: supporting S256 is mandatory for authorization servers that implement PKCE.
//                    // See https://tools.ietf.org/html/rfc7636#section-4.2 for more information.
//                    notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Plain);
//                    notification.CodeChallengeMethods.Add(OpenIdConnectConstants.CodeChallengeMethods.Sha256);
//                }
//            }

//            if (Options.TokenEndpointPath.HasValue)
//            {
//                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken);
//                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials);
//                notification.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password);
//            }

//            // Only populate response_modes_supported and response_types_supported
//            // if the authorization endpoint is available.
//            if (Options.AuthorizationEndpointPath.HasValue)
//            {
//                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.FormPost);
//                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Fragment);
//                notification.ResponseModes.Add(OpenIdConnectConstants.ResponseModes.Query);

//                notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Token);

//                // Only expose response types containing code when
//                // the token endpoint has not been explicitly disabled.
//                if (Options.TokenEndpointPath.HasValue)
//                {
//                    notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.Code);

//                    notification.ResponseTypes.Add(
//                        OpenIdConnectConstants.ResponseTypes.Code + ' ' +
//                        OpenIdConnectConstants.ResponseTypes.Token);
//                }

//                // Only expose the response types containing id_token if an asymmetric signing key is available.
//                if (Options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey))
//                {
//                    notification.ResponseTypes.Add(OpenIdConnectConstants.ResponseTypes.IdToken);

//                    notification.ResponseTypes.Add(
//                        OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
//                        OpenIdConnectConstants.ResponseTypes.Token);

//                    // Only expose response types containing code when
//                    // the token endpoint has not been explicitly disabled.
//                    if (Options.TokenEndpointPath.HasValue)
//                    {
//                        notification.ResponseTypes.Add(
//                            OpenIdConnectConstants.ResponseTypes.Code + ' ' +
//                            OpenIdConnectConstants.ResponseTypes.IdToken);

//                        notification.ResponseTypes.Add(
//                            OpenIdConnectConstants.ResponseTypes.Code + ' ' +
//                            OpenIdConnectConstants.ResponseTypes.IdToken + ' ' +
//                            OpenIdConnectConstants.ResponseTypes.Token);
//                    }
//                }
//            }

//            notification.Scopes.Add(OpenIdConnectConstants.Scopes.OpenId);

//            notification.SubjectTypes.Add(OpenIdConnectConstants.SubjectTypes.Public);

//            foreach (var credentials in Options.SigningCredentials)
//            {
//                // If the signing key is not an asymmetric key, ignore it.
//                if (!(credentials.Key is AsymmetricSecurityKey))
//                {
//                    continue;
//                }

//                // Try to resolve the JWA algorithm short name. If a null value is returned, ignore it.
//                var algorithm = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm);
//                if (string.IsNullOrEmpty(algorithm))
//                {
//                    continue;
//                }

//                notification.IdTokenSigningAlgorithms.Add(algorithm);
//            }

//            await Provider.HandleConfigurationRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The configuration request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default configuration request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The configuration request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendConfigurationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            var response = new OpenIdConnectResponse
//            {
//                [OpenIdConnectConstants.Metadata.Issuer] = notification.Issuer,
//                [OpenIdConnectConstants.Metadata.AuthorizationEndpoint] = notification.AuthorizationEndpoint,
//                [OpenIdConnectConstants.Metadata.TokenEndpoint] = notification.TokenEndpoint,
//                [OpenIdConnectConstants.Metadata.IntrospectionEndpoint] = notification.IntrospectionEndpoint,
//                [OpenIdConnectConstants.Metadata.EndSessionEndpoint] = notification.LogoutEndpoint,
//                [OpenIdConnectConstants.Metadata.RevocationEndpoint] = notification.RevocationEndpoint,
//                [OpenIdConnectConstants.Metadata.UserinfoEndpoint] = notification.UserinfoEndpoint,
//                [OpenIdConnectConstants.Metadata.JwksUri] = notification.CryptographyEndpoint,
//                [OpenIdConnectConstants.Metadata.GrantTypesSupported] = new JArray(notification.GrantTypes),
//                [OpenIdConnectConstants.Metadata.ResponseTypesSupported] = new JArray(notification.ResponseTypes),
//                [OpenIdConnectConstants.Metadata.ResponseModesSupported] = new JArray(notification.ResponseModes),
//                [OpenIdConnectConstants.Metadata.ScopesSupported] = new JArray(notification.Scopes),
//                [OpenIdConnectConstants.Metadata.IdTokenSigningAlgValuesSupported] = new JArray(notification.IdTokenSigningAlgorithms),
//                [OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported] = new JArray(notification.CodeChallengeMethods),
//                [OpenIdConnectConstants.Metadata.SubjectTypesSupported] = new JArray(notification.SubjectTypes),
//                [OpenIdConnectConstants.Metadata.TokenEndpointAuthMethodsSupported] = new JArray(notification.TokenEndpointAuthenticationMethods),
//                [OpenIdConnectConstants.Metadata.IntrospectionEndpointAuthMethodsSupported] = new JArray(notification.IntrospectionEndpointAuthenticationMethods),
//                [OpenIdConnectConstants.Metadata.RevocationEndpointAuthMethodsSupported] = new JArray(notification.RevocationEndpointAuthenticationMethods)
//            };

//            foreach (var metadata in notification.Metadata)
//            {
//                response.SetParameter(metadata.Key, metadata.Value);
//            }

//            return await SendConfigurationResponseAsync(response);
//        }

//        private async Task<bool> InvokeCryptographyEndpointAsync()
//        {
//            // Metadata requests must be made via GET.
//            // See http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
//            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The cryptography request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            var request = new OpenIdConnectRequest(Request.Query);

//            // Note: set the message type before invoking the ExtractCryptographyRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.CryptographyRequest);

//            // Store the cryptography request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractCryptographyRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractCryptographyRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The cryptography request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default cryptography request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The cryptography request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The cryptography request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            var context = new ValidateCryptographyRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateCryptographyRequest(context);

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The cryptography request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default cryptography request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The cryptography request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            var notification = new HandleCryptographyRequestContext(Context, Scheme, Options, request);

//            foreach (var credentials in Options.SigningCredentials)
//            {
//                // If the signing key is not an asymmetric key, ignore it.
//                if (!(credentials.Key is AsymmetricSecurityKey))
//                {
//                    Logger.LogDebug("A non-asymmetric signing key of type '{Type}' was excluded " +
//                                    "from the key set.", credentials.Key.GetType().FullName);

//                    continue;
//                }

//#if SUPPORTS_ECDSA
//                if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) &&
//                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) &&
//                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) &&
//                    !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
//                {
//                    Logger.LogInformation("An unsupported signing key of type '{Type}' was ignored and excluded " +
//                                          "from the key set. Only RSA and ECDSA asymmetric security keys can be " +
//                                          "exposed via the JWKS endpoint.", credentials.Key.GetType().Name);

//                    continue;
//                }
//#else
//                if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
//                {
//                    Logger.LogInformation("An unsupported signing key of type '{Type}' was ignored and excluded " +
//                                          "from the key set. Only RSA asymmetric security keys can be exposed " +
//                                          "via the JWKS endpoint.", credentials.Key.GetType().Name);

//                    continue;
//                }
//#endif

//                var key = new JsonWebKey
//                {
//                    Use = JsonWebKeyUseNames.Sig,

//                    // Resolve the JWA identifier from the algorithm specified in the credentials.
//                    Alg = OpenIdConnectServerHelpers.GetJwtAlgorithm(credentials.Algorithm),

//                    // Use the key identifier specified in the signing credentials.
//                    Kid = credentials.Kid,
//                };

//                if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256))
//                {
//                    RSA algorithm = null;

//                    // Note: IdentityModel 5 doesn't expose a method allowing to retrieve the underlying algorithm
//                    // from a generic asymmetric security key. To work around this limitation, try to cast
//                    // the security key to the built-in IdentityModel types to extract the required RSA instance.
//                    // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395
//                    if (credentials.Key is X509SecurityKey x509SecurityKey)
//                    {
//                        algorithm = x509SecurityKey.PublicKey as RSA;
//                    }

//                    else if (credentials.Key is RsaSecurityKey rsaSecurityKey)
//                    {
//                        algorithm = rsaSecurityKey.Rsa;

//                        // If no RSA instance can be found, create one using
//                        // the RSA parameters attached to the security key.
//                        if (algorithm == null)
//                        {
//                            var rsa = RSA.Create();
//                            rsa.ImportParameters(rsaSecurityKey.Parameters);
//                            algorithm = rsa;
//                        }
//                    }

//                    // Skip the key if an algorithm instance cannot be extracted.
//                    if (algorithm == null)
//                    {
//                        Logger.LogWarning("A signing key was ignored because it was unable " +
//                                          "to provide the requested algorithm instance.");

//                        continue;
//                    }

//                    // Export the RSA public key to create a new JSON Web Key
//                    // exposing the exponent and the modulus parameters.
//                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

//                    Debug.Assert(parameters.Exponent != null &&
//                                 parameters.Modulus != null,
//                        "RSA.ExportParameters() shouldn't return null parameters.");

//                    key.Kty = JsonWebAlgorithmsKeyTypes.RSA;

//                    // Note: both E and N must be base64url-encoded.
//                    // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1
//                    key.E = Base64UrlEncoder.Encode(parameters.Exponent);
//                    key.N = Base64UrlEncoder.Encode(parameters.Modulus);
//                }

//#if SUPPORTS_ECDSA
//                else if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
//                         credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
//                         credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
//                {
//                    ECDsa algorithm = null;

//                    if (credentials.Key is X509SecurityKey x509SecurityKey)
//                    {
//                        algorithm = x509SecurityKey.PublicKey as ECDsa;
//                    }

//                    else if (credentials.Key is ECDsaSecurityKey ecdsaSecurityKey)
//                    {
//                        algorithm = ecdsaSecurityKey.ECDsa;
//                    }

//                    // Skip the key if an algorithm instance cannot be extracted.
//                    if (algorithm == null)
//                    {
//                        Logger.LogWarning("A signing key was ignored because it was unable " +
//                                          "to provide the requested algorithm instance.");

//                        continue;
//                    }

//                    // Export the ECDsa public key to create a new JSON Web Key
//                    // exposing the coordinates of the point on the curve.
//                    var parameters = algorithm.ExportParameters(includePrivateParameters: false);

//                    Debug.Assert(parameters.Q.X != null &&
//                                 parameters.Q.Y != null,
//                        "ECDsa.ExportParameters() shouldn't return null coordinates.");

//                    key.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
//                    key.Crv = OpenIdConnectServerHelpers.GetJwtAlgorithmCurve(parameters.Curve);

//                    // Note: both X and Y must be base64url-encoded.
//                    // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2
//                    key.X = Base64UrlEncoder.Encode(parameters.Q.X);
//                    key.Y = Base64UrlEncoder.Encode(parameters.Q.Y);
//                }
//#endif

//                // If the signing key is embedded in a X.509 certificate, set
//                // the x5t and x5c parameters using the certificate details.
//                var certificate = (credentials.Key as X509SecurityKey)?.Certificate;
//                if (certificate != null)
//                {
//                    // x5t must be base64url-encoded.
//                    // See https://tools.ietf.org/html/rfc7517#section-4.8
//                    key.X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());

//                    // Unlike E or N, the certificates contained in x5c
//                    // must be base64-encoded and not base64url-encoded.
//                    // See https://tools.ietf.org/html/rfc7517#section-4.7
//                    key.X5c.Add(Convert.ToBase64String(certificate.RawData));
//                }

//                notification.Keys.Add(key);
//            }

//            await Provider.HandleCryptographyRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The cryptography request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default cryptography request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The cryptography request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendCryptographyResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            var keys = new JArray();

//            foreach (var key in notification.Keys)
//            {
//                var item = new JObject();

//                // Ensure a key type has been provided.
//                // See https://tools.ietf.org/html/rfc7517#section-4.1
//                if (string.IsNullOrEmpty(key.Kty))
//                {
//                    Logger.LogError("A JSON Web Key was excluded from the key set because " +
//                                    "it didn't contain the mandatory 'kid' parameter.");

//                    continue;
//                }

//                // Create a dictionary associating the
//                // JsonWebKey components with their values.
//                var parameters = new Dictionary<string, string>
//                {
//                    [JsonWebKeyParameterNames.Kid] = key.Kid,
//                    [JsonWebKeyParameterNames.Use] = key.Use,
//                    [JsonWebKeyParameterNames.Kty] = key.Kty,
//                    [JsonWebKeyParameterNames.Alg] = key.Alg,
//                    [JsonWebKeyParameterNames.Crv] = key.Crv,
//                    [JsonWebKeyParameterNames.E] = key.E,
//                    [JsonWebKeyParameterNames.N] = key.N,
//                    [JsonWebKeyParameterNames.X] = key.X,
//                    [JsonWebKeyParameterNames.Y] = key.Y,
//                    [JsonWebKeyParameterNames.X5t] = key.X5t,
//                    [JsonWebKeyParameterNames.X5u] = key.X5u
//                };

//                foreach (var parameter in parameters)
//                {
//                    if (!string.IsNullOrEmpty(parameter.Value))
//                    {
//                        item.Add(parameter.Key, parameter.Value);
//                    }
//                }

//                if (key.KeyOps.Count != 0)
//                {
//                    item.Add(JsonWebKeyParameterNames.KeyOps, new JArray(key.KeyOps));
//                }

//                if (key.X5c.Count != 0)
//                {
//                    item.Add(JsonWebKeyParameterNames.X5c, new JArray(key.X5c));
//                }

//                keys.Add(item);
//            }

//            // Note: AddParameter() is used here to ensure the mandatory "keys" node
//            // is returned to the caller, even if the key set doesn't expose any key.
//            // See https://tools.ietf.org/html/rfc7517#section-5 for more information.
//            var response = new OpenIdConnectResponse();
//            response.AddParameter(OpenIdConnectConstants.Parameters.Keys, keys);

//            return await SendCryptographyResponseAsync(response);
//        }

//        private async Task<bool> SendConfigurationResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.ConfigurationResponse);

//            var notification = new ApplyConfigurationResponseContext(Context, Scheme, Options, request, response);
//            await Provider.ApplyConfigurationResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The configuration request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default configuration request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The configuration response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }

//        private async Task<bool> SendCryptographyResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.CryptographyResponse);

//            var notification = new ApplyCryptographyResponseContext(Context, Scheme, Options, request, response);
//            await Provider.ApplyCryptographyResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The cryptography request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default cryptography request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The cryptography response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }

//        private async Task<bool> InvokeTokenEndpointAsync()
//        {
//            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The token request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
//            if (string.IsNullOrEmpty(Request.ContentType))
//            {
//                Logger.LogError("The token request was rejected because the " +
//                                "mandatory 'Content-Type' header was missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'Content-Type' header must be specified."
//                });
//            }

//            // May have media/type; charset=utf-8, allow partial match.
//            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The token request was rejected because an invalid 'Content-Type' " +
//                                "header was specified: {ContentType}.", Request.ContentType);

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified 'Content-Type' header is not valid."
//                });
//            }

//            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

//            // Note: set the message type before invoking the ExtractTokenRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.TokenRequest);

//            // Store the token request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractTokenRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractTokenRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The token request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default token request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The token request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            // Reject token requests missing the mandatory grant_type parameter.
//            if (string.IsNullOrEmpty(request.GrantType))
//            {
//                Logger.LogError("The token request was rejected because the grant type was missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'grant_type' parameter is missing.",
//                });
//            }

//            // Reject grant_type=authorization_code requests if the authorization endpoint is disabled.
//            else if (request.IsAuthorizationCodeGrantType() && !Options.AuthorizationEndpointPath.HasValue)
//            {
//                Logger.LogError("The token request was rejected because the authorization code grant was disabled.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
//                    ErrorDescription = "The authorization code grant is not allowed by this authorization server."
//                });
//            }

//            // Reject grant_type=authorization_code requests missing the authorization code.
//            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
//            else if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(request.Code))
//            {
//                Logger.LogError("The token request was rejected because the authorization code was missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'code' parameter is missing."
//                });
//            }

//            // Reject grant_type=refresh_token requests missing the refresh token.
//            // See https://tools.ietf.org/html/rfc6749#section-6
//            else if (request.IsRefreshTokenGrantType() && string.IsNullOrEmpty(request.RefreshToken))
//            {
//                Logger.LogError("The token request was rejected because the refresh token was missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'refresh_token' parameter is missing."
//                });
//            }

//            // Reject grant_type=password requests missing username or password.
//            // See https://tools.ietf.org/html/rfc6749#section-4.3.2
//            else if (request.IsPasswordGrantType() && (string.IsNullOrEmpty(request.Username) ||
//                                                       string.IsNullOrEmpty(request.Password)))
//            {
//                Logger.LogError("The token request was rejected because the resource owner credentials were missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'username' and/or 'password' parameters are missing."
//                });
//            }

//            // Try to resolve the client credentials specified in the 'Authorization' header.
//            // If they cannot be extracted, fallback to the client_id/client_secret parameters.
//            var credentials = Request.Headers.GetClientCredentials();
//            if (credentials != null)
//            {
//                // Reject requests that use multiple client authentication methods.
//                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
//                if (!string.IsNullOrEmpty(request.ClientSecret))
//                {
//                    Logger.LogError("The token request was rejected because multiple client credentials were specified.");

//                    return await SendTokenResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "Multiple client credentials cannot be specified."
//                    });
//                }

//                request.ClientId = credentials?.Key;
//                request.ClientSecret = credentials?.Value;
//            }

//            var context = new ValidateTokenRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateTokenRequest(context);

//            // If the validation context was set as fully validated,
//            // mark the OpenID Connect request as confidential.
//            if (context.IsValidated)
//            {
//                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
//                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
//            }

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The token request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default token request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            // Reject grant_type=client_credentials requests if validation was skipped.
//            else if (context.IsSkipped && request.IsClientCredentialsGrantType())
//            {
//                Logger.LogError("The token request must be fully validated to use the client_credentials grant type.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                    ErrorDescription = "Client authentication is required when using the client credentials grant."
//                });
//            }

//            // At this stage, client_id cannot be null for grant_type=authorization_code requests,
//            // as it must either be set in the ValidateTokenRequest notification
//            // by the developer or manually flowed by non-confidential client applications.
//            // See https://tools.ietf.org/html/rfc6749#section-4.1.3
//            if (request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.ClientId))
//            {
//                Logger.LogError("The token request was rejected because the mandatory 'client_id' was missing.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'client_id' parameter is missing."
//                });
//            }

//            // Store the validated client_id as a request property.
//            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

//            Logger.LogInformation("The token request was successfully validated.");

//            AuthenticationTicket ticket = null;

//            // See http://tools.ietf.org/html/rfc6749#section-4.1
//            // and http://tools.ietf.org/html/rfc6749#section-4.1.3 (authorization code grant).
//            // See http://tools.ietf.org/html/rfc6749#section-6 (refresh token grant).
//            if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
//            {
//                ticket = request.IsAuthorizationCodeGrantType() ?
//                    await DeserializeAuthorizationCodeAsync(request.Code, request) :
//                    await DeserializeRefreshTokenAsync(request.RefreshToken, request);

//                if (ticket == null)
//                {
//                    Logger.LogError("The token request was rejected because the " +
//                                    "authorization code or the refresh token was invalid.");

//                    return await SendTokenResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
//                            "The specified authorization code is invalid." :
//                            "The specified refresh token is invalid."
//                    });
//                }

//                // If the client was fully authenticated when retrieving its refresh token,
//                // the current request must be rejected if client authentication was not enforced.
//                if (request.IsRefreshTokenGrantType() && !context.IsValidated && ticket.IsConfidential())
//                {
//                    Logger.LogError("The token request was rejected because client authentication " +
//                                    "was required to use the confidential refresh token.");

//                    return await SendTokenResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                        ErrorDescription = "Client authentication is required to use the specified refresh token."
//                    });
//                }

//                if (ticket.Properties.ExpiresUtc.HasValue &&
//                    ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
//                {
//                    Logger.LogError("The token request was rejected because the " +
//                                    "authorization code or the refresh token was expired.");

//                    return await SendTokenResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
//                            "The specified authorization code is no longer valid." :
//                            "The specified refresh token is no longer valid."
//                    });
//                }

//                // Note: presenters may be empty during a grant_type=refresh_token request if the refresh token
//                // was issued to a public client but cannot be null for an authorization code grant request.
//                var presenters = ticket.GetPresenters();
//                if (request.IsAuthorizationCodeGrantType() && !presenters.Any())
//                {
//                    throw new InvalidOperationException("The presenters list cannot be extracted from the authorization code.");
//                }

//                // Ensure the authorization code/refresh token was issued to the client application making the token request.
//                // Note: when using the refresh token grant, client_id is optional but must validated if present.
//                // As a consequence, this check doesn't depend on the actual status of client authentication.
//                // See https://tools.ietf.org/html/rfc6749#section-6
//                // and http://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
//                if (!string.IsNullOrEmpty(context.ClientId) && presenters.Any() &&
//                    !presenters.Contains(context.ClientId, StringComparer.Ordinal))
//                {
//                    Logger.LogError("The token request was rejected because the authorization " +
//                                    "code was issued to a different client application.");

//                    return await SendTokenResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                        ErrorDescription = request.IsAuthorizationCodeGrantType() ?
//                            "The specified authorization code cannot be used by this client application." :
//                            "The specified refresh token cannot be used by this client application."
//                    });
//                }

//                // Validate the redirect_uri flowed by the client application during this token request.
//                // Note: for pure OAuth2 requests, redirect_uri is only mandatory if the authorization request
//                // contained an explicit redirect_uri. OpenID Connect requests MUST include a redirect_uri
//                // but the specifications allow proceeding the token request without returning an error
//                // if the authorization request didn't contain an explicit redirect_uri.
//                // See https://tools.ietf.org/html/rfc6749#section-4.1.3
//                // and http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
//                var address = ticket.GetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri);
//                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(address))
//                {
//                    if (string.IsNullOrEmpty(request.RedirectUri))
//                    {
//                        Logger.LogError("The token request was rejected because the mandatory 'redirect_uri' " +
//                                        "parameter was missing from the grant_type=authorization_code request.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The mandatory 'redirect_uri' parameter is missing."
//                        });
//                    }

//                    else if (!string.Equals(address, request.RedirectUri, StringComparison.Ordinal))
//                    {
//                        Logger.LogError("The token request was rejected because the 'redirect_uri' " +
//                                        "parameter didn't correspond to the expected value.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The specified 'redirect_uri' parameter doesn't match the client " +
//                                               "redirection endpoint the authorization code was initially sent to."
//                        });
//                    }
//                }

//                // If a code challenge was initially sent in the authorization request and associated with the
//                // code, validate the code verifier to ensure the token request is sent by a legit caller.
//                var challenge = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallenge);
//                if (request.IsAuthorizationCodeGrantType() && !string.IsNullOrEmpty(challenge))
//                {
//                    // Get the code verifier from the token request.
//                    // If it cannot be found, return an invalid_grant error.
//                    var verifier = request.CodeVerifier;
//                    if (string.IsNullOrEmpty(verifier))
//                    {
//                        Logger.LogError("The token request was rejected because the required 'code_verifier' " +
//                                        "parameter was missing from the grant_type=authorization_code request.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The mandatory 'code_verifier' parameter is missing."
//                        });
//                    }

//                    // Note: the code challenge method is always validated when receiving the authorization request.
//                    var method = ticket.GetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod);

//                    Debug.Assert(string.IsNullOrEmpty(method) ||
//                                 string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Plain, StringComparison.Ordinal) ||
//                                 string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Sha256, StringComparison.Ordinal),
//                        "The specified code challenge method should be supported.");

//                    // If the S256 challenge method was used, compute the hash corresponding to the code verifier.
//                    if (string.Equals(method, OpenIdConnectConstants.CodeChallengeMethods.Sha256, StringComparison.Ordinal))
//                    {
//                        using (var algorithm = SHA256.Create())
//                        {
//                            // Compute the SHA-256 hash of the code verifier and encode it using base64-url.
//                            // See https://tools.ietf.org/html/rfc7636#section-4.6 for more information.
//                            var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(request.CodeVerifier));

//                            verifier = Base64UrlEncoder.Encode(hash);
//                        }
//                    }

//                    // Compare the verifier and the code challenge: if the two don't match, return an error.
//                    // Note: to prevent timing attacks, a time-constant comparer is always used.
//                    if (!OpenIdConnectServerHelpers.AreEqual(verifier, challenge))
//                    {
//                        Logger.LogError("The token request was rejected because the 'code_verifier' was invalid.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The specified 'code_verifier' parameter is invalid."
//                        });
//                    }
//                }

//                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Resource))
//                {
//                    // When an explicit resource parameter has been included in the token request
//                    // but was missing from the initial request, the request MUST be rejected.
//                    var resources = ticket.GetResources();
//                    if (!resources.Any())
//                    {
//                        Logger.LogError("The token request was rejected because the 'resource' parameter was not allowed.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The 'resource' parameter is not valid in this context."
//                        });
//                    }

//                    // When an explicit resource parameter has been included in the token request,
//                    // the authorization server MUST ensure that it doesn't contain resources
//                    // that were not allowed during the initial authorization/token request.
//                    else if (!new HashSet<string>(resources).IsSupersetOf(request.GetResources()))
//                    {
//                        Logger.LogError("The token request was rejected because the 'resource' parameter was not valid.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The specified 'resource' parameter is invalid."
//                        });
//                    }
//                }

//                if (request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(request.Scope))
//                {
//                    // When an explicit scope parameter has been included in the token request
//                    // but was missing from the initial request, the request MUST be rejected.
//                    // See http://tools.ietf.org/html/rfc6749#section-6
//                    var scopes = ticket.GetScopes();
//                    if (!scopes.Any())
//                    {
//                        Logger.LogError("The token request was rejected because the 'scope' parameter was not allowed.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The 'scope' parameter is not valid in this context."
//                        });
//                    }

//                    // When an explicit scope parameter has been included in the token request,
//                    // the authorization server MUST ensure that it doesn't contain scopes
//                    // that were not allowed during the initial authorization/token request.
//                    // See https://tools.ietf.org/html/rfc6749#section-6
//                    else if (!new HashSet<string>(scopes).IsSupersetOf(request.GetScopes()))
//                    {
//                        Logger.LogError("The token request was rejected because the 'scope' parameter was not valid.");

//                        return await SendTokenResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                            ErrorDescription = "The specified 'scope' parameter is invalid."
//                        });
//                    }
//                }
//            }

//            var notification = new HandleTokenRequestContext(Context, Scheme, Options, request, ticket);
//            await Provider.HandleTokenRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The token request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default token request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The token request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidGrant,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            // Flow the changes made to the ticket.
//            ticket = notification.Ticket;

//            // Ensure an authentication ticket has been provided or return
//            // an error code indicating that the request was rejected.
//            if (ticket == null)
//            {
//                Logger.LogError("The token request was rejected because it was not handled by the user code.");

//                return await SendTokenResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The token request was rejected by the authorization server."
//                });
//            }

//            return await SignInAsync(ticket);
//        }

//        private async Task<bool> SendTokenResponseAsync(OpenIdConnectResponse response, AuthenticationTicket ticket = null)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.TokenResponse);

//            var notification = new ApplyTokenResponseContext(Context, Scheme, Options, ticket, request, response);
//            await Provider.ApplyTokenResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The token request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default token request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The token response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }

//        private async Task<bool> InvokeIntrospectionEndpointAsync()
//        {
//            OpenIdConnectRequest request;

//            // See https://tools.ietf.org/html/rfc7662#section-2.1
//            // and https://tools.ietf.org/html/rfc7662#section-4
//            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                request = new OpenIdConnectRequest(Request.Query);
//            }

//            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
//                if (string.IsNullOrEmpty(Request.ContentType))
//                {
//                    Logger.LogError("The introspection request was rejected because " +
//                                    "the mandatory 'Content-Type' header was missing.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
//                    });
//                }

//                // May have media/type; charset=utf-8, allow partial match.
//                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//                {
//                    Logger.LogError("The introspection request was rejected because an invalid 'Content-Type' " +
//                                    "header was specified: {ContentType}.", Request.ContentType);

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The specified 'Content-Type' header is not valid."
//                    });
//                }

//                request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
//            }

//            else
//            {
//                Logger.LogError("The introspection request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // Note: set the message type before invoking the ExtractIntrospectionRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.IntrospectionRequest);

//            // Store the introspection request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractIntrospectionRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractIntrospectionRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The introspection request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The introspection request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            if (string.IsNullOrEmpty(request.Token))
//            {
//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'token' parameter is missing."
//                });
//            }

//            // Try to resolve the client credentials specified in the 'Authorization' header.
//            // If they cannot be extracted, fallback to the client_id/client_secret parameters.
//            var credentials = Request.Headers.GetClientCredentials();
//            if (credentials != null)
//            {
//                // Reject requests that use multiple client authentication methods.
//                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
//                if (!string.IsNullOrEmpty(request.ClientSecret))
//                {
//                    Logger.LogError("The introspection request was rejected because " +
//                                    "multiple client credentials were specified.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "Multiple client credentials cannot be specified."
//                    });
//                }

//                request.ClientId = credentials?.Key;
//                request.ClientSecret = credentials?.Value;
//            }

//            var context = new ValidateIntrospectionRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateIntrospectionRequest(context);

//            // If the validation context was set as fully validated,
//            // mark the OpenID Connect request as confidential.
//            if (context.IsValidated)
//            {
//                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
//                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
//            }

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The introspection request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            // Store the validated client_id as a request property.
//            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

//            Logger.LogInformation("The introspection request was successfully validated.");

//            AuthenticationTicket ticket = null;

//            // Note: use the "token_type_hint" parameter to determine
//            // the type of the token sent by the client application.
//            // See https://tools.ietf.org/html/rfc7662#section-2.1
//            switch (request.TokenTypeHint)
//            {
//                case OpenIdConnectConstants.TokenTypeHints.AccessToken:
//                    ticket = await DeserializeAccessTokenAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
//                    ticket = await DeserializeAuthorizationCodeAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.IdToken:
//                    ticket = await DeserializeIdentityTokenAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
//                    ticket = await DeserializeRefreshTokenAsync(request.Token, request);
//                    break;
//            }

//            // Note: if the token can't be found using "token_type_hint",
//            // the search must be extended to all supported token types.
//            // See https://tools.ietf.org/html/rfc7662#section-2.1
//            if (ticket == null)
//            {
//                // To avoid calling the same deserialization methods twice,
//                // an additional check is made to exclude the corresponding
//                // method when an explicit token_type_hint was specified.
//                switch (request.TokenTypeHint)
//                {
//                    case OpenIdConnectConstants.TokenTypeHints.AccessToken:
//                        ticket = await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.IdToken:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request);
//                        break;

//                    default:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;
//                }
//            }

//            if (ticket == null)
//            {
//                Logger.LogInformation("The introspection request was rejected because the token was invalid.");

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    [OpenIdConnectConstants.Parameters.Active] = false
//                });
//            }

//            // Note: unlike refresh or identity tokens that can only be validated by client applications,
//            // access tokens can be validated by either resource servers or client applications:
//            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
//            if (context.IsSkipped && ticket.IsConfidential())
//            {
//                Logger.LogError("The introspection request was rejected because the caller was not authenticated.");

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    [OpenIdConnectConstants.Parameters.Active] = false
//                });
//            }

//            // If the ticket is already expired, directly return active=false.
//            if (ticket.Properties.ExpiresUtc.HasValue &&
//                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
//            {
//                Logger.LogInformation("The introspection request was rejected because the token was expired.");

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    [OpenIdConnectConstants.Parameters.Active] = false
//                });
//            }

//            // When a client_id can be inferred from the introspection request,
//            // ensure that the client application is a valid audience/presenter.
//            if (!string.IsNullOrEmpty(context.ClientId))
//            {
//                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The introspection request was rejected because the " +
//                                    "authorization code was issued to a different client.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        [OpenIdConnectConstants.Parameters.Active] = false
//                    });
//                }

//                // Ensure the caller is listed as a valid audience or authorized presenter.
//                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId) &&
//                                                   ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The introspection request was rejected because the access token " +
//                                    "was issued to a different client or for another resource server.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        [OpenIdConnectConstants.Parameters.Active] = false
//                    });
//                }

//                // Reject the request if the caller is not listed as a valid audience.
//                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId))
//                {
//                    Logger.LogError("The introspection request was rejected because the " +
//                                    "identity token was issued to a different client.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        [OpenIdConnectConstants.Parameters.Active] = false
//                    });
//                }

//                // Reject the introspection request if the caller doesn't
//                // correspond to the client application the token was issued to.
//                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The introspection request was rejected because the " +
//                                    "refresh token was issued to a different client.");

//                    return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                    {
//                        [OpenIdConnectConstants.Parameters.Active] = false
//                    });
//                }
//            }

//            var notification = new HandleIntrospectionRequestContext(Context, Scheme, Options, request, ticket)
//            {
//                Active = true,
//                Issuer = Context.GetIssuer(Options),
//                TokenId = ticket.GetTokenId(),
//                TokenUsage = ticket.GetProperty(OpenIdConnectConstants.Properties.TokenUsage),
//                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)
//            };

//            // Note: only set "token_type" when the received token is an access token.
//            // See https://tools.ietf.org/html/rfc7662#section-2.2
//            // and https://tools.ietf.org/html/rfc6749#section-5.1
//            if (ticket.IsAccessToken())
//            {
//                notification.TokenType = OpenIdConnectConstants.TokenTypes.Bearer;
//            }

//            notification.IssuedAt = ticket.Properties.IssuedUtc;
//            notification.NotBefore = ticket.Properties.IssuedUtc;
//            notification.ExpiresAt = ticket.Properties.ExpiresUtc;

//            // Infer the audiences/client_id claims from the properties stored in the authentication ticket.
//            // Note: the client_id claim must be a unique string so multiple presenters cannot be returned.
//            // To work around this limitation, only the first one is returned if multiple values are listed.
//            notification.Audiences.UnionWith(ticket.GetAudiences());
//            notification.ClientId = ticket.GetPresenters().FirstOrDefault();

//            // Note: non-metadata claims are only added if the caller's client_id is known
//            // AND is in the specified audiences, unless there's no explicit audience.
//            if (!ticket.HasAudience() || (!string.IsNullOrEmpty(context.ClientId) && ticket.HasAudience(context.ClientId)))
//            {
//                notification.Username = ticket.Principal.Identity?.Name;
//                notification.Scopes.UnionWith(ticket.GetScopes());

//                // Potentially sensitive claims are only exposed if the client was authenticated
//                // and if the authentication ticket corresponds to an identity or access token.
//                if (context.IsValidated && (ticket.IsAccessToken() || ticket.IsIdentityToken()))
//                {
//                    foreach (var grouping in ticket.Principal.Claims.GroupBy(claim => claim.Type))
//                    {
//                        // Exclude standard claims, that are already handled via strongly-typed properties.
//                        // Make sure to always update this list when adding new built-in claim properties.
//                        var type = grouping.Key;
//                        switch (type)
//                        {
//                            case OpenIdConnectConstants.Claims.Audience:
//                            case OpenIdConnectConstants.Claims.ExpiresAt:
//                            case OpenIdConnectConstants.Claims.IssuedAt:
//                            case OpenIdConnectConstants.Claims.Issuer:
//                            case OpenIdConnectConstants.Claims.NotBefore:
//                            case OpenIdConnectConstants.Claims.Scope:
//                            case OpenIdConnectConstants.Claims.Subject:
//                            case OpenIdConnectConstants.Claims.TokenType:
//                            case OpenIdConnectConstants.Claims.TokenUsage:
//                                continue;
//                        }

//                        var claims = grouping.ToArray();
//                        switch (claims.Length)
//                        {
//                            case 0: continue;

//                            // When there's only one claim with the same type, directly
//                            // convert the claim as an OpenIdConnectParameter instance,
//                            // whose token type is determined from the claim value type.
//                            case 1:
//                                {
//                                    notification.Claims[type] = claims[0].AsParameter();

//                                    continue;
//                                }

//                            // When multiple claims share the same type, convert all the claims
//                            // to OpenIdConnectParameter instances, retrieve the underlying
//                            // JSON values and add everything to a new JSON array.
//                            default:
//                                {
//                                    notification.Claims[type] = new JArray(claims.Select(claim => claim.AsParameter().Value));

//                                    continue;
//                                }
//                        }
//                    }
//                }
//            }

//            await Provider.HandleIntrospectionRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The introspection request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The introspection request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendIntrospectionResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            var response = new OpenIdConnectResponse
//            {
//                [OpenIdConnectConstants.Claims.Active] = notification.Active
//            };

//            // Only add the other properties if
//            // the token is considered as active.
//            if (notification.Active)
//            {
//                response[OpenIdConnectConstants.Claims.Issuer] = notification.Issuer;
//                response[OpenIdConnectConstants.Claims.Username] = notification.Username;
//                response[OpenIdConnectConstants.Claims.Subject] = notification.Subject;
//                response[OpenIdConnectConstants.Claims.Scope] = string.Join(" ", notification.Scopes);
//                response[OpenIdConnectConstants.Claims.JwtId] = notification.TokenId;
//                response[OpenIdConnectConstants.Claims.TokenType] = notification.TokenType;
//                response[OpenIdConnectConstants.Claims.TokenUsage] = notification.TokenUsage;
//                response[OpenIdConnectConstants.Claims.ClientId] = notification.ClientId;

//                if (notification.IssuedAt != null)
//                {
//                    response[OpenIdConnectConstants.Claims.IssuedAt] =
//                        EpochTime.GetIntDate(notification.IssuedAt.Value.UtcDateTime);
//                }

//                if (notification.NotBefore != null)
//                {
//                    response[OpenIdConnectConstants.Claims.NotBefore] =
//                        EpochTime.GetIntDate(notification.NotBefore.Value.UtcDateTime);
//                }

//                if (notification.ExpiresAt != null)
//                {
//                    response[OpenIdConnectConstants.Claims.ExpiresAt] =
//                        EpochTime.GetIntDate(notification.ExpiresAt.Value.UtcDateTime);
//                }

//                switch (notification.Audiences.Count)
//                {
//                    case 0: break;

//                    case 1:
//                        response[OpenIdConnectConstants.Claims.Audience] = notification.Audiences.ElementAt(0);
//                        break;

//                    default:
//                        response[OpenIdConnectConstants.Claims.Audience] = new JArray(notification.Audiences);
//                        break;
//                }

//                foreach (var claim in notification.Claims)
//                {
//                    response.SetParameter(claim.Key, claim.Value);
//                }
//            }

//            return await SendIntrospectionResponseAsync(response);
//        }

//        private async Task<bool> SendIntrospectionResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.IntrospectionResponse);

//            var notification = new ApplyIntrospectionResponseContext(Context, Scheme, Options, request, response);
//            await Provider.ApplyIntrospectionResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The introspection request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default introspection request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The introspection response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }

//        private async Task<bool> InvokeRevocationEndpointAsync()
//        {
//            if (!string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The revocation request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
//            if (string.IsNullOrEmpty(Request.ContentType))
//            {
//                Logger.LogError("The revocation request was rejected because " +
//                                "the mandatory 'Content-Type' header was missing.");

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'Content-Type' header must be specified."
//                });
//            }

//            // May have media/type; charset=utf-8, allow partial match.
//            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//            {
//                Logger.LogError("The revocation request was rejected because an invalid 'Content-Type' " +
//                                "header was specified: {ContentType}.", Request.ContentType);

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified 'Content-Type' header is not valid."
//                });
//            }

//            var request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));

//            // Note: set the message type before invoking the ExtractRevocationRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.RevocationRequest);

//            // Insert the revocation request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractRevocationRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractRevocationRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The revocation request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The revocation request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            if (string.IsNullOrEmpty(request.Token))
//            {
//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'token' parameter is missing."
//                });
//            }

//            // Try to resolve the client credentials specified in the 'Authorization' header.
//            // If they cannot be extracted, fallback to the client_id/client_secret parameters.
//            var credentials = Request.Headers.GetClientCredentials();
//            if (credentials != null)
//            {
//                // Reject requests that use multiple client authentication methods.
//                // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
//                if (!string.IsNullOrEmpty(request.ClientSecret))
//                {
//                    Logger.LogError("The revocation request was rejected because " +
//                                    "multiple client credentials were specified.");

//                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "Multiple client credentials cannot be specified."
//                    });
//                }

//                request.ClientId = credentials?.Key;
//                request.ClientSecret = credentials?.Value;
//            }

//            var context = new ValidateRevocationRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateRevocationRequest(context);

//            // If the validation context was set as fully validated,
//            // mark the OpenID Connect request as confidential.
//            if (context.IsValidated)
//            {
//                request.SetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel,
//                                    OpenIdConnectConstants.ConfidentialityLevels.Private);
//            }

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The revocation request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            // Store the validated client_id as a request property.
//            request.SetProperty(OpenIdConnectConstants.Properties.ValidatedClientId, context.ClientId);

//            Logger.LogInformation("The revocation request was successfully validated.");

//            AuthenticationTicket ticket = null;

//            // Note: use the "token_type_hint" parameter to determine
//            // the type of the token sent by the client application.
//            // See https://tools.ietf.org/html/rfc7009#section-2.1
//            switch (request.TokenTypeHint)
//            {
//                case OpenIdConnectConstants.TokenTypeHints.AccessToken:
//                    ticket = await DeserializeAccessTokenAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
//                    ticket = await DeserializeAuthorizationCodeAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.IdToken:
//                    ticket = await DeserializeIdentityTokenAsync(request.Token, request);
//                    break;

//                case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
//                    ticket = await DeserializeRefreshTokenAsync(request.Token, request);
//                    break;
//            }

//            // Note: if the token can't be found using "token_type_hint",
//            // the search must be extended to all supported token types.
//            // See https://tools.ietf.org/html/rfc7009#section-2.1
//            if (ticket == null)
//            {
//                // To avoid calling the same deserialization methods twice,
//                // an additional check is made to exclude the corresponding
//                // method when an explicit token_type_hint was specified.
//                switch (request.TokenTypeHint)
//                {
//                    case OpenIdConnectConstants.TokenTypeHints.AccessToken:
//                        ticket = await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.AuthorizationCode:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.IdToken:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;

//                    case OpenIdConnectConstants.TokenTypeHints.RefreshToken:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request);
//                        break;

//                    default:
//                        ticket = await DeserializeAccessTokenAsync(request.Token, request) ??
//                                 await DeserializeAuthorizationCodeAsync(request.Token, request) ??
//                                 await DeserializeIdentityTokenAsync(request.Token, request) ??
//                                 await DeserializeRefreshTokenAsync(request.Token, request);
//                        break;
//                }
//            }

//            if (ticket == null)
//            {
//                Logger.LogInformation("The revocation request was ignored because the token was invalid.");

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
//            }

//            // If the ticket is already expired, directly return a 200 response.
//            else if (ticket.Properties.ExpiresUtc.HasValue &&
//                     ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
//            {
//                Logger.LogInformation("The revocation request was ignored because the token was already expired.");

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse());
//            }

//            // Note: unlike refresh tokens that can only be revoked by client applications,
//            // access tokens can be revoked by either resource servers or client applications:
//            // in both cases, the caller must be authenticated if the ticket is marked as confidential.
//            if (context.IsSkipped && ticket.IsConfidential())
//            {
//                Logger.LogError("The revocation request was rejected because the caller was not authenticated.");

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest
//                });
//            }

//            // When a client_id can be inferred from the introspection request,
//            // ensure that the client application is a valid audience/presenter.
//            if (!string.IsNullOrEmpty(context.ClientId))
//            {
//                if (ticket.IsAuthorizationCode() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The revocation request was rejected because the " +
//                                    "authorization code was issued to a different client.");

//                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest
//                    });
//                }

//                // Ensure the caller is listed as a valid audience or authorized presenter.
//                else if (ticket.IsAccessToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId) &&
//                                                   ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The revocation request was rejected because the access token " +
//                                    "was issued to a different client or for another resource server.");

//                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest
//                    });
//                }

//                // Reject the request if the caller is not listed as a valid audience.
//                else if (ticket.IsIdentityToken() && ticket.HasAudience() && !ticket.HasAudience(context.ClientId))
//                {
//                    Logger.LogError("The revocation request was rejected because the " +
//                                    "identity token was issued to a different client.");

//                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest
//                    });
//                }

//                // Reject the introspection request if the caller doesn't
//                // correspond to the client application the token was issued to.
//                else if (ticket.IsRefreshToken() && ticket.HasPresenter() && !ticket.HasPresenter(context.ClientId))
//                {
//                    Logger.LogError("The revocation request was rejected because the " +
//                                    "refresh token was issued to a different client.");

//                    return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest
//                    });
//                }
//            }

//            var notification = new HandleRevocationRequestContext(Context, Scheme, Options, request, ticket);
//            await Provider.HandleRevocationRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The revocation request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The revocation request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            if (!notification.Revoked)
//            {
//                return await SendRevocationResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.UnsupportedTokenType,
//                    ErrorDescription = "The specified token cannot be revoked."
//                });
//            }

//            return await SendRevocationResponseAsync(new OpenIdConnectResponse());
//        }

//        private async Task<bool> SendRevocationResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.RevocationResponse);

//            var notification = new ApplyRevocationResponseContext(Context, Scheme, Options, request, response);
//            await Provider.ApplyRevocationResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The revocation request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default revocation request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The revocation response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }

//        private async Task<string> SerializeAuthorizationCodeAsync(
//            ClaimsPrincipal principal, AuthenticationProperties properties,
//            OpenIdConnectRequest request, OpenIdConnectResponse response)
//        {
//            // Note: claims in authorization codes are never filtered as they are supposed to be opaque:
//            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
//            // that subsequent access and identity tokens are correctly filtered.

//            // Create a new ticket containing the updated properties.
//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
//            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
//            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
//            ticket.Properties.ExpiresUtc += ticket.GetAuthorizationCodeLifetime() ?? Options.AuthorizationCodeLifetime;

//            // Associate a random identifier with the authorization code.
//            ticket.SetTokenId(Guid.NewGuid().ToString());

//            // Store the code_challenge, code_challenge_method and nonce parameters for later comparison.
//            ticket.SetProperty(OpenIdConnectConstants.Properties.CodeChallenge, request.CodeChallenge)
//                  .SetProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod, request.CodeChallengeMethod)
//                  .SetProperty(OpenIdConnectConstants.Properties.Nonce, request.Nonce);

//            // Store the original redirect_uri sent by the client application for later comparison.
//            ticket.SetProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri,
//                request.GetProperty<string>(OpenIdConnectConstants.Properties.OriginalRedirectUri));

//            // Remove the unwanted properties from the authentication ticket.
//            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

//            var notification = new SerializeAuthorizationCodeContext(Context, Scheme, Options, request, response, ticket)
//            {
//                DataFormat = Options.AuthorizationCodeFormat
//            };

//            await Provider.SerializeAuthorizationCode(notification);

//            if (notification.IsHandled || !string.IsNullOrEmpty(notification.AuthorizationCode))
//            {
//                return notification.AuthorizationCode;
//            }

//            if (notification.DataFormat == null)
//            {
//                throw new InvalidOperationException("A data formatter must be provided.");
//            }

//            var result = notification.DataFormat.Protect(ticket);

//            Logger.LogTrace("A new authorization code was successfully generated using " +
//                            "the specified data format: {Code} ; {Claims} ; {Properties}.",
//                            result, ticket.Principal.Claims, ticket.Properties.Items);

//            return result;
//        }

//        private async Task<string> SerializeAccessTokenAsync(
//            ClaimsPrincipal principal, AuthenticationProperties properties,
//            OpenIdConnectRequest request, OpenIdConnectResponse response)
//        {
//            // Create a new principal containing only the filtered claims.
//            // Actors identities are also filtered (delegation scenarios).
//            principal = principal.Clone(claim =>
//            {
//                // Never exclude the subject claim.
//                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase))
//                {
//                    return true;
//                }

//                // Claims whose destination is not explicitly referenced or doesn't
//                // contain "access_token" are not included in the access token.
//                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.AccessToken))
//                {
//                    Logger.LogDebug("'{Claim}' was excluded from the access token claims.", claim.Type);

//                    return false;
//                }

//                return true;
//            });

//            // Remove the destinations from the claim properties.
//            foreach (var claim in principal.Claims)
//            {
//                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
//            }

//            var identity = (ClaimsIdentity)principal.Identity;

//            // Create a new ticket containing the updated properties and the filtered principal.
//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
//            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
//            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
//            ticket.Properties.ExpiresUtc += ticket.GetAccessTokenLifetime() ?? Options.AccessTokenLifetime;

//            // Associate a random identifier with the access token.
//            ticket.SetTokenId(Guid.NewGuid().ToString());
//            ticket.SetAudiences(ticket.GetResources());

//            // Remove the unwanted properties from the authentication ticket.
//            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

//            var notification = new SerializeAccessTokenContext(Context, Scheme, Options, request, response, ticket)
//            {
//                DataFormat = Options.AccessTokenFormat,
//                EncryptingCredentials = Options.EncryptingCredentials.FirstOrDefault(
//                    credentials => credentials.Key is SymmetricSecurityKey),
//                Issuer = Context.GetIssuer(Options),
//                SecurityTokenHandler = Options.AccessTokenHandler,
//                SigningCredentials = Options.SigningCredentials.FirstOrDefault(
//                    credentials => credentials.Key is SymmetricSecurityKey) ?? Options.SigningCredentials.FirstOrDefault()
//            };

//            await Provider.SerializeAccessToken(notification);

//            if (notification.IsHandled || !string.IsNullOrEmpty(notification.AccessToken))
//            {
//                return notification.AccessToken;
//            }

//            if (notification.SecurityTokenHandler == null)
//            {
//                if (notification.DataFormat == null)
//                {
//                    throw new InvalidOperationException("A security token handler or data formatter must be provided.");
//                }

//                var value = notification.DataFormat.Protect(ticket);

//                Logger.LogTrace("A new access token was successfully generated using the " +
//                                "specified data format: {Token} ; {Claims} ; {Properties}.",
//                                value, ticket.Principal.Claims, ticket.Properties.Items);

//                return value;
//            }

//            // At this stage, throw an exception if no signing credentials were provided.
//            if (notification.SigningCredentials == null)
//            {
//                throw new InvalidOperationException("A signing key must be provided.");
//            }

//            // Extract the main identity from the principal.
//            identity = (ClaimsIdentity)ticket.Principal.Identity;

//            // Store the "usage" property as a claim.
//            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.AccessToken);

//            // Store the "unique_id" property as a claim.
//            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTokenId());

//            // Store the "confidentiality_level" property as a claim.
//            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
//            if (!string.IsNullOrEmpty(confidentiality))
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
//            }

//            // Create a new claim per scope item, that will result
//            // in a "scope" array being added in the access token.
//            foreach (var scope in notification.Scopes)
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.Scope, scope);
//            }

//            // Store the audiences as claims.
//            foreach (var audience in notification.Audiences)
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
//            }

//            // Extract the presenters from the authentication ticket.
//            var presenters = notification.Presenters.ToArray();
//            switch (presenters.Length)
//            {
//                case 0: break;

//                case 1:
//                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
//                    break;

//                default:
//                    Logger.LogWarning("Multiple presenters have been associated with the access token " +
//                                      "but the JWT format only accepts single values.");

//                    // Only add the first authorized party.
//                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
//                    break;
//            }

//            var token = notification.SecurityTokenHandler.CreateEncodedJwt(new SecurityTokenDescriptor
//            {
//                Subject = identity,
//                Issuer = notification.Issuer,
//                EncryptingCredentials = notification.EncryptingCredentials,
//                SigningCredentials = notification.SigningCredentials,
//                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
//                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
//                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
//            });

//            Logger.LogTrace("A new access token was successfully generated using the specified " +
//                            "security token handler: {Token} ; {Claims} ; {Properties}.",
//                            token, ticket.Principal.Claims, ticket.Properties.Items);

//            return token;
//        }

//        private async Task<string> SerializeIdentityTokenAsync(
//            ClaimsPrincipal principal, AuthenticationProperties properties,
//            OpenIdConnectRequest request, OpenIdConnectResponse response)
//        {
//            // Replace the principal by a new one containing only the filtered claims.
//            // Actors identities are also filtered (delegation scenarios).
//            principal = principal.Clone(claim =>
//            {
//                // Never exclude the subject claim.
//                if (string.Equals(claim.Type, OpenIdConnectConstants.Claims.Subject, StringComparison.OrdinalIgnoreCase))
//                {
//                    return true;
//                }

//                // Claims whose destination is not explicitly referenced or doesn't
//                // contain "id_token" are not included in the identity token.
//                if (!claim.HasDestination(OpenIdConnectConstants.Destinations.IdentityToken))
//                {
//                    Logger.LogDebug("'{Claim}' was excluded from the identity token claims.", claim.Type);

//                    return false;
//                }

//                return true;
//            });

//            // Remove the destinations from the claim properties.
//            foreach (var claim in principal.Claims)
//            {
//                claim.Properties.Remove(OpenIdConnectConstants.Properties.Destinations);
//            }

//            var identity = (ClaimsIdentity)principal.Identity;

//            // Create a new ticket containing the updated properties and the filtered principal.
//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
//            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
//            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
//            ticket.Properties.ExpiresUtc += ticket.GetIdentityTokenLifetime() ?? Options.IdentityTokenLifetime;

//            // Associate a random identifier with the identity token.
//            ticket.SetTokenId(Guid.NewGuid().ToString());

//            // Remove the unwanted properties from the authentication ticket.
//            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AccessTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.IdentityTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.RefreshTokenLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

//            ticket.SetAudiences(ticket.GetPresenters());

//            var notification = new SerializeIdentityTokenContext(Context, Scheme, Options, request, response, ticket)
//            {
//                Issuer = Context.GetIssuer(Options),
//                SecurityTokenHandler = Options.IdentityTokenHandler,
//                SigningCredentials = Options.SigningCredentials.FirstOrDefault(
//                    credentials => credentials.Key is AsymmetricSecurityKey)
//            };

//            await Provider.SerializeIdentityToken(notification);

//            if (notification.IsHandled || !string.IsNullOrEmpty(notification.IdentityToken))
//            {
//                return notification.IdentityToken;
//            }

//            if (notification.SecurityTokenHandler == null)
//            {
//                throw new InvalidOperationException("A security token handler must be provided.");
//            }

//            // Extract the main identity from the principal.
//            identity = (ClaimsIdentity)ticket.Principal.Identity;

//            if (string.IsNullOrEmpty(identity.GetClaim(OpenIdConnectConstants.Claims.Subject)))
//            {
//                throw new InvalidOperationException("The authentication ticket was rejected because " +
//                                                    "the mandatory subject claim was missing.");
//            }

//            // Note: identity tokens must be signed but an exception is made by the OpenID Connect specification
//            // when they are returned from the token endpoint: in this case, signing is not mandatory, as the TLS
//            // server validation can be used as a way to ensure an identity token was issued by a trusted party.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
//            if (notification.SigningCredentials == null && request.IsAuthorizationRequest())
//            {
//                throw new InvalidOperationException("A signing key must be provided.");
//            }

//            // Store the "usage" property as a claim.
//            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

//            // Store the "unique_id" property as a claim.
//            identity.AddClaim(OpenIdConnectConstants.Claims.JwtId, ticket.GetTokenId());

//            // Store the "confidentiality_level" property as a claim.
//            var confidentiality = ticket.GetProperty(OpenIdConnectConstants.Properties.ConfidentialityLevel);
//            if (!string.IsNullOrEmpty(confidentiality))
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel, confidentiality);
//            }

//            // Store the audiences as claims.
//            foreach (var audience in notification.Audiences)
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.Audience, audience);
//            }

//            // If a nonce was present in the authorization request, it MUST
//            // be included in the id_token generated by the token endpoint.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
//            var nonce = request.Nonce;
//            if (request.IsAuthorizationCodeGrantType())
//            {
//                // Restore the nonce stored in the authentication
//                // ticket extracted from the authorization code.
//                nonce = ticket.GetProperty(OpenIdConnectConstants.Properties.Nonce);
//            }

//            if (!string.IsNullOrEmpty(nonce))
//            {
//                identity.AddClaim(OpenIdConnectConstants.Claims.Nonce, nonce);
//            }

//            if (notification.SigningCredentials != null && (!string.IsNullOrEmpty(response.Code) ||
//                                                            !string.IsNullOrEmpty(response.AccessToken)))
//            {
//                using (var algorithm = OpenIdConnectServerHelpers.GetHashAlgorithm(notification.SigningCredentials.Algorithm))
//                {
//                    // Create an authorization code hash if necessary.
//                    if (!string.IsNullOrEmpty(response.Code))
//                    {
//                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.Code));

//                        // Note: only the left-most half of the hash of the octets is used.
//                        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
//                        identity.AddClaim(OpenIdConnectConstants.Claims.CodeHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
//                    }

//                    // Create an access token hash if necessary.
//                    if (!string.IsNullOrEmpty(response.AccessToken))
//                    {
//                        var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));

//                        // Note: only the left-most half of the hash of the octets is used.
//                        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
//                        identity.AddClaim(OpenIdConnectConstants.Claims.AccessTokenHash, Base64UrlEncoder.Encode(hash, 0, hash.Length / 2));
//                    }
//                }
//            }

//            // Extract the presenters from the authentication ticket.
//            var presenters = notification.Presenters.ToArray();
//            switch (presenters.Length)
//            {
//                case 0: break;

//                case 1:
//                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
//                    break;

//                default:
//                    Logger.LogWarning("Multiple presenters have been associated with the identity token " +
//                                      "but the JWT format only accepts single values.");

//                    // Only add the first authorized party.
//                    identity.AddClaim(OpenIdConnectConstants.Claims.AuthorizedParty, presenters[0]);
//                    break;
//            }

//            var token = notification.SecurityTokenHandler.CreateEncodedJwt(new SecurityTokenDescriptor
//            {
//                Subject = identity,
//                Issuer = notification.Issuer,
//                EncryptingCredentials = notification.EncryptingCredentials,
//                SigningCredentials = notification.SigningCredentials,
//                IssuedAt = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
//                NotBefore = notification.Ticket.Properties.IssuedUtc?.UtcDateTime,
//                Expires = notification.Ticket.Properties.ExpiresUtc?.UtcDateTime
//            });

//            Logger.LogTrace("A new identity token was successfully generated using the specified " +
//                            "security token handler: {Token} ; {Claims} ; {Properties}.",
//                            token, ticket.Principal.Claims, ticket.Properties.Items);

//            return token;
//        }

//        private async Task<string> SerializeRefreshTokenAsync(
//            ClaimsPrincipal principal, AuthenticationProperties properties,
//            OpenIdConnectRequest request, OpenIdConnectResponse response)
//        {
//            // Note: claims in refresh tokens are never filtered as they are supposed to be opaque:
//            // SerializeAccessTokenAsync and SerializeIdentityTokenAsync are responsible of ensuring
//            // that subsequent access and identity tokens are correctly filtered.

//            // Create a new ticket containing the updated properties.
//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);
//            ticket.Properties.IssuedUtc = Options.SystemClock.UtcNow;
//            ticket.Properties.ExpiresUtc = ticket.Properties.IssuedUtc;
//            ticket.Properties.ExpiresUtc += ticket.GetRefreshTokenLifetime() ?? Options.RefreshTokenLifetime;

//            // Associate a random identifier with the refresh token.
//            ticket.SetTokenId(Guid.NewGuid().ToString());

//            // Remove the unwanted properties from the authentication ticket.
//            ticket.RemoveProperty(OpenIdConnectConstants.Properties.AuthorizationCodeLifetime)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallenge)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.CodeChallengeMethod)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.Nonce)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.OriginalRedirectUri)
//                  .RemoveProperty(OpenIdConnectConstants.Properties.TokenUsage);

//            var notification = new SerializeRefreshTokenContext(Context, Scheme, Options, request, response, ticket)
//            {
//                DataFormat = Options.RefreshTokenFormat
//            };

//            await Provider.SerializeRefreshToken(notification);

//            if (notification.IsHandled || !string.IsNullOrEmpty(notification.RefreshToken))
//            {
//                return notification.RefreshToken;
//            }

//            if (notification.DataFormat == null)
//            {
//                throw new InvalidOperationException("A data formatter must be provided.");
//            }

//            var result = notification.DataFormat.Protect(ticket);

//            Logger.LogTrace("A new refresh token was successfully generated using the " +
//                            "specified data format: {Token} ; {Claims} ; {Properties}.",
//                            result, ticket.Principal.Claims, ticket.Properties.Items);

//            return result;
//        }

//        private async Task<AuthenticationTicket> DeserializeAuthorizationCodeAsync(string code, OpenIdConnectRequest request)
//        {
//            var notification = new DeserializeAuthorizationCodeContext(Context, Scheme, Options, request, code)
//            {
//                DataFormat = Options.AuthorizationCodeFormat
//            };

//            await Provider.DeserializeAuthorizationCode(notification);

//            if (notification.IsHandled || notification.Ticket != null)
//            {
//                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

//                return notification.Ticket;
//            }

//            if (notification.DataFormat == null)
//            {
//                throw new InvalidOperationException("A data formatter must be provided.");
//            }

//            var ticket = notification.DataFormat.Unprotect(code);
//            if (ticket == null)
//            {
//                Logger.LogTrace("The received token was invalid or malformed: {Code}.", code);

//                return null;
//            }

//            // Note: since the data formatter relies on a data protector using different "purposes" strings
//            // per token type, the ticket returned by Unprotect() is guaranteed to be an authorization code.
//            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

//            Logger.LogTrace("The authorization code '{Code}' was successfully validated using " +
//                            "the specified token data format: {Claims} ; {Properties}.",
//                            code, ticket.Principal.Claims, ticket.Properties.Items);

//            return ticket;
//        }

//        private async Task<AuthenticationTicket> DeserializeAccessTokenAsync(string token, OpenIdConnectRequest request)
//        {
//            var notification = new DeserializeAccessTokenContext(Context, Scheme, Options, request, token)
//            {
//                DataFormat = Options.AccessTokenFormat,
//                SecurityTokenHandler = Options.AccessTokenHandler
//            };

//            // Note: ValidateAudience and ValidateLifetime are always set to false:
//            // if necessary, the audience and the expiration can be validated
//            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
//            notification.TokenValidationParameters = new TokenValidationParameters
//            {
//                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key),
//                NameClaimType = OpenIdConnectConstants.Claims.Name,
//                RoleClaimType = OpenIdConnectConstants.Claims.Role,
//                TokenDecryptionKeys = Options.EncryptingCredentials.Select(credentials => credentials.Key)
//                                                                   .Where(key => key is SymmetricSecurityKey),
//                ValidIssuer = Context.GetIssuer(Options),
//                ValidateAudience = false,
//                ValidateLifetime = false
//            };

//            await Provider.DeserializeAccessToken(notification);

//            if (notification.IsHandled || notification.Ticket != null)
//            {
//                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

//                return notification.Ticket;
//            }

//            var handler = notification.SecurityTokenHandler as ISecurityTokenValidator;
//            if (handler == null)
//            {
//                if (notification.DataFormat == null)
//                {
//                    throw new InvalidOperationException("A security token handler or data formatter must be provided.");
//                }

//                var value = notification.DataFormat.Unprotect(token);
//                if (value == null)
//                {
//                    Logger.LogTrace("The received token was invalid or malformed: {Token}.", token);

//                    return null;
//                }

//                // Note: since the data formatter relies on a data protector using different "purposes" strings
//                // per token type, the ticket returned by Unprotect() is guaranteed to be an access token.
//                value.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

//                Logger.LogTrace("The access token '{Token}' was successfully validated using " +
//                                "the specified token data format: {Claims} ; {Properties}.",
//                                token, value.Principal.Claims, value.Properties.Items);

//                return value;
//            }

//            SecurityToken securityToken;
//            ClaimsPrincipal principal;

//            try
//            {
//                if (!handler.CanReadToken(token))
//                {
//                    Logger.LogTrace("The access token '{Token}' was rejected by the security token handler.", token);

//                    return null;
//                }

//                principal = handler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
//            }

//            catch (Exception exception)
//            {
//                Logger.LogDebug("An exception occured while deserializing an identity token: {Exception}.", exception);

//                return null;
//            }

//            // Parameters stored in AuthenticationProperties are lost
//            // when the identity token is serialized using a security token handler.
//            // To mitigate that, they are inferred from the claims or the security token.
//            var properties = new AuthenticationProperties
//            {
//                ExpiresUtc = securityToken.ValidTo,
//                IssuedUtc = securityToken.ValidFrom
//            };

//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name)
//                .SetAudiences(principal.FindAll(OpenIdConnectConstants.Claims.Audience).Select(claim => claim.Value))
//                .SetConfidentialityLevel(principal.GetClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel))
//                .SetPresenters(principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty).Select(claim => claim.Value))
//                .SetScopes(principal.FindAll(OpenIdConnectConstants.Claims.Scope).Select(claim => claim.Value))
//                .SetTokenId(principal.GetClaim(OpenIdConnectConstants.Claims.JwtId))
//                .SetTokenUsage(principal.GetClaim(OpenIdConnectConstants.Claims.TokenUsage));

//            // Ensure that the received ticket is an access token.
//            if (!ticket.IsAccessToken())
//            {
//                Logger.LogTrace("The received token was not an access token: {Token}.", token);

//                return null;
//            }

//            Logger.LogTrace("The access token '{Token}' was successfully validated using " +
//                            "the specified security token handler: {Claims} ; {Properties}.",
//                            token, ticket.Principal.Claims, ticket.Properties.Items);

//            return ticket;
//        }

//        private async Task<AuthenticationTicket> DeserializeIdentityTokenAsync(string token, OpenIdConnectRequest request)
//        {
//            var notification = new DeserializeIdentityTokenContext(Context, Scheme, Options, request, token)
//            {
//                SecurityTokenHandler = Options.IdentityTokenHandler
//            };

//            // Note: ValidateAudience and ValidateLifetime are always set to false:
//            // if necessary, the audience and the expiration can be validated
//            // in InvokeIntrospectionEndpointAsync or InvokeTokenEndpointAsync.
//            notification.TokenValidationParameters = new TokenValidationParameters
//            {
//                IssuerSigningKeys = Options.SigningCredentials.Select(credentials => credentials.Key)
//                                                              .Where(key => key is AsymmetricSecurityKey),

//                NameClaimType = OpenIdConnectConstants.Claims.Name,
//                RoleClaimType = OpenIdConnectConstants.Claims.Role,
//                ValidIssuer = Context.GetIssuer(Options),
//                ValidateAudience = false,
//                ValidateLifetime = false
//            };

//            await Provider.DeserializeIdentityToken(notification);

//            if (notification.IsHandled || notification.Ticket != null)
//            {
//                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.IdToken);

//                return notification.Ticket;
//            }

//            if (notification.SecurityTokenHandler == null)
//            {
//                throw new InvalidOperationException("A security token handler must be provided.");
//            }

//            SecurityToken securityToken;
//            ClaimsPrincipal principal;

//            try
//            {
//                if (!notification.SecurityTokenHandler.CanReadToken(token))
//                {
//                    Logger.LogTrace("The identity token '{Token}' was rejected by the security token handler.", token);

//                    return null;
//                }

//                principal = notification.SecurityTokenHandler.ValidateToken(token, notification.TokenValidationParameters, out securityToken);
//            }

//            catch (Exception exception)
//            {
//                Logger.LogDebug("An exception occured while deserializing an identity token: {Exception}.", exception);

//                return null;
//            }

//            // Parameters stored in AuthenticationProperties are lost
//            // when the identity token is serialized using a security token handler.
//            // To mitigate that, they are inferred from the claims or the security token.
//            var properties = new AuthenticationProperties
//            {
//                ExpiresUtc = securityToken.ValidTo,
//                IssuedUtc = securityToken.ValidFrom
//            };

//            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name)
//                .SetAudiences(principal.FindAll(OpenIdConnectConstants.Claims.Audience).Select(claim => claim.Value))
//                .SetConfidentialityLevel(principal.GetClaim(OpenIdConnectConstants.Claims.ConfidentialityLevel))
//                .SetPresenters(principal.FindAll(OpenIdConnectConstants.Claims.AuthorizedParty).Select(claim => claim.Value))
//                .SetTokenId(principal.GetClaim(OpenIdConnectConstants.Claims.JwtId))
//                .SetTokenUsage(principal.GetClaim(OpenIdConnectConstants.Claims.TokenUsage));

//            // Ensure that the received ticket is an identity token.
//            if (!ticket.IsIdentityToken())
//            {
//                Logger.LogTrace("The received token was not an identity token: {Token}.", token);

//                return null;
//            }

//            Logger.LogTrace("The identity token '{Token}' was successfully validated using " +
//                            "the specified security token handler: {Claims} ; {Properties}.",
//                            token, ticket.Principal.Claims, ticket.Properties.Items);

//            return ticket;
//        }

//        private async Task<AuthenticationTicket> DeserializeRefreshTokenAsync(string token, OpenIdConnectRequest request)
//        {
//            var notification = new DeserializeRefreshTokenContext(Context, Scheme, Options, request, token)
//            {
//                DataFormat = Options.RefreshTokenFormat
//            };

//            await Provider.DeserializeRefreshToken(notification);

//            if (notification.IsHandled || notification.Ticket != null)
//            {
//                notification.Ticket?.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

//                return notification.Ticket;
//            }

//            if (notification.DataFormat == null)
//            {
//                throw new InvalidOperationException("A data formatter must be provided.");
//            }

//            var ticket = notification.DataFormat.Unprotect(token);
//            if (ticket == null)
//            {
//                Logger.LogTrace("The received token was invalid or malformed: {Token}.", token);

//                return null;
//            }

//            // Note: since the data formatter relies on a data protector using different "purposes" strings
//            // per token type, the ticket returned by Unprotect() is guaranteed to be a refresh token.
//            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

//            Logger.LogTrace("The refresh token '{Token}' was successfully validated using " +
//                            "the specified token data format: {Claims} ; {Properties}.",
//                            token, ticket.Principal.Claims, ticket.Properties.Items);

//            return ticket;
//        }

//        private async Task<bool> InvokeLogoutEndpointAsync()
//        {
//            OpenIdConnectRequest request;

//            // Note: logout requests must be made via GET but POST requests
//            // are also accepted to allow flowing large logout payloads.
//            // See https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
//            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                request = new OpenIdConnectRequest(Request.Query);
//            }

//            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
//                if (string.IsNullOrEmpty(Request.ContentType))
//                {
//                    Logger.LogError("The logout request was rejected because " +
//                                    "the mandatory 'Content-Type' header was missing.");

//                    return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The mandatory 'Content-Type' header must be specified."
//                    });
//                }

//                // May have media/type; charset=utf-8, allow partial match.
//                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//                {
//                    Logger.LogError("The logout request was rejected because an invalid 'Content-Type' " +
//                                    "header was specified: {ContentType}.", Request.ContentType);

//                    return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                    {
//                        Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                        ErrorDescription = "The specified 'Content-Type' header is not valid."
//                    });
//                }

//                request = new OpenIdConnectRequest(await Request.ReadFormAsync(Context.RequestAborted));
//            }

//            else
//            {
//                Logger.LogError("The logout request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // Note: set the message type before invoking the ExtractLogoutRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.LogoutRequest);

//            // Store the logout request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractLogoutRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractLogoutRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The logout request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default logout request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The logout request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            var context = new ValidateLogoutRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateLogoutRequest(context);

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The logout request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default logout request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            // Store the validated post_logout_redirect_uri as a request property.
//            request.SetProperty(OpenIdConnectConstants.Properties.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

//            Logger.LogInformation("The logout request was successfully validated.");

//            var notification = new HandleLogoutRequestContext(Context, Scheme, Options, request);
//            await Provider.HandleLogoutRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The logout request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default logout request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The logout request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendLogoutResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            return false;
//        }

//        private async Task<bool> SendLogoutResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.LogoutResponse);

//            // Note: as this stage, the request may be null (e.g if it couldn't be extracted from the HTTP request).
//            var notification = new ApplyLogoutResponseContext(Context, Scheme, Options, request, response)
//            {
//                PostLogoutRedirectUri = request?.GetProperty<string>(OpenIdConnectConstants.Properties.PostLogoutRedirectUri)
//            };

//            await Provider.ApplyLogoutResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The logout request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default logout request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            if (!string.IsNullOrEmpty(response.Error))
//            {
//                // Apply a 400 status code by default.
//                Response.StatusCode = 400;

//                if (Options.ApplicationCanDisplayErrors)
//                {
//                    // Return false to allow the rest of
//                    // the pipeline to handle the request.
//                    return false;
//                }

//                Logger.LogInformation("The logout response was successfully returned " +
//                                      "as a plain-text document: {Response}.", response);

//                return await SendNativePageAsync(response);
//            }

//            // Don't redirect the user agent if no explicit post_logout_redirect_uri was
//            // provided or if the URI was not fully validated by the application code.
//            if (string.IsNullOrEmpty(notification.PostLogoutRedirectUri))
//            {
//                Logger.LogInformation("The logout response was successfully returned: {Response}.", response);

//                return true;
//            }

//            // At this stage, throw an exception if the request was not properly extracted,
//            if (request == null)
//            {
//                throw new InvalidOperationException("The logout response cannot be returned.");
//            }

//            // Attach the request state to the end session response.
//            if (string.IsNullOrEmpty(response.State))
//            {
//                response.State = request.State;
//            }

//            // Create a new parameters dictionary holding the name/value pairs.
//            var parameters = new Dictionary<string, string>();

//            foreach (var parameter in response.GetParameters())
//            {
//                // Ignore null or empty parameters, including JSON
//                // objects that can't be represented as strings.
//                var value = (string)parameter.Value;
//                if (string.IsNullOrEmpty(value))
//                {
//                    continue;
//                }

//                parameters.Add(parameter.Key, value);
//            }

//            Logger.LogInformation("The logout response was successfully returned to '{PostLogoutRedirectUri}': {Response}.",
//                                  notification.PostLogoutRedirectUri, response);

//            var location = QueryHelpers.AddQueryString(notification.PostLogoutRedirectUri, parameters);

//            Response.Redirect(location);
//            return true;
//        }

//        private async Task<bool> InvokeUserinfoEndpointAsync()
//        {
//            OpenIdConnectRequest request;

//            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
//            {
//                request = new OpenIdConnectRequest(Request.Query);
//            }

//            else if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
//            {
//                // Note: if no Content-Type header was specified, assume the userinfo request
//                // doesn't contain any parameter and create an empty OpenIdConnectRequest.
//                if (string.IsNullOrEmpty(Request.ContentType))
//                {
//                    request = new OpenIdConnectRequest();
//                }

//                else
//                {
//                    // May have media/type; charset=utf-8, allow partial match.
//                    if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
//                    {
//                        Logger.LogError("The userinfo request was rejected because an invalid 'Content-Type' " +
//                                        "header was specified: {ContentType}.", Request.ContentType);

//                        return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The specified 'Content-Type' header is not valid."
//                        });
//                    }

//                    request = new OpenIdConnectRequest(await Request.ReadFormAsync());
//                }
//            }

//            else
//            {
//                Logger.LogError("The userinfo request was rejected because an invalid " +
//                                "HTTP method was specified: {Method}.", Request.Method);

//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The specified HTTP method is not valid."
//                });
//            }

//            // Note: set the message type before invoking the ExtractUserinfoRequest event.
//            request.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                OpenIdConnectConstants.MessageTypes.UserinfoRequest);

//            // Insert the userinfo request in the ASP.NET context.
//            Context.SetOpenIdConnectRequest(request);

//            var @event = new ExtractUserinfoRequestContext(Context, Scheme, Options, request);
//            await Provider.ExtractUserinfoRequest(@event);

//            if (@event.Result != null)
//            {
//                if (@event.Result.Handled)
//                {
//                    Logger.LogDebug("The userinfo request was handled in user code.");

//                    return true;
//                }

//                else if (@event.Result.Skipped)
//                {
//                    Logger.LogDebug("The default userinfo request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (@event.IsRejected)
//            {
//                Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ @event.ErrorDescription);

//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = @event.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = @event.ErrorDescription,
//                    ErrorUri = @event.ErrorUri
//                });
//            }

//            Logger.LogInformation("The userinfo request was successfully extracted " +
//                                  "from the HTTP request: {Request}.", request);

//            string token = null;
//            if (!string.IsNullOrEmpty(request.AccessToken))
//            {
//                token = request.AccessToken;
//            }

//            else
//            {
//                string header = Request.Headers[HeaderNames.Authorization];
//                if (!string.IsNullOrEmpty(header))
//                {
//                    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
//                    {
//                        Logger.LogError("The userinfo request was rejected because the " +
//                                        "'Authorization' header was invalid: {Header}.", header);

//                        return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                        {
//                            Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                            ErrorDescription = "The specified 'Authorization' header is invalid."
//                        });
//                    }

//                    token = header.Substring("Bearer ".Length);
//                }
//            }

//            if (string.IsNullOrEmpty(token))
//            {
//                Logger.LogError("The userinfo request was rejected because the access token was missing.");

//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = "The mandatory 'access_token' parameter is missing."
//                });
//            }

//            var context = new ValidateUserinfoRequestContext(Context, Scheme, Options, request);
//            await Provider.ValidateUserinfoRequest(context);

//            if (context.Result != null)
//            {
//                if (context.Result.Handled)
//                {
//                    Logger.LogDebug("The userinfo request was handled in user code.");

//                    return true;
//                }

//                else if (context.Result.Skipped)
//                {
//                    Logger.LogDebug("The default userinfo request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (context.IsRejected)
//            {
//                Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ context.ErrorDescription);

//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = context.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = context.ErrorDescription,
//                    ErrorUri = context.ErrorUri
//                });
//            }

//            Logger.LogInformation("The userinfo request was successfully validated.");

//            var ticket = await DeserializeAccessTokenAsync(token, request);
//            if (ticket == null)
//            {
//                Logger.LogError("The userinfo request was rejected because the access token was invalid.");

//                // Note: an invalid token should result in an unauthorized response
//                // but returning a 401 status would invoke the previously registered
//                // authentication middleware and potentially replace it by a 302 response.
//                // To work around this limitation, a 400 error is returned instead.
//                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                    ErrorDescription = "The specified access token is not valid."
//                });
//            }

//            if (ticket.Properties.ExpiresUtc.HasValue &&
//                ticket.Properties.ExpiresUtc < Options.SystemClock.UtcNow)
//            {
//                Logger.LogError("The userinfo request was rejected because the access token was expired.");

//                // Note: an invalid token should result in an unauthorized response
//                // but returning a 401 status would invoke the previously registered
//                // authentication middleware and potentially replace it by a 302 response.
//                // To work around this limitation, a 400 error is returned instead.
//                // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoError
//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
//                    ErrorDescription = "The specified access token is no longer valid."
//                });
//            }

//            var notification = new HandleUserinfoRequestContext(Context, Scheme, Options, request, ticket)
//            {
//                Issuer = Context.GetIssuer(Options),
//                Subject = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Subject)
//            };

//            // Note: when receiving an access token, its audiences list cannot be used for the "aud" claim
//            // as the client application is not the intented audience but only an authorized presenter.
//            // See http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
//            notification.Audiences.UnionWith(ticket.GetPresenters());

//            // The following claims are all optional and should be excluded when
//            // no corresponding value has been found in the authentication ticket.
//            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Profile))
//            {
//                notification.FamilyName = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.FamilyName);
//                notification.GivenName = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.GivenName);
//                notification.BirthDate = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Birthdate);
//            }

//            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Email))
//            {
//                notification.Email = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.Email);
//            }

//            if (ticket.HasScope(OpenIdConnectConstants.Scopes.Phone))
//            {
//                notification.PhoneNumber = ticket.Principal.GetClaim(OpenIdConnectConstants.Claims.PhoneNumber);
//            }

//            await Provider.HandleUserinfoRequest(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The userinfo request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default userinfo request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            else if (notification.IsRejected)
//            {
//                Logger.LogError("The userinfo request was rejected with the following error: {Error} ; {Description}",
//                                /* Error: */ notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                                /* Description: */ notification.ErrorDescription);

//                return await SendUserinfoResponseAsync(new OpenIdConnectResponse
//                {
//                    Error = notification.Error ?? OpenIdConnectConstants.Errors.InvalidRequest,
//                    ErrorDescription = notification.ErrorDescription,
//                    ErrorUri = notification.ErrorUri
//                });
//            }

//            // Ensure the "sub" claim has been correctly populated.
//            if (string.IsNullOrEmpty(notification.Subject))
//            {
//                throw new InvalidOperationException("The subject claim cannot be null or empty.");
//            }

//            var response = new OpenIdConnectResponse
//            {
//                [OpenIdConnectConstants.Claims.Subject] = notification.Subject,
//                [OpenIdConnectConstants.Claims.Address] = notification.Address,
//                [OpenIdConnectConstants.Claims.Birthdate] = notification.BirthDate,
//                [OpenIdConnectConstants.Claims.Email] = notification.Email,
//                [OpenIdConnectConstants.Claims.EmailVerified] = notification.EmailVerified,
//                [OpenIdConnectConstants.Claims.FamilyName] = notification.FamilyName,
//                [OpenIdConnectConstants.Claims.GivenName] = notification.GivenName,
//                [OpenIdConnectConstants.Claims.Issuer] = notification.Issuer,
//                [OpenIdConnectConstants.Claims.PhoneNumber] = notification.PhoneNumber,
//                [OpenIdConnectConstants.Claims.PhoneNumberVerified] = notification.PhoneNumberVerified,
//                [OpenIdConnectConstants.Claims.PreferredUsername] = notification.PreferredUsername,
//                [OpenIdConnectConstants.Claims.Profile] = notification.Profile,
//                [OpenIdConnectConstants.Claims.Website] = notification.Website
//            };

//            switch (notification.Audiences.Count)
//            {
//                case 0: break;

//                case 1:
//                    response[OpenIdConnectConstants.Claims.Audience] = notification.Audiences.ElementAt(0);
//                    break;

//                default:
//                    response[OpenIdConnectConstants.Claims.Audience] = new JArray(notification.Audiences);
//                    break;
//            }

//            foreach (var claim in notification.Claims)
//            {
//                response.SetParameter(claim.Key, claim.Value);
//            }

//            return await SendUserinfoResponseAsync(response);
//        }

//        private async Task<bool> SendUserinfoResponseAsync(OpenIdConnectResponse response)
//        {
//            var request = Context.GetOpenIdConnectRequest();
//            Context.SetOpenIdConnectResponse(response);

//            response.SetProperty(OpenIdConnectConstants.Properties.MessageType,
//                                 OpenIdConnectConstants.MessageTypes.UserinfoResponse);

//            var notification = new ApplyUserinfoResponseContext(Context, Scheme, Options, request, response);
//            await Provider.ApplyUserinfoResponse(notification);

//            if (notification.Result != null)
//            {
//                if (notification.Result.Handled)
//                {
//                    Logger.LogDebug("The userinfo request was handled in user code.");

//                    return true;
//                }

//                else if (notification.Result.Skipped)
//                {
//                    Logger.LogDebug("The default userinfo request handling was skipped from user code.");

//                    return false;
//                }
//            }

//            Logger.LogInformation("The userinfo response was successfully returned: {Response}.", response);

//            return await SendPayloadAsync(response);
//        }


//    }
//}
