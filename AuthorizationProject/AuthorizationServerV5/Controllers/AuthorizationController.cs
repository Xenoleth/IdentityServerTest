using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using AuthorizationServerV5.External;
using AuthorizationServerV5.Facebook;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using OpenIddict.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Controllers
{
    //public class Request
    //{
    //    public string Username { get; set; }    
    //    public string Password { get; set; }
    //    public string GrantType { get; set; }
    //    public string RefreshToken { get; set; }
    //    public string scope { get; set; }
    //    public List<string> GetScopes()
    //    {
    //        return new List<string>()
    //        {
    //            "offlne_access"
    //        };
    //    }
    //}

    public class AuthorizationController : Controller
    {
        //private readonly IOptions<IdentityOptions> identityOptions;
        //private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<PropyUser> userManager;
        private readonly IMongoDbContext dbContext;
        private readonly IFacebookService facebookService;

        public AuthorizationController(
            //IOptions<IdentityOptions> identityOptions,
            //SignInManager<ApplicationUser> signInManager,
            UserManager<PropyUser> userManager,
            IMongoDbContext dbContext
            )
        {
            this.dbContext = dbContext;
            this.userManager = userManager;
            this.facebookService = new FacebookService();
        }

        [HttpGet("~/")]
        public IActionResult Test()
        {
            return new JsonResult(new
            {
                Value1 = 5,
                Value2 = 7
            });
        }

        [HttpGet("~/api/Properties/rect")]
        public IActionResult Test2()
        {
            return new JsonResult(new
            {
                Value1 = 5,
                Value2 = 7
            });
        }

        [HttpPost("~/token"), Produces("application/json")]
        public async Task<IActionResult> Exhange(OpenIdConnectRequest request)
        {
            if (request.IsPasswordGrantType())
            {
                //request.GrantType = "password";
                // Validate the user credentials.
                // Note: to mitigate brute force attacks, you SHOULD strongly consider
                // applying a key derivation function like PBKDF2 to slow down
                // the password validation process. You SHOULD also consider
                // using a time-constant comparer to prevent timing attacks.
                var bsonUser = await this.dbContext.GetUser(request.Username);

                var user = new PropyUser();
                if (bsonUser.Count == 0)
                {
                    user.Id = Guid.NewGuid().ToString();
                    user.UserName = "AnonUser";
                    user.PasswordHash = "AnonPass";
                    user.SecurityStamp = Guid.NewGuid().ToString();
                }
                else
                {
                    user = new PropyUser()
                    {
                        Id = bsonUser[0]["_id"].ToString(),
                        UserName = bsonUser[0]["UserName"].ToString(),
                        PasswordHash = bsonUser[0]["PasswordHash"].ToString(),
                        SecurityStamp = bsonUser[0]["SecurityStamp"].ToString()
                    };
                }

                // Check password hash
                var hasher = new PasswordHasher<PropyUser>();
                var verificationResult = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
                //if (user.Username != "alice@wonderland.com" ||
                //    user.Password != "P@ssw0rd")
                //{
                //    return Forbid(OpenIdConnectServerDefaults.AuthenticationScheme);
                //}
                // Create a new ClaimsIdentity holding the user identity.
                var identity = new ClaimsIdentity(
                    OpenIdConnectServerDefaults.AuthenticationScheme,
                    OpenIdConnectConstants.Claims.Name,
                    OpenIdConnectConstants.Claims.Role);
                // Add a "sub" claim containing the user identifier, and attach
                // the "access_token" destination to allow OpenIddict to store it
                // in the access token, so it can be retrieved from your controllers.
                //identity.AddClaim(OpenIdConnectConstants.Claims.Subject,
                //    "71346D62-9BA5-4B6D-9ECA-755574D628D8",
                //    OpenIdConnectConstants.Destinations.AccessToken);
                //identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Alice",
                //    OpenIdConnectConstants.Destinations.AccessToken);

                identity.AddClaim(OpenIdConnectConstants.Claims.Subject,
                    user.Id,
                    OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, user.UserName,
                    OpenIdConnectConstants.Destinations.AccessToken);
                // ... add other claims, if necessary.
                var principal = new ClaimsPrincipal(identity);

                //var ticket = CreateTicket(request, principal);
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);
                ticket.SetScopes(new[]
{
                    OpenIdConnectConstants.Scopes.OpenId,
                    OpenIdConnectConstants.Scopes.Email,
                    OpenIdConnectConstants.Scopes.Profile,
                    OpenIdConnectConstants.Scopes.OfflineAccess,
                    //OpenIddictConstants.Scopes.Roles
                }.Intersect(request.GetScopes()));

                // Ask OpenIddict to generate a new token and return an OAuth2 token response.
                //return SignIn(principal, OpenIdConnectServerDefaults.AuthenticationScheme);
                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }
            else if (request.IsRefreshTokenGrantType())
            {
                var info = await this.HttpContext.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

                // Create a new ClaimsIdentity holding the user identity.
                var identity = new ClaimsIdentity(
                    OpenIdConnectServerDefaults.AuthenticationScheme,
                    OpenIdConnectConstants.Claims.Name,
                    OpenIdConnectConstants.Claims.Role);
                // Add a "sub" claim containing the user identifier, and attach
                // the "access_token" destination to allow OpenIddict to store it
                // in the access token, so it can be retrieved from your controllers.
                identity.AddClaim(OpenIdConnectConstants.Claims.Subject,
                    "71346D62-9BA5-4B6D-9ECA-755574D628D8",
                    OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Alice",
                    OpenIdConnectConstants.Destinations.AccessToken);
                // ... add other claims, if necessary.
                var principal = new ClaimsPrincipal(identity);

                var ticket = new AuthenticationTicket(principal, info.Properties,
                OpenIdConnectServerDefaults.AuthenticationScheme);

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }
            else if (request.GrantType == "urn:ietf:params:oauth:grant-type:facebook_access_token")
            {
                var account = await this.facebookService.GetAccountAsync(request.Assertion);

                var bsonUser = await this.dbContext.GetUserByFacebookId(account.Id);
                PropyUser user;
                if (bsonUser.Count == 0)
                {
                    user = new PropyUser()
                    {
                        Id = request.Assertion,
                        FacebookId = account.Id,
                        UserName = account.Username,
                        FirstName = account.FirstName,
                        LastName = account.LastName,
                        Email = account.Email
                    };

                    await this.dbContext.CreateUser(user);
                }
                else
                {
                    user = new PropyUser()
                    {
                        Id = request.Assertion,
                        FacebookId = bsonUser[0]["facebookId"].ToString(),
                        UserName = bsonUser[0]["UserName"].ToString(),
                        FirstName = bsonUser[0]["firstName"].ToString(),
                        LastName = bsonUser[0]["lastName"].ToString(),
                        Email = bsonUser[0]["facebookId"].ToString(),
                    };
                }

                var identity = new ClaimsIdentity(
                        OpenIdConnectServerDefaults.AuthenticationScheme,
                        OpenIdConnectConstants.Claims.Name,
                        OpenIdConnectConstants.Claims.Role);

                identity.AddClaim(OpenIdConnectConstants.Claims.Subject,
                    user.Id,
                    OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, user.UserName,
                    OpenIdConnectConstants.Destinations.AccessToken);

                var principal = new ClaimsPrincipal(identity);

                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);
                ticket.SetScopes(new[]
                    {
                    OpenIdConnectConstants.Scopes.OfflineAccess,
                });

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }
            else if (request.GrantType == "urn:ietf:params:oauth:grant-type:google_identity_token")
            {
                // Exchange recieved Authorization Code for an access token
                var tokenUrl = "https://www.googleapis.com/oauth2/v4/token";

                //var code = "4/1VeXJLNmmH2dIYR8FSeW3OaVlYpK7BtZwVAhqzLvErk";
                var code = request.Assertion;
                var client_id = "295998800597-kao41iolosp6kl304dedl3u2551bogie.apps.googleusercontent.com";
                var client_secret = "z4VDv49a9aGMtQQK4NM8dZnn";
                var grant_type = "authorization_code";
                var redirect_uri = "http://localhost:5000";

                var data = new Dictionary<string, string>
                {
                    { "code", code },
                    { "client_id", client_id },
                    { "client_secret", client_secret },
                    { "grant_type", grant_type },
                    { "redirect_uri", redirect_uri }
                };

                var httpClient = new HttpClient();
                var requestToken = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
                {
                    Content = new FormUrlEncodedContent(data)
                };
                var response = await httpClient.SendAsync(requestToken);
                var responseContent = await response.Content.ReadAsStringAsync();
                var responseContentDeserializrd = JsonConvert.DeserializeObject<ResponseData>(responseContent);
                var accessToken = responseContentDeserializrd.AccessToken;

                // Use the access token to request the user's info
                httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                var userInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo";
                var userResponse = await httpClient.GetAsync(userInfoUrl);
                var userResponseContent = await userResponse.Content.ReadAsStringAsync();
                var userInfo = JsonConvert.DeserializeObject<UserInfo>(userResponseContent);

                // Create user if one does not exist, and log him in
                var user = new PropyUser();
                var bsonUser = await this.dbContext.GetUserByGoogleId(userInfo.Id);
                if (bsonUser.Count == 0)
                {
                    user.Id = Guid.NewGuid().ToString();
                    user.Email = userInfo.Email;
                    user.UserName = userInfo.Name;
                    user.FirstName = userInfo.GivenName;
                    user.LastName = userInfo.FamilyName;
                    user.GoogleId = userInfo.Id;

                    await this.dbContext.CreateUser(user);
                }
                else
                {
                    user.Id = Guid.NewGuid().ToString();
                    user.Email = bsonUser[0]["email"].ToString();
                    user.UserName = bsonUser[0]["UserName"].ToString();
                    user.FirstName = bsonUser[0]["firstName"].ToString();
                    user.LastName = bsonUser[0]["lastName"].ToString();
                    user.GoogleId = bsonUser[0]["googleId"].ToString();
                }

                // Create user's identity, a ticket and then sign him in
                var identity = new ClaimsIdentity(
                        OpenIdConnectServerDefaults.AuthenticationScheme,
                        OpenIdConnectConstants.Claims.Name,
                        OpenIdConnectConstants.Claims.Role);

                identity.AddClaim(OpenIdConnectConstants.Claims.Subject,
                    user.Id,
                    OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, user.UserName,
                    OpenIdConnectConstants.Destinations.AccessToken);

                var principal = new ClaimsPrincipal(identity);

                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);
                ticket.SetScopes(new[]
                    {
                    OpenIdConnectConstants.Scopes.OfflineAccess,
                });

                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            return BadRequest(new OpenIdConnectResponse
            {
                Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                ErrorDescription = "The specified grant type is not supported."
            });
        }

        private AuthenticationTicket CreateTicket(
            OpenIdConnectRequest request, ClaimsPrincipal principal,
            AuthenticationProperties properties = null)
        {
            // Create a new ClaimsPrincipal containing the claims that
            // will be used to create an id_token, a token or a code.
            //var principal = await this.signInManager.CreateUserPrincipalAsync(user);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(principal, properties,
                OpenIdConnectServerDefaults.AuthenticationScheme);

            if (!request.IsRefreshTokenGrantType())
            {
                // Set the list of scopes granted to the client application.
                // Note: the offline_access scope must be granted
                // to allow OpenIddict to return a refresh token.
                ticket.SetScopes(new[]
                {
                    OpenIdConnectConstants.Scopes.OpenId,
                    OpenIdConnectConstants.Scopes.Email,
                    OpenIdConnectConstants.Scopes.Profile,
                    OpenIdConnectConstants.Scopes.OfflineAccess,
                    OpenIddictConstants.Scopes.Roles
                }.Intersect(request.GetScopes()));
            }

            ticket.SetResources("resource_server");

            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            foreach (var claim in ticket.Principal.Claims)
            {
                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                //if (claim.Type == this.identityOptions.Value.ClaimsIdentity.SecurityStampClaimType)
                //{
                //    continue;
                //}

                var destinations = new List<string>
                {
                    OpenIdConnectConstants.Destinations.AccessToken
                };

                // Only add the iterated claim to the id_token if the corresponding scope was granted to the client application.
                // The other claims will only be added to the access_token, which is encrypted when using the default format.
                if ((claim.Type == OpenIdConnectConstants.Claims.Name && ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) ||
                    (claim.Type == OpenIdConnectConstants.Claims.Email && ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) ||
                    (claim.Type == OpenIdConnectConstants.Claims.Role && ticket.HasScope(OpenIddictConstants.Claims.Roles)))
                {
                    destinations.Add(OpenIdConnectConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }
    }
}
