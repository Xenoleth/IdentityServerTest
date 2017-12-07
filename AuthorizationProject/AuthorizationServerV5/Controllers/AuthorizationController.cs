using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using AuthorizationServerV5.External;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using System.Collections.Generic;
using System.Linq;
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
        //private readonly UserManager<ApplicationUser> userManager;
        private readonly IMongoDbContext dbContext;

        public AuthorizationController(
            //IOptions<IdentityOptions> identityOptions,
            //SignInManager<ApplicationUser> signInManager,
            IMongoDbContext dbContext
            )
        {
            this.dbContext = dbContext;
        }

        [HttpPost("~/connect/token"), Produces("application/json")]
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
                var user = new ApplicationUser()
                {
                    Identifier = bsonUser[0]["_id"].ToString(),
                    Username = bsonUser[0]["username"].ToString(),
                    Password = bsonUser[0]["password"].ToString()
                };

                if (user.Username != "alice@wonderland.com" ||
                    user.Password != "P@ssw0rd")
                {
                    return Forbid(OpenIdConnectServerDefaults.AuthenticationScheme);
                }
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
                    user.Identifier,
                    OpenIdConnectConstants.Destinations.AccessToken);
                identity.AddClaim(OpenIdConnectConstants.Claims.Name, user.Username,
                    OpenIdConnectConstants.Destinations.AccessToken);
                // ... add other claims, if necessary.
                var principal = new ClaimsPrincipal(identity);

                //var ticket = CreateTicket(request, principal);
                var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);
                ticket.SetScopes(new[]
{
                    //OpenIdConnectConstants.Scopes.OpenId,
                    //OpenIdConnectConstants.Scopes.Email,
                    //OpenIdConnectConstants.Scopes.Profile,
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
