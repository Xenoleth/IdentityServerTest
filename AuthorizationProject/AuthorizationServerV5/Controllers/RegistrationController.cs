using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using AuthorizationServerV5.Facebook;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Controllers
{
    public class RegistrationController : Controller
    {
        private readonly IMongoDbContext dbContext;
        private readonly IFacebookService facebookService;

        public RegistrationController(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
            this.facebookService = new FacebookService();
        }

        [HttpPost("~/asd/register")]
        [Produces("application/json")]
        public async Task<IActionResult> Register([FromBody]PropyUser user)
        {
            await this.dbContext.CreateUser(user);

            return new JsonResult(new
            {
                response = $"User with name {user.FirstName} was created"
            });
        }

        [HttpPost("~/asd/facebook-login")]
        [Produces("application/json")]
        public async Task<IActionResult> FacebookLogin([FromBody]FacebookToken tokenModel)
        {
            var account = await this.facebookService.GetAccountAsync(tokenModel.AccessToken);

            var bsonUser = await this.dbContext.GetUserByFacebookId(account.Id);
            PropyUser user;
            if (bsonUser.Count == 0)
            {
                user = new PropyUser()
                {

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
                    Id = Guid.NewGuid().ToString(),
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
    }

    public class FacebookToken
    {
        public string AccessToken { get; set; }
    }
}
