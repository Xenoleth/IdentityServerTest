using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using AuthorizationServerV5.Facebook;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
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

        [HttpPost("~/asd/google-login")]
        [Produces("application/json")]
        public async Task<IActionResult> GoogleLogin()
        {
            // Exchange recieved Authorization Code for an access token
            var tokenUrl = "https://www.googleapis.com/oauth2/v4/token";

            var code = "4/1VeXJLNmmH2dIYR8FSeW3OaVlYpK7BtZwVAhqzLvErk";
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
            var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(data)
            };
            var response = await httpClient.SendAsync(request);
            var responseContent = await response.Content.ReadAsStringAsync();
            var responseContentDeserializrd = JsonConvert.DeserializeObject<ResponseData>(responseContent);
            var accessToken = responseContentDeserializrd.AccessToken;

            // Use the access token to request the user's info
            httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
            var userInfoUrl = "https://www.googleapis.com/oauth2/v1/userinfo";
            var userResponse = await httpClient.GetAsync(userInfoUrl);
            var userResponseContent = await userResponse.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<UserInfo>(userResponseContent);

            return new JsonResult(new { });
        }
    }

    public class FacebookToken
    {
        public string AccessToken { get; set; }
    }

    public class ResponseData
    {
        // Success response date
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("token_type")]
        public string TokenType { get; set; }
        [JsonProperty("expires_in")]
        public string ExpiresIn { get; set; }
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        [JsonProperty("id_token")]
        public string IdToken { get; set; }
        // Error response data
        [JsonProperty("error")]
        public string Error { get; set; }
        [JsonProperty("error_description")]
        public string ErrorDescription { get; set; }
    }

    public class UserInfo
    {
        public string Id { get; set; }
        public string Email { get; set; }
        [JsonProperty("verified_email")]
        public bool VerifiedEmail { get; set; }
        public string Name { get; set; }
        [JsonProperty("given_name")]
        public string GivenName { get; set; }
        [JsonProperty("family_name")]
        public string FamilyName { get; set; }
        public string Picture { get; set; }
        public string Locale { get; set; }
        public string Hd { get; set; }
    }
}
