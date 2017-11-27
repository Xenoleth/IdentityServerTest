using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthorizationServerV2.Services
{
    public class ProfileService : IProfileService
    {

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            //Extend here for custom data  and claims like email from user database
            context.IssuedClaims.Add(new Claim(ClaimValueTypes.Email, "foo@mail.foo"));
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.FromResult(true);
        }
    }
}
