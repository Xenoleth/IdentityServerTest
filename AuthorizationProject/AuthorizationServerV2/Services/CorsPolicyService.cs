using System.Threading.Tasks;
using IdentityServer4.Services;

namespace AuthorizationServerV2.Services
{
    public class CorsPolicyService : ICorsPolicyService
    {
        public async Task<bool> IsOriginAllowedAsync(string origin)
        {
            // TODO: Add real allowed origins
            return true;
        }
    }
}
