using System.Threading.Tasks;

namespace AuthorizationServerV5.Facebook
{
    public interface IFacebookService
    {
        Task<Account> GetAccountAsync(string accessToken);
    }
}
