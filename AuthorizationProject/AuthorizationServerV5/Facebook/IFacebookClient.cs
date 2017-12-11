using System.Threading.Tasks;

namespace AuthorizationServerV5.Facebook
{
    public interface IFacebookClient
    {
        Task<T> GetAsync<T>(string accessToken, string endpoint, string args = null);
    }
}
