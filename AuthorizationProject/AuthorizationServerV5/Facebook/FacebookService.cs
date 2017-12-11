using System.Threading.Tasks;

namespace AuthorizationServerV5.Facebook
{
    public class FacebookService : IFacebookService
    {
        private readonly IFacebookClient facebookClient;

        public FacebookService()
        {
            // TODO: Add dependency injection
            this.facebookClient = new FacebookClient();
        }

        public async Task<Account> GetAccountAsync(string accessToken)
        {
            var result = await this.facebookClient.GetAsync<dynamic>(accessToken, "me", "fields=id,name,email,first_name,last_name");

            if (result == null)
            {
                return new Account();
            }

            var account = new Account()
            {
                Id = result.id,
                Email = result.email,
                Username = result.name,
                FirstName = result.first_name,
                LastName = result.last_name
            };

            return account;
        }
    }
}
