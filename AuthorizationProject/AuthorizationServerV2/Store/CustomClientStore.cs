using AuthorizationServerV2.Repository;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using System.Threading.Tasks;

namespace AuthorizationServerV2.Store
{
    public class CustomClientStore : IClientStore
    {
        protected IRepository _dbRepository;

        public CustomClientStore(IRepository repository)
        {
            _dbRepository = repository;
        }

        public Task<Client> FindClientByIdAsync(string clientId)
        {
            return Task.Run(() =>
            {
                var client = _dbRepository.Single<Client>(c => c.ClientId == clientId);
                return client;
            });
        }
    }
}
