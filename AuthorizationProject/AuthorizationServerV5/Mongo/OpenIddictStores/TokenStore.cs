using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;
using OpenIddict.Core;
using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo.OpenIddictStores
{
    public class TokenStore<TToken> : IOpenIddictTokenStore<TToken>
        where TToken : Token
    {
        private readonly IMongoDbContext dbContext;

        public TokenStore(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public Task<long> CountAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<long> CountAsync<TResult>(Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TToken> CreateAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TToken> CreateAsync(OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task DeleteAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TToken>> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TToken> FindByHashAsync(string hash, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TToken> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TToken>> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TResult> GetAsync<TResult>(Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetCiphertextAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetHashAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetIdAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetStatusAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetSubjectAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetTokenTypeAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TToken>> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TResult>> ListAsync<TResult>(Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TToken>> ListInvalidAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetApplicationIdAsync(TToken token, string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetAuthorizationIdAsync(TToken token, string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetExpirationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetStatusAsync(TToken token, string status, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(TToken token, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
