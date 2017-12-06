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
    public class AuthorizationStore<TAuthorization> : IOpenIddictAuthorizationStore<TAuthorization>
        where TAuthorization : Authorization
    {
        private readonly IMongoDbContext dbContext;

        public AuthorizationStore(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        Task<long> IOpenIddictAuthorizationStore<TAuthorization>.CountAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<long> IOpenIddictAuthorizationStore<TAuthorization>.CountAsync<TResult>(Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<TAuthorization> IOpenIddictAuthorizationStore<TAuthorization>.CreateAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<TAuthorization> IOpenIddictAuthorizationStore<TAuthorization>.CreateAsync(OpenIddictAuthorizationDescriptor descriptor, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IOpenIddictAuthorizationStore<TAuthorization>.DeleteAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<TAuthorization> IOpenIddictAuthorizationStore<TAuthorization>.FindAsync(string subject, string client, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<TAuthorization> IOpenIddictAuthorizationStore<TAuthorization>.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<string> IOpenIddictAuthorizationStore<TAuthorization>.GetApplicationIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<TResult> IOpenIddictAuthorizationStore<TAuthorization>.GetAsync<TResult>(Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<string> IOpenIddictAuthorizationStore<TAuthorization>.GetIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<string> IOpenIddictAuthorizationStore<TAuthorization>.GetStatusAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<string> IOpenIddictAuthorizationStore<TAuthorization>.GetSubjectAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<string> IOpenIddictAuthorizationStore<TAuthorization>.GetTypeAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<ImmutableArray<TAuthorization>> IOpenIddictAuthorizationStore<TAuthorization>.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<ImmutableArray<TResult>> IOpenIddictAuthorizationStore<TAuthorization>.ListAsync<TResult>(Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<ImmutableArray<TAuthorization>> IOpenIddictAuthorizationStore<TAuthorization>.ListInvalidAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IOpenIddictAuthorizationStore<TAuthorization>.SetApplicationIdAsync(TAuthorization authorization, string identifier, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IOpenIddictAuthorizationStore<TAuthorization>.SetStatusAsync(TAuthorization authorization, string status, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IOpenIddictAuthorizationStore<TAuthorization>.SetTypeAsync(TAuthorization authorization, string type, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IOpenIddictAuthorizationStore<TAuthorization>.UpdateAsync(TAuthorization authorization, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
