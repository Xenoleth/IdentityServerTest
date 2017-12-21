using OpenIddict.Core;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Immutable;
using System.Threading;
using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;

namespace AuthorizationServerV5.Mongo.OpenIddictStores
{
    public class ApplicationStore<TApplication> : IOpenIddictApplicationStore<TApplication>
        where TApplication : Application
    {
        private readonly IMongoDbContext dbContext;

        public ApplicationStore(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public Task<long> CountAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<long> CountAsync<TResult>(Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public async Task<TApplication> CreateAsync(TApplication application, CancellationToken cancellationToken)
        {
            await this.dbContext.CreateApplication(application);

            return application;
        }

        public async Task<TApplication> CreateAsync(OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
        {
            var app = new Application()
            {
                ClientId = descriptor.ClientId,
                ClientSecret = descriptor.ClientSecret,
                DisplayName = descriptor.DisplayName,
                PostLogoutRedirectUris = descriptor.PostLogoutRedirectUris.ToString(),
                RedirectUris = descriptor.RedirectUris.ToString(),
                Type = descriptor.Type
            };

            await this.dbContext.CreateApplication(app);

            return app as TApplication;
        }

        public async Task DeleteAsync(TApplication application, CancellationToken cancellationToken)
        {
            await this.dbContext.DeleteApplication(application.Identifier);
        }

        public async Task<TApplication> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
        {
            var app = await this.dbContext.FindApplicationByClientId(identifier);

            return app as TApplication;
        }

        public async Task<TApplication> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            var app = await this.dbContext.FindApplicationById(identifier);

            return app as TApplication;
        }

        public Task<ImmutableArray<TApplication>> FindByPostLogoutRedirectUriAsync(string address, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TApplication>> FindByRedirectUriAsync(string address, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<TResult> GetAsync<TResult>(Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetClientIdAsync(TApplication application, CancellationToken cancellationToken)
        {
            return Task.Run(() => application.ClientId);
        }

        public Task<string> GetClientSecretAsync(TApplication application, CancellationToken cancellationToken)
        {
            return Task.Run(() => application.ClientSecret);
        }

        public Task<string> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken)
        {
            return Task.Run(() => "confidential");
        }

        public Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetIdAsync(TApplication application, CancellationToken cancellationToken)
        {
            return Task.Run(() => application.Identifier);
        }

        public Task<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(TApplication application, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<string>> GetRedirectUrisAsync(TApplication application, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<string>> GetTokensAsync(TApplication application, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TApplication>> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<ImmutableArray<TResult>> ListAsync<TResult>(Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetClientSecretAsync(TApplication application, string secret, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetClientTypeAsync(TApplication application, string type, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetPostLogoutRedirectUrisAsync(TApplication application, ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetRedirectUrisAsync(TApplication application, ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task UpdateAsync(TApplication application, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<Application> InstantiateAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new Application());
        }

        internal Task<TResult> GetAsync<TApplication, TState, TResult>(Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TApplication : Application
        {
            throw new NotImplementedException();
        }
    }
}
