using AuthorizationServerV2.External;
using AuthorizationServerV2.Repository;
using AuthorizationServerV2.Store;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MongoDB.Driver;

namespace AuthorizationServerV2.Extensions
{
    public static class IdentityServerBuilderExtensions
    {
        public static IIdentityServerBuilder AddMongoRepository(this IIdentityServerBuilder builder)
        {
            builder.Services.AddTransient<IRepository, MongoRepository>();
            return builder;
        }

        public static IIdentityServerBuilder AddMongoDbForAspIdentity<TIdentity, TRole>(this IIdentityServerBuilder builder, IConfiguration configuration)
            where TIdentity : External.IdentityUser where TRole : External.IdentityRole
        {
            var configurationOptions = configuration.Get<ConfigurationOptions>();
            // TODO: Inject connectionString and dbName
            var client = new MongoClient(
                //configurationOptions.MongoConnection
                "mongodb://localhost:27017"
                );
            var database = client.GetDatabase(
                //configurationOptions.MongoDatabaseName
                "testDatabase"
                );

            // Changed to return UserStore instead of interface IUserStore to work
            builder.Services.AddSingleton<IUserStore<TIdentity>>(x =>
            {
                var usersCollection = database.GetCollection<TIdentity>("Identity_Users");
                IndexChecks.EnsureUniqueIndexOnNormalizedEmail(usersCollection);
                IndexChecks.EnsureUniqueIndexOnNormalizedUserName(usersCollection);
                return new External.UserStore<TIdentity>(usersCollection);
            });

            // Changed to return RoleStore instead of interface IRoleStore to work
            builder.Services.AddSingleton<RoleStore<TRole>>(x =>
            {
                var rolesCollection = database.GetCollection<TRole>("Identity_Roles");
                IndexChecks.EnsureUniqueIndexOnNormalizedRoleName(rolesCollection);
                return new RoleStore<TRole>(rolesCollection);
            });
            // TODO: Add password settings, etc.
            // https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration?tabs=aspnetcore2x
            builder.Services.AddIdentity<TIdentity, TRole>();

            return builder;
        }

        public static IIdentityServerBuilder AddClients(this IIdentityServerBuilder builder)
        {
            builder.Services.AddTransient<IClientStore, CustomClientStore>();
            builder.Services.AddTransient<ICorsPolicyService, InMemoryCorsPolicyService>();
            return builder;
        }

        public static IIdentityServerBuilder AddIdentityApiResources(this IIdentityServerBuilder builder)
        {
            builder.Services.AddTransient<IResourceStore, CustomResourceStore>();
            return builder;
        }

        public static IIdentityServerBuilder AddPersistedGrants(this IIdentityServerBuilder builder)
        {
            builder.Services.TryAddSingleton<IPersistedGrantStore, CustomPersistedGrantStore>();
            return builder;
        }

    }
}
