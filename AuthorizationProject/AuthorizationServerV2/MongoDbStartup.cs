using AuthorizationServerV2.Configuration;
using AuthorizationServerV2.Repository;
using IdentityModel;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson.Serialization;
using System;
using System.Linq;

namespace AuthorizationServerV2
{
    public static class MongoDbStartup
    {
        private static string _newRepositoryMsg = $"Mongo Repository created/populated! Please restart your website, so Mongo driver will be configured  to ignore Extra Elements.";

        public static void UseMongoDbForIdentityServer(this IApplicationBuilder app)
        {
            var repository = app.ApplicationServices.GetService<IRepository>();

            var userManager = app.ApplicationServices.GetService<UserManager<Microsoft.AspNetCore.Identity.MongoDB.IdentityUser>>();

            ConfigureMongoDriver2IgnoreExtraElements();

            var createdNewRepository = false;


            if (!repository.CollectionExists<Client>())
            {
                foreach (var client in Config.GetClients())
                {
                    repository.Add(client);
                }
                createdNewRepository = true;
            }

            if (!repository.CollectionExists<IdentityResource>())
            {
                foreach (var res in Config.GetIdentityResources())
                {
                    repository.Add(res);
                }
                createdNewRepository = true;
            }


            if (!repository.CollectionExists<ApiResource>())
            {
                foreach (var api in Config.GetApiResources())
                {
                    repository.Add(api);
                }
                createdNewRepository = true;
            }
            
            if (createdNewRepository == true)
            {
                AddSampleUsersToMongo(userManager);
            }
            
            if (createdNewRepository)
            {
                throw new Exception(_newRepositoryMsg);
            }

        }
        
        private static void ConfigureMongoDriver2IgnoreExtraElements()
        {
            BsonClassMap.RegisterClassMap<Client>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
            BsonClassMap.RegisterClassMap<IdentityResource>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
            BsonClassMap.RegisterClassMap<ApiResource>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
            BsonClassMap.RegisterClassMap<PersistedGrant>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
        }

        private static void AddSampleUsersToMongo(UserManager<Microsoft.AspNetCore.Identity.MongoDB.IdentityUser> userManager)
        {
            var dummyUsers = Config.GetSampleUsers();

            foreach (var usrDummy in dummyUsers)
            {
                var userDummyEmail = usrDummy.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Email);

                if (userDummyEmail == null)
                {
                    throw new Exception("Could not locate user email from  claims!");
                }


                var user = new Microsoft.AspNetCore.Identity.MongoDB.IdentityUser()
                {
                    UserName = usrDummy.Username,
                    LockoutEnabled = false,
                    EmailConfirmed = true,
                    Email = userDummyEmail.Value,
                    NormalizedEmail = userDummyEmail.Value
                };



                foreach (var claim in usrDummy.Claims)
                {
                    user.AddClaim(claim);
                }
                var result = userManager.CreateAsync(user, usrDummy.Password);
                if (!result.Result.Succeeded)
                {
                    var errorList = result.Result.Errors.ToArray();
                    throw new Exception($"Error Adding sample users to MongoDB! Make sure to drop all collections from Mongo before trying again!");
                }
            }
            return;
        }
    }
}
