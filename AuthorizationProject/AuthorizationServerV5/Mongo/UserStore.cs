using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo
{
    public class UserStore<TUser> : IUserStore<TUser>
        where TUser : ApplicationUser
    {
        private readonly IMongoDbContext dbContext;

        public UserStore(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            await this.dbContext.CreateUser(user.Username, user.Password);

            var result = new IdentityResult();

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            await this.dbContext.DeleteUser(user.Username);

            return IdentityResult.Success;
        }

        public void Dispose()
        {
            // TODO: Implement Dispose
            GC.SuppressFinalize(this);
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var bsonUser = await this.dbContext.GetUserById(userId);
            var user = new ApplicationUser()
            {
                Username = bsonUser[0]["username"].ToString(),
                Password = bsonUser[0]["password"].ToString()
            };

            return user as TUser;
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var bsonUser = await this.dbContext.GetUser(normalizedUserName);
            var user = new ApplicationUser()
            {
                Username = bsonUser[0]["username"].ToString(),
                Password = bsonUser[0]["password"].ToString()
            };

            return user as TUser;
        }

        public async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return user.Username.Normalize();
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            var bsonUser = await this.dbContext.GetUser(user.Username);
            var username = bsonUser[0]["username"].ToString();

            return username;
        }

        public async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return user.Username;
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.Username, normalizedName);
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.Username, userName);
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.Username, user.Username);

            return IdentityResult.Success;
        }
    }
}
