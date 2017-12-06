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
            await this.dbContext.CreateUser(user.UserName, user.Password);

            var result = new IdentityResult();

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            await this.dbContext.DeleteUser(user.UserName);

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
                UserName = bsonUser[0]["username"].ToString(),
                Password = bsonUser[0]["password"].ToString()
            };

            return user as TUser;
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var bsonUser = await this.dbContext.GetUser(normalizedUserName);
            var user = new ApplicationUser()
            {
                UserName = bsonUser[0]["username"].ToString(),
                Password = bsonUser[0]["password"].ToString()
            };

            return user as TUser;
        }

        public async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return user.UserName.Normalize();
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            var bsonUser = await this.dbContext.GetUser(user.UserName);
            var username = bsonUser[0]["username"].ToString();

            return username;
        }

        public async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return user.UserName;
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.UserName, normalizedName);
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.UserName, userName);
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateUser(user.UserName, user.UserName);

            return IdentityResult.Success;
        }
    }
}
