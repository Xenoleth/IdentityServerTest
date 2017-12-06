using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo
{
    public class RoleStore<TRole> : IRoleStore<TRole>
        where TRole : ApplicationRole
    {
        private readonly IMongoDbContext dbContext;

        public RoleStore(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            await this.dbContext.CreateRole(role.Name);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            await this.dbContext.DeleteRole(role.Name);

            return IdentityResult.Success;
        }

        public void Dispose()
        {
            // TODO: Implement Dispose
            GC.SuppressFinalize(this);
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            var bsonRole = await this.dbContext.GetRoleById(roleId);
            var role = new ApplicationRole()
            {
                Name = bsonRole[0]["name"].ToString()
            };

            return role as TRole;
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var bsonRole = await this.dbContext.GetRole(normalizedRoleName);
            var role = new ApplicationRole()
            {
                Name = bsonRole[0]["name"].ToString()
            };

            return role as TRole;
        }

        public async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return role.Name.Normalize();
        }

        public async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            var bsonRole = await this.dbContext.GetRole(role.Name);
            return bsonRole[0]["name"].ToString();
        }

        public async Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            var bsonRole = await this.dbContext.GetRole(role.Name);
            return bsonRole[0]["name"].ToString();
        }

        public async Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateRole(role.Name, normalizedName);
        }

        public async Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateRole(role.Name, roleName);
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            await this.dbContext.UpdateRole(role.Name, role.Name);

            return IdentityResult.Success;
        }
    }
}
