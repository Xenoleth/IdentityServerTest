using MongoDB.Bson;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo.Contracts
{
    public interface IMongoDbContext
    {
        Task CreateUser(string username, string password);
        Task<List<BsonDocument>> GetUser(string username);
        Task<List<BsonDocument>> GetUserById(string id);
        Task UpdateUser(string username, string newName);
        Task DeleteUser(string username);

        Task CreateRole(string role);
        Task<List<BsonDocument>> GetRoleById(string id);
        Task<List<BsonDocument>> GetRole(string name);
        Task UpdateRole(string name, string newName);
        Task DeleteRole(string role);
    }
}
