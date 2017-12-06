using AuthorizationServerV5.Mongo.Contracts;
using MongoDB.Bson;
using MongoDB.Driver;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo
{
    public class MongoDbContext : IMongoDbContext
    {
        private readonly IMongoClient client;
        private readonly IMongoDatabase database;

        public MongoDbContext()
        {
            this.client = new MongoClient("mongodb://localhost:27017");
            this.database = client.GetDatabase("MyCoreDatabase");
        }

        public async Task CreateUser(string username, string password)
        {
            var collection = this.database.GetCollection<BsonDocument>("Users");
            var document = new BsonDocument
            {
                { "username", username },
                { "password", password }
            };
            await collection.InsertOneAsync(document);
        }

        public async Task CreateRole(string role)
        {
            var collection = this.database.GetCollection<BsonDocument>("Roles");
            var document = new BsonDocument
            {
                { "name", role }
            };
            await collection.InsertOneAsync(document);
        }

        public async Task<List<BsonDocument>> GetUser(string username)
        {
            var collection = this.database.GetCollection<BsonDocument>("Users");
            var filter = new BsonDocument()
            {
                { "username", username }
            };
            var result = await collection.Find(filter).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetRole(string name)
        {
            var collection = this.database.GetCollection<BsonDocument>("Roles");
            var document = new BsonDocument
            {
                { "name", name }
            };
            var result = await collection.Find(document).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetUserById(string id)
        {
            var collection = this.database.GetCollection<BsonDocument>("Users");
            var filter = new BsonDocument()
            {
                { "_id", id }
            };
            var result = await collection.Find(filter).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetRoleById(string id)
        {
            var collection = this.database.GetCollection<BsonDocument>("Roles");
            var document = new BsonDocument
            {
                { "_id", id }
            };
            var result = await collection.Find(document).ToListAsync();

            return result;
        }

        public async Task UpdateUser(string username, string newName)
        {
            var collection = this.database.GetCollection<BsonDocument>("Users");
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            var update = Builders<BsonDocument>.Update.Set("username", newName);
            var result = await collection.UpdateOneAsync(filter, update);
        }

        public async Task UpdateRole(string name, string newName)
        {
            var collection = this.database.GetCollection<BsonDocument>("Roles");
            var filter = Builders<BsonDocument>.Filter.Eq("name", name);
            var update = Builders<BsonDocument>.Update.Set("name", newName);
            var result = await collection.UpdateOneAsync(filter, update);
        }

        public async Task DeleteUser(string username)
        {
            var collection = this.database.GetCollection<BsonDocument>("Users");
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            var result = await collection.DeleteOneAsync(filter);
        }

        public async Task DeleteRole(string role)
        {
            var collection = this.database.GetCollection<BsonDocument>("Roles");
            var document = new BsonDocument
            {
                { "name", role }
            };
            await collection.DeleteOneAsync(document);
        }

        // Application store CRUD

    }
}
