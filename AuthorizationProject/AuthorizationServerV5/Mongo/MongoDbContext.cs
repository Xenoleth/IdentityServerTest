using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;
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

        private readonly IMongoCollection<BsonDocument> users;
        private readonly IMongoCollection<BsonDocument> roles;
        private readonly IMongoCollection<BsonDocument> applications;
        private readonly IMongoCollection<BsonDocument> authorizations;
        private readonly IMongoCollection<BsonDocument> scopes;
        private readonly IMongoCollection<BsonDocument> tokens;

        public MongoDbContext()
        {
            this.client = new MongoClient("mongodb://localhost:27017");
            this.database = client.GetDatabase("MyCoreDatabase");

            this.users = this.database.GetCollection<BsonDocument>("Users");
            this.roles = this.database.GetCollection<BsonDocument>("Roles");
            this.applications = this.database.GetCollection<BsonDocument>("Applications");
            this.authorizations = this.database.GetCollection<BsonDocument>("Authorizations");
            this.scopes = this.database.GetCollection<BsonDocument>("Scopes");
            this.tokens = this.database.GetCollection<BsonDocument>("Tokens");
        }

        public async Task CreateUser(string username, string password)
        {
            var document = new BsonDocument
            {
                { "username", username },
                { "password", password }
            };
            await this.users.InsertOneAsync(document);
        }

        public async Task CreateRole(string role)
        {
            var document = new BsonDocument
            {
                { "name", role }
            };
            await this.roles.InsertOneAsync(document);
        }

        public async Task<List<BsonDocument>> GetUser(string username)
        {
            var filter = new BsonDocument()
            {
                { "username", username }
            };
            var result = await this.users.Find(filter).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetRole(string name)
        {
            var document = new BsonDocument
            {
                { "name", name }
            };
            var result = await this.roles.Find(document).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetUserById(string id)
        {
            var filter = new BsonDocument()
            {
                { "_id", id }
            };
            var result = await this.users.Find(filter).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetRoleById(string id)
        {
            var document = new BsonDocument
            {
                { "_id", id }
            };
            var result = await this.roles.Find(document).ToListAsync();

            return result;
        }

        public async Task UpdateUser(string username, string newName)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            var update = Builders<BsonDocument>.Update.Set("username", newName);
            var result = await this.users.UpdateOneAsync(filter, update);
        }

        public async Task UpdateRole(string name, string newName)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("name", name);
            var update = Builders<BsonDocument>.Update.Set("name", newName);
            var result = await this.roles.UpdateOneAsync(filter, update);
        }

        public async Task DeleteUser(string username)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("username", username);
            var result = await this.users.DeleteOneAsync(filter);
        }

        public async Task DeleteRole(string role)
        {
            var document = new BsonDocument
            {
                { "name", role }
            };
            await this.roles.DeleteOneAsync(document);
        }

        // Application store CRUD
        public async Task CreateApplication(Application application)
        {
            var document = new BsonDocument()
            {
                { "id", application.Id ?? "default" },
                { "clientId", application.ClientId ?? "default" },
                { "clientSecret", application.ClientSecret ?? "default" },
                { "concurrencyToken", application.ConcurrencyToken ?? "default" },
                { "displayName", application.DisplayName },
                { "postLogoutRedirectUris", application.PostLogoutRedirectUris ?? "default" },
                { "redirectUris", application.RedirectUris ?? "default" },
                { "type", application.Type ?? "default" }
            };

            await this.applications.InsertOneAsync(document);
        }

        public async Task DeleteApplication(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("id", id);
            var result = await this.applications.DeleteOneAsync(filter);
        }

        public async Task<Application> FindApplicationByClientId(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("clientId", id);
            var bsonApp = await this.applications.Find(filter).ToListAsync();
            var app = new Application()
            {
                Id = bsonApp[0]["id"].ToString(),
                ClientId = bsonApp[0]["clientId"].ToString(),
                ClientSecret = bsonApp[0]["clientSecret"].ToString()
                // TODO: Map the rest of the application model
            };

            return app;
        }

        public async Task<Application> FindApplicationById(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("id", id);
            var bsonApp = await this.applications.Find(filter).ToListAsync();
            var app = new Application()
            {
                Id = bsonApp[0]["id"].ToString(),
                ClientId = bsonApp[0]["clientId"].ToString(),
                ClientSecret = bsonApp[0]["clientSecret"].ToString()
                // TODO: Map the rest of the application model
            };

            return app;
        }

        // Authorization store CRUD
        public async Task CreateAuthorization(Authorization auth)
        {
            var document = new BsonDocument()
            {
                { "id", auth.Id ?? "default" },
                { "concurrencyToken", auth.ConcurrencyToken ?? "default" },
                { "scopes", auth.Scopes ?? "default" },
                { "status", auth.Status ?? "default" },
                { "subject", auth.Subject ?? "default" },
                { "type", auth.Type ?? "default" }
            };

            await this.authorizations.InsertOneAsync(document);
        }

        // Scope store CRUD
        public async Task CreateScope(Scope scope)
        {
            var document = new BsonDocument()
            {
                { "id", scope.Id ?? "default" },
                { "concurrencyToken", scope.ConcurrencyToken ?? "default" },
                { "description", scope.Description ?? "default" },
                { "name", scope.Name ?? "default" }
            };

            await this.scopes.InsertOneAsync(document);
        }

        // Token store CRUD
        public async Task CreateToken(Token token)
        {
            var document = new BsonDocument()
            {
                { "id", token.Id ?? "default" },
                { "ciphertext", token.Ciphertext ?? "default" },
                { "concurrencyToken", token.ConcurrencyToken ?? "default" },
                { "hash", token.Hash ?? "default" },
                { "status", token.Status ?? "default" },
                { "subject", token.Subject ?? "default" },
                { "type", token.Type ?? "default" },
                { "creationDate", token.CreationDate.ToString() ?? "default" },
                { "expirationDate", token.ExpirationDate.ToString() ?? "default" }
            };
                    
            await this.tokens.InsertOneAsync(document);
        }
    }
}
