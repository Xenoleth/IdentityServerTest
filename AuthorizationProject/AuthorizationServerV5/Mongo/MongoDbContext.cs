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

        public async Task CreateUser(PropyUser user)
        {
            var document = new BsonDocument
            {
                { "UserName", user.UserName ?? "default" },
                { "PasswordHash" , user.PasswordHash ?? "default" },
                { "SecurityStamp" , user.SecurityStamp ?? "default" },
                { "Roles" , new BsonArray {
                    "Registered",
                    "Escrow"
                } },
                { "Claims" , new BsonArray { "asd", "zxc" } },
                { "Logins" , new BsonArray { "asd", "zxc" } },
                { "userRatings" , new BsonArray { "asd", "zxc" } },
                { "status" , user.Status ?? "default" },
                {"firstName" , user.FirstName ?? "default" },
                {"lastName" , user.LastName ?? "default" },
                {"email" , user.Email ?? "default" },
                {"avatar" , user.Avatar ?? "default" },
                {"info" , user.Info ?? "default" },
                { "favouriteProperties" , new BsonArray {"asd", "zxc" }},
                { "hiddenProperties" , new BsonArray { "asd", "zxc"}},
                { "listedProperties" , new BsonArray {"asd", "zxc" }},
                {"compares" ,new BsonArray {"asd", "zxc" }},
                {"connections" , new BsonArray {"asd", "zxc" }},
                {"propyNotes" , new BsonArray { "asd", "zxc"}},
                {"phoneNumber" , user.PhoneNumber  ?? "default"},
                {"developments" , new BsonArray { "asd", "zxc"}},
                {"checkIns" , new BsonArray {"asd", "zxc" }},
                {"interests" , new BsonArray {"asd", "zxc" }},
                {"expertises" , new BsonArray { "asd", "zxc"}},
                {"locations" , new BsonArray {"asd", "zxc" }},
                {"languages" , new BsonArray {"asd", "zxc" } },
                {"agency" , user.Agency ?? "default"},
                {"recommendations" , new BsonArray {"asd", "zxc" }},
                {"rating" , user.Rating },
                {"ratingsCount" , user.RatingsCount},
                {"company" , user.Company ?? "default"},
                {"occupation" , user.Occupation ?? "default"},
                {"pROTokens" , user.PROTokens},
                {"request" , new BsonDocument
                    {
                        { "type" , user.Request.Type ?? "default"},
                        { "location" , user.Request.Location ?? "default"}
                    }
                },
                {"propertyInterests" , new BsonArray {"asd", "zxc" }},
                {"vipUntil" , user.VipUntil},
                {"proUntil" , user.ProUntil},
                {"lastLogIn" , user.LastLogIn},
                {"lastNotification" , user.LastNotification},
                {"locationOfWork" , user.LocationOfWork ?? "default"},
                {"isPropyCreated" , user.IsPropyCreated},
                {"pinRequests" , new BsonArray { "asd", "zxc"}},
                {"crawlSite" , user.CrawlSite ?? "default"},
                {"addedOn" , user.AddedOn},
                {"lastUpdated" , user.LastUpdated},
                {"pushIds" , new BsonArray {"asd", "zxc" }},
                {"isEmailNotifications" , user.IsEmailNotifications},
                {"userSettings" , user.UserSettings ?? "default"},
                {"walletId" , user.WalletId  ?? "default"},
                {"transactionHistory" , new BsonArray {"asd", "zxc" }},
                {"stripeCustomerId" , user.StripeCustomerId ?? "default"},
                { "facebookId", user.FacebookId ?? "default" },
                { "googleId", user.GoogleId ?? "default" }
            };

            await this.users.InsertOneAsync(document);
        }

        //public async Task<string> GetClientSecret(Application app)
        //{
        //    return app.ClientSecret;
        //}

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
                { "UserName", username },
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
            var filter = Builders<BsonDocument>.Filter.Eq("UserName", username);
            var update = Builders<BsonDocument>.Update.Set("UserName", newName);
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
            var filter = Builders<BsonDocument>.Filter.Eq("UserName", username);
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

        public async Task<List<BsonDocument>> GetUserByFacebookId(string facebookId)
        {
            var filter = new BsonDocument()
            {
                { "facebookId", facebookId }
            };
            var result = await this.users.Find(filter).ToListAsync();

            return result;
        }

        public async Task<List<BsonDocument>> GetUserByGoogleId(string googleId)
        {
            var filter = new BsonDocument
            {
                { "googleId", googleId }
            };
            var result = await this.users.Find(filter).ToListAsync();

            return result;
        }

        // Application store CRUD
        public async Task CreateApplication(Application application)
        {
            var document = new BsonDocument()
            {
                { "identifier", application.Identifier ?? "default" },
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
            var filter = Builders<BsonDocument>.Filter.Eq("identifier", id);
            var result = await this.applications.DeleteOneAsync(filter);
        }

        public async Task<Application> FindApplicationByClientId(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("clientId", id);
            var bsonApp = await this.applications.Find(filter).ToListAsync();
            var app = new Application()
            {
                Identifier = bsonApp[0]["identifier"].ToString(),
                ClientId = bsonApp[0]["clientId"].ToString(),
                ClientSecret = bsonApp[0]["clientSecret"].ToString()
                // TODO: Map the rest of the application model
            };

            return app;
        }

        public async Task<Application> FindApplicationById(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("identifier", id);
            var bsonApp = await this.applications.Find(filter).ToListAsync();
            var app = new Application()
            {
                Identifier = bsonApp[0]["identifier"].ToString(),
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
                { "identifier", auth.Identifier ?? "default" },
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
                { "identifier", scope.Identifier ?? "default" },
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
                { "identifier", token.Identifier ?? "default" },
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

        public async Task<BsonDocument> FindTokenById(string id)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("identifier", id);
            var result = await this.tokens.Find(filter).ToListAsync();

            return result[0];
        }

        public async Task UpdateToken(Token token)
        {
            var filter = Builders<BsonDocument>.Filter.Eq("identifier", token.Identifier);
            var document = new BsonDocument()
            {
                { "identifier", token.Identifier ?? "default" },
                { "ciphertext", token.Ciphertext ?? "default" },
                { "concurrencyToken", token.ConcurrencyToken ?? "default" },
                { "hash", token.Hash ?? "default" },
                { "status", token.Status ?? "default" },
                { "subject", token.Subject ?? "default" },
                { "type", token.Type ?? "default" },
                { "creationDate", token.CreationDate.ToString() ?? "default" },
                { "expirationDate", token.ExpirationDate.ToString() ?? "default" }
            };

            await this.tokens.ReplaceOneAsync(filter, document);
        }
    }
}
