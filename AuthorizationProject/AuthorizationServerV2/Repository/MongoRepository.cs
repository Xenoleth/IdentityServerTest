using Microsoft.Extensions.Options;
using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthorizationServerV2.Repository
{
    public class MongoRepository : IRepository
    {
        private readonly IMongoClient _client;
        public readonly IMongoDatabase _database;

        public MongoRepository(
            // TODO: Extract options
            //IOptions<ConfigurationOptions> optionsAccessor
            )
        {
            //var configurationOptions = optionsAccessor.Value;

            //_client = new MongoClient(configurationOptions.MongoConnection);
            //_database = _client.GetDatabase(configurationOptions.MongoDatabaseName);
            this._client = new MongoClient("mongodb://localhost:27017");
            this._database = this._client.GetDatabase("testDatabase");
        }

        public IMongoDatabase GetDatabase()
        {
            return _database;
        }

        public IQueryable<T> All<T>() where T : class, new()
        {
            return _database.GetCollection<T>(typeof(T).Name).AsQueryable();
        }

        public IQueryable<T> Where<T>(System.Linq.Expressions.Expression<Func<T, bool>> expression) where T : class, new()
        {
            return All<T>().Where(expression);
        }

        public void Delete<T>(System.Linq.Expressions.Expression<Func<T, bool>> predicate) where T : class, new()
        {
            var result = _database.GetCollection<T>(typeof(T).Name).DeleteMany(predicate);

        }
        public T Single<T>(System.Linq.Expressions.Expression<Func<T, bool>> expression) where T : class, new()
        {
            return All<T>().Where(expression).SingleOrDefault();
        }

        public bool CollectionExists<T>() where T : class, new()
        {
            var collection = _database.GetCollection<T>(typeof(T).Name);
            var filter = new BsonDocument();
            var totalCount = collection.Count(filter);
            return (totalCount > 0) ? true : false;

        }

        public void Add<T>(T item) where T : class, new()
        {
            _database.GetCollection<T>(typeof(T).Name).InsertOne(item);
        }

        public void Add<T>(IEnumerable<T> items) where T : class, new()
        {
            _database.GetCollection<T>(typeof(T).Name).InsertMany(items);
        }
    }
}
