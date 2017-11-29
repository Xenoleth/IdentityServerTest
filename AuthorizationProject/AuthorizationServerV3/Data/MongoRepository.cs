using MongoDB.Bson;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;

namespace AuthorizationServerV3.Data
{
    public class MongoRepository
    {
        private readonly IMongoClient client;
        private readonly IMongoDatabase database;

        // TODO: Add dependency injection
        public MongoRepository()
        {
            this.client = new MongoClient("mongodb://localhost:27017");
            this.database = this.client.GetDatabase("testDatabase");
        }

        // TODO: Evaluate and change methods
        public IMongoDatabase GetDatabase()
        {
            return this.database;
        }

        public IQueryable<T> All<T>() where T : class, new()
        {
            return this.database.GetCollection<T>(typeof(T).Name).AsQueryable();
        }

        public IQueryable<T> Where<T>(System.Linq.Expressions.Expression<Func<T, bool>> expression) where T : class, new()
        {
            return All<T>().Where(expression);
        }

        public void Delete<T>(System.Linq.Expressions.Expression<Func<T, bool>> predicate) where T : class, new()
        {
            var result = this.database.GetCollection<T>(typeof(T).Name).DeleteMany(predicate);

        }
        public T Single<T>(System.Linq.Expressions.Expression<Func<T, bool>> expression) where T : class, new()
        {
            return All<T>().Where(expression).SingleOrDefault();
        }

        public bool CollectionExists<T>() where T : class, new()
        {
            var collection = this.database.GetCollection<T>(typeof(T).Name);
            var filter = new BsonDocument();
            var totalCount = collection.Count(filter);
            return (totalCount > 0) ? true : false;

        }

        public void Add<T>(T item) where T : class, new()
        {
            this.database.GetCollection<T>(typeof(T).Name).InsertOne(item);
        }

        public void Add<T>(IEnumerable<T> items) where T : class, new()
        {
            this.database.GetCollection<T>(typeof(T).Name).InsertMany(items);
        }
    }
}
