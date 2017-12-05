using MongoDbGenericRepository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MongoDB.Driver;
using MongoDbGenericRepository.Models;

namespace AuthorizationServerV4
{
    public class MongoDbContext : IMongoDbContext
    {
        public IMongoClient Client => throw new NotImplementedException();

        public IMongoDatabase Database => throw new NotImplementedException();

        public void DropCollection<TDocument>()
        {
            throw new NotImplementedException();
        }

        public void DropCollection<TDocument>(string partitionKey)
        {
            throw new NotImplementedException();
        }

        public IMongoCollection<TDocument> GetCollection<TDocument>()
        {
            throw new NotImplementedException();
        }

        public IMongoCollection<TDocument> GetCollection<TDocument>(string partitionKey) where TDocument : IDocument
        {
            throw new NotImplementedException();
        }

        public IMongoCollection<TDocument> GetCollection<TDocument, TKey>(string partitionKey)
            where TDocument : IDocument<TKey>
            where TKey : IEquatable<TKey>
        {
            throw new NotImplementedException();
        }
    }
}
