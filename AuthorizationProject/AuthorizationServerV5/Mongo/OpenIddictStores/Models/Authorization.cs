using System;
using System.Collections.Generic;

namespace AuthorizationServerV5.Mongo.OpenIddictStores.Models
{
    public class Authorization
    {
        private string concurrencyToken;
        private IList<Token> tokens;

        public Authorization()
        {
            this.concurrencyToken = Guid.NewGuid().ToString();
            this.tokens = new List<Token>();
        }

        public virtual string Id { get; set; }

        public virtual string ConcurrencyToken
        {
            get
            {
                return this.concurrencyToken;
            }

            set
            {
                this.concurrencyToken = value;
            }
        }

        public virtual string Scopes { get; set; }

        public virtual string Status { get; set; }

        public virtual string Subject { get; set; }
        
        public virtual string Type { get; set; }

        public virtual Application Application { get; set; }

        public virtual IList<Token> Tokens { get; } 
    }
}
