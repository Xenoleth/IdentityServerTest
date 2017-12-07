using System;

namespace AuthorizationServerV5.Mongo.OpenIddictStores.Models
{
    public class Scope
    {
        private string concurrencyToken;

        public Scope()
        {
            this.concurrencyToken = Guid.NewGuid().ToString();
        }

        public virtual string Identifier { get; set; }

        public virtual string Name { get; set; }

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

        public virtual string Description { get; set; }
    }
}
