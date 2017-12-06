using System;

namespace AuthorizationServerV5.Mongo.OpenIddictStores.Models
{
    public class Token
    {
        private string concurrencyToken;

        public Token()
        {
            this.concurrencyToken = Guid.NewGuid().ToString();
        }

        public virtual Application Application { get; set; }

        public virtual Authorization Authorization { get; set; }

        public virtual string Ciphertext { get; set; }

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

        public virtual DateTimeOffset? CreationDate { get; set; }

        public virtual DateTimeOffset? ExpirationDate { get; set; }

        public virtual string Hash { get; set; }

        public virtual string Id { get; set; }

        public virtual string Status { get; set; }

        public virtual string Subject { get; set; }

        public virtual string Type { get; set; }
    }
}
