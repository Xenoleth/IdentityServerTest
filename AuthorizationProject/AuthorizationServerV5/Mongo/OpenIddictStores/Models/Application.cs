using System;
using System.Collections.Generic;

namespace AuthorizationServerV5.Mongo.OpenIddictStores.Models
{
    public class Application
    {
        private string concurrencyToken;
        private readonly IList<Authorization> authorizations;
        private readonly IList<Token> tokens;

        public Application()
        {
            this.concurrencyToken = Guid.NewGuid().ToString();            
            this.authorizations = new List<Authorization>();
            this.tokens = new List<Token>();
        }

        public virtual string Id { get; set; }

        public virtual string ClientId { get; set; }

        public virtual string ClientSecret { get; set; }

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

        public virtual string DisplayName { get; set; }

        public virtual string PostLogoutRedirectUris { get; set; }

        public virtual string RedirectUris { get; set; }

        public virtual string Type { get; set; }

        public virtual IList<Authorization> Authorizations { get; }
        
        public virtual IList<Token> Tokens { get; }
    }
}
