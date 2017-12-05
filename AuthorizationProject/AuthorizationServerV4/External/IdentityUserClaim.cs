using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthorizationServerV4.External
{
    public class IdentityUserClaim
    {
        public IdentityUserClaim()
        {
        }

        public IdentityUserClaim(Claim claim)
        {
            Type = claim.Type;
            Value = claim.Value;
        }

        /// <summary>
        /// Claim type
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// Claim value
        /// </summary>
        public string Value { get; set; }

        public Claim ToSecurityClaim()
        {
            return new Claim(Type, Value);
        }
    }
}
