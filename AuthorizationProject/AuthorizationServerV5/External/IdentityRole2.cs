using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthorizationServerV5.External
{
    public class IdentityRole2 : IdentityRole
    {
        public IdentityRole2()
        {
            Id = ObjectId.GenerateNewId().ToString();
        }

        public IdentityRole2(string roleName) : this()
        {
            Name = roleName;
        }

        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        public string Name { get; set; }

        public string NormalizedName { get; set; }

        public override string ToString() => Name;
    }
}
