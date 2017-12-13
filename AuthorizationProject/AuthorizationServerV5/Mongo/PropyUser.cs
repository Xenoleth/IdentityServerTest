using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Mongo
{
    public class Req
    {
        public string Type { get; set; }
        public string Location { get; set; }
    }

    public class PropyUser
    {
        public PropyUser()
        {
            FavouriteProperties = new List<string>();
            HiddenProperties = new List<string>();
            ListedProperties = new List<string>();
            PropyNotes = new List<string>();
            Developments = new List<string>();
            Expertises = new List<string>();
            Locations = new List<string>();
            Interests = new List<string>();
            PropertyInterests = new List<string>();
            Recommendations = new List<string>();
            Connections = new List<string>();
            CheckIns = new List<string>();
            UserRatings = new List<string>();
            PinRequests = new List<string>();
            Compares = new List<string>();
            pushIds = new List<KeyValuePair<string, string>>();
            TransactionHistory = new List<string>();
            Roles = new List<string>();
            Request = new Req();
        }

        public string SecurityStamp { get; set; }
        public string PasswordHash { get; set; }
        public List<string> Roles { get; set; }
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Status { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
        public string Info { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> FavouriteProperties { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> HiddenProperties { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> ListedProperties { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> Compares { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> Connections { get; set; }
        public List<string> PropyNotes { get; set; }
        public string PhoneNumber { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public List<string> Developments { get; set; }
        public List<string> CheckIns { get; set; }
        public List<string> Interests { get; set; }
        public List<string> Expertises { get; set; }
        public List<string> Locations { get; set; }
        public List<string> Languages { get; set; }
        [BsonRepresentation(BsonType.ObjectId)]
        public string Agency { get; set; }
        public List<string> Recommendations { get; set; }
        public double Rating { get; set; }
        public int RatingsCount { get; set; }
        public string Company { get; set; }
        public string Occupation { get; set; }
        public int PROTokens { get; set; }
        public Req Request { get; set; }
        public List<string> PropertyInterests { get; set; }
        public DateTime VipUntil { get; set; }
        public DateTime ProUntil { get; set; }
        public DateTime LastLogIn { get; set; }
        public DateTime LastNotification { get; set; }
        public string LocationOfWork { get; set; }
        public List<string> UserRatings;
        public bool IsPropyCreated { get; set; }
        public List<string> PinRequests { get; set; }
        public string CrawlSite { get; set; }
        public DateTime AddedOn { get; set; }
        public DateTime LastUpdated { get; set; }
        public List<KeyValuePair<string, string>> pushIds { get; set; }
        public bool IsEmailNotifications { get; set; }
        public string UserSettings { get; set; }
        public string WalletId { get; set; }
        public List<string> TransactionHistory { get; set; }
        public string StripeCustomerId { get; set; }
        public string FacebookId { get; set; }
        public string GoogleId { get; set; }
    }
}
