using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace AuthorizationServerV5.Controllers
{
    public class RegistrationController : Controller
    {
        private readonly IMongoDbContext dbContext;

        public RegistrationController(IMongoDbContext dbContext)
        {
            this.dbContext = dbContext;
        }

        [HttpPost("~/asd/register")]
        public async Task<IActionResult> Register([FromBody]PropyUser user)
        {
            await this.dbContext.CreateUser(user);

            return new JsonResult(new
            {
                response = $"User with name {user.FirstName} was created"
            });
        }
    }
}
