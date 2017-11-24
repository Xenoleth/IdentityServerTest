using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace ResourceServer.Controllers
{
    [Route("identity")]
    [Authorize]
    public class IdentityController : Controller
    {
        [HttpGet]
        public IActionResult Get()
        {
            //return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
            return new JsonResult(User.Claims.Select(c => new { c.Type, c.Value }));
        }
    }
}
