using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServerV5.Controllers
{
    public class InfoController : Controller
    {
        [Authorize, HttpGet("~/info/test")]
        public IActionResult GetMessate()
        {
            return new JsonResult(new
            {
                Name = User.Identity.Name
            });
        }
    }
}
