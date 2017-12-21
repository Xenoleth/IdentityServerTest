using Microsoft.AspNetCore.Mvc;
using Nethereum.Web3;
using Stripe;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NuGetTestEnvironment.Controllers
{

    public class NugetController : Controller
    {
        [HttpGet("~/neth")]
        public async Task<IActionResult> NethereumTest()
        {
            var web = new Web3("https://ropsten.infura.io/0IUpK6V0KD2UhFUkRIaC");
            var gasPrice = await web.Eth.GasPrice.SendRequestAsync();

            return new JsonResult(new { });
        }

        [HttpGet("~/stripe")]
        public IActionResult StripeTest()
        {
            var customers = new StripeCustomerService();
            var charges = new StripeChargeService();

            var customer = customers.Create(new StripeCustomerCreateOptions
            {
                Email = "email@email.com",
                SourceToken = "token"
            });

            var charge = charges.Create(new StripeChargeCreateOptions
            {
                Amount = 500,
                Description = "Sample Charge",
                Currency = "usd",
                CustomerId = customer.Id
            });

            return new JsonResult(new { });
        }
    }
}
