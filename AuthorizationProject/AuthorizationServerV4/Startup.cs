using AspNet.Security.OAuth.Validation;
using AuthorizationServerV4.External;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthorizationServerV4
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            //services.AddDbContext<MongoDbContext>(options =>
            //{
            //    options.UseOpenIddict();
            //});

            services.AddIdentity<External.IdentityUser, External.IdentityRole>()
                .AddUserStore<UserStore<External.IdentityUser>>()
                .AddRoleStore<RoleStore<External.IdentityRole>>()
                .AddDefaultTokenProviders();

            services.AddAuthentication()
                .AddOAuthValidation();

            services.AddOpenIddict(options => 
            {
                //options.AddMvcBinders();
                options.EnableTokenEndpoint("/connect/token");
                options.AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow();

                // DEV option
                options.DisableHttpsRequirement();
            });

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = OAuthValidationDefaults.AuthenticationScheme;
                })
                .AddOAuthValidation();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}
