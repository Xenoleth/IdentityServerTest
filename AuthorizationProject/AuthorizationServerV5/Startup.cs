using AspNet.Security.OAuth.Validation;
using AuthorizationServerV5.Data;
using AuthorizationServerV5.External;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthorizationServerV5
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



            services.AddDbContext<ApplicationDbContext>(options => 
            {
                options.UseInMemoryDatabase(nameof(ApplicationDbContext));
                options.UseOpenIddict();
            });

            services.AddIdentity<IdentityUser2, IdentityRole2>()
                //.AddUserStore<UserStore<External.IdentityUser>>()
                //.AddRoleStore<RoleStore<External.IdentityRole>>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddOpenIddict(options =>
            {
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();
                options.EnableTokenEndpoint("/connect/token");
                options.AllowPasswordFlow()
                    .AllowRefreshTokenFlow();
                // Dev
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
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}
