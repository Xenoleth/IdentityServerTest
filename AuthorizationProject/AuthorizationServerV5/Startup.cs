using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Primitives;
using AuthorizationServerV5.Mongo;
using AuthorizationServerV5.Mongo.Contracts;
using AuthorizationServerV5.Mongo.OpenIddictStores;
using AuthorizationServerV5.Mongo.OpenIddictStores.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Core;
using OpenIddict.Models;

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

            services.AddScoped<IMongoDbContext, MongoDbContext>();
            services.AddScoped<IUserStore<ApplicationUser>, UserStore<ApplicationUser>>();
            services.AddScoped<IRoleStore<ApplicationRole>, RoleStore<ApplicationRole>>();
            
            services.AddScoped<OpenIddictApplication<string>>(x =>
            {
                return new OpenIddictApplication<string>();
            });
            services.AddScoped<OpenIddictAuthorization<string>>(x =>
            {
                return new OpenIddictAuthorization<string>();
            });
            services.AddScoped<OpenIddictScope<string>>(x =>
            {
                return new OpenIddictScope<string>();
            });
            services.AddScoped<OpenIddictToken<string>>(x =>
            {
                return new OpenIddictToken<string>();
            });

            services.AddScoped<IOpenIddictApplicationStore<Application>, ApplicationStore<Application>>();
            services.AddScoped<IOpenIddictAuthorizationStore<Authorization>, AuthorizationStore<Authorization>>();
            services.AddScoped<IOpenIddictScopeStore<Scope>, ScopeStore<Scope>>();
            services.AddScoped<IOpenIddictTokenStore<Token>, TokenStore<Token>>();

            services.AddScoped<OpenIddictApplicationManager<Application>>();
            services.AddScoped<OpenIddictAuthorizationManager<Authorization>>();
            services.AddScoped<OpenIddictScopeManager<Scope>>();
            services.AddScoped<OpenIddictTokenManager<Token>>();

            //services.AddDbContext<ApplicationDbContext>(options => 
            //{
            //    options.UseInMemoryDatabase(nameof(ApplicationDbContext));
            //    options.UseOpenIddict();
            //});

            //services.AddIdentity<IdentityUser2, IdentityRole2>()
            //    //.AddUserStore<UserStore<External.IdentityUser>>()
            //    //.AddRoleStore<RoleStore<External.IdentityRole>>()
            //    .AddEntityFrameworkStores<ApplicationDbContext>()
            //    .AddDefaultTokenProviders();

            services.AddIdentity<ApplicationUser, ApplicationRole>()
                .AddUserStore<UserStore<ApplicationUser>>()
                .AddRoleStore<RoleStore<ApplicationRole>>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;
            });

            services.AddOpenIddict<Application, Authorization, Scope, Token>(options =>
            {
                options.AddMvcBinders();

                options.AddApplicationStore<ApplicationStore<Application>>();
                options.AddAuthorizationStore<AuthorizationStore<Authorization>>();
                options.AddScopeStore<ScopeStore<Scope>>();
                options.AddTokenStore<TokenStore<Token>>();

                //options.EnableAuthorizationEndpoint("/connect/authorize");
                //options.EnableLogoutEndpoint("/connect/logout");
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
