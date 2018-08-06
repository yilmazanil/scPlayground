using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Globalization;
using System.Threading.Tasks;

namespace SCPlayground.WebUI.Project.Pipelines
{
    public class AzureADIdentityProviderProcessor : IdentityProvidersProcessor
    {
        public AzureADIdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }
        protected override string IdentityProviderName
        {
            get { return "xp0.sc.azureAD"; }
        }
        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));

            var identityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();

            string aadInstance = Settings.GetSetting("AADInstance");
            string tenant = Settings.GetSetting("Tenant");
            string clientId = Settings.GetSetting("ClientId");
            string postLogoutRedirectURI = Settings.GetSetting("PostLogoutRedirectURI");
            string redirectURI = Settings.GetSetting("RedirectURI");

            string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

            args.App.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Caption = identityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive,
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectURI,
                RedirectUri = redirectURI,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {

                    SecurityTokenValidated = notification =>
                    {
                        var identity = notification.AuthenticationTicket.Identity;

                        foreach (var claimTransformationService in identityProvider.Transformations)
                        {
                            claimTransformationService.Transform(identity,
                                new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));

                        }

                        notification.AuthenticationTicket = new AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);

                        return Task.FromResult(0);
                    }

                }
            });
        }
    }
}