﻿using Microsoft.Extensions.Configuration;
using SPID.AspNetCore.Authentication.Helpers;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SPID.AspNetCore.Authentication
{
    static class OptionsHelper
    {
        internal static SpidConfiguration CreateFromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection("Spid");
            var options = new SpidConfiguration();

            options.AddIdentityProviders(section
                .GetSection("Providers")
                .GetChildren()
                .ToList()
                .Select(x => new IdentityProvider
                {
                    Method = x.GetValue<RequestMethod>("Method"),
                    Name = x.GetValue<string>("Name"),
                    OrganizationDisplayName = x.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = x.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = x.GetValue<string>("OrganizationName"),
                    OrganizationUrl = x.GetValue<string>("OrganizationUrl"),
                    OrganizationUrlMetadata = x.GetValue<string>("OrganizationUrlMetadata"),
                    ProviderType = x.GetValue<ProviderType>("Type"),
                    SingleSignOnServiceUrl = x.GetValue<string>("SingleSignOnServiceUrl"),
                    SingleSignOutServiceUrl = x.GetValue<string>("SingleSignOutServiceUrl"),
                    SubjectNameIdRemoveText = x.GetValue<string>("SubjectNameIdRemoveText"),
                    PerformFullResponseValidation = x.GetValue<bool>("PerformFullResponseValidation"),
                }));
            options.IsStagingValidatorEnabled = section.GetValue<bool?>("IsStagingValidatorEnabled") ?? false;
            options.IsLocalValidatorEnabled = section.GetValue<bool?>("IsLocalValidatorEnabled") ?? false;
            options.AllowUnsolicitedLogins = section.GetValue<bool?>("AllowUnsolicitedLogins") ?? false;
            options.AssertionConsumerServiceIndex = section.GetValue<ushort?>("AssertionConsumerServiceIndex") ?? 0;
            options.AttributeConsumingServiceIndex = section.GetValue<ushort?>("AttributeConsumingServiceIndex") ?? 0;
            options.CallbackPath = section.GetValue<string>("CallbackPath");
            options.EntityId = section.GetValue<string>("EntityId");
            options.RemoteSignOutPath = section.GetValue<string>("RemoteSignOutPath");
            options.SignOutScheme = section.GetValue<string>("SignOutScheme");
            options.UseTokenLifetime = section.GetValue<bool?>("UseTokenLifetime") ?? false;
            options.SkipUnrecognizedRequests = section.GetValue<bool?>("SkipUnrecognizedRequests") ?? true;
            var certificateSection = section.GetSection("Certificate");
            if (certificateSection != null)
            {
                var certificateSource = certificateSection.GetValue<string>("Source");
                if (certificateSource == "Store")
                {
                    var storeConfiguration = certificateSection.GetSection("Store");
                    var location = section.GetValue<StoreLocation>("Location");
                    var name = section.GetValue<StoreName>("Name");
                    var findType = section.GetValue<X509FindType>("FindType");
                    var findValue = section.GetValue<string>("FindValue");
                    var validOnly = section.GetValue<bool>("validOnly");
                    options.Certificate = X509Helper.GetCertificateFromStore(
                                        StoreLocation.CurrentUser, StoreName.My,
                                        X509FindType.FindBySubjectName,
                                        "HackDevelopers",
                                        validOnly: false);
                }
                else if (certificateSource == "File")
                {
                    var storeConfiguration = certificateSection.GetSection("File");
                    var path = section.GetValue<string>("Path");
                    var password = section.GetValue<string>("Password");
                    options.Certificate = X509Helper.GetCertificateFromFile(path, password);
                }
                else
                {
                    var storeConfiguration = certificateSection.GetSection("Raw");
                    var certificate = section.GetValue<string>("Certificate");
                    var key = section.GetValue<string>("Key");
                    options.Certificate = X509Helper.GetCertificateFromStrings(certificate, key);
                }
            }
            return options;
        }

        internal static void LoadFromConfiguration(SpidConfiguration options, IConfiguration configuration)
        {
            var createdOptions = CreateFromConfiguration(configuration);
            options.AddIdentityProviders(createdOptions.IdentityProviders);
            options.AllowUnsolicitedLogins = createdOptions.AllowUnsolicitedLogins;
            options.AssertionConsumerServiceIndex = createdOptions.AssertionConsumerServiceIndex;
            options.AttributeConsumingServiceIndex = createdOptions.AttributeConsumingServiceIndex;
            options.CallbackPath = createdOptions.CallbackPath;
            options.Certificate = createdOptions.Certificate;
            options.EntityId = createdOptions.EntityId;
            options.IsLocalValidatorEnabled = createdOptions.IsLocalValidatorEnabled;
            options.IsStagingValidatorEnabled = createdOptions.IsStagingValidatorEnabled;
            options.RemoteSignOutPath = createdOptions.RemoteSignOutPath;
            options.SignOutScheme = createdOptions.SignOutScheme;
            options.SkipUnrecognizedRequests = createdOptions.SkipUnrecognizedRequests;
            options.UseTokenLifetime = createdOptions.UseTokenLifetime;
        }
    }
}
