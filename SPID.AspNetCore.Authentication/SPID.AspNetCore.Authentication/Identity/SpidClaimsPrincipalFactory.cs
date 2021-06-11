using Microsoft.AspNetCore.Authentication;
using SPID.AspNetCore.Authentication.Models;
using SPID.AspNetCore.Authentication.Saml;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Identity
{
    public class SpidClaimsPrincipalFactory : ISpidClaimsPrincipalFactory
    {
        public virtual Task<ClaimsPrincipal> CreateAsync(AuthenticationScheme scheme, ResponseType idpAuthnResponse)
        {
            var claims = new Claim[]
            {
                new Claim( ClaimTypes.NameIdentifier, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Email.Equals(x.Name) || SamlAttributes.Email.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( ClaimTypes.Email, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Email.Equals(x.Name) || SamlAttributes.Email.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.Name, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Name.Equals(x.Name) || SamlAttributes.Name.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.Email, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Email.Equals(x.Name) || SamlAttributes.Email.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.FamilyName, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.FamilyName.Equals(x.Name) || SamlAttributes.FamilyName.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.FiscalNumber, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.FiscalNumber.Equals(x.Name) || SamlAttributes.FiscalNumber.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim()?.Replace("TINIT-", "") ?? string.Empty),
                new Claim( SpidClaimTypes.Surname, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Surname.Equals(x.Name) || SamlAttributes.Surname.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.Mail, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Mail.Equals(x.Name) || SamlAttributes.Mail.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.Address, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Address.Equals(x.Name) || SamlAttributes.Address.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.CompanyName, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.CompanyName.Equals(x.Name) || SamlAttributes.CompanyName.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.CountyOfBirth, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.CountyOfBirth.Equals(x.Name) || SamlAttributes.CountyOfBirth.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.DateOfBirth, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.DateOfBirth.Equals(x.Name) || SamlAttributes.DateOfBirth.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.DigitalAddress, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.DigitalAddress.Equals(x.Name) || SamlAttributes.DigitalAddress.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.ExpirationDate, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.ExpirationDate.Equals(x.Name) || SamlAttributes.ExpirationDate.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.Gender, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.Gender.Equals(x.Name) || SamlAttributes.Gender.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.IdCard, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.IdCard.Equals(x.Name) || SamlAttributes.IdCard.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.IvaCode, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.IvaCode.Equals(x.Name) || SamlAttributes.IvaCode.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.MobilePhone, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.MobilePhone.Equals(x.Name) || SamlAttributes.MobilePhone.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.PlaceOfBirth, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.PlaceOfBirth.Equals(x.Name) || SamlAttributes.PlaceOfBirth.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.RegisteredOffice, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.RegisteredOffice.Equals(x.Name) || SamlAttributes.RegisteredOffice.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
                new Claim( SpidClaimTypes.SpidCode, idpAuthnResponse.GetAssertion().GetAttributeStatement().GetAttributes().FirstOrDefault(x => SamlAttributes.SpidCode.Equals(x.Name) || SamlAttributes.SpidCode.Equals(x.FriendlyName))?.GetAttributeValue()?.Trim() ?? string.Empty),
            };
            var identity = new ClaimsIdentity(claims, scheme.Name, SamlAttributes.Email, null);
            return Task.FromResult<ClaimsPrincipal>(new ClaimsPrincipal(identity));
        }
    }
}