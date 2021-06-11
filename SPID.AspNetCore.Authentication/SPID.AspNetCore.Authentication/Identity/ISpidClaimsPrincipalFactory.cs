using Microsoft.AspNetCore.Authentication;
using SPID.AspNetCore.Authentication.Saml;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SPID.AspNetCore.Authentication.Identity
{
    public interface ISpidClaimsPrincipalFactory
    {
        Task<ClaimsPrincipal> CreateAsync(AuthenticationScheme scheme, ResponseType idpAuthnResponse);
    }
}