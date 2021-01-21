﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using SPID.AspNetCore.Authentication.Models;
using System;

namespace SPID.AspNetCore.Authentication.Events
{
    public class AuthenticationSuccessContext : RemoteAuthenticationContext<SpidOptions>
    {
        /// <summary>
        /// Creates a new context object
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        public AuthenticationSuccessContext(HttpContext context, AuthenticationScheme scheme, SpidOptions options)
            : base(context, scheme, options, new AuthenticationProperties())
        { }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        /// <value>
        /// The authentication ticket.
        /// </value>
        public AuthenticationTicket AuthenticationTicket { get; internal set; }
        /// <summary>
        /// Gets or sets the saml authn request identifier.
        /// </summary>
        /// <value>
        /// The saml authn request identifier.
        /// </value>
        public string SamlAuthnRequestId { get; internal set; }
    }
}
