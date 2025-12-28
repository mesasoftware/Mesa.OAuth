namespace Mesa.OAuth.Storage.Basic
{
    using System;
    using Mesa.OAuth.Framework;

    /// <summary>
    /// Simple access token model, this would hold information required to enforce policies such as expiration, and association
    /// with a user accout or other information regarding the information the consumer has been granted access to.
    /// </summary>
    public class AccessToken : TokenBase
    {
        public DateTime ExpiryDate { get; set; }

        public string [ ]? Roles { get; set; }

        public string? UserName { get; set; }
    }
}