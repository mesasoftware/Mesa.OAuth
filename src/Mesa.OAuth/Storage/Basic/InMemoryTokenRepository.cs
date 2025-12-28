namespace Mesa.OAuth.Storage.Basic
{
    using System;
    using System.Collections.Generic;
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Storage.Basic.Interfaces;

    /// <summary>
    /// In-Memory implementation of a token repository
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class InMemoryTokenRepository<T> : ITokenRepository<T>
        where T : TokenBase
    {
        private readonly Dictionary<string , T> tokens = [ ];

        public T GetToken ( string? token )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( token );

            return this.tokens [ token ];
        }

        public void SaveToken ( T token )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( token.Token );

            this.tokens [ token.Token ] = token;
        }
    }
}