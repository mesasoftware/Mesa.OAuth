namespace Mesa.OAuth.Testing
{
    using System;
    using System.Collections.Generic;
    using Mesa.OAuth.Framework.Interfaces;
    using Mesa.OAuth.Storage.Interfaces;

    /// <summary>
    /// A simple nonce store that just tracks all nonces by consumer key in memory.
    /// </summary>
    public class TestNonceStore : INonceStore
    {
        private readonly Dictionary<string , List<string>> nonces = [ ];

        public bool RecordNonceAndCheckIsUnique ( IConsumer consumer , string? nonce )
        {
            ArgumentException.ThrowIfNullOrWhiteSpace ( nonce );
            ArgumentException.ThrowIfNullOrWhiteSpace ( consumer.ConsumerKey );

            var list = this.GetNonceListForConsumer ( consumer.ConsumerKey );

            lock ( list )
            {
                if ( list.Contains ( nonce ) )
                {
                    return false;
                }

                list.Add ( nonce );
                return true;
            }
        }

        private List<string> GetNonceListForConsumer ( string consumerKey )
        {
            new List<string> ( );

            if ( !this.nonces.TryGetValue ( consumerKey , out var list ) )
            {
                lock ( this.nonces )
                {
                    if ( !this.nonces.TryGetValue ( consumerKey , out list ) )
                    {
                        list = [ ];
                        this.nonces [ consumerKey ] = list;
                    }
                }
            }

            return list;
        }
    }
}