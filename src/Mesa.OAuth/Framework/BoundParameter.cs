namespace Mesa.OAuth.Framework
{
    using System.Collections.Specialized;

    internal class BoundParameter
    {
        private readonly OAuthContext context;

        private readonly string name;

        /// <summary>
        /// Initializes a new instance of the <see cref="BoundParameter"/> class.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="context">The context.</param>
        public BoundParameter ( string name , OAuthContext context )
        {
            this.name = name;
            this.context = context;
        }

        /// <summary>
        /// Gets or sets the value.
        /// </summary>
        /// <value>The value.</value>
        public string? Value
        {
            get
            {
                return this.context.AuthorizationHeaderParameters? [ this.name ] != null
                    ? this.context.AuthorizationHeaderParameters [ this.name ]
                    : this.context.QueryParameters [ this.name ] ?? this.context.FormEncodedParameters [ this.name ] ?? null;
            }

            set
            {
                if ( value == null )
                {
                    this.Collection.Remove ( this.name );
                }
                else
                {
                    this.Collection [ this.name ] = value;
                }
            }
        }

        /// <summary>
        /// Gets the collection.
        /// </summary>
        /// <value>The collection.</value>
        private NameValueCollection Collection
        {
            get
            {
                return this.context.UseAuthorizationHeader
                    ? this.context.AuthorizationHeaderParameters ?? [ ]
                    : this.context.RequestMethod == "GET" ? this.context.QueryParameters : this.context.FormEncodedParameters;
            }
        }
    }
}