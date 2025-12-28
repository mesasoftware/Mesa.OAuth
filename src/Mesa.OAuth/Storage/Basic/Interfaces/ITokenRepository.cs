namespace Mesa.OAuth.Storage.Basic.Interfaces
{
    using Mesa.OAuth.Framework;
    using Mesa.OAuth.Storage.Interfaces;

    /// <summary>
    /// A simplistic repository for access and request of token models - the example implementation of
    /// <see cref="ITokenStore" /> relies on this repository - normally you would make use of repositories
    /// wired up to your domain model i.e. NHibernate, Entity Framework etc.
    /// </summary>
    public interface ITokenRepository<T> where T : TokenBase
    {
        /// <summary>
        /// Gets an existing token from the underlying store
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        T GetToken ( string? token );

        /// <summary>
        /// Saves the token in the underlying store
        /// </summary>
        /// <param name="token"></param>
        void SaveToken ( T token );
    }
}