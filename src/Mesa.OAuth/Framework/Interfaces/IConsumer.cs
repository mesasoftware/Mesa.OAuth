namespace Mesa.OAuth.Framework.Interfaces
{
    public interface IConsumer
    {
        string? ConsumerKey { get; set; }

        string? Realm { get; set; }
    }
}