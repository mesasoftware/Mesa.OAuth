namespace Mesa.OAuth.Framework.Interfaces
{
    public interface IToken : IConsumer
    {
        string? SessionHandle { get; set; }

        string? Token { get; set; }

        string? TokenSecret { get; set; }
    }
}