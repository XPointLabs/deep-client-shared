namespace Deep.Client.Shared.Services;

/// <summary>Informative result of the account owner's completed original
/// Initial expiry transition. Not noncommit, recall or new-send authority.</summary>
public sealed class DeepIdV2ContactRetryExpiredException : IOException
{
    public DeepIdV2ContactRetryExpiredException()
        : base("The original contact request retry is expired and closed; remote receipt remains possible.") { }
}
