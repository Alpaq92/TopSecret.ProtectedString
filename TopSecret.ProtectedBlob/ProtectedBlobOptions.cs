namespace TopSecret;

public static class ProtectedBlobOptions
{
    private static int s_defaultChunkSize = ProtectedBlob.DefaultChunkSize;

    public static int DefaultChunkSize
    {
        get => s_defaultChunkSize;
        set
        {
            ProtectedBlob.ValidateChunkSize(value, nameof(value));
            s_defaultChunkSize = value;
        }
    }
}
