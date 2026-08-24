namespace Yubix.Helper;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length >= 3 && args[0] == "--pam-test")
            return PamTestChild.Run(args[1], args[2]);

        return await HelperDaemon.RunAsync();
    }
}
