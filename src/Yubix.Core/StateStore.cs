using System.Text.Json;

namespace Yubix.Core;

public static class StateStore
{
    public static YubixState Load(YubixPaths paths)
    {
        try
        {
            if (File.Exists(paths.StateFile))
                return JsonSerializer.Deserialize<YubixState>(
                    File.ReadAllText(paths.StateFile), Json.Options) ?? new YubixState();
        }
        catch
        {
            // Corrupt state must never brick the helper; fall through to defaults.
        }
        return new YubixState();
    }

    public static void Save(YubixPaths paths, YubixState state)
    {
        Directory.CreateDirectory(paths.StateDir);
        var json = JsonSerializer.Serialize(state,
            new JsonSerializerOptions(Json.Options) { WriteIndented = true });
        Transaction.WriteAtomically(paths.StateFile, json,
            UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
