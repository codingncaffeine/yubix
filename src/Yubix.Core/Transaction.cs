namespace Yubix.Core;

/// <summary>A desired end-state for one file: content, or null = must not exist.</summary>
public sealed record FileChange(string Dest, string? NewContent);

public sealed record TransactionResult(string ManifestPath, string BackupDir);

/// <summary>
/// Applies a set of file changes transactionally: every original is copied to
/// a timestamped backup dir first and a plain-text manifest is written that
/// the POSIX-sh yubix-restore script (and Restore below) can replay.
/// Manifest line format (tab-separated):
///   restore\t&lt;dest&gt;\t&lt;backup&gt;   — file existed; copy backup over dest
///   delete\t&lt;dest&gt;               — file did not exist; remove dest
/// </summary>
public static class Transaction
{
    public static TransactionResult Apply(YubixPaths paths, IReadOnlyList<FileChange> changes, string label)
    {
        Directory.CreateDirectory(paths.BackupsDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss.fff") + "-" + label;
        var backupDir = Path.Combine(paths.BackupsDir, stamp);
        Directory.CreateDirectory(backupDir);

        var manifest = new List<string>();
        foreach (var change in changes)
        {
            if (File.Exists(change.Dest))
            {
                var backup = Path.Combine(backupDir, Path.GetFileName(change.Dest));
                File.Copy(change.Dest, backup, overwrite: true);
                manifest.Add($"restore\t{change.Dest}\t{backup}");
            }
            else
            {
                manifest.Add($"delete\t{change.Dest}");
            }
        }

        var manifestPath = Path.Combine(backupDir, "manifest.txt");
        File.WriteAllText(manifestPath, string.Join('\n', manifest) + "\n");

        // Backups are safely on disk — now mutate.
        foreach (var change in changes)
        {
            if (change.NewContent is null)
            {
                if (File.Exists(change.Dest)) File.Delete(change.Dest);
                continue;
            }
            WriteAtomically(change.Dest, change.NewContent);
        }

        return new TransactionResult(manifestPath, backupDir);
    }

    public static void WriteAtomically(string dest, string content, UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        var tmp = dest + ".yubix-tmp";
        File.WriteAllText(tmp, content);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, mode);
        File.Move(tmp, dest, overwrite: true);
    }

    /// <summary>Replays a manifest — the managed twin of the yubix-restore script.</summary>
    public static void Restore(string manifestPath)
    {
        foreach (var raw in File.ReadAllLines(manifestPath))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            var parts = line.Split('\t');
            switch (parts[0])
            {
                case "restore" when parts.Length >= 3:
                    File.Copy(parts[2], parts[1], overwrite: true);
                    break;
                case "delete" when parts.Length >= 2:
                    if (File.Exists(parts[1])) File.Delete(parts[1]);
                    break;
            }
        }
    }
}
