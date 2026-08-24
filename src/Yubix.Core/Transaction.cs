using System.Runtime.InteropServices;
using System.Text;

namespace Yubix.Core;

/// <summary>A desired end-state for one file: content, or null = must not exist.</summary>
public sealed record FileChange(string Dest, string? NewContent);

public sealed record TransactionResult(string ManifestPath, string BackupDir);

/// <summary>
/// Applies a set of file changes transactionally, in two stages: Prepare
/// copies every original to a timestamped backup dir and writes a plain-text
/// manifest that the POSIX-sh yubix-restore script (and Restore below) can
/// replay; Commit mutates the targets. Callers that arm a failsafe (the
/// pending-apply flag) do so between the stages, so a crash at any point
/// leaves either untouched files or an armed failsafe.
/// Manifest line format (tab-separated):
///   restore\t&lt;dest&gt;\t&lt;backup&gt;   — file existed; copy backup over dest
///   delete\t&lt;dest&gt;               — file did not exist; remove dest
/// </summary>
public static partial class Transaction
{
    public static TransactionResult Apply(YubixPaths paths, IReadOnlyList<FileChange> changes, string label)
    {
        var tx = Prepare(paths, changes, label);
        Commit(changes);
        return tx;
    }

    /// <summary>Stage 1: backups + manifest, durably on disk. Mutates nothing.</summary>
    public static TransactionResult Prepare(YubixPaths paths, IReadOnlyList<FileChange> changes, string label)
    {
        CreatePrivateDir(paths.StateDir);
        CreatePrivateDir(paths.BackupsDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss.fff") + "-" + label;
        var backupDir = Path.Combine(paths.BackupsDir, stamp);
        CreatePrivateDir(backupDir);

        var manifest = new List<string>();
        foreach (var change in changes)
        {
            if (File.Exists(change.Dest))
            {
                var backup = Path.Combine(backupDir, BackupName(change.Dest));
                File.Copy(change.Dest, backup, overwrite: true);
                FsyncPath(backup);
                manifest.Add($"restore\t{change.Dest}\t{backup}");
            }
            else
            {
                manifest.Add($"delete\t{change.Dest}");
            }
        }

        var manifestPath = Path.Combine(backupDir, "manifest.txt");
        WriteAtomically(manifestPath, string.Join('\n', manifest) + "\n");
        FsyncPath(backupDir);
        return new TransactionResult(manifestPath, backupDir);
    }

    /// <summary>Stage 2: write the new contents. Only safe after Prepare.</summary>
    public static void Commit(IReadOnlyList<FileChange> changes)
    {
        foreach (var change in changes)
        {
            if (change.NewContent is null)
            {
                if (File.Exists(change.Dest))
                {
                    File.Delete(change.Dest);
                    FsyncPath(Path.GetDirectoryName(change.Dest)!);
                }
                continue;
            }
            WriteAtomically(change.Dest, change.NewContent);
        }
    }

    /// <summary>Backups are named by the flattened full path — two dests that
    /// share a basename (/etc/pam.d/sudo vs /usr/lib/pam.d/sudo) must not
    /// overwrite each other's backup.</summary>
    private static string BackupName(string dest) => dest.Trim('/').Replace('/', '_');

    public static void WriteAtomically(string dest, string content, UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead)
    {
        var dir = Path.GetDirectoryName(dest)!;
        Directory.CreateDirectory(dir);
        // Unpredictable O_EXCL temp name, mode set at creation: nothing can
        // pre-plant the file, and it is never observable with wrong bits.
        var tmp = Path.Combine(dir, $".{Path.GetFileName(dest)}.yubix-tmp.{Path.GetRandomFileName()}");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = mode;
        try
        {
            using (var fs = new FileStream(tmp, options))
            {
                fs.Write(Encoding.UTF8.GetBytes(content));
                fs.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(tmp, mode); // exact bits even under a restrictive umask
            File.Move(tmp, dest, overwrite: true);
        }
        catch
        {
            try { File.Delete(tmp); } catch { }
            throw;
        }
        FsyncPath(dir);
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
                    FsyncPath(parts[1]);
                    break;
                case "delete" when parts.Length >= 2:
                    if (File.Exists(parts[1]))
                    {
                        File.Delete(parts[1]);
                        FsyncPath(Path.GetDirectoryName(parts[1])!);
                    }
                    break;
            }
        }
    }

    /// <summary>0700 — backups contain copies of auth configuration and the
    /// state dir holds the failsafe flag; neither is world-readable business.</summary>
    internal static void CreatePrivateDir(string path)
    {
        const UnixFileMode Private = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
            return;
        }
        Directory.CreateDirectory(path, Private);
        File.SetUnixFileMode(path, Private); // converge dirs from older versions too
    }

    // Directories cannot be opened through FileStream/File.OpenHandle in
    // .NET, so the fsync that makes a rename/backup durable goes through
    // libc directly. Best-effort: an fsync miss only narrows the crash
    // window, while the tmp-file data itself is flushed strictly above.
    private const int O_RDONLY = 0;

    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static partial int LibcOpen(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fsync")]
    private static partial int LibcFsync(int fd);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int LibcClose(int fd);

    private static void FsyncPath(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        var fd = LibcOpen(path, O_RDONLY);
        if (fd < 0) return;
        try { LibcFsync(fd); } finally { LibcClose(fd); }
    }
}
