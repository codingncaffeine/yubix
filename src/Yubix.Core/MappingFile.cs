namespace Yubix.Core;

/// <summary>
/// Manages the central u2f mapping file content. Format (pam_u2f):
/// one line per user — `user:cred1:cred2:...` where each cred is
/// `keyhandle,pubkey,type,options`. pamu2fcfg prints `user:cred` (or `:cred`
/// with -n); we normalize to the credential part and merge ourselves.
/// </summary>
public static class MappingFile
{
    /// <summary>Extracts the credential portion from raw pamu2fcfg stdout.</summary>
    public static string ExtractCredential(string pamu2fcfgOutput, string user)
    {
        var line = pamu2fcfgOutput.Trim().Split('\n')[^1].Trim();
        if (line.Length == 0)
            throw new FormatException("pamu2fcfg produced no output");

        string cred;
        if (line.StartsWith(user + ":", StringComparison.Ordinal))
            cred = line[(user.Length + 1)..];
        else if (line.StartsWith(':'))
            cred = line[1..];
        else if (!line.Contains(':') && line.Contains(','))
            cred = line; // bare credential
        else
        {
            // Unexpected username prefix — take everything after the first colon.
            var i = line.IndexOf(':');
            cred = i >= 0 ? line[(i + 1)..] : line;
        }

        if (cred.Length == 0 || !cred.Contains(','))
            throw new FormatException("pamu2fcfg output does not look like a credential");
        if (cred.Contains('\n') || cred.Contains(' '))
            throw new FormatException("credential contains unexpected whitespace");
        return cred;
    }

    /// <summary>Merges a new credential into existing mapping content.</summary>
    public static string Merge(string existingContent, string user, string credential)
    {
        var lines = existingContent.Replace("\r\n", "\n").Split('\n')
            .Where(l => l.Trim().Length > 0)
            .ToList();

        var idx = lines.FindIndex(l => l.StartsWith(user + ":", StringComparison.Ordinal));
        if (idx >= 0)
            lines[idx] = lines[idx] + ":" + credential;
        else
            lines.Add(user + ":" + credential);

        return string.Join('\n', lines) + "\n";
    }

    public static int CredentialCount(string content, string user)
    {
        foreach (var line in content.Split('\n'))
        {
            if (!line.StartsWith(user + ":", StringComparison.Ordinal)) continue;
            return line.Split(':').Length - 1;
        }
        return 0;
    }

    public static IEnumerable<string> Users(string content) =>
        content.Split('\n')
            .Where(l => l.Contains(':'))
            .Select(l => l.Split(':')[0].Trim())
            .Where(u => u.Length > 0);
}
