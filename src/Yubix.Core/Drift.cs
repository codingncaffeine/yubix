using System.Security.Cryptography;
using System.Text;

namespace Yubix.Core;

/// <summary>
/// Detects the ways an OS update (or an admin) can invalidate our PAM setup
/// behind our back. At apply time the helper records what it derived the
/// override from (vendor content hash) and what it wrote (generated hash);
/// comparing those against the live files distinguishes every case
/// mechanically — the Debian pam-auth-update idea.
/// </summary>
public static class Drift
{
    public static string Sha256Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    /// <summary>Flags for one surface. Empty list = clean (or nothing recorded).</summary>
    public static List<string> Classify(SurfaceRecord? record, string? etcContent, string? vendorContent)
    {
        var flags = new List<string>();
        if (record is null) return flags;

        if (etcContent is null)
        {
            // The override we wrote is gone entirely (manual delete, --overwrite install).
            flags.Add("overrideMissing");
        }
        else if (!PamGenerator.HasMarker(etcContent))
        {
            // File exists but our line is gone — the classic pacdiff-overwrite
            // aftermath. In 2FA mode this is a silent security downgrade.
            flags.Add("markerLost");
        }
        else if (record.GeneratedSha256 is not null && Sha256Hex(etcContent) != record.GeneratedSha256)
        {
            // Our line is still there but someone edited around it — show, don't touch.
            flags.Add("thirdPartyEdit");
        }

        if (record.VendorExisted)
        {
            if (vendorContent is null)
                flags.Add("orphanedOverride");   // vendor twin vanished (package rename/migration)
            else if (record.VendorSha256 is not null && Sha256Hex(vendorContent) != record.VendorSha256)
                flags.Add("vendorDrift");        // vendor changed under our stale copy
        }
        else if (vendorContent is not null)
        {
            flags.Add("vendorAppeared");         // a package now ships the file we created
        }

        return flags;
    }

    /// <summary>Human wording for each flag, used by the GUI log and docs.</summary>
    public static string Describe(string flag) => flag switch
    {
        "overrideMissing" => "the PAM file Yubix wrote no longer exists — key auth is off for this surface",
        "markerLost" => "the Yubix line is gone from the PAM file (a pacnew overwrite?) — key auth is off for this surface",
        "thirdPartyEdit" => "the PAM file was edited outside Yubix (Yubix will not auto-touch it)",
        "orphanedOverride" => "the vendor PAM file this was based on has disappeared — the surface may have been renamed by an update",
        "vendorDrift" => "the vendor PAM file changed in an update; the Yubix copy is stale — re-apply to pick up the new base",
        "vendorAppeared" => "a package now ships a vendor file for this surface — the file in /etc/pam.d shadows it, so the new vendor version is not in use",
        _ => flag,
    };
}
