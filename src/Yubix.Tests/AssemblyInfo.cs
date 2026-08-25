using System.Runtime.Versioning;

// These tests exercise Linux PAM layouts, Unix file modes and a POSIX shell
// script — there is no platform other than Linux for them to run on, and
// saying so keeps the platform compatibility analyser quiet about calls like
// File.GetUnixFileMode. Matches the same declaration on Yubix.Helper.
[assembly: SupportedOSPlatform("linux")]
