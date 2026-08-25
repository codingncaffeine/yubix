using System.Runtime.Versioning;

// The helper edits Linux PAM files, drives libpam through a child process and
// sets Unix file modes: it is a Linux-only program by construction, and there
// is no build of it that isn't. Declaring that is what stops the platform
// compatibility analyser flagging calls like File.SetUnixFileMode, which it
// otherwise has to assume might run somewhere those APIs don't exist. Nothing
// references this assembly, so the constraint can't propagate anywhere.
[assembly: SupportedOSPlatform("linux")]
