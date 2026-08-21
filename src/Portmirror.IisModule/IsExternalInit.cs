namespace System.Runtime.CompilerServices;

// net48 lacks this type, which the compiler requires for `init`-only setters used by the
// source-linked models. Providing it lets those files compile unchanged into this assembly.
internal static class IsExternalInit
{
}
