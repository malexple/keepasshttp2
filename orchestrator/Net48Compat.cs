// Compatibility shim required to compile C# 9+ init-only properties
// (used by our `record` DTOs) when targeting net48. This type is a
// no-op marker the compiler looks for at compile time only; it has no
// runtime behavior of its own. Present natively in .NET 5+, absent from
// .NET Framework, so we declare it ourselves. Remove this file if the
// project is ever moved back to a modern .NET TFM.

namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit
    {
    }
}
