using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: AssemblyCompany("Government of Singapore")]
[assembly: AssemblyCopyright("Copyright © 2022")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

// Allow CI/CD to stamp this
[assembly: AssemblyInformationalVersion("local-build")]

#if DEBUG
[assembly: AssemblyProduct("MyInfoConnector (Debug)")]
[assembly: AssemblyConfiguration("Debug")]
#else
    [assembly: AssemblyProduct("MyInfoConnector (Release)")]
    [assembly: AssemblyConfiguration("Release")]
#endif
