# CryptoHelper
Cryptography helper methods for hasing passwords using a PBKDF2 implemenation.

This utility ports the password hashing functionality from the  [`System.Web.Helpers.Crypto`](http://aspnetwebstack.codeplex.com/SourceControl/latest#src/System.Web.Helpers/Crypto.cs) class to DNX. On DNX the new ASP.NET Data Protection stack is used. Where as classic .NET 4.0 and 4.5 applications  will use `Rfc2898DeriveBytes` 

### [**Download CryptoHelper using NuGet**](https://www.nuget.org/packages/CryptoHelper)

##### Download from the NuGet Package Manager Console:
```
Install-Package CryptoHelper
```
