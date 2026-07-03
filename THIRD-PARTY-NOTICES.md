# Third-party material and references

`TopSecret.ProtectedString` is licensed under the [MIT License](LICENSE). This
file records the third-party material the project incorporates, builds on, or
cites. Entries are grouped by license, then by how this project uses them.



Apache License 2.0  -- https://www.apache.org/licenses/LICENSE-2.0


Icon assets (shipped in assets/string/icon.png / assets/string/icon.svg):
  - Material Design Icons "shield" glyph -- silhouette underlying the package icon.   https://pictogrammers.com/library/mdi/icon/shield/
  - Material Design Icons "alpha-t" glyph -- "T" overlay on the package icon.   https://pictogrammers.com/library/mdi/icon/alpha-t/
  (Combined notice for both glyphs: https://github.com/Templarian/MaterialDesign/blob/master/LICENSE)

Reference implementation (informational citation, no code reuse):
  - phc-winner-argon2 -- Argon2 designers' reference C implementation, used to cross-check the managed Argon2id wiring.   https://github.com/p-h-c/phc-winner-argon2



MIT License  -- https://opensource.org/licenses/MIT


Runtime dependencies (resolved transitively by the published NuGet packages):
  - Konscious.Security.Cryptography.Argon2 -- Argon2id KDF used by ComputeArgon2idHash and VerifyArgon2idHash.   https://github.com/kmaragon/Konscious.Security.Cryptography
  - Microsoft.TSS -- Microsoft Research's TPM Software Stack; runtime dependency of the optional TopSecret.ProtectedString.LinuxTpm subpackage for TPM 2.0 command marshalling against /dev/tpmrm0.   https://github.com/microsoft/TSS.MSR

Build-time-only dependencies (PrivateAssets="all"; not shipped in the NuGet output):
  - Microsoft.SourceLink.GitHub -- embeds repository source-link metadata into the symbol package.   https://github.com/dotnet/sourcelink

Test-only dependencies (not shipped in the NuGet output):
  - NUnit -- test framework used by the unit-test suite.   https://nunit.org/
  - NUnit3TestAdapter -- VSTest adapter that lets `dotnet test` discover NUnit tests.   https://github.com/nunit/nunit3-vs-adapter
  - NUnit.Analyzers -- Roslyn analyzers that catch common NUnit-test mistakes.   https://github.com/nunit/nunit.analyzers
  - Microsoft.NET.Test.Sdk -- VSTest host the test runner uses to load the test assembly.   https://github.com/microsoft/vstest
  - coverlet.collector -- code-coverage data collector for the test suite.   https://github.com/coverlet-coverage/coverlet



CDDL 1.0  -- https://opensource.org/licenses/CDDL-1.0


Design inspiration (no code copied; independent C# reimplementation):
  - Evolveum GuardedString (OpenICF / ConnId connector framework) -- the encrypted-at-rest buffer, callback-based Access, and AppendChar / MakeReadOnly API shape are modelled after this Java class.   https://github.com/Evolveum/openicf/blob/master/framework/java/connector-framework/src/main/java/org/identityconnectors/common/security/GuardedString.java



CC BY-SA 4.0  -- https://creativecommons.org/licenses/by-sa/4.0/


Design inspiration (Stack Overflow answers and comments; thread "How to protect strings without SecureString?" -- https://stackoverflow.com/questions/55590869):
  - Ian Boyd's answer -- named the class "ProtectedString" and proposed the CryptProtectMemory wrapping approach.
  - Dai's answer -- described the AppendChar one-keystroke-at-a-time input pattern that the library implements.
  - Patrick Hofman's answer -- "any homebrew will likely be less secure than Microsoft's" caveat that informs the threat-model section.
  - nvoigt's answer -- "if you can authenticate with certs instead of credentials, do that" caveat that informs the threat-model section.
  - Panagiotis Kanavos's comments -- "at the moment of use, all bets are off" critique that motivates Dispose / wipe / pinned-buffer machinery.

Parameter guidance (informational citation):
  - OWASP Password Storage Cheat Sheet -- source of the Argon2id defaults exposed by DefaultArgon2id* constants.   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html



IETF / RFC  -- no copyright restrictions on technical use; see RFC 5378


Algorithm specification:
  - RFC 9106 -- "Argon2 Memory-Hard Function for Password Hashing", the algorithm specification.   https://datatracker.ietf.org/doc/html/rfc9106



## Microsoft documentation and issue trackers  -- referenced under documentation fair use


Background reading on SecureString deprecation:
  - Microsoft Learn -- System.Security.SecureString reference page (the official "don't use this for new code" notice).   https://learn.microsoft.com/en-us/dotnet/fundamentals/runtime-libraries/system-security-securestring
  - .NET platform-compat DE0001 -- formal deprecation analyser entry for SecureString.   https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md
  - dotnet/runtime issue #30612 -- canonical issue tracking SecureString obsolescence.   https://github.com/dotnet/runtime/issues/30612

Background reading on pinned memory and zeroing:
  - Microsoft Learn -- GC.AllocateArray<T>(Int32, Boolean) reference.   https://learn.microsoft.com/en-us/dotnet/api/system.gc.allocatearray
  - dotnet/runtime discussion #48697 -- why Array.Clear is not a guaranteed wipe and CryptographicOperations.ZeroMemory is.   https://github.com/dotnet/runtime/discussions/48697
  - dotnet/runtime issue #27146 -- design discussion behind GC.AllocateArray and the pinned object heap.   https://github.com/dotnet/runtime/issues/27146

Background reading on memory protection (key-at-rest wrapping research):
  - Microsoft Learn -- CryptProtectMemory function reference.   https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory

Background reading on Apple Secure Enclave (AppleSecKeyProtector implementation):
  - Apple Platform Security -- "The Secure Enclave" chapter describing SEP architecture and key handling.   https://support.apple.com/guide/security/the-secure-enclave-sec59b0b31ff/web
  - Apple Developer -- "Protecting keys with the Secure Enclave" code-level guide for SecKey + ECIES.   https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
  - Apple Platform Security -- "Keychain data protection" overview of accessibility classes.   https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web

Background reading on Android Keystore (AndroidKeystoreProtector implementation):
  - Android developer docs -- Android Keystore system overview, used to wire up AndroidKeystoreProtector.   https://developer.android.com/privacy-and-security/keystore
  - AOSP -- hardware-backed Keystore (TEE / StrongBox) reference for the security model.   https://source.android.com/docs/security/features/keystore

Background reading on Windows TPM 2.0 (WindowsTpmProtector implementation):
  - Microsoft Learn -- NCrypt API reference, used by the optional TopSecret.ProtectedString.WindowsTpm subpackage.   https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/
  - Microsoft Learn -- "Microsoft Platform Crypto Provider" documentation for TPM-backed CNG keys.   https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers

Background reading on Linux TPM 2.0 (LinuxTpmProtector implementation):
  - Linux kernel docs -- in-kernel TPM resource manager (/dev/tpmrm0) reference.   https://docs.kernel.org/security/tpm/tpm-security.html
  - TCG -- TPM 2.0 Library Specification, the wire-protocol the Microsoft.TSS dependency speaks.   https://trustedcomputinggroup.org/resource/tpm-library-specification/



## Independent technical writing  -- cited under fair use for design and audit context


Pinned memory and secret zeroing:
  - Geralt -- "Secure memory in .NET", reference write-up for the GC.AllocateArray + CryptographicOperations.ZeroMemory pattern.   https://www.geralt.xyz/secure-memory

AES-GCM correctness and pitfalls:
  - Scott Brady -- "Authenticated Encryption in .NET with AES-GCM", practical .NET-side guide.   https://www.scottbrady.io/c-sharp/aes-gcm-dotnet
  - Soatok -- "Why AES-GCM Sucks", critique of cache-timing and nonce-reuse failure modes.   https://soatok.blog/2020/05/13/why-aes-gcm-sucks/
  - AquilaX -- "Cryptographic Implementation Vulnerabilities", concrete failure cases.   https://aquilax.ai/blog/cryptographic-implementation-vulnerabilities
  - NIST CSRC -- "Practical Challenges with AES-GCM", academic perspective on AES-GCM limits.   https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Practical%20Challenges%20with%20AES-GCM.pdf

SecureString context:
  - The Security Vault -- "Breaking C# SecureString", demonstration that SecureString does not keep secrets out of memory dumps.   https://thesecurityvault.com/breaking_c_sharp_securestring/

Master-key-at-rest research:
  - slowerzs.net -- public PoC that decrypts CryptProtectMemory-protected memory in-process; the basis for treating Windows DPAPI as obscurity-only.   https://blog.slowerzs.net/posts/cryptdecryptmemory/
  - Cloudflare -- "The Linux kernel key retention service", evaluation of why the keyring cannot hold a symmetric AES key for in-kernel use.   https://blog.cloudflare.com/the-linux-kernel-key-retention-service-and-why-you-should-use-it-in-your-next-application/
  - LWN -- coverage of memfd_secret(2) landing in Linux 5.14.   https://lwn.net/Articles/865256/
  - man7.org -- memfd_secret(2) man page used to bound what the primitive defends.   https://man7.org/linux/man-pages/man2/memfd_secret.2.html
  - kernel.org -- Linux key retention service documentation.   https://docs.kernel.org/security/keys/core.html
  - saweis.net -- "State of SGX Development", basis for ruling SGX out as a portable target.   https://saweis.net/posts/State-of-SGX-Development.html
  - spacetime.dev -- Boojum write-up; basis for treating split-secret schemes as obscurity-only against heap dumps.   https://spacetime.dev/encrypting-secrets-in-memory
  - darthnull.org -- "ECIES on the Secure Enclave", reference for the SEP-EC-wrap shape used in AppleSecKeyProtector.   https://darthnull.org/secure-enclave-ecies/

Password hashing background:
  - Password Hashing Competition (2013-2015) -- the open competition that selected Argon2.   https://www.password-hashing.net/



## Brand reference  -- color palette only, no asset or code reuse


Package icon palette:
  - Jellyfin brand gradient (#AA5CC3 -> #00A4DC) -- used as the colour reference for the shield silhouette in the package icon; this project is not affiliated with or endorsed by Jellyfin, and brand assets remain (c) the Jellyfin Project.   https://commons.wikimedia.org/wiki/Category:Jellyfin
  - Jellyfin dev-icon gradient (#F2364D -> #FDC92F, from "Jellyfin_-_icon-solid-dev.svg", CC BY-SA 4.0, (c) the Jellyfin contributors) -- used as the colour reference for the shield silhouette in the ProtectedBlob package icon (assets/blob/icon.svg); palette reference only, no asset reuse.   https://commons.wikimedia.org/wiki/Category:Jellyfin#/media/File:Jellyfin_-_icon-solid-dev.svg
  - Jellyfin vue-icon gradient (#41B883 -> #34495E, from "Jellyfin_-_icon-solid-vue.svg", CC BY-SA 4.0, (c) the Jellyfin contributors) -- used as the colour reference for the shield silhouette in the satellite-package icon (assets/rest/icon.svg: WindowsTpm, LinuxTpm, Configuration); palette reference only, no asset reuse.   https://commons.wikimedia.org/wiki/Category:Jellyfin#/media/File:Jellyfin_-_icon-solid-vue.svg



## Wikipedia  -- CC BY-SA 4.0  -- https://creativecommons.org/licenses/by-sa/4.0/


Background reading:
  - "White-box cryptography" -- basis for excluding white-box AES from the implementation options.   https://en.wikipedia.org/wiki/White-box_cryptography
