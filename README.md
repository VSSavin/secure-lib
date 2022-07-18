Simple secure library.
Implements 'Secure' interface:
- AES encodind/decoding;
- RSA encoding/decoding;

Implements platform specific (OS dependent) interfaces 'PlatformSecure' (for generating secure key) and 'PlatformSpecificSecure' (for encoding/decoding messages).
Use the static method 'PlatformSecureFactory.getPlatformSecurity()'' to get the platform specific implementation of the interface 'PlatformSecure'.
See tests as examples.