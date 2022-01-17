# TestHook

A xposed module which can hook common Java crypto methods and print logs.

## Feature

Help you get the arguments/results of the following Java crypto methods:

* `java.security.MessageDigest.digest()`
* `java.security.MessageDigest.digest(byte[] input)`
* `java.security.MessageDigest.update()`
* `java.security.MessageDigest.update(byte[] input)`
* `java.security.MessageDigest.update(byte[] input, int offset, int len)`
* `javax.crypto.Mac.doFinal()`
* `javax.crypto.Mac.doFinal(byte[] input)`
* `javax.crypto.Mac.doFinal(byte[] output, int outOffset)`
* `javax.crypto.spec.SecretKeySpec(byte[] key, String algorithm)`
* `javax.crypto.spec.SecretKeySpec(byte[] key, int offset, int len, String algorithm)`
* `javax.crypto.spec.DESKeySpec(byte[] key)`
* `javax.crypto.spec.DESKeySpec(byte[] key, int offset)`
* `javax.crypto.spec.IvParameterSpec(byte[] iv)`
* `javax.crypto.spec.IvParameterSpec(byte[] iv, int offset, int len)`
* `javax.crypto.spec.DESedeKeySpec(byte[] key)`
* `javax.crypto.spec.DESedeKeySpec(byte[] key, int offset)`
* `javax.crypto.Cipher.doFinal()`
* `javax.crypto.Cipher.doFinal(byte[] input)`
* `javax.crypto.Cipher.doFinal(byte[] input, int inputOffset, int inputLen)`
* `java.security.spec.X509EncodedKeySpec(byte[] encodedKey)`
* `java.security.spec.PKCS8EncodedKeySpec(byte[] encodedKey)`
* `java.security.spec.RSAPublicKeySpec(BigInteger modulus, BigInteger publicExponent)`
* `java.security.spec.RSAPrivateKeySpec(BigInteger modulus, BigInteger privateExponent)`

# Tips

This repo is just a toy, if you really need this, please try [frida](https://frida.re/docs/home/).