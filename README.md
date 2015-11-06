[![Build Status](https://travis-ci.org/TOGoS/PHPRSAUtil.svg?branch=master)](https://travis-ci.org/TOGoS/PHPRSAUtil)

# PHP RSA Util

Utilities for generating and verifying signatures and converting
between various key formats.

Primary operations revolve around ```TOGoS_RSAUtil_Signature```
objects, which represent the signing of a specific piece of data with
a specific key.
A Signature indicates the key and data (either inline or by a hash URI),
the algorithm used to calculate the signature, and the signature data
itself.

See http://www.nuke24.net/docs/2012/RSA.html for my personal
collection of information about key formats.

## Usage example

```php
/*
 * Assuming $dataStore is an object that the guy verifying also has
 * access to
 */

$privateKey = file_get_contents('private-key.der'); // Will work with 'pem' files, too.
$publicKey  = file_get_contents('public-key.der');
$payload = "Hello!";

$dataStore->store($payload);
$dataStore->store($publicKey);

$publicKeyUri = "urn:sha1:".TOGoS_Base32::encode(hash('sha1',$publicKey,true));
$sig = TOGoS_RSAUtil::sign($payload, $privateKey, OPENSSL_ALGO_SHA1);


$sigCodec = new TOGoS_RSAUtil_BAA3SignatureCodec();
$sigBlob = $sigCodec->encode($sig);
```

Send ```$sigBlob``` to someone, and they can...

```php
/*
 * Assuming $dataStore and $sigBlob are input variables
 * Using BAA3 codec, the public key and payload data are referenced by
 * but not contained in the signature.  We fetch them from $dataStore.
 */

$sigCodec = new TOGoS_RSAUtil_BAA3SignatureCodec();
$sig = $sigCodec->decode($sigBlob);
TOGoS_RSAUtil::verify($sig, $dataStore);
echo "Signature was valid!  Here's the data!\n";
echo (string)$dataStore->getBlob($sig->getPayloadUri());
```
