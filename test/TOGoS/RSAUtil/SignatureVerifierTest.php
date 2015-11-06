<?php

class TOGoS_RSAUtil_SignatureVerifierTest extends PHPUnit_Framework_TestCase
{
	public function testVerifyValidSignature() {
		$key = openssl_pkey_new( array(
			'digest_alg' => 'sha1',
			'private_key_bits' => 2048, // For faster unit testing
			'private_key_type' => OPENSSL_KEYTYPE_RSA
		) );
		
		$det = openssl_pkey_get_details($key);
		//print_r($det);
		
		/** PEM-formatted public key */
		$pubKeyPem = $det['key'];
		$pubKeyDer = TOGoS_RSAUtil_Util::pemToDer($pubKeyPem);
		
		$DS = new TOGoS_RSAUtil_DataStore();
		$pubKeyUri = $DS->store($pubKeyDer);
		
		$data = "Hello, world!";
		
		$sig = TOGoS_RSAUtil::sign($data, $key, $pubKeyUri);
		
		$this->assertTrue(TOGoS_RSAUtil::verif($sig, $DS), "Signature should have verified!");

		// Change the data and make sure the signature's no longer valid!
		$badSig = new TOGoS_RSAUtil_Signature(
			$sig->getPublicKeyUri(),
			Nife_Util::blob($data.'; drop all tables'),
			$sig->getAlgorithmName(),
			$sig->getSignatureBytes());
		
		$this->assertFalse(TOGoS_RSAUtil::verif($badSig, $DS), "Signature should have verified!");
	}
}
