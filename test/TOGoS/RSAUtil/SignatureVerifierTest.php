<?php

class TOGoS_RSAUtil_SignatureVerifierTest extends PHPUnit_Framework_TestCase
{
	public function testVerifyValidSignature() {
		$keyPair = TOGoS_RSAUtil_KeyPair::generate(array('size'=>1024)); // For faster unit testing
		
		$DS = new TOGoS_RSAUtil_DataStore();
		
		$pubKeyUri = $DS->store($keyPair->getPublicKeyDer());
		// I guess we're also testing generateKeyPair, then.
		$this->assertEquals($pubKeyUri, $keyPair->getPublicKeyUri());
		
		$data = "Hello, world!";
		
		$sig = TOGoS_RSAUtil::sign($data, $keyPair);
		
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
