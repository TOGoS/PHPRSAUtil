<?php

class TOGoS_RSAUtil_SignatureVerifierTest extends PHPUnit_Framework_TestCase
{
	public function testVerifyValidSignature() {
		$keyPair = TOGoS_RSAUtil::generateKeyPair(array('size'=>2048)); // For faster unit testing
		
		$DS = new TOGoS_RSAUtil_DataStore();
		
		$pubKeyUri = $DS->store($keyPair['publicKeyDer']);
		// I guess we're also testing generateKeyPair, then.
		$this->assertEquals($pubKeyUri, $keyPair['publicKeyUrn']);
		
		$data = "Hello, world!";
		
		$sig = TOGoS_RSAUtil::sign($data, $keyPair['privateKeyDer'], $pubKeyUri);
		
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
