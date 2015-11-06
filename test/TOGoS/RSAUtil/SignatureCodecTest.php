<?php

abstract class TOGoS_RSAUtil_SignatureCodecTest extends PHPUnit_Framework_TestCase
{
	protected abstract function makeCodec();
	
	public function testEncodeDecode() {
		$codec = $this->makeCodec();
		
		$payload = new Nife_StringBlob("Hello, world!");
		//$keyUrn = 'urn:bitprint:RPWPDCR73XTHHWTKZM6EWTCAYPIYSTIG.H2FMJSBMXRRHCNASUHMXRVTIXAN2QZPJB4VIZAY';
		$keyUrn = 'urn:sha1:RPWPDCR73XTHHWTKZM6EWTCAYPIYSTIG';
		
		$payloadThing = $codec->supportsInlinePayload() ? $payload : "urn:sha1:".TOGoS_Base32::encode(hash('sha1',$payload,true));
		
		$sig = new TOGoS_RSAUtil_Signature($keyUrn, $payloadThing, "SHA1withRSA", "xyz123"); // Obviously not a /valid/ signature.
		
		$blah = $codec->encode($sig);
		$this->assertTrue( $blah instanceof Nife_Blob, "Encoded signature's not a Nife_Blob!" );
		// Ensure no cheating!
		$blah = new Nife_StringBlob( (string)$blah );
		$decoded = $codec->decode($blah);
		$this->assertEquals($sig->jsonSerialize(), $decoded->jsonSerialize());
	}
}
