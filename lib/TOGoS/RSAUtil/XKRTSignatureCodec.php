<?php

class TOGoS_RSAUtil_XKRTSignatureCodec implements TOGoS_RSAUtil_SignatureCodec
{
	// See http://piccouch.appspot.com/uri-res/raw/urn:bitprint:XKRTAT4AEABXDGUEEKKDMARNVUMZUIFG.L5LLQZODRQYNREWM6FRU74V5SEJZ3QXGYLNGILI/signed-data-schema.rdf
	const TBB_MAGIC = "TBB\x81";
	const TBB_SCHEMA_ID = "\xba\xa3\x30\x4f\x80\x20\x03\x71\x9a\x84\x22\x94\x36\x02\x2d\xad\x19\x9a\x20\xa6";
	
	protected function uriToSha1( $uri ) {
		if( preg_match('#urn:(?:sha1|bitprint):([A-Z2-7]{32})\b#', $uri, $bif) ) {
			return TOGoS_Base32::decode($bif[1]);
		} else {
			// Well, if we have some datastore, we could go fetch the thing
			throw new Exception("Unrecognized SHA-1 URN: $uri");
		}
	}
	
	protected function payloadSha1( $sig ) {
		$uri = $sig->getPayloadUri();
		if( $uri !== null ) {
			return $this->uriToSha1($uri);
		}
		$dat = $sig->getPayload();
		if( $dat !== null ) {
			return hash('sha1', (String)$dat, false);
		}
		throw new Exception("Can't get SHA-1 of signature payload because it doesn't have one!");
	}
	
	protected function sha1Urn( $sha1 ) {
		return "urn:sha1:".TOGoS_Base32::encode($sha1);
	}
	
	public function supportsInlinePayload() {
		return false;
	}
	
	public function encode( TOGoS_RSAUtil_Signature $sig ) {
		if( $sig->getAlgorithmName() !== 'SHA1withRSA' ) {
			throw new Exception("Can only encode SHA1withRSA signatures; given a ".$sig->getAlgorithmName());
		}
		$keySha1 = $this->uriToSha1($sig->getPublicKeyUri());
		$contentSha1 = $this->payloadSha1($sig);
		return new Nife_StringBlob(self::TBB_MAGIC . self::TBB_SCHEMA_ID . $keySha1 . $contentSha1 . $sig->getSignatureBytes());
	}
	
	public function decode( Nife_Blob $blob ) {
		$blob = (string)$blob;
		if( substr($blob, 0, 24) !== self::TBB_MAGIC . self::TBB_SCHEMA_ID ) {
			throw new Exception("Malformed XKRT signature; header does not match expected value.");
		}
		if( strlen($blob) < 64 ) {
			throw new Exception(
				"Malformed XKRT signature; too short to contain key and content hashes (".strlen($blob).
				" of minimum 64 bytes)");
		}
		$keyHash     = substr($blob, 24, 20);
		$payloadHash = substr($blob, 44, 20);
		$sigBytes    = substr($blob, 64);
		return new TOGoS_RSAUtil_Signature(
			$this->sha1Urn($keyHash),
			$this->sha1Urn($payloadHash),
			'SHA1withRSA',
			$sigBytes
		);
	}
}
