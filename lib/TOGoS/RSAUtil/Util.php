<?php

class TOGoS_RSAUtil_Util
{
	public static function derToPem($der, $type='PUBLIC KEY') {
		$pem = chunk_split(base64_encode($der), 64, "\n");
		$pem = "-----BEGIN $type-----\n".$pem."-----END $type-----\n";
		return $pem;
	}
	
	public static function looksLikePem($pem, &$content='') {
		if( preg_match('#--+BEGIN (PUBLIC KEY|PRIVATE KEY)--+\n(.*)\n--+END \1--+#s', $pem, $bif) ) {
			$content = $bif[2];
			return true;
		} else {
			return false;
		}
	}
	
	public static function pemToDer($pem) {
		if( !self::looksLikePem($pem, $base64) ) {
			throw new Exception("Failed to parse PEM data: $pem");
		}
		return base64_decode($base64);
	}
	
	/**
	 * Returns the Java Security algorithm name
	 */
	public static function rsaAlgoNameFromId( $opensslAlgo ) {
		switch( $opensslAlgo ) {
		case OPENSSL_ALGO_SHA1:
			return 'SHA1withRSA';
		case OPENSSL_ALGO_SHA512:
			return 'SHA512withRSA';
		default:
			throw new Exception("Unsupported algorithm: $opensslAlgo");
		}
	}
	
	public static function rsaAlgoIdFromName( $name ) {
		switch( $name ) {
		case 'SHA1withRSA':
		case 'SHA1':
		case 'sha1':
		case 'sha1WithRSAEncryption':
		case 'RSA-SHA1':
			return OPENSSL_ALGO_SHA1;
		case 'SHA256withRSA':
		case 'SHA256':
		case 'sha256':
		case 'sha256WithRSAEncryption':
		case 'RSA-SHA256':
			return OPENSSL_ALGO_SHA256;
		case 'SHA512withRSA':
		case 'SHA512':
		case 'sha512':
		case 'sha512WithRSAEncryption':
		case 'RSA-SHA512':
			return OPENSSL_ALGO_SHA256;
		default:
			throw new Exception("Unsupported algorithm name: $name");
		}
	}
	
	/**
	 * @return Nife_Blob
	 */
	public static function getSignaturePayload( TOGoS_RSAUtil_Signature $sig, $blobSource ) {
		$payload = $sig->getPayload();
		if( $payload !== null ) return $payload;
		
		$payloadUri = $sig->getPayloadUri();
		if( $payloadUri !== null ) {
			$payload = $blobSource->getBlob($payloadUri);
			if( $payload === null ) {
				throw new Exception("Signature payload not found; URI = $payloadUri");
			}
			return $payload;
		}
		
		throw new Exception("Signature has no payload nor payload URI!");
	}
}
