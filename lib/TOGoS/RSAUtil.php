<?php

/**
 * @api
 */
class TOGoS_RSAUtil
{	
	/**
	 * Returns a Signature object
	 */
	public static function sign($data, $privateKey, $publicKeyUri, $sslAlgo=OPENSSL_ALGO_SHA1 ) {
		if( is_resource($privateKey) ) {
			$freeKey = false;
		} else if( is_string($privateKey) ) {
			$privateKey = TOGoS_RSAUtil_Util::looksLikePem($privateKey) ?
				$privateKey : TOGoS_RSAUtil_Util::derToPem($privateKey);
			$privateKey = openssl_pkey_get_private($privateKey);
			$freeKey = true;
		} else {
			throw new Exception("\$privateKey must be a private key resource or a PEM or DER string");
		}
		
		openssl_sign( (string)$data, $sigBytes, $privateKey, $sslAlgo );
		
		if( $freeKey ) openssl_free_key($privateKey);
		
		return new TOGoS_RSAUtil_Signature( $publicKeyUri, Nife_Util::blob($data), TOGoS_RSAUtil_Util::rsaAlgoNameFromId($sslAlgo), $sigBytes );
	}

	/**
	 * @return true if the signature is valid, false otherwise
	 */
	public static function verif(TOGoS_RSAUtil_Signature $sig, $blobSource) {
		$pubKeyData = $blobSource->getBlob($sig->getPublicKeyUri());
		$pubKeyPem = TOGoS_RSAUtil_Util::looksLikePem($pubKeyData) ?
			$pubKeyData : TOGoS_RSAUtil_Util::derToPem($pubKeyData);
		$pubKey = openssl_pkey_get_public($pubKeyPem);
		if( $pubKey === false ) {
			throw new Exception("Failed to parse public key data");
		}
		$data = TOGoS_RSAUtil_Util::getSignaturePayload($sig, $blobSource);
		$verified = openssl_verify(
			$data, $sig->getSignatureBytes(), $pubKey,
			TOGoS_RSAUtil_Util::rsaAlgoIdFromName($sig->getAlgorithmName()) );
		openssl_free_key($pubKey);
		return (bool)$verified;
	}
	
	/**
	 * @throws TOGoS_RSAUtil_InvalidSignatureException if the signature is invalid
	 */
	public static function verify(TOGoS_RSAUtil_Signature $sig, $blobSource) {
		if( !self::verif($sig, $blobSource) ) {
			throw new TOGoS_RSAUtil_InvalidSignatureException("Signature is invalid!");
		}
	}
}
