<?php

class TOGoS_RSAUtil_UnrparseableURNException extends Exception { }

class TOGoS_RSAUtil_SimpleAuthorizer
{
	protected static function normalizeUrn( $urn ) {
		if( preg_match( '/^urn:(?:sha1|bitprint):([A-Z2-7]{32})\b/', $urn, $bif ) ) {
			return "urn:sha1:{$bif[1]}";
		} else {
			throw new TOGoS_RSAUtil_UnparseableURNException("Can't parse SHA-1 hash from '$urn'");
		}
	}
	
	protected $validKeyUrns = array();
	protected $blobSource;
	
	public function __construct( $validKeys, $blobSource=null ) {
		foreach( $validKeys as $keyUrn ) {
			$keyUrn = self::normalizeUrn($keyUrn);
			$this->validKeyUrns[$keyUrn] = $keyUrn;
		}
		$this->blobSource = $blobSource;
	}
	
	/**
	 * @return boolean true iff the signature is (A) valid, and (B)
	 * signed by one of our valid keys
	 */
	public function isAuthorized( TOGoS_RSAUtil_Signature $sig ) {
		$keyUrn = $sig->getPublicKeyUri();
		try {
			$keyUrn = $this->normalizeUrn($keyUrn);
		} catch( TOGoS_RSAUtil_UnparseableURNException $e ) {
			return false;
		}
		if( !isset($this->validKeyUrns[$keyUrn]) ) return false;
		
		return TOGoS_RSAUtil::verif( $sig, $this->blobSource );
	}
}
