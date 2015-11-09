<?php

class TOGoS_RSAUtil_KeyPair
{
	protected $privDer;
	protected $pubDer;
	protected $pubUri;
	
	protected function __construct( $privDer, $pubDer, $pubUri ) {
		$this->privDer = $privDer;
		$this->pubDer = $pubDer;
		$this->pubUri = $pubUri;
	}
	
	public function getPrivateKeyDer() {
		return $this->privDer;
	}
	public function getPrivateKeyPem() {
		return TOGoS_RSAUtil_Util::derToPem($this->privDer,"PRIVATE KEY");
	}
	public function getPublicKeyDer() {
		return $this->pubDer;
	}
	public function getPublicKeyPem() {
		return TOGoS_RSAUtil_Util::derToPem($this->privDer,"PUBLIC KEY");
	}
	public function getPublicKeyUri() {
		return $this->pubUri;
	}
	
	protected static function create2( $privDer, $pubDer ) {
		return new self($privDer, $pubDer, "urn:sha1:".TOGoS_Base32::encode(hash('sha1',$pubDer,true)));
	}

	public static function create( $priv, $pub ) {
		return self::create2( TOGoS_RSAUtil_Util::toDer($priv), TOGoS_RSAUtil_Util::toDer($pub) );
	}
	
	public static function generate($options=array(), $dataStore=null) {
		$bits = isset($options['size']) ? $options['size'] : 4096;
		
		$key = openssl_pkey_new( array(
			'digest_alg' => 'sha1',
			'private_key_bits' => $bits,
			'private_key_type' => OPENSSL_KEYTYPE_RSA
		) );
		
		if( !openssl_pkey_export($key, $privateKeyPem) ) {
			throw new Exception("openssl_pkey_export failed with no explanation");
		}
		$privateKeyDer = TOGoS_RSAUtil_Util::pemToDer($privateKeyPem);
		
		$det = openssl_pkey_get_details($key);
		/** PEM-formatted public key */
		$publicKeyPem = $det['key'];
		$publicKeyDer = TOGoS_RSAUtil_Util::pemToDer($publicKeyPem);
		
		if( $dataStore !== null ) {
			$dataStore->store($publicKeyDer);
		}
		
		return self::create2($privateKeyDer, $publicKeyDer);
	}
}
