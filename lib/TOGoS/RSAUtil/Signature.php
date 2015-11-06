<?php

class TOGoS_RSAUtil_Signature implements JsonSerializable
{
	/**
	 * URI of the public part of the key that generated this signature.
	 */
	protected $publicKeyUri;
	/**
	 * URI of data that is signed.
	 */
	protected $payloadUri;
	/**
	 * Alternately, the payload itself, as a Nife_Blob object
	 */
	protected $payload;
	/**
	 * E.g. SHA1withRSA.  This is technically independent of
	 * payloadUri, but if payload URI happens to include the hash that
	 * gets signed (urn:sha1:.... in the SHA1 case), then we can verify
	 * the signature without fetching the data.
	 */
	protected $algorithmName;
	/**
	 * Output of the signing function.
	 * Length depends on key size?
	 */
	protected $signatureBytes;
	
	/**
	 * @param mixed $payload if a Nife_Blob, this is the payload itself; if a string, this is the URI of the payload.
	 */
	public function __construct( $pubKeyUri, $payload, $algorithmName, $signatureBytes ) {
		$this->publicKeyUri = $pubKeyUri;
		if( $payload instanceof Nife_Blob ) {
			$this->payload = $payload;
		} else if( is_string($payload) ) {
			$this->payloadUri = $payload;
		} else {
			throw new Exception("$payload must be a Nife_Blob or a string");
		}
		$this->algorithmName = $algorithmName;
		$this->signatureBytes = $signatureBytes;
	}
	
	public function getPublicKeyUri() { return $this->publicKeyUri; }
	public function getPayloadUri() { return $this->payloadUri; }
	public function getPayload() { return $this->payload; }
	public function getAlgorithmName() { return $this->algorithmName; }
	public function getSignatureBytes() { return $this->signatureBytes; }
	
	public static function __set_state($arr) {
		$obj = new static();
		foreach( $arr as $k=>$v ) {
			$obj->$k = $v;
		}
		$obj->__wakeup();
		return $obj;
	}
	
	public function jsonSerialize() {
		$arr = array();
		$arr['publicKeyUri'] = $this->publicKeyUri;
		if( $this->payloadUri ) {
			$arr['payloadUri'] = $this->payloadUri;
		} else {
			$arr['payload'] = (string)$this->payload;
		}
		$arr['algorithmName'] = $this->algorithmName;
		$arr['signatureBytes'] = $this->signatureBytes;
		return $arr;
	}
}
