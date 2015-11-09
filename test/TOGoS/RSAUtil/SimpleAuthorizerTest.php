<?php

class TOGoS_RSAUtil_SimpleAuthorizerTest extends PHPUnit_Framework_TestCase
{
	public function testAuthorizeStuff() {
		$key1 = TOGoS_RSAUtil::generateKeyPair(array('size'=>2048));
		$key2 = TOGoS_RSAUtil::generateKeyPair(array('size'=>2048));
		
		$DS = new TOGoS_RSAUtil_DataStore();
		$DS->store($key1['publicKeyDer']);
		$DS->store($key2['publicKeyDer']);
		
		$SA = new TOGoS_RSAUtil_SimpleAuthorizer( array($key1['publicKeyUri']), $DS );
		
		$msg = "Hello, worlde!";
		
		$sig1 = TOGoS_RSAUtil::sign( $msg, $key1['privateKeyDer'], $key1['publicKeyUri'] );
		$sig2 = TOGoS_RSAUtil::sign( $msg, $key2['privateKeyDer'], $key2['publicKeyUri'] );

		$this->assertTrue(  $SA->isAuthorized($sig1) );
		$this->assertFalse( $SA->isAuthorized($sig2) );
	}
}