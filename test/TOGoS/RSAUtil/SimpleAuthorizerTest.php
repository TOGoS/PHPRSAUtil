<?php

class TOGoS_RSAUtil_SimpleAuthorizerTest extends PHPUnit_Framework_TestCase
{
	public function testAuthorizeStuff() {
		$DS = new TOGoS_RSAUtil_DataStore();
		
		$key1 = TOGoS_RSAUtil_KeyPair::generate(array('size'=>2048), $DS);
		$key2 = TOGoS_RSAUtil_KeyPair::generate(array('size'=>2048), $DS);
		
		$SA = new TOGoS_RSAUtil_SimpleAuthorizer( array($key1->getPublicKeyUri()), $DS );
		
		$msg = "Hello, worlde!";
		
		$sig1 = TOGoS_RSAUtil::sign( $msg, $key1 );
		$sig2 = TOGoS_RSAUtil::sign( $msg, $key2 );

		$this->assertTrue(  $SA->isAuthorized($sig1) );
		$this->assertFalse( $SA->isAuthorized($sig2) );
	}
}