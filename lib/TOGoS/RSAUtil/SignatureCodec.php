<?php

interface TOGoS_RSAUtil_SignatureCodec
{
	public function supportsInlinePayload();
	
	public function decode( Nife_Blob $blob );
	public function encode( TOGoS_RSAUtil_Signature $sig );
}
