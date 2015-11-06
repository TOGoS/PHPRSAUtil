<?php

class TOGoS_RSAUtil_PNGSignatureCodec implements TOGoS_RSAUtil_SignatureCodec
{
	public function supportsInlinePayload() {
		return true;
	}
	
	public function encode( TOGoS_RSAUtil_Signature $sig ) {
	}
	
	public function decode( Nife_Blob $encoded ) {
		$chunkCollector = new EarthIT_Collector();
		$pngChunkParser = new TOGoS_PNGChunks_Parser($chunkCollector);
		$encoded->writeTo(array($pngChunkParser,'data'));
		$pngChunkParser->end();
		$chunkCollector->collection->
	}
}