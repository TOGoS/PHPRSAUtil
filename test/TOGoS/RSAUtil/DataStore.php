<?php

class TOGoS_RSAUtil_DataStore
{
	protected $store = array();
	
	public function store($data) {
		$id = "urn:sha1:".TOGoS_Base32::encode(hash('sha1',(string)$data,true));
		$this->store[$id] = Nife_Util::blob($data);
		return $id;
	}
	
	public function getBlob($id) {
		return $this->store[$id];
	}
}
