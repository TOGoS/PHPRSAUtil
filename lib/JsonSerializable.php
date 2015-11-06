<?php

// This is defined by PHP 5.4, but not earlier.
// In the 'earlier' case, this can get auto-loaded.
interface JsonSerializable {
	/** Return the object in a form that can be passed to json_encode, e.g. an array */
	public function jsonSerialize();
}
