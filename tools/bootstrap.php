<?php
// CLI protocol tools. The client file is copied byte-for-byte from the reviewed installed module.
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
define('ABSPATH',__DIR__.'/');
final class ARTA_Security_System {const VERSION='1.4.0';}
class WP_Error {public function __construct(private string $code,private string $message=''){}public function get_error_code():string{return $this->code;}}
function is_wp_error($v):bool{return $v instanceof WP_Error;}
require_once dirname(__DIR__).'/client/rules-feed.php';
