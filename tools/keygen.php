<?php
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
if (!function_exists('sodium_crypto_sign_keypair')) {fwrite(STDERR,"PHP Sodium is required.\n");exit(1);}
$private=$argv[1]??'';$public=$argv[2]??'';
if (!$private || !$public || $private===$public || file_exists($private) || file_exists($public)) {fwrite(STDERR,"Supply two distinct new output paths. Existing files are never overwritten.\n");exit(1);}
$pair=sodium_crypto_sign_keypair();$pub=sodium_crypto_sign_publickey($pair);$id='arta-'.substr(hash('sha256',$pub),0,12);
$privateData=json_encode(['key_id'=>$id,'secret_key'=>base64_encode(sodium_crypto_sign_secretkey($pair))],JSON_PRETTY_PRINT)."\n";
$publicData=json_encode(['key_id'=>$id,'public_key'=>base64_encode($pub),'fingerprint'=>hash('sha256',$pub)],JSON_PRETTY_PRINT)."\n";
$handle=fopen($private,'x');if (!$handle)exit(1);chmod($private,0600);fwrite($handle,$privateData);fclose($handle);
$handle=fopen($public,'x');if (!$handle)exit(1);fwrite($handle,$publicData);fclose($handle);
sodium_memzero($privateData);sodium_memzero($pair);
echo "Public identity only:\n".$publicData."Private key saved locally; do not share it in chat or commit it.\n";
