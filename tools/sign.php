<?php
require_once __DIR__.'/bootstrap.php';
try {
    $source=$argv[1]??'';$out=$argv[2]??'';
    if (!is_file($source) || filesize($source)>65536 || !$out) throw new RuntimeException('Invalid input');
    $rules=json_decode(file_get_contents($source),true,10,JSON_THROW_ON_ERROR);
    if (!is_array($rules) || !array_is_list($rules) || count($rules)>32) throw new RuntimeException('Invalid rules');
    foreach ($rules as $r) if (is_wp_error(ARTA_Security_Feed::validate_rule($r))) throw new RuntimeException('Rule validation failed');
    $encoded=getenv('ARTA_RULE_SIGNING_KEY')?:'';$secret=base64_decode($encoded,true);
    if (!is_string($secret) || strlen($secret)!==64) throw new RuntimeException('Signing secret is missing or invalid');
    $pair=sodium_crypto_sign_seed_keypair(substr($secret,0,32));
    if (!hash_equals(sodium_crypto_sign_secretkey($pair),$secret)) throw new RuntimeException('Signing secret is inconsistent');
    $public=sodium_crypto_sign_publickey($pair);$id='arta-'.substr(hash('sha256',$public),0,12);
    $identity=json_decode(file_get_contents(dirname(__DIR__).'/publisher-public-key.json'),true,4,JSON_THROW_ON_ERROR);
    if (!is_array($identity) || count($identity)!==3
        || !hash_equals($id,(string)($identity['key_id']??''))
        || !hash_equals(base64_encode($public),(string)($identity['public_key']??''))
        || !hash_equals(hash('sha256',$public),(string)($identity['fingerprint']??''))) {
        throw new RuntimeException('Signing key does not match the approved public publisher identity');
    }
    $previous=0;$channel=dirname(__DIR__).'/channel/stable.json';
    if (is_file($channel)) {
        if (filesize($channel)>98304) throw new RuntimeException('Previous channel is oversized');
        $old=json_decode(file_get_contents($channel),true,12,JSON_THROW_ON_ERROR);
        $oldBody=base64_decode($old['payload']??'',true);$oldSig=base64_decode($old['signature']??'',true);
        if (($old['key_id']??'')!==$id || !is_string($oldBody) || !is_string($oldSig) || strlen($oldSig)!==64 || !sodium_crypto_sign_verify_detached($oldSig,$oldBody,$public)) throw new RuntimeException('Previous channel identity is not trusted');
        $oldPayload=json_decode($oldBody,true,10,JSON_THROW_ON_ERROR);
        if (!is_int($oldPayload['sequence']??null)) throw new RuntimeException('Previous sequence is invalid');
        $previous=$oldPayload['sequence'];
    }
    $sequence=max(time(),$previous+1,(int)(getenv('ARTA_PREVIOUS_SEQUENCE')?:0)+1);$now=time();
    $payload=json_encode(['schema'=>1,'audience'=>'arta-security-system','sequence'=>$sequence,'issued_at'=>$now,'expires_at'=>$now+1209600,'engine_min'=>'1.4.0','engine_before'=>'2.0.0','rules'=>$rules],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    $envelope=json_encode(['key_id'=>$id,'payload'=>base64_encode($payload),'signature'=>base64_encode(sodium_crypto_sign_detached($payload,$secret))],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
    $verified=ARTA_Security_Feed::verify($envelope,[$id=>base64_encode($public)],0);
    if (is_wp_error($verified)) throw new RuntimeException('Signed package validation failed: '.$verified->get_error_code());
    if (!is_dir($out) && !mkdir($out,0755,true)) throw new RuntimeException('Output directory unavailable');
    file_put_contents($out.'/stable.json',$envelope);
    file_put_contents($out.'/public-key.json',json_encode(['key_id'=>$id,'public_key'=>base64_encode($public),'fingerprint'=>hash('sha256',$public)],JSON_PRETTY_PRINT)."\n");
    file_put_contents($out.'/release.json',json_encode(['tag'=>'rules-'.$sequence,'sequence'=>$sequence,'rules'=>count($rules),'sha256'=>$verified['sha256']],JSON_PRETTY_PRINT)."\n");
    sodium_memzero($secret);sodium_memzero($pair);
    echo 'Signed sequence '.$sequence.' with '.count($rules)." reviewed rules.\n";
} catch (Throwable $e) {fwrite(STDERR,$e->getMessage()."\n");exit(1);}
