<?php
require_once __DIR__.'/bootstrap.php';
$pair=sodium_crypto_sign_seed_keypair(hash('sha256','PUBLIC-SYNTHETIC-PROTOCOL-FIXTURE-NOT-PRODUCTION',true));$secret=sodium_crypto_sign_secretkey($pair);$public=base64_encode(sodium_crypto_sign_publickey($pair));
$p=['schema'=>1,'audience'=>'arta-security-system','sequence'=>10,'issued_at'=>time()-30,'expires_at'=>time()+3600,'engine_min'=>'1.4.0','engine_before'=>'2.0.0','rules'=>json_decode(file_get_contents(dirname(__DIR__).'/rules/rules.json'),true)];
function envelope(array $p):string{global $secret;$s=json_encode($p,JSON_UNESCAPED_SLASHES);return json_encode(['key_id'=>'test','payload'=>base64_encode($s),'signature'=>base64_encode(sodium_crypto_sign_detached($s,$secret))]);}
$valid=envelope($p);$checks=0;
function expect(bool $v,string $name){global $checks;$checks++;if(!$v)throw new RuntimeException($name);}
try{
 expect(!is_wp_error(ARTA_Security_Feed::verify($valid,['test'=>$public])),'valid package');
 foreach(['audience'=>'other','schema'=>2,'sequence'=>0,'issued_at'=>time()+3600,'expires_at'=>time()-1,'engine_min'=>'9.0.0']as$k=>$v){$q=$p;$q[$k]=$v;expect(is_wp_error(ARTA_Security_Feed::verify(envelope($q),['test'=>$public])),'invalid '.$k);}
 expect(is_wp_error(ARTA_Security_Feed::verify($valid,['test'=>$public],10)),'replay rejected');
 $q=json_decode($valid,true);$q['signature']=base64_encode(str_repeat('a',64));expect(is_wp_error(ARTA_Security_Feed::verify(json_encode($q),['test'=>$public])),'tampering rejected');
 expect(is_wp_error(ARTA_Security_Feed::verify($valid,[])),'unknown publisher rejected');
 expect(is_wp_error(ARTA_Security_Feed::verify(str_repeat('x',100000),['test'=>$public])),'size bounded');
 $r=$p['rules'][0];$r['mode']='block';expect(is_wp_error(ARTA_Security_Feed::validate_rule($r)),'broad blocking rejected');
 $r=$p['rules'][0];$r['conditions'][0]['op']='regex';expect(is_wp_error(ARTA_Security_Feed::validate_rule($r)),'remote regex rejected');
 $r=$p['rules'][0];$r['conditions'][0]['field']='password';expect(is_wp_error(ARTA_Security_Feed::validate_rule($r)),'credential fields excluded');
 echo 'Protocol checks passed: '.$checks."\n";
}catch(Throwable $e){fwrite(STDERR,$e->getMessage()."\n");exit(1);}
