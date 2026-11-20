<?php
/** Signed data-only rule feed. Trust configuration is deployed separately, never accepted from a request. */
defined('ABSPATH') || exit;
final class ARTA_Security_Feed {
    private const ACTIVE='arta_ss_feed_active_v1';
    private const PREVIOUS='arta_ss_feed_previous_v1';
    private const STATUS='arta_ss_feed_status_v1';
    private const HIGHWATER='arta_ss_feed_sequence_v1';
    private const LOCK='arta_ss_feed_lock_v1';
    public const HOOK='arta_ss_feed_tick_v1';
    private const MAX_BYTES=98304;
    private static ?array $active_cache=null;

    public static function init(): void {
        add_filter('cron_schedules',static function(array $s): array {$s['arta_ss_six_hours']=['interval'=>21600,'display'=>'ARTA Security: setiap 6 jam'];return $s;});
        add_action('init',[self::class,'schedule'],90);
        add_action(self::HOOK,[self::class,'tick']);
    }
    public static function configuration(): ?array {
        if (!defined('ARTA_SS_RULE_FEED') || !is_array(ARTA_SS_RULE_FEED)) return null;
        $v=ARTA_SS_RULE_FEED;
        if (!self::valid_url($v['url']??null) || !is_array($v['keys']??null) || count($v['keys'])<1 || count($v['keys'])>3) return null;
        foreach ($v['keys'] as $id=>$key) {
            if (!is_string($id) || !preg_match('/^[a-z0-9-]{1,32}$/D',$id) || !is_string($key)) return null;
            $decoded=base64_decode($key,true);
            if (!is_string($decoded) || strlen($decoded)!==32 || base64_encode($decoded)!==$key) return null;
        }
        return $v;
    }
    public static function valid_url($url): bool {
        // One repository-owned channel file; no credentials, ports, query, redirects, arbitrary destinations or private IPs.
        return is_string($url) && strlen($url)<=240 && (bool)preg_match('~^https://raw\.githubusercontent\.com/artakelana/arta-security-rules/main/channel/stable\.json$~D',$url);
    }
    public static function schedule(): void {
        if (!ARTA_Security_System::allowed() || self::configuration()===null || !function_exists('sodium_crypto_sign_verify_detached')) return;
        if (!wp_next_scheduled(self::HOOK)) wp_schedule_event(time()+random_int(180,600),'arta_ss_six_hours',self::HOOK);
    }
    private static function error(string $code): WP_Error {return new WP_Error($code,'Paket aturan belum dapat digunakan.');}
    private static function exact_keys(array $v,array $keys): bool {$a=array_keys($v);sort($a);sort($keys);return $a===$keys;}
    private static function version($v): bool {return is_string($v) && (bool)preg_match('/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/D',$v);}
    public static function validate_rule($r) {
        if (!is_array($r) || !self::exact_keys($r,['id','title','mode','methods','path','path_mode','plugin','conditions'])) return self::error('rule_schema');
        if (!is_string($r['id']) || !preg_match('/^feed_[a-z0-9_]{1,36}$/D',$r['id'])
            || !is_string($r['title']) || strlen($r['title'])<1 || strlen($r['title'])>120 || preg_match('/[\x00-\x1f\x7f<>]/',$r['title'])
            || !in_array($r['mode'],['monitor','block'],true) || !in_array($r['path_mode'],['exact','prefix'],true)
            || !is_string($r['path']) || strlen($r['path'])>180 || !preg_match('~^/[a-zA-Z0-9_./-]*$~D',$r['path']) || str_contains($r['path'],'..') || str_contains($r['path'],'//')) return self::error('rule_value');
        if (!is_array($r['methods']) || !array_is_list($r['methods']) || count($r['methods'])<1 || count($r['methods'])>3
            || count(array_unique($r['methods'],SORT_REGULAR))!==count($r['methods'])) return self::error('rule_methods');
        foreach ($r['methods'] as $m) if (!in_array($m,['GET','HEAD','POST'],true)) return self::error('rule_methods');
        if ($r['plugin']!==null) {
            $p=$r['plugin'];
            if (!is_array($p) || !self::exact_keys($p,['file','min','before']) || !is_string($p['file'])
                || !preg_match('~^[a-z0-9][a-z0-9-]{0,63}/[a-z0-9][a-z0-9_.-]{0,79}\.php$~D',$p['file']) || str_contains($p['file'],'..')
                || !self::version($p['min']) || !self::version($p['before']) || version_compare($p['min'],$p['before'],'>=')) return self::error('rule_plugin');
        }
        // A blocking virtual patch must identify an affected active plugin and a concrete exact endpoint.
        if ($r['mode']==='block' && ($r['plugin']===null || $r['path_mode']!=='exact' || $r['path']==='/')) return self::error('rule_block_scope');
        if ($r['plugin']===null && in_array('POST',$r['methods'],true)) return self::error('rule_post_scope');
        if (!is_array($r['conditions']) || !array_is_list($r['conditions']) || count($r['conditions'])<1 || count($r['conditions'])>4) return self::error('rule_conditions');
        foreach ($r['conditions'] as $c) {
            if (!is_array($c) || !self::exact_keys($c,['source','field','op','value']) || !in_array($c['source'],['query','form'],true)
                || !is_string($c['field']) || !preg_match('/^[a-zA-Z0-9_]{1,48}$/D',$c['field']) || self::secret_field($c['field'])
                || !in_array($c['op'],['equals','contains'],true) || !is_string($c['value']) || strlen($c['value'])<1 || strlen($c['value'])>128
                || preg_match('/[\x00-\x1f\x7f]/',$c['value'])) return self::error('rule_condition');
            if ($c['source']==='form' && !in_array('POST',$r['methods'],true)) return self::error('rule_form_method');
        }
        if (in_array($r['path'],['/wp-admin/admin-ajax.php','/wp-admin/admin-post.php'],true)) {
            $action=false;
            foreach ($r['conditions'] as $c) if ($c['field']==='action' && $c['op']==='equals' && preg_match('/^[a-z0-9_]{1,64}$/D',$c['value'])) $action=true;
            if (!$action) return self::error('rule_action_scope');
        }
        return $r;
    }
    private static function secret_field(string $name): bool {return (bool)preg_match('/pass|pwd|token|nonce|secret|signature|authorization|api.?key|otp|code|cookie|email|phone|card/i',$name);}
    public static function verify(string $body,array $keys, int $floor=0, bool $allow_old=false) {
        if (!function_exists('sodium_crypto_sign_verify_detached')) return self::error('crypto_unavailable');
        if (strlen($body)>self::MAX_BYTES || strlen($body)<80) return self::error('envelope_size');
        try {$e=json_decode($body,true,12,JSON_THROW_ON_ERROR);} catch (Throwable $e) {return self::error('envelope_json');}
        if (!is_array($e) || !self::exact_keys($e,['key_id','payload','signature']) || !is_string($e['key_id'])
            || !is_string($e['payload']) || !is_string($e['signature']) || !isset($keys[$e['key_id']]) || !is_string($keys[$e['key_id']])) return self::error('envelope_schema');
        $payload=base64_decode($e['payload'],true);$sig=base64_decode($e['signature'],true);$key=base64_decode($keys[$e['key_id']],true);
        if (!is_string($payload) || strlen($payload)>65536 || base64_encode($payload)!==$e['payload'] || !is_string($sig) || strlen($sig)!==64
            || !is_string($key) || strlen($key)!==32 || !sodium_crypto_sign_verify_detached($sig,$payload,$key)) return self::error('signature_invalid');
        try {$p=json_decode($payload,true,10,JSON_THROW_ON_ERROR);} catch (Throwable $e) {return self::error('payload_json');}
        if (!is_array($p) || !self::exact_keys($p,['schema','audience','sequence','issued_at','expires_at','engine_min','engine_before','rules'])
            || $p['schema']!==1 || $p['audience']!=='arta-security-system' || !is_int($p['sequence']) || $p['sequence']<1 || $p['sequence']>2147483647
            || !is_int($p['issued_at']) || !is_int($p['expires_at']) || !self::version($p['engine_min']) || !self::version($p['engine_before'])) return self::error('payload_schema');
        $now=time();
        if ($p['issued_at']>$now+300 || $p['expires_at']<=$now || $p['expires_at']<=$p['issued_at'] || $p['expires_at']-$p['issued_at']>2678400) return self::error('package_time');
        if (version_compare(ARTA_Security_System::VERSION,$p['engine_min'],'<') || version_compare(ARTA_Security_System::VERSION,$p['engine_before'],'>=')) return self::error('engine_incompatible');
        if (!$allow_old && $p['sequence']<=$floor) return self::error('sequence_not_new');
        if (!is_array($p['rules']) || !array_is_list($p['rules']) || count($p['rules'])>32) return self::error('rules_limit');
        $ids=[];
        foreach ($p['rules'] as $r) {
            $checked=self::validate_rule($r);if (is_wp_error($checked)) return $checked;
            if (isset($ids[$r['id']])) return self::error('rule_duplicate');$ids[$r['id']]=true;
        }
        return ['payload'=>$p,'envelope'=>$body,'sha256'=>hash('sha256',$payload),'key_id'=>$e['key_id']];
    }
    public static function tick(): void {self::update(false);}
    public static function update(bool $manual=false): array {
        $config=self::configuration();
        if ($config===null) return ['ok'=>false,'status'=>'not_configured'];
        if (!function_exists('sodium_crypto_sign_verify_detached')) return ['ok'=>false,'status'=>'crypto_unavailable'];
        $lock=ARTA_Security_Events::lock(self::LOCK,40);
        if ($lock===null) return ['ok'=>false,'status'=>'busy'];
        try {
            $state=get_option(self::STATUS,[]);if (!is_array($state)) $state=[];
            if (time()-(int)($state['checked_at']??0)<60) return ['ok'=>false,'status'=>'wait'];
            $state['checked_at']=time();$state['result']='checking';update_option(self::STATUS,$state,false);
            $r=wp_safe_remote_get($config['url'],['timeout'=>12,'redirection'=>0,'sslverify'=>true,'limit_response_size'=>self::MAX_BYTES+1,
                'headers'=>['Accept'=>'application/json','Cache-Control'=>'no-cache'],'cookies'=>[],'user-agent'=>'ARTA-Security-Rules/'.ARTA_Security_System::VERSION]);
            if (is_wp_error($r)) return self::finish($state,false,'network_failed');
            if (wp_remote_retrieve_response_code($r)!==200) return self::finish($state,false,'http_failed');
            $body=wp_remote_retrieve_body($r);
            if (!is_string($body) || strlen($body)>self::MAX_BYTES) return self::finish($state,false,'envelope_size');
            $stored=get_option(self::ACTIVE,[]);
            $floor=max(0,(int)get_option(self::HIGHWATER,0),is_array($stored)?(int)($stored['highest_sequence']??0):0);
            $checked=self::verify($body,$config['keys'],$floor);
            if (is_wp_error($checked)) {
                if ($checked->get_error_code()==='sequence_not_new') {
                    $current=get_option(self::ACTIVE,[]);
                    if (is_array($current) && is_string($current['envelope']??null) && hash_equals(hash('sha256',$current['envelope']),hash('sha256',$body))) return self::finish($state,true,'current');
                }
                return self::finish($state,false,$checked->get_error_code());
            }
            $old=get_option(self::ACTIVE,[]);
            if (is_array($old) && is_string($old['envelope']??null)) update_option(self::PREVIOUS,$old,false);
            $active=['envelope'=>$body,'installed_at'=>time(),'highest_sequence'=>$checked['payload']['sequence']];
            if (!update_option(self::ACTIVE,$active,false) && get_option(self::ACTIVE)!==$active) return self::finish($state,false,'storage_failed');
            $seq=$checked['payload']['sequence'];
            update_option(self::HIGHWATER,$seq,false);self::$active_cache=null;
            $state['installed_at']=time();$state['sequence']=$seq;
            return self::finish($state,true,'updated');
        } finally {ARTA_Security_Events::unlock(self::LOCK,$lock);}
    }
    private static function finish(array $state,bool $ok,string $code): array {
        $state['result']=$code;if ($ok) $state['success_at']=time();
        update_option(self::STATUS,$state,false);return ['ok'=>$ok,'status'=>$code];
    }
    public static function active(): array {
        if (self::$active_cache!==null) return self::$active_cache;
        self::$active_cache=[];$config=self::configuration();$raw=get_option(self::ACTIVE,[]);
        if ($config===null || !is_array($raw) || !is_string($raw['envelope']??null)) return [];
        $checked=self::verify($raw['envelope'],$config['keys'],0,true);
        if (!is_wp_error($checked)) self::$active_cache=$checked['payload'];
        return self::$active_cache;
    }
    public static function status(): array {
        $cfg=self::configuration();$s=get_option(self::STATUS,[]);if (!is_array($s)) $s=[];
        $p=self::active();$raw=get_option(self::ACTIVE,[]);
        $result=(string)($s['result']??'never_checked');
        $labels=['not_configured'=>'Sumber belum dikonfigurasi','crypto_unavailable'=>'Verifikasi tanda tangan tidak tersedia','never_checked'=>'Belum diperiksa','checking'=>'Memeriksa paket',
            'current'=>'Versi terbaru terverifikasi','updated'=>'Pembaruan berhasil','owner_rollback'=>'Versi sebelumnya dipulihkan pemilik','network_failed'=>'Koneksi penerbit gagal','http_failed'=>'Paket belum tersedia',
            'signature_invalid'=>'Tanda tangan ditolak','sequence_not_new'=>'Paket lama ditolak','package_time'=>'Masa berlaku paket tidak sah','engine_incompatible'=>'Versi engine belum cocok','storage_failed'=>'Penyimpanan gagal'];
        if ($cfg===null) $result='not_configured';elseif (!function_exists('sodium_crypto_sign_verify_detached')) $result='crypto_unavailable';
        elseif (!$p && is_array($raw) && isset($raw['envelope'])) $result='package_time';
        $stamp=static fn($t)=>is_numeric($t)&&$t>0?gmdate('d/m/Y H:i',(int)$t+25200).' WIB':'Belum ada';
        return ['configured'=>$cfg!==null,'ready'=>$cfg!==null&&function_exists('sodium_crypto_sign_verify_detached'),'status'=>$result,'label'=>$labels[$result]??'Paket ditolak oleh validasi','sequence'=>(int)($p['sequence']??0),
            'rule_count'=>count($p['rules']??[]),'checked'=>$stamp($s['checked_at']??0),'installed'=>$stamp($s['installed_at']??0),
            'expires'=>$stamp($p['expires_at']??0),'last_success'=>$stamp($s['success_at']??0),
            'schedule'=>wp_next_scheduled(self::HOOK)?$stamp(wp_next_scheduled(self::HOOK)):'Belum terjadwal',
            'interval_hours'=>6,'baseline_active'=>true,'source'=>'GitHub · artakelana/arta-security-rules'];
    }
    public static function rollback(): array {
        $cfg=self::configuration();if ($cfg===null) return ['ok'=>false,'status'=>'not_configured'];
        $lock=ARTA_Security_Events::lock(self::LOCK,20);if ($lock===null) return ['ok'=>false,'status'=>'busy'];
        try {
            $previous=get_option(self::PREVIOUS,[]);
            if (!is_array($previous) || !is_string($previous['envelope']??null)) return ['ok'=>false,'status'=>'no_previous'];
            $check=self::verify($previous['envelope'],$cfg['keys'],0,true);
            if (is_wp_error($check)) return ['ok'=>false,'status'=>$check->get_error_code()];
            $current=get_option(self::ACTIVE,[]);$highest=max((int)get_option(self::HIGHWATER,0),is_array($current)?(int)($current['highest_sequence']??0):0);
            $next=['envelope'=>$previous['envelope'],'installed_at'=>time(),'highest_sequence'=>$highest];
            if (!update_option(self::ACTIVE,$next,false) && get_option(self::ACTIVE)!==$next) return ['ok'=>false,'status'=>'storage_failed'];
            // The highest accepted sequence is retained, so network replay cannot undo this owner choice.
            self::$active_cache=null;$state=get_option(self::STATUS,[]);if (!is_array($state))$state=[];
            $state['installed_at']=time();$state['result']='owner_rollback';update_option(self::STATUS,$state,false);
            return ['ok'=>true,'status'=>'owner_rollback'];
        } finally {ARTA_Security_Events::unlock(self::LOCK,$lock);}
    }
    public static function protected_request(): bool {
        $path=(string)wp_parse_url((string)($_SERVER['REQUEST_URI']??'/'),PHP_URL_PATH);
        if (is_user_logged_in() || (defined('DOING_CRON')&&DOING_CRON)) return true;
        if (class_exists('ARTA_Login_Gateway',false) && ARTA_Login_Gateway::path_is_login($path)) return true;
        if (preg_match('~^/(?:akses-akun|wp-login\.php|checkout|cart|my-account|wc-api|arta-csp-report)(?:/|$)~i',$path)) return true;
        if (preg_match('~^/(?:partner|mitra|pengelola)/(?:login|register|otp|verify|reset|logout)(?:/|$)~i',$path)) return true;
        if (preg_match('~^/wp-json/(?:arta-payment|wc|wc-admin|woocommerce)(?:/|$)~i',$path)) return true;
        if (isset($_GET['wc-ajax']) || isset($_GET['wc-api'])) return true;
        $rest=$_GET['rest_route']??null;
        if (is_string($rest) && preg_match('~^/(?:arta-payment|wc|wc-admin|woocommerce)(?:/|$)~i',$rest)) return true;
        foreach ([$_GET['action']??'',$_POST['action']??''] as $action) if (is_string($action)&&preg_match('/login|logout|auth|otp|two.factor|midtrans|payment|checkout|password|arta_ss_/i',$action)) return true;
        return false;
    }
    private static function plugin_matches($spec): bool {
        if ($spec===null) return true;
        static $versions=[];
        $file=$spec['file'];
        if (!array_key_exists($file,$versions)) {
            $active=(array)get_option('active_plugins',[]);
            if (is_multisite()) $active=array_merge($active,array_keys((array)get_site_option('active_sitewide_plugins',[])));
            $versions[$file]=null;
            if (in_array($file,$active,true) && is_file(WP_PLUGIN_DIR.'/'.$file)) {
                $data=get_file_data(WP_PLUGIN_DIR.'/'.$file,['Version'=>'Version']);
                if (is_string($data['Version']??null)) $versions[$file]=$data['Version'];
            }
        }
        $v=$versions[$file];return is_string($v)&&version_compare($v,$spec['min'],'>=')&&version_compare($v,$spec['before'],'<');
    }
    public static function rule_matches(array $r,string $path,string $method): bool {
        if (!in_array($method,$r['methods'],true) || !self::plugin_matches($r['plugin'])) return false;
        if ($r['path_mode']==='exact' ? $path!==$r['path'] : !str_starts_with($path,$r['path'])) return false;
        foreach ($r['conditions'] as $c) {
            $input=$c['source']==='query'?$_GET:$_POST;$v=$input[$c['field']]??null;
            if (!is_string($v) || strlen($v)>4096) return false;
            $v=wp_unslash($v);
            if ($c['op']==='equals' ? !hash_equals($c['value'],$v) : stripos($v,$c['value'])===false) return false;
        }
        return true;
    }
    public static function evaluate(): ?array {
        if (!ARTA_Security_System::allowed() || self::protected_request()) return null;
        $method=$_SERVER['REQUEST_METHOD']??'';if (!in_array($method,['GET','HEAD','POST'],true)) return null;
        $path=(string)wp_parse_url((string)($_SERVER['REQUEST_URI']??'/'),PHP_URL_PATH);
        if (strlen($path)>2048) return null;
        $p=self::active();$monitored=null;
        foreach ($p['rules']??[] as $r) {
            if (!self::rule_matches($r,$path,$method)) continue;
            if ($r['mode']==='block') {
                return ['rule'=>$r['id'],'mode'=>'block','local'=>false];
            }
            $monitored??=$r['id'];
        }
        return $monitored!==null?['rule'=>$monitored,'mode'=>'monitor','local'=>false]:null;
    }
}
