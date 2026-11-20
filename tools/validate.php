<?php
require_once __DIR__.'/bootstrap.php';
$path=$argv[1]??'';
try {
    if (!is_file($path) || filesize($path)>65536) throw new RuntimeException('Invalid rules file');
    $rules=json_decode(file_get_contents($path),true,10,JSON_THROW_ON_ERROR);
    if (!is_array($rules) || !array_is_list($rules) || count($rules)>32) throw new RuntimeException('Invalid rule collection');
    $seen=[];
    foreach ($rules as $r) {
        $v=ARTA_Security_Feed::validate_rule($r);
        if (is_wp_error($v)) throw new RuntimeException('Rule rejected: '.$v->get_error_code());
        if (isset($seen[$v['id']])) throw new RuntimeException('Duplicate rule');$seen[$v['id']]=true;
    }
    echo 'Validated '.count($rules)." rules.\n";
} catch (Throwable $e) {fwrite(STDERR,$e->getMessage()."\n");exit(1);}
