<?php

$redirectUrl = 'https://typo3.org/my-account/sso/forge/';
//$redirectUrl = 'http://localhost/4-2/index.php?id=33';

$absoluteRefererUrl = $_SERVER["HTTP_REFERER"];

if (!empty($absoluteRefererUrl) && filter_var($absoluteRefererUrl, FILTER_VALIDATE_URL)) {
	$parsedUrl = parse_url($absoluteRefererUrl);
	if ($parsedUrl['host'] === 'forge.typo3.org') {
		$redirectUrl .= '?returnTo=' . rawurlencode(ltrim($parsedUrl['path'], '/'));
//		$redirectUrl .= '&returnTo=' . rawurlencode(ltrim($parsedUrl['path'], '/'));
	}
	
}

header('Location: ' . $redirectUrl);
exit;


