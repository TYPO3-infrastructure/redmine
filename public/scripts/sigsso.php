<?php

// Debug switch
#$debugflag=true;

# --
#
# Signature-Based Single Sign-On Framework
# SSO Agent (PHP)
#
# Version            : 0.7.3
# Last update        : 27.09.2006
#
# (c) net&works GmbH, Hannover, Germany
# http://www.single-signon.com
#
# --

#############################################################################
# Copyright (C) 2003-2006 Dietrich Heise - net&works GmbH - <heise@naw.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#############################################################################


/*  Changelog
0.7.x
  Fixed warnings:
   PHP Notice:  Undefined index:  Error in /usr/local/sigsso/sigsso_0.7.3.php on line 281
   PHP Notice:  Undefined index:  CookieDomain in /usr/local/sigsso/sigsso_0.7.3.php on line 312
   PHP Notice:  Undefined index:  CookieSecure in /usr/local/sigsso/sigsso_0.7.3.php on line 312

0.7.3
  changed $HTTP_SERVER_VARS to $_SERVER to provide PHP5 compatibility
  changed $HTTP_GET_VARS to $_GET to provide PHP5 compatibility
0.7.2
  fix of $this vars
0.7.1
  bug fixed $flags missing in globals in line 311
0.7
  various enhancements for user propagation functionality
0.62
  fixed some bugs to make agent run on Windows server
  added config variable "windows_server"
0.61
  changed default config path to absolute
0.6
  optical changes :-)
0.5.5
  Fixed bug that caused "signature invalid" errors
0.5.4
  included php-adapter now has to return an array instead of a string
  that has to be exploded
0.5.3
  added php:// and cmd:// to config
  use "cmd://path/to/script --many-options=val" for command line 
  use "php://path/to/script --url=redirect" for php script
0.5.2
  errorcodes() split in errorcode_default() and errorcodes()
  changed tmp_signature_file = value
    to tmp_signature_dir and tmp_signature_prefix
  changed $_SERVER to $HTTP_SERVER_VARS :(
  changed $_GET to $HTTP_GET_VARS :(
0.5.1:
  added openssl verify per command line
  added externalopenssl = 1
  added tmp_signature_file = VALUE 
*/

// vars to be used in the config

// %remote% = $_SERVER["REMOTE_ADDR"];
// %agent%  = $_SERVER["HTTP_USER_AGENT"];
// %user%   = $_GET['user'];

// return values

// redirecturl
// CookieName
// CookieValue
// CookieExpires
// CookiePath
// CookieDomain
// CookieSecure


$configfile="/var/www/vhosts/forge.typo3.org/home/sso/sigsso.conf";
$errorcodes = array();
errorcode_default();

// get variables
getvars();

// check for user,tpa_id and expires
checkvars();
readconfig();
errorcode();


$logging = touch($logfile);
$logging = @fopen($logfile, "a");
if (!$logging){            // can't open config
  errorpage(22);
}

// create and check signed string
if (!$version) $data = 'user='.$user.'&tpa_id='.$tpa_id.'&expires='.$expires;
else $data = 'version='.$version.'&user='.$user.'&tpa_id='.$tpa_id.'&expires='.$expires.'&action='.$action.'&flags='.$flags.'&userdata='.$userdata;
if ($debugflag) printf('<br>Parameters detected: '.$data);

if (ereg("^2.",$version)){
	// decode $userdata and $flags and evaluate $flags
	$userdata = base64_decode($userdata);
	if ($debugflag) printf('<br>submitted userdata: '.$userdata);
	
	$tmpflags = split("\|",base64_decode($flags));
	unset($flags);
	for ($i=0;$i<count($tmpflags);$i++){
		$tmpflag=split("=",$tmpflags[$i]);
		$flags["$tmpflag[0]"]=$tmpflag[1];
	}
	if ($debugflag) {
		printf('<br>flags: ');
		print_r($flags);
	}
}

// read config, set $confline und $public_ssl_key
readconfig();

// check signature
checksign();

// link allready used?

checkused();

// run SSO-script and process return values

if ($cmd == "cmd"){
	// get protocol version from the adapter
	
	$getver=split(" ",$confline,2);
	$getver=$getver[0]." --get_version\n";
	$tempver ='';
	$tmp = exec ($getver,$tempver);
	$tempver=split("\ |\t",$tempver[0]);
	if ( $tempver[0] && $tempver[0]!="Error") $adapter_version=$tempver[1];
	else $adapter_version = "1.0";
	if ($debugflag) printf('<br>Adapter protocol version: '.$adapter_version);

	if ($adapter_version == "1.0") {
		$return ='';
		exec ($confline,$return);
		if ($debugflag) {
	    		print('<br>Command executed: '.$confline);
	    		print('<br>Return values: ');
			print_r($return);
		}
	}
	elseif (ereg("^2.",$adapter_version)){
		switch($action){
		case logon:
			if ($flags["create_modify"]=="1") {
				$confline_create_modify=trim($confline)." --version=".$version." --action=create_modify --userdata="."\"".$userdata."\""."\n";
				exec($confline_create_modify,$return);
				if ($debugflag) {
	    				print('<br>Command executed: '.$confline_create_modify);
	    				print('<br>Return values: ');
					print_r($return);
				}
				if (!$return[0]) {
					$confline_logon=trim($confline)." --version=".$version." --action=logon --userdata="."\"".$userdata."\""."\n";
					exec($confline_logon,$return);
					if ($debugflag) {
	    					print('<br>Command executed: '.$confline_logon);
	    					print('<br>Return values: ');
						print_r($return);
					}
				}
			}
			else {
				$confline_logon=trim($confline)." --version=".$version." --action=logon --userdata="."\"".$userdata."\""."\n";
				exec($confline_logon,$return);
				if ($debugflag) {
					print('<br>Command executed: '.$confline_create_modify);
	    				print('<br>Return values: ');
					print_r($return);
				}
			}
			break;
		case logoff:
			// still needs to be done
			break;
		case remove:
			// still needs to be done
			break;
		}

	}
	$sso_values = array();
	$j = -1;
	foreach ($return as $i){
		$pieces = split ("\ |\t",$i,2);  // split char whitespace
		
		if ($pieces[0] == "Error"){
			$errortext = $pieces[1];
			errorpage (40);
		}
		if ($pieces[0] != "redirecturl"){
			if ($pieces[0] == "CookieName") {
				$j = $j + 1;
				$sso_values[$j] = array();
			}
			$sso_values[$j] =  $sso_values[$j] + array( $pieces[0] => trim($pieces[1]));
		}else{
			$sso_values += array( $pieces[0] => trim($pieces[1]));      // $pieces[0] == "redirecturl
		}
	}

}elseif ($cmd == "php"){

	// Include php script
	$confline = trim($confline);
	$arr_exec = split("--url=",$confline);
	$exec = trim($arr_exec[0]);
	$url = trim($arr_exec[1]);
	include_once($exec);
	if ($debugflag) print('<br>Included once: '.$exec);

	// get protocol version from the adapter
	if (function_exists('get_version')) $adapter_version = get_version();
	if (!isset($adapter_version)) $adapter_version = "1.0";
	if ($debugflag) printf('<br>Adapter protocol version: '.$adapter_version);
	
	if ($adapter_version == "1.0") {
		$sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url);
		if ($debugflag) print('<br>Executed function sso with params : '.$user.' '.$_SERVER["REMOTE_ADDR"].' '.$_SERVER["HTTP_USER_AGENT"]);
	}

	elseif (ereg("^2.",$adapter_version)){
		switch ($action) {
		case 'logon':
			if ($flags["create_modify"] == "1"){
				$sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url,$version,"create_modify",$userdata);
				if ($debugflag) print('<br>Executed function sso with params : '.$user.' '.$_SERVER["REMOTE_ADDR"].' '.$_SERVER["HTTP_USER_AGENT"].' '.$url.' '.$version.' create_modify '.$userdata);

				
				if (!$sso_values) $sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url,$version,"logon",$userdata);
				if ($debugflag) print('<br>Executed function sso again with params : '.$user.' '.$_SERVER["REMOTE_ADDR"].' '.$_SERVER["HTTP_USER_AGENT"].' '.$url.' '. $version.' logon '.$userdata);
			}
			else {
				$sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url,$version,"logon",$userdata);
				if ($debugflag) print('<br>Executed function sso with params : '.$user.' '.$_SERVER["REMOTE_ADDR"].' '.$_SERVER["HTTP_USER_AGENT"].' '.$url.' '. $version.' logon '.$userdata);
			}
			break;

		// nothing really happens right now... needs to be finished later
		case 'logoff':
			$sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url,$version,"logoff",$userdata,$version);
			if (!$sso_values){
				successmessage($action);
			}
			break;
		case 'remove':
			$sso_values = sso($user,$_SERVER["REMOTE_ADDR"],$_SERVER["HTTP_USER_AGENT"],$url,$version,"remove",$userdata,$version);
			if (!$sso_values){
				successmessage($action);
			}
			break;
		}
	}
	
	if (isset($sso_values['Error']) && $sso_values['Error'] != ""){
		$errortext = $sso_values['Error'];
		errorpage (40);
	}	
}

if (isset($sso_values['Error']) && $sso_values['Error'] != ""){
  errorpage ($sso_values['Error']);
}

#print_r("<pre>");
#print_r($sso_values);
#print_r("</pre>");

if ($loglevel > 3){
  $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$user." TPA_ID:".$tpa_id." TIMESTAMP:".$expires." SIGNATURE:".$_GET['signature']."\n";
}elseif ($loglevel > 1){
  $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$user." TPA_ID:".$tpa_id."\n";
}
fwrite($logging,$logit);
fclose($logging);

// begin hoven changes
$j=(count($sso_values)-2);
// end hoven changes
for ($i = 0; $i <= $j; $i++){
  if (isset($sso_values[$i]["CookiePath"])){
    $path = $sso_values[$i]["CookiePath"];
  }else{
    $path = "/";
  }
  setcookie(
    $sso_values[$i]["CookieName"],
    $sso_values[$i]["CookieValue"],
    $sso_values[$i]["CookieExpires"],
    $path,
    isset($sso_values[$i]["CookieDomain"]) ? $sso_values[$i]["CookieDomain"] : '',
    isset($sso_values[$i]["CookieSecure"]) ? $sso_values[$i]["CookieSecure"] : FALSE
  );
}
header("Location: ".$sso_values["redirecturl"]);


function getvars(){
  global $debugflag,$_GET,$tpa_id,$thistime,$user,$expires,$sign,$action,$userdata,$version,$flags;
  $tpa_id = $_GET['tpa_id'];
  $thistime = time();
  $user = $_GET['user'];
  $expires = $_GET['expires'];
  $sign = $_GET['signature'];
  $sign = hex2bin($sign);

  # N.Hoven 23.6.05
  # added vars for user propagation
  $version = $_GET['version'];
  $action = $_GET['action'];
  $flags = $_GET['flags'];
  $userdata = $_GET['userdata'];
  #/ N.Hoven

  if ($debugflag) {
	print('<br>Signature detected: '.$sign);
	print('<br>Signature hex2bin and back: '.bin2hex($sign));
  }
}

function hex2bin($data) {
    $len = strlen($data);
    $newdata='';
    for($i=0;$i<$len;$i+=2) {
        $newdata .=  pack("C",hexdec(substr($data,$i,2)));
    }
    return $newdata;
}

function checkvars(){
  global $tpa_id,$user,$expires,$thistime;
  if (!$user){ // no user?
    errorpage(1);
  }
  if (!$tpa_id){ // no tpa_id?
    errorpage(2);
  }
  if (!$expires){ // no expirationtime?
    errorpage(3);
  }
  if ($expires < $thistime){
    errorpage(33);
  }
}

function readconfig(){
  global $configfile,$tokensfile,$logfile,$loglevel,$confline,$user,$tpa_id,$public_ssl_key,$externalOpenssl,$tmp_signature_prefix,$tmp_signature_dir,$_SERVER,$cmd;

  $file = @fopen($configfile,"r");
  if (!$file){            // can't read config
    errorpage(0);
  }
  $filesize = filesize($configfile);
  $entries = fread($file, $filesize);
  fclose ($file);
  $confline="";
  $lines = explode("\n",$entries);
  $section='';
  foreach ($lines as $i){
    if (strtolower(trim($i)) == '[global]'){
      $section='global';
    }elseif (strtolower(trim($i)) == '[main]'){
      $section='main';
    }

    # begin Hoven changes 13.07.05
    # fix for Windows: limit explode b/c of "C:" etc.
    
    $tmp = explode(":",$i,2);
    # end Hoven changes
 
    if ($section == 'global'){
      if ("public_ssl_key" == strtolower(trim($tmp[0]))){
        $public_ssl_key = trim($tmp[1]);
      }elseif ("loglevel" == strtolower(trim($tmp[0]))){
        $loglevel = trim($tmp[1]);
      }elseif ("tokensfile" == strtolower(trim($tmp[0]))){
	$tokensfile	= trim($tmp[1]);
      }elseif ("logfile" == strtolower(trim($tmp[0]))){
	$logfile	= trim($tmp[1]);
      }elseif ("externalopenssl" == strtolower(trim($tmp[0]))){
        $externalOpenssl = trim($tmp[1]);
      }elseif ("tmp_signature_prefix" == strtolower(trim($tmp[0]))){
        $tmp_signature_prefix = trim($tmp[1]);
      }elseif ("tmp_signature_dir" == strtolower(trim($tmp[0]))){
        $tmp_signature_dir = trim($tmp[1]);
      }elseif ("windows_server" == strtolower(trim($tmp[0]))){
        $windows_server = trim($tmp[1]);
      }

    }elseif ($section=='main'){
      if ($tpa_id == trim($tmp[0])){
		$cmd = preg_replace("/\:\/\/.*/", "", trim(str_replace("$tmp[0]:","",$i)));
        $confline = trim(str_replace("$tmp[0]:","",$i));
	# begin Hoven changes 13.07.05
	# fix for Windows: remove slash at the beginning if on windows

        if ($windows_server == "1") {
          $confline = str_replace("$cmd://","",$confline);
        }
        else {
          $confline = str_replace("$cmd:/","",$confline);
        }
	# end Hoven changes

        $confline = trim($confline);
        $confline = str_replace("%remote%",$_SERVER["REMOTE_ADDR"],$confline);
        $confline = str_replace("%agent%","\"".$_SERVER["HTTP_USER_AGENT"]."\"",$confline);
        $confline = str_replace("%user%","\"".$user."\"",$confline);
        $confline.= "\n";
      }
    }
  }

  if (!$confline){  // no config entry for tpa_id
    errorpage(30);
  }
  if (!$public_ssl_key){  // no config entry for public_ssl_key
    errorpage(10);
  }
  if (!$tokensfile){  // no tokensfile entry
    errorpage(11);
  }
  if (!$logfile){  // no logfile entry
    errorpage(12);
  }
}

function checksign(){
  global $debugflag,$public_ssl_key,$data,$sign,$externalOpenssl,$tmp_signature_dir,$tmp_signature_prefix;


  if (($externalOpenssl == 1)||($externalOpenssl == true)){
if ($debugflag) printf('<br>Using EXTERNAL openssl');
    $tmp_signature_file = $tmp_signature_dir."/".uniqid($tmp_signature_prefix);
    $tmp_file = @fopen ($tmp_signature_file, "w");
    fwrite($tmp_file, $sign);
    fclose($tmp_file);
if ($debugflag) printf('<br>Data to verify: '.$data);
    
   $verify = shell_exec("echo -n \"".$data."\"|openssl dgst -sha1 -verify \"".$public_ssl_key."\" -signature \"".$tmp_signature_file."\"");
   unlink($tmp_signature_file);

if ($debugflag) printf('<br>Verification result string: '.$verify);

    if ($verify == "Verified OK\n"){
      $ok = 1;
    }else{
      errorpage(32);
    }
  }else{
if ($debugflag) printf('<br>Using INTERNAL openssl');
    $fp = @fopen($public_ssl_key, "r");
    if ($fp) {
      $cert = fread($fp, 8192);
      fclose($fp);
      $pubkeyid = openssl_get_publickey($cert);
if ($debugflag) {
	printf('<br>Data to verify: '.$data);
	printf('<br>Key: '.$cert);
}
      // compute signature
      $ok = @openssl_verify($data, $sign, $pubkeyid);
      // remove key from memory
      @openssl_free_key($pubkeyid);
    }else{
      errorpage(20);
    }
  }
  if ($ok != 1) { // error in signature
    errorpage(32);
  }
}

function checkused(){
  global $tokensfile,$expires,$user,$tpa_id,$thistime;

  $file = touch($tokensfile); 
  if (!$file){            // can't read tokensfile
     errorpage(21);
  }
  $file = @fopen($tokensfile,"r");
  if (!$file){            // can't read tokensfile
     errorpage(21);
  }
  $filesize = filesize($tokensfile);
  $tokensactive = fread($file, $filesize);
  fclose ($file);

  $lines = explode("\n",$tokensactive);
  foreach ($lines as $i){
    $tmp = explode(":",$i);
    if (($tmp[0] == $expires)&&($tmp[1] == $user)&&($tmp[2] == $tpa_id)){
      errorpage(31);
    }
  }
  $filew = @fopen($tokensfile,"w+");
  $content = "";
  foreach ($lines as $j){
    $tmp = explode(":",$j);
    if ($tmp[0] > $thistime){
      $content.= $tmp[0].':'.$tmp[1].':'.$tmp[2]."\n";
    }
  }
  $content.= $expires.':'.$user.':'.$tpa_id."\n";
  if (!fwrite($filew,$content)){
    errorpage(21);
  }
  fclose ($filew);
}


function errorpage($error){
  global $_SERVER,$_GET,$logging,$loglevel,$logit,$logfile,$thistime,$errorcodes,$errortext;
  
  if ($loglevel > 2){
    // Date format: Sat Mar 10 15:16:08 MST 2001
    $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$_GET['user']." TPA_ID:".$_GET['tpa_id']." TIMESTAMP:".$_GET['expires']." SIGNATURE:".$_GET['signature']." ERROR ".$error.":".$errorcodes[$error]."\n";
  }elseif ($loglevel > 0){
    $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$_GET['user']." TPA_ID:".$_GET['tpa_id']." ERROR ".$error.":".$errorcodes[$error]."\n";
  }
  // Write to Logfile
  if ($error != 0 && $logging){
    fwrite($logging,$logit);
    fclose($logging);
  }
	$errorPageTemplate = file_get_contents(dirname(__FILE__) . '/sigsso_errorpage_template.html');
  if (isset($errorcodes[$error+200])){
    header("Location: ".$errorcodes[$error+200]);
  }elseif (isset($errorcodes[$error+100])){
	$errorPage = str_replace('###ERROR_TITLE###', 'A login error occurred.', $errorPageTemplate);
	$errorPage = str_replace('###ERROR_MESSAGE###', $errorcodes[$error+100] . '<br />' . $errortext, $errorPage);
	echo ($errorPage);
  }else{
	$errorPage = str_replace('###ERROR_TITLE###', 'A login error occurred.', $errorPageTemplate);
	$errorPage = str_replace('###ERROR_MESSAGE###', $errorcodes[$error] . '<br />' . $errortext, $errorPage);
	echo ($errorPage);
  }
  exit; 
}

function errorcode_default(){
  global $configfile,$errorcodes;

  // Standard Codes:
  $errorcodes += Array(
	0 => "sigsso: file access error - sigsso config file",	//
	1 => "sigsso: Invocation error - missing USER",		//user_missing
	2 => "sigsso: Invocation error - missing TPA_ID",	//tpaid_missing
	3 => "sigsso: Invocation error - missing ExpirationTime",//expires_missing
	4 => "sigsso: Invocation error - missing signature",	//signature_missing
	10 => "sigsso: error in configfile - missing public_ssl_key",//sslkey_missingconf
	11 => "sigsso: error in configfile - missing tokensfile entry",//usedtokens_missingconf
	12 => "sigsso: error in configfile - missing logfile",	//logfile_missingconf
	20 => "sigsso: file access error - SSL public key file",	//sslkey_missingfile
	21 => "sigsso: file access error - UsedTokens file",	//usedtokens_missingfile
	22 => "sigsso: file access error - log file",		//logfile_missingfile
	30 => "sigsso: validation error - TPA_ID is invalid or not configured",//tpaid_unknown
	31 => 'The single-signon link you followed has already been used. For security reasons you can use a SSO link only once. Please go back to where you clicked the link and request a new one by reloading the page.',//usedtokens_allreadyused
	32 => "sigsso: validation error - signature invalid",	//signature_invallid
	33 => 'The single-signon link you followed has expired. For security reasons you can use a SSO link only during a short time. Please go back to where you clicked the link and request a new one by reloading the page.', //expires_exeeded
	40 => "sigsso: An error in the Third Party Application Adapter occurred. It said: " //tpa_error
  );
}

function errorcode(){
  global $configfile,$errorcodes;

  $file = @fopen($configfile,"r");
  $entries = fread($file, filesize($configfile));
  fclose ($file);
  $lines = explode("\n",$entries);
  $section='';
  foreach ($lines as $i){
    if (strtolower(trim($i)) == '[global]'){
      $section='global';
    }elseif (strtolower(trim($i)) == '[main]'){
      $section='main';
    }elseif (strtolower(trim($i)) == '[errorcodes]'){
      $section='errorcodes';
    }
    $tmp = explode(":",$i,2);
    $tmp2 = trim($tmp[0]); // conf entry name
    if(isset($tmp[1])){
      $tmp3 = trim($tmp[1]); // conf entry value
    }
    if ($section == 'errorcodes'){
      if ("user_missing" == $tmp2){
        checkifurl($tmp3,1);
      }elseif ("tpaid_missing" == strtolower($tmp2)){
        checkifurl($tmp3,2);
      }elseif ("expires_missing" == strtolower($tmp2)){
        checkifurl($tmp3,3);
      }elseif ("signature_missing" == strtolower($tmp2)){
        checkifurl($tmp3,4);
      }elseif ("sslkey_missingconf" == strtolower($tmp2)){
        checkifurl($tmp3,10);
      }elseif ("usedtokens_missingconf" == strtolower($tmp2)){
        checkifurl($tmp3,11);
      }elseif ("logfile_missingconf" == strtolower($tmp2)){
        checkifurl($tmp3,12);
      }elseif ("sslkey_missingfile" == strtolower($tmp2)){
        checkifurl($tmp3,20);
      }elseif ("usedtokens_missingfile" == strtolower($tmp2)){
        checkifurl($tmp3,21);
      }elseif ("logfile_missingfile" == strtolower($tmp2)){
        checkifurl($tmp3,22);
      }elseif ("tpaid_unknown" == strtolower($tmp2)){
        checkifurl($tmp3,30);
      }elseif ("usedtokens_allreadyused" == strtolower($tmp2)){
        checkifurl($tmp3,31);
      }elseif ("signature_invalid" == strtolower($tmp2)){
        checkifurl($tmp3,32);
      }elseif ("expires_exeeded" == strtolower($tmp2)){
        checkifurl($tmp3,33);
      }elseif ("tpa_error" == strtolower($tmp2)){
        checkifurl($tmp3,40);
      }
    }
  }
}

function successmessage($action){
  global $_SERVER,$_GET,$logging,$loglevel,$logit,$logfile,$thistime,$errorcodes,$errortext;
  
  if ($loglevel > 2){
    // Date format: Sat Mar 10 15:16:08 MST 2001
    $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$_GET['user']." TPA_ID:".$_GET['tpa_id']." TIMESTAMP:".$_GET['expires']." SIGNATURE:".$_GET['signature']." SUCCESS: action '".$action."' completed successfully\n";
  }elseif ($loglevel > 0){
    $logit = date("D M j G:i:s T Y")." IP:".$_SERVER["REMOTE_ADDR"]." USER:".$_GET['user']." TPA_ID:".$_GET['tpa_id']." SUCCESS: action '".$action."' completed successfully\n";
  }
  // Write to Logfile
  fwrite($logging,$logit);
  fclose($logging);
  

  echo "<html>\n<head>\n<title>action '".$action."' completed successfully</title>\n</head>\n";
  echo "<body onLoad=\"setTimeout('window.close()',5000)\">\n<h1>Server Notice</h1>\n<p>";;
  echo "action '".$action."' completed successfully.<p>";
  echo "if this window doesn't close within 5 seconds<BR>please click <a href=\"#\" onclick=\"window.close()\">here</a>";
  echo "</p>\n</body>\n</html>";
  exit; 
}


function checkifurl($text,$errorcode){
  global $errorcodes;
  
  if (preg_match ("/^https:\/\//",strtolower(trim($text)))){
    $num = 200 + $errorcode;
    $errorcodes += Array($num => $text);
  }elseif (preg_match ("/^http:\/\//",strtolower(trim($text)))){
    $num = 200 + $errorcode;
    $errorcodes += Array($num => $text);
  }elseif ($text){
    $num = 100 + $errorcode;
    $errorcodes += Array($num => $text);
  }
}

?>
