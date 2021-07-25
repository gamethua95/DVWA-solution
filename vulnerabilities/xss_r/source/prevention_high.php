<?php

header ("X-XSS-Protection: 0");
//header("Content-Security-Policy: default-src 'self'");

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
	// Get input
	$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
	//$sname = htmlspecialchars(strip_tags($name), ENT_QUOTES, 'UTF-8');
	//$sname = filter_var($name, FILTER_SANITIZE_STRING);
	/*		function jsEscape($str) {
			  $output = '';
			  $str = str_split($str);
			  for($i=0;$i<count($str);$i++) {
			   $chrNum = ord($str[$i]);
			   $chr = $str[$i];
			   if($chrNum === 226) {
			     if(isset($str[$i+1]) && ord($str[$i+1]) === 128) {
			       if(isset($str[$i+2]) && ord($str[$i+2]) === 168) {
			         $output .= '\u2028';
			         $i += 2;
			         continue;
			       }
			       if(isset($str[$i+2]) && ord($str[$i+2]) === 169) {
			         $output .= '\u2029';
			         $i += 2;
			         continue;
			       }
			     }
			   }
			   switch($chr) {
			     case "'":
			     case '"':
			     case "\n";
			     case "\r";
			     case "&";
			     case "\\";
			     case "<":
			     case ">":
			       $output .= sprintf("\\u%04x", $chrNum);
			     break;
			     default:
			       $output .= $str[$i];
			     break;
			    }
			  }
			  return $output;
			}	
		$sname = jsEscape($name); */

/* -------------------------------------------------------------------------------- HOW TO PREVENT XSS ATTACKS ----------------------------------------------------------------------------------

	- FILTER INPUT ON ARRIVAL (At the point where user input is received, filter as strictly as possible based on what is expected or valid input) and ENCODE DATA ON OUTPUT (At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding).

		1. Use strip_tags — Strip HTML and PHP tags from a string
			$sname = strip_tags($name);

		2. Use htmlspecialchars - Convert special characters to HTML entities
			$sname = htmlspecialchars($name, ENT_QUOTES, ['UTF-8']);

		Or Use htmlentities - Convert all applicable characters to HTML entities 
			$sname = htmlentities($name, ENT_QUOTES, ['UTF-8']);

		3. Use Sanitize filters
			#sname = filter_var($name, FILTER_SANITIZE_STRING);	

		4. Unicode-escape when in a JavaScript context. When in a JavaScript string context, you need to Unicode-escape input as already described. Unfortunately, PHP doesn't provide an API to Unicode-escape a string. Here is some code to do that in PHP:

			function jsEscape($str) {
			  $output = '';
			  $str = str_split($str);
			  for($i=0;$i<count($str);$i++) {
			   $chrNum = ord($str[$i]);
			   $chr = $str[$i];
			   if($chrNum === 226) {
			     if(isset($str[$i+1]) && ord($str[$i+1]) === 128) {
			       if(isset($str[$i+2]) && ord($str[$i+2]) === 168) {
			         $output .= '\u2028';
			         $i += 2;
			         continue;
			       }
			       if(isset($str[$i+2]) && ord($str[$i+2]) === 169) {
			         $output .= '\u2029';
			         $i += 2;
			         continue;
			       }
			     }
			   }
			   switch($chr) {
			     case "'":
			     case '"':
			     case "\n";
			     case "\r";
			     case "&";
			     case "\\";
			     case "<":
			     case ">":
			       $output .= sprintf("\\u%04x", $chrNum);
			     break;
			     default:
			       $output .= $str[$i];
			     break;
			    }
			  }
			  return $output;
			}	

		4. Other consider functions if suitable
			urlencode(), 	

	- USE APPROPRIATE RESPONSE HEADERS. To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the Content-Type and X-Content-Type-Options headers to ensure that browsers interpret the responses in the way you intend.
			
	- CONTENT SECURITY POLICY. As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.

		Use "header("Content-Security-Policy: default-src 'self'");" inside an PHP page or configure at .htaccess file to add CSP header: "Header set Content-Security-Policy "default-src 'self';" so all content only come from the site's own origin (this excludes subdomains.)

		Or Anither example CSP is as follows:
		default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';

		This policy specifies that resources such as images and scripts can only be loaded from the same origin as the main page. So even if an attacker can successfully inject an XSS payload they can only load resources from the current origin. This greatly reduces the chance that an attacker can exploit the XSS vulnerability.
*/		
	// Feedback for end user
	$html .= "<pre>Hello ${name}</pre>";
	//$html .= "<pre>Hello ${sname}</pre>";

}

?>
