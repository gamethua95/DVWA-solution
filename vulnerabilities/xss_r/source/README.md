# Cross-Site Scripting (XSS) Explaination for Each Security Level and Suggestion
---

## Low level

### Explaination

Check out **source code** below:

![image](https://user-images.githubusercontent.com/56772435/126078264-d2fddf60-f0ea-4a42-b7bd-1769fc40c898.png)

There is no input filter on arrival. Attacker could inject any content.

---

## Medium level

### Explaination

Check out **source code** below:

![image](https://user-images.githubusercontent.com/56772435/126078388-cd4c3dfc-48c6-4397-bad6-e5651fbd5413.png)

There is a function called [str_replace()](https://www.php.net/manual/en/function.str-replace.php) which is used to replace all occurrences of the search string with the replacement string. 

`$name = str_replace( '<script>', '', $_GET[ 'name' ] );`

In this case, it replaces **<script>** by **NULL** so any input like this **<script>alert(1)</script>** will be converted to **alert(1)</script>**:

![image](https://user-images.githubusercontent.com/56772435/126078840-dd2f9720-e6fa-4685-9f8f-da832ba7c908.png)

The point is developers will have to declare a list of possible malicious inputs which is obviously not a wise thing to do. So, attacker just need to supply an unexpected input to get scripts run such as, <SCRIPT>, <SCript> or any other HTML tags. 
  
![image](https://user-images.githubusercontent.com/56772435/126079244-370e307a-173d-4500-85da-d1c1e8f2dd54.png)

---

## High level

### Explaination
   
Check out **source code** below:
  
![image](https://user-images.githubusercontent.com/56772435/126079439-a7bcd9ba-950e-459e-8111-e49e0ae6a74e.png)

There is a function called [preg_replace()](https://www.php.net/manual/en/function.preg-replace.php) which is used to perform a regular expression search and replace.
  
$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
  
In this case, it will perform a regular expression search to detect **<script>** tag and replaces everything inside the tag by NULL. The problem is developer is supposed to be skillful in regex and there is much more than just a **<script>** tag.
  
---

## FOR MEMEDIATION, PLEASE READ [prevention_high.php](https://github.com/gamethua95/DVWA-solution/blob/main/vulnerabilities/xss_r/source/prevention_high.php)
