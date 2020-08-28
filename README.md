Goloris - slowloris[1] for nginx DoS
===============================================

#### Note: This version has been modified from the original that can be found [here](github.com/valyala/goloris)

* Notable changes:
     - Added tor flag to use tor socks proxy
     - Set maxConnections flag to set maximum number of simultaneous connections
        - recommended to set maxConnections flag to <= `ulimit -n` 


Original Readme below:

---

## FAQ

* **Features**

  - Uses as low network bandwidth as possible.
  - Low CPU and memory usage.
  - Automatically and silently eats all the available TCP connections
    to the server.
  - Supports https.
  - Easily hackable thanks to clear and concise Go syntax
    and powerful Golang features.


* **Limitations**

  - Can eat up to 64K TCP connections from a single IP due to TCP limitations.
    Just use proxies if you want overcoming this limitation :)


* **How it works?**

  It tries occupying and keeping busy as much tcp connections
  to the victim as possible by using as low network bandwidth as possible.
  If goloris is lucky enough, then eventually it should eat all the available
  connections to the victim, so no other client could connect to it.
  See the source code for more insights.


* **How quickly it can take down unprotected nginx with default settings?**

  In a few minutes with default config options.


* **Which versions of nginx are vulnerable?**

  All up to 1.5.9 if unprotected as described below (i.e. with default config).


* **How to protect nginx against goloris?**

  I know the following options:
  - Limit the number of simultaneous TCP connections from the same
    source ip. See, for example, connlimit in iptables
    or http://nginx.org/en/docs/http/ngx_http_limit_conn_module.html
  - Deny POST requests.
  - Patch nginx, so it drops connection if the client sends POST
    body at very slow rate.


* **How to use it?**

  ```bash
  go get -u -a github.com/amosburton/goloris.git
  go build github.com/amosburton/goloris.git
  ./goloris -help
  ```

P.S. Don't forget adjusting `ulimit -n` before experimenting.

And remember - goloris is published for educational purposes only.

* ** Example command **

    ```bash
    ./goloris --dialWorkersCount 100 --victimUrl xxx --hostHeader example.com --proxy "http https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=100&country=all, http https://www.proxyscan.io/download?type=http, http https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt, http https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt, socks5 https://api.proxyscrape.com/?request=getproxies&proxytype=socks5&timeout=1000&country=all, socks5 https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt, socks5 https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt, socks5 https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt, http https://multiproxy.org/txt_all/proxy.txt, https://github.com/fate0/proxylist/blob/master/proxy.list, socks5 https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt" --refreshProxies 5m
    ```

