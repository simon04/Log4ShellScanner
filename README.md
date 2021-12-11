# Log4ShellScanner
Scans and catches callbacks of systems that are impacted by Log4J Log4Shell vulnerability across specific headers.

*Very Beta Warning!* :)

![Alt text](https://raw.githubusercontent.com/mwarnerblu/Log4ShellScanner/main/extras/log4shellscanner_output.png "Log4Shell Scanner Output")

In an effort to simplify the annoying effort of figuring out what actually has vulnerable log4j, I put together a scanner which attempts to pollute X-Api-Version, User-Agent, and Authentication headers. In my testing I'm able to get back vulnerable servers however this likely need additional expansion as new methods of injection are realized.

# Usage

```
Usage of ./log4shell:
  -DestCIDR string
        What Subnet do you want to scan? (default "192.168.10.0/24")
  -DestPort string
        At what port are the applications you want to scan? (default "8080")
  -SourceIP string
        Your Preferred Source/Requesting IP for Callback (default "Unset")
  -SourcePort string
        Port used for listening on callback, defaults to 8081 (default "8081")
  -Stdin
        Read destination URLs from stdin, e.g., 'log4shell < ips.txt'
```

Example: scan 192.168.10.0/24

```
./log4shell -SourceIP 192.168.10.130 -SourcePort 8081 -DestCIDR 192.168.10.0/24 -DestPort 8080
```

Example: scan URLs from file

```
echo http://192.168.10.13:8080/foo/bar >> urls.txt
echo http://192.168.10.42:8080/baz >> urls.txt
./log4shell -SourceIP 192.168.10.130 -SourcePort 8081 -Stdin < urls.txt
```

# Known Limitations
As this was thrown together for internal testing and validation there's a few limitations still! 

* Only goes over HTTP right now, HTTPS can be easily added in the future
* Does not allow a variety of ports
* Could be better threaded 
* Doesn't handle exit gracefully and just waits for callbacks
