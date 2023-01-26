# ssh-scanner
Some (hacky) fast SSH-Scanner to try some credential at ✨ webscale ✨ against a lot (or maybe even all IPv4) SSH servers.

## Usage
As a preparation [`masscan`](https://github.com/robertdavidgraham/masscan) the target network for open SSH servers, write a text file, one target IP per line.

```
Usage of ./ssh-scanner:
  -cmd string
    	SSH command (default "id")
  -cpuprofile string
    	write cpu profile to file
  -input string
    	Text file with ip addresses (default "in.txt")
  -interactivepass
    	Read password as console input
  -logfile string
    	Logfile (default "log.jsonl")
  -logpass
    	Log password
  -loguser
    	Log user
  -p int
    	SSH port (default 22)
  -pass string
    	SSH password
  -src string
    	Comma separated list of source IP addresses to use
  -t int
    	Parallelism, must be smaller than: net.ipv4.ip_local_port_range (second value - first value) (default 40000)
  -user string
    	SSH user
```

## Considerations
* Tuning TCP kernel parameters yields better, faster results
* You'll get a bunch of abuse complaints, much more than from a `masscan` -> talk to you ISP or be your ISP
* Code quality could be improved, this was a quick hack to determine impact of some hardcoded credentials in some internet of shit device
* More features could be added, e.g. writing results to an Elasticsearch or database
