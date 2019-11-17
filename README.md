# gohima 

Gohima is a lightweight 'intrusion mitigation' Go application that monitors local Sysmon (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) events in real-time for malicious activity. Gohima leverages signatures written in the Sigma Generic Signature Format .yml (https://github.com/Neo23x0/sigma). 

Gohima currently only supports 'Selection' (Detect if matches all fields under selection) and 'EventId' Sigma rule configuration. Event matching with filter, keyword and tags are not supported yet. Gohima will actively kill processes based on PID upon signature matches (custom actions to be implemented in the future). 
 
This is a proof of concept tool, created purely to test the idea of leveraging Sysmon for active intrusion mitigation against powershell reverse shells and other detection signatures etc. (In addition to being a weekend project to learn Go.) 

Any tool that performs active mitigations on a system using signature matching is bound to cause issues, especially when killing processes by PID. Obviously don't use this on any production environment. I provide no guarentees on the behaviour of the application and i'm not responsible for any impact on the systems you choose to run this on! 

Use at your own risk!


**Prerequisites:**

- Sysmon is deployed on local system, capturing events you want gohima.exe to act on.
  - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://github.com/SwiftOnSecurity/sysmon-config 

- Sigma rules are configured
  - https://github.com/Neo23x0/sigma

- Below Go modules.

```
go get -t -v "www.velocidex.com/golang/evtx"
go get -t -v "github.com/ghodss/yaml"
go get -t -v "github.com/tidwall/gjson"
go get -t -v "github.com/ryanuber/go-glob"
```

**Compile**
```
$ go build -o gohima.exe gohima.go
```

**Configuration**
```
Place your Sigma format rules (.yml) in a folder called 'rules' in same directory as binary.

Alternatively use the following ruleset from Sigma: 

https://github.com/Neo23x0/sigma/tree/master/rules/windows/sysmon 
```
**Usage**

```
gohima.exe (https://github.com/PotatoIndustries/gohima)

a proof of concept Go based local intrusion mitigation agent for Windows platform.

Usage: gohima.exe
  -agree
        Set this flag to run gohima.exe.

NOTE: This is an experimental tool, not for production use.

gohima.exe monitors your live local sysmon eventlogs, performs signature matching based on configured Sigma .yml rulesets to detect intrusion and automatically kills processes upon detection. Use with caution!
```

**Run** 
```
$ gohima.exe -agree
```

**Known Issues**

- Lag. gohima.exe tails the local sysmon .evtx file, events are not immediately (at least from initial inspection) written to the file. Expect lag times of up to 1 minute before a mitigation action actually occurs, which in real world scenarios can be quite a long delay. So there is lag before Gohima can even start parsing the event, performing matches for signatures and then reacting.


Enjoy~
