# evtxsc

A Java-based Windows Event Log (EVTX) utility that quickly parses complete logs and flags suspicious events including brute force attempts, suspicious PowerShell activity, and privilege escalation. 

## Utilities

- \[4625] Brute Force Detection: Flags failed login patterns.
- \[4104] Powershell Script Analysis: Flags script blocks with obfuscation, malicious commands, and network activity.
- \[4672, 4728, 4732] Privilege Escalation Detection: Flags all privilege assignments and security group modifications.

## Installation
_Requires [Java 17+](https://www.java.com/en/), [Apache Maven](https://maven.apache.org/), [EVTX](https://learn.microsoft.com/en-us/shows/inside/event-viewer) Files in XML format._

```bash
git clone https://github.com/braedenbucher/evtxsc.git
cd evtxsc
mvn clean install
chmod +x evtxsc.sh # linux/mac only
```

## Usage

Basic execution:
```bash
# Linux/Mac
./evtxsc.sh [flags]

# Windows
evtxsc.bat [flags]
```

Basic scan of all event types:
```bash
[evtxsc] -f file.xml
```

Run specific scans:
```bash
[evtxsc] -f file.xml --scan bruteforce powershell
```

Save results to file:
```bash
[evtxsc] -f file.xml --output results.txt
```

Process multiple files with different configurations:
```bash
[evtxsc] -f file1.xml --scan bruteforce --output bf.txt \
       -f file2.xml --append master.log --no-console
```

### Command Line Options

`-f <filepath>` - Specify EVTX XML file to scan (required, repeatable)

`--scan <types>` - Space-separated scan types: `bruteforce`, `powershell`, `privesc` (default: all)

`--output <filepath>` - Write results to file (overwrites existing)

`--append <filepath>` - Append results to file

`--no-console` - Suppress console output

## License

MIT License - see [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes.








