## Setup 

### Metasploitable 3 with VirtualBox

* https://github.com/rapid7/metasploitable3/wiki
* Used installed guide: https://github.com/rapid7/metasploitable3/blob/master/README.md and default script build_win2008.sh, host OS MacOS SIerra 10.12.3

### Snort
* https://www.snort.org/
* Installed to host OS with homebrew , Version 2.9.9.0 GRE (Build 56)

```shell
brew install snort
```

* Used snort.conf registered rules 2990
* See attached snort.conf in github for the possible modifications:
* Opened snort (in host OS) with the following command in bash:
```shell
snort -c /etc/snort/rules/snort.conf -i vboxnet0 -l /Users/tkasu/Programming/snort-files/ -A console -k none
```

### Metasploit
* https://github.com/rapid7/metasploit-framework 
* Additional tools
	* nmap: brew install nmap
* All examples are done with command line tool msfconsole (/opt/metasploit-framework/bin/msfconsole)

