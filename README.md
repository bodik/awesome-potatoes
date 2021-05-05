# Awesome Windows Potatoes

Study notes on Windows NTLM Reflection and token stealing based EOPs.


## Misc

* **RPC/Microsoft RPC/MSRPC (Microsoft Remote Procedure Call)** -- ... is a modified version of DCE/RPC. Additions include partial support for UCS-2 (but not Unicode) strings, implicit handles, and complex calculations in the variable-length string and structure paradigms already present in DCE/RPC.

* **COM** -- Component Object Model (COM) is a binary-interface standard for software components introduced by Microsoft in 1993. It is used to enable inter-process communication object creation in a large range of programming languages. COM is the basis for several other Microsoft technologies and frameworks. Basicaly it is an communication middleware. Different component types are identified by class IDs (CLSIDs), which are Globally Unique Identifiers (GUIDs). Each COM component exposes its functionality through one or more interfaces. The different interfaces supported by a component are distinguished from each other using interface IDs (IIDs), which are GUIDs too.

* **Reflection attack** -- This article is about the attack on authentication systems. For the denial of service attack, see Distributed Reflection Denial of Service. In computer security, a reflection attack is a method of attacking a challenge–response authentication system that uses the same protocol in both directions. That is, the same challenge–response protocol is used by each side to authenticate the other side. The essential idea of the attack is to trick the target into providing the answer to its own challenge.[1]

* **Windows Access Token** -- [x4] When you login to a system whether it is locally, over the network, as a service, or even directly calling the LogonUser API function the authentication package creates a logon session and then has Local Security Authority (LSA) create an access token for the user. This token represents the account security context and contains information including: The ID of the logon session, User and group SIDs, The integrity level, Privileges held by the user or groups the user is in.

  * **Restricted/Filtered vs Elevated tokens** -- When you login you will actually be assigned two tokens. One being the token with full 
    access. The other token will be a restricted or filtered token that will only have a subset of the permissions. It is the restricted token 
    that Windows Explorer and most processes typically will run under. The most relevant part about the restricted token is that it may not 
    even list some of the privileges that the user has. So, if we want to use the unrestricted token, UAC requires “run as administrator” and 
    going through the elevation prompt.

  * **Primary and impersonation tokens** -- Now there are two types of tokens: primary and impersonation. Primary tokens are only able to be 
    attached to a process while impersonation tokens can only be attached to threads. Impersonation is how a server can assume the identity of 
    a client and the security access that the user has. The impersonation is only temporary and overrides the primary token for just the 
    thread until it finishes. There are several levels of access tokens: Anonymous, Identification, Impersonation and Delegation

  * **Privileges** -- Privileges are special rights to perform various system operations. These are assigned to the user and as mentioned 
    earlier are listed in the user token. They can be in an enabled or disabled state. This isn’t to be confused with restricted tokens. It’s 
    fairly trivial to enable a privilege and it is merely used as a safeguard to prevent unintended actions.

* **SeImpersonatePrivilege** -- SeImpersonatePrivilege can allow process to impersonate a token of a user and run under the security context of it. There is also a very similar sibling of SeImpersonatePrivilege called SeAssignPrimaryTokenPrivilege. If we have SeImpersonatePrivilege we can call CreateProcessWithTokenW() to create a process with the token we have. It’s sibling SeAssignPrimaryTokenPrivilege allows the ability to call CreateProcessAsUserA() which performs similarly. Another option would be to create a thread and set the token of the thread with either SetThreadToken() or ImpersonateLoggedOnUser(). One API call that can come in handy is DuplicateTokenEx() which will duplicate a token but you can specify the type of token you want. Primary and Impersonation tokens can be converted to each other.



## References in timeline

* 31.03.2001 -- The SMB authentication relay attack by Sir Dystic -- https://en.wikipedia.org/wiki/SMBRelay

* ??.2004 -- Microsoft Release Windows XP SP2

* ??.2004: Jesse Burns of iSec demonstrates HTTP-toSMB version at Black Hat (but doesn’t release the tool)

* 2007 -- HD Moore re-implements HTTP-to-SMB attack, integrates it into Metasploit development code branch

* 2008 -- Microsoft Mitigate SMB/SMB Reflection in MS08-68

* 2009 -- Microsoft Mitigate HTTP/SMB Reflection in MS09-13

* 18.12.2014 -- Issue 222: Windows: Local WebDAV NTLM Reflection Elevation of Privilege -- https://bugs.chromium.org/p/project-zero/issues/detail?id=222

* 09.04.2015 -- Issue 325: Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege -- https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1

* 29.12.2015 -- Social Engineering The Windows Kernel: Finding And Exploiting Token Handling Vulnerabilities -- https://www.youtube.com/watch?v=QRpfvmMbDMg

* 16.01.2016 -- Hot Potato

* 20.01.2016 -- Smashed Potato

* 18.08.2016 -- ?MS fixed Hot Potato exploit technique by MS16-075

* 26.09.2016 -- Rotten potato -- https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/, https://github.com/foxglovesec/RottenPotato

* 18.08.2017 -- James Forshaw - COM in Sixty Seconds! (well minutes more likely) @ Infiltrate 2017.mp4 -- https://www.youtube.com/watch?v=dfMuzAZRGm4

* **TODO** 25.08.2017 -- Abusing Token Privileges For Windows Local Privilege Escalation -- https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/, https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt

* 19.01.2018 -- James Forshaw - Abusing Access Tokens for UAC Bypasses -- https://www.youtube.com/watch?v=UTvOfmtNVKI, https://www.powershellgallery.com/packages/NtObjectManager/1.1.31, https://gist.github.com/tyranid/9ffef5962a642d4a1bb8e4ee7e3bebc5, https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html, https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-2.html, https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-3.html

* 10.08.2018 -- Juicy Potato (abusing the golden privileges) -- http://ohpe.it/juicy-potato/

* 05.10.2018 -- @tifkin_ (Lee Christensen), @harmj0y(Will Schroeder), @enigma0x3(Matt Nelson): The Unintended Risks of Trusting Active Directory @ DerbyCon 2018 -- https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory, https://github.com/leechristensen/SpoolSample, https://www.youtube.com/watch?v=-bcWZQCLk_4

* ??.11.2018 -- Microsoft Mitigate Rotten/Juicy Potato in later Windows versions (1809 onwards)

* **TODO** 21.01.2019 -- Abusing Exchange: One API call away from Domain Admin -- https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/, https://github.com/dirkjanm/privexchange/

* **TODO** 06.11.2019 -- Tyranid's Lair: The Ethereal Beauty of a Missing Header -- https://www.tiraniddo.dev/2019/11/the-ethereal-beauty-of-missing-header.html

* **TODO** 08.10.2019 -- Active Directory Open to More NTLM Attacks: Drop The MIC 2 (CVE 2019-1166) and Exploiting LMv2 Clients (CVE-2019-1338) -- https://www.crowdstrike.com/blog/active-directory-ntlm-attack-security-advisory/

* 12.11.2019 -- Danyal Drew: Ghost Potato -- https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html

* **TODO** 05.12.2019 -- itm4n: Give Me Back My Privileges! Please? -- https://itm4n.github.io/localservice-privileges/, https://github.com/itm4n/FullPowers

* 06.12.2019 -- We thought they were potatoes but they were beans (from Service Account to SYSTEM again) -- https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/, https://github.com/antonioCoco/RogueWinRM

* 07.01.2020 -- #HITBCyberWeek​ D2T2 - Reimplementing Local RPC In .Net - James Forshaw -- https://www.youtube.com/watch?v=2GJf8Hrxm4k

* 14.04.2020 -- Ceri Coburn: SweetPotato – Service to SYSTEM -- https://ethicalchaos.dev/2020/04/13/sweetpotato-local-service-to-system-privesc/, https://github.com/CCob/SweetPotato

* 25.04.2020 -- Tyranid's Lair: Sharing a Logon Session a Little Too Much -- https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html

* **TODO** 02.05.2020 -- From LOCAL/NETWORK SERVICE to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 and Server 2016/2019. -- https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/, https://github.com/itm4n/PrintSpoofer

* **TODO** 04.05.2020 -- From NETWORK SERVICE to SYSTEM -- https://decoder.cloud/2020/05/04/from-network-service-to-system/

* 11.05.2020 -- Decoder: No more JuicyPotato? Old story, welcome RoguePotato! -- https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/, https://github.com/antonioCoco/RoguePotato

* 14.05.2020 -- Sylvain Heiniger: Relaying NTLM authentication over RPC -- https://blog.compass-security.com/2020/05/relaying-ntlm-authentication-over-rpc/

* 30.05.2020 -- Decoder: The impersonation game -- https://decoder.cloud/2020/05/30/the-impersonation-game/, https://github.com/decoder-it/juicy_2

* **TODO** 22.01.2021 -- MSRPC Printer Spooler Relay (CVE-2021-1678) -- https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/

* 01.04.2021 -- Micah Van Deusen: The Power of SeImpersonation -- https://micahvandeusen.com/the-power-of-seimpersonation/, https://github.com/micahvandeusen/GenericPotato

* 26.04.2021 -- Relaying Potatoes: Another Unexpected Privilege Escalation Vulnerability in Windows RPC Protocol -- https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop/



## Other references

* [x1] https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html
* [x2] https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/
* [x3] https://decoder.cloud/2018/01/13/potato-and-tokens/
* [x4] https://micahvandeusen.com/the-power-of-seimpersonation/
* [x5] https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html
* [yy] anything else I found publicly available on the Internet, used and lost reference to. sory.



## Exploits, Techniques and Potatoes

### The SMB authentication relay attack by Sir Dystic

aka MS08-068 Microsoft Windows SMB Relay Code Execution

* https://en.wikipedia.org/wiki/SMBRelay
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbrelayx.py
* https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/windows/smb/smb_relay.rb

Relay listener would reflects/relay incoming SMB connection (authentication requests) 
back to the target allowing attacker to reuse created session. Microsoft mitigated the
attack in 2008 by disallowing SMB->SMB relaying (perhaps fully same-protocol relaying).


### Windows: Local WebDAV NTLM Reflection Elevation of Privilege

* https://bugs.chromium.org/p/project-zero/issues/detail?id=222 (includes PoC)

Relay listener uses HTTP-to-SMB NTLM relaying, where attacker can trigger outbound WebDAV connection
from NT AUTHORITY\SYSTEM process. Windows Defender file scan can be requested by normal user towards UNC path `\\ip\resource`, where protocol used to communicate with UNC depends on providers order. The default Windows configuration will attempt SMB, and then if unavailable, will then attempt WebDAV (is WebClient service is running).

Although normal user cannot start the service by himself, there's a way to trigger service to be started on certain event -- https://www.tiraniddo.dev/2015/03/starting-webclient-service.html 


### Potato (aka Hot potato)

* https://github.com/foxglovesec/Potato
* https://foxglovesecurity.com/2016/01/16/hot-potato/
* https://github.com/Kevin-Robertson/Tater (powershell implementation)

Elaborate technique to privesc based on cross-protocol NTLM reflection/relaying (extension of 'Local WebDAV NTLM Reflection Elevation of Privilege'). Many windows component uses HTTP protocol for periodic tasks such as various updates. Local attacker can gain HTTP MITM position with NBNS spoofing and WPAD configuration file in order to capture outgoing traffic from system component running as NT AUTHORITY\SYSTEM to his listener. Listener would request and relay NTLM authentication on the channel back to the calling host to gain possible RCE via psexec.

NBNS is network name resolving mechanism used when local hosts file and DNS resolution fails. To help DNS resolution to fail, a local attacker can exhaust all UDP ports on local machine. Various system components can be abused on different versions of Windows:

* Windows 7 can be fairly reliably exploited through the Windows Defender update mechanism.
* Windows Server 2008 -- Windows updates
* Windows 8/10/Server 2012 -- “The Windows Server 2012 R2, Windows Server 2012, Windows 8.1, and Windows 8 operating systems include an automatic update mechanism that downloads certificate trust lists (CTLs) on a daily basis.”


### Smashed Potato

* https://github.com/Cn33liz/SmashedPotato

A modification of @breenmachine original Hot Potato Priv Esc Exploit. Mofifications: Merged all .NET assemblies into a single assembly and Compressed this into a Byte[] array, Runs Potato assembly from Memory, Included the InstallUtil AppLocker Bypass method (Credits @SubTee), Made some Automation.


### Rotten Potato

* https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
* https://github.com/foxglovesec/RottenPotato

* based on:
  * Social Engineering The Windows Kernel: Finding And Exploiting Token Handling Vulnerabilities -- https://www.youtube.com/watch?v=QRpfvmMbDMg
  * Issue 325: Windows: DCOM DCE/RPC Local NTLM Reflection Elevation of Privilege -- https://bugs.chromium.org/p/project-zero/issues/detail?id=325&redir=1

Evolution of the 'Hot Potato' technique, where attacker manipulates DCOM object running as NT AUTHORITY\SYSTEM (BITSv1 service) to load other DCOM object from attacker specified DCOM server/service (ATS1). Attacker service (ATS1) will handle incoming request over RPC connection and process the incomming NTLM authentication from the attacked service (BITSv1).

The handling is two-fold, instead of implementing full RPC interface ATS1 relays RPC communication to the local RPC service at 135 (just as templating mechanism for the protocol messages; easier than to full MSRPC impl.) up to the point where NTLM auth takes place and at the same time it performs local (in-memory) NTLM authentication scheme via API `AcquireSecurityHandle` and `AcceptSecurityContext`. When NTLM Challenge is about to be send back to the attacked service (BITSv1), the challenge value and `SecurityHandle` field (Reserved field in the wire frame) is replaced in the packet for the value from the local authentication process/scheme and forwarded to the attacked service.

On the background, windows will finish local authentication of the attacked service (BITSv1) to the attacker thread (??via SecurityHandle reference, most likely because serialized DCOM messages contains required memory pointers) yielding it's NT AUTHORITY\SYSTEM token for impersonation in the attackers process (typicaly via meterpreter incognito), which can be used for privesc.

To perform the attack, an attacker must have the `SeImpersonate` privilege, which is the case of many application server such as IIS and MSSQL.

Vulnerability has been fixed on versions >= Windows 10 1809 & Windows Server 2019 [x1,x2]


### Lonely Potato

* https://decoder.cloud/2017/12/23/the-lonely-potato/

Modification of the RottenPotato to impersonate directly with Windows API without meterpreter and incognito.


### Rotten Potato NG

* https://github.com/breenmachine/RottenPotatoNG

Reimplementation of the Rotten Potato to C++ and changed to spawn privesced cmd directly without meterpreter.


### Juicy Potato

* http://ohpe.it/juicy-potato/

> RottenPotatoNG and its variants leverages the privilege escalation chain based on BITS service having the MiTM listener on 127.0.0.1:6666
> and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where BITS was
> intentionally disabled and port 6666 was taken.> We decided to weaponize RottenPotatoNG: Say hello to Juicy Potato.
> ...
> We discovered that, other than BITS there are a several COM servers we can abuse. They just need to:
> * be instantiable by the current user, normally a “service user” which has impersonation privileges
> * implement the IMarshal interface
> * run as an elevated user (SYSTEM, Administrator, …)
>
> After some testing we obtained and tested an extensive list of interesting CLSID’s on several Windows versions.

Enhanced version of RottenPotatoNG, where same technique can be abused on several COM objects fulfilling needed requirements.
The exploit might work in the environment where BITS service is disabled or port 6666 taken which would make RottenPotatoNG to fail.

The exploit as such has been mitigated by the same DCOM hardening as RottenPotatoNG.

Juicy potato was automated several times:
* https://github.com/klezVirus/CandyPotato
* https://github.com/TsukiCTF/Lovely-Potato


### SpoolSample

* https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory
* https://github.com/leechristensen/SpoolSample

MS-RPRN a printer RPC protocol which allows to setup a notification object on attacked server, which would notify consumer server about new print jobs. During setup an attacked server would create authenticated channel to the consumer server allowing to steal various authentication material.

In domain environment an compromised server (CS) with unconstrained delegation can force domain controller to authenticate to it and TGS used to authenticate to CS will contain a DC host key TGT (unconstrained delegation) allowing attacker to perform DCSync. In case of NTLM authentication it should provide a way to relay the authentication if the DC HOST$ principal is in admin group anywhere.

The same RPC call can be abused otherwise, see `PrintSpoofer` for reference.


### Ghost Potato

* https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html
* https://shenaniganslabs.io/files/impacket-ghostpotato.zip

This exploit/research fills a few-gaps and eventualy abuses the nuances of the mitigations implemented by MS in MS08-68 and MS09-13. Those patches mitigated SMB->SMB relaying and HTTP->SMB respectively, but the details were publicly unknown. Later in 2014 (WebDAV reflection) and 2016 (Hot Potato) was the mitigation bypassed via usage of localhost and local authentication. Ghost Potato shows that there was/is already another bypass technique possible.

The relay mitigations for relaying attacks relied on the lsass.exe challenge cache, where client names were cached along with challenges. Cache was consulted in the final authentication step, where in case of remote reflection the client name did not correspond with the cached challenge and hence the relay attack was mitigated. The bug is present in the cache implementation, which times out stale entries after 300 seconds and eviction function is called on any authentication request.

Patched `ntlmrelayx.py` performing the attack would:

* relay all messages up to AUTHENTICATE message
* waits 300 seconds with open channel
* does second authentication attempt with a bogus password to evict "old" entry from the cache
* finishes the original authentication handshake with cache cleaned.

The initial request trigger from the high-privileged process is not part of the attack and has to be performed manualy (demo from administrators notepad) or by other means.


### RogueWinRM

* https://decoder.cloud/2019/12/06/we-thought-they-were-potatoes-but-they-were-beans/
* https://github.com/antonioCoco/RogueWinRM

After MS fixed the 'OXID resolver' component responsible for guarding RottenPotato technique with restrictions (disable resolver towards any but port tcp/135, disallow remote logon to prevent IMarshaling via remote server), the researchers found that BITS service tries to connect to local WinRM service on startup (with 2 minutes idle shutdown) and also tries to do web NTLM SPNEGO authentication. On systems without WinRM (5985/tcp) service runing, it is possible to start fake winrm service, trigger BITS service start and steal it's token (as long as target user hold SeImpersonatePrivilege).


### PrintSpoofer

* https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
* https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html
* https://github.com/leechristensen/SpoolSample
* https://github.com/itm4n/PrintSpoofer

The point of Potato exploit family is in stealing high-privilege access token from service account user (having SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege) by relaying NTLM authentication from some SYSTEM process to the local authenticator (AcceptSecurityContext loop). So far, the robbed process must be forced to communicate with attacker controlled endpoint with HTTP or TCP RPC handler (local or remote). 

PrintSpoofer abuses the stealing realy with "RCP over NamedPipes" IPC which also allows server to do client impersonation via `CreateNamedPipe() > ConnectNamedPipe() aka Accept() > ImpersonateNamedPipeClient()` in order to allow server act on clients behaf.

This specific exploit uses two things to steal the token:
  * uses `RpcRemoteFindFirstPrinterChangeNotificationEx` to force local SYSTEM service to connect and authenticate to the attacker specified named pipe on the local server. The destination pipe is fixed to `\\HOSTNAME\pipe\spoolss` and normaly occupied by the system service.
  * But the HOSTNAME part of the target can contain '/' which allows to bypass the name validation checks in abused component and normalization used later converts that target string into attacker controllable name `\\HOSTNAME/suffix` to `\\HOSTNAME\suffix\pipe\spoolss`

Attacker thus can run named pipe impersonation listener and force SYSTEM service to connect and authenticate to this pipe and steal SYSTEM impersonation token in the process.

The impersonation can be avoided in the client process/service with the specific flags during `CreateFile()` (aka `OpenFile()`)


### SweetPotato

* https://ethicalchaos.dev/2020/04/13/sweetpotato-local-service-to-system-privesc/
* https://github.com/CCob/SweetPotato

Compound potatoes exploit pack rewritten to C# including combined exploit techniques and other features such as: Rotten/Juicy Potato (BITS and other DCOMs NTLM reflection eops), RogueWinRM, PrintSpoofer, automatically attempts the correct exploit to execute.


### Rogue Potato

* https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
* https://github.com/antonioCoco/RoguePotato

???DCOM uses 'OXID resolver' component in order to locate other DCOM objects AKA the 'OXID resolver' is responsible to resolve the 'bindingstring' presented by the DCOM caller into structs/info allowing attacked DCOM object to actualy fetch the data???. The component was restricted after JuicyPotato, so the source of the remote storage must be at port 135 and if the storage is remote only ANONYMOUS LOGON token can be obtained (so exploit path was effectively closed). The OXID response can contain not only TCP/IP connection information, but the objects can be fetched over various transports including local named pipe.

The attack can be mounted as follows:

* run external TCP redirector from ATTACKEREXTERNAL:135 > ATTACKEDBOX:xxxx
* run fake OXID resolver on ATTACKEDBOX:xxxx
* run local named pipe YYY handler
* trigger BITS service DCOM to load remote object from ATTACKEREXTERNAL, which request in turn ends up at fake OXID resolver
* fake OXID resolver returns crafted response with information that remote object to load can be reachec via local named pipe YYY
* BITS service DCOM connects to local named pipe YYY and allows attacker to get impersonation token for NETWORK SERVICE
* token for NETWORK SERVICE allows to open local RPCSS process and access it's tokens, which list should contain also NT AUTHORITY\SYSTEM impersonation token

Note here that there's a requirement on named pipe name which must be bypassed via slash confusion trick from `itm4n/PrintSpoofer` exploit


### Relaying NTLM authentication over RPC

* https://blog.compass-security.com/2020/05/relaying-ntlm-authentication-over-rpc/
* https://github.com/SecureAuthCorp/impacket/pull/857

Generaly, MSRPC communication does not implement any integrity protection so MITM attacks might apply and relay captured NTLM authentication to (almost) arbitrary RPC target. This work adds RPC MS-TSCH (task scheduler) to the `ntlmrelayx.py`, where SMB->RPC, HTTP->RPC and RPC->RPC (used by various network monitoring tools) relaying tested between W10 a WDC2016.

In order to use the feature, some external connection/credentials must be captured and relayed by the updated tool.

Fixed as CVE-2020-1113 which adds integrity checks on MS-TSCH protocol but not on all RPC services/protocols.


### Generic Potato

* https://micahvandeusen.com/the-power-of-seimpersonation/
* https://github.com/micahvandeusen/GenericPotato

Generic impersonation server/handler using high-level impersonation API instead of relaying messages to AcceptSecurityContext loop. It can be used when attacker:

  * does have and access to service account (account has SeImpersonatePrivilege)
  * all known OS based privesc paths are not working or disabled
    * no printservice -- PrintSpoofer
    * winrm already running -- roguewinrm
    * cannot relay to external machine and bits disabled -- roguepotato
  * but there is a way how to force a high-privileged process to do outbound http request (SSRF) or perform arbitrary filesystem read/wring 
    (open/save file).


### juicy_2

* https://decoder.cloud/2020/05/30/the-impersonation-game/
* https://github.com/decoder-it/juicy_2

Combined JuicyPotato and RoguePotato (external oxid resolver) port for new Windows (aka JuicyPotato for Win10 > 1803 & Win Server 2019) allowing to test misc CLSIDS for posibility to steal an impersonation tokens.


### RemotePotato0

* https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop/
* https://github.com/antonioCoco/RemotePotato0

This potato, instead of stealing token, tries to abuse full cross-protocol relay from RPC->RPC authentication to SMB/HTTP/LDAP (so it not require SeImpersonatePrivilege). Also, it does to target SYSTEM process/service and it's credentials, but rather abuses various CLSIDS (DCOMs) which impersonates user from 'Session 1' (interactive logon) when activated/called from 'Session 0' (remote logon, scheduled task or service context).

The attack is an 'Rogue Potato' extension, where local attacker forces DCOM activator to unmarshal and use `IStorage` object pointing to remote attacker controlled TCP redirector (remote address at tcp/135) where the traffic will be redirected to (or handled directly by) the fake `Oxid resolver`. The resolver returns a string binding for an RPC endpoint under the attacker’s control. The client (CLSID on behaf of the session 1 user) will make an authenticated request to the attacker RPC server, which will relay the authentication to the external protected resource such as SMB, LDAP or HTTP.

If there's and Domain admin logged interactively (Session 1) on the attacked box and the attacker has remote access to the box (session 0), the attacker can relay DA authentication and eg. add new domain admin. The attack is possible only if signing is not required on the target protocols.
