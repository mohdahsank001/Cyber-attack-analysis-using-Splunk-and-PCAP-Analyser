# Cyber-attack-analysis using SPLUNK and PCAP Analyser
In this project I have used SPLUNK to analyse the given PCAP dataset to detect Cyber attacks including other threats and provide possible solutions.


 


Cyber-attack threat detection in the Network Traffic Data and feasible countermeasures

       Mohammed Ahsan Kollathodi
               CIS, University of Melbourne, Melbourne, Australia. mhdahsan2000@gmail.com
Abstract. 

In today’s world Internet have become ubiquitous and the number of users are on the rise on day to day basis. With the rise in user data and network usage there exists a greater responsibility to protect the network from cyber threats including malware attacks where the user data would be accessed and manipulated by unauthorized users involving hackers. In such a circumstance, quite often Splunk can be a very powerful analytic tool that can help detect these cyber security threats and attacks. The very purpose of this project was to analyze and evaluate the network traffic using Splunk as a tool for the given dataset and to assess the many different consequences and countermeasures that can be deployed in the real world for cyber threats and attacks.
Keywords. Cyber-threat detection, Splunk, malware analysis, network traffic evaluation.
1.	INTRODUCTION
Technology has become quickly evolving in a world propelled by social networks, online transactions, cloud computing and Machine Learning. However, with the technological evolution and changes, this results in an increase in the rate of cybercrimes which would constantly evolve and create new forms of attacks which would enable the attackers to enter and penetrate even the most advanced or well-controlled environments, and results in higher damage and eventually remain invisible. But this is something that can be followed and detected using appropriate tools. Splunk can be very powerful machine learning and analytics tools with advanced analytics capabilities that can help to detect potential security violations and security threats that would exist in  a given network as we would analyze the network traffic data. Through this project I have initially captured the network traffic through WireShark into a PCAP file and then did analysis leveraging the analytic capabilities of Splunk.[1] 

Methodology 

Ingesting the pcap. file into Splunk 

Splunk enterprise software and PCAP Analyzer application were setup in the local machine. The .pcap file which was provided for this analysis was ingested in the software by creating the file location in the Windows Operating system and placing the file inside it. [2]

PCAPConversion converted the pcap file into csv and created a new file called as inside the folder “PCAPcsv” and also “PCAPConverted”.  Once the csv file was created, it was ingested into Splunk as .csv file.

Initially both Splunk Software and PCAP Analyzer applications were installed initially. Analysing the data using Splunk, validating the evidences of the following attack scenarios contained in the given pcap file. Splunk Search or PCAP Analyzer Dashboard can be deployed where applicable, a new field extraction was required when using the Splunk Search. 

Overview of the Dataset 

The dataset would represent the network traffic comprised of 91,713 number of events, where the start date event was around 2021-02-16 12:43:03.481 and the last event date was around 2021-08-13 15:27:58.000 which would represent around 256,482 minutes of network traffic data. 

This was found out using the following query (as in Figure 1.)

 

          Figure 1. Splunk command to Search for the start and finish time of the events (in a Network Traffic.)

  
Start and end date and time for the network traffic (as shown in Figure 2.)

 

Figure 2. The results for above Splunk query with the start and end dates for the network traffic.

 

Figure 3. Searching for start and end times of search in Splunk.

 

Figure 4. Start and end time results in SPLUK.

That’s a duration on 178 days, 2 hours, 41 minutes, and 25 seconds or that is the same as 5 months, 28 days, 2 hours, 41 minutes and 25 seconds. (it’s the same as 4274 hours or 256,481 minutes – rounded down value.)

High level view of the dataset 

An explanatory analysis on the data was done using basic features of Splunk and the graphical views. Once the data was analysed using “Top Talker Overview” feature of PCAP Analyzer, the summary of data could be obtained with all of the top values in each category. As the data was analysed, It could be seen that the most widely used protocol is the TCP which accounts for nearly 94 percent of all events which was followed by TLS (2 percent) and SMTP(1.335 percent) and HTTP(0.853 percent), and SSL (0.12 percent) as shown in Figure 5. 

 
Figure 5. Top protocols (Packets)












Figure 6. Top Conversation (Packets)
				
 

Figure 7. Top Sender (Packets)

 

Figure 8. Top Receiver(Packets)

 

Figure 9. Top Ports (Packets)


 

Figure 10. Top MAC (Packets)


 

Figure 11. Top Protocols (Sum Bytes)

The Above figure (as shown in Figure 11.) shows that there might be a pattern of attack for the time period between 12:50 and 12:55 PM. And also, this could be pre-longed between the period 12:55 PM and 1:00 PM. The Protocols with the highest traffic during that time period would correspond to TCP, TLS, SSL and HTTP protocols for which a peak of 1.5 GB of traffic was found. 

 

Figure 12. Top Conversation (Sum Bytes)

 

Figure 13. Top Sender (Sum Bytes)
 
 

Figure 14. Top Receiver (Sum Bytes)

 

Figure 15. Top Destination Ports (Sum Bytes)

 

Figure 16. Top VLAN’s (Sum Bytes)

 

Figure 17. Top MAC (Sum Bytes)

Attacks and Detection

To Calculate the number of email addresses that have been targeted by spam by searching by protocol with the key word of “RCPT”, the following command can be deployed as shown below. 

sourcetype="pcap:csv" source="/Applications/Splunk/etc/apps/SplunkForPCAP/PCAPcsv/traffic_capture.pcap.csv" protocol=SMTP AND info = "*RCPT*"


 

Figure 18 - The search query deployed in SPLUNK to find the SPAM attack


The results consisted of around 220 events, each of the result consisting of an email address in the “info” field. Next, the following query could be executed to obtain the IP address of the attacker consisting of the start and end time of the attack. 

 

Figure 19 – Search the SPAM attack.

 

Figure 20 - Searching for the IP address of the attacker.

 

Figure 21 - IP address of the attacker with start and end time of the attack.


Field Extraction: To find the targeted emails, an investigation will have to be done on the email recipients of the SPAM attack. During a SPAM Attack the targeted emails would become endangered to be infected. If that’s the case, the malicious emails would be sent on their behalf [3]. By adapting the “PCAP analyser Extract New Fields” functionality this can be achieved along with the regex functionality (by creating new regular expression) “(?<email>[\w\d\.\-\_]+\@[\w\d\.\-\_]+\.[\w\d]+)”,The emails addresses of the SPAM attack can be searched using the following command as shown below. 

sourcetype="pcap:csv" source="/Applications/Splunk/etc/apps/SplunkForPCAP/PCAPcsv/traffic_capture.pcap.csv" protocol = "SMTP" AND info = "*RCPT*"| top limit=20000 email | dedup email | table email


 

Figure 22 – Creating a new regular expression to create a new field for extracting email. 

 
Figure 23 – Selecting fields to extract email. 


 

Figure 24 – Inputting the Regular Expression to extract emails in Splunk.


 

Figure 25 - Table view of the Targeted emails. (To see all of the Target emails see Appendix 1.)


 

Figure 26 – List view of targeted emails. 


 

Figure 27 – List view of targeted emails. 


 

Figure 28 – Search to find the targeted email in SPLUNK.

 

Figure 29 – Splunk Command to find the targeted email.

The Above figures and text consist of the search queries that were used to investigate the victims or the recipients of the SPAM Attack and also the results in a table view. To search for the first and last recipient of the SPAM attack with their timestamps, we would use the following search query. This would also return the IP addresses of the servers targeted. 


 

  Figure 30 - Searching for the first and last recipient of the SPAM Attack in SPLUNK.



 

Figure 31 - The result showing the first and last recipient of the SPAM Attack in SPLUNK.

 

Figure 32 – Searching for IP addresses that are targeted by the SPAM attack in SPLUNK. 

 

Figure 33 – Results showing the IP addresses that are targeted by the SPAM attack with the VICTIM and ATTACKER with begin and finish time stamp. 


Finally, we could notice that most of the requests were directed to the port 65500. 


Attack Narrative

 At 12:54:12.059 the attacker 249.56.230.66 made the first attempt to connect to “smtp.aol.com” via the DNS protocol which received a response from the DNS server, and the IP address corresponding to 205.188.186.137 address that would consist of the first set of victims. Then the bot strived to authenticate in the email system which was obtained by the time “12:55:54.773”.

Following this event at “13:00:11.838” an email was sent to the first victim “yuwi86@yahoo.com” using the SMTP protocol. This same process was repeated for many IP Addresses in total, with a total of 110 email events distributed unevenly among the addresses. Most of the transactions occurred at the port 65500.  
 
 

Figure 34 – Finding the emails which are target emails SPAM Attack. 
Essentially all of the mail transfer would happen through the SMTP or the Simple mail transfer protocol [7]. It is an internet standard communication protocol for the electronic mail transmission, Mail servers and the other message transfer agents which would send and receive mail messages. Once the log was analyzed, It was found the “RCPT TO” command which would specify the recipient or it includes a destination mail box or a forward path.
 

Figure 35 - Finding all of the transactions through the SMTP protocol.   

Once the above results were obtained in the output, I could search for the keyword RCPT TO, to get the other details like Attacker and victim IP addresses and also the protocol.

The URI strings were investigated in the POST method. The URI string would be subject to vulnerabilities and the attacker might use it to gain access to the Application layer by the means of Malicious code[]. I had to create to a new field for extraction called as URI with the regular expression  “^(?:[^ \n]* ){8}(?P<URI>[^ ]+)”. 

 

Figure 36 - Regular expression (Regex) for extracting the URI. 


 

Figure 37 - Regular expression (Regex) for extracting the URI within SPLUNK.


Using the regular expression above to create a new field called as URI I could find the top values as following, (As shown in Figure 44.)

 

				  Figure 38 - Top Values for URI 

Once analysing the above data, it could be concluded that the URI string for the malware attack would be associated with the following string as following which is “/ajax.php”. 

 

Figure 39 - URI string for the malware attack with occurrence or count.

Clearly the attack was through using ajax.php file. Malicious software could utilize HTTP protocol for the communication purposes particularly through different parts of the requests like Uniform resource Identifier (URI).[3]


 

    	 		Figure 40 - Searching for URI in SPLUNK.

 

				Figure 41 - URI Search Command in SPLUNK.

 

			Figure 42 - Top Values for the URI search within given PCAP file. 

 

Figure 43 - Creating a new Regular expression to find URI in the given PCAP file

 

Figure 44 - Regular expression to find the URI.

TCP SYN scan is one of the most common techniques for port scan. It’s another form of TCP Scanning.  It’s called as half open scanning as a full TCP connection is never initiated. As the target port is open, it would reply with a SYN-ACK packet. To identify the TCP SYN scan of a particular IP corresponding to 249.56.230.66, the following command as below can be deployed (As shown in Figure 51.)

 

Figure 45 – Splunk Search for TCP SYN scan from IP 249.56.230.66

 

Figure 46 – Search Command for TCP SYN scan from IP 249.56.230.66

 

Figure 47 –Splunk Search to obtain the statistics of packets sent each minute.

 

Figure 48 – Modified Splunk Search to obtain the statistics of packets sent each minute


 

Figure 49 - Searching for start and end time for the TCP Port scan.


 

Figure 50 - Start and end time of the TCP Port scan.

Consequences 

The CIA triad is a security model that assists to evaluate the IT security of a system. The following consequences could be identified by taking into account the attack’s potential impacts over confidentiality, integrity and availability (CIA triad) of the victim and the network.[6]

Preserving confidentially of the personal data and privacy is very important in today’s world and is it is mostly reliant on being able to explain and mandate some levels for information. Integrity is a crucial part of the CIA triad and it is optimized to protect the data from deletion or modification by unauthorized party and it would make certain that only authorized personnel would make the required changes. While Availability would make certain that the computing resources would have adequate architecture setup that are particularly designed to enhance availability. [15]

For the Command and control (HTTP and IRC based) type of attacks, As the attacker connects and controls the channel, they would be allowed to access the targeted system remotely, which might affect the confidentiality of data as this attack can be launched for espionage. Moreover, the attacker might influence the data at their will, violating the integrity principle and also, they might turn the victim’s system down by affecting the accessibility. [9]

In the case of, Malware (HTTP and URI based) type of attacks, Once the malware enters the system of victim users, it might compromise their confidentiality as the attackers will be able to gain access and steal the user data and user’s privacy could be lost. In addition to it, the victims might also be subjected to spying as the malware might consist of spyware again compromising the confidentiality of users. Moreover, once the malware enters the victim computer it could bring down the whole system through infectious programs hence affecting the availability of the entire system. Additionally, through malware hackers might be able gain unauthorized access and also delete important applications and firmware hence affecting the Integrity of the system. [6][16]

 The spam attack can be correlated with the impacts on availability in two different ways. Most Importantly, the attacker might dismantle the resources allocated to the targeted server with a high amount of spam emails, which might saturate the bandwidth of the network. In addition to it, from a user’s perspective, all of the targeted email recipients might recognize a loss in the availability of their email services, thus not being able to receive anything apart from spam emails. [8]

Patterns of Attack

The successive patterns of attack were obtained from the previous analysis in line with the main features employed to find the evidence of the attacks, in addition to the extracted fields could assist to learn more about the patterns of the attack. The particular values of each feature can be recognised in each of the attack narrative section. In addition to it, the DDoS attack detection is explained primarily with respect to the Smart detection system.[6]

Command and Control: src_ip + dst_ip + dst_port + protocol + URI 
Malware: src_ip +dst_ip+ dst_port + protocol + URI
SPAM: src_ip + dst_port + protocol 
IRC: src_ip + dst_port + protocol
DDoS Attack: src_ip + dst_ip+src_port+ dst_port+ protocol 

Through this experiment, it could be concluded that to detect a distributed denial of service attack, source and destination ip addresses, source and destination ports and the protocol are all required. 
An Ideal detection to evade such threats would be a smart detection system. A Smart Detection is created to combat DDoS attacks on the Internet in a modern collaborative way. In this approach, the system would accumulate the network traffic samples and would classify them. In this method, the normal traffic and the DDoS signatures would be extracted, labelled and then stored in the database. Here the attack notification messages are distributed using a cloud platform for appropriate use by traffic control protection systems. The Signature dataset or the SDS would be made using feature selection techniques. And finally the most precise algorithm would be selected, trained and loaded into the traffic classification system.
The central part of the detection System would consist of a Signature Dataset(SDS) and a machine learning Algorithm(MLA). Initially, the normal traffic and DDoS signatures were extracted, labelled and stored in a database. Signature Dataset was then made using feature selection techniques. Finally, the most accurate algorithm was selected, trained and loaded into the traffic classification system. The architecture of the detection system was devised to work with samples of network traffic provided by industrial standard traffic sampling protocols, composed from network devices. The unlabelled samples are collected and assembled in flow tables in the receive buffer. Thus, when the table length is greater than or equal to the reference value, they are granted to the classifier responsible for labelling them. If the flow table expires, it may be processed one more time. The existence of minor flow tables is higher at lower sampling rates or under certain forms of DoS attacks, and example for this would be the SYN flood attacks.  While detecting the DDoS Attacks, particularly in smart detection the (FlowID) during each cycle of detection process, the traffic samples are received and stored in a flow table. For each flow a unique identifier is calculated based on the five tuple structure (src_IP, dst_IP, src_Port,dst_Port and transport protocol.) [8]
 
Figure 51 - The operation scenario overview of the Smart Detection System. (image source: F. S. De Lima Filho, F. A. F. Silveira, A. De Medeiros Brito Junior, G. Vargas-Solar, and L. F. Silveira, “Smart Detection: An Online Approach for DoS/DDoS Attack Detection Using Machine Learning,” Secur. Commun. Networks, vol. 2019).[8]
 
Figure 52 -  Smart Detection System overview. (image source : F. S. De Lima Filho, F. A. F. Silveira, A. De Medeiros Brito Junior, G. Vargas-Solar, and L. F. Silveira, “Smart Detection: An Online Approach for DoS/DDoS Attack Detection Using Machine Learning,” Secur. Commun. Networks, vol. 2019).[8]
Other sources of data could be gathered if more data was available. For C2 attack, either HTTP or IRC based, packet features could be used for detecting the attack, such as “length in bytes, number of packets, flow duration” and “average bytes per packet” [5]. For SPAM attack, focus could be set on the professional words of the email, the header’s “hour of day”, the “number of all URLs” and payload features [3]. 




Countermeasures 

Countermeasures		SPAM	IRC	DDoS Attack
Access management system			X	
Information of encryption[6]			X	X
Approval checkpoints[6]			X	X
Scheduled updates[6]		X	X	X
Incident management system[6]		X	X	X
Disaster recovery plan[6]		X	X	X
Web proxy[6]			X	X
DNS Security[6]			X	X
IDS[6]		X	X	X
IPS[6]		X	X	X
HIPS[6]		X	X	X
Email Security System[6]		X		
Antivirus System[6]		X		X
SETA Program[5][6]		X	X	
Honeypot/Honeynet[6]		X	X	X
SMTP Proxy[14]		X		X
History-based IP filtering (HIP)[14]				X
Secure Overlay Services (SOS)[14]				X
Load Balancing[14]				X
Throttling[14]				X
Source network Mechanisms[14] 				X
^CentreTrack[14]				X
Egress filtering[14]				X
ICMP TraceBack[14]				X
Link Testing TraceBack[14]				X
  
^centreTrack is an architecture proposed by Stone, which creates an overlay network of IP tunnels by linking all the edge routers to the central tracking routers, and all suspicious traffic is rerouted from the edge routers to the tracking routers. [5][6][14]	

Conclusion 

Once analyzing the pattern of the attack, it could be seen to be very similar to that of botnet architecture, comprising of a network or infected machines that can be remotely managed by the Command-and-Control Channels.[6] In addition to it, we could consider that the botnet would use both IRC and HTTP channels establishing communication through at least one known server. Once connected the botmaster was able to infect the targeted machines with a malicious payload. [4]

Once infected, 249.56.230.66 (bot) was organised to initiate the botnet propagation. The bot can be utilised to send commands to be run by the victims (IRC which is push based) and to dispatch requests for victims to download malware (HTTP- pull based) so as to recruit additional bots. All of these attacks can be associated to the Command-and-Control section of the Cyber Kill Chain (CKC), where the intruders might gain access and manipulate the victim’s system remotely [5][6]. 

The Bots can also be employed for developing a massive SPAM method [4].  In the case of SPAM attack, the bot was employed to dispatch uninvited email messages to a very big group of recipients as a campaign to gain profits and or to create additional bots. All of these attacks can be associated with the Command-and-Control section of the Cyber Kill Chain (CKC) where the intruders might obtain access and exploit the victim’s system remotely [5].

Moreover, we could also conclude that the botnet attack could also have employed for flooding DDoS attack. A distributed denial of service attack (DDoS) attack is commonly considered as a crucial threat for the existing Internet due to its ability to produce a large volume of unwanted traffic. It is quite often a challenge to detect and respond to the DDoS attacks due to the big and compound network environments. An HTTP flooding DDoS attack would utilize what appears to be legitimate HTTP GET or POST requests to attack a web server application. These flooding attacks quite often depend on a botnet which is a collection of Internet-connected computers that have been maliciously allocated through the use of malware. [10] 

Finally, It could be observed that the analysis was restricted by the amount of data as there could be additional findings that could be put together from further sources of attack. 

References 
[1] A. Bendovschi, “Cyber-Attacks – Trends, Patterns and Security Countermeasures,” Procedia Econ. Financ., vol. 28, no. April, pp. 24–31, 2015.
[2] J. Stearley, S. Corwell, and K. Lord, “Bridging the gaps: joining information sources with splunk,” Proc. 2010 Work. Manag. Syst. via log Anal. Mach. Learn. Tech., p. 8, 2010.
[3] X. Gui, J. Liu, M. Chi, C. Li and Z. Lei, "Analysis of malware application based on massive network traffic," in China Communications, vol. 13, no. 8, pp. 209-221, Aug. 2016, doi: 10.1109/CC.2016.7563724.
[3] H. Drucker, D. Wu, and V. N. Vapnik, “Support vector machines for spam categorization,” IEEE Trans. Neural Networks, vol. 10, no. 5, pp. 1048–1054, 1999.
[4] splunkbase, 'PCAP Analyzer for Splunk', 2020. [Online]. Available: https://splunkbase.splunk.com/app/2748/     [Accessed: 20- Aug- 2021].

[5] Y. Xiao, J. Liu, K. Ghaboosi, H. Deng, and J. Zhang, “Botnet: Classification, attacks,   detection, tracing, and preventive measures,” Eurasip J. Wirel. Commun. Netw., vol. 2009, 2009.

[6] Sarah Monazam Erfani, Yi.Han 2020, Teaching Sessions, COMP90073 Security Analytics,  Teaching materials. Available : Online [Accessed 19-Aug-2021].
[7] R. P. Lopes and J. L. Oliveira, “A uniform resource identifier scheme for SNMP,” 2002 IEEE Work. IP Oper. Manag. IPOM 2002, vol. 00, no. C, pp. 85–90, 2002.
[8] F. S. De Lima Filho, F. A. F. Silveira, A. De Medeiros Brito Junior, G. Vargas-Solar, and L. F. Silveira, “Smart Detection: An Online Approach for DoS/DDoS Attack Detection Using Machine Learning,” Secur. Commun. Networks, vol. 2019.
[9] M. Ashtiani and M. Abdollahi Azgomi, “A distributed simulation framework for modeling cyber attacks and the evaluation of security measures,” Simulation, vol. 90, no. 9, pp. 1071–1102, 2014.
[10] I. GHAFIR, M. HAMMOUDEH, and V. PRENOSIL, “Botnet Command and Control Traffic Detection Challenges A Correlation based Solution,” no. April, pp. 1–5, 2016.
[11] K. Thakur, T. Hayajneh, and J. Tseng, “Cyber Security in Social Media: Challenges and the Way Forward,” IT Prof., vol. 21, no. 2, pp. 41–49, 2019. 
[12] K. Zeb, O. Baig, and M. K. Asif, “DDoS attacks and countermeasures in cyberspace,” 2015 2nd World Symp. Web Appl. Networking, WSWAN 2015, 2015. 
[13]  P. Ritchie, “The security risks of AJAX/web 2.0 applications,” Netw. Secur., vol. 2007, no. 3, pp. 4–8, 2007.
[14] C. Douligeris and A. Mitrokotsa, “DDoS attacks and defense mechanisms: Classification and state-of-the-art,” Comput. Networks, vol. 44, no. 5, pp. 643–666, 2004. 
[15] Forcepoint, ‘What is CIA Triad ?’', 2021. [Online]. Available: https://www.forcepoint.com/cyber-edu/cia-triad [Accessed: 20- Aug- 2021].

[16] T. F. Stafford and A. Urbaczewski, “Spyware: The Ghost in the Machine,” Commun. Assoc. Inf. Syst., vol. 14, no. September, 2004.


Appendix 1 

1.	List of all emails that were the victims of the SPAM attack.

yuwi86@yahoo.com

yiti007@gmail.com

wilsonjason16@yahoo.com

wiest@reed.edu

viper84z@gmail.com

vietdam@yahoo.com

vbshadow14@yahoo.com

user2002sg@yahoo.com

tvandeerhaa@aol.com

topraise@yahoo.com

tlnlvs2k3@comcast.net

timstjhn@yahoo.com

thomas117711@aol.com

sunjie170779916@sina.com

stud4fun80@yahoo.com

strongrthanb4@yahoo.com

socal81878@yahoo.com

snray1947@gmail.com

skipakar@comcast.net

simmut@yahoo.com

sildu@gmx.de

shoaibjaved_khan@hotmail.com

scoutmasterbrian@yahoo.com

santeefive@cox.net

rmaestas27@gmail.com

rlounsberry@charter.net

rick.p@tiscali.co.uk

rhherbe@gmail.com

rbindi194513@yahoo.com

pturek9211@aol.com

prestona1111@gmail.com

pierre_edwards@yahoo.com

philip@flowercard.net

peter@geomedia.tv

obiewhitmore@yahoo.com

neboopacic@yahoo.com

mtpatel2565@gmail.com

mjgtyp@yahoo.com

michael@yourhome.org

mesalocon480@yahoo.com

mcaruso1@nyc.rr.com

maxsheffield@sbcglobal.net

martinjerry54@yahoo.com

madhushanka02@gmail.com

luccy_porter@yahoo.com

lovetoplaywithboth@gmail.com

lloydbryandperez@yahoo.com

lilironman007@aol.com

legofan65@yahoo.com

kwolpink@yahoo.com

klo8905@yahoo.com

kkjohnson8791@yahoo.com

jwktm29@yahoo.com

joyness08@yahoo.com

josecortez1794@yahoo.com

jorixnava@yahoo.com

joecparkcity@aol.com

jizzle200928@yahoo.com

jemambo@gmail.com

jcyran@iupui.edu

james_mccauley02@yahoo.com

jake_wall@yahoo.com.au

iqbalnasir25@gmail.com

incasoy98@yahoo.com

ilikepandoraaa@yahoo.com

igmanskiraj@aol.com

hmgfirestar@yahoo.com

hellsdemonhimanshu@gmail.com

hartmutpietsch@aol.com

greenchilly_chavi@ymail.com

gorgamaulana@yahoo.com

glenpark4393@aol.com

gca100@hotmail.com

funpantyhose@yahoo.com

flemingmsub@yahoo.com

eslam_bend@yahoo.com

emad_khmees@yahoo.com

drapper@teamcmp.com

dominicbobo@ymail.com

dj198979@aol.com

dexx211mi@sbcglobal.net

dewayne_taylor23@yahoo.com

denise.pilater@laposte.net

dawnarnold71@cox.net

darkwolf673@yahoo.com

daddybbad@aol.com

cltm1@aol.com

chungchihung1982@gmail.com

chancebarr13@yahoo.com

ceg_c11@yahoo.com

carycumber@yahoo.com

bricjoran394@aol.com

briaeros19@yahoo.fr

brendagoetz@rogers.com

borii@live.com

boostedeclipse11@yahoo.com

blueflame4509@yahoo.com

bloom814@yahoo.com

bigadaniel@aol.com

barathi@gmail.com

bamkristina1@yahoo.com

as_cracknell@btopenworld.com

ankuramyadav@yahoo.com

andreablair81@gmail.com

amara.amara2009@gmail.com

amabeamer@aol.com

alexis_ashton17@yahoo.com

aftabemohabat@yahoo.com

aden4deman@yahoo.com

abdelmadjid64@yahoo.com




![image](https://user-images.githubusercontent.com/67852641/154593143-29456bae-f81a-4afd-9d13-32730bf4185d.png)


