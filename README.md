---
Write-up: Pyramid of Pain - TryHackMe
---

Objective:
The goal of this room was to understand and apply the Pyramid of Pain model to enhance my ability to detect and mitigate various types of indicators of compromise (IOCs) in the context of security operations. This model, introduced by David Bianco, classifies IOCs into different levels based on the ease of detection and the difficulty for an attacker to change or avoid them. The task involved learning how to identify and address IOCs at various levels, from basic hash values to advanced tactics, techniques, and procedures (TTPs).

Pyramid of Pain Overview:
The Pyramid of Pain is a framework that ranks different types of IOCs based on the "pain" they cause an attacker when blocked or detected. The higher the level, the more difficult it is for an attacker to evade detection. The Pyramid consists of the following layers:

Hash Values (Least Painful)

IP Addresses

Domain Names

Host Artifacts

Network Artifacts

Tactics, Techniques, and Procedures (TTPs) (Most Painful)

Step-by-Step Process:
1. Hash Values
The first level of the Pyramid of Pain deals with hash values. Hash values are unique identifiers for files that allow us to detect known malicious files.

Actions Taken:

We analyzed the hash values of suspicious files in the system and compared them against known threat intelligence databases (e.g., VirusTotal) to identify any known malware.

2. IP Addresses
The next level focuses on the detection of malicious IP addresses that might be involved in communications with the attacker’s infrastructure (e.g., Command and Control servers).

Actions Taken:

We analyzed network traffic logs to identify suspicious inbound and outbound connections to known malicious IP addresses.

We cross-referenced these IP addresses with threat intelligence feeds to confirm they were associated with known bad actors.

Outcome:

Blocking or blacklisting malicious IP addresses can disrupt the attacker’s ability to communicate with their infrastructure. However, this method can be easily bypassed by attackers using dynamic IP addresses or IP spoofing techniques.

3. Domain Names
At this level, we learned to identify malicious domain names. Attackers often use domains for phishing attacks, malware delivery, and C2 communications.

Actions Taken:

We examined DNS logs to detect any suspicious domain names used in network traffic.

Used WHOIS lookups and domain reputation checks to verify whether the domain was associated with malicious activity.

Outcome:

Blocking malicious domains can prevent attackers from gaining control over their compromised systems. However, this method can also be bypassed if attackers use domain generation algorithms (DGAs) or frequently change their domains.

4. Host Artifacts
Host artifacts refer to files, processes, and registry keys left behind on the victim’s system by the attacker. This level requires identifying and analyzing system changes caused by an intrusion.

Actions Taken:

We analyzed file system logs, registry entries, and running processes to detect malicious artifacts that may indicate an ongoing attack.

Tools like Sysmon and Windows Event Logs were used to monitor and detect unusual behavior.

Outcome:

Detecting host artifacts is an effective method for identifying attackers on the system, but it can be challenging if the attacker uses rootkits or other methods to hide their presence.

5. Network Artifacts
Network artifacts involve the analysis of traffic patterns, protocol usage, and other network-level traces left behind by the attacker. Identifying unusual network activity can be crucial in detecting an ongoing attack.

Actions Taken:

We analyzed network traffic captures using tools like Wireshark and tcpdump to detect suspicious behavior such as unusual ports or protocols being used.

Looked for patterns indicative of lateral movement or exfiltration.

Outcome:

Network artifact analysis can help detect attacks that may not have been identified at the host level. However, attackers can evade detection by using encryption or tunneling protocols.

6. Tactics, Techniques, and Procedures (TTPs)
At the highest level of the Pyramid of Pain, we learned to identify the attacker’s Tactics, Techniques, and Procedures (TTPs). TTPs represent the behavior and methodology used by attackers to carry out their operations.

Actions Taken:

We referenced the MITRE ATT&CK framework to map observed behaviors to specific TTPs.

By analyzing network traffic and host activity, we identified the tactics and techniques being used by the attacker, such as credential dumping or lateral movement.

Outcome:

Identifying TTPs gives us the most comprehensive understanding of the attacker’s operations. While detecting TTPs requires more advanced skills and resources, it provides long-term defense by helping organizations develop proactive defenses against specific attack methods.

Conclusion:
The Pyramid of Pain model offers a clear way to understand the relative difficulty of detecting and mitigating different IOCs. As a SOC Analyst Level 1, learning to prioritize these IOCs based on their impact is essential for effective threat detection and incident response. The higher up the Pyramid, the more complex and painful the detection process is for attackers. Therefore, focusing on TTPs provides the most valuable insights into an attacker’s behavior, but it requires continuous monitoring and advanced analysis.

Key Takeaways:
Hash values are effective but can be easily bypassed.

IP addresses and domain names are useful but not foolproof due to attackers’ ability to change them frequently.

Host and network artifacts can help detect an attack but may be hidden using advanced techniques.

TTPs offer the best defense strategy by providing insight into the attacker’s behavior, but they require advanced skills and more resources to track.

This exercise gave me a deeper understanding of how different IOCs affect the detection process and how SOC Analysts can use these insights to better protect organizations from evolving threats. I look forward to applying these concepts in real-world security operations.

Dengan write-up ini, kamu bisa mendokumentasikan apa yang sudah kamu pelajari secara sistematis dan menjadikannya bagian dari portofolio GitHub atau LinkedIn kamu.







You said:
btw repository namenya apa ya


ChatGPT said:
Nama repository yang bagus harus mencerminkan isinya dengan jelas. Beberapa opsi untuk repository write-up TryHackMe kamu:

SOC-Level1-Writeups → Menunjukkan bahwa ini berisi catatan dari perjalananmu sebagai SOC Analyst Level 1.

TryHackMe-Writeups → Simpel dan langsung ke point, jika kamu hanya ingin fokus pada TryHackMe.

SOC-Analyst-Journey → Cocok jika kamu ingin dokumentasi jangka panjang untuk perjalananmu sebagai SOC Analyst.

Threat-Detection-Notes → Lebih spesifik jika fokus utama adalah analisis ancaman dan deteksi serangan.

BlueTeam-Writeups → Jika kamu ingin menonjolkan aspek defensive security dalam SOC.

Kalau tujuan utamamu buat portofolio SOC Analyst Level 1, SOC-Level1-Writeups atau **SOC-







You said:
maksudnya buat pyramid of pain tryhackme


ChatGPT said:
Kalau khusus untuk Pyramid of Pain di TryHackMe, nama repository yang cocok bisa:

pyramid-of-pain-writeup → Langsung jelas bahwa ini tentang Pyramid of Pain.

THM-PyramidOfPain → Menunjukkan ini dari TryHackMe.

ioc-detection-pyramid → Jika ingin fokus pada analisis IOC berdasarkan Pyramid of Pain.

SOC-IoC-Analysis → Lebih luas tapi masih relevan dengan SOC Analyst dan Pyramid of Pain.

Kalau ini bagian dari kumpulan write-up SOC Analyst Level 1, bisa juga dimasukkan dalam SOC-Level1-Writeups sebagai sub-folder atau file terpisah.

Mau buat repo terpisah atau gabung ke repo besar?







You said:
descriptionnya apa


ChatGPT said:
Berikut adalah contoh description untuk repository Pyramid of Pain di TryHackMe:

Repository Description:

This repository contains my write-up and analysis of the Pyramid of Pain room on TryHackMe. The Pyramid of Pain model is a framework used to understand and classify Indicators of Compromise (IOCs) based on their difficulty for attackers to evade and the level of detection they require. In this room, I learned about various types of IOCs including:

Hash values

IP addresses

Domain names

Host artifacts

Network artifacts

Tactics, Techniques, and Procedures (TTPs)

This write-up includes detailed steps and explanations for each IOC, along with methods for detecting and mitigating them in the context of Security Operations Center (SOC) tasks. Through this, I gained a deeper understanding of how different types of IOCs impact threat detection and response. This is a key part of my learning journey towards becoming a proficient SOC Analyst.

Hash-based detection is quick and effective but can easily be bypassed by attackers who alter the file (e.g., through packing or obfuscation).

Outcome:

While hash value analysis can quickly identify malicious files, it’s important to note that attackers can easily modify files to avoid detection by altering their hash.
