---
title: Verification Clarification
description: NahamCon2025 CTF Malware Reversing Challenge
date: 2025-09-13
tldr: A fake "captcha.zip" verification page places a PowerShell download-and-run command into your clipboard; the payload fetches a staged, multi-encoded PowerShell loader via a DNS TXT lookup - decode the stages (Base64 → Inflate → string fixes) to reveal the final payload and flag.
draft: false 
tags: malware-analysis
toc: false 
---

# Challenge Description

**Author:** @resume  

**Difficulty:** 🟡 Medium



One of our users received an unexpected email asking them to complete extra verification in order to download a zip file, but they weren’t expecting to receive any files.

Your task is to investigate the verification **link** provided in the email and determine if it’s suspicious or potentially malicious (“phishy”).

> **Note:** If the verification link doesn’t respond when you visit it directly, try accessing it using a different method or tool. The challenge is functional, and you should receive a response.

[captcha.zip](https://captcha.zip/)

## Solution
The challenge begins by accessing the provided [captcha.zip](https://captcha.zip/) URL, which actually points to a web page rather than a ZIP file.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/1.png?raw=true)

{{< /callout >}}


This challenge presents a fake CAPTCHA page designed to trick the user into copying a malicious command to their clipboard, with the goal of getting them to unknowingly execute it on their own machine. This behavior is confirmed when clicking the **"I'm not a robot"** button, which follows the same pattern by placing a malicious command in the clipboard, attempting to deceive the user into running it locally.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/2.png?raw=true)

{{< /callout >}}

When pasting the clipboard contents into PowerShell, the malicious payload becomes visible. The payload uses `irm` (Invoke-RestMethod) to download a script from the `/verify` endpoint, then executes it directly in memory using `iex` (Invoke-Expression). This technique allows the script to run without being saved to disk, making it harder to detect.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/3.png?raw=true)

{{< /callout >}}

In this case, to avoid executing the payload in memory and instead inspect the next stage, the `iex` command is removed before running the script. This allows us to observe the subsequent payload stage without triggering execution.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/4.png?raw=true)

{{< /callout >}}

The next stage reveals a variable encoded in Base64, which is decoded and executed in a new shell context using the `ShellExecute` command. Decoding this Base64 payload with CyberChef shows that it queries the host `5gmlw.pyrchdata.com` for a TXT DNS record.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/5.png?raw=true)

{{< /callout >}}

In this stage, I used two methods to retrieve the TXT DNS record for `5gmlw.pyrchdata.com`.

First, I ran the following PowerShell command:

```powershell
nslookup -type=TXT 5gmlw.pyrchdata.com 8.8.8.8
```

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/6_1.png?raw=true)

{{< /callout >}}

Second, I used the online tool [MXToolbox](https://mxtoolbox.com/) to perform the same query.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/6_2.png?raw=true)

{{< /callout >}}

Choosing between these methods depends on personal preference. I used both to compare outputs and to explore different tools and approaches.

The TXT record contains another Base64-encoded string, which likely represents the next stage of the malware payload.

When decoding the Base64 string from the TXT DNS record, the next stage of the payload becomes visible.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/7.png?raw=true)

{{< /callout >}}

The payload is a PowerShell command that:

1. **Decodes a Base64 string:**  
   The embedded Base64-encoded string is converted into a byte array using `[System.Convert]::FromBase64String()`.

2. **Decompresses the data:**  
   The byte array is then decompressed using the DEFLATE algorithm through `System.IO.Compression.DeflateStream`.

3. **Reads the decompressed script:**  
   A `System.IO.StreamReader` reads the decompressed data as ASCII text, revealing the next stage of the payload.

4. **Executes the script in memory:**  
   The final part dynamically constructs and executes the script in memory, likely using `Invoke-Expression` (`iex`) or a similar method to avoid writing to disk.

To decode the Base64-encoded payload, I used CyberChef with a **Base64 decode** followed by a **Raw Inflate** operation to decompress the data.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/8.png?raw=true)

{{< /callout >}}

Looking at the decoded result, only some parts appeared meaningful. Upon closer inspection, I noticed that certain words were reversed. For example, `;metsyS gn'+'isu` corresponds to `using System;`, and `;secivreS'+'poretn'+'I.emitnuR.metsyS'+' gnisu` translates to `using System.Runtime.InteropServices;`.

With this in mind, I applied a **reverse** operation in CyberChef to restore the reversed strings into a readable format.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/9.png?raw=true)

{{< /callout >}}

After reversing the strings, the payload started to make more sense and became easier to read. While analyzing the script further, I noticed it contained another Base64-like string, but attempting to decode it directly failed.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/10.png?raw=true)

{{< /callout >}}

On closer inspection, I realized the string wasn’t valid Base64 as-is because the script performs a replacement operation, replacing every occurrence of `S6R` with `[CHAR]34`, which represents a double quote (`"` character). This behavior can be seen in the following line:

```powershell
-REPLACE 'S6R', [CHAR]34
```
By removing the `S6R` placeholders from the Base64 string, it transforms into a valid Base64-encoded string. After cleaning it up, I was able to successfully decode it, which revealed the final payload and the flag.

{{< callout type="customimg" >}}

![Screenshot of the challenge page](https://github.com/IamLeandrooooo/MalwareCTFChallenges/blob/main/2025/NahamCon2025-CTF/Verification%20Clarification/images/11.png?raw=true)

{{< /callout >}}