---
title: SANDY - Malware Reverse Challenge
description: SANDY is a Huntress 2025 CTF reverse engineering challenge where you analyze a malicious binary, uncover its logic, and extract the hidden flag.
date: 2025-10-03
tldr: An AutoIt3-packed binary ("Sandy") drops a second-stage PowerShell stager into an %APPDATA% directory; that PowerShell is heavily obfuscated and implements a crypto-stealer. Analysis required using an AutoIt3 decompiler to recover the AutoIt script and reveal the stager code, then deobfuscating the PowerShell to find the stealer logic and extract the hidden flag embedded inside the obfuscated script.
draft: false 
tags: reverse
toc: false 
---

# Challenge Description

**Author:** John Hammond  


My friend Sandy is really into cryptocurrencies! She's been trying to get me into it too, so she showed me a lot of Chrome extensions I could add to manage my wallets. Once I got everything sent up, she gave me this cool program!

She says it adds better protection so my wallets can't get messed with by hackers.

Sandy wouldn't lie to me, would she...? Sandy is the best!

## A Note for the Reader

Before jumping into the technical solution, a quick (and painful) anecdote: this challenge was meant to be solved with an AutoIt3 decompiler, something I didn’t even know existed at the time. Like an idiot, I went straight to my go-to tool (IDA) and tried to make sense of the binary. The main part of the malware was a huge Base64 blob that was dinamically loaded, it *was* the second-stage payload (the PowerShell stager). For some reason IDA chopped part of that blob(A HUGE ONE BTW), which I misread as an intentional part of the challenge. I spent time hunting for the "missing" fragments and carefully stitching the broken code back together. Long story short: I wasted hours trying to make sense of this when a language-specific decompiler would have exposed the WHOLE MALICIOUS SCRIPT immediately.

Those were some truly hellish hours, but they're worth documenting: I’ll explain what I tried, why it failed, and how the AutoIt3 decompiler ultimately saved my ass from more useless hours of torture.  

**TL;DR:** IDA trolled me hard, and I learned the hard way to check for language-specific tools first, before jumping head first with the tools that I usually use. (Being honest, I’ll probably make the same mistake again someday.) 😂

## Phase 1: Chasing Ghosts

The challenge begins with a seemingly normal binary, which, upon inspection with PEStudio, turns out to be packed with UPX.

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/upx.png?raw=true)


I unpacked the file and ran **floss** to extract all the strings, and couldn't find anything relevant. I loaded the unpacked executable into PEStudio and was able to get the binary's manifest, which indicated the technology used to compile it. That's where I discovered it was an **AutoIt3** binary. I kinda ignored it at the time and shoved it to the back of my mind… Not a good idea. 💀

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/manifest.png?raw=true)

I loaded the binary into **IDA** and tried running it, only to be greeted with the following error:

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/idaerror.png?raw=true)

It seemed that one of the strings wasn't properly terminated, thus the message box. I copied the error message from the pop-up and checked if there was anything meaningful hidden in the Base64. Sure enough, there was part of a PowerShell script but it was incomplete.

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/powershell.png?raw=true)

This is where I would be for a day reversing the whole binary, literally chasing ghosts.


So, let's go step by step. I decided to locate where the code was being loaded so I could dump it, assuming the challenge intentionally threw that error to force manual reversing. I traced the binary to a section that iterates (a `for` loop) over the payload size and loads the code piece by piece. I set a breakpoint in the loader function and inspected the `EAX` register, that held the pointer to the current line of the malware being dynamically loaded.

> **Note:** I reached this part of the binary by actually running it, setting breakpoints, and following the rabbit hole until I found the function that caused the error.

{{< callout type="customimg" >}}
![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/1.png?raw=true)
{{< /callout >}}

After doing some loops manually, I eventually noticed that it was a lot of endless and junk code, most likely to obfuscate or difficult the code analysis, like any malware has, really. I decided to do a python script that would trigger the breakpoint ONLY when the `EAX` register had the value that I was looking for.

The script was the following:
```py
import ida_bytes
import idc
import os
import ida_kernwin

try:
    eax_value = idc.get_reg_value("EAX")
    
    if eax_value and eax_value != idc.BADADDR:
        # Type 0 = C-style null-terminated strings
        string_data = ida_bytes.get_strlit_contents(eax_value, 10000, 0)
        
        if string_data and b"Global $base64Chunks[]" in string_data:
            # Log to file
            with open(r"C:\users\caralho\ida.txt", "a") as f:
                f.write(f"=== BREAKPOINT HIT - DEBUGGER PAUSED ===\n")
                f.write(f"EAX Pointer: {hex(eax_value)}\n")
                f.write(f"Full String: {string_data}\n")
                f.write("-" * 50 + "\n")
            
            ida_kernwin.msg(f"[BREAKPOINT HIT] String captured! Debugger paused.\n")
            return True  # Break
        else:
            return False  # No break
    
    else:
        return False  # No break

except Exception as e:
    ida_kernwin.msg(f"[ERROR] {e}\n")
    return False  # No break on error
```

The script begins by reading the `EAX` register with `idc.get_reg_value("EAX")`; that register holds the return value from the function that is loading the code. It immediately sanity-checks that pointer, if `eax_value` is zero or `idc.BADADDR`, the script returns `False` and does nothing, avoiding bogus reads.

When the pointer looks valid, the script calls `ida_bytes.get_strlit_contents(eax_value, 10000, 0)` to read a C-style (null-terminated) string from that address. The value `10000` is intentionally large so the script can capture very long Base64 blobs or embedded scripts that wouldn't fit a small buffer. The raw bytes read from memory are then searched for the `Global $base64Chunks[]"` part, which identifies the string that was throwing the error.

If the marker is found, the script dumps the EAX value into a dump file.

After writing the captured data the script returns `True`. The `True` value is how the breakpoint handler knows to pause execution at that moment, allowing to inspect memory manually. Any exceptions are caught and printed to IDA's messages, and the script returns `False` on error so it won't crash the debugging session.

Sure enough the breakpoint is hit when the condition is met.

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/2.png?raw=true)

Before digging into the Base64 chunks, I wanted to know exactly which line of the code this fragment was coming from. To figure that out, I tracked the counter controlling the `for` loop, specifically the `inc ebx` instruction. By following that, I could map each dynamically loaded string back to its position in the AutoIt script.

{{< callout type="customimg" >}}
![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/inc.png?raw=true)
{{< /callout >}}


The counter's value was `1BD`, which converts from hex to decimal as 445, meaning this fragment came from line 445. Imagine trying to figure that out manually 😂.  

Anyway, with the dump in hand, I could finally see what the value actually was before moving on to inspect where the code was being sliced and loaded. In my mind, that made the most sense as the next step.

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/3.png?raw=true)

I practically pulled a SpongeBob *Chinese face* the moment I inspected the dumped value, it was exactly the same as the error string. My jaw dropped. After a few seconds of head-scratching I came up with two possibilities: either the challenge expects us to patch this loader code on-the-fly and let it finish so we can dump the rest of the AutoIt script (and recover the remaining Base64), or there's an earlier routine, way before the spot I was tracing, that's failing and causing the loader to break before it ever reaches the real payload.

Honestly, the first idea felt right, so I wrote a tiny Python patcher to close the Base64 string by appending `"]` to the end. The plan was simple: patch the broken string in-memory so the loader would stop erroring, let the program continue, and (hopefully) stream out the rest of the AutoIt script, including the remaining Base64 chunks. It was a bit of duct-tape reasoning, but worth a shot.

The script was the following:
```py
import ida_bytes
import idc
import os
import ida_kernwin

try:
    eax_value = idc.get_reg_value("EAX")
    if eax_value and eax_value != idc.BADADDR:
        # First, check if this is our target string for patching
        string_data = ida_bytes.get_strlit_contents(eax_value, 8190, 0)
        if string_data and b"Global $base64Chunks[]" in string_data:
            # Find the actual length (position of null terminator)
            length = 0
            while True:
                lo = ida_bytes.get_byte(eax_value + length)
                hi = ida_bytes.get_byte(eax_value + length + 1)
                if lo == 0 and hi == 0:
                    break
                length += 2
                
            end_of_string_addr = eax_value + length
            ida_bytes.patch_byte(end_of_string_addr, 0x22)
            ida_bytes.patch_byte(end_of_string_addr + 1, 0x00)
            
            ida_bytes.patch_byte(end_of_string_addr + 2, 0x5d)
            ida_bytes.patch_byte(end_of_string_addr + 3, 0x00)
            
            ida_bytes.patch_byte(end_of_string_addr + 4, 0x00)
            ida_bytes.patch_byte(end_of_string_addr + 5, 0x00)
            
        with open(r"C:\users\caralho\eax_dump.txt", "a") as f:
            f.write(f"EAX: {hex(eax_value)}")
            
            # Read string data specifically for dumping (fresh read)
            dump_string_data = ida_bytes.get_strlit_contents(eax_value, 16380, 0)
            if dump_string_data:
                # Write the FULL string without truncation
                f.write(f" -> String: ")
                f.write(dump_string_data.decode('utf-8', errors='replace'))  # Decode properly
            else:
                # If not a string, show raw bytes
                raw_bytes = ida_bytes.get_bytes(eax_value, 32)  # First 32 bytes
                if raw_bytes:
                    f.write(f" -> Bytes: {raw_bytes.hex()}")
            f.write(f"\n")
    
    # Return False to NOT break - let program continue running
    return False

except Exception as e:
    with open(r"C:\users\caralho\eax_dump.txt", "a") as f:
        f.write(f"ERROR: {e}\n")
    return False
```

The script starts by reading the `EAX` register with `idc.get_reg_value("EAX")` and verifies the pointer is valid. If it is, the script reads a candidate C-style string from memory using `ida_bytes.get_strlit_contents(eax_value, 8190, 0)` and checks whether that string contains the AutoIt marker `b"Global $base64Chunks[]"`. If the marker is present, the script assumes this is the broken Base64-containing string that needs to be fixed. The value of the string `8190` was calculated using the previous string length multiplied by 2. Since we are dealing with UTF-16, each character takes 2 bytes, and the original string size was 4095 characters. Multiplying 4095 by 2 gives 8190 bytes, which is the length we pass to `get_strlit_contents` to ensure we read the full string before hitting the null terminator.

To find the end of the string it doesn’t rely on a simple `get_strlit_contents` length, instead it walks the bytes two at a time with `ida_bytes.get_byte(eax_value + length)` and `ida_bytes.get_byte(eax_value + length + 1)` until it finds two consecutive zero bytes. That two-byte step is intentional: like previously said, the string in memory is UTF‑16/wide (little-endian), so characters are stored as 2‑byte code units and the terminator is a double‑null. Once it locates the terminator, it computes `end_of_string_addr` and then writes a small patch sequence at and after that address:

- `ida_bytes.patch_byte(end_of_string_addr, 0x22)` writes `"` (double-quote).
- `ida_bytes.patch_byte(end_of_string_addr + 1, 0x00)` writes the NULL byte that follows (UTF‑16).
- `ida_bytes.patch_byte(end_of_string_addr + 2, 0x5d)` writes `]`.
- `ida_bytes.patch_byte(end_of_string_addr + 3, 0x00)` the following NULL for UTF‑16.
- `ida_bytes.patch_byte(end_of_string_addr + 4, 0x00)` and `+5` write the terminating double‑NULL so the string is properly terminated.

Those patches effectively append `"]` to the wide string and then re-terminate it, closing whatever truncated Base64 array syntax was causing the earlier runtime error.

The `EAX` register is then dumped one by one, to get the whole scipt.

I got everything ready, and tadaaaaaaaaaan, the program doesn't break anymore and advances to the next step, which previously failed because of that annoying string error. But best of all, I finally have the full script dump in my hands or at least I thought so...

{{< callout type="customimg" >}}
![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/5.png?raw=true)
{{< /callout >}}

Errrrmmm, Houston, we have a problem. A big one. After poking through the dumped AutoIt script I still couldn't find the rest of the Base64 chunks, so it looks like my patching hack wasn't the intended path after all.

From the portion I do have, the logic is clear: the script concatenates and decodes Base64 chunks, decodes it, writes the resulting PowerShell payload into `%APPDATA%` (or a Temp subfolder there), and then executes that PowerShell stager. But since I don't have the complete PowerShell script, I can't say exactly what it does, only that it "does things." And those unknown things could be the crypto‑stealer logic (and the hidden flag), so the hunt continues.

From the dump I was able to recreate the malware's behavior. I changed the write‑to‑disk portion to make the output easier to obtain; apart from that modification, this is an accurate reconstruction.

```AutoIt
Global $base64Chunks[] = [ _
<Base64 incomplete code – redacted for readability>
]

Func _Base64Decode($pKkevvyiPlecxgqr)
    Local $idPpaetop = ObjCreate("MSXML2.DOMDocument")
    Local $var_3322 = $idPpaetop.createElement("base64")
    $var_3322.dataType = "bin.base64"
    $var_3322.text = $pKkevvyiPlecxgqr
Return $var_3322.nodeTypedValue
EndFunc

Func _Dec($var_3357)
    Return BinaryToString(_Base64Decode($var_3357), 4)
EndFunc

Local $x1 = ""
Local $x2 = ""

For $x2 = 0 To UBound($base64Chunks) - 1
    $x1 &= $base64Chunks[$x2]
Next

Local $x3 = _Dec($x1)

$x3 = "$e1 = 'lfdfzpzpiw'" & @CRLF & "$d1 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e1))" & @CRLF & "Invoke-Expression $d1" & @CRLF & "$e2 = 'gecwwiswie'" & @CRLF & "$d2 = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e2))" & @CRLF & "Invoke-Expression $d2" & @CRLF & $x3

FileWrite("C:\Users\Caralho\script.ps1", $x3)
```

But then again, here I am with everything **except** the full Base64 blob that's the backbone of this malware. I started poking around the binary for places the code gets loaded.

I found the first loader invocation and began digging into the function. At the very start of the routine an address is moved into the register `EDI`, and immediately afterwards that pointer is dereferenced, it points to the in‑memory string the program later uses. I thought **“AAAH HA! FOUND YOU!”**, only to discover the string was the exact same truncated Base64 fragment.

Before showing you the end result that made me want to throw myself out the window, here are the steps I followed.  

I basically wrote a Python script to trigger the breakpoint when the register that was used for the count would hit **443**.  
Why **443**? I wanted a bit of "distance" to analyze before hitting line **445**, which is the one containing the Base64 code.

```py
import idc
import ida_kernwin

# Get EAX value as number
eax_value = idc.get_reg_value("EAX")

# Just display the numeric value
ida_kernwin.msg(f"EAX value: {eax_value} (0x{eax_value:X})\n")

# If you want to check if it's 443 specifically:
if eax_value == 443:
    ida_kernwin.msg("EAX equals 443!\n")
    return True
```

After triggering the breakpoint, I stepped manually until I hit the count register of **445**.  
Before executing the code, I calculated the next offset for the dereferenced address that would hit the code for line **445**, and dumped it with the following script:

```py
import ida_bytes
import ida_segment
import os

# --- Configuration ---
start_ea = 0x292FC74   # Start of your data
output_file = r"C:\Users\caralho\Desktop\dump.txt"  # Change path as needed

# --- Determine the segment end ---
seg = ida_segment.getseg(start_ea)
if seg:
    max_len = seg.end_ea - start_ea
else:
    max_len = 0x10000  # fallback if segment not found

# --- Read bytes dynamically until double null (UTF-16LE) ---
data = bytearray()
offset = 0
while offset < max_len:
    b1 = ida_bytes.get_byte(start_ea + offset)
    b2 = ida_bytes.get_byte(start_ea + offset + 1)
    if b1 == 0 and b2 == 0:
        break
    data.append(b1)
    data.append(b2)
    offset += 2  # UTF-16LE uses 2 bytes per character

# --- Decode UTF-16LE ---
try:
    text = data.decode("utf-16le")
except Exception as e:
    print("Decoding failed:", e)
    text = data.hex()

# --- Save to file ---
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, "w", encoding="utf-8") as f:
    f.write(text)

print("Dump saved to:", output_file)
print("Contents:\n", text)
```

This was the sad output of the script.

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/deref1.png?raw=true)


The output left me **extremely annoyed**. Every idea I had in mind, every logical approach I tried against this challenge had failed. I found myself up against a wall with no clear direction.

This is where I took a step back and started thinking about other ways to solve the challenge, because obviously what I was doing wasn't cutting it.


## Phase 2: Who You Gonna Call?

After stepping back from my tunnel vision, I decided to look into the technology itself, specifically what AutoIt3 had to offer. That's when I stumbled across something game-changing: **there's actually a decompiler that can recover the original script**.  

According to the [AutoIt3 Decompiling FAQ](https://www.autoitscript.com/wiki/Decompiling_FAQ):  

> *If the version of AutoIt is v3.2.5.1 or lower, then the decompiler is located at  
> `C:\Program Files\AutoIt3\Extras\Exe2Aut\Exe2Aut.exe` by default.*  

This was a huge breakthrough. The manifest we had enumerated earlier showed that our script version was **3.0.0.0**, which falls right within the range of decompilable versions. Finally, I was back on track with this challenge.

After a bit of trial and error, I finally landed on the version that worked with the binary. I went through a bunch of different installers, most of them just threw errors for reasons unknown.  

Thankfully, AutoIt maintains a fantastic [archive of installers](https://www.autoitscript.com/autoit3/files/archive/autoit/), which saved me a ton of time (and frustration). 

Huge shoutout to that archive, all my homies love that archive!

The version that finally worked for this binary was **autoit-v3.2.4.0-setup.exe**.  
With it, I was able to successfully recover the script straight from the binary.

{{< callout type="customimg" >}}
![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/convert.png?raw=true)
{{< /callout >}}

And the script

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/script.png?raw=true)

After analysing the extracted the script, I was able to get the whole base64 string, and let me tell you something, **LET ME TELL YOU SOMETHING**, it was huge, like, I was like 1/100 of it from IDA. So basically IDA was trolling me, very hard.

I extracted the script and perform a normal base64 decode with Cyberchef, and it resulted in this:

```powershell
$encodedScript = "<redacted base64 for readability>"
$decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript))
Invoke-Expression $decodedScript

$encodedScript = "<redacted base64 for readability>"
$decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript))
Invoke-Expression $decodedScript

...


$encodedScript = "<redacted base64 for readability>"
$decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript))
Invoke-Expression $decodedScript

$encodedJson = "<redacted base64 for readability>"
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedJson)))

$encodedScript = "<redacted base64 for readability>"
$decodedScript = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedScript))
Invoke-Expression $decodedScript
```

This code takes a Base64-encoded string assigned to `$encodedScript`, decodes it from Base64 into a Unicode string, and then immediately executes the decoded content in memory using `Invoke-Expression`. In other words, the script is just a loader: it hides the real payload inside Base64 and then runs it dynamically after decoding.

If we decode the base64, the code now has an AES decryption routine:

```powershell
$base64coded = "<redacted base64 for readability>"
$base64EncryptedFunction = $base64coded.Substring(32, $base64coded.Length - 64)
$key1 = "eeJsXD3VT2a7iFMF"
$key2 = "4QK0Zm3Qri61BgF8"
$key3 = "AGAuSHwl7pZo1uQL"
$fullKey = $key1 + $key2 + $key3
$salt = "nBYiV2b8wVrdqsCY"
$keyDerivation = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($fullKey, [System.Text.Encoding]::UTF8.GetBytes($salt), 1000)
$keyBytes = $keyDerivation.GetBytes(32)
$iv = "qGCve1NYklJH6BIV"
$ivBytes = [System.Text.Encoding]::UTF8.GetBytes($iv)
if ($ivBytes.Length -lt 16) { $ivBytes = $ivBytes + @(0) * (16 - $ivBytes.Length) } elseif ($ivBytes.Length -gt 16) { $ivBytes = $ivBytes[0..15] }
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $keyBytes
$aes.IV = $ivBytes
$decryptor = $aes.CreateDecryptor()
$encryptedBytes = [System.Convert]::FromBase64String($base64EncryptedFunction)
$decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
$memoryStream = New-Object System.IO.MemoryStream(, $decryptedBytes)
$gzipStream = New-Object System.IO.Compression.GZipStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
$streamReader = New-Object System.IO.StreamReader($gzipStream)
$decryptedFunction = $streamReader.ReadToEnd()
Invoke-Expression $decryptedFunction
```

This code takes a Base64-encoded string and trims off the first 32 and last 32 characters, leaving the portion in the middle to be used as the encrypted payload. It then reconstructs an AES key by concatenating three hardcoded key fragments, applying PBKDF2 (via `Rfc2898DeriveBytes`) with a salt and 1000 iterations, and extracting 32 key bytes. An IV is also prepared from another hardcoded string, adjusted to exactly 16 bytes.  

With these values, the script creates an AES decryptor and applies it to the Base64-decoded payload. The decrypted data is then passed through a GZip stream for decompression, producing the final plaintext code. This code is read into memory and immediately executed with `Invoke-Expression`.  

In short, the script hides its real functionality by embedding an AES-encrypted, GZip-compressed payload inside a Base64 string, and only reveals and runs it at runtime.


Many of these code sections were essentially dead weight. For example, many routines did nothing useful and simply returned `null`:

```powershell
function FvFunction {
    $fveData = @(
        "<redacted base64>",
        "<redacted base64>"
    )
    return $null
}

```

The core of the script was, unsurprisingly, a crypto stealer: it crawled browser extensions (Metamask and similar wallets) looking for stored wallet data and exfiltrated anything it could grab. After slogging through the obfuscated mess and decoding the relevant pieces, I finally uncovered the flag. In short, the `$encodedJson` blob once decoded contains a JSON structure that holds the flag in one part of it.

The retrieval of the flag can be seen in the following image:

![UPX](https://github.com/IamLeandrooooo/huntressWriteUp/blob/main/images/SANDI/flag.png?raw=true)

To wrap up: I really enjoyed this challenge. In hindsight it would have been much smoother if I'd done a bit more research before diving in head-first, but the trial-and-error was part of the fun. Tinkering in IDA, tracing loaders, and chasing down that stubborn Base64 string made for a satisfying (if occasionally irritating) ride.

Did I learn something new? Absolutely, I feel that I always do!

Did you learn something from this writeup? Maybe, and if not, at least take my mistake as a friendly reminder: don't be as stubborn as I was. Don’t waste hours bashing your head against the same wall. Step back, change your approach, and the path forward usually appears. 

In other words, don't be stupid like I was 😂

