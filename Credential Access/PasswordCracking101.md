# Cracking Passwords

## Methods

## Brute-force attack

consists of an attacker submitting many passwords or passphrases with the hope of eventually guessing correctly. The attacker systematically checks all possible passwords and passphrases until the correct one is found.

### Dictionary attack

Form of brute force attack technique which tries to determine the decryption key or passphrase by trying thousands or millions of likely possibilities, such as words in a dictionary or previously used passwords, often from lists obtained from past security breaches.

### Lookup Tables
### Reverse Lookup Tables
### Rainbow Tables attack
### Hashing with Salt

TODO
Rainbow tables are one type of tool that have been developed to derive a password by looking only at a hashed value.

Rainbow tables are not always needed as there are more straightforward methods of plaintext recovery available. 
these are not adequate for systems that use long passwords because of the difficulty of storing all the options available and searching through such an extensive database to perform a reverse lookup of a hash.

To address this issue of scale, reverse lookup tables were generated that stored only a smaller selection of hashes that when reversed could make long chains of passwords. Although the reverse lookup of a hash in a chained table takes more computational time, the lookup table itself can be much smaller, so hashes of longer passwords can be stored. Rainbow tables are a refinement of this chaining technique and provide a solution to a problem called chain collisions.

https://github.com/dwyl/english-words

### Basic

#### Hashes
```bash
echo -n *hash* | wc -c: Get the count of characters within the hash
```

|Nb° Character|Algorithm|Hashcat Mode|
|-|-|-|
|32|MD5|0|
|40|SHA1|100|
|64|SHA256 <br >Or<br > SHA3-256|1400  <br >Or<br >  17400|
|128|SHA2-512 <br >Or<br > SHA3-512|1700 <br >Or<br > 17600|


#### Password lists

- **rockyou.txt**: Wordlist is a password dictionary, the collection of the most used and potential password. 

#### Customm Dictionary generation

##### Tesseract

[Tesseract](https://github.com/tesseract-ocr/tesseract) is an optical character recognition engine for various operating systems developped by Google. This can be used to extract keyword from harvested images.

Note that in many cases, in order to get better OCR results, you'll need to [improve the quality](https://tesseract-ocr.github.io/tessdoc/ImproveQuality.html) of the image you are giving Tesseract.

```bash
tesseract imagename outputbase [-l lang] [--oem ocrenginemode]
for x in *.jpg; do tesseract $x stoud -psm 11 -l eng >>tesser.out; done
```

##### CeWL

[CeWL](https://github.com/digininja/CeWL) is a ruby app which spiders a given URL to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.

```bash
cewl --with-numbers https://domain.com > cewl_website_mainpage.txt
```
- **--with-numbers**: Include "words" with numbers
- **-m 8**: Some people specify this parameter in order to fetch words that are equal or bigger than 8.
*Note that -m 8 could lead to miss some interesting word, as some users take products names or the names of the company as password and in to meet the password policy, they add characther at the end such as (eg: G00gl3\*\*)*
Those combination can be created using rule-based attack in hashcat.

```bash
sort -u cewl_website_mainpage.txt /usr/share/seclists/Dictionary/english_dictionnary.txt > unique_word.txt # Delete english word from the list
```

### Cisco7t

User passwords and most other passwords (Type 7) (not enable secrets) in Cisco IOS configuration files are encrypted using a scheme that is very weak by modern cryptographic standards.

[ciscot7](https://github.com/theevilbit/ciscot7) is a small tool to decrypt Cisco IOS type 7 passwords, it can also encrypt clear text passwords if required.

```bash
ciscot7.py -d -p PASSWORD
```

For more information: [Cisco IOS Password Encryption Facts](https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html)

### Hashcat

hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and macOS, and has facilities to help enable distributed password cracking.

```bash
hashcat --example-hashes | less
hashcat -m *Mode* *Hashes* *Worlist*
```

#### Rule-based attack
The rule-based attack is like a programming language designed for password candidate generation.

Here below is how to generate a new worldlist taking into account rule-based attack
```bash
hashcat -r /usr/share/hashcat/rules/best64.rules *wordlist* --stdout > custom_wl.txt
```

##### For the anecdote

In 2012, the best64 challenge [forum thread](https://hashcat.net/forum/thread-1002.html) goal was to find the set of 64 rules that would be the most efficient for cracking a given set of hashes (the phpbb.com leak) with a given dictionary (so called top10k). While not having the best methodology (training and validation sets are identical), the winner (Arex1337) produced a set of 64 rules that is quite good in practice.
[Source](https://www.synacktiv.com/en/publications/rulesfinder-automatically-create-good-password-cracking-rulesets.html)

### Bruteforcing

##### Zip Bruteforcing

```bash
zip2john file.hash # hash.txt Get hashed password out of zip archive
./john file.hash --wordlist rockyou.txt
```

##### SMB Bruteforcing

```bash
cme smb *ip* -u *user.txt* -p *passwords.txt* --continue-on-success
smbpasswd -U *username* -r *IP* # Test the user
```

##### References:

- https://www.4armed.com/blog/hashcat-rule-based-attack/