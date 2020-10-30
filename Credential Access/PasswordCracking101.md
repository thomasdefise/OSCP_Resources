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



### Hashcat

hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and macOS, and has facilities to help enable distributed password cracking.


1) hashcat --example-hashes | less
2) hashcat -m *Mode* *Hashes* *Worlist*
