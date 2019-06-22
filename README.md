# Fast parallel hardware-accelerated brute-force for popular crypto algorithms

I'm bored of seeing the same problems over and over again in CTFs.
It's always AES or RC4, SHA or MD5. It's always a 32 bits brute.

And I was also annoyed by how difficult it is to find a simple, hackable example code
for using the fancy cpu instructions.

I just collected all the code I had lying around for parallelizing the brute force.
Next time I can just copy paste the code and quickly work off the template.
Run it on some beefy server with a nice cpu with many cores and AES-NI and SHA-NI.
