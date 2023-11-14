This is a C++ implementation of the algorithm given in Section 6 of [Locally Verifiable Signature and Key Aggregation](https://eprint.iacr.org/2022/179.pdf). The implementation is based on the C library pbc for pairings. 

### Requirements:
C++ compiler   
[pbc](https://github.com/blynn/pbc/tree/master)  
[GMP](https://gmplib.org/)  


### Usage:
1. Run `make`
2. Run `./signtest`


### Notes:
The implementation uses a type A pairing (See PBC manual):

https://crypto.stanford.edu/pbc/manual.pdf

The parameters of this pairing are given in the file  "a.param"

The hash function considered for mapping from the message space to the prime field space is the Identity Map.
The parameter B for the public key can be modified form the file Param.cpp

The DPP algorithm used is the one of "https://www.researchgate.net/publication/221425410_Fully_Collusion_Secure_Dynamic_Broadcast_Encryption_with_Constant-Size_Ciphertexts_or_Decryption_Keys"



