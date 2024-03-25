Members:


Melido Bello - encoding

Thierno Dicko - decoding

Both worked in main function through discord calls. The project was tested with windows subsystem for linux.



******************************************************************


How it works

Step 1 - get to the directory

cd /mnt/c/Users/<username>/<folder location>

should look like this
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/5a38cbf3-7aa4-44d7-b3a2-130e4cc9bd2e)

Step 2 - type make
should see this
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/a7bc1db3-df11-4015-b6f0-8c4089af7b92)

Step 3 - type ./kem-enc -g /tmp/testkey -b 2048

This is to make RSA key pair (private and public keys) of 2048 bits in the same directory tmp . 

These are the files withing tmp
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/5378edbc-ada0-471f-96cb-257d37fe0047)


testkey being the private key
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/fd3c20aa-8b97-437b-b37b-1e7a59715918)

testkey.pub being the public key
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/5d4ecf13-6edb-4814-a7da-0b6fd6867a72)

Step 4 - encode file.txt with public key by typing ./kem-enc -e -i input.txt -o encrypted.dat -k /tmp/testkey.pub

files we got:
input.txt (this file holds the text we want to encode)
encrypted.dat (this is the filed encoded)
testkey.pub (this is the public key)

this is the input.txt
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/b575dd36-1ce4-4b8d-9e03-96bca9de1523)

this is the encrypted.dat
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/3cd2a86a-1cc4-4647-8082-a4c5554e4417)


Step 5 - decode encrypted.dat with private key by typing ./kem-enc -d -i encrypted.dat -o decrypted.txt -k /tmp/testkey

Final output is the original text
![image](https://github.com/MelidoB/CCA2-Hybrid-Encryption/assets/48568341/4adf7aaf-9b5e-46b2-baad-cb2d105b347e)


