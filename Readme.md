# Cryptobench

Cryptobench is an Android app developed as part of my bachelorthesis that benchmarks different cryptographic algorithms from different security providers. The app uses java and native (C and C++) code to see the performance differences between each provider.

## Algorithms

At the moment Cryptobench supports the following algorithms from the following providers:

|                          | Bouncy Castle/ Spongy Castle | mbedTLS            | WolfCrypt          | OpenSSL            | BoringSSL          |
|--------------------------|------------------------------|--------------------|--------------------|--------------------|--------------------|
| RSA/OAEP/1024-bit key    | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| MD-5                     | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Diffie-Hellman(RFC-5114) | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| ECDH(SECP-256r1)         | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| AES-CBC/NoPadding/128    | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| AES-CTR/NoPadding/128    | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| AES-GCM/NoPadding/128    | :heavy_check_mark:           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| AES-OFB/NoPadding/128    | :heavy_check_mark:           | Not provided       | Not provided       | :heavy_check_mark: | :heavy_check_mark: |


## Tests

CryptoBench supports 2 different types of test, Complete Test and Special Test:

 * Complete Test: In this test the app will try every algorithm from every provider a finite number of times. The app will try the different AES algorithms and MD-5 from 128 bytes to 1024 bytes, RSA with a 128 bytes message, Diffie-Hellman and ECDH. The user can specify how many times does the app must try the different algorithms.
 <br />
 The repetitions value is a general value that will be used to repeat every test.
 This test is useful to set the mean, the standard deviation and the fastest and slowest time of the different algorithms.
 
 If the user wants, once the app is installed, this test can be triggered through the ADB terminal running the following command:
 
 ```
 am start -n com.example.juanperezdealgaba.sac/.CompleteTestActivity -e test 1 -e aes 20 -e hash 7 -e dh 5 -e rsa 15
 ```
 
 This will start an activity with the desired values.
 
 * Special Test: In this test the app wil perform an algorithm from a provider a given amount of times (minutes). This test will be used how much does the CPU temperature of the device changes during the different process and also to determine specific time measures as the byte/ microseconds of the algorithms. This test will also spend an amount of time starting the structures, the RNGS, assigning data,... to see the differences between each provider.

 This test can also be started directly from the ADB terminal using the command: 

 ```
am start -n com.example.juanperezdealgaba.sac/.ConcreteTest -e lib BoringSSL -e algo DH -e min 1 -e  blocksize 128 -e key 1 -e rep 2
 ```
Possible values for "lib" are: WolfCrypt, Bouncy, mbedTLS, BoringSSL and OpenSSL. Possible values for "algo" are: RSA, AES-CBC,AES-OFB,AES-GCM,AES-CTR,DH,ECDH and MD5.

The adb commands can be chained with the "wait" to automatize all the tests.

```
am start -n com.example.juanperezdealgaba.sac/.ConcreteTest -e lib BoringSSL -e algo DH -e min 1 -e  blocksize 128 -e key 1 -e rep 2 & wait 4m & am start -n com.example.juanperezdealgaba.sac/.ConcreteTest -e lib BoringSSL -e algo RSA -e min 1 -e  blocksize 128 -e key 1 -e rep 2
 ```

As we are starting a new activity for every test, you have to take into account the time the test
need to be performed, if not the two activities will run at the same time and the temperature 
of the device will not be measured in a "trusted environment". 

 ### Notes
 * Some algorithms have fixed values, for example RSA will always encrypt and decrypt a 128 bytes message and the blocksize in DH and ECDH is completely ignored as we are measuring the key agreement.

 * If the user leaves any of the fields in "Special Test" empty, they will be replaced with the default one. (Minutes = 1, Blocksize = 1024 and key = 1)

 * The results of the folder /CryptoBench/ cannot be read by the Android file reader, in a PC there shouldn´t be any problem.

### Known Bugs
 * First time that app is started, it will crash. This is because it tries to create files before the app asked for read/write permission. If you granted the permission, the next time you open the app this will be fixed.
 
 * If you want to use an algorithm from a provider that doesn´t support it, the app will crash. (For example, AESOFB from mbedTLS).

 * If a test is cancelled or the phone is chagend from vertical to horizontal (or vice versa), you will have to restart the app to keep using it. As your results won´t be saved.
