package com.example.juanperezdealgaba.sac;

import android.util.Base64;
import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;

import java.security.Key;
import java.security.KeyFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import java.security.spec.PKCS8EncodedKeySpec;

import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;



public class RSAPrueba {

    public void testRSA(FileWriter writer, TextView results, int blocksize, int rep_rsa){
        Security.addProvider(new BouncyCastleProvider());

        try {
            String public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" +
                    "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" +
                    "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" +
                    "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" +
                    "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" +
                    "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" +
                    "wQIDAQAB";

            PublicKey public_key_ready = getPublicKeyFromString(public_key);

            PrivateKey private_key_ready = getPrivateKeyFromByte();

            RandomStringGenerator string = new RandomStringGenerator();

            byte[] input = string.generateRandomString(blocksize).getBytes();

            for(int i = 0; i<rep_rsa;i++) {

                Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");

                // encrypt the plaintext using the public key
                cipher.init(Cipher.ENCRYPT_MODE, public_key_ready);

                long start = System.nanoTime();
                byte[] encrypted = cipher.doFinal(input);
                long end = System.nanoTime();
                long result = (end - start) / 1000;
                writer.write("Time to encrypt: " + result + " ms\n");


                byte[] decrypted = decrypt(encrypted, private_key_ready, writer);
                String decrypted_fin = new String(decrypted,"UTF-8");
                System.out.println("We start here:");
                System.out.println(decrypted_fin);
            }



        }catch (Exception o){
            throw new RuntimeException(o);
        }
    }

    public void testRSA(){
        Security.addProvider(new BouncyCastleProvider());

        try {
            String private_key = "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n" +
                    "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n" +
                    "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n" +
                    "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n" +
                    "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n" +
                    "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n" +
                    "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n" +
                    "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n" +
                    "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n" +
                    "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n" +
                    "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n" +
                    "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n" +
                    "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n" +
                    "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n" +
                    "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n" +
                    "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n" +
                    "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n" +
                    "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n" +
                    "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n" +
                    "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n" +
                    "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n" +
                    "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n" +
                    "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n" +
                    "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n" +
                    "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw";

            String public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n" +
                    "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n" +
                    "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n" +
                    "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n" +
                    "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n" +
                    "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n" +
                    "wQIDAQAB";

           // PrivateKey private_key_ready = getPrivateKeyFromString(private_key);
            PublicKey public_key_ready = getPublicKeyFromString(public_key);

            String prueba = "this is a test";

            byte[] input = prueba.getBytes();

            byte[] encrypted = encrypt(input,public_key_ready);
            //byte[] decrypted = decrypt(encrypted,private_key_ready);
            //String decrypted_fin = new String(decrypted,"UTF-8");
            System.out.println("We start here:");
            //System.out.println(decrypted_fin);

        }catch (Exception o){
            throw new RuntimeException(o);
        }
    }

    public static byte[] encrypt(byte[] text, PublicKey key) throws Exception
    {
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    /**
     * Encrypt a text using public key. The result is enctypted BASE64 encoded text
     * @param text The original unencrypted text
     * @param key The public key
     * @return Encrypted text encoded as BASE64
     * @throws java.lang.Exception
     */
    public static String encrypt(String text, PublicKey key) throws Exception
    {
        String encryptedText;
        byte[] cipherText = encrypt(text.getBytes("UTF8"),key);
        encryptedText = encodeBASE64(cipherText);
        return encryptedText;
    }

    /**
     * Decrypt text using private key
     * @param text The encrypted text
     * @param key The private key
     * @return The unencrypted text
     * @throws java.lang.Exception
     */
    public static byte[] decrypt(byte[] text, PrivateKey key,FileWriter writer) throws Exception
    {
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding","SC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        long start = System.nanoTime();
        dectyptedText = cipher.doFinal(text);
        long end = System.nanoTime();
        long result = (end - start) / 1000;
        writer.write("Time to decrypt: " + result + "ms\n");
        System.out.println("File has been decrypted");
        return dectyptedText;

    }


    /**
     * Convert a Key to string encoded as BASE64
     * @param key The key (private or public)
     * @return A string representation of the key
     */
    public static String getKeyAsString(Key key)
    {
        // Get the bytes of the key
        byte[] keyBytes = key.getEncoded();
        return encodeBASE64(keyBytes);
    }


    public static PrivateKey getPrivateKeyFromByte() throws Exception
    {
        byte[] private_k ={(byte)0x30,(byte)0x82,(byte)0x04,(byte)0xA3,(byte)0x02,(byte)0x01,(byte)0x00,(byte)0x02,(byte)0x82,(byte)0x01,(byte)0x01,(byte)0x00,(byte)0xCB,
                (byte)0xC0,(byte)0xDB,(byte)0xBF,(byte)0xCA,(byte)0x6B,(byte)0xA4,(byte)0x9F,(byte)0xF4,(byte)0x90,(byte)0xA8,(byte)0x65,(byte)0x19,(byte)0xE2,
                (byte)0x58,(byte)0xA3,(byte)0x3A,(byte)0x36,(byte)0xB7,(byte)0xAD,(byte)0x04,(byte)0x1B,(byte)0xC2,(byte)0xF4,(byte)0xE7,(byte)0xAD,(byte)0x60,
                (byte)0xD7,(byte)0x74,(byte)0x76,(byte)0xF4,(byte)0xBB,(byte)0xCC,(byte)0x47,(byte)0x98,(byte)0x72,(byte)0xBC,(byte)0x66,(byte)0x65,(byte)0x18,
                (byte)0x9A,(byte)0x66,(byte)0x9F,(byte)0xAE,(byte)0x7E,(byte)0x03,(byte)0x8C,(byte)0x47,(byte)0x5C,(byte)0x89,(byte)0xC9,(byte)0x62,(byte)0x23,
                (byte)0xEE,(byte)0x2B,(byte)0x3A,(byte)0xCA,(byte)0x52,(byte)0x70,(byte)0x29,(byte)0x78,(byte)0xB6,(byte)0x7E,(byte)0xBF,(byte)0x0D,(byte)0x47,
                (byte)0xA1,(byte)0xC3,(byte)0x80,(byte)0x66,(byte)0xD5,(byte)0x8A,(byte)0xD3,(byte)0x3D,(byte)0xEB,(byte)0xDB,(byte)0xAB,(byte)0x80,(byte)0xF2,
                (byte)0x44,(byte)0x18,(byte)0x38,(byte)0xA5,(byte)0xFD,(byte)0x42,(byte)0xDF,(byte)0xC3,(byte)0x6C,(byte)0x27,(byte)0x6F,(byte)0xB0,(byte)0x5F,
                (byte)0x70,(byte)0x17,(byte)0xC8,(byte)0x11,(byte)0x2B,(byte)0x4A,(byte)0x6D,(byte)0xC7,(byte)0xD3,(byte)0x3A,(byte)0x47,(byte)0x5D,(byte)0xCD,
                (byte)0xBC,(byte)0x1C,(byte)0x6F,(byte)0x55,(byte)0x00,(byte)0x29,(byte)0x7D,(byte)0xCF,(byte)0x63,(byte)0x07,(byte)0xD9,(byte)0xD3,(byte)0xCE,
                (byte)0x98,(byte)0x4E,(byte)0x80,(byte)0xCE,(byte)0x09,(byte)0x88,(byte)0x46,(byte)0x2F,(byte)0x95,(byte)0x5F,(byte)0x05,(byte)0x2E,(byte)0x18,
                (byte)0x3D,(byte)0xC9,(byte)0x9A,(byte)0x2F,(byte)0x31,(byte)0x87,(byte)0x7A,(byte)0x5B,(byte)0x07,(byte)0xF7,(byte)0x6A,(byte)0x85,(byte)0xCA,
                (byte)0xF3,(byte)0xDD,(byte)0x55,(byte)0x43,(byte)0x14,(byte)0xEB,(byte)0xFE,(byte)0x44,(byte)0x18,(byte)0xA2,(byte)0xAD,(byte)0x58,(byte)0xA7,
                (byte)0xEE,(byte)0xBC,(byte)0x8B,(byte)0xA4,(byte)0xF8,(byte)0x9C,(byte)0xDA,(byte)0xBB,(byte)0x35,(byte)0x60,(byte)0xBE,(byte)0x50,(byte)0xD5,
                (byte)0x63,(byte)0x40,(byte)0x7C,(byte)0x4D,(byte)0x40,(byte)0xC4,(byte)0x0C,(byte)0xCD,(byte)0x4E,(byte)0xA5,(byte)0x58,(byte)0x25,(byte)0xFC,
                (byte)0xCF,(byte)0x28,(byte)0x37,(byte)0xC8,(byte)0x7F,(byte)0x3C,(byte)0x38,(byte)0x04,(byte)0x24,(byte)0x51,(byte)0x72,(byte)0x17,(byte)0x29,
                (byte)0xF4,(byte)0x3E,(byte)0x36,(byte)0x4B,(byte)0xD8,(byte)0x43,(byte)0x57,(byte)0x31,(byte)0x68,(byte)0xCA,(byte)0x15,(byte)0x3E,(byte)0x96,
                (byte)0x3B,(byte)0xDB,(byte)0xE7,(byte)0x95,(byte)0xB6,(byte)0x12,(byte)0xB3,(byte)0xA4,(byte)0xC7,(byte)0xB2,(byte)0x1E,(byte)0x40,(byte)0x67,
                (byte)0xED,(byte)0xC8,(byte)0xAE,(byte)0x9A,(byte)0x4E,(byte)0x6A,(byte)0x80,(byte)0xB4,(byte)0xC4,(byte)0x24,(byte)0x07,(byte)0xD6,(byte)0x66,
                (byte)0x97,(byte)0xB8,(byte)0x7F,(byte)0x87,(byte)0x85,(byte)0x66,(byte)0x3F,(byte)0xD1,(byte)0x73,(byte)0xC6,(byte)0x3C,(byte)0x26,(byte)0x3D,
                (byte)0x88,(byte)0x4B,(byte)0x99,(byte)0x15,(byte)0x3E,(byte)0x35,(byte)0x32,(byte)0xC1,(byte)0x02,(byte)0x03,(byte)0x01,(byte)0x00,(byte)0x01,
                (byte)0x02,(byte)0x82,(byte)0x01,(byte)0x00,(byte)0x38,(byte)0x60,(byte)0xD6,(byte)0xED,(byte)0x4C,(byte)0xBF,(byte)0x58,(byte)0x40,(byte)0x02,
                (byte)0x55,(byte)0xFC,(byte)0xA2,(byte)0x6C,(byte)0xF5,(byte)0x1A,(byte)0x7D,(byte)0x9F,(byte)0xE0,(byte)0x00,(byte)0x16,(byte)0xD9,(byte)0xAA,
                (byte)0x2C,(byte)0xD9,(byte)0xC3,(byte)0x39,(byte)0x50,(byte)0x30,(byte)0x8D,(byte)0xC3,(byte)0x54,(byte)0x98,(byte)0x9A,(byte)0x3F,(byte)0xBD,
                (byte)0x49,(byte)0x12,(byte)0x24,(byte)0x6B,(byte)0x18,(byte)0xD1,(byte)0xB0,(byte)0x4F,(byte)0xC2,(byte)0xE2,(byte)0x8F,(byte)0x6C,(byte)0xC3,
                (byte)0x5A,(byte)0x31,(byte)0xAE,(byte)0x0D,(byte)0x7F,(byte)0xCF,(byte)0xA9,(byte)0x1A,(byte)0x8D,(byte)0x5D,(byte)0x1E,(byte)0x37,(byte)0xFB,
                (byte)0x74,(byte)0xD3,(byte)0xC1,(byte)0x5D,(byte)0x95,(byte)0x52,(byte)0x87,(byte)0x5C,(byte)0x02,(byte)0x18,(byte)0x58,(byte)0x5F,(byte)0x77,
                (byte)0x24,(byte)0xCA,(byte)0x15,(byte)0xBC,(byte)0x8A,(byte)0x4C,(byte)0x99,(byte)0x3F,(byte)0x23,(byte)0x7E,(byte)0xDE,(byte)0x80,(byte)0x37,
                (byte)0xFC,(byte)0xB7,(byte)0x34,(byte)0xCA,(byte)0x62,(byte)0xBE,(byte)0x0B,(byte)0x76,(byte)0x8A,(byte)0x79,(byte)0xA6,(byte)0x10,(byte)0x96,
                (byte)0x58,(byte)0x36,(byte)0x2A,(byte)0x05,(byte)0x24,(byte)0xA6,(byte)0x46,(byte)0x5F,(byte)0xEF,(byte)0xEF,(byte)0x29,(byte)0x8B,(byte)0xEC,
                (byte)0x54,(byte)0x84,(byte)0x99,(byte)0x9B,(byte)0x67,(byte)0xF0,(byte)0xF0,(byte)0xD7,(byte)0xE7,(byte)0x2A,(byte)0xF0,(byte)0x10,(byte)0x2B,
                (byte)0x9E,(byte)0x72,(byte)0xBB,(byte)0xE1,(byte)0x91,(byte)0x58,(byte)0x16,(byte)0x46,(byte)0x39,(byte)0xE4,(byte)0xBD,(byte)0x2B,(byte)0xE2,
                (byte)0xDB,(byte)0x62,(byte)0xF3,(byte)0xB0,(byte)0x72,(byte)0xB8,(byte)0xCA,(byte)0x84,(byte)0x7C,(byte)0xFA,(byte)0xEA,(byte)0x6E,(byte)0x1B,
                (byte)0x79,(byte)0xD2,(byte)0x9D,(byte)0x81,(byte)0x50,(byte)0x22,(byte)0xC7,(byte)0xA3,(byte)0x44,(byte)0xE6,(byte)0x2C,(byte)0x26,(byte)0x8C,
                (byte)0xD5,(byte)0xE4,(byte)0xB5,(byte)0x24,(byte)0x25,(byte)0x24,(byte)0xC0,(byte)0xA3,(byte)0x6E,(byte)0xD7,(byte)0x4D,(byte)0x5E,(byte)0x0F,
                (byte)0xF1,(byte)0xA3,(byte)0x5F,(byte)0xC6,(byte)0xE2,(byte)0x41,(byte)0xB6,(byte)0xA7,(byte)0xF3,(byte)0x0E,(byte)0xD4,(byte)0x72,(byte)0xDC,
                (byte)0x29,(byte)0xF7,(byte)0xB5,(byte)0x37,(byte)0x91,(byte)0x60,(byte)0x06,(byte)0x25,(byte)0xE3,(byte)0xDD,(byte)0x08,(byte)0xE5,(byte)0xBE,
                (byte)0x0B,(byte)0xE3,(byte)0x25,(byte)0x99,(byte)0x21,(byte)0xD5,(byte)0xAB,(byte)0x36,(byte)0x29,(byte)0x38,(byte)0x1A,(byte)0x3C,(byte)0xE0,
                (byte)0x6A,(byte)0x65,(byte)0xA3,(byte)0xF4,(byte)0xDF,(byte)0xBD,(byte)0xFC,(byte)0x56,(byte)0x76,(byte)0x20,(byte)0xDB,(byte)0x72,(byte)0x12,
                (byte)0xCA,(byte)0xF7,(byte)0xD3,(byte)0xFE,(byte)0xD7,(byte)0x80,(byte)0xAD,(byte)0x51,(byte)0xAD,(byte)0xC6,(byte)0xB9,(byte)0x85,(byte)0x3F,
                (byte)0xBF,(byte)0x77,(byte)0xF4,(byte)0x4B,(byte)0xC9,(byte)0x14,(byte)0xAA,(byte)0x45,(byte)0xD7,(byte)0x04,(byte)0xF1,(byte)0xB8,(byte)0x39,
                (byte)0x02,(byte)0x81,(byte)0x81,(byte)0x00,(byte)0xEE,(byte)0xDD,(byte)0x03,(byte)0x47,(byte)0x7E,(byte)0xF3,(byte)0xB7,(byte)0xE7,(byte)0x44,
                (byte)0x27,(byte)0x2F,(byte)0xB9,(byte)0xBE,(byte)0x6E,(byte)0xF3,(byte)0x4A,(byte)0x63,(byte)0x7D,(byte)0xED,(byte)0x57,(byte)0xA7,(byte)0xC1,
                (byte)0x02,(byte)0x45,(byte)0x58,(byte)0xC8,(byte)0xAE,(byte)0x96,(byte)0x41,(byte)0xC6,(byte)0x6B,(byte)0x4C,(byte)0x94,(byte)0xDE,(byte)0x52,
                (byte)0xDA,(byte)0xB3,(byte)0x1C,(byte)0x6E,(byte)0x9B,(byte)0x4A,(byte)0x14,(byte)0xB6,(byte)0x77,(byte)0x48,(byte)0x8D,(byte)0xE9,(byte)0xC8,
                (byte)0xBD,(byte)0x2C,(byte)0x7A,(byte)0xB7,(byte)0x76,(byte)0x3E,(byte)0x6A,(byte)0x02,(byte)0xB6,(byte)0x17,(byte)0x71,(byte)0x0F,(byte)0x6D,
                (byte)0xBD,(byte)0x00,(byte)0x67,(byte)0x9C,(byte)0x19,(byte)0xD6,(byte)0x9D,(byte)0x48,(byte)0x5E,(byte)0xCE,(byte)0x2F,(byte)0x92,(byte)0xD8,
                (byte)0x1E,(byte)0x43,(byte)0x04,(byte)0x92,(byte)0x05,(byte)0xDA,(byte)0x9C,(byte)0x33,(byte)0xC2,(byte)0xD9,(byte)0x14,(byte)0x3B,(byte)0xD9,
                (byte)0xB8,(byte)0xF6,(byte)0xE8,(byte)0x42,(byte)0x72,(byte)0x68,(byte)0x45,(byte)0xD2,(byte)0x24,(byte)0x77,(byte)0xAD,(byte)0x97,(byte)0x9C,
                (byte)0xFE,(byte)0x5E,(byte)0x90,(byte)0x81,(byte)0x08,(byte)0x04,(byte)0x07,(byte)0xCE,(byte)0xA7,(byte)0xCB,(byte)0xF6,(byte)0xC0,(byte)0x5A,
                (byte)0x52,(byte)0x7C,(byte)0x4E,(byte)0xE7,(byte)0x34,(byte)0x7D,(byte)0xAE,(byte)0xE0,(byte)0x2A,(byte)0x40,(byte)0x5C,(byte)0xD4,(byte)0x85,
                (byte)0xF4,(byte)0x7B,(byte)0x02,(byte)0x81,(byte)0x81,(byte)0x00,(byte)0xDA,(byte)0x5F,(byte)0x03,(byte)0x26,(byte)0xB0,(byte)0xC4,(byte)0xE6,
                (byte)0x6F,(byte)0x4A,(byte)0x92,(byte)0x7F,(byte)0x89,(byte)0xE2,(byte)0x5F,(byte)0x80,(byte)0x74,(byte)0x67,(byte)0xDE,(byte)0x04,(byte)0xBD,
                (byte)0x62,(byte)0x80,(byte)0xF1,(byte)0x77,(byte)0x0E,(byte)0x7B,(byte)0x8F,(byte)0xA1,(byte)0x5E,(byte)0xBB,(byte)0x06,(byte)0x98,(byte)0x22,
                (byte)0x68,(byte)0x08,(byte)0x08,(byte)0xE2,(byte)0x1D,(byte)0xB9,(byte)0x50,(byte)0x9C,(byte)0xD7,(byte)0x88,(byte)0x32,(byte)0x8A,(byte)0xA1,
                (byte)0xAE,(byte)0xF4,(byte)0xE9,(byte)0x2D,(byte)0x03,(byte)0xE1,(byte)0x70,(byte)0x7B,(byte)0xE3,(byte)0x33,(byte)0x8B,(byte)0x5F,(byte)0x5D,
                (byte)0x4C,(byte)0x68,(byte)0x63,(byte)0xCC,(byte)0x21,(byte)0xD8,(byte)0x65,(byte)0x1B,(byte)0xE4,(byte)0xA0,(byte)0x79,(byte)0x07,(byte)0xCD,
                (byte)0xA0,(byte)0x2E,(byte)0x65,(byte)0x13,(byte)0x86,(byte)0x56,(byte)0x5C,(byte)0xDC,(byte)0x84,(byte)0x48,(byte)0x91,(byte)0xF5,(byte)0x49,
                (byte)0x58,(byte)0x11,(byte)0x19,(byte)0x3F,(byte)0x67,(byte)0x04,(byte)0x2D,(byte)0xAF,(byte)0xB4,(byte)0xBE,(byte)0x9B,(byte)0xC4,(byte)0x25,
                (byte)0x55,(byte)0x58,(byte)0x19,(byte)0x13,(byte)0x78,(byte)0x2E,(byte)0x43,(byte)0xE9,(byte)0xCF,(byte)0xD0,(byte)0x5D,(byte)0xC6,(byte)0xA2,
                (byte)0xEB,(byte)0x2C,(byte)0x3A,(byte)0x39,(byte)0x8C,(byte)0x8D,(byte)0x35,(byte)0xDA,(byte)0x74,(byte)0xBB,(byte)0x39,(byte)0xCA,(byte)0x51,
                (byte)0x17,(byte)0xB5,(byte)0xC6,(byte)0xF3,(byte)0x02,(byte)0x81,(byte)0x80,(byte)0x55,(byte)0x61,(byte)0x87,(byte)0x04,(byte)0x8D,(byte)0x6A,
                (byte)0x8C,(byte)0xB8,(byte)0x0B,(byte)0xF2,(byte)0x7D,(byte)0xEA,(byte)0xC5,(byte)0x19,(byte)0x5F,(byte)0xB9,(byte)0x9D,(byte)0x6A,(byte)0xAB,
                (byte)0xE6,(byte)0x03,(byte)0x3E,(byte)0xC8,(byte)0x93,(byte)0x05,(byte)0x33,(byte)0x66,(byte)0xC4,(byte)0xAA,(byte)0xEA,(byte)0x43,(byte)0xFC,
                (byte)0x71,(byte)0xD2,(byte)0x2E,(byte)0x87,(byte)0xA2,(byte)0x32,(byte)0x6D,(byte)0x8E,(byte)0xF0,(byte)0xA2,(byte)0x0A,(byte)0xBF,(byte)0x04,
                (byte)0x9E,(byte)0x45,(byte)0x8C,(byte)0xCD,(byte)0xA2,(byte)0x12,(byte)0x93,(byte)0x75,(byte)0x9E,(byte)0xC5,(byte)0xC2,(byte)0x06,(byte)0x58,
                (byte)0xC6,(byte)0xBF,(byte)0x1F,(byte)0x18,(byte)0xCA,(byte)0x06,(byte)0x3F,(byte)0x14,(byte)0x35,(byte)0x54,(byte)0xAF,(byte)0x43,(byte)0xC4,
                (byte)0x2B,(byte)0xD9,(byte)0x2F,(byte)0x8B,(byte)0x51,(byte)0xA5,(byte)0x56,(byte)0x94,(byte)0xE5,(byte)0x19,(byte)0xA4,(byte)0x9E,(byte)0xE7,
                (byte)0x7D,(byte)0x86,(byte)0x0F,(byte)0x43,(byte)0x40,(byte)0x6E,(byte)0xB1,(byte)0x21,(byte)0xB8,(byte)0x08,(byte)0x0D,(byte)0x1F,(byte)0x9F,
                (byte)0xEF,(byte)0xDB,(byte)0x1B,(byte)0xF1,(byte)0x08,(byte)0xD8,(byte)0x5A,(byte)0x67,(byte)0x05,(byte)0x19,(byte)0xCD,(byte)0x52,(byte)0xC9,
                (byte)0x63,(byte)0x80,(byte)0x4A,(byte)0x48,(byte)0xE5,(byte)0xCA,(byte)0x46,(byte)0x76,(byte)0xCA,(byte)0xDE,(byte)0x31,(byte)0x9E,(byte)0xA8,
                (byte)0xB7,(byte)0x05,(byte)0xF8,(byte)0x83,(byte)0xF5,(byte)0x02,(byte)0x81,(byte)0x80,(byte)0x6A,(byte)0x8B,(byte)0x81,(byte)0x16,(byte)0x17,
                (byte)0x99,(byte)0x7A,(byte)0x75,(byte)0x42,(byte)0x85,(byte)0x48,(byte)0x05,(byte)0x16,(byte)0x96,(byte)0x52,(byte)0x2E,(byte)0x79,(byte)0x9F,
                (byte)0x31,(byte)0xE0,(byte)0xD5,(byte)0x76,(byte)0xE4,(byte)0x59,(byte)0x9A,(byte)0x8F,(byte)0x5E,(byte)0xFC,(byte)0xF5,(byte)0x23,(byte)0x7B,
                (byte)0x8C,(byte)0x2E,(byte)0xFD,(byte)0x63,(byte)0x2E,(byte)0x32,(byte)0x65,(byte)0x1E,(byte)0x4D,(byte)0xDE,(byte)0xB8,(byte)0xAA,(byte)0x93,
                (byte)0x3E,(byte)0x60,(byte)0xB4,(byte)0xE4,(byte)0x7A,(byte)0x00,(byte)0xA4,(byte)0xAC,(byte)0x12,(byte)0x1D,(byte)0xE0,(byte)0x34,(byte)0xFE,
                (byte)0x03,(byte)0x81,(byte)0x9A,(byte)0x0E,(byte)0x34,(byte)0xE3,(byte)0x1C,(byte)0x80,(byte)0x60,(byte)0x94,(byte)0xC3,(byte)0x70,(byte)0x28,
                (byte)0x9D,(byte)0x4E,(byte)0x0E,(byte)0xA1,(byte)0x94,(byte)0x5F,(byte)0x7A,(byte)0x64,(byte)0x18,(byte)0xDA,(byte)0xDF,(byte)0x10,(byte)0x29,
                (byte)0x66,(byte)0xEC,(byte)0x6A,(byte)0x33,(byte)0xAD,(byte)0x85,(byte)0xE9,(byte)0xD5,(byte)0x78,(byte)0x15,(byte)0x0A,(byte)0xB3,(byte)0x15,
                (byte)0x7D,(byte)0x16,(byte)0x5A,(byte)0x15,(byte)0xA9,(byte)0xE6,(byte)0x7D,(byte)0xF4,(byte)0xD4,(byte)0xDD,(byte)0xF7,(byte)0xAF,(byte)0x4A,
                (byte)0x91,(byte)0xE8,(byte)0x5B,(byte)0xA6,(byte)0x30,(byte)0xA2,(byte)0x73,(byte)0x99,(byte)0x52,(byte)0x75,(byte)0x4C,(byte)0x0F,(byte)0x2D,
                (byte)0x9B,(byte)0x31,(byte)0x05,(byte)0xC8,(byte)0x83,(byte)0x51,(byte)0x02,(byte)0x81,(byte)0x81,(byte)0x00,(byte)0x9A,(byte)0xA2,(byte)0xA1,
                (byte)0x8B,(byte)0x3C,(byte)0xAC,(byte)0xAE,(byte)0x9E,(byte)0x5F,(byte)0x30,(byte)0x3C,(byte)0xCB,(byte)0x06,(byte)0x0B,(byte)0x8E,(byte)0xA4,
                (byte)0xCB,(byte)0xBB,(byte)0xFC,(byte)0x90,(byte)0x48,(byte)0xB0,(byte)0x67,(byte)0xFF,(byte)0x8B,(byte)0x5A,(byte)0xDF,(byte)0xA2,(byte)0xBC,
                (byte)0x0F,(byte)0x20,(byte)0xA8,(byte)0x2C,(byte)0xD9,(byte)0x4D,(byte)0xC5,(byte)0x2B,(byte)0xA8,(byte)0xC7,(byte)0xE0,(byte)0x39,(byte)0xC3,
                (byte)0xAC,(byte)0xF6,(byte)0xBC,(byte)0x47,(byte)0xD1,(byte)0x55,(byte)0x00,(byte)0xEA,(byte)0xE0,(byte)0x79,(byte)0xB8,(byte)0xBC,(byte)0x1C,
                (byte)0xE3,(byte)0x76,(byte)0x2D,(byte)0xD0,(byte)0x7D,(byte)0x82,(byte)0xCD,(byte)0x91,(byte)0x38,(byte)0x93,(byte)0xA8,(byte)0xB7,(byte)0x2F,
                (byte)0x81,(byte)0x66,(byte)0x7E,(byte)0x79,(byte)0x7E,(byte)0x38,(byte)0xA2,(byte)0x05,(byte)0xED,(byte)0x75,(byte)0x30,(byte)0xCE,(byte)0xED,
                (byte)0xCF,(byte)0x86,(byte)0x78,(byte)0xC2,(byte)0x96,(byte)0xCF,(byte)0x85,(byte)0xD7,(byte)0xB8,(byte)0x94,(byte)0x94,(byte)0x54,(byte)0xBE,
                (byte)0x7E,(byte)0x09,(byte)0x58,(byte)0xCA,(byte)0x2E,(byte)0x36,(byte)0x44,(byte)0x27,(byte)0xA4,(byte)0x1C,(byte)0xD9,(byte)0x66,(byte)0x4B,
                (byte)0x97,(byte)0xDE,(byte)0x31,(byte)0x4B,(byte)0x02,(byte)0xFB,(byte)0xD4,(byte)0x4E,(byte)0x35,(byte)0x1F,(byte)0x86,(byte)0x1C,(byte)0x89,
                (byte)0x59,(byte)0xD2,(byte)0x09,(byte)0x0C,(byte)0x55,(byte)0x73,(byte)0x82,(byte)0x70};
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(private_k);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(privSpec);
        return privateKey;
    }

    /**
     * Generates Public Key from BASE64 encoded string
     * @param key BASE64 encoded string which represents the key
     * @return The PublicKey
     * @throws java.lang.Exception
     */
    public static PublicKey getPublicKeyFromString(String key) throws Exception
    {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(Base64.decode(key,1)));
        return publicKey;
    }

    /**
     * Encode bytes array to BASE64 string
     * @param bytes
     * @return Encoded string
     */
    private static String encodeBASE64(byte[] bytes)
    {
        // BASE64Encoder b64 = new BASE64Encoder();
        // return b64.encode(bytes, false);
        return Base64.encodeToString(bytes,Base64.DEFAULT);
    }

    /**
     * Decode BASE64 encoded string to bytes array
     * @param text The string
     * @return Bytes array
     * @throws IOException
     */
    private static byte[] decodeBASE64(String text) throws IOException
    {
        // BASE64Decoder b64 = new BASE64Decoder();
        // return b64.decodeBuffer(text);
        return Base64.decode(text,Base64.DEFAULT);
    }
}
