package com.example.CryptoBench.sac;

import android.util.Base64;
import android.widget.TextView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;

import java.math.BigDecimal;
import java.security.Key;
import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import java.security.spec.PKCS8EncodedKeySpec;

import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


public class RSA {

    public void testRSA(FileWriter writer, TextView results, int blocksize, int rep_rsa,int total_rep){
        Security.addProvider(new BouncyCastleProvider());

        byte[] encrypted = new byte[0];

        try {
            Keys key_st = new Keys();
            String public_key = key_st.returnPublicKey();

            PublicKey public_key_ready = getPublicKeyFromString(public_key);

            PrivateKey private_key_ready = getPrivateKeyFromByte();

            RandomStringGenerator string = new RandomStringGenerator();

            byte[] input = string.generateRandomString(blocksize).getBytes();


            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
            for (int i = 0; i < total_rep; i++) {
                cipher.init(Cipher.ENCRYPT_MODE, public_key_ready);
                int repetitions = 0;
                long start = System.nanoTime();
                for (int j = 0; j < rep_rsa - 1; j++) {
                    encrypted = cipher.doFinal(input);
                    repetitions += 1;
                }

                long end = System.nanoTime();
                long elapsedTime = end - start;
                double seconds = (double) elapsedTime / 1000000000.0;
                double result = ((double)repetitions * (blocksize)) / seconds;

                try {
                    writer.write("Seconds" + seconds + "\n");
                    writer.write("Repetitions encrypt: " + repetitions + "\n");
                    writer.write("Time to encrypt: " + new BigDecimal(result).toPlainString() + " byte/seconds" + "\n");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            for (int i = 0; i < total_rep; i++) {
                byte[] decryptedText = null;
                int repetitions = 0;
                // decrypt the text using the private key
                cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");
                cipher.init(Cipher.DECRYPT_MODE, private_key_ready);
                long start = System.nanoTime();
                for (int j = 0; j < rep_rsa - 1; j++) {
                    decryptedText = cipher.doFinal(encrypted);
                    repetitions += 1;
                }

                long end = System.nanoTime();
                long elapsedTime = end - start;
                double seconds = (double) elapsedTime / 1000000000.0;

                try {
                    writer.write("Time to decrypt: " + (repetitions * (blocksize)) / seconds + " byte/seconds" + "\n");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        }catch (Exception o){
            throw new RuntimeException(o);
        }
    }

    public void testRSATime(FileWriter writer, TextView results, int blocksize, long rep_key ,long rep_rsa,int total_rep){
        Security.addProvider(new BouncyCastleProvider());

        try {
            Keys key_st = new Keys();
            String public_key = key_st.returnPublicKey();

            PublicKey public_key_ready;
            PrivateKey private_key_ready;
            RandomStringGenerator string = new RandomStringGenerator();

            int repetitions = 0;
            long finishTime = System.currentTimeMillis()+rep_key;
            long start = System.nanoTime();
            while(System.currentTimeMillis() <= finishTime) {
                public_key_ready = getPublicKeyFromString(public_key);
                private_key_ready = getPrivateKeyFromByte();
                Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");

                cipher.init(Cipher.ENCRYPT_MODE, public_key_ready);

                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            try {
                writer.write("Time setting key: " + (repetitions/seconds) + " times/second" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

            public_key_ready = getPublicKeyFromString(public_key);

            private_key_ready = getPrivateKeyFromByte();

            bool_value.value = true;

            byte[] input = string.generateRandomString(blocksize).getBytes();
            byte[] encrypted = new byte[0];
            for (int i = 0; i < total_rep; i++) {
                repetitions = 0;
                finishTime = System.currentTimeMillis() + rep_rsa;

                Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");
                cipher.init(Cipher.ENCRYPT_MODE, public_key_ready);
                 start = System.nanoTime();
                while (bool_value.value) {

                    encrypted = cipher.doFinal(input);
                    repetitions += 1;
                }

                 end = System.nanoTime();
                elapsedTime = end - start;
                seconds = (double) elapsedTime / 1000000000.0;
                bool_value.value = true;
                System.out.println("Value of rep: " + i);
                double result = ((double)repetitions * (blocksize)) / seconds;
                try {
                    writer.write("Seconds" + seconds + "\n");
                    writer.write("Repetitions encrypt: " + repetitions + "\n");
                    writer.write("Time to encrypt: " + new BigDecimal(result).toPlainString() + " byte/seconds" + "\n");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            try {
                writer.write("\n");
                writer.write("\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

            bool_value.value = true;
            System.out.println("Finish encrypting");
            for (int i = 0; i < total_rep; i++) {
                byte[] decryptedText = null;
                repetitions = 0;
                // decrypt the text using the private key
                Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "SC");
                finishTime = System.currentTimeMillis()+rep_key;
                cipher.init(Cipher.DECRYPT_MODE, private_key_ready);
                start = System.nanoTime();
                while (bool_value.value) {
                    decryptedText = cipher.doFinal(encrypted);
                    repetitions += 1;
                }

                 end = System.nanoTime();
                elapsedTime = end - start;
                seconds = (double) elapsedTime / 1000000000.0;
                double result = ((double)repetitions * (blocksize)) / seconds;
                bool_value.value = true;
                System.out.println("Value of rep: " + i);
                try {

                    writer.write("Seconds" + seconds + "\n");
                    writer.write("Repetitions encrypt: " + repetitions + "\n");
                    writer.write("Time to de" +
                            "crypt: " + new BigDecimal(result).toPlainString() + " byte/seconds" + "\n");

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }



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
        Keys key_st = new Keys();
        byte[] private_k = key_st.returnPrivateKey();
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
