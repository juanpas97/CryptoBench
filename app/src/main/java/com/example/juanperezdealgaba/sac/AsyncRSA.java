package com.example.juanperezdealgaba.sac;


import android.os.AsyncTask;
import android.util.Log;
import android.widget.TextView;


import org.spongycastle.crypto.AsymmetricCipherKeyPair;


import java.io.FileWriter;


import static com.example.juanperezdealgaba.sac.RSA.Decrypt;
import static com.example.juanperezdealgaba.sac.RSA.Encrypt;
import static com.example.juanperezdealgaba.sac.RSA.GenerateKeys;

/**
 * Created by juanperezdealgaba on 1/3/18.
 */

class MyTaskParams {
    String randomString;
    FileWriter writer;
    TextView results;
    int repetitions;

    MyTaskParams(String randomString, FileWriter writer, TextView results, int repetitions) {
        this.randomString = randomString;
        this.writer = writer;
        this.results = results;
        this.repetitions = repetitions;
    }
}


class AsyncRSA extends AsyncTask<MyTaskParams, Void, TextView> {


    @Override
    protected TextView doInBackground(MyTaskParams... params) {
        String randomString = params[0].randomString;
        FileWriter writer = params[0].writer;
        TextView results = params[0].results;
        int repetitions = params[0].repetitions;
        try {
            System.out.println("************RSA**************");
            results.append("\n************RSA***************\n");
            writer.write("\n************RSA***************\n");

            for(int i = 0;i < repetitions; i++) {
                System.out.println("Plaintext[" + randomString.length() + "]: " + randomString);
                AsymmetricCipherKeyPair keyPair = GenerateKeys();
                String plainMessage = randomString;
                long startTimeEncrypt = System.nanoTime();
                String encryptedMessage = Encrypt(plainMessage.getBytes("UTF-8"),
                        keyPair.getPublic());
                long endTimeEncrypt = System.nanoTime();
                long durationEncrypt = (endTimeEncrypt - startTimeEncrypt);
                System.out.println("Encrypted[" + encryptedMessage.length() + "]: " + encryptedMessage);
                System.out.println("Time to encrypt:" + durationEncrypt + "ms\n");
                writer.write("Time to encrypt:" + durationEncrypt + "ms\n");
                results.append("Time to encrypt:" + durationEncrypt + "ms\n");

                long startTimeDecrypt = System.nanoTime();
                String decryptedMessage = Decrypt(encryptedMessage, keyPair.getPrivate());
                long endTimeDecrypt = System.nanoTime();
                long durationDecrypt = (endTimeDecrypt - startTimeDecrypt);
                writer.write("Time to decrypt:" + durationDecrypt + "ms\n");
                results.append("Time to decrypt:" + durationDecrypt + "ms\n");
                System.out.println("Decrypted[" + decryptedMessage.length() + "]: " + decryptedMessage);
                System.out.println("Time to decrypt:" + durationDecrypt + "ms");
            }

            System.out.println("********************************");
            writer.write("********************************\n");
            results.append("********************************\n");
            writer.close();
        } catch (Exception i) {
            Log.e("RSA", i.getMessage(), i);
        }
        return results;
    }

    @Override
    protected void onPostExecute(TextView report) {

            super.onPostExecute(report);
            String magia = "Test finished successfully!";
            report.append(magia);


    }
}

