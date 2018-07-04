package com.example.CryptoBench.sac;

import android.widget.TextView;

import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.util.encoders.Hex;


import java.io.FileWriter;
import java.io.IOException;
import java.util.Random;


/**
 * Created by juanperezdealgaba on 3/3/18.
 */

public class MD5Implementation {

        public void testmd5(FileWriter writer, TextView results,int blocksize,int rep_hash,int total_rep) throws IOException{
            RandomStringGenerator input = new RandomStringGenerator();

        byte[] inputBytes = input.generateRandomString(blocksize).getBytes();


        MD5Digest examplemd5 = new MD5Digest();

        for (int i = 0; i < total_rep; i++) {
            int repetitions = 0;
            byte[] hash = new byte[0];
            long StartHash = System.nanoTime();
            for (int j = 0; j < rep_hash; j++) {
                hash = new byte[examplemd5.getDigestSize()];
                examplemd5.update(inputBytes, 0, inputBytes.length);
                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - StartHash;
            double seconds = (double) elapsedTime / 1000000000.0;

            try {
                writer.write("repetitions:" + repetitions + "\n" );
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time to hash: " + String.format("%.4f", (repetitions * (blocksize)) / seconds) + " byte/seconds" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }



    public void testmd5Time(FileWriter writer, TextView results,long rep_aes,int blocksize,int total_rep) throws IOException {

        System.out.println("***********Bouncy Castle/MD-5**************");
        writer.write("\n**********Bouncy Castle/MD-5********\n");

        int repetitions = 0;
        bool_value.value = true;
        RandomStringGenerator string = new RandomStringGenerator();
        for (int i = 0; i < total_rep; i++) {
            MD5Digest examplemd5 = new MD5Digest();
            byte[] hash = new byte[0];
            String input = RandomStringGenerator.generateRandomString(blocksize);
            long finishTime = System.currentTimeMillis() + rep_aes;
            long start = System.nanoTime();
            while (bool_value.value) {

                byte[] inputBytes = input.getBytes();
                examplemd5.update(inputBytes, 0, inputBytes.length);
                hash = new byte[examplemd5.getDigestSize()];

                repetitions += 1;
            }
            long end = System.nanoTime();
            long elapsedTime = end - start;
            double seconds = (double) elapsedTime / 1000000000.0;
            double result = ((double)repetitions * (blocksize)) / seconds;
            bool_value.value = true;
            try {
                writer.write("Repetitions:" + repetitions + "\n" );
                writer.write("Seconds:" + seconds + "\n" );
                writer.write("Time to hash: " + result + " byte/seconds" + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
