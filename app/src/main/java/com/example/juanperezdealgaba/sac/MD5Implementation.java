package com.example.juanperezdealgaba.sac;

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

        public void testmd5(FileWriter writer, TextView results,int blocksize,int rep_hash) throws IOException{
            RandomStringGenerator input = new RandomStringGenerator();

        byte[] inputBytes = input.generateRandomString(blocksize).getBytes();



        MD5Digest examplemd5 = new MD5Digest();
        examplemd5.update(inputBytes, 0, inputBytes.length);

        for(int i = 0; i < rep_hash;i++) {
            byte[] hash = new byte[examplemd5.getDigestSize()];
            long StartHash = System.nanoTime();
            examplemd5.doFinal(hash, 0);
            long endHash = System.nanoTime();
            long timeHash = (endHash - StartHash) / 1000;

            //System.out.println("Input (hex): " + new String(Hex.encode(inputBytes)));
            //System.out.println("Output (hex): " + new String(Hex.encode(hash)));

            System.out.println("Time to generate Hash: " + timeHash + "ms\n");
            writer.write("Time to generate Hash: " + timeHash + "ms\n");
            //results.append("Time to generate Hash:" + timeHash + "ms\n");
        }


    }

        public void testmd5(String input, FileWriter writer, TextView results) throws IOException{

        byte[] inputBytes = input.getBytes();



        MD5Digest examplemd5 = new MD5Digest();
        examplemd5.update(inputBytes, 0, inputBytes.length);

        byte[] hash = new byte[examplemd5.getDigestSize()];
        long StartHash =System.nanoTime();
        examplemd5.doFinal(hash, 0);
        long endHash =System.nanoTime();
        long timeHash = (endHash - StartHash);

        System.out.println("Input (hex): " + new String(Hex.encode(inputBytes)));
        System.out.println("Output (hex): " + new String(Hex.encode(hash)));

        System.out.println("Time to generate Hash:" + timeHash + "ms\n");
        writer.write("Time to generate Hash:" + timeHash + "ms\n");
        results.append("Time to generate Hash:" + timeHash + "ms\n");


    }

    public void testmd5(String input){

        byte[] inputBytes = input.getBytes();

        System.out.println("***********MD5**************");


        MD5Digest md5 = new MD5Digest();
        md5.update(inputBytes, 0, inputBytes.length);

        byte[] hash = new byte[md5.getDigestSize()];
        long StartHash =System.nanoTime();
        md5.doFinal(hash, 0);
        long endHash =System.nanoTime();
        long timeHash = (endHash - StartHash);

        System.out.println("Input (hex): " + new String(Hex.encode(inputBytes)));
        System.out.println("Output (hex): " + new String(Hex.encode(hash)));

        System.out.println("Time to generate Hash:" + timeHash + "ms\n");
        System.out.println("********************************");

    }

    public void testmd5(FileWriter writer, TextView results,long result_time) throws IOException{

        System.out.println("***********Bouncy Castle/MD-5**************");
        writer.write("\n**********Bouncy Castle/MD-5********\n");
        results.append("*******Bouncy Castle/MD-5******\n");
        int algo_repet = 0;
        while (System.currentTimeMillis() < result_time) {
                RandomStringGenerator string = new RandomStringGenerator();
                String input = RandomStringGenerator.generateRandomString();

                byte[] inputBytes = input.getBytes();

                MD5Digest examplemd5 = new MD5Digest();
                examplemd5.update(inputBytes, 0, inputBytes.length);

                byte[] hash = new byte[examplemd5.getDigestSize()];
                long StartHash = System.nanoTime();
                examplemd5.doFinal(hash, 0);
                long endHash = System.nanoTime();
                long timeHash = (endHash - StartHash);

                System.out.println("Input (hex): " + new String(Hex.encode(inputBytes)));
                System.out.println("Output (hex): " + new String(Hex.encode(hash)));

                System.out.println("Time to generate Hash:" + timeHash + "ms\n");
                writer.write("Time to generate Hash:" + timeHash + "ms\n");
                results.append("Time to generate Hash:" + timeHash + "ms\n");
            algo_repet += 1;
        }

                System.out.println("Times executed:" + algo_repet + "\n");
                writer.write("Times executed:" + algo_repet + "\n");
                results.append("Times executed:" + algo_repet + "\n");
                System.out.println("***********************\n");
                writer.write("********************************\n");
                results.append("**********************************\n");

    }

    public void testmd5Time(FileWriter writer, TextView results,long rep_aes) throws IOException{

        System.out.println("***********Bouncy Castle/MD-5**************");
        writer.write("\n**********Bouncy Castle/MD-5********\n");

        int repetitions = 0;
        long finishTime = System.currentTimeMillis() + rep_aes;
        while(System.currentTimeMillis() <= finishTime) {
            RandomStringGenerator string = new RandomStringGenerator();
            String input = RandomStringGenerator.generateRandomString();

            byte[] inputBytes = input.getBytes();

            MD5Digest examplemd5 = new MD5Digest();
            examplemd5.update(inputBytes, 0, inputBytes.length);

            byte[] hash = new byte[examplemd5.getDigestSize()];
            long StartHash = System.nanoTime();
            examplemd5.doFinal(hash, 0);
            long endHash = System.nanoTime();
            long timeHash = (endHash - StartHash);


            writer.write("Time to generate Hash:" + timeHash + "ms\n");
            repetitions +=1;
        }
        writer.write("Times performed" + repetitions);

        System.out.println("***********************\n");
        writer.write("********************************\n");

    }
}
