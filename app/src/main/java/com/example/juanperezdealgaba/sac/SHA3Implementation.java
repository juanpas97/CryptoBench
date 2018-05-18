package com.example.juanperezdealgaba.sac;

import android.widget.TextView;

import org.spongycastle.crypto.digests.SHA3Digest;
import org.spongycastle.util.encoders.Hex;

import java.io.FileWriter;
import java.io.IOException;

/**
 * Created by juanperezdealgaba on 3/3/18.
 */

public class SHA3Implementation {

    public void testSHA3(String input, FileWriter writer, TextView results) throws IOException{

        System.out.println("***********SHA-3**************");
        writer.write("**********SHA-3***************\n");
        results.append("**********SHA-3************\n");

        byte[] inputbytes = input.getBytes();

        SHA3Digest sha3 = new SHA3Digest();

        sha3.update(inputbytes, 0, inputbytes.length);

        byte[] digested = new byte[sha3.getDigestSize()];

        long startSHA3 = System.nanoTime();
        sha3.doFinal(digested, 0);
        long endSHA3 = System.nanoTime();
        long timeSHA3 = (endSHA3 - startSHA3);

        System.out.println("Time to generate Hash:" + timeSHA3 + "ms\n");
        writer.write("Time to generate Hash:" + timeSHA3 + "ms\n");
        results.append("Time to generate Hash:" + timeSHA3 + "ms\n");


        System.out.println("Input (hex): " + new String(Hex.encode(inputbytes)));
        System.out.println("Output (hex): " + new String(Hex.encode(digested)));

        System.out.println("********************************");
        writer.write("********************************\n");
        results.append("********************************\n");
    }
}
