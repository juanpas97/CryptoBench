package com.example.juanperezdealgaba.sac;


import java.util.Random;


/**
 * Created by juanperezdealgaba on 25/2/18.
 *
 * This class will create the RandomString that will be used to perform the tests.
 * The string will have 128 bits.
 */

public class RandomStringGenerator {
    /**
     *
     * @return
     */

    public static String generateRandomString() {
        Random rand = new Random();
        StringBuilder stringBuilder = new StringBuilder();
        char[] chars = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
                'q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0'};
        for (int i = 0; i < 128; ++i) {
            char selectedChar = chars[rand.nextInt(chars.length)];
            stringBuilder.append(selectedChar);
        }

        final String randomstring = stringBuilder.toString();

        return randomstring;
    }

    /**
     *
     * @param args
     */
    public static void main (String [ ] args){

        String pene = generateRandomString();
        System.out.println(pene);
    }
}
