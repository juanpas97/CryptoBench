package com.example.juanperezdealgaba.sac;

import org.spongycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

import java.security.SecureRandom;

import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.PKCS7Padding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;


/**
 * Created by juanperezdealgaba on 26/2/18 expanding the code on
 * https://github.com/p120ph37/cbc-aes-example
 *
 * This AES encryption will be using Cipherblock Chaining(CBC).
 */

public class AESCBCBouncyCastle {


        private final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(new AESEngine());
        private final SecureRandom random = new SecureRandom();

        private KeyParameter key;
        private BlockCipherPadding bcp = new PKCS7Padding();

        /**
         *
         * @param bcp
         */

        public void setPadding(BlockCipherPadding bcp) {

            this.bcp = bcp;
        }

        /**
         *
         * @param key
         */
        public void setKey(byte[] key) {

                this.key = new KeyParameter(key);
        }

        /**
         *
         * @param input
         * @return
         * @throws DataLengthException
         * @throws InvalidCipherTextException
         */
        public byte[] encrypt(byte[] input)  throws DataLengthException,
                InvalidCipherTextException {
            return processing(input, true);
        }

        /**
         *
         * @param input
         * @return
         * @throws DataLengthException
         * @throws InvalidCipherTextException
         */

        public byte[] decrypt(byte[] input)
                throws DataLengthException, InvalidCipherTextException {
            return processing(input, false);
        }

        /**
         *
         * @param input
         * @param encrypt
         * @return
         * @throws DataLengthException
         * @throws InvalidCipherTextException
         */

        private byte[] processing(byte[] input, boolean encrypt)
                throws DataLengthException, InvalidCipherTextException {

            PaddedBufferedBlockCipher pbbc =
                    new PaddedBufferedBlockCipher(cbcBlockCipher, bcp);

            int blockSize = cbcBlockCipher.getBlockSize();
            int inputOffset = 0;
            int inputLength = input.length;
            int outputOffset = 0;

            byte[] iv = new byte[blockSize];
            if(encrypt) {
                random.nextBytes(iv);
                outputOffset += blockSize;
            } else {
                System.arraycopy(input, 0 , iv, 0, blockSize);
                inputOffset += blockSize;
                inputLength -= blockSize;
            }

            pbbc.init(encrypt, new ParametersWithIV(key, iv));
            byte[] output = new byte[pbbc.getOutputSize(inputLength) + outputOffset];

            if(encrypt) {
                System.arraycopy(iv, 0 , output, 0, blockSize);
            }

            int outputLength = outputOffset + pbbc.processBytes(
                    input, inputOffset, inputLength, output, outputOffset);

            outputLength += pbbc.doFinal(output, outputLength);

            return Arrays.copyOf(output, outputLength);

        }
}
