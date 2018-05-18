package com.example.juanperezdealgaba.sac;

import org.spongycastle.crypto.BlockCipher;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.paddings.BlockCipherPadding;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;





/**
 * Created by juanperezdealgaba on 25/2/18 extending the code of
 * http://www.mytechnotes.biz/2012/08/aes-256-symmetric-encryption-with.html
 *
 * This AES encryption will be using Electronic Codebook(ECB).
 */

public class AESBouncyCastle {

    private final BlockCipher AESCipher = new AESEngine();

    private PaddedBufferedBlockCipher pbbc;
    private KeyParameter key;

    /**
     *
     * @param bcp
     */
    public void setPadding(BlockCipherPadding bcp) {
        this.pbbc = new PaddedBufferedBlockCipher(AESCipher, bcp);
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

    public byte[] encrypt(byte[] input)
            throws DataLengthException, InvalidCipherTextException {
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

        pbbc.init(encrypt, key);

        byte[] output = new byte[pbbc.getOutputSize(input.length)];
        int bytesWrittenOut = pbbc.processBytes(
                input, 0, input.length, output, 0);

        pbbc.doFinal(output, bytesWrittenOut);

        return output;

    }
}
