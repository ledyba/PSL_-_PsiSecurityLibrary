package psi.lib.security.rsa;

import java.math.*;
import java.util.*;

/**
 * <p>タイトル: PSI Security Library</p>
 *
 * <p>説明: セキュリティ確保に必要なライブラリ群</p>
 *
 * <p>著作権: Copyright (c) 2007 PSI</p>
 *
 * <p>会社名: </p>
 *
 * @author 未入力
 * @version 1.0
 */
public class RSAKeyPair {
    private static final Random RANDOM = new Random();
    private BigInteger PrimeA;
    private BigInteger PrimeB;
    private BigInteger Module;
    private int ModuleBits;
    private byte[] ModuleBytes;
    private int PowerBits;
    private BigInteger PowerPublic;
    private BigInteger PowerSecret;
    private final int KeyLength;
    private final int PowerLength;
    protected RSAKeyPair(int key_length,int power_length) {
        KeyLength = key_length;
        PowerLength = power_length;
        ModuleBits = key_length << 4;
        PowerBits = power_length << 3;
        initialize();
    }
    protected RSAKeyPair(int power_length,byte[] power_public,
                         int module_length,byte[] module){
        PowerPublic = new BigInteger(1,power_public);
        Module = new BigInteger(1,module);
        KeyLength = 0;
        PowerLength = 0;
    }

    private void initialize() {
        PrimeA = BigInteger.probablePrime(KeyLength, RANDOM);
        PrimeB = BigInteger.probablePrime(KeyLength, RANDOM);
        Module = PrimeA.multiply(PrimeB);
        ModuleBytes = Module.toByteArray();
        initializePower();
    }

    private void initializePower() {
        BigInteger tmp_prime_a = PrimeA.subtract(BigInteger.ONE);
        BigInteger tmp_prime_b = PrimeB.subtract(BigInteger.ONE);
        BigInteger tmp_prime_mul = tmp_prime_a.multiply(tmp_prime_b);
        boolean running = true;
        BigInteger tmp_public = null;
        BigInteger tmp_secret = null;
        BigInteger[] tmp_p_array;
        while (running) {
            tmp_public = new BigInteger(PowerLength, RANDOM);
            tmp_p_array = extendedEuclid2(tmp_public, tmp_prime_mul);
            tmp_secret = tmp_p_array[0];
            if (tmp_public.multiply(tmp_secret)
                .remainder(tmp_prime_mul).equals(BigInteger.ONE)) {
                running = false;
            }
        }
        PowerPublic = tmp_public;
        PowerSecret = tmp_secret;
    }
    /**
     * 法を取得します。
     * @return BigInteger
     */
    protected BigInteger getModule() {
        return Module;
    }
    /**
     * 法を、バイト列で取得します。サーバ送信用とか。
     * @return byte[]
     */
    public byte[] getModuleBytes(){
        return ModuleBytes;
    }
    /**
     * 公開する指数を取得します。
     * @return BigInteger
     */
    protected BigInteger getPowerPublic() {
        return PowerPublic;
    }
    /**
     * 公開する指数を取得します。サーバ送信用とかいかがですか。
     * @return byte[]
     */
    public byte[] getPowerPublicBytes() {
        return PowerPublic.toByteArray();
    }
    /**
     * 秘密の指数を取得します。
     * @return BigInteger
     */
    protected BigInteger getPowerSecret() {
        return PowerSecret;
    }
    /**
     * 秘密の指数を取得します。サーバ送信用。
     * @return byte[]
     */
    public byte[] getPowerSecretBytes() {
        return PowerSecret.toByteArray();
    }

    /**
     * 拡張ユークリッド互除法
     */
    private static BigInteger[] extendedEuclid2(BigInteger a, BigInteger b) {

        BigInteger x = null;
        BigInteger y = null;
        if (a.remainder(b).compareTo(BigInteger.ZERO) == 0) {
            BigInteger[] returnVal = new BigInteger[2];
            returnVal[0] = BigInteger.ZERO;
            returnVal[1] = BigInteger.ONE;
            return returnVal;
        } else {
            BigInteger[] temp = extendedEuclid2(b, a.remainder(b));
            x = temp[0];
            y = temp[1];

            BigInteger[] returnVal = new BigInteger[2];
            returnVal[0] = y;
            returnVal[1] = x.subtract(y.multiply(a.divide(b)));

            return returnVal;
        }
    }

    public int getModuleBits() {
        return ModuleBits;
    }

    public int getPowerBits() {
        return PowerBits;
    }
}
