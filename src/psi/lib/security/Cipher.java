package psi.lib.security;

import java.io.IOException;

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
public interface Cipher {
    public byte[] encData(byte[] data, int off, int len) throws IOException;

    public byte[] decData(byte[] data, int off, int len) throws IOException;
}
