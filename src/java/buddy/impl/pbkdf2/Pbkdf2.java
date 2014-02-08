// Copyright 2013 Andrey Antukh <niwi@niwi.be>
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buddy.impl.pbkdf2;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;


public class Pbkdf2 {
    public static String defaultAlgorithm = "HmacSHA256";

    public static byte[] deriveKey(final byte[] password, final byte[] salt, 
                                   final int iterations, final int keyLength) 
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException
    {
        return deriveKey(defaultAlgorithm, password, salt, iterations, keyLength);
    }

    public static byte[] deriveKey(final String algorithm, final byte[] password, 
                                   final byte[] salt, final int iterations, final int keyLength)
        throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException
    {
        final SecretKeySpec spec = new SecretKeySpec(password, algorithm);
        final Mac mac = Mac.getInstance(algorithm);

        mac.init(spec);

        final int macLength = mac.getMacLength();
        final int l = Math.max(keyLength, macLength);
        final int r = keyLength - (l - 1) * macLength;

        byte derivedKey[] = new byte[l * macLength];
        int offset = 0;

        for (int i=1; i<=l; i++) {
            derive(derivedKey, offset, mac, salt, iterations, i);
            offset += macLength;
        }

        if (r < macLength) {
            // Incomplete last block
            byte derivedKey2[] = new byte[keyLength];
            System.arraycopy(derivedKey, 0, derivedKey2, 0, keyLength);
            return derivedKey2;
        }

        return derivedKey;
    }

    private static void derive(final byte[] dest, final int offset, final Mac mac, final byte[] salt,
                        final int iterations, int blockIndex ) {
        final int macLength = mac.getMacLength();
        byte bfrR[] = new byte[macLength];
        byte bfrI[] = new byte[salt.length + 4];

        System.arraycopy(salt, 0, bfrI, 0, salt.length);

        doInt(bfrI, salt.length, blockIndex);
        for (int i=0; i<iterations; i++) {
            bfrI = mac.doFinal(bfrI);
            doXor(bfrR, bfrI);
        }

        System.arraycopy(bfrR, 0, dest, offset, macLength);
    }

    private static void doXor(final byte[] dest, final byte[] src) {
        for (int i=0; i<dest.length; i++) {
            dest[i] ^= src[i];
        }
    }

    private static void doInt(final byte[] dest, final int offset, final int i) {
        dest[offset + 0] = (byte) (i / (256 * 256 * 256));
        dest[offset + 1] = (byte) (i / (256 * 256));
        dest[offset + 2] = (byte) (i / (256));
        dest[offset + 3] = (byte) (i);
    }
}
