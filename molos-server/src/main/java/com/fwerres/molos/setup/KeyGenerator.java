/*
 * Copyright 2023 Frank Werres (https://github.com/FrankWerres/molos)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fwerres.molos.setup;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public class KeyGenerator {
	/**
     * @param keySize
     * @param keyUse
     * @param keyAlg
     * @param kid
     * @return
     */
    public static RSAKey generateRSAKey(Integer keySize, KeyUse keyUse, Algorithm keyAlg, String kid) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize);
            KeyPair kp = generator.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
            RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kp.getPrivate();

            RSAKey rsaKey = new RSAKey.Builder(pub)
                    .privateKey(priv)
                    .keyUse(keyUse)
                    .algorithm(keyAlg)
                    .keyID(kid)
                    .build();

            return rsaKey;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
}
