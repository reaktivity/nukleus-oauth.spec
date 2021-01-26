/**
 * Copyright 2016-2021 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.specification.nukleus.oauth.internal;

import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.unmodifiableMap;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.reaktivity.specification.nukleus.oauth.internal.OAuthJwtKeys.RFC7515_ES256;
import static org.reaktivity.specification.nukleus.oauth.internal.OAuthJwtKeys.RFC7515_RS256;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import org.agrona.LangUtil;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.kaazing.k3po.lang.el.Function;
import org.kaazing.k3po.lang.el.spi.FunctionMapperSpi;
import org.reaktivity.specification.oauth.internal.types.control.OAuthResolveExFW;

import com.hierynomus.asn1.encodingrules.der.DERDecoder;
import com.hierynomus.asn1.types.ASN1Tag;
import com.hierynomus.asn1.types.constructed.ASN1Sequence;
import com.hierynomus.asn1.types.primitive.ASN1Integer;

public final class OAuthFunctions
{
    private static final Map<String, Supplier<JwtHelper>> HELPER_FACTORIES;

    static
    {
        Map<String, Supplier<JwtHelper>> helperFactories = new HashMap<>();
        helperFactories.put("RS256", () -> new JwtHelper(RFC7515_RS256, "RS256", "SHA256withRSA"));
        helperFactories.put("ES256", () -> new JwtHelper(RFC7515_ES256, "ES256", "SHA256withECDSA"));
        HELPER_FACTORIES = unmodifiableMap(helperFactories);
    }

    @Function
    public static OAuthResolveExBuilder resolveEx()
    {
        return new OAuthResolveExBuilder();
    }

    @Function
    public static JwtHelper jwt(
        String kind)
    {
        Supplier<JwtHelper> helperFactory = HELPER_FACTORIES.get(kind);
        return helperFactory.get();
    }

    static JwtHelper jwt(
        KeyPair pair,
        String kind,
        String algorithm)
    {
        return new JwtHelper(pair, kind, algorithm);
    }

    static byte[] decodeIntegrity(
        byte[] integrity)
    {
        return JwtSigner.decodeDER(integrity);
    }

    public static final class JwtHelper
    {
        private final KeyPair keyPair;
        private final String kind;
        private final String algorithm;
        private final List<String> claims;

        private JwtHelper(
            KeyPair keyPair,
            String kind,
            String algorithm)
        {
            this.keyPair = keyPair;
            this.kind = kind;
            this.algorithm = algorithm;
            this.claims = new ArrayList<>();
        }

        public JwtHelper expiresInSeconds(
            int seconds)
        {
            long expiry = MILLISECONDS.toSeconds(currentTimeMillis()) + seconds;
            return claim("exp", expiry);
        }

        public JwtHelper claim(
            String name,
            Object... values)
        {
            if (values != null)
            {
                if (values.length == 1)
                {
                    Object value = values[0];
                    String format = value instanceof String ? "\"%s\":\"%s\"" : "\"%s\":%d";
                    this.claims.add(String.format(format, name, value));
                }
                else
                {
                    StringBuilder claim = new StringBuilder();
                    claim.append(String.format("\"%s\":[", name));
                    for (int i = 0; i < values.length; i++)
                    {
                        if (i > 0)
                        {
                            claim.append(',');
                        }
                        Object value = values[i];
                        String format = value instanceof String ? "\"%s\"" : ":%d";
                        claim.append(String.format(format, value));
                    }
                    claim.append(']');
                    this.claims.add(claim.toString());
                }
            }
            return this;
        }

        public String sign() throws GeneralSecurityException
        {
            String header = String.format("{\"kid\":\"%s\",\"alg\":\"%s\"}", kind, kind);
            String payload = claims.stream().collect(Collectors.joining(",", "{", "}"));

            Base64.Encoder base64 = Base64.getUrlEncoder().withoutPadding();
            String header64 = new String(base64.encode(header.getBytes(UTF_8)), US_ASCII);
            String payload64 = new String(base64.encode(payload.getBytes(UTF_8)), US_ASCII);
            String securedInput = String.format("%s.%s", header64, payload64);

            JwtSigner signer = JwtSigner.getInstance(algorithm);
            signer.initSign(keyPair.getPrivate());
            signer.update(securedInput.getBytes(US_ASCII));
            byte[] integrity = signer.sign();
            String integrity64 = new String(base64.encode(integrity), US_ASCII);

            return String.format("%s.%s", securedInput, integrity64);
        }
    }

    public static final class OAuthResolveExBuilder
    {
        private final OAuthResolveExFW.Builder resolveExRW;

        private OAuthResolveExBuilder()
        {
            MutableDirectBuffer writeExBuffer = new UnsafeBuffer(new byte[1024 * 8]);
            this.resolveExRW = new OAuthResolveExFW.Builder().wrap(writeExBuffer, 0, writeExBuffer.capacity());
        }

        public OAuthResolveExBuilder issuer(
            String issuerName)
        {
            resolveExRW.issuer(issuerName);
            return this;
        }

        public OAuthResolveExBuilder audience(
            String audienceName)
        {
            resolveExRW.audience(audienceName);
            return this;
        }

        public byte[] build()
        {
            final OAuthResolveExFW resolveEx = resolveExRW.build();
            final byte[] array = new byte[resolveEx.sizeof()];
            resolveEx.buffer().getBytes(resolveEx.offset(), array);
            return array;
        }
    }

    private static final class JwtSigner
    {
        private static final Map<String, JwtSigner> SIGNERS = new ConcurrentHashMap<>();

        private final Signature signature;
        private final UnaryOperator<byte[]> decoder;

        public static JwtSigner getInstance(
            String algorithm)
        {
            return SIGNERS.computeIfAbsent(algorithm, JwtSigner::newSigner);
        }

        public void initSign(
            PrivateKey privateKey) throws InvalidKeyException
        {
            signature.initSign(privateKey);
        }

        public void update(
            byte[] data) throws SignatureException
        {
            signature.update(data);
        }

        public byte[] sign() throws SignatureException
        {
            return decoder.apply(signature.sign());
        }

        static byte[] decodeDER(
            byte[] integrity)
        {
            final DERDecoder decoder = new DERDecoder();
            final ASN1Sequence sequence0 = new ASN1Sequence.Parser(decoder).parse(ASN1Tag.SEQUENCE, integrity);
            final ASN1Sequence sequence1 = (ASN1Sequence) sequence0.get(0);
            final ASN1Integer element0 = (ASN1Integer) sequence1.get(0);
            final ASN1Integer element1 = (ASN1Integer) sequence1.get(1);

            final byte[] r = element0.getValue().toByteArray();
            final byte[] s = element1.getValue().toByteArray();

            final int offsetR = r.length & 0x01;
            final int lengthR = r.length - offsetR;
            final int offsetS = s.length & 0x01;
            final int lengthS = s.length - offsetS;

            assert offsetR == 0x00 ^ r[0] == 0;
            assert offsetS == 0x00 ^ s[0] == 0;

            byte[] rawIntegrity = new byte[lengthR + lengthS];
            System.arraycopy(r, offsetR, rawIntegrity, 0, lengthR);
            System.arraycopy(s, offsetS, rawIntegrity, lengthR, lengthS);

            return rawIntegrity;
        }

        private JwtSigner(
            Signature signature,
            UnaryOperator<byte[]> decoder)
        {
            this.signature = signature;
            this.decoder = decoder;
        }

        private static JwtSigner newSigner(
            String algorithm)
        {
            UnaryOperator<byte[]> decoder = algorithm.endsWith("withECDSA") ? JwtSigner::decodeDER : UnaryOperator.identity();
            JwtSigner newSigner = null;
            try
            {
                Signature signature = Signature.getInstance(algorithm);
                newSigner = new JwtSigner(signature, decoder);
            }
            catch (NoSuchAlgorithmException ex)
            {
                LangUtil.rethrowUnchecked(ex);
            }
            return newSigner;
        }
    }

    public static class Mapper extends FunctionMapperSpi.Reflective
    {

        public Mapper()
        {
            super(OAuthFunctions.class);
        }

        @Override
        public String getPrefixName()
        {
            return "oauth";
        }
    }

    private OAuthFunctions()
    {
        // utility
    }
}
