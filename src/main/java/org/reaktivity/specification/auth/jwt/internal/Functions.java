/**
 * Copyright 2016-2017 The Reaktivity Project
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
package org.reaktivity.specification.auth.jwt.internal;

import static java.lang.String.format;

import java.util.Base64;

import org.kaazing.k3po.lang.el.Function;
import org.kaazing.k3po.lang.el.spi.FunctionMapperSpi;

public final class Functions
{

    /* The following are JWS compact serializations of a JSON Web Token with
    ** headers {"kid":"key2","alg":"RS256"} and payload {"iss":"test issuer"}
    ** signed using the keys given in RFC 7515 appendices A.2 and A.3.
    */
    private static final String VALID_RS256_SIGNED_JWT =
           "eyJraWQiOiJrZXkyIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJ0ZXN0IGlzc3VlciJ9." +
           "JYrWm0k-_u04FwVM_eY5NjpSYvYPi2AtQ5GY0nfOl2glXUSbMYc47t2GpOvMb59gmwSf7YaFn2LNVKdFGrIf8j" +
           "ElotgXhGHLAj2-Hww_AILjlj7Brwkw_tv4nvsx6oIHxHt5Md5z00SUrJPJHl5WIKk8KibQ8IHb_RU1G_pwhUHq" +
           "Itm-Ayt91IY-f4FBZc4yCVb9PXS7TPv9IwwJPkW14pZs9qjypejhTFc1okCm5tz9T0mPRNt_BoqBQJvTP571lR" +
           "tyQ6bTcnN0aY8sreXY_jNxPXrTLgg6zooYWp1y_OW287BSVHKmAWBmtG-XoMbRaZbxEe07M29uDu0GZjZhQg";

    private static final String VALID_ES256_SIGNED_JWT =
           "eyJraWQiOiJrZXkxIiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJqd3QgdGVzdCJ9." +
           "PJ0yFl_eVoIMyLPYgDL_SUMk6fZ3RqafBbGpmW2bZMs-BHv3Sd-hWup6VWqItLnJgAUNHZJIztiwLfjl9hSWWw";

    // headers: {"kid":"key1","alg":"ES256"} payload: {"iss":"test issuer","exp":1493539200}
    // (expiry 30-Mar-17 00:00:00)
    private static final String EXPIRED_ES256_SIGNED_JWT =
           "eyJraWQiOiJrZXkxIiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJ0ZXN0IGlzc3VlciIsImV4cCI6MTQ5MzUzOTIwMH0." +
           "hWhi3Wmve1AQLQHUuN8PR9qElutw378ydEPtZWub2Qkh7Ei46mfW-zwaoloyj57cRS7G2R-GtkA6LjNKX0WSDA";

    // headers: {"kid":"key1","alg":"ES256"} payload: {"iss":"test issuer","nbf":1809072000}
    // (nbf 30-Mar-27 00:00:00)
    private static final String UNREADY_ES256_SIGNED_JWT =
           "eyJraWQiOiJrZXkxIiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJ0ZXN0IGlzc3VlciIsIm5iZiI6MTgwOTA3MjAwMH0." +
           "IamaLKCC-m31Zrb513OM9funekwAqf7HVe0MW5xbFBP99MXME7r1GRao8c8XN-XvMelqwkPDVxJoUCGzBGcnSw";

    @Function
    public static String base64Encode(String value)
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes());
    }

    @Function
    public static String append(String... strings)
    {
        StringBuilder x = new StringBuilder();
        for (String s : strings)
        {
            x.append(s);
        }
        return x.toString();
    }

    @Function
    public static byte length8(String value)
    {
        int length = value.length();
        if (length > 0xFF)
        {
            throw new IllegalArgumentException(format("Length of \"%s\" cannot be expressed as a single byte", value));
        }
        return (byte) length;
    }

    @Function
    public static String expiredSignedJwtES256()
    {
        return EXPIRED_ES256_SIGNED_JWT;
    }

    @Function
    public static String unreadySignedJwtES256()
    {
        return UNREADY_ES256_SIGNED_JWT;
    }

    @Function
    public static String validSignedJwtES256()
    {
        return VALID_ES256_SIGNED_JWT;
    }

    @Function
    public static String validSignedJwtRS256()
    {
        return VALID_RS256_SIGNED_JWT;
    }

    public static class Mapper extends FunctionMapperSpi.Reflective
    {

        public Mapper()
        {
            super(Functions.class);
        }

        @Override
        public String getPrefixName()
        {
            return "jwt";
        }
    }

    private Functions()
    {
        // utility
    }
}
