package com.ccsobj.apns;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Date;
import java.util.concurrent.TimeUnit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import com.turo.pushy.apns.util.DateAsTimeSinceEpochTypeAdapter;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.base64.Base64;
import io.netty.handler.codec.base64.Base64Dialect;



public class ApnsJWT {

    String p8path;
    String keyId; 
    String teamId;
    public final String token;

    public ApnsJWT(String p8path,String keyId,String teamId){
        this.p8path = p8path;
        this.teamId = teamId;
        this.keyId  = keyId;
        this.token  = newToken();
    }

    String newToken(){
        try {
            Date date = new Date(System.currentTimeMillis());
            return authenticationToken(p8path, keyId, teamId, date);
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | SignatureException
                | IOException e1) {
            e1.printStackTrace();
            return null;
        }
    }

    private static class AuthenticationTokenHeader {

        @SerializedName("alg")
        private final String algorithm = "ES256";

        @SerializedName("typ")
        private final String tokenType = "JWT";

        @SerializedName("kid")
        private final String keyId;

        AuthenticationTokenHeader(final String keyId) {
            this.keyId = keyId;
        }

    }

    private static class AuthenticationTokenClaims {

        @SerializedName("iss")
        private final String issuer;

        @SerializedName("iat")
        private final Date issuedAt;

        AuthenticationTokenClaims(final String teamId, final Date issuedAt) {
            this.issuer = teamId;
            this.issuedAt = issuedAt;
        }

        String getIssuer() {
            return this.issuer;
        }

        Date getIssuedAt() {
            return this.issuedAt;
        }
    }

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping()
            .registerTypeAdapter(Date.class, new DateAsTimeSinceEpochTypeAdapter(TimeUnit.SECONDS)).create();

    static String encodeUnpaddedBase64UrlString(final byte[] data) {
        final ByteBuf wrappedString = Unpooled.wrappedBuffer(data);
        final ByteBuf encodedString = Base64.encode(wrappedString, Base64Dialect.URL_SAFE);

        final String encodedUnpaddedString = encodedString.toString(StandardCharsets.US_ASCII).replace("=", "");

        wrappedString.release();
        encodedString.release();

        return encodedUnpaddedString;
    }

    static byte[] decodeBase64EncodedString(final String base64EncodedString) {
        final ByteBuf base64EncodedByteBuf = Unpooled
                .wrappedBuffer(base64EncodedString.getBytes(StandardCharsets.US_ASCII));

        final ByteBuf decodedByteBuf = Base64.decode(base64EncodedByteBuf);
        final byte[] decodedBytes = new byte[decodedByteBuf.readableBytes()];

        decodedByteBuf.readBytes(decodedBytes);

        base64EncodedByteBuf.release();
        decodedByteBuf.release();

        return decodedBytes;
    }

    public static ECPrivateKey loadPrivKey(String p8path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        // 去除头尾标识及回车符
        final InputStream inputStream = new FileInputStream(p8path);
        final StringBuilder privateKeyBuilder = new StringBuilder();
        final BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        boolean haveReadHeader = false;
        for (String line; (line = reader.readLine()) != null;) {
            if (!haveReadHeader) {
                if (line.contains("BEGIN PRIVATE KEY")) {
                    haveReadHeader = true;
                }
            } else {
                if (line.contains("END PRIVATE KEY")) {
                    break;
                } else {
                    privateKeyBuilder.append(line);
                }
            }
        }
        final String base64EncodedPrivateKey = privateKeyBuilder.toString();
        reader.close();

        // base64解码
        final byte[] keyBytes = decodeBase64EncodedString(base64EncodedPrivateKey);

        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        final KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey signingKey = (ECPrivateKey) keyFactory.generatePrivate(keySpec);
        return signingKey;
    }

    public static String authenticationToken(String p8path, String keyId, String teamId, final Date issuedAt)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException,
            SignatureException {
            
        // 生成head、claims两部分json
        AuthenticationTokenHeader header = new AuthenticationTokenHeader(keyId);
        AuthenticationTokenClaims claims = new AuthenticationTokenClaims(teamId, issuedAt);
        final String headerJson = GSON.toJson(header);
        final String claimsJson = GSON.toJson(claims);
        
        // base64Url编码后，拼接成签名前字符串
        final StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append(encodeUnpaddedBase64UrlString(headerJson.getBytes(StandardCharsets.US_ASCII)));
        payloadBuilder.append('.');
        payloadBuilder.append(encodeUnpaddedBase64UrlString(claimsJson.getBytes(StandardCharsets.US_ASCII)));
        
        // 由p8生成私钥
        ECPrivateKey signingKey = loadPrivKey(p8path);

        // SHA256withECDSA签名
        final Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signingKey);
        signature.update(payloadBuilder.toString().getBytes(StandardCharsets.US_ASCII));
        byte[] signatureBytes = signature.sign();
        
        // 签名base64Url编码，并拼接在最后
        payloadBuilder.append('.');
        payloadBuilder.append(encodeUnpaddedBase64UrlString(signatureBytes));

        String token = payloadBuilder.toString();
        return token;
    }


}