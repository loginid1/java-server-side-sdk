package io.loginid.sdk.java;

import io.jsonwebtoken.*;
import io.loginid.sdk.java.api.AuthenticateApi;
import io.loginid.sdk.java.api.CodesApi;
import io.loginid.sdk.java.api.TransactionsApi;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.ApiException;
import io.loginid.sdk.java.invokers.ApiResponse;
import io.loginid.sdk.java.model.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;

public class LoginId {
    private final String clientId;
    private final String privateKey;
    private final String baseUrl;
    private final Set<String> codeTypes = new HashSet<>();

    public LoginId(String clientId, String privateKey, String baseUrl) {
        this.clientId = clientId;
        this.privateKey = privateKey;
        this.baseUrl = baseUrl;

        Collections.addAll(codeTypes, "short", "long", "phrase");
    }

    public String getClientId() {
        return clientId;
    }

    public boolean isValidCodeType(String codeType) {
        return codeTypes.contains(codeType);
    }

    public long getUtcEpoch() {
        return Instant.now().getEpochSecond();
    }

    public String getRandomString() {
        return getRandomString(16);
    }

    public String getRandomString(int length) {
        String randomCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        StringBuilder randomString = new StringBuilder();
        Random random = new Random();
        while (randomString.length() < length) {
            int index = random.nextInt(randomCharSet.length());
            randomString.append(randomCharSet.charAt(index));
        }
        return randomString.toString();
    }

    public boolean verifyToken(String token) {
        return verifyToken(token, null);
    }

    public boolean verifyToken(String token, String userName) {
        SigningKeyResolver signingKeyResolver = new LoginIdSigningKeyResolver();
        Jws<Claims> claims = Jwts.parserBuilder().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(token);

        Claims payload = claims.getBody();
        JwsHeader headers = claims.getHeader();

        if (userName != null) {
            return userName.equalsIgnoreCase((String) payload.get("udata"));
        }
        return true;
    }

    public String generateServiceToken(String scope, String algorithm, String userName, String userId, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (algorithm == null) {
            algorithm = "ES256";
        }
        if (nonce == null) {
            nonce = getRandomString(16);
        }

        Map<String, Object> payload = new HashMap<>();

        payload.put("client_id", clientId);
        payload.put("type", scope);
        payload.put("nonce", nonce);
        payload.put("iat", getUtcEpoch());

        if (userName != null) {
            payload.put("username", userName);
        } else if (userId != null) {
            payload.put("user_id", userId);
        }

        Map<String, Object> headers = new HashMap<>();

        headers.put("alg", algorithm);
        headers.put("typ", "JWT");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String privateKeyContent = privateKey;
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        String jws = Jwts.builder().setHeader(headers).setClaims(payload).signWith(privateKey).compact();
        return jws;
    }

    public ApiResponse<CodesCodeTypeGenerateResponse> generateCode(String userId, String codeType, String codePurpose, boolean isAuthorized) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("codes.generate", null, null, null, null);

        CodesApi codesApi = new CodesApi();
        ApiClient apiClient = codesApi.getApiClient();

        apiClient.setAccessToken(token);

        CodesCodeTypeGenerateBody codesCodeTypeGenerateBody = new CodesCodeTypeGenerateBody();
        codesCodeTypeGenerateBody.setClientId(clientId);
        codesCodeTypeGenerateBody.setUserId(userId);
        codesCodeTypeGenerateBody.setPurpose(CodesCodeTypeGenerateBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeGenerateBody.setAuthorize(isAuthorized);

        return codesApi.codesCodeTypeGeneratePostWithHttpInfo(codeType, codesCodeTypeGenerateBody, null);
    }

    public ApiResponse<CodesCodeTypeAuthorizeResponse> authorizeCode(String userId, String code, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.authorize", null, null, null, null);

        CodesApi codesApi = new CodesApi();
        ApiClient apiClient = codesApi.getApiClient();

        apiClient.setAccessToken(token);

        CodesCodeTypeAuthorizeBody codesCodeTypeAuthorizeBody = new CodesCodeTypeAuthorizeBody();

        codesCodeTypeAuthorizeBody.setClientId(clientId);
        codesCodeTypeAuthorizeBody.setUserId(userId);
        codesCodeTypeAuthorizeBody.setPurpose(CodesCodeTypeAuthorizeBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeAuthorizeBody.setCode(code);

        return codesApi.codesCodeTypeAuthorizePostWithHttpInfo(codeType, codesCodeTypeAuthorizeBody, null);
    }

    public ApiResponse<CodesCodeTypeInvalidateAllResponse> invalidateAllCodes(String userId, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.invalidate", null, null, null, null);

        CodesApi codesApi = new CodesApi();
        ApiClient apiClient = codesApi.getApiClient();

        apiClient.setAccessToken(token);

        CodesCodeTypeInvalidateAllBody codesCodeTypeInvalidateAllBody = new CodesCodeTypeInvalidateAllBody();
        codesCodeTypeInvalidateAllBody.setClientId(clientId);
        codesCodeTypeInvalidateAllBody.setPurpose(CodesCodeTypeInvalidateAllBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeInvalidateAllBody.setUserId(userId);

        return codesApi.codesCodeTypeInvalidateAllPostWithHttpInfo(codeType, null, null);
    }

    public ApiResponse<AuthenticationResponse> waitCode(String userName, String code, String codeType) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("auth.temporary", null, null, null, null);

        AuthenticateApi authenticateApi = new AuthenticateApi();
        ApiClient apiClient = authenticateApi.getApiClient();

        apiClient.setAccessToken(token);

        AuthenticateCodeWaitBody authenticateCodeWaitBody = new AuthenticateCodeWaitBody();
        authenticateCodeWaitBody.setClientId(clientId);
        authenticateCodeWaitBody.setUsername(userName);

        AuthenticatecodewaitAuthenticationCode authenticatecodewaitAuthenticationCode = new AuthenticatecodewaitAuthenticationCode();
        authenticatecodewaitAuthenticationCode.setCode(code);
        authenticatecodewaitAuthenticationCode.setType(AuthenticatecodewaitAuthenticationCode.TypeEnum.fromValue(codeType));
        authenticateCodeWaitBody.setAuthenticationCode(authenticatecodewaitAuthenticationCode);

        ApiResponse<AuthenticationResponse> result = authenticateApi.authenticateCodeWaitPostWithHttpInfo(authenticateCodeWaitBody, null);
        String jwtToken = result.getData().getJwt();

        if (jwtToken == null || !verifyToken(jwtToken)) {
            throw new SecurityException();
        }

        return result;
    }

    public String generateTxAuthToken(String txPayload, String userName, String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(txPayload.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getUrlEncoder().encodeToString(hashBytes);

        hash.replaceAll("^=+", "");
        hash.replaceAll("=+$", "");

        String algorithm = "ES256";
        if (nonce == null) {
            nonce = getRandomString(16);
        }

        Map<String, Object> payload = new HashMap<>();

        payload.put("type", "tx.create");
        payload.put("nonce", nonce);
        payload.put("payload_hash", hash);
        payload.put("iat", getUtcEpoch());

        if (userName != null) {
            payload.put("username", userName);
        }

        Map<String, Object> headers = new HashMap<>();

        headers.put("alg", algorithm);
        headers.put("typ", "JWT");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String privateKeyContent = privateKey;
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        String jws = Jwts.builder().setHeader(headers).setClaims(payload).signWith(privateKey).compact();
        return jws;
    }

    public String createTxId(String txPayload, String userName) throws ApiException, NoSuchAlgorithmException, InvalidKeySpecException {
        TransactionsApi transactionsApi = new TransactionsApi();
        ApiClient apiClient = transactionsApi.getApiClient();

        String token = generateTxAuthToken(txPayload, userName, null);
        apiClient.setAccessToken(token);

        TxBody txBody = new TxBody();
        txBody.setClientId(clientId);
        txBody.setUsername(userName);
        txBody.setTxType("text");
        txBody.setTxPayload(txPayload);
        txBody.setNonce(getRandomString());

        ApiResponse<InlineResponse2005> result = transactionsApi.txPostWithHttpInfo(txBody);
        return result.getData().getTxId();
    }

    public boolean verifyTransaction(String txToken, String txPayload) throws NoSuchAlgorithmException {
        SigningKeyResolver signingKeyResolver = new LoginIdSigningKeyResolver();
        Jws<Claims> claims = Jwts.parserBuilder().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(txToken);

        Claims payload = claims.getBody();
        JwsHeader headers = claims.getHeader();

        String toHash = txPayload
                + payload.getOrDefault("nonce", "")
                + payload.getOrDefault("server_nonce", "");

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(toHash.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getUrlEncoder().encodeToString(hashBytes);

        hash.replaceAll("^=+", "");
        hash.replaceAll("=+$", "");

        return payload.get("tx_hash").equals(hash);
    }
}
