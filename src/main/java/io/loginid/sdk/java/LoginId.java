package io.loginid.sdk.java;

import io.jsonwebtoken.*;
import io.loginid.sdk.java.api.AuthenticateApi;
import io.loginid.sdk.java.api.TransactionsApi;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.ApiException;
import io.loginid.sdk.java.model.*;

import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@SuppressWarnings("unused")
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

    public LoginId(String clientId, String privateKey) {
        this(clientId, privateKey, "https://directweb.usw1.loginid.io/api/native");
    }

    public String getClientId() {
        return clientId;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * @param codeType The type of the code
     * @return 'true' if the code type is valid, 'false' otherwise
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean isValidCodeType(String codeType) {
        return codeTypes.contains(codeType);
    }

    /**
     * @return UTC Epoch in seconds
     */
    public long getUtcEpoch() {
        return Instant.now().getEpochSecond();
    }

    /**
     * Generates a random string of length 16 with alphanumeric characters
     *
     * @return A random string of alphanumeric characters
     */
    public String getRandomString() {
        return getRandomString(16);
    }

    /**
     * Generates a random string of given length with alphanumeric characters
     *
     * @param length The length of the output string
     * @return A random string of alphanumeric characters
     */
    @SuppressWarnings("SpellCheckingInspection")
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

    /**
     * Verifies a JWT token returned upon user authorization
     *
     * @param token The JWT token
     * @return 'true' if the token is valid, 'false' otherwise
     */
    public boolean verifyToken(String token) {
        return verifyToken(token, null);
    }

    /**
     * Verifies a JWT token returned upon user authorization
     *
     * @param token    The JWT token
     * @param username (Nullable) If provided, checks if 'username' matches the 'udata' in JWT
     * @return 'true' if the token is valid, 'false' otherwise
     */
    @SuppressWarnings({"SpellCheckingInspection", "rawtypes"})
    public boolean verifyToken(String token, @Nullable String username) {
        LoginIdSigningKeyResolver signingKeyResolver = new LoginIdSigningKeyResolver();

        ApiClient apiClient = signingKeyResolver.getCertificatesApi().getApiClient();
        apiClient.setBasePath(baseUrl);
        
        Jws<Claims> claims = Jwts.parserBuilder().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(token);

        Claims payload = claims.getBody();
        JwsHeader headers = claims.getHeader();

        if (username != null) {
            return username.equalsIgnoreCase((String) payload.get("udata"));
        }
        return true;
    }

    /**
     * Generates a service token
     *
     * @param scope    The scope of the service
     * @param username (Nullable) The username to be granted by the token
     * @param userId   (Nullable) The user ID to be granted by the token; ignored if username is provided
     * @param nonce    (Nullable) Nonce for the token; auto-generated if not provided
     * @return The JWT service token
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public String generateServiceToken(String scope, @Nullable String username, @Nullable String userId, @Nullable String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return generateServiceToken(scope, null, username, userId, nonce);
    }

    /**
     * Generates a service token
     *
     * @param scope     The scope of the service
     * @param algorithm (Nullable) Encryption algorithm; defaults to "ES256"
     * @param username  (Nullable) The username to be granted by the token
     * @param userId    (Nullable) The user ID to be granted by the token; ignored if username is provided
     * @param nonce     (Nullable) Nonce for the token; auto-generated if not provided
     * @return The JWT service token
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @SuppressWarnings({"UnnecessaryLocalVariable", "DuplicatedCode"})
    public String generateServiceToken(String scope, @Nullable String algorithm, @Nullable String username, @Nullable String userId, @Nullable String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
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

        if (username != null) {
            payload.put("username", username);
        } else if (userId != null) {
            payload.put("user_id", userId);
        }

        Map<String, Object> headers = new HashMap<>();

        headers.put("alg", algorithm);
        headers.put("typ", "JWT");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String privateKeyContent = privateKey;
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        String jws = Jwts.builder().setHeader(headers).setClaims(payload).signWith(privateKey).compact();
        return jws;
    }


    /**
     * Generates an Authorization Token for Transaction Flow
     *
     * @param txPayload The transaction payload
     * @param username  (Nullable) The username
     * @param nonce     (Nullable) Nonce for the token; auto-generated if not provided
     * @return The JWT authorization token
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @SuppressWarnings({"UnnecessaryLocalVariable", "DuplicatedCode"})
    public String generateTxAuthToken(String txPayload, @Nullable String username, @Nullable String nonce) throws NoSuchAlgorithmException, InvalidKeySpecException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(txPayload.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getUrlEncoder().encodeToString(hashBytes);

        hash = hash.replaceAll("^=+", "");
        hash = hash.replaceAll("=+$", "");

        String algorithm = "ES256";
        if (nonce == null) {
            nonce = getRandomString(16);
        }

        Map<String, Object> payload = new HashMap<>();

        payload.put("type", "tx.create");
        payload.put("nonce", nonce);
        payload.put("payload_hash", hash);
        payload.put("iat", getUtcEpoch());

        if (username != null) {
            payload.put("username", username);
        }

        Map<String, Object> headers = new HashMap<>();

        headers.put("alg", algorithm);
        headers.put("typ", "JWT");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        String privateKeyContent = privateKey;
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

        String jws = Jwts.builder().setHeader(headers).setClaims(payload).signWith(privateKey).compact();
        return jws;
    }

    /**
     * Creates a transaction ID
     *
     * @param txPayload The transaction payload
     * @param username  (Nullable) The username
     * @return The transaction ID
     * @throws ApiException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public String createTx(String txPayload, @Nullable String username) throws ApiException, NoSuchAlgorithmException, InvalidKeySpecException {
        TransactionsApi transactionsApi = new TransactionsApi();

        ApiClient apiClient = transactionsApi.getApiClient();
        apiClient.setBasePath(baseUrl);
        if (this.privateKey == null) {
            String token = generateTxAuthToken(txPayload, username, null);
            apiClient.setAccessToken(token);
        }

        TxBody txBody = new TxBody();
        txBody.setClientId(clientId);
        txBody.setUsername(username);
        txBody.setTxType("text");
        txBody.setTxPayload(txPayload);
        txBody.setNonce(getRandomString());

        TxResponse result = transactionsApi.txPost(txBody);
        return result.getTxId();
    }

    /**
     * Verifies the JWT returned upon completion of a transaction
     *
     * @param txToken   The JWT token
     * @param txPayload The original transaction payload
     * @return 'true' if the JWT token is valid, 'false' otherwise
     * @throws NoSuchAlgorithmException
     */
    @SuppressWarnings("rawtypes")
    public boolean verifyTransaction(String txToken, String txPayload) throws NoSuchAlgorithmException {
        LoginIdSigningKeyResolver signingKeyResolver = new LoginIdSigningKeyResolver();

        ApiClient apiClient = signingKeyResolver.getCertificatesApi().getApiClient();
        apiClient.setBasePath(baseUrl);

        Jws<Claims> claims = Jwts.parserBuilder().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(txToken);

        Claims payload = claims.getBody();
        JwsHeader headers = claims.getHeader();

        String toHash = txPayload
                + payload.getOrDefault("nonce", "")
                + payload.getOrDefault("server_nonce", "");

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = messageDigest.digest(toHash.getBytes(StandardCharsets.UTF_8));
        String hash = Base64.getUrlEncoder().encodeToString(hashBytes);

        hash = hash.replaceAll("^=+", "");
        hash = hash.replaceAll("=+$", "");

        return payload.get("tx_hash").equals(hash);
    }

    /**
     * Waits for a given code
     *
     * @param username The username
     * @param code     The code associated with the username
     * @param codeType The type of the code
     * @return The response body from Code Wait
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public AuthenticationResponse waitCode(String username, String code, String codeType) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        ApiClient apiClient = new ApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setConnectTimeout(3*60*1000);
        apiClient.setReadTimeout(3*60*1000);
        if (this.privateKey == null) {
            String token = generateServiceToken("auth.temporary", null, null, null, null);
            apiClient.setAccessToken(token);
        }

        AuthenticateApi authenticateApi = new AuthenticateApi(apiClient);

        AuthenticateCodeWaitBody authenticateCodeWaitBody = new AuthenticateCodeWaitBody();
        authenticateCodeWaitBody.setClientId(getClientId());
        authenticateCodeWaitBody.setUsername(username);

        AuthenticatecodewaitAuthenticationCode authenticatecodewaitAuthenticationCode = new AuthenticatecodewaitAuthenticationCode();
        authenticatecodewaitAuthenticationCode.setCode(code);
        authenticatecodewaitAuthenticationCode.setType(AuthenticatecodewaitAuthenticationCode.TypeEnum.fromValue(codeType));
        authenticateCodeWaitBody.setAuthenticationCode(authenticatecodewaitAuthenticationCode);

        AuthenticationResponse result = authenticateApi.authenticateCodeWaitPost(authenticateCodeWaitBody, null);
        String jwtToken = result.getJwt();

        if (jwtToken == null || !verifyToken(jwtToken)) {
            throw new SecurityException();
        }

        return result;
    }

    /**
     * Start user login process with cloud biometric verification
     *
     * @param username The username of the user
     * @param credId The uuid of the credential
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public AuthenticateVerifyInitResponse initAuthenticationVerify(String username, String credId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        
        AuthenticateApi authenticateApi = new AuthenticateApi();
        
        ApiClient apiClient = authenticateApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        if (this.privateKey == null) {
            String token = generateServiceToken("auth.login", null, null, null, null);
            apiClient.setAccessToken(token);
        }

        AuthenticateVerifyInitBody authenticateVerifyInitBody = new AuthenticateVerifyInitBody();
        authenticateVerifyInitBody.setClientId(getClientId());
        authenticateVerifyInitBody.setUsername(username);

        AuthenticateVerifyInitOptions authenticateVerifyInitOptions = new AuthenticateVerifyInitOptions();
        authenticateVerifyInitOptions.setCredentialUuid(credId);

        authenticateVerifyInitBody.setOptions(authenticateVerifyInitOptions);

        AuthenticateVerifyInitResponse result = authenticateApi.authenticateAuthidInitPost(authenticateVerifyInitBody, null);
        return result;
    }

    /**
     * Start user login process with authid
     *
     * @param username The username of the user
     * @param credId The uuid of the credential
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public AuthenticationResponse completeAuthenticationVerify(String username, String credID) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        AuthenticateApi authenticateApi = new AuthenticateApi();

        ApiClient apiClient = authenticateApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());

        AuthenticateVerifyCompleteBody authenticateVerifyCompleteBody = new AuthenticateVerifyCompleteBody();
        authenticateVerifyCompleteBody.setClientId(getClientId());
        authenticateVerifyCompleteBody.setUsername(username);
        authenticateVerifyCompleteBody.setCredentialUuid(credID);

        AuthenticationResponse result = authenticateApi.authenticateAuthidCompletePost(authenticateVerifyCompleteBody, null);
        return result;
    }

    /**
     * init user login process with public key
     *
     * @param userId The ID of the user to generate the new recovery code for
     * @param publickeyAlg The encryption algorithm; defaults to ES256
     * @param publickey The publickey used as credential
     * @return The challenge id and nonce
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public AuthenticatePublickeyInitResponse initUserLoginPublickey(String username, String publickeyAlg, String publickey) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        AuthenticateApi authenticateApi = new AuthenticateApi();

        ApiClient apiClient = authenticateApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        if (this.privateKey == null) {
            String token = generateServiceToken("auth.login", null, null, null, null);
            apiClient.setAccessToken(token);
        }

        PublickeyInitBody publickeyInitBody = new PublickeyInitBody();
        publickeyInitBody.setClientId(getClientId());
        publickeyInitBody.setUsername(username);
        publickeyInitBody.setPublickey(publickey);
        if (publickeyAlg.length() > 0) {
            publickeyInitBody.setPublickeyAlg(publickeyAlg);
        } 

        AuthenticatePublickeyInitResponse result = authenticateApi.authenticatePublickeyInitPost(publickeyInitBody);
        return result;
    }

    /**
     * complete user login process with public key
     *
     * @param userId The ID of the user to generate the new recovery code for
     * @param challengeID The temporary generated ID 
     * @param assertion The JWT used for assertion
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public AuthenticationResponse completeUserLoginPublickey(String username, String challengeID, String assertion) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        AuthenticateApi authenticateApi = new AuthenticateApi();

        ApiClient apiClient = authenticateApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());

        PublickeyCompleteBody publickeyCompleteBody = new PublickeyCompleteBody();
        publickeyCompleteBody.setClientId(getClientId());
        publickeyCompleteBody.setUsername(username);
        publickeyCompleteBody.setChallengeId(challengeID);
        publickeyCompleteBody.setAssertion(assertion);

        AuthenticationResponse result = authenticateApi.authenticatePublickeyCompletePost(publickeyCompleteBody);
        return result;
    }
}
