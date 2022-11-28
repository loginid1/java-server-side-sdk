package io.loginid.sdk.java;

import io.jsonwebtoken.security.InvalidKeyException;
import io.loginid.sdk.java.api.CodesApi;
import io.loginid.sdk.java.api.CredentialsApi;
import io.loginid.sdk.java.api.ManagementApi;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.ApiException;
import io.loginid.sdk.java.model.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import javax.annotation.Nullable;

@SuppressWarnings("unused")
public class LoginIdManagement extends LoginId {

    public LoginIdManagement(String clientId, String privateKey, String baseUrl) {
        super(clientId, isValidPrivateKey(privateKey), baseUrl);
    }

    public LoginIdManagement(String clientId, String privateKey) {
        super(clientId, isValidPrivateKey(privateKey));
    }
    
    private static String isValidPrivateKey(String privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("missing private key");
        }
        return privateKey;
    }

    /**
     * Returns the user ID based on username
     *
     * @param username The username
     * @return The user ID
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public UUID getUserId(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.retrieve", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        ManageUsersRetrieveBody manageUsersRetrieveBody = new ManageUsersRetrieveBody();
        manageUsersRetrieveBody.setUsername(username);
        UserProfile result = managementApi.manageUsersRetrievePost(getClientId(), manageUsersRetrieveBody);

        return result.getId();
    }

    /**
     * Deletes a user by their username
     *
     * @param username The username to be deleted
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public void deleteByUsername(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        ManageUsersDeleteBody manageUsersDeleteBody = new ManageUsersDeleteBody();
        manageUsersDeleteBody.setUsername(username);
        managementApi.manageUsersDeletePost(getClientId(), manageUsersDeleteBody);
    }

    /**
     * Deletes a user by user ID
     *
     * @param userId The user ID to be deleted
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public void deleteByUserId(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        managementApi.manageUsersUserIdDelete(getClientId(), userId);
    }

    /**
     * Activates a previously deactivated user
     *
     * @param userId The user ID to be activated
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public void activateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.activate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        User result = managementApi.manageUsersUserIdActivatePut(getClientId(), userId);
    }

    /**
     * Deactivates a currently active user
     *
     * @param userId The user ID to be deactivated
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public void deactivateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.deactivate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        User result = managementApi.manageUsersUserIdDeactivatePut(getClientId(), userId);
    }

    /**
     * Generate a code
     *
     * @param userId       The user ID for the code
     * @param codeType     The code type
     * @param codePurpose  The purpose of the code
     * @param isAuthorized Indicates if the code authorizes the user or not
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    public CodesCodeTypeGenerateResponse generateCode(String userId, String codeType, String codePurpose, boolean isAuthorized) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("codes.generate", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeGenerateBody codesCodeTypeGenerateBody = new CodesCodeTypeGenerateBody();
        codesCodeTypeGenerateBody.setClientId(getClientId());
        codesCodeTypeGenerateBody.setUserId(userId);
        codesCodeTypeGenerateBody.setPurpose(CodesCodeTypeGenerateBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeGenerateBody.setAuthorize(isAuthorized);

        return codesApi.codesCodeTypeGeneratePost(codeType, codesCodeTypeGenerateBody, null);
    }

    /**
     * Generate a code. Either `userId` or `username` must be present.
     *
     * @param userId       (Nullable) The user ID for the code
     * @param username     (Nullable) The username for the code
     * @param codeType     The code type
     * @param codePurpose  The purpose of the code
     * @param isAuthorized Indicates if the code authorizes the user or not
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public CodesCodeTypeGenerateResponse generateCode(@Nullable String userId, @Nullable String username, String codeType, String codePurpose, boolean isAuthorized) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("codes.generate", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeGenerateBody codesCodeTypeGenerateBody = new CodesCodeTypeGenerateBody();
        codesCodeTypeGenerateBody.setClientId(getClientId());
        codesCodeTypeGenerateBody.setPurpose(CodesCodeTypeGenerateBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeGenerateBody.setAuthorize(isAuthorized);
        if (!this.isNullOrEmpty(userId)) {
            codesCodeTypeGenerateBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            codesCodeTypeGenerateBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }
        
        return codesApi.codesCodeTypeGeneratePost(codeType, codesCodeTypeGenerateBody, null);
    }

    /**
     * Authorizes a given code
     *
     * @param userId      The user ID associated with the code
     * @param code        The code that needs authorization
     * @param codeType    The type of the code
     * @param codePurpose The purpose of the code
     * @return The response body from code authorization
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    public CodesCodeTypeAuthorizeResponse authorizeCode(String userId, String code, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.authorize", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeAuthorizeBody codesCodeTypeAuthorizeBody = new CodesCodeTypeAuthorizeBody();

        codesCodeTypeAuthorizeBody.setClientId(getClientId());
        codesCodeTypeAuthorizeBody.setUserId(userId);
        codesCodeTypeAuthorizeBody.setPurpose(CodesCodeTypeAuthorizeBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeAuthorizeBody.setCode(code);

        return codesApi.codesCodeTypeAuthorizePost(codeType, codesCodeTypeAuthorizeBody, null);
    }

    /**
     * Authorizes a given code
     *
     * @param userId      (Nullable) The user ID associated with the code
     * @param username    (Nullable) The user ID associated with the code
     * @param code        The code that needs authorization
     * @param codeType    The type of the code
     * @param codePurpose The purpose of the code
     * @return The response body from code authorization
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public CodesCodeTypeAuthorizeResponse authorizeCode(@Nullable String userId, @Nullable String username, String code, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.authorize", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeAuthorizeBody codesCodeTypeAuthorizeBody = new CodesCodeTypeAuthorizeBody();

        codesCodeTypeAuthorizeBody.setClientId(getClientId());
        codesCodeTypeAuthorizeBody.setPurpose(CodesCodeTypeAuthorizeBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeAuthorizeBody.setCode(code);
        if (!this.isNullOrEmpty(userId)) {
            codesCodeTypeAuthorizeBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            codesCodeTypeAuthorizeBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        return codesApi.codesCodeTypeAuthorizePost(codeType, codesCodeTypeAuthorizeBody, null);
    }

    /**
     * Invalidates all authentication codes of given type and purpose for given user
     *
     * @param userId      The user ID
     * @param codeType    The code type
     * @param codePurpose The purpose of the code
     * @return The response body from invalidating all codes
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    public CodesCodeTypeInvalidateAllResponse invalidateAllCodes(String userId, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.invalidate", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeInvalidateAllBody codesCodeTypeInvalidateAllBody = new CodesCodeTypeInvalidateAllBody();
        codesCodeTypeInvalidateAllBody.setClientId(getClientId());
        codesCodeTypeInvalidateAllBody.setPurpose(CodesCodeTypeInvalidateAllBody.PurposeEnum.fromValue(codePurpose));
        codesCodeTypeInvalidateAllBody.setUserId(userId);

        return codesApi.codesCodeTypeInvalidateAllPost(codeType, codesCodeTypeInvalidateAllBody, null);
    }

    /**
     * Invalidates all authentication codes of given type and purpose for given user. Either `userId` or `username` must be present.
     *
     * @param userId      (Nullable) The user ID
     * @param username    (Nullable) The username
     * @param codeType    The code type
     * @param codePurpose The purpose of the code
     * @return The response body from invalidating all codes
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public CodesCodeTypeInvalidateAllResponse invalidateAllCodes(@Nullable String userId, @Nullable String username, String codeType, String codePurpose) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        if (!isValidCodeType(codeType)) {
            throw new IllegalArgumentException();
        }

        String token = generateServiceToken("codes.invalidate", null, null, null, null);

        CodesApi codesApi = new CodesApi();

        ApiClient apiClient = codesApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CodesCodeTypeInvalidateAllBody codesCodeTypeInvalidateAllBody = new CodesCodeTypeInvalidateAllBody();
        codesCodeTypeInvalidateAllBody.setClientId(getClientId());
        codesCodeTypeInvalidateAllBody.setPurpose(CodesCodeTypeInvalidateAllBody.PurposeEnum.fromValue(codePurpose));
        if (!this.isNullOrEmpty(userId)) {
            codesCodeTypeInvalidateAllBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            codesCodeTypeInvalidateAllBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        return codesApi.codesCodeTypeInvalidateAllPost(codeType, codesCodeTypeInvalidateAllBody, null);
    }

    /**
     * Returns an exhaustive list of credentials for a given user
     *
     * @param userId The user ID of the end user whose list of credentials are required
     * @return User's credentials
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsResponse getCredentials(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.list", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsListBody credentialsListBody = new CredentialsListBody();
        credentialsListBody.setClientId(getClientId());
        credentialsListBody.setUserId(userId);

        CredentialsResponse result = credentialsApi.credentialsListPost(credentialsListBody, null);
        return result;
    }

    /**
     * Returns an exhaustive list of credentials for a given user. Either `userId` or `username` must be present.
     *
     * @param userId   (Nullable) The user ID of the end user whose list of credentials are required
     * @param username (Nullable) The username of the end user whose list of credentials are required
     * @return User's credentials
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsResponse getCredentials(@Nullable String userId, @Nullable String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.list", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsListBody credentialsListBody = new CredentialsListBody();
        credentialsListBody.setClientId(getClientId());
        if (!this.isNullOrEmpty(userId)) {
            credentialsListBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            credentialsListBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        CredentialsResponse result = credentialsApi.credentialsListPost(credentialsListBody, null);
        return result;
    }

    /**
     * add a public key as a credential. Either `userId` or `username` must be present.
     *
     * @param userId         (Nullable) The user ID of the end user
     * @param username       (Nullable) The username of the end user
     * @param publickeyAlg   The algorithm the public key is verified against, defaults to ES256
     * @param publickey The  base64 encoded public key
     * @param credentialName Optional name of credential
     * @return User's credentials
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    public AuthenticationResponse addPublicKeyCredential(@Nullable String userId, @Nullable String username, String publickeyAlg, String publickey, String credentialName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.force_add", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsPublickeyBody credentialsPublickeyBody = new CredentialsPublickeyBody();
        credentialsPublickeyBody.setClientId(getClientId());
        if (!this.isNullOrEmpty(userId)) {
            credentialsPublickeyBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            credentialsPublickeyBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        credentialsPublickeyBody.setPublickey(publickey);
        if (publickeyAlg.length() > 0) {
            credentialsPublickeyBody.setPublickeyAlg(publickeyAlg);
        }

        CredentialsPublickeyOptions credentialsPublickeyOptions = new CredentialsPublickeyOptions();
        credentialsPublickeyOptions.setCredentialName(credentialName);

        AuthenticationResponse result = credentialsApi.credentialsPublickeyPost(credentialsPublickeyBody);
        return result;
    }

    /**
     * Renames the credential of a user
     *
     * @param userId      The ID of the user
     * @param credId      The ID of the credential to be renamed
     * @param updatedName The new name
     * @return The renamed credential's details
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsChangeResponse renameCredential(String userId, String credId, String updatedName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.rename", null, null, null, null);
        
        CredentialsApi credentialsApi = new CredentialsApi();
        
        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);
        
        CredentialsRenameBody credentialsRenameBody = new CredentialsRenameBody();
        credentialsRenameBody.setClientId(getClientId());
        credentialsRenameBody.setUserId(userId);
        
        CredentialsrenameCredential credentialsrenameCredential = new CredentialsrenameCredential();
        credentialsrenameCredential.setName(updatedName);
        credentialsrenameCredential.setUuid(credId);
        
        credentialsRenameBody.setCredential(credentialsrenameCredential);
        
        CredentialsChangeResponse result = credentialsApi.credentialsRenamePost(credentialsRenameBody, null);
        return result;
    }

    /**
     * Renames the credential of a user. Either `userId` or `username` must be present.
     *
     * @param userId      (Nullable) The ID of the user
     * @param username    (Nullable) The username of the user
     * @param credId      The ID of the credential to be renamed
     * @param updatedName The new name
     * @return The renamed credential's details
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsChangeResponse renameCredential(@Nullable String userId, @Nullable String username, String credId, String updatedName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.rename", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsRenameBody credentialsRenameBody = new CredentialsRenameBody();
        credentialsRenameBody.setClientId(getClientId());
        if (!this.isNullOrEmpty(userId)) {
            credentialsRenameBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            credentialsRenameBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        CredentialsrenameCredential credentialsrenameCredential = new CredentialsrenameCredential();
        credentialsrenameCredential.setName(updatedName);
        credentialsrenameCredential.setUuid(credId);

        credentialsRenameBody.setCredential(credentialsrenameCredential);

        CredentialsChangeResponse result = credentialsApi.credentialsRenamePost(credentialsRenameBody, null);
        return result;
    }

    /**
     * Revokes an existing credential from a user
     *
     * @param userId The user ID to extract the credential
     * @param credId The credential ID to be revoked
     * @return The revoked credential's details
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @Deprecated
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsChangeResponse revokeCredential(String userId, String credId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.revoke", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsRevokeBody credentialsRevokeBody = new CredentialsRevokeBody();
        credentialsRevokeBody.setClientId(getClientId());
        credentialsRevokeBody.setUserId(userId);

        CredentialsrevokeCredential credentialsrevokeCredential = new CredentialsrevokeCredential();
        credentialsrevokeCredential.setUuid(credId);

        credentialsRevokeBody.setCredential(credentialsrevokeCredential);

        CredentialsChangeResponse result = credentialsApi.credentialsRevokePost(credentialsRevokeBody, null);
        return result;
    }

    /**
     * Revokes an existing credential from a user. Either `userId` or `username` must be present.
     *
     * @param userId   (Nullable) The user ID to extract the credential
     * @param username (Nullable) The username to extract the credential
     * @param credId The credential ID to be revoked
     * @return The revoked credential's details
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsChangeResponse revokeCredential(@Nullable String userId, @Nullable String username, String credId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.revoke", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsRevokeBody credentialsRevokeBody = new CredentialsRevokeBody();
        credentialsRevokeBody.setClientId(getClientId());
        if (!this.isNullOrEmpty(userId)) {
            credentialsRevokeBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            credentialsRevokeBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        CredentialsrevokeCredential credentialsrevokeCredential = new CredentialsrevokeCredential();
        credentialsrevokeCredential.setUuid(credId);

        credentialsRevokeBody.setCredential(credentialsrevokeCredential);

        CredentialsChangeResponse result = credentialsApi.credentialsRevokePost(credentialsRevokeBody, null);
        return result;
    }

    /**
     * Adds a new user without credentials. The new user can create new credentials with recovery flow
     *
     * @param username The username of the new user
     * @return The new user's profile
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    public UserProfile createUserWithoutCredentials(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.create", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();

        ApiClient apiClient = managementApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        ManageUsersBody manageUsersBody = new ManageUsersBody();
        manageUsersBody.setUsername(username);

        UserProfile result = managementApi.manageUsersPost(getClientId(), manageUsersBody, null);
        return result;
    }

    /**
     * Add a credential without pre-generated authorization code
     *
     * @param userId The ID of the user to add the new credential for
     * @return The attestation payload for the new credential
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public CredentialsFido2InitForceResponse initAddCredentialWithoutCode(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.force_add", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsFido2InitForceBody credentialsFido2InitForceBody = new CredentialsFido2InitForceBody();
        credentialsFido2InitForceBody.setClientId(getClientId());
        credentialsFido2InitForceBody.setUserId(userId);

        CredentialsFido2InitForceResponse result = credentialsApi.credentialsFido2InitForcePost(credentialsFido2InitForceBody,null);
        return result;
    }

    /**
     * Generate a recovery code. Either `userId` or `username` must be present.
     *
     * @param userId   (Nullable) The ID of the user to generate the new recovery code for
     * @param username (Nullable) The userName of the user to generate the new recovery code for
     * @return The response body from the code generation request
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public CredentialsRecoverycodeResponse generateRecoveryCode(@Nullable String userId, @Nullable String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.add_recovery", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();

        ApiClient apiClient = credentialsApi.getApiClient();
        apiClient.setBasePath(getBaseUrl());
        apiClient.setAccessToken(token);

        CredentialsRecoverycodeBody credentialsRecoverycodeBody = new CredentialsRecoverycodeBody();
        credentialsRecoverycodeBody.setClientId(getClientId());
        if (!this.isNullOrEmpty(userId)) {
            credentialsRecoverycodeBody.setUserId(userId);
        } else if (!this.isNullOrEmpty(username)) {
            credentialsRecoverycodeBody.setUsername(username);
        } else {
            throw new ApiException("Missing the required parameter 'userId' or 'username'");
        }

        CredentialsRecoverycodeResponse result = credentialsApi.credentialsRecoveryCodePost(credentialsRecoverycodeBody,null);
        return result;
    }
}
