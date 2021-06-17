package io.loginid.sdk.java;

import io.loginid.sdk.java.api.CredentialsApi;
import io.loginid.sdk.java.api.ManagementApi;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.ApiException;
import io.loginid.sdk.java.model.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

@SuppressWarnings("unused")
public class LoginIdManagement extends LoginId {

    public LoginIdManagement(String clientId, String privateKey, String baseUrl) {
        super(clientId, privateKey, baseUrl);
    }

    /**
     * Returns the user ID based on username
     *
     * @param userName The username
     * @return The user ID
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    public UUID getUserId(String userName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.retrieve", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ManageUsersRetrieveBody manageUsersRetrieveBody = new ManageUsersRetrieveBody();
        manageUsersRetrieveBody.setUsername(userName);
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

        apiClient.setAccessToken(token);

        User result = managementApi.manageUsersUserIdDeactivatePut(getClientId(), userId);
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
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsResponse getCredentials(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.list", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();
        ApiClient apiClient = credentialsApi.getApiClient();

        apiClient.setAccessToken(token);

        CredentialsResponse result = credentialsApi.credentialsGet(UUID.fromString(userId), getClientId(), null);
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
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsRenameRevokeResponse renameCredential(String userId, String credId, String updatedName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.rename", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();
        ApiClient apiClient = credentialsApi.getApiClient();

        apiClient.setAccessToken(token);

        CredentialsRenameBody credentialsRenameBody = new CredentialsRenameBody();
        credentialsRenameBody.setClientId(getClientId());
        credentialsRenameBody.setUserId(userId);

        CredentialsrenameCredential credentialsrenameCredential = new CredentialsrenameCredential();
        credentialsrenameCredential.setName(updatedName);
        credentialsrenameCredential.setUuid(credId);

        credentialsRenameBody.setCredential(credentialsrenameCredential);

        CredentialsRenameRevokeResponse result = credentialsApi.credentialsRenamePost(credentialsRenameBody, null);
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
    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsRenameRevokeResponse revokeCredential(String userId, String credId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.revoke", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();
        ApiClient apiClient = credentialsApi.getApiClient();

        apiClient.setAccessToken(token);

        CredentialsRevokeBody credentialsRevokeBody = new CredentialsRevokeBody();
        credentialsRevokeBody.setClientId(getClientId());
        credentialsRevokeBody.setUserId(userId);

        CredentialsrevokeCredential credentialsrevokeCredential = new CredentialsrevokeCredential();
        credentialsrevokeCredential.setUuid(credId);

        credentialsRevokeBody.setCredential(credentialsrevokeCredential);

        CredentialsRenameRevokeResponse result = credentialsApi.credentialsRevokePost(credentialsRevokeBody, null);
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
    public UserProfile addUserWithoutCredentials(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.create", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ManageUsersBody manageUsersBody = new ManageUsersBody();
        manageUsersBody.setUsername(username);

        UserProfile result = managementApi.manageUsersPost(getClientId(), manageUsersBody, null);
        return result;
    }
}
