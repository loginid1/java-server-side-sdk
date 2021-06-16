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

    public void deleteByUsername(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ManageUsersDeleteBody manageUsersDeleteBody = new ManageUsersDeleteBody();
        manageUsersDeleteBody.setUsername(username);
        managementApi.manageUsersDeletePost(getClientId(), manageUsersDeleteBody);
    }

    public void deleteByUserId(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        managementApi.manageUsersUserIdDelete(getClientId(), userId);
    }

    public void activateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.activate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        User result = managementApi.manageUsersUserIdActivatePut(getClientId(), userId);
    }

    public void deactivateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.deactivate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        User result = managementApi.manageUsersUserIdDeactivatePut(getClientId(), userId);
    }

    @SuppressWarnings("UnnecessaryLocalVariable")
    public CredentialsResponse getCredentials(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.list", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();
        ApiClient apiClient = credentialsApi.getApiClient();

        apiClient.setAccessToken(token);

        CredentialsResponse result = credentialsApi.credentialsGet(UUID.fromString(userId), getClientId(), null);
        return result;
    }

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
