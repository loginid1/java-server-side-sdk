package io.loginid.sdk.java;

import io.loginid.sdk.java.api.CredentialsApi;
import io.loginid.sdk.java.api.ManagementApi;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.ApiException;
import io.loginid.sdk.java.invokers.ApiResponse;
import io.loginid.sdk.java.model.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

public class LoginIdManagement extends LoginId {

    public LoginIdManagement(String clientId, String privateKey, String baseUrl) {
        super(clientId, privateKey, baseUrl);
    }

    public UUID getUserId(String userName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.retrieve", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        UsersRetrieveBody usersRetrieveBody = new UsersRetrieveBody();
        usersRetrieveBody.setUsername(userName);
        ApiResponse<UserProfile> result = managementApi.manageUsersRetrievePostWithHttpInfo(getClientId(), usersRetrieveBody);

        return result.getData().getId();
    }

    public void deleteByUsername(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        UsersDeleteBody usersDeleteBody = new UsersDeleteBody();
        usersDeleteBody.setUsername(username);
        ApiResponse<Void> result = managementApi.manageUsersDeletePostWithHttpInfo(getClientId(), usersDeleteBody);
    }

    public void deleteByUserId(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.delete", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ApiResponse<Void> result = managementApi.manageUsersUserIdDeleteWithHttpInfo(getClientId(), userId);
    }

    public void activateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.activate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ApiResponse<User> result = managementApi.manageUsersUserIdActivatePutWithHttpInfo(getClientId(), userId);
    }

    public void deactivateUserById(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.deactivate", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ApiResponse<User> result = managementApi.manageUsersUserIdDeactivatePutWithHttpInfo(getClientId(), userId);
    }

    public ApiResponse<CredentialsResponse> getCredentials(String userId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("credentials.list", null, null, null, null);

        CredentialsApi credentialsApi = new CredentialsApi();
        ApiClient apiClient = credentialsApi.getApiClient();

        apiClient.setAccessToken(token);

        ApiResponse<CredentialsResponse> result = credentialsApi.credentialsGetWithHttpInfo(UUID.fromString(userId), getClientId(), null);

        return result;
    }

    public ApiResponse<CredentialsRenameRevokeResponse> renameCredential(String userId, String credId, String updatedName) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
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

        ApiResponse<CredentialsRenameRevokeResponse> result = credentialsApi.credentialsRenamePostWithHttpInfo(credentialsRenameBody, null);

        return result;
    }


    public ApiResponse<CredentialsRenameRevokeResponse> revokeCredential(String userId, String credId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
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

        ApiResponse<CredentialsRenameRevokeResponse> result = credentialsApi.credentialsRevokePostWithHttpInfo(credentialsRevokeBody, null);

        return result;
    }

    public ApiResponse<UserProfile> addUserWithoutCredentials(String username) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String token = generateServiceToken("users.create", null, null, null, null);

        ManagementApi managementApi = new ManagementApi();
        ApiClient apiClient = managementApi.getApiClient();

        apiClient.setAccessToken(token);

        ManageUsersBody manageUsersBody = new ManageUsersBody();
        manageUsersBody.setUsername(username);

        ApiResponse<UserProfile> result = managementApi.manageUsersPostWithHttpInfo(getClientId(), manageUsersBody, null);

        return result;
    }
}
