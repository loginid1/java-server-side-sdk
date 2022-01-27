/*
 * LoginID Service API
 * # Introduction  <span class=\"subtext\"> Welcome to the LoginID API docs. This documentation will help understand the API calls being made behind our SDKs.  These APIs can be used to manage authentication, users, and user credentials. </span>  # Authentication  <span class=\"subtext\"> There is one main form of authentication for the API: <br/>&bull; API Service Token </span> 
 *
 * OpenAPI spec version: 0.1.0
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */

package io.loginid.sdk.java.model;

import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Objects;
/**
 * InlineResponse20022
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2022-01-25T11:19:57.896818-05:00[America/Toronto]")
public class CredentialsProofEvaluateResponse {
  @SerializedName("result_url")
  private String resultUrl = null;

  @SerializedName("token_type")
  private String tokenType = null;

  @SerializedName("auth_token")
  private String authToken = null;

  public CredentialsProofEvaluateResponse resultUrl(String resultUrl) {
    this.resultUrl = resultUrl;
    return this;
  }

   /**
   * Get resultUrl
   * @return resultUrl
  **/
  @Schema(example = "https://...", description = "")
  public String getResultUrl() {
    return resultUrl;
  }

  public void setResultUrl(String resultUrl) {
    this.resultUrl = resultUrl;
  }

  public CredentialsProofEvaluateResponse tokenType(String tokenType) {
    this.tokenType = tokenType;
    return this;
  }

   /**
   * Get tokenType
   * @return tokenType
  **/
  @Schema(example = "Bearer", description = "")
  public String getTokenType() {
    return tokenType;
  }

  public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
  }

  public CredentialsProofEvaluateResponse authToken(String authToken) {
    this.authToken = authToken;
    return this;
  }

   /**
   * Get authToken
   * @return authToken
  **/
  @Schema(example = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZ....", description = "")
  public String getAuthToken() {
    return authToken;
  }

  public void setAuthToken(String authToken) {
    this.authToken = authToken;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CredentialsProofEvaluateResponse credentialsProofEvaluateResponse = (CredentialsProofEvaluateResponse) o;
    return Objects.equals(this.resultUrl, credentialsProofEvaluateResponse.resultUrl) &&
        Objects.equals(this.tokenType, credentialsProofEvaluateResponse.tokenType) &&
        Objects.equals(this.authToken, credentialsProofEvaluateResponse.authToken);
  }

  @Override
  public int hashCode() {
    return Objects.hash(resultUrl, tokenType, authToken);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CredentialsVerifyEvaluateResponse {\n");
    
    sb.append("    resultUrl: ").append(toIndentedString(resultUrl)).append("\n");
    sb.append("    tokenType: ").append(toIndentedString(tokenType)).append("\n");
    sb.append("    authToken: ").append(toIndentedString(authToken)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}
