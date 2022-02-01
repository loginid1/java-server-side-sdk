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
 * PublickeyCompleteBody
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2022-01-25T11:19:57.896818-05:00[America/Toronto]")
public class PublickeyCompleteBody {
  @SerializedName("client_id")
  private String clientId = null;

  @SerializedName("username")
  private String username = null;

  @SerializedName("challenge_id")
  private String challengeId = null;

  @SerializedName("assertion")
  private String assertion = null;

  @SerializedName("no_jwt")
  private Boolean noJwt = false;

  public PublickeyCompleteBody clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

   /**
   * Get clientId
   * @return clientId
  **/
  @Schema(example = "[client ID]", description = "")
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public PublickeyCompleteBody username(String username) {
    this.username = username;
    return this;
  }

   /**
   * Get username
   * @return username
  **/
  @Schema(example = "[username]", description = "")
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public PublickeyCompleteBody challengeId(String challengeId) {
    this.challengeId = challengeId;
    return this;
  }

   /**
   * Get challengeId
   * @return challengeId
  **/
  @Schema(example = "[temporary unique id]", description = "")
  public String getChallengeId() {
    return challengeId;
  }

  public void setChallengeId(String challengeId) {
    this.challengeId = challengeId;
  }

  public PublickeyCompleteBody assertion(String assertion) {
    this.assertion = assertion;
    return this;
  }

   /**
   * Get assertion
   * @return assertion
  **/
  @Schema(example = "[JWT string]", description = "")
  public String getAssertion() {
    return assertion;
  }

  public void setAssertion(String assertion) {
    this.assertion = assertion;
  }

  public PublickeyCompleteBody noJwt(Boolean noJwt) {
    this.noJwt = noJwt;
    return this;
  }

   /**
   * Get noJwt
   * @return noJwt
  **/
  @Schema(description = "")
  public Boolean isNoJwt() {
    return noJwt;
  }

  public void setNoJwt(Boolean noJwt) {
    this.noJwt = noJwt;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PublickeyCompleteBody publickeyCompleteBody = (PublickeyCompleteBody) o;
    return Objects.equals(this.clientId, publickeyCompleteBody.clientId) &&
        Objects.equals(this.username, publickeyCompleteBody.username) &&
        Objects.equals(this.challengeId, publickeyCompleteBody.challengeId) &&
        Objects.equals(this.assertion, publickeyCompleteBody.assertion) &&
        Objects.equals(this.noJwt, publickeyCompleteBody.noJwt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId, username, challengeId, assertion, noJwt);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PublickeyCompleteBody {\n");
    
    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    username: ").append(toIndentedString(username)).append("\n");
    sb.append("    challengeId: ").append(toIndentedString(challengeId)).append("\n");
    sb.append("    assertion: ").append(toIndentedString(assertion)).append("\n");
    sb.append("    noJwt: ").append(toIndentedString(noJwt)).append("\n");
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