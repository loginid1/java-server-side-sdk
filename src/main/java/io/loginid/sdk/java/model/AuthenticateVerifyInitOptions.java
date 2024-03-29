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
 * AuthenticateauthidinitOptions
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2022-01-25T11:19:57.896818-05:00[America/Toronto]")
public class AuthenticateVerifyInitOptions {
  @SerializedName("credential_uuid")
  private String credentialUuid = null;

  public AuthenticateVerifyInitOptions credentialUuid(String credentialUuid) {
    this.credentialUuid = credentialUuid;
    return this;
  }

   /**
   * Get credentialUuid
   * @return credentialUuid
  **/
  @Schema(description = "")
  public String getCredentialUuid() {
    return credentialUuid;
  }

  public void setCredentialUuid(String credentialUuid) {
    this.credentialUuid = credentialUuid;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticateVerifyInitOptions authenticateauthidinitOptions = (AuthenticateVerifyInitOptions) o;
    return Objects.equals(this.credentialUuid, authenticateauthidinitOptions.credentialUuid);
  }

  @Override
  public int hashCode() {
    return Objects.hash(credentialUuid);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticateauthidinitOptions {\n");
    
    sb.append("    credentialUuid: ").append(toIndentedString(credentialUuid)).append("\n");
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
