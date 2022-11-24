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
 * Registerfido2initOptions
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-10T08:30:05.952Z[GMT]")
public class RegisterFido2InitOptions {
  @SerializedName("register_session")
  private String registerSession = null;

  @SerializedName("display_name")
  private String displayName = null;

  @SerializedName("override_name")
  private String overrideName = null;

  @SerializedName("roaming_authenticator")
  private Boolean roamingAuthenticator = false;

  public RegisterFido2InitOptions registerSession(String registerSession) {
    this.registerSession = registerSession;
    return this;
  }

   /**
   * Get registerSession
   * @return registerSession
  **/
  @Schema(description = "")
  public String getRegisterSession() {
    return registerSession;
  }

  public void setRegisterSession(String registerSession) {
    this.registerSession = registerSession;
  }

  public RegisterFido2InitOptions displayName(String displayName) {
    this.displayName = displayName;
    return this;
  }

   /**
   * Get displayName
   * @return displayName
  **/
  @Schema(description = "")
  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public RegisterFido2InitOptions overrideName(String overrideName) {
    this.overrideName = overrideName;
    return this;
  }

   /**
   * Get overrideName
   * @return overrideName
  **/
  @Schema(description = "")
  public String getOverrideName() {
    return overrideName;
  }

  public void setOverrideName(String overrideName) {
    this.overrideName = overrideName;
  }

  public RegisterFido2InitOptions roamingAuthenticator(Boolean roamingAuthenticator) {
    this.roamingAuthenticator = roamingAuthenticator;
    return this;
  }

  /**
   * Get overrideName
   * @return overrideName
   **/
  @Schema(description = "")
  public Boolean getRoamingAuthenticator() {
    return roamingAuthenticator;
  }

  public void setRoamingAuthenticator(Boolean roamingAuthenticator) {
    this.roamingAuthenticator = roamingAuthenticator;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RegisterFido2InitOptions options = (RegisterFido2InitOptions) o;
    return Objects.equals(this.registerSession, options.registerSession) &&
        Objects.equals(this.displayName, options.displayName) &&
        Objects.equals(this.overrideName, options.overrideName) &&
        Objects.equals(this.roamingAuthenticator, options.roamingAuthenticator);
  }

  @Override
  public int hashCode() {
    return Objects.hash(registerSession, displayName, overrideName, roamingAuthenticator);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Registerfido2initOptions {\n");

    sb.append("    registerSession: ").append(toIndentedString(registerSession)).append("\n");
    sb.append("    displayName: ").append(toIndentedString(displayName)).append("\n");
    sb.append("    overrideName: ").append(toIndentedString(overrideName)).append("\n");
    sb.append("    roamingAuthenticator: ").append(toIndentedString(roamingAuthenticator)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}