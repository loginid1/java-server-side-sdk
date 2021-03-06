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
public class Registerfido2initOptions {
  @SerializedName("register_session")
  private String registerSession = null;

  @SerializedName("ipsidy_account")
  private String ipsidyAccount = null;

  @SerializedName("invitation")
  private Invitation invitation = null;

  public Registerfido2initOptions registerSession(String registerSession) {
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

  public Registerfido2initOptions ipsidyAccount(String ipsidyAccount) {
    this.ipsidyAccount = ipsidyAccount;
    return this;
  }

   /**
   * Get ipsidyAccount
   * @return ipsidyAccount
  **/
  @Schema(description = "")
  public String getIpsidyAccount() {
    return ipsidyAccount;
  }

  public void setIpsidyAccount(String ipsidyAccount) {
    this.ipsidyAccount = ipsidyAccount;
  }

  public Registerfido2initOptions invitation(Invitation invitation) {
    this.invitation = invitation;
    return this;
  }

   /**
   * Get invitation
   * @return invitation
  **/
  @Schema(description = "")
  public Invitation getInvitation() {
    return invitation;
  }

  public void setInvitation(Invitation invitation) {
    this.invitation = invitation;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Registerfido2initOptions registerfido2initOptions = (Registerfido2initOptions) o;
    return Objects.equals(this.registerSession, registerfido2initOptions.registerSession) &&
        Objects.equals(this.ipsidyAccount, registerfido2initOptions.ipsidyAccount) &&
        Objects.equals(this.invitation, registerfido2initOptions.invitation);
  }

  @Override
  public int hashCode() {
    return Objects.hash(registerSession, ipsidyAccount, invitation);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Registerfido2initOptions {\n");

    sb.append("    registerSession: ").append(toIndentedString(registerSession)).append("\n");
    sb.append("    ipsidyAccount: ").append(toIndentedString(ipsidyAccount)).append("\n");
    sb.append("    invitation: ").append(toIndentedString(invitation)).append("\n");
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
