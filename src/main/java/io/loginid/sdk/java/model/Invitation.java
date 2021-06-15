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
 * Invitation
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-10T08:30:05.952Z[GMT]")
public class Invitation {
  @SerializedName("organization_id")
  private String organizationId = null;

  @SerializedName("organization_name")
  private String organizationName = null;

  @SerializedName("correlation_id")
  private String correlationId = null;

  @SerializedName("otp")
  private String otp = null;

  public Invitation organizationId(String organizationId) {
    this.organizationId = organizationId;
    return this;
  }

   /**
   * Get organizationId
   * @return organizationId
  **/
  @Schema(description = "")
  public String getOrganizationId() {
    return organizationId;
  }

  public void setOrganizationId(String organizationId) {
    this.organizationId = organizationId;
  }

  public Invitation organizationName(String organizationName) {
    this.organizationName = organizationName;
    return this;
  }

   /**
   * Get organizationName
   * @return organizationName
  **/
  @Schema(description = "")
  public String getOrganizationName() {
    return organizationName;
  }

  public void setOrganizationName(String organizationName) {
    this.organizationName = organizationName;
  }

  public Invitation correlationId(String correlationId) {
    this.correlationId = correlationId;
    return this;
  }

   /**
   * Get correlationId
   * @return correlationId
  **/
  @Schema(description = "")
  public String getCorrelationId() {
    return correlationId;
  }

  public void setCorrelationId(String correlationId) {
    this.correlationId = correlationId;
  }

  public Invitation otp(String otp) {
    this.otp = otp;
    return this;
  }

   /**
   * Get otp
   * @return otp
  **/
  @Schema(description = "")
  public String getOtp() {
    return otp;
  }

  public void setOtp(String otp) {
    this.otp = otp;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Invitation invitation = (Invitation) o;
    return Objects.equals(this.organizationId, invitation.organizationId) &&
        Objects.equals(this.organizationName, invitation.organizationName) &&
        Objects.equals(this.correlationId, invitation.correlationId) &&
        Objects.equals(this.otp, invitation.otp);
  }

  @Override
  public int hashCode() {
    return Objects.hash(organizationId, organizationName, correlationId, otp);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Invitation {\n");

    sb.append("    organizationId: ").append(toIndentedString(organizationId)).append("\n");
    sb.append("    organizationName: ").append(toIndentedString(organizationName)).append("\n");
    sb.append("    correlationId: ").append(toIndentedString(correlationId)).append("\n");
    sb.append("    otp: ").append(toIndentedString(otp)).append("\n");
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
