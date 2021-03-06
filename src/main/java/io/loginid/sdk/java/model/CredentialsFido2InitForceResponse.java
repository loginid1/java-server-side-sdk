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
 * InlineResponse20014
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-07-06T19:49:38.774Z[GMT]")
public class CredentialsFido2InitForceResponse {
  @SerializedName("attestation_payload")
  private InlineResponse200AttestationPayload attestationPayload = null;

  public CredentialsFido2InitForceResponse attestationPayload(InlineResponse200AttestationPayload attestationPayload) {
    this.attestationPayload = attestationPayload;
    return this;
  }

   /**
   * Get attestationPayload
   * @return attestationPayload
  **/
  @Schema(required = true, description = "")
  public InlineResponse200AttestationPayload getAttestationPayload() {
    return attestationPayload;
  }

  public void setAttestationPayload(InlineResponse200AttestationPayload attestationPayload) {
    this.attestationPayload = attestationPayload;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CredentialsFido2InitForceResponse credentialsFido2InitForceResponse = (CredentialsFido2InitForceResponse) o;
    return Objects.equals(this.attestationPayload, credentialsFido2InitForceResponse.attestationPayload);
  }

  @Override
  public int hashCode() {
    return Objects.hash(attestationPayload);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class InlineResponse20014 {\n");
    
    sb.append("    attestationPayload: ").append(toIndentedString(attestationPayload)).append("\n");
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
