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

import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.v3.oas.annotations.media.Schema;

import java.io.IOException;
import java.util.Objects;

/**
 * CodeTypeGenerateBody
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-10T08:30:05.952Z[GMT]")
public class CodesCodeTypeGenerateBody {
  @SerializedName("client_id")
  private String clientId = null;

  @SerializedName("user_id")
  private String userId = null;

  /**
   * Gets or Sets purpose
   */
  @JsonAdapter(PurposeEnum.Adapter.class)
  public enum PurposeEnum {
    ADD_CREDENTIAL("add_credential"),
    TEMPORARY_AUTHENTICATION("temporary_authentication");

    private String value;

    PurposeEnum(String value) {
      this.value = value;
    }
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
    public static PurposeEnum fromValue(String text) {
      for (PurposeEnum b : PurposeEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
    public static class Adapter extends TypeAdapter<PurposeEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final PurposeEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public PurposeEnum read(final JsonReader jsonReader) throws IOException {
        Object value = jsonReader.nextString();
        return PurposeEnum.fromValue(String.valueOf(value));
      }
    }
  }  @SerializedName("purpose")
  private PurposeEnum purpose = null;

  @SerializedName("authorize")
  private Boolean authorize = null;

  public CodesCodeTypeGenerateBody clientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

   /**
   * Get clientId
   * @return clientId
  **/
  @Schema(description = "")
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public CodesCodeTypeGenerateBody userId(String userId) {
    this.userId = userId;
    return this;
  }

   /**
   * Get userId
   * @return userId
  **/
  @Schema(description = "")
  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public CodesCodeTypeGenerateBody purpose(PurposeEnum purpose) {
    this.purpose = purpose;
    return this;
  }

   /**
   * Get purpose
   * @return purpose
  **/
  @Schema(description = "")
  public PurposeEnum getPurpose() {
    return purpose;
  }

  public void setPurpose(PurposeEnum purpose) {
    this.purpose = purpose;
  }

  public CodesCodeTypeGenerateBody authorize(Boolean authorize) {
    this.authorize = authorize;
    return this;
  }

   /**
   * Get authorize
   * @return authorize
  **/
  @Schema(description = "")
  public Boolean isAuthorize() {
    return authorize;
  }

  public void setAuthorize(Boolean authorize) {
    this.authorize = authorize;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CodesCodeTypeGenerateBody codesCodeTypeGenerateBody = (CodesCodeTypeGenerateBody) o;
    return Objects.equals(this.clientId, codesCodeTypeGenerateBody.clientId) &&
        Objects.equals(this.userId, codesCodeTypeGenerateBody.userId) &&
        Objects.equals(this.purpose, codesCodeTypeGenerateBody.purpose) &&
        Objects.equals(this.authorize, codesCodeTypeGenerateBody.authorize);
  }

  @Override
  public int hashCode() {
    return Objects.hash(clientId, userId, purpose, authorize);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CodeTypeGenerateBody {\n");

    sb.append("    clientId: ").append(toIndentedString(clientId)).append("\n");
    sb.append("    userId: ").append(toIndentedString(userId)).append("\n");
    sb.append("    purpose: ").append(toIndentedString(purpose)).append("\n");
    sb.append("    authorize: ").append(toIndentedString(authorize)).append("\n");
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