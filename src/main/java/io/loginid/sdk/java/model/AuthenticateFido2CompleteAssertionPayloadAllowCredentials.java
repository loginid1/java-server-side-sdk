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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * AuthenticateFido2CompleteAssertionPayloadAllowCredentials
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-10T08:30:05.952Z[GMT]")
public class AuthenticateFido2CompleteAssertionPayloadAllowCredentials {
  @SerializedName("id")
  private String id = null;

  @SerializedName("type")
  private String type = null;

  /**
   * Gets or Sets transports
   */
  @JsonAdapter(TransportsEnum.Adapter.class)
  public enum TransportsEnum {
    USB("usb"),
    NFC("nfc"),
    BLE("ble"),
    INTERNAL("internal");

    private String value;

    TransportsEnum(String value) {
      this.value = value;
    }
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
    public static TransportsEnum fromValue(String text) {
      for (TransportsEnum b : TransportsEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
    public static class Adapter extends TypeAdapter<TransportsEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TransportsEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TransportsEnum read(final JsonReader jsonReader) throws IOException {
        Object value = jsonReader.nextString();
        return TransportsEnum.fromValue(String.valueOf(value));
      }
    }
  }  @SerializedName("transports")
  private List<TransportsEnum> transports = null;

  public AuthenticateFido2CompleteAssertionPayloadAllowCredentials id(String id) {
    this.id = id;
    return this;
  }

   /**
   * Get id
   * @return id
  **/
  @Schema(example = "QwyAKUcyNuSj8AD-Ynqi3lI958KpWs -Y9YptZ9KFGLVidh", description = "")
  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public AuthenticateFido2CompleteAssertionPayloadAllowCredentials type(String type) {
    this.type = type;
    return this;
  }

   /**
   * Get type
   * @return type
  **/
  @Schema(example = "public-key", description = "")
  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public AuthenticateFido2CompleteAssertionPayloadAllowCredentials transports(List<TransportsEnum> transports) {
    this.transports = transports;
    return this;
  }

  public AuthenticateFido2CompleteAssertionPayloadAllowCredentials addTransportsItem(TransportsEnum transportsItem) {
    if (this.transports == null) {
      this.transports = new ArrayList<TransportsEnum>();
    }
    this.transports.add(transportsItem);
    return this;
  }

   /**
   * Get transports
   * @return transports
  **/
  @Schema(description = "")
  public List<TransportsEnum> getTransports() {
    return transports;
  }

  public void setTransports(List<TransportsEnum> transports) {
    this.transports = transports;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticateFido2CompleteAssertionPayloadAllowCredentials authenticateFido2CompleteAssertionPayloadAllowCredentials = (AuthenticateFido2CompleteAssertionPayloadAllowCredentials) o;
    return Objects.equals(this.id, authenticateFido2CompleteAssertionPayloadAllowCredentials.id) &&
        Objects.equals(this.type, authenticateFido2CompleteAssertionPayloadAllowCredentials.type) &&
        Objects.equals(this.transports, authenticateFido2CompleteAssertionPayloadAllowCredentials.transports);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, type, transports);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class InlineResponse2003AssertionPayloadAllowCredentials {\n");

    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    transports: ").append(toIndentedString(transports)).append("\n");
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
