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
 * AuthenticationResponseCredential
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-10T08:30:05.952Z[GMT]")
public class AuthenticationResponseCredential {
  @SerializedName("uuid")
  private String uuid = null;

  /**
   * Gets or Sets type
   */
  @JsonAdapter(TypeEnum.Adapter.class)
  public enum TypeEnum {
    FIDO2("fido2"),
    PASSWORD("password"),
    PUBLICKEY("public_key");

    private String value;

    TypeEnum(String value) {
      this.value = value;
    }
    public String getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.valueOf(value);
    }
    public static TypeEnum fromValue(String text) {
      for (TypeEnum b : TypeEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
    public static class Adapter extends TypeAdapter<TypeEnum> {
      @Override
      public void write(final JsonWriter jsonWriter, final TypeEnum enumeration) throws IOException {
        jsonWriter.value(enumeration.getValue());
      }

      @Override
      public TypeEnum read(final JsonReader jsonReader) throws IOException {
        Object value = jsonReader.nextString();
        return TypeEnum.fromValue(String.valueOf(value));
      }
    }
  }  @SerializedName("type")
  private TypeEnum type = null;

  @SerializedName("name")
  private String name = null;

  public AuthenticationResponseCredential uuid(String uuid) {
    this.uuid = uuid;
    return this;
  }

   /**
   * Get uuid
   * @return uuid
  **/
  @Schema(description = "")
  public String getUuid() {
    return uuid;
  }

  public void setUuid(String uuid) {
    this.uuid = uuid;
  }

  public AuthenticationResponseCredential type(TypeEnum type) {
    this.type = type;
    return this;
  }

   /**
   * Get type
   * @return type
  **/
  @Schema(description = "")
  public TypeEnum getType() {
    return type;
  }

  public void setType(TypeEnum type) {
    this.type = type;
  }

  public AuthenticationResponseCredential name(String name) {
    this.name = name;
    return this;
  }

   /**
   * Get name
   * @return name
  **/
  @Schema(description = "")
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    AuthenticationResponseCredential authenticationResponseCredential = (AuthenticationResponseCredential) o;
    return Objects.equals(this.uuid, authenticationResponseCredential.uuid) &&
        Objects.equals(this.type, authenticationResponseCredential.type) &&
        Objects.equals(this.name, authenticationResponseCredential.name);
  }

  @Override
  public int hashCode() {
    return Objects.hash(uuid, type, name);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AuthenticationResponseCredential {\n");

    sb.append("    uuid: ").append(toIndentedString(uuid)).append("\n");
    sb.append("    type: ").append(toIndentedString(type)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
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
