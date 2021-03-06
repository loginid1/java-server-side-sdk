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

import java.util.Objects;
import java.util.Arrays;

import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.v3.oas.annotations.media.Schema;

import java.io.IOException;

/**
 * ManageUsersBody
 */

@javax.annotation.Generated(value = "io.swagger.codegen.v3.generators.java.JavaClientCodegen", date = "2021-06-15T16:43:19.800Z[GMT]")
public class ManageUsersBody {
    @SerializedName("username")
    private String username = null;

    public ManageUsersBody username(String username) {
        this.username = username;
        return this;
    }

    /**
     * Get username
     *
     * @return username
     **/
    @Schema(description = "")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }


    @Override
    public boolean equals(java.lang.Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ManageUsersBody manageUsersBody = (ManageUsersBody) o;
        return Objects.equals(this.username, manageUsersBody.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username);
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class ManageUsersBody {\n");

        sb.append("    username: ").append(toIndentedString(username)).append("\n");
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