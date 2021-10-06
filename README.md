# java-server-side-sdk

The LoginId Server Side SDK in Java provides methods to connect to LoginIDs APIs in a simple, robust and secure way.

For more detailed information on getting started, please visit our documentation: [Java - Getting Started](https://docs.loginid.io/Server-SDKs/Java/java-get-started). 

Once you have registered a **Backend** application in the dashboard at [LoginID](https://loginid.io), start by following these simple steps:

- clone this project: `git clone https://github.com/loginid1/java-server-side-sdk.git`
- cd into `java-server-side-sdk`
- run `mvn clean install`

You can now use the SDK in your local development machine!

## Example

Here is a simple code snippet that connects to LoginID, creates a user and retrieves the userId of the newly created user.
 It works as shown on a Mac environment and if you have chosen to create a configuration file as documented:

```
package io.loginid.doc;

import io.loginid.sdk.java.LoginIdManagement;
import io.loginid.sdk.java.invokers.ApiClient;
import io.loginid.sdk.java.invokers.Configuration;
import io.loginid.sdk.java.model.UserProfile;

import java.io.FileReader;
import java.util.Properties;
import java.util.UUID;

public class Main {
    public static void main(String[] args) {
        try {

            // Load configuration from properties file
            Properties props = new Properties();
            props.load(new FileReader(String.format("%s/%s", System.getProperty("user.home"), ".loginid/config")));

            // Create and set a default API Client so that the configured base_url is used
            ApiClient apiClient = new ApiClient();
            apiClient.setBasePath(props.getProperty("base_url"));
            Configuration.setDefaultApiClient(apiClient);

            // Create the management client
            LoginIdManagement mgmt = new LoginIdManagement(
                    props.getProperty("client_id_backend"),
                    props.getProperty("API_PRIVATE_KEY"),
                    props.getProperty("base_url"));

            // Create a user and retrieve the userId
            UserProfile profile = mgmt.createUserWithoutCredentials("doc.doooe@example.com");
            UUID userId = mgmt.getUserId(profile.getUsername());
            System.out.println(userId.toString());
            
        } catch (Exception e) {
            // if this occurs check if you have tried to create the same user twice!
            e.printStackTrace();
        }
    }
}
```