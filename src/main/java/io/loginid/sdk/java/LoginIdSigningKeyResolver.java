package io.loginid.sdk.java;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.loginid.sdk.java.api.CertificatesApi;
import io.loginid.sdk.java.invokers.ApiException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LoginIdSigningKeyResolver extends SigningKeyResolverAdapter {
    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String keyId = header.getKeyId();
        Key key = null;
        try {
            key = lookupVerificationKey(keyId);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (ApiException e) {
            e.printStackTrace();
        }

        return key;
    }

    private String getPublicKey(String keyId) throws ApiException {
        CertificatesApi certificatesApi = new CertificatesApi();

        return certificatesApi.certsGetWithHttpInfo(keyId, null).getData();
    }

    private Key lookupVerificationKey(String keyId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
//        String publicKeyContent = "-----BEGIN PUBLIC KEY-----" +
//                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpnAHxBlabYP9EPr32lkfARyVfSxO" +
//                "jGP0LLgt4nprTIGYrg0oMjiJNBNbhV4vI3pDyScSNCbjeXd2UKlhQLXb0Q==" +
//                "-----END PUBLIC KEY-----";
        String publicKeyContent = getPublicKey(keyId);
        publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(keySpecX509);

        return publicKey;
    }

}
