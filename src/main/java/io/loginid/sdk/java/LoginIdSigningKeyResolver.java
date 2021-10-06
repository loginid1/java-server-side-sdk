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
	final private CertificatesApi certificatesApi = new CertificatesApi();
	
    /**
     * Get certificatesApi
     *
     * @return CertificatesApi
     */
	public CertificatesApi getCertificatesApi() {
		return certificatesApi;
	}
	
    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        String keyId = header.getKeyId();
        Key key = null;
        try {
            key = lookupVerificationKey(keyId);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | ApiException e) {
            e.printStackTrace();
        }

        return key;
    }

    /**
     * Return the client's public key based on 'kid'
     *
     * @param keyId The kid included in the JWT header
     * @return The public key if present
     * @throws ApiException
     */
    private String getPublicKey(String keyId) throws ApiException {
        CertificatesApi certificatesApi = new CertificatesApi();

        return certificatesApi.certsGetWithHttpInfo(keyId, null).getData();
    }

    /**
     * Returns a Key object based on the public key of a client
     *
     * @param keyId The kid included in the JWT header
     * @return Key object based on the public key
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ApiException
     */
    @SuppressWarnings("UnnecessaryLocalVariable")
    private Key lookupVerificationKey(String keyId) throws NoSuchAlgorithmException, InvalidKeySpecException, ApiException {
        String publicKeyContent = getPublicKey(keyId);
        publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(keySpecX509);

        return publicKey;
    }

}
