package org.miniorange.saml;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import edu.umd.cs.findbugs.annotations.NonNull;

public class MoSAMLAuthenticationTokenInfo extends AbstractAuthenticationToken{

    private MoSAMLUserInfo userInfo;

    public MoSAMLAuthenticationTokenInfo(@NonNull MoSAMLUserInfo userInfo) {
        super(userInfo.getAuthorities());
        this.userInfo = userInfo;
        this.setDetails(userInfo);
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "No Password for SAML application";
    }

    @Override
    public Object getPrincipal() {
        return userInfo;
    }
}
