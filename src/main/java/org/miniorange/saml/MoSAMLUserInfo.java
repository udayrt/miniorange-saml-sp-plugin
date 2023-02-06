package org.miniorange.saml;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MoSAMLUserInfo implements UserDetails {

    private String username;
    private List<GrantedAuthority> grantedAuthorities;

    public MoSAMLUserInfo (String username, Collection<? extends GrantedAuthority> grantedAuthorities) {
        this.username = username;
        this.grantedAuthorities = new ArrayList<>(grantedAuthorities);
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
