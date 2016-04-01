package com.btmatthews.sso.demo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class SSOUserDetailsImpl implements UserDetails {

    private final String username;

    private final String givenName;

    private final String surname;

    private final String email;

    private final Set<GrantedAuthority> authorities = new HashSet<>();

    public SSOUserDetailsImpl(final String username,
                              final String givenName,
                              final String surname,
                              final String email,
                              final Collection<GrantedAuthority> authorities) {
        this.username = username;
        this.givenName = givenName;
        this.surname = surname;
        this.email = email;
        this.authorities.addAll(authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getGivenName() { return givenName; }

    public String getSurname() { return surname; }

    public String getEmail() { return email; }

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
