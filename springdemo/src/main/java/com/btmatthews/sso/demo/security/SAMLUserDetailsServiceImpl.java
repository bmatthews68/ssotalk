package com.btmatthews.sso.demo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {
    @Override
    public Object loadUserBySAML(final SAMLCredential credential) throws UsernameNotFoundException {
        final String username = credential.getNameID().getValue();
        final String[] roles = credential.getAttributeAsStringArray("Role");
        final String email = credential.getAttributeAsString("email");
        final String surname = credential.getAttributeAsString("surname");
        final String givenName = credential.getAttributeAsString("givenName");
        final Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (final String role : roles) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase().replace('-', '_')));
        }
        return new SSOUserDetailsImpl(username, givenName, surname, email, authorities);
    }
}
