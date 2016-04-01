package com.btmatthews.sso.demo.security;

import net.spy.memcached.MemcachedClient;
import net.spy.memcached.transcoders.Transcoder;
import org.opensaml.xml.XMLObject;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;

import javax.servlet.http.HttpServletRequest;

public class MemcachedMessageStorageFactory implements SAMLMessageStorageFactory {

    private final MemcachedMessageStorage messageStorage;

    public MemcachedMessageStorageFactory(final MemcachedClient memcachedClient,
                                          final int ttl,
                                          final Transcoder<XMLObject> transcoder) {
        this.messageStorage = new MemcachedMessageStorage(memcachedClient, ttl, transcoder);
    }

    @Override
    public SAMLMessageStorage getMessageStorage(final HttpServletRequest request) {
        return messageStorage;
    }
}
