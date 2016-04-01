package com.btmatthews.sso.demo.security;

import net.spy.memcached.MemcachedClient;
import net.spy.memcached.transcoders.Transcoder;
import org.opensaml.xml.XMLObject;
import org.springframework.security.saml.storage.SAMLMessageStorage;

public class MemcachedMessageStorage implements SAMLMessageStorage {

    private final MemcachedClient memcachedClient;

    private final int ttl;

    private final Transcoder<XMLObject> transcoder;

    public MemcachedMessageStorage(final MemcachedClient memcachedClient,
                                   final int ttl,
                                   final Transcoder<XMLObject> transcoder) {
        this.memcachedClient = memcachedClient;
        this.ttl = ttl;
        this.transcoder = transcoder;
    }

    @Override
    public void storeMessage(final String messageId,
                             final XMLObject message) {
        memcachedClient.add(messageId, ttl, message, transcoder);
    }

    @Override
    public XMLObject retrieveMessage(final String messageId) {
        return memcachedClient.get(messageId, transcoder);
    }
}
