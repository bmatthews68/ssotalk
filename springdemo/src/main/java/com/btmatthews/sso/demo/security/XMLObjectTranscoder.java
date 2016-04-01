package com.btmatthews.sso.demo.security;

import net.spy.memcached.CachedData;
import net.spy.memcached.transcoders.Transcoder;
import org.apache.tomcat.util.http.fileupload.ByteArrayOutputStream;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLObjectHelper;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class XMLObjectTranscoder implements Transcoder<XMLObject> {

    private final ParserPool parserPool;

    public XMLObjectTranscoder(final ParserPool parserPool) {
        this.parserPool = parserPool;
    }

    @Override
    public boolean asyncDecode(final CachedData data) {
        return false;
    }

    @Override
    public CachedData encode(XMLObject object) {
        try (final ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            XMLObjectHelper.marshallToOutputStream(object, outputStream);
            final byte[] data = outputStream.toByteArray();
            return new CachedData(0, data, data.length);
        } catch (final MarshallingException e) {
        } catch (final IOException e) {
        }
        return null;
    }

    @Override
    public XMLObject decode(final CachedData d) {
        try (final ByteArrayInputStream inputStream = new ByteArrayInputStream(d.getData())) {
            return XMLObjectHelper.unmarshallFromInputStream(parserPool, inputStream);
        } catch (final UnmarshallingException e) {
        } catch (final XMLParserException e) {
        } catch (final IOException e) {
        }
        return null;
    }

    @Override
    public int getMaxSize() {
        return CachedData.MAX_SIZE;
    }
}
