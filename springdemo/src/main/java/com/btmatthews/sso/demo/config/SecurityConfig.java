package com.btmatthews.sso.demo.config;

import com.btmatthews.sso.demo.security.MemcachedMessageStorageFactory;
import com.btmatthews.sso.demo.security.XMLObjectTranscoder;
import net.spy.memcached.MemcachedClient;
import net.spy.memcached.transcoders.Transcoder;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLContextProviderLB;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.File;
import java.net.URI;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${keystore.location}")
    private String keyStoreLocation;

    @Value("${keystore.password}")
    private String keyStorePassword;

    @Value("${key.alias}")
    private String keyAlias;

    @Value("${key.password}")
    private String keyPassword;

    @Value("${idp.metadata.path}")
    private String idpMetadataPath;

    @Value("${sp.id}")
    private String spId;

    @Value("${sp.base.url}")
    private String spBaseUrl;

    @Autowired
    private MemcachedClient memcachedClient;

    @Autowired
    private SAMLUserDetailsService userDetailsService;

    @Bean
    public static SAMLBootstrap samlBootstrap() {
        return new SAMLBootstrap();
    }

    @Override
    public void configure(final WebSecurity web) {
        web.ignoring().antMatchers("/css/**", "/images/**", "/js/**");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http.httpBasic().authenticationEntryPoint(samlEntryPoint());
        http.csrf().ignoringAntMatchers("/saml/**");
        http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class);
        http.addFilterBefore(samlFilter(), BasicAuthenticationFilter.class);
        http.authorizeRequests()
                .antMatchers("/saml/**").permitAll()
                .antMatchers("/", "/page/index.html").permitAll()
                .antMatchers("/page/profile.html").hasRole("USER")
                .anyRequest().authenticated();
        http.logout().logoutSuccessUrl("/");
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(samlAuthenticationProvider());
    }


    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    @Bean
    public ParserPool parserPool() throws Exception {
        final StaticBasicParserPool parserPool = new StaticBasicParserPool();
        parserPool.initialize();
        return parserPool;
    }

    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public HttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        final SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails(userDetailsService);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }

    @Bean
    public Transcoder<XMLObject> transcoder() throws Exception {
        return new XMLObjectTranscoder(parserPool());
    }

    @Bean
    public SAMLMessageStorageFactory messageStorageFactory() throws Exception {
        return new MemcachedMessageStorageFactory(memcachedClient, 360000, transcoder());
    }

    @Bean
    public SAMLContextProvider contextProvider(final SAMLMessageStorageFactory factory) {
        final URI uri = URI.create(spBaseUrl);
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            final SAMLContextProviderLB contextProvider = new SAMLContextProviderLB();
            contextProvider.setScheme(uri.getScheme());
            contextProvider.setServerName(uri.getHost());
            contextProvider.setServerPort(uri.getPort());
            contextProvider.setIncludeServerPortInRequestURL(uri.getPort() != 443);
            contextProvider.setContextPath(uri.getPath());
            contextProvider.setStorageFactory(factory);
            return contextProvider;
        } else {
            final SAMLContextProviderImpl contextProvider = new SAMLContextProviderImpl();
            contextProvider.setStorageFactory(factory);
            return contextProvider;
        }
    }

    @Bean
    public SAMLLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        final WebSSOProfileConsumerImpl consumer = new WebSSOProfileConsumerImpl();
        return consumer;
    }

    @Bean
    public WebSSOProfileConsumer hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        final WebSSOProfileImpl profile =  new WebSSOProfileImpl();
        return profile;
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    @Bean
    public KeyManager keyManager() {
        final FileSystemResourceLoader loader = new FileSystemResourceLoader();
        final Resource storeFile = loader.getResource(keyStoreLocation);
        final Map<String, String> keyPasswords = new HashMap<>();
        if (keyPassword != null && keyPassword.length() > 0) {
            keyPasswords.put(keyAlias, keyPassword);
        }
        return new JKSKeyManager(storeFile, keyStorePassword, keyPasswords, keyAlias);
    }

    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer() {
        return new TLSProtocolConfigurer();
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        final WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        webSSOProfileOptions.setAuthnContextComparison(AuthnContextComparisonTypeEnumeration.EXACT);
       // webSSOProfileOptions.setAuthnContexts(Collections.singletonList(AuthnContext.PASSWORD_AUTHN_CTX)); // PPT_AUTH_CTX
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        final SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        final ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(false);
        extendedMetadata.setSignMetadata(true);
        extendedMetadata.setRequireLogoutRequestSigned(true); // TODO
        return extendedMetadata;
    }

    @Bean
    public MetadataProvider idpExtendedMetadataProvider()
            throws Exception {
        final FilesystemMetadataProvider metadataProvider = new FilesystemMetadataProvider(new File(idpMetadataPath));
        metadataProvider.setParserPool(parserPool());
        metadataProvider.initialize();
        return metadataProvider;
    }

    @Bean
    @Qualifier("metadata")
    public MetadataManager metadata() throws Exception {
        final List<MetadataProvider> providers = new ArrayList<>();
        providers.add(idpExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        final MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(spId);
        metadataGenerator.setEntityBaseURL(spBaseUrl);
        metadataGenerator.setWantAssertionSigned(true); // TODO
        metadataGenerator.setRequestSigned(true); // TODO
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        return metadataGenerator;
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        final SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/page/profile.html");
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        final SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        final SAMLProcessingFilter filter = new SAMLProcessingFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(successRedirectHandler());
        filter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return filter;
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        final SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        final SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler();
        handler.setInvalidateHttpSession(true);
        handler.setClearAuthentication(true);
        return handler;
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[]{logoutHandler()},
                new LogoutHandler[]{logoutHandler()});
    }

    @Bean
    public SAMLBinding httpPostBinding() throws Exception {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @Bean
    public SAMLBinding httpRedirectDeflateBinding() throws Exception {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public SAMLProcessorImpl processor() throws Exception {
        final Collection<SAMLBinding> bindings = new ArrayList<>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        return new SAMLProcessorImpl(bindings);
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        final List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()));
        return new FilterChainProxy(chains);
    }
}
