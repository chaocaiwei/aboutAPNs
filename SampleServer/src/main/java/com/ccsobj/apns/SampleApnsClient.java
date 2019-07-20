package com.ccsobj.apns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLException;
import javax.swing.text.html.parser.Entity;

import com.ccsobj.apns.ResponseHandler.Result;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpScheme;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http2.DefaultHttp2Connection;
import io.netty.handler.codec.http2.DelegatingDecompressorFrameListener;
import io.netty.handler.codec.http2.Http2SecurityUtil;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.handler.codec.http2.Http2Stream;
import io.netty.handler.codec.http2.HttpConversionUtil;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import io.netty.util.AsciiString;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.internal.PlatformDependent;

/**
 * Configures the client pipeline to support HTTP/2 frames.
 * 
 * @param <ChannelFuture>
 */
public class SampleApnsClient {

    
    String host = "api.sandbox.push.apple.com";
    int port = 443;

    private  ApnsJWT jwt;
    SslContext sslContext;
    ApnsChannelInitializer initializer;

    public SampleApnsClient(String p12Path,String p12Pwd){
        try {
            sslContext = sslContext(p12Path, p12Pwd);
            initializer = new ApnsChannelInitializer(sslContext);
        } catch (SSLException | FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public SampleApnsClient(String p8path,String keyId,String teamId){
        this.jwt = new ApnsJWT(p8path,keyId,teamId);
        try {
            sslContext = sslContext();
            initializer = new ApnsChannelInitializer(sslContext);
        } catch (SSLException e) {
            e.printStackTrace();
        }
    }

    void sent(String deviceToken,String topic,String payload) {

        // 创建请求
        String path = "/3/device/" + deviceToken;
        HttpScheme scheme = HttpScheme.HTTPS;
        AsciiString hostName = new AsciiString("api.sandbox.push.apple.com:443");
        HttpVersion version = HttpVersion.valueOf("HTTP/1.1");
        ByteBuf body = Unpooled.wrappedBuffer(payload.getBytes(CharsetUtil.UTF_8));
        FullHttpRequest request = new DefaultFullHttpRequest(version, new HttpMethod("POST"), path,body);
        request.headers().add(HttpHeaderNames.HOST, hostName);
        request.headers().add(HttpConversionUtil.ExtensionHeaderNames.SCHEME.text(), scheme.name());
        request.headers().add("apns-topic", topic);
        if(this.jwt != null){
            request.headers().add(HttpHeaderNames.AUTHORIZATION, "bearer " + this.jwt.token);
        }

        // 发送请求
        Channel channel = initializer.channel;
        channel.write(request);
        channel.flush();

        // 等待返回结果
        Result result = initializer.responseHandler.awaite();
        System.out.println("sent " + (result.isSuccess ? "成功" : "失败" ) + result.reason);
    }

    boolean connect()  {
        
        Bootstrap b = new Bootstrap();
        b.group(new NioEventLoopGroup());
        b.channel(NioSocketChannel.class);
        b.option(ChannelOption.SO_KEEPALIVE, true);
        b.option(ChannelOption.TCP_NODELAY, true);
        b.remoteAddress(host, port);
        b.handler(this.initializer);
        
        Channel channel = b.connect().syncUninterruptibly().channel();
        channel.newPromise();
        boolean isSuc = initializer.settingsHandler.await();
        System.out.println("Connected to [" + host + ':' + port + ']' + (isSuc ? "Success" : "fail"));
        
        return isSuc;
    }

    


    PrivateKeyEntry getPrivKeyEntry(String p12File, String password) {
        try {
            final InputStream p12InputStream = new FileInputStream(p12File);
            final KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(p12InputStream, password.toCharArray());
            final Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                KeyStore.Entry entry;
                if (password != null) {
                    final KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(
                            password.toCharArray());
                    entry = keyStore.getEntry(alias, passwordProtection);
                } else {
                    entry = keyStore.getEntry(alias, null);
                }
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    return (PrivateKeyEntry) entry;
                }
            }
        } catch (Exception e) {
            // TODO: handle exception
        }
        return null;
    }
    

    final SslContext sslContext(String p12File, String password) throws SSLException, FileNotFoundException {
        // 由p12生成私钥和证书
        final KeyStore.PrivateKeyEntry privateKeyEntry = this.getPrivKeyEntry(p12File, password);
        final X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
        final PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        // 由私钥和证书 生成netty的SslContext
        final SslProvider sslProvider;
        if (OpenSsl.isAvailable()) {
            // Native SSL provider is available; will use native provider.
            sslProvider = SslProvider.OPENSSL_REFCNT;
        } else {
            // Native SSL provider not available; will use JDK SSL provider.
            sslProvider = SslProvider.JDK;
        }
        final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().sslProvider(sslProvider)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE);
        sslContextBuilder.keyManager(privateKey, password, certificate);

        return sslContextBuilder.build();
    }

    final SslContext sslContext(String pemFilePath) throws SSLException {

        final SslProvider sslProvider;
        if (OpenSsl.isAvailable()) {
            // Native SSL provider is available; will use native provider.
            sslProvider = SslProvider.OPENSSL_REFCNT;
        } else {
            // Native SSL provider not available; will use JDK SSL provider.
            sslProvider = SslProvider.JDK;
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().sslProvider(sslProvider)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE);

        final File pemFile = new File(pemFilePath);
        sslContextBuilder.trustManager(pemFile);

        return sslContextBuilder.build();
    }

    final SslContext sslContext() throws SSLException {

        final SslProvider sslProvider;
        if (OpenSsl.isAvailable()) {
            // Native SSL provider is available; will use native provider.
            sslProvider = SslProvider.OPENSSL_REFCNT;
        } else {
            // Native SSL provider not available; will use JDK SSL provider.
            sslProvider = SslProvider.JDK;
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().sslProvider(sslProvider)
                .ciphers(Http2SecurityUtil.CIPHERS, SupportedCipherSuiteFilter.INSTANCE);

        return sslContextBuilder.build();
    }

}