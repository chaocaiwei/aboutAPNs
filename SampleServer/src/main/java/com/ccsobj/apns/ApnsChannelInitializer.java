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

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
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
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandler;
import io.netty.handler.codec.http2.HttpToHttp2ConnectionHandlerBuilder;
import io.netty.handler.codec.http2.InboundHttp2ToHttpAdapterBuilder;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
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
import io.netty.util.concurrent.Promise;
import io.netty.util.internal.PlatformDependent;

class ApnsChannelInitializer extends ChannelInitializer<SocketChannel> {
    private SslContext     sslCtx;
    public SocketChannel   channel;
    public SettingsHandler settingsHandler;
    public ResponseHandler responseHandler;

    ApnsChannelInitializer(SslContext sslCtx) {
        this.sslCtx = sslCtx;
    }

    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        this.channel = ch;
        this.settingsHandler = new SettingsHandler(ch.newPromise());
        this.responseHandler = new ResponseHandler(ch);
        ChannelPipeline pipeline = ch.pipeline();
        SslHandler handle = sslCtx.newHandler(ch.alloc());
        pipeline.addLast(handle);

        // We must wait for the handshake to finish and the protocol to be negotiated
        // before configuring
        // the HTTP/2 components of the pipeline.
        pipeline.addLast(new ApplicationProtocolNegotiationHandler("h2") {
            @Override
            protected void configurePipeline(ChannelHandlerContext ctx, String protocol) {
                if (ApplicationProtocolNames.HTTP_2.equals(protocol)) {
                    ChannelPipeline p = ctx.pipeline();
                    configureEndOfPipeline(p, ch);
                } else {
                    ctx.close();
                    throw new IllegalStateException("unknown protocol: " + protocol);
                }
            }
        });
    }

    protected void configureEndOfPipeline(ChannelPipeline pipeline, SocketChannel ch) {
        final DefaultHttp2Connection connection = new DefaultHttp2Connection(false);
        HttpToHttp2ConnectionHandler connectionHandler = new HttpToHttp2ConnectionHandlerBuilder().frameListener(
                new DelegatingDecompressorFrameListener(connection, new InboundHttp2ToHttpAdapterBuilder(connection)
                        .maxContentLength(Integer.MAX_VALUE).propagateSettings(true).build()))
                .connection(connection).build();
        pipeline.addLast(connectionHandler);
        pipeline.addLast(settingsHandler, responseHandler);
    }

}

class SettingsHandler extends SimpleChannelInboundHandler<Http2Settings> {
    final ChannelPromise promise;

    public SettingsHandler(ChannelPromise promise) {
        this.promise = promise;
    }

    public Boolean await() {
        promise.awaitUninterruptibly(30, TimeUnit.SECONDS);
        return promise.isSuccess();
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Http2Settings msg) throws Exception {
        promise.setSuccess();
        ctx.pipeline().remove(this);
    }

}

class ResponseHandler extends SimpleChannelInboundHandler<FullHttpResponse> {

    class Result {
        boolean isSuccess;
        int     statusCode;
        String  reason;

        public Result(int statusCode,String  reason){
            this.statusCode = statusCode;
            this.reason = reason;
            this.isSuccess = statusCode == 200;
        }

    }
    public Result result;
    Channel channel;
    ChannelPromise promise;

    public ResponseHandler(Channel channel) {
        this.channel = channel;
    }

    public Result awaite(){
        this.result = null;
        promise = channel.newPromise();
        Boolean isPro = promise.awaitUninterruptibly(30, TimeUnit.SECONDS);
        return this.result;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpResponse msg) throws Exception {
        Integer streamId = msg.headers().getInt(HttpConversionUtil.ExtensionHeaderNames.STREAM_ID.text());
        int code = msg.status().code();
        String reason = "";
        ByteBuf content = msg.content();
        if (content.isReadable()) {
            int contentLength = content.readableBytes();
            byte[] arr = new byte[contentLength];
            content.readBytes(arr);
            reason = new String(arr, 0, contentLength, CharsetUtil.UTF_8);
        }
        this.result = new Result(code,reason);
        this.promise.setSuccess();
    }

}